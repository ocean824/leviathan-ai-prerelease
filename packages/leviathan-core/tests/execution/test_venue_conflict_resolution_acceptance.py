"""Independent acceptance for authenticated, exact OMS venue-conflict waivers."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from leviathan_store.engine import create_engine_and_sessionmaker, init_schema
from leviathan_store.oms_ledger import open_order_gateway_actor
from sqlalchemy.ext.asyncio import AsyncEngine

from leviathan_core.execution.broker_port import (
    FakeBrokerPort,
    FakeSubmitResult,
)
from leviathan_core.execution.broker_port_v1 import BrokerVenue, _issue_account_view
from leviathan_core.execution.broker_reconciliation import FakeBrokerReconciliation
from leviathan_core.execution.oms import OrderGatewayActor
from leviathan_core.execution.order_models import (
    BrokerObservation,
    ClientIdKey,
    LedgerIntegrityKey,
    OMSValidationError,
    OrderRequest,
    OrderSnapshot,
    OrderState,
    PaperDispatchEvidence,
)
from leviathan_core.execution.venue_conflict_resolution import (
    VenueConflictResolutionError,
    issue_venue_conflict_resolution_request,
)
from leviathan_core.security.principal_verifier import (
    PrincipalVerifier,
    RSAPublicKeyV1,
    TrustedIssuerV1,
)

pytestmark = pytest.mark.asyncio

_ACCOUNT = "venue-resolution-acceptance"
_NOW = datetime.now(UTC)
_LEDGER_KEY = LedgerIntegrityKey(b"oms-ops-acceptance-ledger-key-synthetic-32")
_CLIENT_KEY = ClientIdKey(b"oms-ops-acceptance-client-key-synthetic-32")
_REASONS = "BINDING_VERIFIED"


def _request(intent: str = "ops-acceptance-intent") -> OrderRequest:
    return OrderRequest(
        project_id="leviathan-ai",
        environment="paper",
        account_id=_ACCOUNT,
        venue=BrokerVenue.ALPACA.value,
        instrument_id="AAPL",
        native_contract_id="paper-AAPL",
        side="BUY",
        quantity=Decimal("1"),
        order_type="LIMIT",
        time_in_force="DAY",
        client_order_id=None,
        intent_idempotency_key=intent,
        attempt=1,
        strategy_id="oms-ops-acceptance",
        risk_policy_digest="e" * 64,
        actor_id="synthetic-test-context",
        capability="paper-submit",
        limit_price=Decimal("100"),
    )


class _SyntheticKeys:
    def __init__(self, key: RSAPublicKeyV1) -> None:
        self._key = key

    def get_key(self, _issuer: str, _kid: str) -> RSAPublicKeyV1:
        return self._key


class _SyntheticRevocations:
    def is_revoked(self, _issuer: str, _jti: str) -> bool:
        return False


def _operator_principal(*, role: str = "operator", scopes: list[str] | None = None) -> Any:
    fixture = Path(__file__).parents[2] / "tests/security/fixtures/sec003_synthetic_rsa.json"
    key_data = json.loads(fixture.read_text(encoding="utf-8"))
    modulus = int(key_data["modulus_hex"], 16)
    public_exponent = int(key_data["public_exponent_hex"], 16)
    private_exponent = int(key_data["private_exponent_hex"], 16)
    verifier = PrincipalVerifier(
        trusted_issuer=TrustedIssuerV1(
            issuer="oms.ops.acceptance.synthetic",
            audience="oms.acceptance.synthetic",
            org_id="xyra.acceptance.synthetic",
            project_id="leviathan-ai",
            env="paper",
        ),
        key_set=_SyntheticKeys(RSAPublicKeyV1(modulus, public_exponent)),
        revocations=_SyntheticRevocations(),
        clock=lambda: datetime.now(UTC),
    )
    now = int(datetime.now(UTC).timestamp())
    header = {"alg": "RS256", "kid": "oms-ops-synthetic", "typ": "JWT"}
    claims = {
        "iss": "oms.ops.acceptance.synthetic",
        "aud": "oms.acceptance.synthetic",
        "org": "xyra.acceptance.synthetic",
        "sub": "operator.acceptance.synthetic",
        "role": role,
        "scope": scopes or ["oms:venue-conflict:resolve"],
        "env": "paper",
        "jti": "oms-ops-acceptance-jti",
        "iat": now - 1,
        "nbf": now - 1,
        "exp": now + 600,
        "venue": BrokerVenue.ALPACA.value,
        "portfolio": "paper-book",
        "strategy": "oms-ops-acceptance",
    }

    def encode(value: object) -> str:
        data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    signing_input = f"{encode(header)}.{encode(claims)}"
    digest_info = bytes.fromhex("3031300d060960864801650304020105000420")
    digest_info += hashlib.sha256(signing_input.encode("ascii")).digest()
    size = (modulus.bit_length() + 7) // 8
    padding_size = size - len(digest_info) - 3
    encoded_message = b"\x00\x01" + b"\xff" * padding_size + b"\x00" + digest_info
    signature = pow(int.from_bytes(encoded_message, "big"), private_exponent, modulus).to_bytes(
        size, "big"
    )
    encoded_signature = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
    return verifier.verify(f"{signing_input}.{encoded_signature}")


async def _open(database: Path) -> tuple[OrderGatewayActor, FakeBrokerPort, AsyncEngine]:
    engine, sessions = create_engine_and_sessionmaker(f"sqlite+aiosqlite:///{database}")
    await init_schema(engine)
    reconciliation = FakeBrokerReconciliation()
    broker = FakeBrokerPort(
        reconciliation,
        account_id=_ACCOUNT,
        environment="paper",
        venue=BrokerVenue.ALPACA,
    )
    actor = open_order_gateway_actor(
        sessions,
        broker,
        reconciliation,
        _CLIENT_KEY,
        ledger_key=_LEDGER_KEY,
        allow_in_memory=True,
    )
    return actor, broker, engine


async def _close(actor: OrderGatewayActor, engine: AsyncEngine) -> None:
    await actor.close()
    await engine.dispose()


def _dispatch_evidence(
    order: OrderSnapshot, *, risk_approved: bool = True, halt_clear: bool = True
) -> PaperDispatchEvidence:
    request = order.request
    return PaperDispatchEvidence(
        order_id=order.order_id,
        request_digest=request.digest,
        account_id=request.account_id,
        venue=request.venue,
        strategy_id=request.strategy_id,
        policy_digest=request.risk_policy_digest,
        account_session_verified=True,
        entitled=True,
        feed_fresh=True,
        risk_approved=risk_approved,
        halt_clear=halt_clear,
        allowlisted=True,
    )


async def _quarantine(
    actor: OrderGatewayActor,
    broker: FakeBrokerPort,
    order: OrderSnapshot,
    observation_id: str,
) -> OrderSnapshot:
    observation = BrokerObservation(
        observation_id=observation_id,
        environment="paper",
        account_id=_ACCOUNT,
        venue=BrokerVenue.IBKR_TWS.value,
        client_order_id=order.request.client_order_id or "",
        status=OrderState.WORKING,
        observed_at=_NOW,
        venue_order_id=f"foreign-{observation_id}",
        broker_sequence=7,
    )
    broker.queue_account_view(_issue_account_view(
        _ACCOUNT,
        (observation,),
        (),
        7,
        (),
        datetime(1970, 1, 1, tzinfo=UTC),
        complete=True,
    ))
    quarantined = await actor.reconcile(order.order_id)
    assert quarantined.state is OrderState.RECONCILE_REQUIRED
    assert "VENUE_ACCOUNT_CONFLICT" in quarantined.discrepancies
    return quarantined


def _resolution_request(
    review: Any, *, human_confirmed: bool = True, key: str = "ops-key-1"
) -> Any:
    return issue_venue_conflict_resolution_request(
        environment=review.environment,
        account_id=review.account_id,
        conflict_id=review.conflict_id,
        expected_ledger_revision=review.ledger_revision,
        principal=_operator_principal(),
        human_confirmed=human_confirmed,
        reason_code=_REASONS,
        idempotency_key=key,
    )


async def test_authenticated_exact_waiver_preserves_history_and_allows_next_submit(
    tmp_path: Path,
) -> None:
    actor, broker, engine = await _open(tmp_path / "exact-waiver-submit.db")
    try:
        order = await actor.create(_request())
        broker.queue_submit(FakeSubmitResult("venue-before-exact-waiver"))
        working = await actor.submit(order.order_id, _dispatch_evidence(order))
        assert working.state is OrderState.WORKING
        await _quarantine(actor, broker, order, "foreign-observation-first")
        ledger = vars(actor)["_ledger"]
        prior_conflict = next(
            event for event in await ledger.events(order.order_id)
            if event["code"] == "VENUE_ACCOUNT_CONFLICT"
        )
        prior_evidence = json.loads(json.dumps(prior_conflict["evidence"]))
        review = await actor.review_venue_conflict("paper", _ACCOUNT)
        request = _resolution_request(review)

        resolution, duplicate = await asyncio.gather(
            actor.resolve_venue_conflict(request),
            actor.resolve_venue_conflict(request),
        )

        assert resolution.conflict_id == review.conflict_id
        assert duplicate.resolution_id == resolution.resolution_id
        assert duplicate.resolved_ledger_revision == resolution.resolved_ledger_revision
        assert resolution.operator_principal_id == "operator.acceptance.synthetic"
        restored = await actor.get(order.order_id)
        assert restored is not None and restored.state is OrderState.WORKING
        assert "VENUE_ACCOUNT_CONFLICT" not in restored.discrepancies
        after_resolution = await ledger.events(order.order_id)
        same_conflict = next(
            event for event in after_resolution
            if event["code"] == "VENUE_ACCOUNT_CONFLICT"
        )
        assert same_conflict["evidence"] == prior_evidence
        assert same_conflict["sequence"] == prior_conflict["sequence"]
        assert any(event["code"] == "VENUE_ACCOUNT_CONFLICT_RESOLVED" for event in after_resolution)
        assert broker.submit_calls == 1
        assert broker.cancel_calls == 0

        denied_orders = (
            ("risk-gated-after-waiver", False, True, "RISK_NOT_APPROVED"),
            ("halt-gated-after-waiver", True, False, "HALT_ACTIVE"),
        )
        for intent, risk_approved, halt_clear, code in denied_orders:
            candidate = await actor.create(_request(intent))
            with pytest.raises(OMSValidationError) as denied:
                await actor.submit(
                    candidate.order_id,
                    _dispatch_evidence(
                        candidate, risk_approved=risk_approved, halt_clear=halt_clear
                    ),
                )
            assert denied.value.code == code
            assert broker.submit_calls == 1

        next_order = await actor.create(_request("intent-after-exact-waiver"))
        broker.queue_submit(FakeSubmitResult("venue-after-exact-waiver"))
        next_working = await actor.submit(next_order.order_id, _dispatch_evidence(next_order))
        assert next_working.state is OrderState.WORKING
        assert broker.submit_calls == 2
        assert broker.cancel_calls == 0
    finally:
        await _close(actor, engine)


async def test_new_observation_requarantines_after_exact_waiver(
    tmp_path: Path,
) -> None:
    actor, broker, engine = await _open(tmp_path / "oms-ops-requarantine.db")
    try:
        order = await actor.create(_request("requarantine-intent"))
        broker.queue_submit(FakeSubmitResult("venue-before-requarantine"))
        working = await actor.submit(order.order_id, _dispatch_evidence(order))
        assert working.state is OrderState.WORKING
        await _quarantine(actor, broker, order, "foreign-observation-before")
        original = await actor.review_venue_conflict("paper", _ACCOUNT)
        await actor.resolve_venue_conflict(_resolution_request(original, key="waiver-before"))

        restored = await actor.get(order.order_id)
        assert restored is not None and restored.state is OrderState.WORKING
        await _quarantine(actor, broker, restored, "foreign-observation-after")

        current = await actor.review_venue_conflict("paper", _ACCOUNT)
        assert current.binding_venue == original.binding_venue == BrokerVenue.ALPACA.value
        assert current.binding_environment == original.binding_environment == "paper"
        assert current.observation_ids == ("foreign-observation-after",)
        assert current.conflict_id != original.conflict_id
        assert (await actor.get(order.order_id)).state is OrderState.RECONCILE_REQUIRED  # type: ignore[union-attr]
        assert broker.submit_calls == 1
        assert broker.cancel_calls == 0
    finally:
        await _close(actor, engine)


async def test_unissued_request_and_missing_human_confirmation_never_release(
    tmp_path: Path,
) -> None:
    actor, broker, engine = await _open(tmp_path / "unissued-request.db")
    try:
        order = await actor.create(_request("unissued-intent"))
        quarantined = await _quarantine(actor, broker, order, "foreign-unissued")
        review = await actor.review_venue_conflict("paper", _ACCOUNT)
        request = _resolution_request(review)

        with pytest.raises(VenueConflictResolutionError):
            await actor.resolve_venue_conflict(replace(request, idempotency_key="tampered"))
        with pytest.raises(VenueConflictResolutionError):
            await actor.resolve_venue_conflict(_resolution_request(review, human_confirmed=False))
        with pytest.raises(VenueConflictResolutionError):
            issue_venue_conflict_resolution_request(
                environment="paper",
                account_id=_ACCOUNT,
                conflict_id=review.conflict_id,
                expected_ledger_revision=review.ledger_revision,
                principal=object(),  # type: ignore[arg-type]
                human_confirmed=True,
                reason_code=_REASONS,
                idempotency_key="forged-principal",
            )
        with pytest.raises(VenueConflictResolutionError):
            issue_venue_conflict_resolution_request(
                environment="paper",
                account_id=_ACCOUNT,
                conflict_id=review.conflict_id,
                expected_ledger_revision=review.ledger_revision,
                principal=_operator_principal(role="service"),
                human_confirmed=True,
                reason_code=_REASONS,
                idempotency_key="service-principal",
            )

        current = await actor.get(order.order_id)
        assert current is not None and current.state is quarantined.state
        assert "VENUE_ACCOUNT_CONFLICT" in current.discrepancies
        assert broker.submit_calls == 0
        assert broker.cancel_calls == 0
    finally:
        await _close(actor, engine)


async def test_stale_revision_and_incomplete_broker_image_leave_quarantine(
    tmp_path: Path,
) -> None:
    actor, broker, engine = await _open(tmp_path / "resolution-denials.db")
    try:
        order = await actor.create(_request("denial-intent"))
        stale_view = broker.read_account_view(_ACCOUNT)
        broker.queue_submit(FakeSubmitResult("venue-before-denial"))
        working = await actor.submit(order.order_id, _dispatch_evidence(order))
        assert working.state is OrderState.WORKING
        await _quarantine(actor, broker, order, "foreign-denial")
        review = await actor.review_venue_conflict("paper", _ACCOUNT)
        stale = issue_venue_conflict_resolution_request(
            environment="paper",
            account_id=_ACCOUNT,
            conflict_id=review.conflict_id,
            expected_ledger_revision=review.ledger_revision - 1,
            principal=_operator_principal(),
            human_confirmed=True,
            reason_code=_REASONS,
            idempotency_key="stale-revision",
        )
        with pytest.raises(VenueConflictResolutionError):
            await actor.resolve_venue_conflict(stale)

        wrong_scope = issue_venue_conflict_resolution_request(
            environment="demo",
            account_id=_ACCOUNT,
            conflict_id=review.conflict_id,
            expected_ledger_revision=review.ledger_revision,
            principal=_operator_principal(),
            human_confirmed=True,
            reason_code=_REASONS,
            idempotency_key="wrong-environment-scope",
        )
        with pytest.raises(VenueConflictResolutionError):
            await actor.resolve_venue_conflict(wrong_scope)

        broker.queue_account_view(stale_view)
        with pytest.raises(VenueConflictResolutionError):
            await actor.resolve_venue_conflict(_resolution_request(review, key="stale-broker-view"))

        from leviathan_core.execution.broker_port_v1 import (
            BrokerOutcomeUnknown,
            BrokerUnknownCode,
        )

        broker.queue_account_view(BrokerOutcomeUnknown(BrokerUnknownCode.UNKNOWN_ACCOUNT_VIEW))
        with pytest.raises(VenueConflictResolutionError):
            await actor.resolve_venue_conflict(_resolution_request(review, key="incomplete-view"))

        current = await actor.get(order.order_id)
        assert current is not None and current.state is OrderState.RECONCILE_REQUIRED
        assert "VENUE_ACCOUNT_CONFLICT" in current.discrepancies
        assert broker.submit_calls == 1
        assert broker.cancel_calls == 0
    finally:
        await _close(actor, engine)


async def test_account_hold_rejects_dispatch_for_a_different_intent(
    tmp_path: Path,
) -> None:
    actor, broker, engine = await _open(tmp_path / "oms-ops-hold.db")
    try:
        conflicted = await actor.create(_request("held-intent"))
        await _quarantine(actor, broker, conflicted, "foreign-hold")
        other = await actor.create(_request("different-intent"))
        with pytest.raises(OMSValidationError) as denied:
            await actor.submit(other.order_id, _dispatch_evidence(other))
        assert denied.value.code == "ACCOUNT_RECONCILE_REQUIRED"
        blocked = await actor.get(other.order_id)
        assert blocked is not None and blocked.state is OrderState.RISK_REJECTED
        assert broker.submit_calls == 0
        assert broker.cancel_calls == 0
    finally:
        await _close(actor, engine)
