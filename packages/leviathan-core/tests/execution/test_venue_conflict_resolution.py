"""Writer-owned tests for exact venue-conflict identity capture."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from leviathan_store.engine import create_engine_and_sessionmaker, init_schema
from leviathan_store.oms_ledger import open_order_gateway_actor
from leviathan_store.oms_operator_resolution import OmsOperatorResolutionRow
from leviathan_store.tables import OmsEventRow
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from leviathan_core.execution.broker_port import FakeBrokerPort, FakeSubmitResult
from leviathan_core.execution.broker_port_v1 import BrokerVenue, _issue_account_view
from leviathan_core.execution.broker_reconciliation import FakeBrokerReconciliation
from leviathan_core.execution.oms import OrderGatewayActor
from leviathan_core.execution.order_models import (
    BrokerObservation,
    ClientIdKey,
    LedgerIntegrityKey,
    OrderRequest,
    OrderState,
    PaperDispatchEvidence,
)
from leviathan_core.execution.venue_conflict_resolution import (
    VenueConflictResolutionCode,
    VenueConflictResolutionError,
    issue_venue_conflict_resolution_request,
)
from leviathan_core.numeric import canonical_json
from leviathan_core.security.principal_verifier import (
    PrincipalVerifier,
    RSAPublicKeyV1,
    TrustedIssuerV1,
)

pytestmark = pytest.mark.asyncio

_ACCOUNT = "ops-resolution-account"
_LEDGER_KEY = LedgerIntegrityKey(b"oms-ops-resolution-test-ledger-key-32")
_CLIENT_KEY = ClientIdKey(b"oms-ops-resolution-test-client-key-32")


def _request(*, venue: str = BrokerVenue.ALPACA.value, intent: str = "ops-intent") -> OrderRequest:
    return OrderRequest(
        project_id="leviathan-ai",
        environment="paper",
        account_id=_ACCOUNT,
        venue=venue,
        instrument_id="AAPL",
        native_contract_id="paper-AAPL",
        side="BUY",
        quantity=Decimal("1"),
        order_type="LIMIT",
        time_in_force="DAY",
        client_order_id=None,
        intent_idempotency_key=intent,
        attempt=1,
        strategy_id="ops-resolution-test",
        risk_policy_digest="e" * 64,
        actor_id="test-operator",
        capability="paper-submit",
        limit_price=Decimal("100"),
    )


async def _open(
    database: Path,
) -> tuple[
    OrderGatewayActor,
    FakeBrokerPort,
    AsyncEngine,
    async_sessionmaker[AsyncSession],
]:
    engine, sessions = create_engine_and_sessionmaker(f"sqlite+aiosqlite:///{database}")
    await init_schema(engine)
    reconciliation = FakeBrokerReconciliation()
    broker = FakeBrokerPort(
        reconciliation, account_id=_ACCOUNT, venue=BrokerVenue.ALPACA,
    )
    actor = open_order_gateway_actor(
        sessions,
        broker,
        reconciliation,
        _CLIENT_KEY,
        ledger_key=_LEDGER_KEY,
        allow_in_memory=True,
    )
    return actor, broker, engine, sessions


class _SyntheticKeys:
    def __init__(self, key: RSAPublicKeyV1) -> None:
        self._key = key

    def get_key(self, _issuer: str, _kid: str) -> RSAPublicKeyV1:
        return self._key


class _SyntheticRevocations:
    def is_revoked(self, _issuer: str, _jti: str) -> bool:
        return False


def _operator_principal() -> Any:
    fixture = Path(__file__).parents[2] / "tests/security/fixtures/sec003_synthetic_rsa.json"
    key_data = json.loads(fixture.read_text(encoding="utf-8"))
    modulus = int(key_data["modulus_hex"], 16)
    public_exponent = int(key_data["public_exponent_hex"], 16)
    private_exponent = int(key_data["private_exponent_hex"], 16)
    verifier = PrincipalVerifier(
        trusted_issuer=TrustedIssuerV1(
            issuer="oms.ops.synthetic",
            audience="oms.synthetic",
            org_id="xyra.synthetic",
            project_id="leviathan-ai",
            env="paper",
        ),
        key_set=_SyntheticKeys(RSAPublicKeyV1(modulus, public_exponent)),
        revocations=_SyntheticRevocations(),
        clock=lambda: datetime.now(UTC),
    )
    now = int(datetime.now(UTC).timestamp())
    header = {"alg": "RS256", "kid": "synthetic-key-1", "typ": "JWT"}
    claims = {
        "iss": "oms.ops.synthetic",
        "aud": "oms.synthetic",
        "org": "xyra.synthetic",
        "sub": "operator.synthetic",
        "role": "operator",
        "scope": ["oms:venue-conflict:resolve"],
        "env": "paper",
        "jti": "oms-ops-jti-1",
        "iat": now - 1,
        "nbf": now - 1,
        "exp": now + 600,
        "venue": BrokerVenue.ALPACA.value,
        "portfolio": "paper-book",
        "strategy": "ops-resolution-test",
    }

    def encode(value: object) -> str:
        payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")

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


def _dispatch_evidence(order: Any) -> Any:
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
        risk_approved=True,
        halt_clear=True,
        allowlisted=True,
    )


async def test_quarantine_captures_exact_observation_identity_and_deterministic_conflict_id(
    tmp_path: Path,
) -> None:
    actor, broker, engine, _sessions = await _open(tmp_path / "captured-conflict.db")
    try:
        created = await actor.create(_request())
        observed_at = datetime(2026, 10, 6, 15, 0, tzinfo=UTC)
        observation = BrokerObservation(
            observation_id="foreign-observation-17",
            environment="paper",
            account_id=_ACCOUNT,
            venue=BrokerVenue.IBKR_TWS.value,
            client_order_id=created.request.client_order_id or "",
            status=OrderState.WORKING,
            observed_at=observed_at,
            venue_order_id="foreign-order-17",
            broker_sequence=7,
        )
        broker.queue_account_view(_issue_account_view(
            _ACCOUNT,
            (observation,),
            (),
            7,
            (),
            datetime(1950, 1, 1, tzinfo=UTC),
            complete=True,
        ))

        quarantined = await actor.reconcile(created.order_id)

        assert quarantined.state is OrderState.RECONCILE_REQUIRED
        assert "VENUE_ACCOUNT_CONFLICT" in quarantined.discrepancies
        ledger = vars(actor)["_ledger"]
        events = await ledger.events(created.order_id)
        conflict_event = next(
            event for event in events if event["code"] == "VENUE_ACCOUNT_CONFLICT"
        )
        evidence = conflict_event["evidence"]
        assert evidence["binding_venue"] == BrokerVenue.ALPACA.value
        assert evidence["binding_environment"] == "paper"
        assert evidence["observations"] == [{
            "observation_id": "foreign-observation-17",
            "venue": BrokerVenue.IBKR_TWS.value,
            "environment": "paper",
        }]
        assert evidence["affected_order_ids"] == [created.order_id]
        identity_payload = {
            "environment": "paper",
            "account_id": _ACCOUNT,
            "binding_venue": BrokerVenue.ALPACA.value,
            "binding_environment": "paper",
            "observations": [[
                "foreign-observation-17", BrokerVenue.IBKR_TWS.value, "paper",
            ]],
            "affected_order_ids": [created.order_id],
        }
        identity_digest = hashlib.sha256(canonical_json(identity_payload)).hexdigest()
        assert evidence["identity_digest"] == identity_digest

        review = await actor.review_venue_conflict("paper", _ACCOUNT)
        expected_conflict_material = {
            "environment": "paper",
            "account_id": _ACCOUNT,
            "binding_venue": BrokerVenue.ALPACA.value,
            "binding_environment": "paper",
            "observation_ids": ["foreign-observation-17"],
            "identity_digest": identity_digest,
            "orders": [[
                created.order_id,
                conflict_event["sequence"],
                conflict_event["state"],
                evidence,
            ]],
        }
        assert review.conflict_id == hashlib.sha256(
            canonical_json(expected_conflict_material)
        ).hexdigest()
        assert (await actor.review_venue_conflict("paper", _ACCOUNT)).conflict_id == (
            review.conflict_id
        )
    finally:
        await actor.close()
        await engine.dispose()


async def test_legacy_identityless_conflict_cannot_be_reviewed_for_waiver(
    tmp_path: Path,
) -> None:
    actor, _broker, engine, _sessions = await _open(tmp_path / "legacy-conflict.db")
    try:
        order = await actor.create(_request(venue=BrokerVenue.IBKR_TWS.value))
        quarantined = await actor.reconcile(order.order_id)
        assert "VENUE_ACCOUNT_CONFLICT" in quarantined.discrepancies
        with pytest.raises(VenueConflictResolutionError) as raised:
            await actor.review_venue_conflict("paper", _ACCOUNT)
        assert raised.value.code == VenueConflictResolutionCode.LEGACY_CONFLICT_UNWAIVABLE.value
    finally:
        await actor.close()
        await engine.dispose()


async def test_resolution_row_persists_exact_captured_identity(tmp_path: Path) -> None:
    actor, broker, engine, sessions = await _open(tmp_path / "resolution-row.db")
    try:
        broker.queue_submit(FakeSubmitResult("venue-order-ops-1", OrderState.WORKING))
        created = await actor.create(_request())
        working = await actor.submit(created.order_id, _dispatch_evidence(created))
        assert working.state is OrderState.WORKING

        broker.queue_account_view(_issue_account_view(
            _ACCOUNT,
            (BrokerObservation(
                observation_id="resolution-trigger-1",
                environment="paper",
                account_id=_ACCOUNT,
                venue=BrokerVenue.IBKR_TWS.value,
                client_order_id=working.request.client_order_id or "",
                status=OrderState.WORKING,
                observed_at=datetime.now(UTC),
                venue_order_id="foreign-venue-order-1",
                broker_sequence=1,
            ),),
            (),
            1,
            (),
            datetime(1970, 1, 1, tzinfo=UTC),
            complete=True,
        ))
        quarantined = await actor.reconcile(working.order_id)
        assert quarantined.state is OrderState.RECONCILE_REQUIRED

        review = await actor.review_venue_conflict("paper", _ACCOUNT)
        resolution_request = issue_venue_conflict_resolution_request(
            environment="paper",
            account_id=_ACCOUNT,
            conflict_id=review.conflict_id,
            expected_ledger_revision=review.ledger_revision,
            principal=_operator_principal(),
            human_confirmed=True,
            reason_code="BINDING_VERIFIED",
            idempotency_key="ops-resolution-idempotency-1",
        )
        result = await actor.resolve_venue_conflict(resolution_request)
        async with sessions() as session:
            row = await session.get(OmsOperatorResolutionRow, result.resolution_id)
            assert row is not None
            assert row.account_id == _ACCOUNT
            assert row.environment == "paper"
            assert row.binding_venue == BrokerVenue.ALPACA.value
            assert row.binding_environment == "paper"
            assert row.observation_ids == ["resolution-trigger-1"]
            assert row.identity_digest == review.identity_digest
            events = (await session.scalars(select(OmsEventRow).where(
                OmsEventRow.order_id == working.order_id,
                OmsEventRow.code == "VENUE_ACCOUNT_CONFLICT",
            ))).all()
            assert len(events) == 1
            assert events[0].evidence["observations"][0]["observation_id"] == (
                "resolution-trigger-1"
            )
        resolved = await actor.get(working.order_id)
        assert resolved is not None and resolved.state is OrderState.WORKING
        assert "VENUE_ACCOUNT_CONFLICT" not in resolved.discrepancies
        assert broker.submit_calls == 1
        assert broker.cancel_calls == 0
    finally:
        await actor.close()
        await engine.dispose()
