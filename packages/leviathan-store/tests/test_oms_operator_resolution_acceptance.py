"""Independent persistence and restart acceptance for OMS-OPS-001."""

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
from leviathan_store.tables import OmsOrderRow
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from leviathan_core.execution.broker_port import FakeBrokerPort, FakeSubmitResult
from leviathan_core.execution.broker_port_v1 import BrokerVenue, _issue_account_view
from leviathan_core.execution.broker_reconciliation import FakeBrokerReconciliation
from leviathan_core.execution.oms import OrderGatewayActor
from leviathan_core.execution.order_models import (
    BrokerObservation,
    ClientIdKey,
    LedgerIntegrityKey,
    OMSLedgerCorruption,
    OMSValidationError,
    OrderRequest,
    OrderSnapshot,
    OrderState,
    PaperDispatchEvidence,
)
from leviathan_core.execution.venue_conflict_resolution import (
    issue_venue_conflict_resolution_request,
)
from leviathan_core.security.principal_verifier import (
    PrincipalVerifier,
    RSAPublicKeyV1,
    TrustedIssuerV1,
)

pytestmark = pytest.mark.asyncio

_ACCOUNT = "venue-resolution-store-acceptance"
_NOW = datetime.now(UTC)
_LEDGER_KEY = LedgerIntegrityKey(b"oms-ops-store-acceptance-ledger-key-32byte")
_CLIENT_KEY = ClientIdKey(b"oms-ops-store-acceptance-client-key-32bytes")


class _SyntheticKeys:
    def __init__(self, key: RSAPublicKeyV1) -> None:
        self._key = key

    def get_key(self, _issuer: str, _kid: str) -> RSAPublicKeyV1:
        return self._key


class _SyntheticRevocations:
    def is_revoked(self, _issuer: str, _jti: str) -> bool:
        return False


def _principal() -> Any:
    fixture = (
        Path(__file__).resolve().parents[3]
        / "packages/leviathan-core/tests/security/fixtures/sec003_synthetic_rsa.json"
    )
    key_data = json.loads(fixture.read_text(encoding="utf-8"))
    modulus = int(key_data["modulus_hex"], 16)
    public_exponent = int(key_data["public_exponent_hex"], 16)
    private_exponent = int(key_data["private_exponent_hex"], 16)
    verifier = PrincipalVerifier(
        trusted_issuer=TrustedIssuerV1(
            issuer="oms.ops.store.synthetic",
            audience="oms.store.synthetic",
            org_id="xyra.store.synthetic",
            project_id="leviathan-ai",
            env="paper",
        ),
        key_set=_SyntheticKeys(RSAPublicKeyV1(modulus, public_exponent)),
        revocations=_SyntheticRevocations(),
        clock=lambda: datetime.now(UTC),
    )
    now = int(datetime.now(UTC).timestamp())
    header = {"alg": "RS256", "kid": "oms-ops-store-synthetic", "typ": "JWT"}
    claims = {
        "iss": "oms.ops.store.synthetic",
        "aud": "oms.store.synthetic",
        "org": "xyra.store.synthetic",
        "sub": "operator.store.synthetic",
        "role": "operator",
        "scope": ["oms:venue-conflict:resolve"],
        "env": "paper",
        "jti": "oms-ops-store-acceptance-jti",
        "iat": now - 1,
        "nbf": now - 1,
        "exp": now + 600,
        "venue": BrokerVenue.ALPACA.value,
        "portfolio": "paper-book",
        "strategy": "oms-ops-store-acceptance",
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


def _request(intent: str) -> OrderRequest:
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
        strategy_id="oms-ops-store-acceptance",
        risk_policy_digest="f" * 64,
        actor_id="synthetic-store-context",
        capability="paper-submit",
        limit_price=Decimal("100"),
    )


async def _open(
    database: Path, reconciliation: FakeBrokerReconciliation | None = None
) -> tuple[
    OrderGatewayActor,
    FakeBrokerPort,
    AsyncEngine,
    async_sessionmaker[AsyncSession],
    FakeBrokerReconciliation,
]:
    engine, sessions = create_engine_and_sessionmaker(f"sqlite+aiosqlite:///{database}")
    await init_schema(engine)
    memory = reconciliation or FakeBrokerReconciliation()
    broker = FakeBrokerPort(
        memory,
        account_id=_ACCOUNT,
        environment="paper",
        venue=BrokerVenue.ALPACA,
    )
    actor = open_order_gateway_actor(
        sessions,
        broker,
        memory,
        _CLIENT_KEY,
        ledger_key=_LEDGER_KEY,
        allow_in_memory=True,
    )
    return actor, broker, engine, sessions, memory


async def _close(actor: OrderGatewayActor, engine: AsyncEngine) -> None:
    await actor.close()
    await engine.dispose()


async def _make_conflict(
    actor: OrderGatewayActor,
    broker: FakeBrokerPort,
    order: OrderSnapshot,
    observation_id: str,
) -> None:
    observation = BrokerObservation(
        observation_id=observation_id,
        environment="paper",
        account_id=_ACCOUNT,
        venue=BrokerVenue.IBKR_TWS.value,
        client_order_id=order.request.client_order_id or "",
        status=OrderState.WORKING,
        observed_at=_NOW,
        venue_order_id=f"foreign-{observation_id}",
        broker_sequence=9,
    )
    broker.queue_account_view(_issue_account_view(
        _ACCOUNT,
        (observation,),
        (),
        9,
        (),
        datetime(1970, 1, 1, tzinfo=UTC),
        complete=True,
    ))
    result = await actor.reconcile(order.order_id)
    assert result.state is OrderState.RECONCILE_REQUIRED
    assert "VENUE_ACCOUNT_CONFLICT" in result.discrepancies


def _dispatch_evidence(order: OrderSnapshot) -> PaperDispatchEvidence:
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


async def _issued_request(actor: OrderGatewayActor, key: str) -> Any:
    review = await actor.review_venue_conflict("paper", _ACCOUNT)
    return issue_venue_conflict_resolution_request(
        environment="paper",
        account_id=_ACCOUNT,
        conflict_id=review.conflict_id,
        expected_ledger_revision=review.ledger_revision,
        principal=_principal(),
        human_confirmed=True,
        reason_code="BINDING_VERIFIED",
        idempotency_key=key,
    )


async def test_committed_evidence_precedes_clear_and_crash_stays_quarantined(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "resolution-crash.db"
    actor, broker, engine, sessions, memory = await _open(database)
    order = await actor.create(_request("crash-before-clear"))
    broker.queue_submit(FakeSubmitResult("venue-before-crash"))
    working = await actor.submit(order.order_id, _dispatch_evidence(order))
    assert working.state is OrderState.WORKING
    await _make_conflict(actor, broker, order, "crash-observation")
    request = await _issued_request(actor, "crash-idempotency")
    ledger = vars(actor)["_ledger"]
    clear = ledger.clear_venue_conflict_quarantine

    async def crash_before_clear(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("synthetic crash before quarantine clear")

    monkeypatch.setattr(ledger, "clear_venue_conflict_quarantine", crash_before_clear)
    with pytest.raises(RuntimeError, match="synthetic crash"):
        await actor.resolve_venue_conflict(request)
    async with sessions() as session:
        resolutions = (await session.scalars(select(OmsOperatorResolutionRow))).all()
        assert len(resolutions) == 1
        assert resolutions[0].conflict_id == request.conflict_id
    before_close = await actor.get(order.order_id)
    assert before_close is not None and before_close.state is OrderState.RECONCILE_REQUIRED
    assert "VENUE_ACCOUNT_CONFLICT" in before_close.discrepancies
    assert broker.submit_calls == 1 and broker.cancel_calls == 0
    monkeypatch.setattr(ledger, "clear_venue_conflict_quarantine", clear)
    await _close(actor, engine)

    reopened, reopened_broker, reopened_engine, _sessions, _memory = await _open(database, memory)
    try:
        after_restart = await reopened.get(order.order_id)
        assert after_restart is not None
        assert after_restart.state is OrderState.RECONCILE_REQUIRED
        assert "VENUE_ACCOUNT_CONFLICT" in after_restart.discrepancies
        review = await reopened.review_venue_conflict("paper", _ACCOUNT)
        assert review.conflict_id == request.conflict_id
        other = await reopened.create(_request("other-intent-after-crash"))
        with pytest.raises(OMSValidationError) as denied:
            await reopened.submit(other.order_id, _dispatch_evidence(other))
        assert denied.value.code == "ACCOUNT_RECONCILE_REQUIRED"
        assert reopened_broker.submit_calls == 0
        assert reopened_broker.cancel_calls == 0
    finally:
        await _close(reopened, reopened_engine)


async def test_tampered_resolution_record_cannot_clear_the_quarantine(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    actor, broker, engine, sessions, _memory = await _open(tmp_path / "resolution-tamper.db")
    try:
        order = await actor.create(_request("tamper-resolution"))
        broker.queue_submit(FakeSubmitResult("venue-before-tamper"))
        working = await actor.submit(order.order_id, _dispatch_evidence(order))
        assert working.state is OrderState.WORKING
        await _make_conflict(actor, broker, order, "tamper-observation")
        other = await actor.create(_request("tampered-resolution-other-intent"))
        request = await _issued_request(actor, "tamper-idempotency")
        ledger = vars(actor)["_ledger"]
        clear = ledger.clear_venue_conflict_quarantine

        async def tamper_then_clear(*args: Any, **kwargs: Any) -> Any:
            async with sessions() as session:
                await session.execute(
                    update(OmsOperatorResolutionRow)
                    .where(OmsOperatorResolutionRow.account_id == _ACCOUNT)
                    .values(chain="0" * 64)
                )
                await session.commit()
            return await clear(*args, **kwargs)

        monkeypatch.setattr(ledger, "clear_venue_conflict_quarantine", tamper_then_clear)
        with pytest.raises(OMSLedgerCorruption):
            await actor.resolve_venue_conflict(request)

        with pytest.raises(OMSLedgerCorruption):
            await actor.get(order.order_id)
        async with sessions() as session:
            stored = await session.get(OmsOrderRow, order.order_id)
            assert stored is not None and stored.state == OrderState.RECONCILE_REQUIRED.value
            assert "VENUE_ACCOUNT_CONFLICT" in stored.discrepancies
        async with sessions() as session:
            persisted = await session.scalar(select(OmsOperatorResolutionRow))
            assert persisted is not None and persisted.chain == "0" * 64
        with pytest.raises(OMSLedgerCorruption):
            await actor.submit(other.order_id, _dispatch_evidence(other))
        assert broker.submit_calls == 1 and broker.cancel_calls == 0
    finally:
        await _close(actor, engine)
