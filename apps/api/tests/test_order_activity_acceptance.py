"""Independent acceptance for the authenticated PAPER OMS activity route."""

from __future__ import annotations

import asyncio
import re
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from leviathan_store.engine import create_engine_and_sessionmaker, init_schema
from leviathan_store.oms_ledger import OrderLedger, open_order_gateway_actor

from leviathan_api.routers.order_activity import create_order_activity_router
from leviathan_api.routers.orders import OrderRuntime, PaperDispatchGate
from leviathan_core.execution.broker_port import FakeBrokerPort
from leviathan_core.execution.broker_port_v1 import BrokerVenue
from leviathan_core.execution.broker_reconciliation import FakeBrokerReconciliation
from leviathan_core.execution.oms import ActivityLedgerPage, ActivityOrderItem
from leviathan_core.execution.order_models import (
    ClientIdKey,
    Fill,
    FillCorrection,
    LedgerIntegrityKey,
    OrderRequest,
    OrderSnapshot,
    OrderState,
    PaperDispatchEvidence,
)
from leviathan_core.risk.halt import HaltAuthority
from leviathan_core.security.authz_models import (
    _VERIFIER_MARKER,
    PrincipalV1,
    TrustedPrincipalAdapterV1,
    TrustedPrincipalV1,
)
from leviathan_vault.client import VaultStatus
from leviathan_vault.trading_bindings import TradingAccountBindingV1

_PATH = "/orders/activity"
_ACCOUNT = "activity-paper-account"
_OTHER_ACCOUNT = "activity-other-account"
_STRATEGY = "activity-acceptance-strategy"
_NOW = datetime(2026, 10, 6, 15, 0, tzinfo=UTC)
_CLIENT_KEY = ClientIdKey(b"activity-acceptance-client-key-32-bytes!")
_LEDGER_KEY = LedgerIntegrityKey(b"activity-acceptance-integrity-key-32bytes!")
_MISSING = object()


def _principal(
    *,
    project_id: str = "leviathan-ai",
    roles: tuple[str, ...] = ("operator",),
    venue: str | None = None,
) -> TrustedPrincipalV1:
    claims = PrincipalV1(
        principal_id="activity-acceptance-operator",
        project_id=project_id,
        roles=roles,
        env="test",
        venue=venue,
    )
    return TrustedPrincipalAdapterV1.from_verified_claims(claims, verifier_marker=_VERIFIER_MARKER)


def _request(
    *,
    account_id: str = _ACCOUNT,
    side: str = "BUY",
    quantity: str = "4",
    instrument_id: str = "NQ-202612",
    intent: str = "activity-intent-1",
    attempt: int = 1,
    environment: str = "paper",
) -> OrderRequest:
    return OrderRequest(
        project_id="leviathan-ai",
        environment=environment,
        account_id=account_id,
        venue=BrokerVenue.ALPACA.value,
        instrument_id=instrument_id,
        native_contract_id="NQ.synthetic",
        side=side,
        quantity=Decimal(quantity),
        order_type="LIMIT",
        time_in_force="DAY",
        client_order_id=_CLIENT_KEY.derive(account_id, intent, attempt),
        intent_idempotency_key=intent,
        attempt=attempt,
        strategy_id=_STRATEGY,
        risk_policy_digest="d" * 64,
        actor_id="synthetic-operator",
        capability="paper-order-read-acceptance",
        limit_price=Decimal("100.25"),
    )


def _dispatch_evidence(order_id: str, request: OrderRequest) -> PaperDispatchEvidence:
    return PaperDispatchEvidence(
        order_id=order_id,
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


async def _seed_activity(sessions: Any) -> None:
    """Create immutable original fills and separate corrections before actor attach."""
    ledger = OrderLedger(sessions, key=_LEDGER_KEY)
    fixtures = (
        # BUY is corrected from 2.50 to 1.50 units.
        ("BUY", "4", "buy-corrected", "execution-buy", "2.50", "1.50", "100.25"),
        # SELL remains a negative 0.25 net contribution after correction.
        ("SELL", "2", "sell-corrected", "execution-sell", "0.50", "0.25", "100.25"),
        # A full bust is represented as a correction and nets to zero.
        ("SELL", "1", "sell-busted", "execution-busted", "0.40", "0", "0"),
    )
    try:
        created_rows = []
        for index, (side, quantity, intent, execution_id, original, revised, price) in enumerate(
            fixtures, start=1
        ):
            request = _request(
                side=side,
                quantity=quantity,
                intent=intent,
                attempt=1,
            )
            created = await ledger.create(request)
            await ledger.mark_submitting(
                created.order_id, _dispatch_evidence(created.order_id, created.request)
            )
            await ledger.mark_submit_result(
                created.order_id, OrderState.WORKING, f"venue-order-{index}"
            )
            created_rows.append((index, created, execution_id, original, revised, price))

        # Establish all WORKING states first so the test-only direct ledger seed
        # does not exercise submit account gates after corrections add evidence.
        for index, created, execution_id, original, revised, price in created_rows:
            await ledger.record_fill(
                created.order_id,
                Fill(
                    venue=BrokerVenue.ALPACA.value,
                    account_id=_ACCOUNT,
                    execution_id=execution_id,
                    quantity=Decimal(original),
                    price=Decimal("100.25"),
                    occurred_at=_NOW + timedelta(seconds=index),
                    commission=Decimal("0.01"),
                ),
            )
            await ledger.record_fill_correction(
                created.order_id,
                FillCorrection(
                    venue=BrokerVenue.ALPACA.value,
                    account_id=_ACCOUNT,
                    execution_id=execution_id,
                    correction_id=f"correction-{index}",
                    revision=1,
                    revised_quantity=Decimal(revised),
                    revised_price=Decimal(price) if Decimal(revised) > 0 else None,
                    occurred_at=_NOW + timedelta(seconds=index + 10),
                    revised_commission=Decimal("0.01") if Decimal(revised) > 0 else Decimal(0),
                ),
            )
    finally:
        ledger.close()


def _make_runtime(
    sessions: Any,
    *,
    account_id: str,
    environment: str,
) -> tuple[OrderRuntime, FakeBrokerPort, HaltAuthority]:
    halts = HaltAuthority()
    gate_state = SimpleNamespace(dispatch_gate=None, dispatch_fence=None, halts=halts)
    dispatch_gate = PaperDispatchGate(gate_state)  # type: ignore[arg-type]
    reconciliation = FakeBrokerReconciliation()
    broker = FakeBrokerPort(
        reconciliation,
        account_id=account_id,
        environment=environment,
        venue=BrokerVenue.ALPACA,
    )
    actor = open_order_gateway_actor(
        sessions,
        broker,
        reconciliation,
        _CLIENT_KEY,
        ledger_key=_LEDGER_KEY,
        dispatch_gate=dispatch_gate,
        allow_in_memory=True,
    )
    binding = TradingAccountBindingV1(
        project_id="leviathan-ai",
        environment="development",
        broker="FAKE-EXCHANGE",
        adapter_protocol="fake-paper",
        adapter_version="1",
        account_ref=account_id,
        session_ref=f"{environment}-acceptance-session",
        venue_allowlist=(BrokerVenue.ALPACA.value,),
        instrument_allowlist=("NQ-202612",),
        instrument_mapping_revision="mapping-v1",
        instrument_mapping_date=datetime(2026, 10, 1, tzinfo=UTC).date(),
        strategy_allowlist=(_STRATEGY,),
        hard_risk_limit_revision="risk-v1",
        session_mode=environment,
        credential_ref="vault://leviathan-ai/development/FAKE_API_KEY",
    )
    runtime = OrderRuntime(
        actor=actor,
        bindings=(binding,),
        credential_statuses={
            binding.credential_ref: VaultStatus(
                name="FAKE_API_KEY",
                scope="leviathan-ai",
                environment="development",
            )
        },
        native_contracts={(BrokerVenue.ALPACA.value, "NQ-202612"): "NQ.synthetic"},
        operator_authorizer=lambda _request: True,
        evidence_source=lambda _snapshot: _dispatch_evidence("activity-order", _request()),
        dispatch_gate=dispatch_gate,
    )
    return runtime, broker, halts


def _app():
    engines: list[Any] = []
    runtimes: list[OrderRuntime] = []
    halts: list[HaltAuthority] = []
    components: dict[str, Any] = {}

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        engine, sessions = create_engine_and_sessionmaker("sqlite+aiosqlite:///:memory:")
        engines.append(engine)
        await init_schema(engine)
        await _seed_activity(sessions)
        paper, broker, halt = _make_runtime(sessions, account_id=_ACCOUNT, environment="paper")
        runtimes.append(paper)
        halts.append(halt)
        application.state.leviathan = SimpleNamespace(orders=paper)
        components.update(runtime=paper, broker=broker, sessions=sessions)

        other_engine, other_sessions = create_engine_and_sessionmaker(
            "sqlite+aiosqlite:///:memory:"
        )
        engines.append(other_engine)
        await init_schema(other_engine)
        other, other_broker, other_halt = _make_runtime(
            other_sessions, account_id=_OTHER_ACCOUNT, environment="paper"
        )
        runtimes.append(other)
        halts.append(other_halt)
        components.update(other_runtime=other, other_broker=other_broker)

        demo_engine, demo_sessions = create_engine_and_sessionmaker("sqlite+aiosqlite:///:memory:")
        engines.append(demo_engine)
        await init_schema(demo_engine)
        demo, demo_broker, demo_halt = _make_runtime(
            demo_sessions, account_id=_ACCOUNT, environment="demo"
        )
        runtimes.append(demo)
        halts.append(demo_halt)
        components.update(demo_runtime=demo, demo_broker=demo_broker)
        application.state.activity_acceptance = components
        yield
        for runtime in reversed(runtimes):
            await runtime.close()
        for engine in reversed(engines):
            await engine.dispose()
        for halt_authority in halts:
            halt_authority.close()

    application = FastAPI(lifespan=lifespan)
    application.include_router(create_order_activity_router(enabled=True))
    application.state.activity_principal = _principal()

    @application.middleware("http")
    async def inject_principal(request: Request, call_next: Any):
        principal = application.state.activity_principal
        if principal is not _MISSING:
            request.state.trusted_principal = principal
        return await call_next(request)

    return application


@pytest.fixture
def client() -> Any:
    application = _app()
    with TestClient(application) as active:
        yield active


def _no_store(response: Any) -> None:
    assert "no-store" in response.headers.get("cache-control", "").lower()


def test_paper_operator_scope_is_derived_from_runtime_and_query_cannot_select_account(
    client: TestClient,
) -> None:
    response = client.get(_PATH)
    assert response.status_code == 200, response.text
    assert response.json()["account_id"] == _ACCOUNT
    assert response.json()["environment"] == "paper"

    invalid_scope = client.get(f"{_PATH}?account_id={_OTHER_ACCOUNT}")
    assert invalid_scope.status_code == 400
    assert invalid_scope.json() == {"error": {"code": "INVALID_ACTIVITY_QUERY"}}
    assert client.app.state.activity_acceptance["broker"].submit_calls == 0
    assert client.app.state.activity_acceptance["broker"].cancel_calls == 0
    assert client.app.state.activity_acceptance["broker"].read_calls == 0
    assert client.app.state.activity_acceptance["broker"].account_view_calls == 0


@pytest.mark.parametrize(
    ("principal", "expected"),
    [
        (_principal(roles=("researcher",)), {"error": {"code": "PAPER_ACTIVITY_FORBIDDEN"}}),
        (_principal(project_id="another-project"), {"error": {"code": "PAPER_ACTIVITY_FORBIDDEN"}}),
        (
            _principal(venue=BrokerVenue.IBKR_TWS.value),
            {"error": {"code": "PAPER_ACTIVITY_FORBIDDEN"}},
        ),
    ],
)
def test_principal_role_project_and_venue_are_scoped(
    client: TestClient, principal: TrustedPrincipalV1, expected: dict[str, object]
) -> None:
    client.app.state.activity_principal = principal
    response = client.get(_PATH)
    assert response.status_code == 403
    assert response.json() == expected
    _no_store(response)


def test_non_paper_runtime_is_forbidden_even_for_operator(client: TestClient) -> None:
    client.app.state.leviathan.orders = client.app.state.activity_acceptance["demo_runtime"]
    response = client.get(_PATH)
    assert response.status_code == 403
    assert response.json() == {"error": {"code": "PAPER_SCOPE_REQUIRED"}}
    _no_store(response)
    assert client.app.state.activity_acceptance["demo_broker"].submit_calls == 0


def test_activity_keeps_original_fills_and_corrections_separate_and_exact_net_units(
    client: TestClient,
) -> None:
    response = client.get(_PATH)
    assert response.status_code == 200, response.text
    payload = response.json()
    assert len(payload["items"]) <= 50
    assert set(payload) == {
        "schema_version",
        "evidence_label",
        "environment",
        "account_id",
        "high_water_sequence",
        "items",
        "net_filled_units",
        "next_cursor",
    }
    assert payload["evidence_label"] == "OMS ledger evidence"
    assert isinstance(payload["high_water_sequence"], int)
    assert 0 <= payload["high_water_sequence"] <= (1 << 53) - 1

    items = payload["items"]
    assert [item["kind"] for item in items].count("ORDER") == 3
    assert [item["kind"] for item in items].count("FILL") == 3
    assert [item["kind"] for item in items].count("FILL_CORRECTION") == 3
    sequences = [item["ledger_sequence"] for item in items]
    assert sequences == sorted(sequences)
    assert all(
        type(sequence) is int and 0 < sequence <= payload["high_water_sequence"]
        for sequence in sequences
    )

    fill = next(
        item["fill"]
        for item in items
        if item["kind"] == "FILL" and item["fill"]["execution_id"] == "execution-buy"
    )
    correction = next(
        item["correction"]
        for item in items
        if item["kind"] == "FILL_CORRECTION"
        and item["correction"]["execution_id"] == "execution-buy"
    )
    assert fill["quantity"] == "2.5"
    assert fill["price"] == "100.25"
    assert fill["occurred_at_utc"].endswith("Z")
    assert correction["revised_quantity"] == "1.5"
    assert correction["revised_price"] == "100.25"
    assert correction["occurred_at_utc"].endswith("Z")

    summary = payload["net_filled_units"]
    assert summary == [{"venue": "ALPACA", "instrument_id": "NQ-202612", "quantity": "1.25"}]
    orders = [item["order"] for item in items if item["kind"] == "ORDER"]
    by_side = {order["side"] + str(order["order_id"]): order for order in orders}
    assert sorted(order["filled_quantity"] for order in orders if order["side"] == "BUY") == ["1.5"]
    assert sorted(order["filled_quantity"] for order in orders if order["side"] == "SELL") == [
        "0",
        "0.25",
    ]
    assert all(order["created_at_utc"].endswith("Z") for order in orders)
    assert all(
        set(order)
        == {
            "order_id",
            "venue",
            "instrument_id",
            "side",
            "state",
            "quantity",
            "filled_quantity",
            "discrepancies",
            "created_at_utc",
        }
        for order in orders
    )
    assert len(by_side) == 3


def test_bounded_pagination_is_stable_at_one_high_water_mark(client: TestClient) -> None:
    first = client.get(_PATH, params={"limit": 2})
    assert first.status_code == 200
    payload = first.json()
    assert len(payload["items"]) == 2
    assert payload["next_cursor"] is not None
    high_water = payload["high_water_sequence"]

    # Append an order after page 1. The continuation stays pinned to page 1's HWM.
    runtime = client.app.state.leviathan.orders
    asyncio.run(runtime.actor.create(_request(intent="activity-late-after-hwm")))
    cursor = payload["next_cursor"]
    remaining: list[dict[str, Any]] = []
    while cursor is not None:
        page = client.get(_PATH, params={"limit": 2, "cursor": cursor})
        assert page.status_code == 200, page.text
        current = page.json()
        assert current["high_water_sequence"] == high_water
        assert len(current["items"]) <= 2
        remaining.extend(current["items"])
        cursor = current["next_cursor"]

    combined = payload["items"] + remaining
    sequences = [item["ledger_sequence"] for item in combined]
    assert sequences == sorted(sequences)
    assert len(sequences) == len(set(sequences))
    assert all(
        item.get("order", {}).get("order_id") != "activity-late-after-hwm" for item in combined
    )
    assert all(item["ledger_sequence"] <= high_water for item in combined)
    assert client.get(_PATH, params={"limit": 100}).status_code == 200


def test_more_than_100_net_summary_groups_returns_fixed_too_large(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    actor = client.app.state.leviathan.orders.actor

    async def synthetic_activity_page(
        environment: str,
        account_id: str,
        *,
        after_sequence: int,
        high_water_sequence: int | None,
        limit: int,
    ) -> ActivityLedgerPage:
        assert (environment, account_id) == ("paper", _ACCOUNT)
        assert after_sequence == 0
        assert high_water_sequence is None
        assert limit == 100
        items = tuple(
            ActivityOrderItem(
                ledger_sequence=index + 1,
                snapshot=OrderSnapshot(
                    order_id=f"activity-over-cap-order-{index:03}",
                    request=_request(
                        instrument_id=f"NQ-GROUP-{index:03}",
                        intent=f"activity-group-intent-{index:03}",
                    ),
                    state=OrderState.CREATED,
                    version=0,
                    venue_order_id=None,
                    filled_quantity=Decimal(0),
                    discrepancies=(),
                    submit_attempted=False,
                    cancel_attempted=False,
                ),
                created_at=_NOW,
            )
            for index in range(101)
        )
        groups = tuple(
            (BrokerVenue.ALPACA.value, f"NQ-GROUP-{index:03}", Decimal(0)) for index in range(101)
        )
        return ActivityLedgerPage(101, items, True, groups)

    monkeypatch.setattr(actor, "read_activity_page", synthetic_activity_page, raising=False)
    response = client.get(_PATH, params={"limit": 100})

    assert response.status_code == 413
    assert response.json() == {"error": {"code": "ACTIVITY_TOO_LARGE"}}
    broker = client.app.state.activity_acceptance["broker"]
    assert broker.submit_calls == broker.cancel_calls == 0
    assert broker.read_calls == broker.account_view_calls == 0


@pytest.mark.parametrize(
    "query",
    [
        "limit=0",
        "limit=101",
        "limit=1.5",
        "limit=1&limit=2",
        "cursor=",
        "account_id=activity-other-account",
        "limit=1&unlisted=synthetic-password-canary",
    ],
)
def test_invalid_query_is_fixed_and_content_free(client: TestClient, query: str) -> None:
    response = client.get(f"{_PATH}?{query}")
    assert response.status_code == 400
    assert response.json() == {"error": {"code": "INVALID_ACTIVITY_QUERY"}}
    assert "synthetic-password-canary" not in response.text


def test_lesson_19_free_text_query_is_neither_echoed_nor_logged(
    client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    secret_like = "my password is synthetic-canary-9182"
    response = client.get(f"{_PATH}?operator_note=my%20password%20is%20synthetic-canary-9182")

    assert response.status_code == 400
    assert response.json() == {"error": {"code": "INVALID_ACTIVITY_QUERY"}}
    assert secret_like not in response.text
    assert secret_like not in caplog.text
    assert "synthetic-canary-9182" not in caplog.text
    assert client.app.state.activity_acceptance["broker"].submit_calls == 0
    assert client.app.state.activity_acceptance["broker"].cancel_calls == 0


def test_cursor_tampering_and_cross_account_reuse_fail_closed(client: TestClient) -> None:
    first = client.get(_PATH, params={"limit": 1})
    token = first.json()["next_cursor"]
    assert isinstance(token, str) and len(token) <= 512
    assert re.fullmatch(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}", token)
    payload_part, signature_part = token.split(".", 1)
    changed_signature = ("A" if signature_part[0] != "A" else "B") + signature_part[1:]
    changed = f"{payload_part}.{changed_signature}"
    tampered = client.get(_PATH, params={"cursor": changed})
    assert tampered.status_code == 400
    assert tampered.json() == {"error": {"code": "INVALID_ACTIVITY_CURSOR"}}

    client.app.state.leviathan.orders = client.app.state.activity_acceptance["other_runtime"]
    cross_scope = client.get(_PATH, params={"cursor": token})
    assert cross_scope.status_code == 400
    assert cross_scope.json() == {"error": {"code": "INVALID_ACTIVITY_CURSOR"}}
    assert client.app.state.activity_acceptance["other_broker"].submit_calls == 0


def test_response_claims_only_ledger_evidence_and_never_echoes_request_text(
    client: TestClient,
) -> None:
    response = client.get(_PATH)
    assert response.status_code == 200
    body = response.text.casefold()
    assert "broker_confirmed" not in body
    assert "broker-confirmed" not in body
    assert "cost_basis" not in body
    assert "valuation" not in body
    assert "buying_power" not in body
    assert "reconciliation_freshness" not in body
    assert "activity-acceptance-operator" not in body
    assert "synthetic-password-canary" not in body
    for item in response.json()["items"]:
        assert "broker" not in item
        if item["kind"] == "ORDER":
            assert "broker" not in item["order"]
        elif item["kind"] == "FILL":
            assert "broker" not in item["fill"]
        else:
            assert "broker" not in item["correction"]

    canary_cursor = client.get(f"{_PATH}?cursor=synthetic-password-canary")
    assert canary_cursor.status_code == 400
    assert canary_cursor.json() == {"error": {"code": "INVALID_ACTIVITY_CURSOR"}}
    assert "synthetic-password-canary" not in canary_cursor.text


def _forged_app() -> FastAPI:
    application = FastAPI()
    application.include_router(create_order_activity_router(enabled=True))
    application.state.leviathan = SimpleNamespace(orders=None)
    application.state.activity_principal = object()

    @application.middleware("http")
    async def inject_forged(request: Request, call_next: Any):
        request.state.trusted_principal = application.state.activity_principal
        return await call_next(request)

    return application


def test_missing_and_forged_principals_have_uniform_401(client: TestClient) -> None:
    client.app.state.activity_principal = _MISSING
    missing = client.get(_PATH)
    forged = TestClient(_forged_app()).get(_PATH)
    assert missing.status_code == forged.status_code == 401
    assert missing.json() == forged.json() == {"error": {"code": "PRINCIPAL_UNTRUSTED"}}
    assert missing.text == forged.text
    _no_store(missing)
    _no_store(forged)


def test_every_response_and_unlisted_method_is_no_store(client: TestClient) -> None:
    success = client.get(_PATH)
    invalid_query = client.get(f"{_PATH}?limit=0")
    invalid_cursor = client.get(f"{_PATH}?cursor=bad")
    client.app.state.activity_principal = _principal(roles=("researcher",))
    forbidden = client.get(_PATH)
    client.app.state.activity_principal = _principal()
    client.app.state.leviathan.orders = None
    unavailable = client.get(_PATH)
    method_errors = [
        client.request(method, _PATH)
        for method in ("POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")
    ]

    responses = (success, invalid_query, invalid_cursor, forbidden, unavailable, *method_errors)
    assert [response.status_code for response in responses] == [
        200,
        400,
        400,
        403,
        503,
        405,
        405,
        405,
        405,
        405,
        405,
    ]
    for response in responses:
        _no_store(response)


def test_disabled_router_is_unavailable_and_still_no_store() -> None:
    app = FastAPI()
    app.include_router(create_order_activity_router())
    response = TestClient(app).get(_PATH)
    assert response.status_code == 503
    assert response.json() == {"error": {"code": "PAPER_ACTIVITY_UNAVAILABLE"}}
    _no_store(response)
