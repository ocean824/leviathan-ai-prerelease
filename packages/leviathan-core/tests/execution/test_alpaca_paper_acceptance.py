"""Independent OMS-ALPACA-001 contract checks using synthetic records only."""

from __future__ import annotations

import builtins
import copy
import http.client
import json
import os
import pickle
import socket
import urllib.request
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from leviathan_core.execution.broker_port_v1 import (
    BrokerEnvironment,
    BrokerOutcomeUnknown,
    BrokerPortError,
    BrokerPortV1,
    BrokerRejected,
    BrokerRejectionCode,
    BrokerUnknownCode,
    CancelResultV1,
    SubmitResultV1,
)
from leviathan_core.execution.brokers.alpaca_mapping import (
    AlpacaAssetMapV1,
    AlpacaAssetV1,
    AlpacaMappingError,
    AlpacaOrderSpecV1,
    map_alpaca_order,
)
from leviathan_core.execution.brokers.alpaca_paper import (
    AlpacaAccountRecordV1,
    AlpacaBaseUrlIdentity,
    AlpacaExecutionRecordV1,
    AlpacaOrderRecordV1,
    AlpacaPaperBrokerPortV1,
    AlpacaPaperError,
    AlpacaPositionRecordV1,
    AlpacaSessionBindingV1,
    AlpacaTradeUpdateV1,
    FakeAlpacaOMSEvidence,
    RecordedAlpacaTransport,
    RecordedHttpError,
)
from leviathan_core.execution.order_models import (
    BrokerObservation,
    Fill,
    FillCorrection,
    OrderRequest,
    OrderSnapshot,
    OrderState,
)

FIXTURES = Path(__file__).parent / "fixtures" / "alpaca_paper"
PAPER_ACCOUNT = "synthetic-paper-account-01"
BASE_TIME = datetime(2026, 10, 5, 15, tzinfo=UTC)


def _json(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _binding(**overrides: Any) -> AlpacaSessionBindingV1:
    data = _json("paper_session.json")["binding"]
    data.update(overrides)
    with suppress(ValueError):
        data["environment"] = BrokerEnvironment(data["environment"])
    with suppress(ValueError):
        data["base_url_identity"] = AlpacaBaseUrlIdentity(data["base_url_identity"])
    return AlpacaSessionBindingV1(**data)


def _assets(*, round_quantity: bool = False) -> AlpacaAssetMapV1:
    data = _json("paper_session.json")["assets"]
    assets = tuple(
        AlpacaAssetV1(
            instrument_id=item["instrument_id"],
            asset_id=item["asset_id"],
            symbol=item["symbol"],
            tick_size=Decimal(item["tick_size"]),
            lot_size=Decimal(item["lot_size"]),
            round_quantity_toward_zero=(round_quantity or item["round_quantity_toward_zero"]),
        )
        for item in data["items"]
    )
    return AlpacaAssetMapV1(revision=data["revision"], assets=assets)


def _request(which: str = "limit", **overrides: Any) -> OrderRequest:
    data = _json("orders.json")[which].copy()
    for name in ("quantity", "limit_price"):
        if data.get(name) is not None:
            data[name] = Decimal(data[name])
    data.update(overrides)
    data.setdefault("intent_idempotency_key", "synthetic-intent-1")
    data.setdefault("attempt", 1)
    return OrderRequest(**data)


def _order_record(
    *,
    state: str = "accepted",
    venue_order_id: str = "synthetic-venue-order-01",
    client_order_id: str = "synthetic-client-limit-001",
    account_id: str = PAPER_ACCOUNT,
    filled_quantity: Decimal = Decimal(0),
    asset_id: str | None = None,
    side: str | None = None,
    quantity: Decimal | None = None,
) -> AlpacaOrderRecordV1:
    reservation: dict[str, Any] = {}
    if asset_id is not None or side is not None or quantity is not None:
        reservation = {"asset_id": asset_id, "side": side, "quantity": quantity}
    return AlpacaOrderRecordV1(
        venue_order_id=venue_order_id,
        client_order_id=client_order_id,
        account_id=account_id,
        state=state,
        observed_at=BASE_TIME,
        filled_quantity=filled_quantity,
        broker_sequence=7,
        **reservation,
    )


def _account(
    *,
    revision: int = 10,
    venue_time_ns: int | None = 100,
    open_orders: tuple[AlpacaOrderRecordV1, ...] = (),
    positions: tuple[AlpacaPositionRecordV1, ...] = (),
    executions: tuple[AlpacaExecutionRecordV1, ...] = (),
    executions_complete: bool = True,
) -> AlpacaAccountRecordV1:
    source = _json("zero_account.json")
    return AlpacaAccountRecordV1(
        account_id=source["account_id"],
        broker_revision=revision,
        open_orders=open_orders,
        positions=positions,
        observed_at=datetime.fromisoformat(source["observed_at"].replace("Z", "+00:00")),
        venue_time_ns=venue_time_ns,
        executions_since=datetime.fromisoformat(source["executions_since"].replace("Z", "+00:00")),
        executions=executions,
        executions_complete=executions_complete,
    )


def _port(
    transport: RecordedAlpacaTransport,
    *,
    binding: AlpacaSessionBindingV1 | None = None,
    assets: AlpacaAssetMapV1 | None = None,
    oms_evidence: FakeAlpacaOMSEvidence | None = None,
    now_ns: int = 100,
    settle_window: timedelta = timedelta(seconds=2),
) -> AlpacaPaperBrokerPortV1:
    port = AlpacaPaperBrokerPortV1(
        binding or _binding(),
        assets or _assets(),
        transport,
        oms_evidence=oms_evidence or FakeAlpacaOMSEvidence(),
        clock_ns=lambda: now_ns,
        settle_window=settle_window,
    )
    assert isinstance(port, BrokerPortV1)
    return port


class _Permit:
    def __init__(
        self,
        request: OrderRequest,
        *,
        order_id: str = "synthetic-local-order-01",
        expected_order_id: str = "synthetic-local-order-01",
        revision: int = 10,
    ) -> None:
        self.order_id = order_id
        self.expected_order_id = expected_order_id
        self.digest = request.digest
        self.revision = revision
        self.consumptions: list[tuple[str, str, int]] = []

    def consume(self, order_id: str, request_digest: str, expected_revision: int) -> None:
        if (
            self.consumptions
            or order_id != self.expected_order_id
            or (order_id, request_digest, expected_revision)
            != (
                self.order_id,
                self.digest,
                self.revision,
            )
        ):
            raise ValueError("INVALID_PERMIT")
        self.consumptions.append((order_id, request_digest, expected_revision))


@pytest.fixture(autouse=True)
def forbid_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail immediately if adapter/tests try any network path."""

    def denied(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("network access is forbidden in OMS-ALPACA-001 acceptance")

    monkeypatch.setattr(socket.socket, "connect", denied)
    monkeypatch.setattr(socket.socket, "connect_ex", denied)
    monkeypatch.setattr(socket, "create_connection", denied)
    monkeypatch.setattr(http.client.HTTPConnection, "connect", denied)
    monkeypatch.setattr(urllib.request, "urlopen", denied)


def test_fixture_provenance_is_synthetic_and_transport_is_exact_recorded_type() -> None:
    assert {path.name for path in FIXTURES.iterdir()} == {
        "paper_session.json",
        "orders.json",
        "zero_account.json",
        "trade_updates.json",
    }
    for path in FIXTURES.glob("*.json"):
        assert "synthetic" in path.read_text(encoding="utf-8").lower()
    with pytest.raises(AlpacaPaperError, match="RECORDED_TRANSPORT_REQUIRED"):
        AlpacaPaperBrokerPortV1(
            _binding(),
            _assets(),
            object(),
            oms_evidence=FakeAlpacaOMSEvidence(),
            clock_ns=lambda: 100,
        )  # type: ignore[arg-type]


def test_session_binding_is_closed_paper_and_revision_bound() -> None:
    with pytest.raises(AlpacaPaperError, match="PAPER_SESSION_REQUIRED"):
        _binding(environment=BrokerEnvironment.LIVE)
    with pytest.raises(AlpacaPaperError, match="PAPER_SESSION_REQUIRED"):
        _binding(base_url_identity="https://live.example.invalid")
    with pytest.raises(AlpacaPaperError, match="PAPER_SESSION_REQUIRED"):
        _binding(api_version="v1")
    with pytest.raises(AlpacaPaperError, match="INVALID_CREDENTIAL_REFERENCE"):
        _binding(credential_ref="vault://leviathan-ai/live/alpaca/KEY")
    with pytest.raises(AlpacaPaperError, match="INVALID_CREDENTIAL_REFERENCE"):
        _binding(credential_ref="paper-secret-value")
    assets = _assets()
    mismatched_assets = AlpacaAssetMapV1("different-map-revision", assets.assets)
    with pytest.raises(AlpacaPaperError, match="MAPPING_REVISION_MISMATCH"):
        AlpacaPaperBrokerPortV1(
            _binding(),
            mismatched_assets,
            RecordedAlpacaTransport(),
            oms_evidence=FakeAlpacaOMSEvidence(),
            clock_ns=lambda: 1,
        )
    # A credential reference is inert metadata. No file/credential provider is touched.
    binding = _binding(credential_ref="vault://leviathan-ai/development/alpaca/SYNTHETIC_TEST")
    port = _port(RecordedAlpacaTransport(), binding=binding)
    assert port.venue.environment is BrokerEnvironment.PAPER
    assert port.venue.account_id == PAPER_ACCOUNT


def test_submit_rejects_live_demo_wrong_account_and_wrong_venue_before_transport() -> None:
    for request in (
        _request(environment="demo"),
        _request(account_id="different-paper-account"),
        _request(venue="OTHER"),
    ):
        fake = RecordedAlpacaTransport()
        result = _port(fake).submit(request, _Permit(request), 10)
        result.assert_sealed()
        assert result.state is OrderState.REJECTED
        assert fake.account_lookup_ids == []
        assert fake.client_lookup_ids == []
        assert fake.post_payloads == []


def test_mapping_emits_only_exact_market_and_limit_fields() -> None:
    session = _json("paper_session.json")
    assets = _assets()
    market = _request("market")
    mapped_market = map_alpaca_order(
        AlpacaOrderSpecV1(
            instrument_id=market.instrument_id,
            native_contract_id=market.native_contract_id,
            side=market.side,
            quantity=market.quantity,
            order_type=market.order_type,
            time_in_force=market.time_in_force,
            client_order_id=market.client_order_id,
        ),
        assets,
    )
    assert mapped_market.to_wire() == {
        "symbol": "AAPL",
        "qty": "3",
        "side": "buy",
        "type": "market",
        "time_in_force": "day",
        "client_order_id": "synthetic-client-market-001",
        "order_class": "simple",
        "extended_hours": False,
    }
    limit = _request()
    mapped_limit = map_alpaca_order(
        AlpacaOrderSpecV1(
            instrument_id=limit.instrument_id,
            native_contract_id=limit.native_contract_id,
            side=limit.side,
            quantity=limit.quantity,
            order_type=limit.order_type,
            time_in_force=limit.time_in_force,
            client_order_id=limit.client_order_id,
            limit_price=limit.limit_price,
        ),
        assets,
    )
    assert mapped_limit.to_wire()["limit_price"] == "123.45"
    assert len(session["assets"]["items"]) == 2


def test_optional_missing_client_order_id_is_rejected_before_transport() -> None:
    request = _request("market", client_order_id=None)
    fake = RecordedAlpacaTransport()
    permit = _Permit(request)

    result = _port(fake).submit(request, permit, 10)

    result.assert_sealed()
    assert result.state is OrderState.REJECTED
    assert result.rejection_code is BrokerRejectionCode.INVALID_ORDER
    assert permit.consumptions == []
    assert fake.account_lookup_ids == []
    assert fake.client_lookup_ids == []
    assert fake.post_payloads == []


def test_mapping_rejects_unsupported_types_classes_tif_instruments_and_price_quantity() -> None:
    common: dict[str, Any] = {
        "instrument_id": "equity-AAPL",
        "native_contract_id": "asset-AAPL",
        "side": "BUY",
        "quantity": Decimal(3),
        "order_type": "LIMIT",
        "time_in_force": "DAY",
        "client_order_id": "synthetic-client-01",
        "limit_price": Decimal("123.45"),
    }
    for order_type in ("STOP", "STOP_LIMIT"):
        with pytest.raises(AlpacaMappingError) as caught:
            AlpacaOrderSpecV1(**{**common, "order_type": order_type})
        assert caught.value.code == "UNSUPPORTED_ORDER_TYPE"
    for order_class in ("bracket", "oco", "oto"):
        with pytest.raises(AlpacaMappingError) as caught:
            AlpacaOrderSpecV1(**{**common, "order_class": order_class})
        assert caught.value.code == "UNSUPPORTED_ORDER_CLASS"
    for invalid in (
        {"time_in_force": "GTD"},
        {"instrument_kind": "CRYPTO"},
        {"instrument_kind": "OPTION"},
        {"extended_hours": True},
        {"notional": Decimal(100)},
    ):
        with pytest.raises(AlpacaMappingError):
            AlpacaOrderSpecV1(**{**common, **invalid})
    with pytest.raises(AlpacaMappingError) as caught:
        map_alpaca_order(
            AlpacaOrderSpecV1(**{**common, "limit_price": Decimal("123.451")}), _assets()
        )
    assert caught.value.code == "TICK_VIOLATION"
    with pytest.raises(AlpacaMappingError) as caught:
        map_alpaca_order(AlpacaOrderSpecV1(**{**common, "quantity": Decimal("3.5")}), _assets())
    assert caught.value.code == "LOT_VIOLATION"
    with pytest.raises(AlpacaMappingError) as caught:
        AlpacaAssetV1("equity-fraction", "fraction-asset", "FRAC", Decimal("0.01"), Decimal("0.1"))
    assert caught.value.code == "FRACTIONAL_UNSUPPORTED"


def test_quantity_rounds_toward_zero_only_when_mapping_explicitly_allows_it() -> None:
    request = _request(quantity=Decimal("3.9"))
    fake = RecordedAlpacaTransport()
    port = _port(fake, assets=_assets(round_quantity=True))
    permit = _Permit(request)
    fake.queue_account(_account())
    fake.queue_client_read(None)
    fake.queue_post(_order_record(client_order_id=request.client_order_id))
    assert port.submit(request, permit, 10).state is OrderState.WORKING
    assert fake.post_payloads[0].to_wire()["qty"] == "3"
    assert fake.post_payloads[0].to_wire()["limit_price"] == "123.45"


def test_128_character_client_id_is_sent_verbatim_without_normalization() -> None:
    client_id = "x" * 128
    request = _request(client_order_id=client_id)
    fake = RecordedAlpacaTransport()
    fake.queue_account(_account())
    fake.queue_client_read(None)
    fake.queue_post(_order_record(client_order_id=client_id))
    result = _port(fake).submit(request, _Permit(request), 10)
    assert result.state is OrderState.WORKING
    assert fake.post_payloads[0].client_order_id == client_id
    assert fake.post_payloads[0].to_wire()["client_order_id"] == client_id


def test_permit_must_be_valid_and_is_consumed_before_any_transport() -> None:
    request = _request()
    for permit, expected_revision in (
        (_Permit(request, order_id="wrong-order"), 10),
        (_Permit(request), 11),
    ):
        fake = RecordedAlpacaTransport()
        with pytest.raises(BrokerRejected) as rejected:
            _port(fake).submit(request, permit, expected_revision)
        assert rejected.value.code == BrokerRejectionCode.INVALID_ORDER.value
        assert fake.account_lookup_ids == []
        assert fake.post_payloads == []
    fake = RecordedAlpacaTransport()
    permit = _Permit(request)
    port = _port(fake)
    events: list[str] = []
    original_consume = permit.consume

    def consume(order_id: str, digest: str, revision: int) -> None:
        events.append("permit")
        original_consume(order_id, digest, revision)

    permit.consume = consume  # type: ignore[method-assign]
    original_account = fake.get_account_view

    def account(account_id: str) -> AlpacaAccountRecordV1:
        events.append("account")
        return original_account(account_id)

    fake.get_account_view = account  # type: ignore[method-assign]
    fake.queue_account(_account())
    fake.queue_client_read(None)
    fake.queue_post(_order_record(client_order_id=request.client_order_id))
    port.submit(request, permit, 10)
    assert events[:2] == ["permit", "account"]
    assert permit.consumptions == [(permit.order_id, request.digest, 10)]
    with pytest.raises(BrokerRejected) as reused:
        port.submit(request, permit, 10)
    assert reused.value.code == BrokerRejectionCode.INVALID_ORDER.value
    assert fake.post_payloads


def test_missing_permit_or_bad_digest_is_rejected_without_transport() -> None:
    request = _request()
    fake = RecordedAlpacaTransport()
    with pytest.raises(BrokerRejected):
        _port(fake).submit(request, None, 10)  # type: ignore[arg-type]
    assert fake.account_lookup_ids == []
    permit = _Permit(request)
    permit.digest = "f" * 64
    with pytest.raises(BrokerRejected):
        _port(fake).submit(request, permit, 10)  # type: ignore[arg-type]
    assert fake.post_payloads == []


def test_mandatory_preflight_matches_revision_clock_and_zero_order_snapshot() -> None:
    request = _request()
    for revision, venue_time, expected_unknown in (
        (9, 100, True),
        (10, None, True),
        (10, 100, False),
    ):
        fake = RecordedAlpacaTransport()
        port = _port(fake)
        fake.queue_account(_account(revision=revision, venue_time_ns=venue_time))
        if not expected_unknown:
            fake.queue_client_read(None)
            fake.queue_post(_order_record(client_order_id=request.client_order_id))
        if expected_unknown:
            with pytest.raises(BrokerOutcomeUnknown) as caught:
                port.submit(request, _Permit(request), 10)
            assert caught.value.code == BrokerUnknownCode.UNKNOWN_SUBMIT.value
        else:
            result = port.submit(request, _Permit(request), 10)
            result.assert_sealed()
            assert result.state is OrderState.WORKING
        assert len(fake.post_payloads) == (0 if expected_unknown else 1)


def test_249ms_skew_dispatches_250ms_or_unknown_skew_blocks() -> None:
    request = _request()
    for now_ns, venue_ns, should_submit in (
        (249_000_100, 100, True),
        (250_000_100, 100, False),
        (100, None, False),
    ):
        fake = RecordedAlpacaTransport()
        port = _port(fake, now_ns=now_ns)
        fake.queue_account(_account(venue_time_ns=venue_ns))
        if should_submit:
            fake.queue_client_read(None)
            fake.queue_post(_order_record(client_order_id=request.client_order_id))
            assert port.submit(request, _Permit(request), 10).state is OrderState.WORKING
        else:
            with pytest.raises(BrokerOutcomeUnknown):
                port.submit(request, _Permit(request), 10)
        assert bool(fake.post_payloads) is should_submit


def test_duplicate_id_in_open_orders_executions_exact_lookup_and_post_duplicate_reconcile() -> None:
    request = _request()
    duplicate = _order_record(state="new", client_order_id=request.client_order_id)
    execution = AlpacaExecutionRecordV1(
        execution_id="synthetic-execution-duplicate",
        venue_order_id="synthetic-venue-order-01",
        client_order_id=request.client_order_id,
        account_id=PAPER_ACCOUNT,
        asset_id="asset-AAPL",
        side="BUY",
        quantity=Decimal(1),
        price=Decimal("123.45"),
        executed_at=BASE_TIME,
    )
    for snapshot in (_account(open_orders=(duplicate,)), _account(executions=(execution,))):
        fake = RecordedAlpacaTransport()
        fake.queue_account(snapshot)
        result = _port(fake).submit(request, _Permit(request), 10)
        result.assert_sealed()
        assert result.rejection_code is BrokerRejectionCode.DUPLICATE_CLIENT_ORDER_ID
        assert not fake.client_lookup_ids and not fake.post_payloads

    fake = RecordedAlpacaTransport()
    fake.queue_account(_account())
    fake.queue_client_read(duplicate)
    result = _port(fake).submit(request, _Permit(request), 10)
    assert result.rejection_code is BrokerRejectionCode.DUPLICATE_CLIENT_ORDER_ID
    assert fake.client_lookup_ids == [request.client_order_id]
    assert not fake.post_payloads

    # The venue's duplicate response is reconciled by the exact client ID and never retried.
    fake = RecordedAlpacaTransport()
    fake.queue_account(_account())
    fake.queue_client_read(None)
    fake.queue_post(RecordedHttpError(409, reason_code="DUPLICATE_CLIENT_ORDER_ID"))
    fake.queue_client_read(duplicate)
    result = _port(fake).submit(request, _Permit(request), 10)
    assert result.rejection_code is BrokerRejectionCode.DUPLICATE_CLIENT_ORDER_ID
    assert fake.client_lookup_ids == [request.client_order_id, request.client_order_id]
    assert len(fake.post_payloads) == 1


def test_lost_submit_5xx_reset_and_429_are_unknown_with_no_retry() -> None:
    request = _request()
    failures = (
        TimeoutError("synthetic timeout canary"),
        RecordedHttpError(503, response_body={"private": "synthetic-body-canary"}),
        ConnectionResetError("synthetic reset canary"),
        RecordedHttpError(429, response_body="synthetic 429 body canary"),
    )
    for failure in failures:
        fake = RecordedAlpacaTransport()
        fake.queue_account(_account())
        fake.queue_client_read(None)
        fake.queue_post(failure)
        with pytest.raises(BrokerOutcomeUnknown) as caught:
            _port(fake).submit(request, _Permit(request), 10)
        assert caught.value.code == BrokerUnknownCode.UNKNOWN_SUBMIT.value
        assert len(fake.post_payloads) == 1
        assert "canary" not in str(caught.value).lower()
        assert "canary" not in repr(caught.value.args).lower()


def test_unknown_submit_marks_client_identity_attempted_and_refuses_resubmit() -> None:
    request = _request()
    fake = RecordedAlpacaTransport()
    port = _port(fake)
    fake.queue_account(_account(revision=10))
    fake.queue_client_read(None)
    fake.queue_post(TimeoutError("synthetic lost response"))
    with pytest.raises(BrokerOutcomeUnknown):
        port.submit(request, _Permit(request), 10)
    fake.queue_account(_account(revision=11))
    fake.queue_client_read(None)
    with pytest.raises(BrokerOutcomeUnknown):
        port.submit(request, _Permit(request, revision=11), 11)
    assert len(fake.post_payloads) == 1


def test_sell_quantity_is_bounded_by_long_position_net_same_asset_sell_reservations() -> None:
    open_orders = (
        _order_record(
            venue_order_id="synthetic-aapl-sell-reservation",
            client_order_id="synthetic-aapl-sell-reservation-client",
            asset_id="asset-AAPL",
            side="SELL",
            quantity=Decimal(3),
        ),
        _order_record(
            venue_order_id="synthetic-aapl-buy-open",
            client_order_id="synthetic-aapl-buy-open-client",
            asset_id="asset-AAPL",
            side="BUY",
            quantity=Decimal(100),
        ),
        _order_record(
            venue_order_id="synthetic-msft-sell-open",
            client_order_id="synthetic-msft-sell-open-client",
            asset_id="asset-MSFT",
            side="SELL",
            quantity=Decimal(100),
        ),
    )
    snapshot = _account(
        positions=(AlpacaPositionRecordV1("asset-AAPL", Decimal(10)),),
        open_orders=open_orders,
    )

    allowed_request = _request(
        "market",
        side="SELL",
        quantity=Decimal(7),
        client_order_id="synthetic-sell-at-reservation-limit",
    )
    fake = RecordedAlpacaTransport()
    fake.queue_account(snapshot)
    fake.queue_client_read(None)
    fake.queue_post(_order_record(client_order_id=allowed_request.client_order_id))
    result = _port(fake).submit(allowed_request, _Permit(allowed_request), 10)
    result.assert_sealed()
    assert result.state is OrderState.WORKING
    assert fake.post_payloads[0].to_wire()["qty"] == "7"
    assert len(fake.post_payloads) == 1

    excessive_request = _request(
        "market",
        side="SELL",
        quantity=Decimal(8),
        client_order_id="synthetic-sell-over-reservation-limit",
    )
    fake = RecordedAlpacaTransport()
    fake.queue_account(snapshot)
    port = _port(fake)
    with pytest.raises(BrokerRejected) as blocked:
        port.submit(excessive_request, _Permit(excessive_request), 10)
    assert blocked.value.code == BrokerRejectionCode.INVALID_ORDER.value
    assert fake.post_payloads == []


def test_sell_without_a_sufficient_position_or_with_incomplete_open_order_detail_fails_closed() -> (
    None
):
    request = _request(
        "market",
        side="SELL",
        quantity=Decimal(1),
        client_order_id="synthetic-sell-without-long-inventory",
    )
    fake = RecordedAlpacaTransport()
    fake.queue_account(_account(positions=(), open_orders=()))
    with pytest.raises(BrokerRejected) as blocked:
        _port(fake).submit(request, _Permit(request), 10)
    assert blocked.value.code == BrokerRejectionCode.INVALID_ORDER.value
    assert fake.post_payloads == []

    # Legacy construction allows an open order without reservation metadata. It
    # cannot safely be treated as a BUY or ignored when evaluating a SELL.
    incomplete_open_order = _order_record(
        venue_order_id="synthetic-open-order-without-reservation-data",
        client_order_id="synthetic-open-order-incomplete-client",
    )
    fake = RecordedAlpacaTransport()
    fake.queue_account(
        _account(
            positions=(AlpacaPositionRecordV1("asset-AAPL", Decimal(10)),),
            open_orders=(incomplete_open_order,),
        )
    )
    with pytest.raises(BrokerOutcomeUnknown) as unknown:
        _port(fake).submit(request, _Permit(request), 10)
    assert unknown.value.code == BrokerUnknownCode.UNKNOWN_SUBMIT.value
    assert fake.post_payloads == []
    assert fake.client_lookup_ids == []


@pytest.mark.parametrize("missing_detail", ("asset_id", "side", "quantity"))
def test_sell_with_partially_missing_reservation_detail_is_unknown_before_post(
    missing_detail: str,
) -> None:
    request = _request(
        "market",
        side="SELL",
        quantity=Decimal(1),
        client_order_id=f"synthetic-sell-incomplete-{missing_detail}",
    )
    open_order = _order_record(
        venue_order_id=f"synthetic-open-order-{missing_detail}",
        client_order_id=f"synthetic-open-client-{missing_detail}",
        asset_id="asset-AAPL",
        side="SELL",
        quantity=Decimal(2),
    )
    # Simulate a malformed/incomplete transport record reaching the adapter after
    # the immutable record constructor boundary.
    object.__setattr__(open_order, missing_detail, None)
    fake = RecordedAlpacaTransport()
    fake.queue_account(
        _account(
            positions=(AlpacaPositionRecordV1("asset-AAPL", Decimal(10)),),
            open_orders=(open_order,),
        )
    )
    with pytest.raises(BrokerOutcomeUnknown) as unknown:
        _port(fake).submit(request, _Permit(request), 10)
    assert unknown.value.code == BrokerUnknownCode.UNKNOWN_SUBMIT.value
    assert fake.post_payloads == []
    assert fake.client_lookup_ids == []


@pytest.mark.parametrize("first_post_unknown", (False, True), ids=("accepted", "unknown"))
@pytest.mark.parametrize("restart_adapter", (False, True), ids=("same-port", "restarted-port"))
def test_distinct_sell_after_first_sell_uses_durable_open_order_reservation(
    first_post_unknown: bool,
    restart_adapter: bool,
) -> None:
    """An unchanged long position cannot fund a second SELL over the first order."""
    first = _request(
        "market",
        side="SELL",
        quantity=Decimal(6),
        client_order_id="synthetic-first-sell-001",
        intent_idempotency_key="synthetic-first-sell-intent-001",
    )
    second = _request(
        "market",
        side="SELL",
        quantity=Decimal(5),
        client_order_id="synthetic-second-sell-002",
        intent_idempotency_key="synthetic-second-sell-intent-002",
    )
    first_order = _order_record(
        state="accepted",
        venue_order_id="synthetic-first-sell-venue-001",
        client_order_id=first.client_order_id,
        asset_id="asset-AAPL",
        side="SELL",
        quantity=Decimal(6),
    )
    unchanged_snapshot = _account(
        positions=(AlpacaPositionRecordV1("asset-AAPL", Decimal(10)),),
        open_orders=(),
    )
    oms_evidence = FakeAlpacaOMSEvidence()
    fake = RecordedAlpacaTransport()
    fake.queue_account(unchanged_snapshot)
    fake.queue_client_read(None)
    if first_post_unknown:
        fake.queue_post(TimeoutError("synthetic first sell response lost"))
    else:
        fake.queue_post(first_order)

    first_port = _port(fake, oms_evidence=oms_evidence)
    first_permit = _Permit(
        first,
        order_id="synthetic-local-first-sell-001",
        expected_order_id="synthetic-local-first-sell-001",
    )
    if first_post_unknown:
        with pytest.raises(BrokerOutcomeUnknown) as unknown:
            first_port.submit(first, first_permit, 10)
        assert unknown.value.code == BrokerUnknownCode.UNKNOWN_SUBMIT.value
    else:
        result = first_port.submit(first, first_permit, 10)
        result.assert_sealed()
        assert result.state is OrderState.WORKING

    # The broker snapshot remains exactly unchanged and omits the first order.
    # Shared OMS evidence must retain the reservation/uncertainty across a port
    # reconstruction, so another client ID cannot use the same long position.
    fake.queue_account(unchanged_snapshot)
    fake.queue_client_read(None)
    second_port = (
        _port(fake, oms_evidence=oms_evidence) if restart_adapter else first_port
    )
    second_permit = _Permit(
        second,
        order_id="synthetic-local-second-sell-002",
        expected_order_id="synthetic-local-second-sell-002",
    )
    with pytest.raises(BrokerRejected) as blocked:
        second_port.submit(second, second_permit, 10)
    assert blocked.value.code == BrokerRejectionCode.INVALID_ORDER.value
    assert [payload.client_order_id for payload in fake.post_payloads] == [
        first.client_order_id
    ]
    assert fake.client_lookup_ids[0] == first.client_order_id
    assert set(fake.client_lookup_ids) <= {first.client_order_id, second.client_order_id}
    assert all(account_id == PAPER_ACCOUNT for account_id in fake.account_lookup_ids)


@pytest.mark.parametrize(
    ("field", "request_overrides", "supplied_venue_order_id"),
    (
        ("venue_order_id", {}, "synthetic-venue-order-other"),
        (
            "client_order_id",
            {"client_order_id": "synthetic-client-order-other"},
            "synthetic-venue-order-confirmed",
        ),
    ),
)
def test_cancel_refuses_supplied_identity_when_exact_client_lookup_disagrees(
    field: str,
    request_overrides: dict[str, str],
    supplied_venue_order_id: str,
) -> None:
    request = _request(**request_overrides)
    order = OrderSnapshot(
        order_id="synthetic-local-order-01",
        request=request,
        state=OrderState.WORKING,
        version=1,
        venue_order_id=supplied_venue_order_id,
        filled_quantity=Decimal(0),
        discrepancies=(),
        submit_attempted=True,
        cancel_attempted=False,
    )
    record_venue_id = (
        supplied_venue_order_id if field == "client_order_id" else "synthetic-venue-order-confirmed"
    )
    confirmed_record = _order_record(
        venue_order_id=record_venue_id,
        client_order_id="synthetic-client-limit-001",
        account_id=PAPER_ACCOUNT,
    )
    fake = RecordedAlpacaTransport()
    fake.queue_account(_account(open_orders=(confirmed_record,)))

    with pytest.raises(BrokerRejected) as refused:
        _port(fake).cancel(order)

    assert refused.value.code == BrokerRejectionCode.INVALID_ORDER.value
    assert fake.account_lookup_ids == [PAPER_ACCOUNT]
    assert fake.delete_ids == []


@pytest.mark.parametrize("incomplete", (False, True), ids=("missing-read", "incomplete-view"))
def test_cancel_unavailable_or_incomplete_account_evidence_is_unknown(incomplete: bool) -> None:
    request = _request()
    order = OrderSnapshot(
        order_id="synthetic-local-order-01",
        request=request,
        state=OrderState.WORKING,
        version=1,
        venue_order_id="synthetic-venue-order-01",
        filled_quantity=Decimal(0),
        discrepancies=(),
        submit_attempted=True,
        cancel_attempted=False,
    )
    fake = RecordedAlpacaTransport()
    if incomplete:
        fake.queue_account(_account(executions_complete=False))

    with pytest.raises(BrokerOutcomeUnknown) as caught:
        _port(fake).cancel(order)

    assert caught.value.code == BrokerUnknownCode.UNKNOWN_CANCEL.value
    assert fake.delete_ids == []


@pytest.mark.parametrize(
    ("field", "contradiction"),
    (
        ("asset_id", "asset-MSFT"),
        ("side", "SELL"),
        ("quantity", Decimal(2)),
    ),
)
def test_accepted_post_with_contradictory_native_order_details_is_unknown_and_discrepant(
    field: str,
    contradiction: str | Decimal,
) -> None:
    request = _request("market")
    details: dict[str, Any] = {
        "asset_id": "asset-AAPL",
        "side": "BUY",
        "quantity": Decimal(3),
    }
    details[field] = contradiction
    fake = RecordedAlpacaTransport()
    fake.queue_account(_account())
    fake.queue_client_read(None)
    fake.queue_post(
        _order_record(
            state="accepted",
            client_order_id=request.client_order_id,
            **details,
        )
    )
    port = _port(fake)

    with pytest.raises(BrokerOutcomeUnknown) as unknown:
        port.submit(request, _Permit(request), 10)

    assert unknown.value.code == BrokerUnknownCode.UNKNOWN_SUBMIT.value
    assert port.discrepancies == ("CONFLICT",)
    assert len(fake.post_payloads) == 1
    assert fake.post_payloads[0].to_wire()["symbol"] == "AAPL"


def test_shared_oms_evidence_rejects_cross_port_revision_regression_before_third_post() -> None:
    first = _request(
        "market",
        side="SELL",
        quantity=Decimal(6),
        client_order_id="synthetic-revision-sell-first",
        intent_idempotency_key="synthetic-revision-sell-first-intent",
    )
    second = _request(
        "market",
        side="SELL",
        quantity=Decimal(3),
        client_order_id="synthetic-revision-sell-second",
        intent_idempotency_key="synthetic-revision-sell-second-intent",
    )
    stale = _request(
        "market",
        side="SELL",
        quantity=Decimal(5),
        client_order_id="synthetic-revision-sell-stale-third",
        intent_idempotency_key="synthetic-revision-sell-stale-intent",
    )
    unchanged_long = (AlpacaPositionRecordV1("asset-AAPL", Decimal(10)),)
    first_order = _order_record(
        state="accepted",
        venue_order_id="synthetic-revision-sell-first-venue",
        client_order_id=first.client_order_id,
        asset_id="asset-AAPL",
        side="SELL",
        quantity=Decimal(6),
    )
    first_open = _order_record(
        state="accepted",
        venue_order_id=first_order.venue_order_id,
        client_order_id=first.client_order_id,
        filled_quantity=Decimal(0),
        asset_id="asset-AAPL",
        side="SELL",
        quantity=Decimal(6),
    )
    evidence = FakeAlpacaOMSEvidence()
    fake = RecordedAlpacaTransport()

    # Port 1 observes rev10 with a long position of 10 and no orders, then
    # submits SELL6.
    fake.queue_account(_account(revision=10, positions=unchanged_long, open_orders=()))
    fake.queue_client_read(None)
    fake.queue_post(first_order)
    first_port = _port(fake, oms_evidence=evidence)
    first_result = first_port.submit(
        first,
        _Permit(
            first,
            order_id="synthetic-local-revision-order-1",
            expected_order_id="synthetic-local-revision-order-1",
            revision=10,
        ),
        10,
    )
    assert first_result.state is OrderState.WORKING

    # Port 2 sees rev11: the long position is still 10 and the first SELL6 is
    # still fully open (filled 0), leaving exactly 4 shares available. A
    # distinct SELL3 may be accepted.
    fake.queue_account(_account(revision=11, positions=unchanged_long, open_orders=(first_open,)))
    fake.queue_client_read(None)
    second_order = _order_record(
        state="accepted",
        venue_order_id="synthetic-revision-sell-second-venue",
        client_order_id=second.client_order_id,
        asset_id="asset-AAPL",
        side="SELL",
        quantity=Decimal(3),
    )
    fake.queue_post(second_order)
    second_port = _port(fake, oms_evidence=evidence)
    second_result = second_port.submit(
        second,
        _Permit(
            second,
            order_id="synthetic-local-revision-order-2",
            expected_order_id="synthetic-local-revision-order-2",
            revision=11,
        ),
        11,
    )
    assert second_result.state is OrderState.WORKING

    # Port 3 has no local revision history. Shared OMS evidence must still
    # remember that rev11 was observed and reject a stale rev10 snapshot before
    # any third POST.
    fake.queue_account(_account(revision=10, positions=unchanged_long, open_orders=()))
    fake.queue_client_read(None)
    stale_port = _port(fake, oms_evidence=evidence)
    with pytest.raises(BrokerOutcomeUnknown) as regressed:
        stale_port.submit(
            stale,
            _Permit(
                stale,
                order_id="synthetic-local-revision-order-3",
                expected_order_id="synthetic-local-revision-order-3",
                revision=10,
            ),
            10,
        )

    assert regressed.value.code == BrokerUnknownCode.UNKNOWN_SUBMIT.value
    assert [payload.client_order_id for payload in fake.post_payloads] == [
        first.client_order_id,
        second.client_order_id,
    ]


def test_shared_oms_evidence_rejects_conflicting_complete_view_at_same_revision() -> None:
    first = _request(
        "market",
        side="SELL",
        quantity=Decimal(1),
        client_order_id="synthetic-same-revision-first",
        intent_idempotency_key="synthetic-same-revision-first-intent",
    )
    second = _request(
        "market",
        side="SELL",
        quantity=Decimal(1),
        client_order_id="synthetic-same-revision-second",
        intent_idempotency_key="synthetic-same-revision-second-intent",
    )
    evidence = FakeAlpacaOMSEvidence()
    fake = RecordedAlpacaTransport()
    fake.queue_account(
        _account(
            revision=10,
            positions=(AlpacaPositionRecordV1("asset-AAPL", Decimal(10)),),
            open_orders=(),
        )
    )
    fake.queue_client_read(None)
    fake.queue_post(
        _order_record(
            state="accepted",
            venue_order_id="synthetic-same-revision-first-venue",
            client_order_id=first.client_order_id,
            asset_id="asset-AAPL",
            side="SELL",
            quantity=Decimal(1),
        )
    )
    first_port = _port(fake, oms_evidence=evidence)
    first_port.submit(
        first,
        _Permit(
            first,
            order_id="synthetic-local-same-revision-order-1",
            expected_order_id="synthetic-local-same-revision-order-1",
            revision=10,
        ),
        10,
    )

    # A different complete account body at the same revision is equivocation,
    # even though a newly constructed adapter has no local prior snapshot.
    fake.queue_account(
        _account(
            revision=10,
            positions=(AlpacaPositionRecordV1("asset-AAPL", Decimal(9)),),
            open_orders=(),
        )
    )
    same_revision_port = _port(fake, oms_evidence=evidence)
    with pytest.raises(BrokerOutcomeUnknown) as conflict:
        same_revision_port.submit(
            second,
            _Permit(
                second,
                order_id="synthetic-local-same-revision-order-2",
                expected_order_id="synthetic-local-same-revision-order-2",
                revision=10,
            ),
            10,
        )

    assert conflict.value.code == BrokerUnknownCode.UNKNOWN_SUBMIT.value
    assert [payload.client_order_id for payload in fake.post_payloads] == [
        first.client_order_id
    ]


def test_4xx_returns_closed_rejection_without_echoing_body() -> None:
    request = _request()
    fake = RecordedAlpacaTransport()
    fake.queue_account(_account())
    fake.queue_client_read(None)
    fake.queue_post(RecordedHttpError(422, response_body={"message": "private-body-canary"}))
    result = _port(fake).submit(request, _Permit(request), 10)
    result.assert_sealed()
    assert result.state is OrderState.REJECTED
    assert result.rejection_code is BrokerRejectionCode.VENUE_REJECTED
    assert "private-body-canary" not in repr(result)
    assert "private-body-canary" not in str(
        RecordedHttpError(422, response_body="private-body-canary")
    )


def test_account_view_exact_account_positions_orders_executions_and_read_rate_limit() -> None:
    order = _order_record(state="partially_filled", filled_quantity=Decimal(1))
    execution = AlpacaExecutionRecordV1(
        execution_id="synthetic-execution-view",
        venue_order_id=order.venue_order_id,
        client_order_id=order.client_order_id,
        account_id=PAPER_ACCOUNT,
        asset_id="asset-AAPL",
        side="BUY",
        quantity=Decimal(1),
        price=Decimal("123.45"),
        executed_at=BASE_TIME,
    )
    fake = RecordedAlpacaTransport()
    fake.queue_account(
        _account(
            open_orders=(order,),
            positions=(AlpacaPositionRecordV1("asset-AAPL", Decimal(2)),),
            executions=(execution,),
        )
    )
    view = _port(fake).read_account_view(PAPER_ACCOUNT)
    view.assert_sealed()
    assert view.broker_revision == 10
    assert view.positions == (("equity-AAPL", Decimal(2)),)
    assert view.open_orders[0].client_order_id == order.client_order_id
    assert view.executions[0].execution_id == execution.execution_id
    assert view.executions_since == datetime(2026, 10, 5, 14, 59, tzinfo=UTC)
    with pytest.raises(BrokerRejected) as wrong:
        _port(RecordedAlpacaTransport()).read_account_view("different-paper-account")
    assert wrong.value.code == BrokerRejectionCode.ACCOUNT_MISMATCH.value
    fake = RecordedAlpacaTransport()
    fake.queue_account(RecordedHttpError(429, response_body="private-read-body"))
    with pytest.raises(BrokerRejected) as limited:
        _port(fake).read_account_view(PAPER_ACCOUNT)
    assert limited.value.code == BrokerRejectionCode.RATE_LIMITED.value
    assert "private-read-body" not in str(limited.value)


def test_incomplete_or_unmappable_account_snapshot_is_unknown() -> None:
    for record in (
        _account(executions_complete=False),
        _account(positions=(AlpacaPositionRecordV1("unknown-asset", Decimal(2)),)),
        _account(open_orders=(_order_record(state="canceled"),)),
    ):
        fake = RecordedAlpacaTransport()
        fake.queue_account(record)
        with pytest.raises(BrokerOutcomeUnknown) as caught:
            _port(fake).read_account_view(PAPER_ACCOUNT)
        assert caught.value.code == BrokerUnknownCode.UNKNOWN_ACCOUNT_VIEW.value


def test_account_completeness_and_cursor_are_rechecked_at_use_boundary() -> None:
    incomplete = _account()
    object.__setattr__(incomplete, "executions_complete", 1)
    fake = RecordedAlpacaTransport()
    fake.queue_account(incomplete)
    with pytest.raises(BrokerOutcomeUnknown) as caught:
        _port(fake).read_account_view(PAPER_ACCOUNT)
    assert caught.value.code == BrokerUnknownCode.UNKNOWN_ACCOUNT_VIEW.value

    invalid_cursor = _account()
    object.__setattr__(invalid_cursor, "executions_since", BASE_TIME + timedelta(seconds=1))
    fake = RecordedAlpacaTransport()
    fake.queue_account(invalid_cursor)
    with pytest.raises(BrokerOutcomeUnknown) as caught:
        _port(fake).read_account_view(PAPER_ACCOUNT)
    assert caught.value.code == BrokerUnknownCode.UNKNOWN_ACCOUNT_VIEW.value


def test_venue_clock_bool_or_invalid_type_blocks_dispatch() -> None:
    request = _request()
    for bad_venue_time in (True, -1):
        account = _account()
        object.__setattr__(account, "venue_time_ns", bad_venue_time)
        fake = RecordedAlpacaTransport()
        fake.queue_account(account)
        with pytest.raises(BrokerOutcomeUnknown) as caught:
            _port(fake).submit(request, _Permit(request), 10)
        assert caught.value.code == BrokerUnknownCode.UNKNOWN_SUBMIT.value
        assert fake.post_payloads == []


def test_account_snapshot_revision_cannot_regress_or_change_at_same_revision() -> None:
    fake = RecordedAlpacaTransport()
    port = _port(fake)
    fake.queue_account(_account(revision=12))
    assert port.read_account_view(PAPER_ACCOUNT).broker_revision == 12
    fake.queue_account(_account(revision=11))
    with pytest.raises(BrokerOutcomeUnknown) as regressed:
        port.read_account_view(PAPER_ACCOUNT)
    assert regressed.value.code == BrokerUnknownCode.UNKNOWN_ACCOUNT_VIEW.value
    fake.queue_account(_account(revision=12, venue_time_ns=101))
    with pytest.raises(BrokerOutcomeUnknown) as changed:
        port.read_account_view(PAPER_ACCOUNT)
    assert changed.value.code == BrokerUnknownCode.UNKNOWN_ACCOUNT_VIEW.value


def test_cancel_timeout_is_unknown_and_cancel_false_is_not_claimed_success() -> None:
    request = _request()
    order = OrderSnapshot(
        order_id="synthetic-local-order-01",
        request=request,
        state=OrderState.WORKING,
        version=1,
        venue_order_id="synthetic-venue-order-01",
        filled_quantity=Decimal(0),
        discrepancies=(),
        submit_attempted=True,
        cancel_attempted=False,
    )
    fake = RecordedAlpacaTransport()
    fake.queue_account(
        _account(
            open_orders=(
                _order_record(
                    venue_order_id="synthetic-venue-order-01",
                    client_order_id=request.client_order_id,
                ),
            )
        )
    )
    fake.queue_delete(TimeoutError("synthetic cancel canary"))
    with pytest.raises(BrokerOutcomeUnknown) as caught:
        _port(fake).cancel(order)
    assert caught.value.code == BrokerUnknownCode.UNKNOWN_CANCEL.value
    assert "canary" not in str(caught.value)
    assert fake.delete_ids == ["synthetic-venue-order-01"]
    fake = RecordedAlpacaTransport()
    fake.queue_account(
        _account(
            open_orders=(
                _order_record(
                    venue_order_id="synthetic-venue-order-01",
                    client_order_id=request.client_order_id,
                ),
            )
        )
    )
    fake.queue_delete(False)
    result = _port(fake).cancel(order)
    result.assert_sealed()
    assert isinstance(result, CancelResultV1) and result.confirmed is False


def test_read_order_uses_client_identity_then_venue_fallback_and_checks_scope() -> None:
    request = _request()
    order = OrderSnapshot(
        order_id="synthetic-local-order-01",
        request=request,
        state=OrderState.WORKING,
        version=1,
        venue_order_id="synthetic-venue-order-01",
        filled_quantity=Decimal(0),
        discrepancies=(),
        submit_attempted=True,
        cancel_attempted=False,
    )
    fake = RecordedAlpacaTransport()
    fake.queue_client_read(None)
    fake.queue_venue_read(_order_record(client_order_id=request.client_order_id))
    observed = _port(fake).read_order(order)
    assert isinstance(observed, BrokerObservation)
    assert observed.status is OrderState.WORKING
    assert fake.client_lookup_ids == [request.client_order_id]
    assert fake.venue_lookup_ids == ["synthetic-venue-order-01"]
    other = OrderSnapshot(
        order_id=order.order_id,
        request=_request(account_id="other-paper"),
        state=order.state,
        version=order.version,
        venue_order_id=order.venue_order_id,
        filled_quantity=Decimal(0),
        discrepancies=(),
        submit_attempted=True,
        cancel_attempted=False,
    )
    with pytest.raises(BrokerRejected) as wrong:
        _port(RecordedAlpacaTransport()).read_order(other)
    assert wrong.value.code == BrokerRejectionCode.ACCOUNT_MISMATCH.value


def test_stream_partial_fill_correction_and_reconnect_replay_are_idempotent() -> None:
    updates: list[AlpacaTradeUpdateV1] = []
    for item in _json("trade_updates.json"):
        updates.append(
            AlpacaTradeUpdateV1(
                venue_order_id=item["venue_order_id"],
                client_order_id=item["client_order_id"],
                account_id=item["account_id"],
                event_type=item["event_type"],
                event_time=datetime.fromisoformat(item["event_time"].replace("Z", "+00:00")),
                event_sequence=item["event_sequence"],
                execution_id=item.get("execution_id"),
                quantity=Decimal(item["quantity"]) if item.get("quantity") is not None else None,
                price=Decimal(item["price"]) if item.get("price") is not None else None,
                correction_id=item.get("correction_id"),
                revision=item.get("revision"),
            )
        )
    fake = RecordedAlpacaTransport()
    port = _port(fake)
    fake.queue_updates(tuple(updates))
    first = port.poll_trade_updates()
    assert isinstance(first[0], Fill) and first[0].quantity == Decimal(1)
    assert isinstance(first[1], FillCorrection) and first[1].revised_quantity == Decimal("0.5")
    fake.queue_updates(tuple(updates))
    assert port.poll_trade_updates() == ()
    assert fake.update_polls == 2


def test_replayed_stream_key_with_different_payload_is_quarantined() -> None:
    fake = RecordedAlpacaTransport()
    port = _port(fake)
    original = AlpacaTradeUpdateV1(
        venue_order_id="synthetic-order",
        client_order_id="synthetic-client",
        account_id=PAPER_ACCOUNT,
        event_type="new",
        event_time=BASE_TIME,
        event_sequence=1,
    )
    conflicting = AlpacaTradeUpdateV1(
        venue_order_id="synthetic-order",
        client_order_id="synthetic-client",
        account_id=PAPER_ACCOUNT,
        event_type="new",
        event_time=BASE_TIME + timedelta(milliseconds=1),
        event_sequence=1,
    )
    fake.queue_updates((original,))
    assert len(port.poll_trade_updates()) == 1
    fake.queue_updates((conflicting,))
    with pytest.raises(AlpacaPaperError, match="TRADE_UPDATE_DISCREPANCY"):
        port.poll_trade_updates()


def test_configuration_tamper_and_credential_metadata_never_read_secret_files(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = RecordedAlpacaTransport()
    binding = _binding(credential_ref="vault://leviathan-ai/development/alpaca/SYNTHETIC_TEST")
    port = _port(fake, binding=binding)
    fake.queue_account(_account())

    def block_open(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("credential file access is forbidden")

    monkeypatch.setattr(builtins, "open", block_open)
    monkeypatch.setattr(Path, "open", block_open)
    monkeypatch.setattr(os, "open", block_open)
    assert port.read_account_view(PAPER_ACCOUNT).account_id == PAPER_ACCOUNT


def test_positive_dispatch_has_closed_sealed_result_identity_and_no_copy() -> None:
    request = _request()
    fake = RecordedAlpacaTransport()
    fake.queue_account(_account())
    fake.queue_client_read(None)
    fake.queue_post(_order_record(client_order_id=request.client_order_id))
    port = _port(fake, settle_window=timedelta(seconds=3))
    result = port.submit(request, _Permit(request), 10)
    assert isinstance(result, SubmitResultV1)
    result.assert_sealed()
    assert result.state is OrderState.WORKING
    assert port.capability.atomic_revision_dispatch is False
    assert port.capability.settle_window == timedelta(seconds=3)
    assert port.venue.environment is BrokerEnvironment.PAPER
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(BrokerPortError) as denied:
            operation(result)
        assert "WORKING" not in str(denied.value)


def test_post_construction_configuration_tamper_fails_before_io() -> None:
    fake = RecordedAlpacaTransport()
    port = _port(fake)
    object.__setattr__(port._binding, "calendar_revision", "tampered-calendar")
    with pytest.raises(AlpacaPaperError, match="CONFIG_TAMPERED"):
        port.read_account_view(PAPER_ACCOUNT)
    assert fake.account_lookup_ids == []
