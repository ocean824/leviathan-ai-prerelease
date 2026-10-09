from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from enum import StrEnum
from typing import Literal

import pytest

from leviathan_core.execution.order_models import OrderState
from leviathan_core.reporting.paper_session_export import (
    PaperActivityCaptureV1,
    PaperActivityOrderV1,
    PaperActivityPageV1,
    PaperOrderStateV1,
    PaperSessionExportCode,
    PaperSessionExportError,
    PaperSessionExportFormat,
    _normalize_oms_page,
    export_paper_activity,
)

_NOW = datetime(2026, 10, 6, 12, 0, tzinfo=UTC)


def _order(**changes: object) -> PaperActivityOrderV1:
    fields: dict[str, object] = {
        "ledger_sequence": 1,
        "order_id": "order-01",
        "environment": "paper",
        "account_id": "paper-account-1",
        "venue": "SIM",
        "instrument_id": "EURUSD",
        "side": "BUY",
        "state": PaperOrderStateV1.FILLED,
        "quantity": Decimal("2.50"),
        "filled_quantity": Decimal("2.5"),
        "created_at": _NOW,
    }
    return PaperActivityOrderV1(**(fields | changes))  # type: ignore[arg-type]


def _fill(**changes: object) -> object:
    from leviathan_core.reporting.paper_session_export import PaperActivityFillV1

    fields: dict[str, object] = {
        "ledger_sequence": 2,
        "order_id": "order-01",
        "instrument_id": "EURUSD",
        "side": "BUY",
        "venue": "SIM",
        "account_id": "paper-account-1",
        "execution_id": "exec-01",
        "quantity": Decimal("2.5"),
        "price": Decimal("1.1250"),
        "commission": Decimal("0.01"),
        "occurred_at": _NOW,
    }
    return PaperActivityFillV1(**(fields | changes))  # type: ignore[arg-type]


def _correction(**changes: object) -> object:
    from leviathan_core.reporting.paper_session_export import PaperActivityCorrectionV1

    fields: dict[str, object] = {
        "ledger_sequence": 3,
        "order_id": "order-01",
        "instrument_id": "EURUSD",
        "side": "BUY",
        "venue": "SIM",
        "account_id": "paper-account-1",
        "execution_id": "exec-01",
        "correction_id": "correction-01",
        "revision": 1,
        "revised_quantity": Decimal("2.25"),
        "revised_price": Decimal("1.125"),
        "revised_commission": Decimal("0.02"),
        "occurred_at": _NOW,
    }
    return PaperActivityCorrectionV1(**(fields | changes))  # type: ignore[arg-type]


def _page(
    *,
    orders: tuple[object, ...] = (_order(),),
    fills: tuple[object, ...] = (_fill(),),
    corrections: tuple[object, ...] = (_correction(),),
    high_water_sequence: int = 3,
    net: tuple[tuple[str, str, Decimal], ...] = (("SIM", "EURUSD", Decimal("2.25")),),
) -> PaperActivityPageV1:
    return PaperActivityPageV1(
        high_water_sequence,
        orders,  # type: ignore[arg-type]
        fills,  # type: ignore[arg-type]
        corrections,  # type: ignore[arg-type]
        False,
        net,
    )


class _Adapter:
    def __init__(
        self, capture: PaperActivityCaptureV1 | None = None, error: Exception | None = None
    ) -> None:
        self.capture = capture or PaperActivityCaptureV1("paper", "paper-account-1", _page())
        self.error = error
        self.calls: list[dict[str, object]] = []

    def read_page(
        self,
        *,
        environment: Literal["paper"],
        account_id: str,
        cursor: str | None,
        limit: int,
    ) -> PaperActivityCaptureV1:
        self.calls.append(
            {"environment": environment, "account_id": account_id, "cursor": cursor, "limit": limit}
        )
        if self.error is not None:
            raise self.error
        assert self.capture is not None
        return self.capture


def test_closed_order_state_values_drift_check() -> None:
    assert {value.value for value in PaperOrderStateV1} == {value.value for value in OrderState}


def test_json_export_is_stable_exact_and_separates_correction() -> None:
    adapter = _Adapter()
    first = export_paper_activity(adapter, account_id="paper-account-1")
    second = export_paper_activity(adapter, account_id="paper-account-1")

    assert first == second
    document = json.loads(first)
    assert document["as_of_high_water_sequence"] == 3
    assert document["evidence_label"] == "OMS ledger evidence"
    assert document["net_filled_units_label"] == "OMS net filled units"
    records = document["records"]
    assert [row["record_type"] for row in records] == [
        "ORDER",
        "FILL",
        "FILL_CORRECTION",
        "NET_FILLED_UNITS",
    ]
    assert records[1]["quantity"] == "2.5"
    assert records[1]["price"] == "1.125"
    assert records[2]["quantity"] == "2.25"
    assert records[2]["execution_id"] == records[1]["execution_id"]
    assert "units_label" not in records[2]
    assert records[3]["quantity"] == "2.25"
    serialized = first.decode("ascii")
    assert "paper-account-1" not in serialized
    assert adapter.calls[0] == {
        "environment": "paper",
        "account_id": "paper-account-1",
        "cursor": None,
        "limit": 50,
    }


def test_csv_export_is_stable_and_keeps_correction_as_a_separate_row() -> None:
    adapter = _Adapter()
    first = export_paper_activity(
        adapter, account_id="paper-account-1", format=PaperSessionExportFormat.CSV
    )
    second = export_paper_activity(
        adapter, account_id="paper-account-1", format=PaperSessionExportFormat.CSV
    )
    assert first == second
    rows = list(csv.DictReader(io.StringIO(first.decode("utf-8"))))
    assert [row["record_type"] for row in rows] == [
        "PAGE",
        "ORDER",
        "FILL",
        "FILL_CORRECTION",
        "NET_FILLED_UNITS",
    ]
    assert rows[2]["quantity"] == "2.5"
    assert rows[3]["quantity"] == "2.25"
    assert rows[4]["units_label"] == "OMS net filled units"


@pytest.mark.parametrize("format", [PaperSessionExportFormat.JSON, PaperSessionExportFormat.CSV])
def test_unknown_open_state_canary_is_rejected_without_echo(
    format: PaperSessionExportFormat,
) -> None:
    class _CanaryState(StrEnum):
        SECRET_CANARY = "ghp_SECRET_CANARY_VALUE"

    adapter = _Adapter(
        PaperActivityCaptureV1(
            "paper", "paper-account-1", _page(orders=(_order(state=_CanaryState.SECRET_CANARY),))
        )
    )
    with pytest.raises(PaperSessionExportError) as caught:
        export_paper_activity(adapter, account_id="paper-account-1", format=format)
    assert caught.value.code is PaperSessionExportCode.INVALID_PAGE
    assert "ghp_SECRET_CANARY_VALUE" not in str(caught.value)


def test_live_scope_is_rejected_before_reading() -> None:
    adapter = _Adapter()
    with pytest.raises(PaperSessionExportError) as caught:
        export_paper_activity(adapter, account_id="paper-account-1", environment="live")
    assert caught.value.code is PaperSessionExportCode.NON_PAPER_SCOPE
    assert adapter.calls == []
    assert "paper-account-1" not in str(caught.value)


def test_bad_cursor_and_invalid_limit_are_rejected_before_reading() -> None:
    adapter = _Adapter()
    with pytest.raises(PaperSessionExportError) as cursor_error:
        export_paper_activity(adapter, account_id="paper-account-1", cursor="")
    assert cursor_error.value.code is PaperSessionExportCode.INVALID_CURSOR
    with pytest.raises(PaperSessionExportError) as limit_error:
        export_paper_activity(adapter, account_id="paper-account-1", limit=True)
    assert limit_error.value.code is PaperSessionExportCode.INVALID_PAGE
    assert adapter.calls == []


def test_adapter_cursor_error_is_content_free() -> None:
    adapter = _Adapter(error=PaperSessionExportError(PaperSessionExportCode.INVALID_CURSOR))
    with pytest.raises(PaperSessionExportError) as caught:
        export_paper_activity(adapter, account_id="paper-account-1", cursor="opaque-secret-cursor")
    assert caught.value.code is PaperSessionExportCode.INVALID_CURSOR
    assert "opaque-secret-cursor" not in str(caught.value)


def test_nan_decimal_is_rejected_with_fixed_code() -> None:
    adapter = _Adapter(
        PaperActivityCaptureV1(
            "paper",
            "paper-account-1",
            _page(fills=(_fill(quantity=Decimal("NaN")),), corrections=()),
        )
    )
    with pytest.raises(PaperSessionExportError) as caught:
        export_paper_activity(adapter, account_id="paper-account-1")
    assert caught.value.code is PaperSessionExportCode.INVALID_AMOUNT
    assert str(caught.value) == "INVALID_AMOUNT"


def test_correction_without_matching_full_fill_identity_is_rejected() -> None:
    missing_venue = _correction(venue="OTHER")
    adapter = _Adapter(
        PaperActivityCaptureV1("paper", "paper-account-1", _page(corrections=(missing_venue,)))
    )
    with pytest.raises(PaperSessionExportError) as caught:
        export_paper_activity(adapter, account_id="paper-account-1")
    assert caught.value.code is PaperSessionExportCode.INCONSISTENT_CORRECTION


def test_capture_scope_must_match_requested_account() -> None:
    adapter = _Adapter(PaperActivityCaptureV1("paper", "another-account", _page()))
    with pytest.raises(PaperSessionExportError) as caught:
        export_paper_activity(adapter, account_id="paper-account-1")
    assert caught.value.code is PaperSessionExportCode.INVALID_PAGE
    assert "another-account" not in str(caught.value)


def test_execution_id_can_repeat_across_venues_with_distinct_full_keys() -> None:
    orders = (_order(), _order(ledger_sequence=2, order_id="order-02", venue="OTHER"))
    fills = (_fill(ledger_sequence=3), _fill(ledger_sequence=4, venue="OTHER", order_id="order-02"))
    corrections = (
        _correction(ledger_sequence=5, correction_id="corr-sim"),
        _correction(
            ledger_sequence=6, correction_id="corr-other", venue="OTHER", order_id="order-02"
        ),
    )
    page = _page(orders=orders, fills=fills, corrections=corrections, high_water_sequence=6)
    document = json.loads(
        export_paper_activity(
            _Adapter(PaperActivityCaptureV1("paper", "paper-account-1", page)),
            account_id="paper-account-1",
        )
    )
    fill_rows = [row for row in document["records"] if row["record_type"] == "FILL"]
    correction_rows = [
        row for row in document["records"] if row["record_type"] == "FILL_CORRECTION"
    ]
    assert len(fill_rows) == 2
    assert len(correction_rows) == 2
    assert [row["execution_id"] for row in fill_rows] == ["exec-01", "exec-01"]


def test_duplicate_execution_id_within_venue_and_account_is_rejected() -> None:
    page = _page(fills=(_fill(), _fill(ledger_sequence=4)), corrections=(), high_water_sequence=4)
    with pytest.raises(PaperSessionExportError) as caught:
        export_paper_activity(
            _Adapter(PaperActivityCaptureV1("paper", "paper-account-1", page)),
            account_id="paper-account-1",
        )
    assert caught.value.code is PaperSessionExportCode.INCONSISTENT_CORRECTION


def test_page_containers_reject_wrong_record_types_and_dual_shape_values() -> None:
    class _DualShape:
        ledger_sequence = 2
        snapshot = object()
        created_at = _NOW
        fill = object()
        order_id = "order-01"
        instrument_id = "EURUSD"
        side = "BUY"

    wrong_container = _page(orders=(_fill(),), fills=(), corrections=())
    dual_shape = _page(fills=(_DualShape(),), corrections=())
    for page in (wrong_container, dual_shape):
        with pytest.raises(PaperSessionExportError) as caught:
            export_paper_activity(
                _Adapter(PaperActivityCaptureV1("paper", "paper-account-1", page)),
                account_id="paper-account-1",
            )
        assert caught.value.code is PaperSessionExportCode.INVALID_PAGE


def test_normalizer_classifies_union_by_exact_type_and_preserves_container_order() -> None:
    @dataclass(frozen=True)
    class _SourceRequest:
        environment: str = "paper"
        account_id: str = "paper-account-1"
        venue: str = "SIM"
        instrument_id: str = "EURUSD"
        side: str = "BUY"
        quantity: Decimal = Decimal("2")

    @dataclass(frozen=True)
    class _SourceSnapshot:
        order_id: str = "order-01"
        request: _SourceRequest = _SourceRequest()
        state: StrEnum = OrderState.FILLED
        filled_quantity: Decimal = Decimal("2")

    @dataclass(frozen=True)
    class _SourceOrderItem:
        ledger_sequence: int = 2
        snapshot: _SourceSnapshot = _SourceSnapshot()
        created_at: datetime = _NOW

    @dataclass(frozen=True)
    class _SourceFill:
        venue: str = "SIM"
        account_id: str = "paper-account-1"
        execution_id: str = "exec-01"
        quantity: Decimal = Decimal("2")
        price: Decimal = Decimal("1")
        commission: Decimal = Decimal(0)
        occurred_at: datetime = _NOW

    @dataclass(frozen=True)
    class _SourceFillItem:
        ledger_sequence: int = 1
        order_id: str = "order-01"
        instrument_id: str = "EURUSD"
        side: Literal["BUY", "SELL"] = "BUY"
        fill: _SourceFill = _SourceFill()

    @dataclass(frozen=True)
    class _SourceCorrection:
        venue: str = "SIM"
        account_id: str = "paper-account-1"
        execution_id: str = "exec-01"
        correction_id: str = "corr-1"
        revision: int = 1
        revised_quantity: Decimal = Decimal("1")
        revised_price: Decimal | None = Decimal("1")
        revised_commission: Decimal = Decimal(0)
        occurred_at: datetime = _NOW

    @dataclass(frozen=True)
    class _SourceCorrectionItem:
        ledger_sequence: int = 3
        order_id: str = "order-01"
        instrument_id: str = "EURUSD"
        side: Literal["BUY", "SELL"] = "BUY"
        correction: _SourceCorrection = _SourceCorrection()

    @dataclass(frozen=True)
    class _SourcePage:
        high_water_sequence: int = 3
        items: tuple[object, ...] = (_SourceOrderItem(), _SourceFillItem(), _SourceCorrectionItem())
        has_more: bool = False
        net_filled_units: tuple[tuple[str, str, Decimal], ...] = ()

    result = _normalize_oms_page(
        _SourcePage(),
        page_type=_SourcePage,
        order_type=_SourceOrderItem,
        fill_type=_SourceFillItem,
        correction_type=_SourceCorrectionItem,
        order_state_type=OrderState,
    )
    assert [item.ledger_sequence for item in result.orders] == [2]
    assert [item.ledger_sequence for item in result.fills] == [1]
    assert [item.ledger_sequence for item in result.corrections] == [3]

    class _Unknown(_SourceOrderItem):
        pass

    with pytest.raises(PaperSessionExportError) as caught:
        _normalize_oms_page(
            _SourcePage(items=(_Unknown(),)),
            page_type=_SourcePage,
            order_type=_SourceOrderItem,
            fill_type=_SourceFillItem,
            correction_type=_SourceCorrectionItem,
            order_state_type=OrderState,
        )
    assert caught.value.code is PaperSessionExportCode.INVALID_PAGE
