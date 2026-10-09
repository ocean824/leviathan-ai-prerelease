from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime
from decimal import Decimal
from typing import Literal, cast

import pytest

from leviathan_core.reporting.paper_session_export import (
    PaperActivityCaptureV1,
    PaperActivityCorrectionV1,
    PaperActivityFillV1,
    PaperActivityOrderV1,
    PaperActivityPageV1,
    PaperOrderStateV1,
    PaperSessionExportCode,
    PaperSessionExportError,
    PaperSessionExportFormat,
    export_paper_activity,
)

ACCOUNT_ID = "acct-SYNTHETIC-FULL-001"
SECRET_VALUE = "SYNTHETIC-SECRET-CANARY"
CREDENTIAL_REF = "credential://SYNTHETIC-CREDENTIAL-REF"
RAW_PROVIDER = "SYNTHETIC-RAW-PROVIDER-PAYLOAD"


def _order(
    *,
    ledger_sequence: int = 1,
    state: PaperOrderStateV1 = PaperOrderStateV1.FILLED,
    order_id: str = "order-synthetic-1",
    venue: str = "SIM",
    account_id: str = ACCOUNT_ID,
) -> PaperActivityOrderV1:
    return PaperActivityOrderV1(
        ledger_sequence=ledger_sequence,
        order_id=order_id,
        environment="paper",
        account_id=account_id,
        venue=venue,
        instrument_id="SYNTH-ES",
        side="BUY",
        state=state,
        quantity=Decimal("0.3000000000000000000003"),
        filled_quantity=Decimal("0.3"),
        created_at=datetime(2026, 10, 6, 12, 0, tzinfo=UTC),
    )


def _fill(
    *,
    ledger_sequence: int = 2,
    venue: str = "SIM",
    account_id: str = ACCOUNT_ID,
    execution_id: str = "execution-synthetic-1",
    order_id: str = "order-synthetic-1",
) -> PaperActivityFillV1:
    return PaperActivityFillV1(
        ledger_sequence=ledger_sequence,
        order_id=order_id,
        instrument_id="SYNTH-ES",
        side="BUY",
        venue=venue,
        account_id=account_id,
        execution_id=execution_id,
        quantity=Decimal("0.1000000000000000000001"),
        price=Decimal("123.4500000000000000000001"),
        commission=Decimal("0.0000000000000000000003"),
        occurred_at=datetime(2026, 10, 6, 12, 1, tzinfo=UTC),
    )


def _correction(
    *,
    ledger_sequence: int = 3,
    venue: str = "SIM",
    account_id: str = ACCOUNT_ID,
    execution_id: str = "execution-synthetic-1",
    correction_id: str = "correction-synthetic-1",
    order_id: str = "order-synthetic-1",
) -> PaperActivityCorrectionV1:
    return PaperActivityCorrectionV1(
        ledger_sequence=ledger_sequence,
        order_id=order_id,
        instrument_id="SYNTH-ES",
        side="BUY",
        venue=venue,
        account_id=account_id,
        execution_id=execution_id,
        correction_id=correction_id,
        revision=1,
        revised_quantity=Decimal("0.1000000000000000000002"),
        revised_price=Decimal("123.4500000000000000000002"),
        revised_commission=Decimal("0.0000000000000000000004"),
        occurred_at=datetime(2026, 10, 6, 12, 2, tzinfo=UTC),
    )


def _page(
    *,
    high_water_sequence: int = 3,
    orders: tuple[object, ...] | None = None,
    fills: tuple[object, ...] | None = None,
    corrections: tuple[object, ...] | None = None,
    has_more: bool = False,
    net_filled_units: tuple[tuple[str, str, Decimal], ...] | None = None,
) -> PaperActivityPageV1:
    return PaperActivityPageV1(
        high_water_sequence=high_water_sequence,
        orders=(_order(),) if orders is None else orders,  # type: ignore[arg-type]
        fills=(_fill(),) if fills is None else fills,  # type: ignore[arg-type]
        corrections=(_correction(),) if corrections is None else corrections,  # type: ignore[arg-type]
        has_more=has_more,
        net_filled_units=(
            (
                ("SIM", "SYNTH-ES", Decimal("0.2000000000000000000002")),
                ("SIM", "SYNTH-NQ", Decimal("-0.125")),
            )
            if net_filled_units is None
            else net_filled_units
        ),
    )


class _SyntheticReadAdapter:
    def __init__(
        self,
        page: object | None = None,
        *,
        account_id: str = ACCOUNT_ID,
        environment: str = "paper",
        error: Exception | None = None,
    ) -> None:
        self.capture = PaperActivityCaptureV1(
            environment,
            account_id,
            _page() if page is None else page,  # type: ignore[arg-type]
        )
        self.error = error
        self.calls: list[tuple[str, str, str | None, int]] = []

    def read_page(
        self,
        *,
        environment: Literal["paper"],
        account_id: str,
        cursor: str | None,
        limit: int,
    ) -> PaperActivityCaptureV1:
        self.calls.append((environment, account_id, cursor, limit))
        if self.error is not None:
            raise self.error
        return self.capture


def _export(adapter: _SyntheticReadAdapter, export_format: PaperSessionExportFormat) -> bytes:
    return export_paper_activity(
        adapter,
        account_id=ACCOUNT_ID,
        cursor="opaque-synthetic-cursor",
        limit=10,
        format=export_format,
    )


def test_json_and_csv_are_deterministic_with_exact_decimal_text() -> None:
    page = _page()
    permuted = _page(
        orders=tuple(reversed(page.orders)),
        fills=tuple(reversed(page.fills)),
        corrections=tuple(reversed(page.corrections)),
        net_filled_units=tuple(reversed(page.net_filled_units)),
    )

    for export_format in (PaperSessionExportFormat.JSON, PaperSessionExportFormat.CSV):
        first = _export(_SyntheticReadAdapter(page), export_format)
        second = _export(_SyntheticReadAdapter(permuted), export_format)
        assert first == second

    document = json.loads(_export(_SyntheticReadAdapter(page), PaperSessionExportFormat.JSON))
    assert document["as_of_high_water_sequence"] == 3
    rows = document["records"]
    original = next(row for row in rows if row["record_type"] == "FILL")
    assert original["quantity"] == "0.1000000000000000000001"
    assert original["price"] == "123.4500000000000000000001"
    assert original["commission"] == "0.0000000000000000000003"
    assert next(row for row in rows if row["instrument_id"] == "SYNTH-NQ")["quantity"] == "-0.125"

    csv_rows = list(
        csv.DictReader(
            io.StringIO(
                _export(_SyntheticReadAdapter(page), PaperSessionExportFormat.CSV).decode("utf-8")
            )
        )
    )
    assert next(row for row in csv_rows if row["record_type"] == "FILL")["price"] == (
        "123.4500000000000000000001"
    )


def test_correction_is_a_new_record_and_does_not_rewrite_original_fill() -> None:
    encoded = _export(_SyntheticReadAdapter(), PaperSessionExportFormat.JSON)
    rows = json.loads(encoded)["records"]
    fill = next(row for row in rows if row["record_type"] == "FILL")
    correction = next(row for row in rows if row["record_type"] == "FILL_CORRECTION")

    assert fill["ledger_sequence"] == 2
    assert fill["quantity"] == "0.1000000000000000000001"
    assert fill["price"] == "123.4500000000000000000001"
    assert correction["ledger_sequence"] == 3
    assert correction["quantity"] == "0.1000000000000000000002"
    assert correction["price"] == "123.4500000000000000000002"
    assert correction["revision"] == 1
    assert correction["execution_id"] == fill["execution_id"]
    assert correction["correction_id"] == "correction-synthetic-1"


@pytest.mark.parametrize(
    "export_format", (PaperSessionExportFormat.JSON, PaperSessionExportFormat.CSV)
)
def test_export_excludes_account_principal_credentials_and_raw_provider_payload(
    export_format: PaperSessionExportFormat,
) -> None:
    output = _export(_SyntheticReadAdapter(), export_format)

    for excluded in (ACCOUNT_ID, SECRET_VALUE, CREDENTIAL_REF, RAW_PROVIDER):
        assert excluded.encode("ascii") not in output


def test_live_scope_is_denied_before_adapter_read_and_error_is_content_free() -> None:
    adapter = _SyntheticReadAdapter()
    with pytest.raises(PaperSessionExportError) as caught:
        export_paper_activity(
            adapter,
            account_id=ACCOUNT_ID,
            environment="live",
            cursor="LIVE-CURSOR-CANARY",
        )

    assert caught.value.code is PaperSessionExportCode.NON_PAPER_SCOPE
    assert str(caught.value) == "NON_PAPER_SCOPE"
    assert ACCOUNT_ID not in str(caught.value)
    assert adapter.calls == []


def test_failed_capture_and_inconsistent_correction_produce_no_export_bytes() -> None:
    unavailable = _SyntheticReadAdapter(error=RuntimeError(SECRET_VALUE))
    with pytest.raises(PaperSessionExportError) as unavailable_error:
        _export(unavailable, PaperSessionExportFormat.JSON)
    assert unavailable_error.value.code is PaperSessionExportCode.ACTIVITY_UNAVAILABLE
    assert SECRET_VALUE not in str(unavailable_error.value)

    bad_correction = _correction(execution_id="unknown-execution-synthetic")
    page = _page(orders=(), fills=(), corrections=(bad_correction,), net_filled_units=())
    with pytest.raises(PaperSessionExportError) as correction_error:
        _export(_SyntheticReadAdapter(page), PaperSessionExportFormat.JSON)
    assert correction_error.value.code is PaperSessionExportCode.INCONSISTENT_CORRECTION
    assert "unknown-execution-synthetic" not in str(correction_error.value)


def test_requested_cursor_and_page_size_are_forwarded_to_read_adapter() -> None:
    adapter = _SyntheticReadAdapter()
    export_paper_activity(
        adapter,
        account_id=ACCOUNT_ID,
        cursor="opaque-synthetic-cursor",
        limit=10,
    )
    assert adapter.calls == [("paper", ACCOUNT_ID, "opaque-synthetic-cursor", 10)]


def test_unknown_open_order_state_is_rejected_without_echoing_state_text() -> None:
    item = _order(state=cast(PaperOrderStateV1, "SYNTHETIC-UNKNOWN-ORDER-STATE-CANARY"))
    adapter = _SyntheticReadAdapter(
        _page(orders=(item,), fills=(), corrections=(), net_filled_units=())
    )

    with pytest.raises(PaperSessionExportError) as caught:
        _export(adapter, PaperSessionExportFormat.JSON)

    assert caught.value.code is PaperSessionExportCode.INVALID_PAGE
    assert str(caught.value) == "INVALID_PAGE"
    assert "SYNTHETIC-UNKNOWN-ORDER-STATE-CANARY" not in str(caught.value)


def test_overlapping_order_and_fill_shape_is_rejected_instead_of_dropping_fill_fields() -> None:
    fill_shaped_order = _fill(execution_id="execution-secret-canary")
    adapter = _SyntheticReadAdapter(
        _page(orders=(fill_shaped_order,), fills=(), corrections=(), net_filled_units=())
    )

    with pytest.raises(PaperSessionExportError) as caught:
        _export(adapter, PaperSessionExportFormat.JSON)

    assert caught.value.code is PaperSessionExportCode.INVALID_PAGE
    assert caught.value.code != PaperSessionExportCode.ACTIVITY_UNAVAILABLE
    assert "execution-secret-canary" not in str(caught.value)
    assert RAW_PROVIDER not in str(caught.value)


def test_fill_identity_is_venue_account_and_execution_scoped() -> None:
    shared_execution_id = "execution-shared-across-venues"
    fill_a = _fill(ledger_sequence=1, venue="VENUE-A", execution_id=shared_execution_id)
    fill_b = _fill(ledger_sequence=2, venue="VENUE-B", execution_id=shared_execution_id)
    cross_venue = _page(
        high_water_sequence=2,
        orders=(),
        fills=(fill_a, fill_b),
        corrections=(),
        net_filled_units=(),
    )

    rows = json.loads(
        _export(_SyntheticReadAdapter(cross_venue), PaperSessionExportFormat.JSON)
    )["records"]
    fills = [row for row in rows if row["record_type"] == "FILL"]
    assert {(row["venue"], row["execution_id"]) for row in fills} == {
        ("VENUE-A", shared_execution_id),
        ("VENUE-B", shared_execution_id),
    }

    fill_a_duplicate = _fill(
        ledger_sequence=2,
        venue="VENUE-A",
        execution_id=shared_execution_id,
    )
    duplicate = _page(
        high_water_sequence=2,
        orders=(),
        fills=(fill_a, fill_a_duplicate),
        corrections=(),
        net_filled_units=(),
    )
    with pytest.raises(PaperSessionExportError) as caught:
        _export(_SyntheticReadAdapter(duplicate), PaperSessionExportFormat.JSON)
    assert caught.value.code is PaperSessionExportCode.INCONSISTENT_CORRECTION
    assert shared_execution_id not in str(caught.value)


def test_correction_lineage_uses_the_full_venue_account_execution_key() -> None:
    execution_id = "execution-cross-venue-lineage"
    fill_a = _fill(ledger_sequence=1, venue="VENUE-A", execution_id=execution_id)
    fill_b = _fill(ledger_sequence=2, venue="VENUE-B", execution_id=execution_id)
    correction_b = _correction(
        ledger_sequence=3,
        venue="VENUE-B",
        execution_id=execution_id,
    )
    page = _page(
        high_water_sequence=3,
        orders=(),
        fills=(fill_a, fill_b),
        corrections=(correction_b,),
        net_filled_units=(),
    )

    rows = json.loads(
        _export(_SyntheticReadAdapter(page), PaperSessionExportFormat.JSON)
    )["records"]
    venue_a_fill = next(
        row
        for row in rows
        if row["record_type"] == "FILL" and row["venue"] == "VENUE-A"
    )
    venue_b_fill = next(
        row
        for row in rows
        if row["record_type"] == "FILL" and row["venue"] == "VENUE-B"
    )
    correction = next(row for row in rows if row["record_type"] == "FILL_CORRECTION")
    assert correction["venue"] == "VENUE-B"
    assert correction["execution_id"] == execution_id
    assert correction["ledger_sequence"] == 3
    assert venue_a_fill["quantity"] == "0.1000000000000000000001"
    assert venue_b_fill["quantity"] == "0.1000000000000000000001"

    wrong_venue_correction = _correction(
        ledger_sequence=3,
        venue="VENUE-C",
        execution_id=execution_id,
    )
    mismatched = _page(
        high_water_sequence=3,
        orders=(),
        fills=(fill_a, fill_b),
        corrections=(wrong_venue_correction,),
        net_filled_units=(),
    )
    with pytest.raises(PaperSessionExportError) as caught:
        _export(_SyntheticReadAdapter(mismatched), PaperSessionExportFormat.JSON)
    assert caught.value.code is PaperSessionExportCode.INCONSISTENT_CORRECTION
    assert execution_id not in str(caught.value)
