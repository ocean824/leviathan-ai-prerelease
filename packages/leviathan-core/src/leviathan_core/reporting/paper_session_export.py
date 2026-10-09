"""Deterministic, read-only export of captured PAPER OMS activity."""

from __future__ import annotations

import csv
import io
import json
import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from enum import StrEnum
from importlib import import_module
from typing import Any, Literal, NoReturn, Protocol, cast

from leviathan_core.numeric import NumericError, canonical_str

_MAX_PAGE_SIZE = 100
_MAX_CURSOR_LENGTH = 8192
_MAX_HIGH_WATER = (1 << 53) - 1
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z", re.ASCII)


class PaperSessionExportCode(StrEnum):
    """Closed, content-free export failure codes."""

    NON_PAPER_SCOPE = "NON_PAPER_SCOPE"
    INVALID_CURSOR = "INVALID_CURSOR"
    INVALID_PAGE = "INVALID_PAGE"
    INVALID_AMOUNT = "INVALID_AMOUNT"
    INCONSISTENT_CORRECTION = "INCONSISTENT_CORRECTION"
    ACTIVITY_UNAVAILABLE = "ACTIVITY_UNAVAILABLE"


class PaperSessionExportError(ValueError):
    """A content-free failure at the paper activity export boundary."""

    __slots__ = ("code",)

    def __init__(self, code: PaperSessionExportCode) -> None:
        if not isinstance(code, PaperSessionExportCode):
            raise TypeError("invalid export error code")
        self.code = code
        super().__init__(code.value)


class PaperSessionExportFormat(StrEnum):
    JSON = "json"
    CSV = "csv"


class PaperOrderStateV1(StrEnum):
    """Closed snapshot of the OMS OrderState wire values."""

    CREATED = "CREATED"
    RISK_PENDING = "RISK_PENDING"
    RISK_REJECTED = "RISK_REJECTED"
    READY = "READY"
    SUBMITTING = "SUBMITTING"
    DISPATCH_IN_FLIGHT = "DISPATCH_IN_FLIGHT"
    WORKING = "WORKING"
    PARTIALLY_FILLED = "PARTIALLY_FILLED"
    FILLED = "FILLED"
    REJECTED = "REJECTED"
    REJECTED_HALTED = "REJECTED_HALTED"
    EXPIRED = "EXPIRED"
    CANCEL_PENDING = "CANCEL_PENDING"
    CANCEL_REQUESTED_UNCONFIRMED = "CANCEL_REQUESTED_UNCONFIRMED"
    CANCELED = "CANCELED"
    UNKNOWN_SUBMIT = "UNKNOWN_SUBMIT"
    UNKNOWN_CANCEL = "UNKNOWN_CANCEL"
    RECONCILE_REQUIRED = "RECONCILE_REQUIRED"


@dataclass(frozen=True, slots=True)
class PaperActivityOrderV1:
    ledger_sequence: int
    order_id: str
    environment: str
    account_id: str
    venue: str
    instrument_id: str
    side: Literal["BUY", "SELL"]
    state: PaperOrderStateV1
    quantity: Decimal
    filled_quantity: Decimal
    created_at: datetime


@dataclass(frozen=True, slots=True)
class PaperActivityFillV1:
    ledger_sequence: int
    order_id: str
    instrument_id: str
    side: Literal["BUY", "SELL"]
    venue: str
    account_id: str
    execution_id: str
    quantity: Decimal
    price: Decimal
    commission: Decimal
    occurred_at: datetime


@dataclass(frozen=True, slots=True)
class PaperActivityCorrectionV1:
    ledger_sequence: int
    order_id: str
    instrument_id: str
    side: Literal["BUY", "SELL"]
    venue: str
    account_id: str
    execution_id: str
    correction_id: str
    revision: int
    revised_quantity: Decimal
    revised_price: Decimal | None
    revised_commission: Decimal
    occurred_at: datetime


PaperActivityNetGroupV1 = tuple[str, str, Decimal]


@dataclass(frozen=True, slots=True)
class PaperActivityPageV1:
    """Normalized page; its ledger high-water sequence is the as-of marker.

    The as-of value is a sequence, not a timestamp. The exporter does not
    synthesize wall-clock time or accept an as-of value from its caller.
    Source OMS DTOs never enter export core.
    """

    high_water_sequence: int
    orders: tuple[PaperActivityOrderV1, ...]
    fills: tuple[PaperActivityFillV1, ...]
    corrections: tuple[PaperActivityCorrectionV1, ...]
    has_more: bool
    net_filled_units: tuple[PaperActivityNetGroupV1, ...]


@dataclass(frozen=True, slots=True)
class PaperActivityCaptureV1:
    """One account-bound page captured by an injected read adapter."""

    environment: str
    account_id: str
    page: PaperActivityPageV1


class PaperActivityReadAdapter(Protocol):
    """Read-only adapter that resolves cursors and returns one captured page."""

    def read_page(
        self,
        *,
        environment: Literal["paper"],
        account_id: str,
        cursor: str | None,
        limit: int,
    ) -> PaperActivityCaptureV1: ...


@dataclass(frozen=True, slots=True)
class _ExportRow:
    kind: str
    ledger_sequence: int | None = None
    order_id: str = ""
    venue: str = ""
    instrument_id: str = ""
    side: str = ""
    state: str = ""
    quantity: str = ""
    filled_quantity: str = ""
    execution_id: str = ""
    correction_id: str = ""
    revision: int | None = None
    price: str = ""
    commission: str = ""
    occurred_at_utc: str = ""
    units_label: str = ""


_CSV_FIELDS = (
    "record_type",
    "ledger_sequence",
    "order_id",
    "venue",
    "instrument_id",
    "side",
    "state",
    "quantity",
    "filled_quantity",
    "execution_id",
    "correction_id",
    "revision",
    "price",
    "commission",
    "occurred_at_utc",
    "units_label",
)


def _fail(code: PaperSessionExportCode) -> NoReturn:
    raise PaperSessionExportError(code)


def _identifier(value: object) -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        _fail(PaperSessionExportCode.INVALID_PAGE)
    return value


def _amount(value: object, *, allow_negative: bool = False, allow_zero: bool = True) -> str:
    if type(value) is not Decimal:
        _fail(PaperSessionExportCode.INVALID_AMOUNT)
    try:
        normalized = canonical_str(value)
    except NumericError:
        _fail(PaperSessionExportCode.INVALID_AMOUNT)
    if (not allow_negative and value < 0) or (not allow_zero and value == 0):
        _fail(PaperSessionExportCode.INVALID_AMOUNT)
    return normalized


def _timestamp(value: object) -> str:
    if type(value) is not datetime or value.tzinfo is not UTC:
        _fail(PaperSessionExportCode.INVALID_PAGE)
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _valid_sequence(value: object, high_water_sequence: int) -> int:
    if type(value) is not int or not 1 <= value <= high_water_sequence:
        _fail(PaperSessionExportCode.INVALID_PAGE)
    return value


def _build_rows(
    page: PaperActivityPageV1, *, account_id: str, limit: int
) -> tuple[list[_ExportRow], int, bool]:
    if type(page) is not PaperActivityPageV1:
        _fail(PaperSessionExportCode.INVALID_PAGE)
    if (
        type(page.high_water_sequence) is not int
        or not 0 <= page.high_water_sequence <= _MAX_HIGH_WATER
        or type(page.has_more) is not bool
        or type(page.orders) is not tuple
        or type(page.fills) is not tuple
        or type(page.corrections) is not tuple
        or len(page.orders) + len(page.fills) + len(page.corrections) > limit
        or type(page.net_filled_units) is not tuple
        or len(page.net_filled_units) > _MAX_PAGE_SIZE
    ):
        _fail(PaperSessionExportCode.INVALID_PAGE)

    rows: list[_ExportRow] = []
    sequences: set[int] = set()
    orders: dict[str, tuple[str, str, str]] = {}
    fills: dict[tuple[str, str, str], tuple[str, str, str, str, int]] = {}
    correction_rows: list[PaperActivityCorrectionV1] = []

    for order_item in page.orders:
        if type(order_item) is not PaperActivityOrderV1:
            _fail(PaperSessionExportCode.INVALID_PAGE)
        sequence = _valid_sequence(order_item.ledger_sequence, page.high_water_sequence)
        if sequence in sequences:
            _fail(PaperSessionExportCode.INVALID_PAGE)
        sequences.add(sequence)
        if (
            type(order_item.environment) is not str
            or order_item.environment != "paper"
            or _identifier(order_item.account_id) != account_id
            or type(order_item.state) is not PaperOrderStateV1
            or order_item.side not in {"BUY", "SELL"}
        ):
            _fail(PaperSessionExportCode.INVALID_PAGE)
        order_id = _identifier(order_item.order_id)
        venue = _identifier(order_item.venue)
        instrument_id = _identifier(order_item.instrument_id)
        if order_id in orders:
            _fail(PaperSessionExportCode.INVALID_PAGE)
        orders[order_id] = (venue, instrument_id, order_item.side)
        rows.append(
            _ExportRow(
                kind="ORDER",
                ledger_sequence=sequence,
                order_id=order_id,
                venue=venue,
                instrument_id=instrument_id,
                side=order_item.side,
                state=order_item.state.value,
                quantity=_amount(order_item.quantity, allow_zero=False),
                filled_quantity=_amount(order_item.filled_quantity),
                occurred_at_utc=_timestamp(order_item.created_at),
            )
        )

    for fill_item in page.fills:
        if type(fill_item) is not PaperActivityFillV1:
            _fail(PaperSessionExportCode.INVALID_PAGE)
        sequence = _valid_sequence(fill_item.ledger_sequence, page.high_water_sequence)
        if sequence in sequences:
            _fail(PaperSessionExportCode.INVALID_PAGE)
        sequences.add(sequence)
        if type(fill_item.side) is not str or fill_item.side not in {"BUY", "SELL"}:
            _fail(PaperSessionExportCode.INVALID_PAGE)
        venue = _identifier(fill_item.venue)
        fill_account = _identifier(fill_item.account_id)
        if fill_account != account_id:
            _fail(PaperSessionExportCode.INVALID_PAGE)
        execution_id = _identifier(fill_item.execution_id)
        order_id = _identifier(fill_item.order_id)
        instrument_id = _identifier(fill_item.instrument_id)
        fill_key = (venue, fill_account, execution_id)
        if fill_key in fills:
            _fail(PaperSessionExportCode.INCONSISTENT_CORRECTION)
        fills[fill_key] = (order_id, instrument_id, fill_item.side, venue, sequence)
        rows.append(
            _ExportRow(
                kind="FILL",
                ledger_sequence=sequence,
                order_id=order_id,
                venue=venue,
                instrument_id=instrument_id,
                side=fill_item.side,
                execution_id=execution_id,
                quantity=_amount(fill_item.quantity, allow_zero=False),
                price=_amount(fill_item.price, allow_zero=False),
                commission=_amount(fill_item.commission),
                occurred_at_utc=_timestamp(fill_item.occurred_at),
            )
        )

    for correction_item in page.corrections:
        if type(correction_item) is not PaperActivityCorrectionV1:
            _fail(PaperSessionExportCode.INCONSISTENT_CORRECTION)
        sequence = _valid_sequence(correction_item.ledger_sequence, page.high_water_sequence)
        if sequence in sequences:
            _fail(PaperSessionExportCode.INVALID_PAGE)
        sequences.add(sequence)
        correction_rows.append(correction_item)
        correction_account = _identifier(correction_item.account_id)
        if correction_account != account_id:
            _fail(PaperSessionExportCode.INVALID_PAGE)

    revisions: dict[tuple[str, str, str], tuple[int, int]] = {}
    correction_ids: set[tuple[str, str, str]] = set()
    for item in sorted(
        correction_rows,
        key=lambda value: (value.venue, value.account_id, value.execution_id, value.revision),
    ):
        if (
            type(item.side) is not str
            or item.side not in {"BUY", "SELL"}
            or type(item.revision) is not int
            or item.revision < 1
        ):
            _fail(PaperSessionExportCode.INCONSISTENT_CORRECTION)
        venue = _identifier(item.venue)
        fill_account = _identifier(item.account_id)
        execution_id = _identifier(item.execution_id)
        correction_id = _identifier(item.correction_id)
        order_id = _identifier(item.order_id)
        instrument_id = _identifier(item.instrument_id)
        fill_key = (venue, fill_account, execution_id)
        original = fills.get(fill_key)
        if original is None:
            _fail(PaperSessionExportCode.INCONSISTENT_CORRECTION)
        previous_revision, previous_sequence = revisions.get(fill_key, (0, original[4]))
        if (
            original[:4] != (order_id, instrument_id, item.side, venue)
            or item.revision != previous_revision + 1
            or item.ledger_sequence <= previous_sequence
        ):
            _fail(PaperSessionExportCode.INCONSISTENT_CORRECTION)
        correction_key = (venue, fill_account, correction_id)
        if correction_key in correction_ids:
            _fail(PaperSessionExportCode.INCONSISTENT_CORRECTION)
        correction_ids.add(correction_key)
        revisions[fill_key] = (item.revision, item.ledger_sequence)
        quantity = _amount(item.revised_quantity)
        price = "" if item.revised_price is None else _amount(item.revised_price, allow_zero=False)
        if (quantity == "0") != (price == ""):
            _fail(PaperSessionExportCode.INCONSISTENT_CORRECTION)
        rows.append(
            _ExportRow(
                kind="FILL_CORRECTION",
                ledger_sequence=item.ledger_sequence,
                order_id=order_id,
                venue=venue,
                instrument_id=instrument_id,
                side=item.side,
                execution_id=execution_id,
                correction_id=correction_id,
                revision=item.revision,
                quantity=quantity,
                price=price,
                commission=_amount(item.revised_commission),
                occurred_at_utc=_timestamp(item.occurred_at),
            )
        )

    for row in rows:
        if (
            row.kind in {"FILL", "FILL_CORRECTION"}
            and row.order_id in orders
            and (row.venue, row.instrument_id, row.side) != orders[row.order_id]
        ):
            _fail(PaperSessionExportCode.INVALID_PAGE)

    net_rows: list[_ExportRow] = []
    net_keys: set[tuple[str, str]] = set()
    for group in page.net_filled_units:
        if type(group) is not tuple or len(group) != 3:
            _fail(PaperSessionExportCode.INVALID_PAGE)
        venue, instrument_id, units = group
        venue = _identifier(venue)
        instrument_id = _identifier(instrument_id)
        key = (venue, instrument_id)
        if key in net_keys:
            _fail(PaperSessionExportCode.INVALID_PAGE)
        net_keys.add(key)
        net_rows.append(
            _ExportRow(
                kind="NET_FILLED_UNITS",
                venue=venue,
                instrument_id=instrument_id,
                quantity=_amount(units, allow_negative=True),
                units_label="OMS net filled units",
            )
        )

    rows.sort(key=lambda row: (row.ledger_sequence or 0, row.kind, row.order_id))
    rows.extend(sorted(net_rows, key=lambda row: (row.venue, row.instrument_id)))
    return rows, page.high_water_sequence, page.has_more


def _json_bytes(rows: Sequence[_ExportRow], *, high_water_sequence: int, has_more: bool) -> bytes:
    payload = {
        "schema_version": 1,
        "evidence_label": "OMS ledger evidence",
        "environment": "paper",
        "as_of_high_water_sequence": high_water_sequence,
        "has_more": has_more,
        "net_filled_units_label": "OMS net filled units",
        "records": [
            {
                key: value
                for key, value in (
                    ("record_type", row.kind),
                    ("ledger_sequence", row.ledger_sequence),
                    ("order_id", row.order_id or None),
                    ("venue", row.venue or None),
                    ("instrument_id", row.instrument_id or None),
                    ("side", row.side or None),
                    ("state", row.state or None),
                    ("quantity", row.quantity or None),
                    ("filled_quantity", row.filled_quantity or None),
                    ("execution_id", row.execution_id or None),
                    ("correction_id", row.correction_id or None),
                    ("revision", row.revision),
                    ("price", row.price or None),
                    ("commission", row.commission or None),
                    ("occurred_at_utc", row.occurred_at_utc or None),
                    ("units_label", row.units_label or None),
                )
                if value is not None
            }
            for row in rows
        ],
    }
    try:
        return (
            json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
        ).encode("ascii")
    except (TypeError, ValueError):
        _fail(PaperSessionExportCode.INVALID_PAGE)


def _csv_bytes(rows: Sequence[_ExportRow], *, high_water_sequence: int, has_more: bool) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(
        stream, fieldnames=_CSV_FIELDS, lineterminator="\n", extrasaction="raise"
    )
    writer.writeheader()
    writer.writerow(
        {
            "record_type": "PAGE",
            "ledger_sequence": high_water_sequence,
            "state": "HAS_MORE" if has_more else "COMPLETE",
            "units_label": "OMS net filled units",
        }
    )
    for row in rows:
        writer.writerow(
            {
                "record_type": row.kind,
                "ledger_sequence": "" if row.ledger_sequence is None else row.ledger_sequence,
                "order_id": row.order_id,
                "venue": row.venue,
                "instrument_id": row.instrument_id,
                "side": row.side,
                "state": row.state,
                "quantity": row.quantity,
                "filled_quantity": row.filled_quantity,
                "execution_id": row.execution_id,
                "correction_id": row.correction_id,
                "revision": "" if row.revision is None else row.revision,
                "price": row.price,
                "commission": row.commission,
                "occurred_at_utc": row.occurred_at_utc,
                "units_label": row.units_label,
            }
        )
    return stream.getvalue().encode("utf-8")


def _normalize_oms_page(
    page: object,
    *,
    page_type: type[object],
    order_type: type[object],
    fill_type: type[object],
    correction_type: type[object],
    order_state_type: type[StrEnum],
) -> PaperActivityPageV1:
    """Normalize the closed OMS DTO union by exact runtime type."""
    if type(page) is not page_type:
        _fail(PaperSessionExportCode.INVALID_PAGE)
    orders: list[PaperActivityOrderV1] = []
    fills: list[PaperActivityFillV1] = []
    corrections: list[PaperActivityCorrectionV1] = []
    seen_sequences: set[int] = set()
    source_page = cast(Any, page)
    high_water = source_page.high_water_sequence
    source_items = source_page.items
    has_more = source_page.has_more
    net_filled_units = source_page.net_filled_units
    if (
        type(high_water) is not int
        or not 0 <= high_water <= _MAX_HIGH_WATER
        or type(source_items) is not tuple
        or len(source_items) > _MAX_PAGE_SIZE
        or type(has_more) is not bool
        or type(net_filled_units) is not tuple
        or len(net_filled_units) > _MAX_PAGE_SIZE
    ):
        _fail(PaperSessionExportCode.INVALID_PAGE)
    for item in source_items:
        if type(item) is order_type:
            item_kind = "order"
        elif type(item) is fill_type:
            item_kind = "fill"
        elif type(item) is correction_type:
            item_kind = "correction"
        else:
            _fail(PaperSessionExportCode.INVALID_PAGE)
        source_item = cast(Any, item)
        sequence = source_item.ledger_sequence
        if type(sequence) is not int or sequence in seen_sequences:
            _fail(PaperSessionExportCode.INVALID_PAGE)
        seen_sequences.add(sequence)
        if item_kind == "order":
            snapshot = source_item.snapshot
            request = snapshot.request
            source_state = snapshot.state
            if type(source_state) is not order_state_type:
                _fail(PaperSessionExportCode.INVALID_PAGE)
            try:
                local_state = PaperOrderStateV1(source_state.value)
            except (ValueError, TypeError):
                _fail(PaperSessionExportCode.INVALID_PAGE)
            orders.append(
                PaperActivityOrderV1(
                    sequence,
                    snapshot.order_id,
                    request.environment,
                    request.account_id,
                    request.venue,
                    request.instrument_id,
                    request.side,
                    local_state,
                    request.quantity,
                    snapshot.filled_quantity,
                    source_item.created_at,
                )
            )
        elif item_kind == "fill":
            fill = source_item.fill
            fills.append(
                PaperActivityFillV1(
                    sequence,
                    source_item.order_id,
                    source_item.instrument_id,
                    source_item.side,
                    fill.venue,
                    fill.account_id,
                    fill.execution_id,
                    fill.quantity,
                    fill.price,
                    fill.commission,
                    fill.occurred_at,
                )
            )
        elif item_kind == "correction":
            correction = source_item.correction
            corrections.append(
                PaperActivityCorrectionV1(
                    sequence,
                    source_item.order_id,
                    source_item.instrument_id,
                    source_item.side,
                    correction.venue,
                    correction.account_id,
                    correction.execution_id,
                    correction.correction_id,
                    correction.revision,
                    correction.revised_quantity,
                    correction.revised_price,
                    correction.revised_commission,
                    correction.occurred_at,
                )
            )
    return PaperActivityPageV1(
        high_water,
        tuple(orders),
        tuple(fills),
        tuple(corrections),
        has_more,
        net_filled_units,
    )


def normalize_oms_activity_page(page: object) -> PaperActivityPageV1:
    """Adapt the in-flight OMS page DTO without coupling export core to OMS."""
    try:
        oms_module = import_module("leviathan_core.execution.oms")
        model_module = import_module("leviathan_core.execution.order_models")
        oms_types = vars(oms_module)
        model_types = vars(model_module)

        return _normalize_oms_page(
            page,
            page_type=cast(type[object], oms_types["ActivityLedgerPage"]),
            order_type=cast(type[object], oms_types["ActivityOrderItem"]),
            fill_type=cast(type[object], oms_types["ActivityFillItem"]),
            correction_type=cast(type[object], oms_types["ActivityCorrectionItem"]),
            order_state_type=cast(type[StrEnum], model_types["OrderState"]),
        )
    except PaperSessionExportError:
        raise
    except Exception:
        _fail(PaperSessionExportCode.INVALID_PAGE)


def export_paper_activity(
    adapter: PaperActivityReadAdapter,
    *,
    account_id: str,
    environment: str = "paper",
    cursor: str | None = None,
    limit: int = 50,
    format: PaperSessionExportFormat = PaperSessionExportFormat.JSON,
) -> bytes:
    """Capture and serialize one bounded PAPER page.

    The page high-water sequence is the authoritative as-of marker; no
    wall-clock as-of is created or accepted from the caller.
    """
    if type(environment) is not str or environment != "paper":
        _fail(PaperSessionExportCode.NON_PAPER_SCOPE)
    if (
        type(account_id) is not str
        or type(limit) is not int
        or not 1 <= limit <= _MAX_PAGE_SIZE
        or not isinstance(format, PaperSessionExportFormat)
    ):
        _fail(PaperSessionExportCode.INVALID_PAGE)
    _identifier(account_id)
    if cursor is not None and (
        type(cursor) is not str or not cursor or len(cursor) > _MAX_CURSOR_LENGTH
    ):
        _fail(PaperSessionExportCode.INVALID_CURSOR)
    try:
        capture = adapter.read_page(
            environment="paper", account_id=account_id, cursor=cursor, limit=limit
        )
    except PaperSessionExportError:
        raise
    except Exception:
        _fail(PaperSessionExportCode.ACTIVITY_UNAVAILABLE)
    if (
        type(capture) is not PaperActivityCaptureV1
        or type(capture.environment) is not str
        or capture.environment != "paper"
        or type(capture.account_id) is not str
        or capture.account_id != account_id
    ):
        _fail(PaperSessionExportCode.INVALID_PAGE)
    try:
        rows, high_water_sequence, has_more = _build_rows(
            capture.page, account_id=account_id, limit=limit
        )
    except PaperSessionExportError:
        raise
    except Exception:
        _fail(PaperSessionExportCode.INVALID_PAGE)
    if format is PaperSessionExportFormat.JSON:
        return _json_bytes(rows, high_water_sequence=high_water_sequence, has_more=has_more)
    return _csv_bytes(rows, high_water_sequence=high_water_sequence, has_more=has_more)


__all__ = [
    "PaperActivityCaptureV1",
    "PaperActivityCorrectionV1",
    "PaperActivityFillV1",
    "PaperActivityOrderV1",
    "PaperActivityPageV1",
    "PaperActivityReadAdapter",
    "PaperOrderStateV1",
    "PaperSessionExportCode",
    "PaperSessionExportError",
    "PaperSessionExportFormat",
    "export_paper_activity",
    "normalize_oms_activity_page",
]
