"""Offline translation of recorded CFTC CSV releases into COT vintages.

The layout ID describes a fixture schema, not a verified live CFTC feed. No
transport, scheduling, publication inference, or persistence occurs here.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import weakref
from collections.abc import Callable, Iterable
from contextlib import suppress
from dataclasses import InitVar, dataclass, field, fields
from datetime import date
from decimal import Decimal
from functools import wraps
from itertools import pairwise
from typing import Literal, NoReturn, SupportsIndex, TypeVar

from leviathan_core.macro_cot.models import (
    COTMarketMapV1,
    COTReportVintageV1,
    COTValidationError,
)
from leviathan_core.numeric import NumericError, parse_decimal, parse_int

_FAMILY = "Disaggregated Futures"
_LAYOUT = "synthetic-disaggregated-csv-v1"
_REQUIRED = frozenset(
    {
        "report_date",
        "report_family",
        "cftc_market_code",
        "mm_long",
        "mm_short",
        "mm_spreading",
        "open_interest",
    }
)
_OPTIONAL = frozenset({"constituent_id"})
_FILE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII)
_SHA_RE = re.compile(r"[0-9a-fA-F]{64}\Z", re.ASCII)
_DATE_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}\Z", re.ASCII)
_URL_RE = re.compile(r"https://[A-Za-z0-9.-]+(?:/[A-Za-z0-9._~/%?=&+:#-]*)?\Z", re.ASCII)
_MAX_PAYLOAD_BYTES = 16 * 1024 * 1024
_MAX_ROWS = 10000
_MAX_NS = 2**63 - 1
_ISSUER = object()
_ISSUED: dict[int, tuple[weakref.ReferenceType[object], str]] = {}
_RecordT = TypeVar("_RecordT")


class CFTCAdapterError(ValueError):
    """Typed, content-free rejection of source or mapping evidence."""

    __slots__ = ("reason_code",)

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


class _NoClone:
    __slots__ = ()

    def __copy__(self) -> NoReturn:
        raise TypeError("CFTC adapter records cannot be copied")

    def __deepcopy__(self, memo: object) -> NoReturn:
        raise TypeError("CFTC adapter records cannot be copied")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise TypeError("CFTC adapter records cannot be pickled")

    def __setstate__(self, state: object) -> NoReturn:
        raise CFTCAdapterError("RECORD_FROZEN")


def _guard_reinit(first_field: str, reason_code: str) -> Callable[[type[_RecordT]], type[_RecordT]]:
    """Reject a second dataclass initializer before it writes its first slot."""

    def decorate(cls: type[_RecordT]) -> type[_RecordT]:
        original_init = cls.__init__

        @wraps(original_init)
        def guarded(self: _RecordT, *args: object, **kwargs: object) -> None:
            if _has_registry_identity(self):
                raise CFTCAdapterError(reason_code)
            try:
                object.__getattribute__(self, first_field)
            except AttributeError:
                pass
            else:
                raise CFTCAdapterError(reason_code)
            original_init(self, *args, **kwargs)

        def blocked_setstate(self: _RecordT, state: object) -> NoReturn:
            raise CFTCAdapterError(reason_code)

        cls.__init__ = guarded  # type: ignore[assignment]
        cls.__setstate__ = blocked_setstate  # type: ignore[attr-defined]
        return cls

    return decorate


def _canonical_value(value: object) -> object:
    if value is None or type(value) in (str, bool, int):
        return value
    if type(value) is bytes:
        return {"bytes_sha256": hashlib.sha256(value).hexdigest(), "bytes_length": len(value)}
    if type(value) is date:
        return {"date": value.isoformat()}
    if type(value) is Decimal:
        if not value.is_finite():
            raise ValueError("invalid decimal")
        parts = value.as_tuple()
        digits = list(parts.digits)
        exponent = parts.exponent
        if not isinstance(exponent, int) or len(digits) > 100 or abs(exponent) > 100:
            raise ValueError("invalid decimal")
        while len(digits) > 1 and digits[-1] == 0:
            digits.pop()
            exponent += 1
        if all(digit == 0 for digit in digits):
            return {"decimal": [0, "0", 0]}
        return {"decimal": [parts.sign, "".join(str(digit) for digit in digits), exponent]}
    if type(value) is tuple:
        return [_canonical_value(item) for item in value]
    if type(value) in (
        COTReportVintageV1,
        CFTCSourceEnvelopeV1,
        CFTCAdaptedReleaseV1,
        CFTCAsOfViewV1,
    ):
        return {
            "record": type(value).__name__,
            "fields": {
                part.name: _canonical_value(object.__getattribute__(value, part.name))
                for part in fields(value)  # type: ignore[arg-type]
            },
        }
    raise TypeError("unsupported issued value")


def _value_digest(value: object) -> str:
    payload = json.dumps(
        _canonical_value(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def _register_issued(value: object) -> None:
    identity = id(value)
    if _has_registry_identity(value):
        raise CFTCAdapterError("RECORD_FROZEN")
    digest = _value_digest(value)

    def forget(reference: weakref.ReferenceType[object]) -> None:
        entry = _ISSUED.get(identity)
        if entry is not None and entry[0] is reference:
            _ISSUED.pop(identity, None)

    _ISSUED[identity] = (weakref.ref(value, forget), digest)


def _has_registry_identity(value: object) -> bool:
    entry = _ISSUED.get(id(value))
    return entry is not None and entry[0]() is value


def _is_issued(value: object) -> bool:
    entry = _ISSUED.get(id(value))
    if entry is None or entry[0]() is not value:
        return False
    try:
        return _value_digest(value) == entry[1]
    except (AttributeError, TypeError, ValueError, RecursionError):
        return False


def _nonnegative_ns(value: object) -> int:
    parsed: int | None = None
    with suppress(NumericError):
        parsed = parse_int(value, field="timestamp", min_value=0, max_value=_MAX_NS)
    if parsed is None:
        raise CFTCAdapterError("INVALID_RELEASE_TIME")
    return parsed


@_guard_reinit("file_id", "RECORD_FROZEN")
@dataclass(frozen=True, slots=True, weakref_slot=True, kw_only=True)
class CFTCSourceEnvelopeV1(_NoClone):
    """A recorded, hash-pinned single-market CSV file and observation manifest."""

    file_id: str
    payload_bytes: bytes = field(repr=False)
    file_sha256: str
    file_revision: int
    is_preliminary: bool
    report_family: str
    market_code_namespace: str
    market_id: str
    mapping_version: str
    units: str
    column_map: tuple[tuple[str, str], ...]
    source_url: str
    published_ns: int | None
    received_ns: int
    available_ns: int
    layout_id: str = _LAYOUT

    def __post_init__(self) -> None:
        if _has_registry_identity(self):
            raise CFTCAdapterError("RECORD_FROZEN")
        if self.layout_id != _LAYOUT:
            raise CFTCAdapterError("UNSUPPORTED_LAYOUT")
        if not isinstance(self.file_id, str) or _FILE_ID_RE.fullmatch(self.file_id) is None:
            raise CFTCAdapterError("INVALID_SOURCE_ID")
        if (
            type(self.payload_bytes) is not bytes
            or not 0 < len(self.payload_bytes) <= _MAX_PAYLOAD_BYTES
        ):
            raise CFTCAdapterError("UNSUPPORTED_LAYOUT")
        if not isinstance(self.file_sha256, str) or _SHA_RE.fullmatch(self.file_sha256) is None:
            raise CFTCAdapterError("SOURCE_HASH_MISMATCH")
        digest = hashlib.sha256(self.payload_bytes).hexdigest()
        if digest != self.file_sha256.lower():
            raise CFTCAdapterError("SOURCE_HASH_MISMATCH")
        object.__setattr__(self, "file_sha256", digest)
        revision: int | None = None
        with suppress(NumericError):
            revision = parse_int(
                self.file_revision, field="revision", min_value=0, max_value=2**31 - 1
            )
        if revision is None:
            raise CFTCAdapterError("INVALID_REVISION")
        object.__setattr__(self, "file_revision", revision)
        if type(self.is_preliminary) is not bool:
            raise CFTCAdapterError("INVALID_REVISION")
        if self.report_family != _FAMILY:
            raise CFTCAdapterError("REPORT_FAMILY_MISMATCH")
        if self.market_code_namespace != "CFTC" or self.units != "contracts":
            raise CFTCAdapterError("UNSUPPORTED_LAYOUT")
        if not isinstance(self.market_id, str) or not self.market_id:
            raise CFTCAdapterError("MAPPING_AMBIGUOUS")
        if not isinstance(self.mapping_version, str) or not self.mapping_version:
            raise CFTCAdapterError("MAPPING_AMBIGUOUS")
        if not isinstance(self.source_url, str) or _URL_RE.fullmatch(self.source_url) is None:
            raise CFTCAdapterError("INVALID_SOURCE_URL")
        if type(self.column_map) is not tuple or any(
            type(pair) is not tuple
            or len(pair) != 2
            or any(not isinstance(part, str) or not part or len(part) > 128 for part in pair)
            for pair in self.column_map
        ):
            raise CFTCAdapterError("UNSUPPORTED_LAYOUT")
        names = [name for name, _ in self.column_map]
        headers = [header for _, header in self.column_map]
        if not _REQUIRED.issubset(names):
            raise CFTCAdapterError("SCHEMA_MISSING_COLUMN")
        if (
            set(names) - (_REQUIRED | _OPTIONAL)
            or len(set(names)) != len(names)
            or len(set(headers)) != len(headers)
            or any(any(ord(char) < 32 or ord(char) > 126 for char in header) for header in headers)
        ):
            raise CFTCAdapterError("UNSUPPORTED_LAYOUT")
        object.__setattr__(self, "column_map", tuple(sorted(self.column_map)))
        received = _nonnegative_ns(self.received_ns)
        available = _nonnegative_ns(self.available_ns)
        published = None if self.published_ns is None else _nonnegative_ns(self.published_ns)
        if received > available or (published is not None and published > received):
            raise CFTCAdapterError("INVALID_RELEASE_TIME")
        _register_issued(self)


@_guard_reinit("file_id", "RESULT_NOT_ISSUED")
@dataclass(frozen=True, slots=True, weakref_slot=True, kw_only=True)
class CFTCAdaptedReleaseV1(_NoClone):
    """Parsed vintages with evidence provenance; no point-in-time claim."""

    file_id: str
    file_sha256: str
    source_url: str
    market_id: str
    mapping_version: str
    status: Literal["READY", "VINTAGE_UNKNOWN"]
    vintages: tuple[COTReportVintageV1, ...]
    published_ns: int | None
    received_ns: int
    available_ns: int
    reason_codes: tuple[str, ...] = ()
    _issuer: InitVar[object | None] = field(default=None, repr=False)

    def __post_init__(self, _issuer: object | None) -> None:
        if _has_registry_identity(self):
            raise CFTCAdapterError("RESULT_NOT_ISSUED")
        if _issuer is not _ISSUER:
            raise CFTCAdapterError("RESULT_NOT_ISSUED")
        if not self.vintages or any(type(row) is not COTReportVintageV1 for row in self.vintages):
            raise CFTCAdapterError("INVALID_RESULT_STATE")
        expected = "VINTAGE_UNKNOWN" if self.published_ns is None else "READY"
        expected_reasons = () if expected == "READY" else (expected,)
        if self.status != expected or self.reason_codes != expected_reasons:
            raise CFTCAdapterError("INVALID_RESULT_STATE")
        if any(row.published_ns != self.published_ns for row in self.vintages):
            raise CFTCAdapterError("INVALID_RESULT_STATE")
        _register_issued(self)


@_guard_reinit("market_id", "RESULT_NOT_ISSUED")
@dataclass(frozen=True, slots=True, weakref_slot=True, kw_only=True)
class CFTCAsOfViewV1(_NoClone):
    """Only source revisions visible as of a caller's UTC timestamp."""

    market_id: str
    mapping_version: str
    asof_ns: int
    status: Literal["READY", "UNAVAILABLE", "VINTAGE_UNKNOWN"]
    visible_vintages: tuple[COTReportVintageV1, ...]
    selected_revision_ids: tuple[tuple[str, date, int], ...]
    is_revised: bool
    gap_report_dates: tuple[date, ...]
    reason_codes: tuple[str, ...]
    _issuer: InitVar[object | None] = field(default=None, repr=False)

    def __post_init__(self, _issuer: object | None) -> None:
        if _has_registry_identity(self):
            raise CFTCAdapterError("RESULT_NOT_ISSUED")
        if _issuer is not _ISSUER:
            raise CFTCAdapterError("RESULT_NOT_ISSUED")
        if self.status not in ("READY", "UNAVAILABLE", "VINTAGE_UNKNOWN"):
            raise CFTCAdapterError("INVALID_RESULT_STATE")
        if type(self.is_revised) is not bool:
            raise CFTCAdapterError("INVALID_RESULT_STATE")
        if any(type(row) is not COTReportVintageV1 for row in self.visible_vintages):
            raise CFTCAdapterError("INVALID_RESULT_STATE")
        _register_issued(self)


def _mapping_codes(envelope: CFTCSourceEnvelopeV1, mapping: COTMarketMapV1) -> dict[str, str]:
    if type(mapping) is not COTMarketMapV1:
        raise CFTCAdapterError("MAPPING_AMBIGUOUS")
    if type(mapping.effective_from) is not date or (
        mapping.effective_to is not None and type(mapping.effective_to) is not date
    ):
        raise CFTCAdapterError("MAPPING_AMBIGUOUS")
    if envelope.market_id != mapping.market_id or envelope.mapping_version != mapping.version:
        raise CFTCAdapterError("MAPPING_AMBIGUOUS")
    codes = mapping.constituent_codes
    if (
        not codes
        or len(codes) != len(mapping.constituent_ids)
        or {ident for ident, _ in codes} != set(mapping.constituent_ids)
        or len({ident for ident, _ in codes}) != len(codes)
        or len({code for _, code in codes}) != len(codes)
        or len(set(mapping.constituent_ids)) != len(mapping.constituent_ids)
        or any(not ident or not code for ident, code in codes)
    ):
        raise CFTCAdapterError("MAPPING_AMBIGUOUS")
    if mapping.effective_to is not None and mapping.effective_to <= mapping.effective_from:
        raise CFTCAdapterError("MAPPING_AMBIGUOUS")
    return {code: ident for ident, code in codes}


def _read_rows(envelope: CFTCSourceEnvelopeV1) -> list[dict[str, str]]:
    translated: list[dict[str, str]] | None = None
    try:
        decoded = envelope.payload_bytes.decode("utf-8-sig", errors="strict")
        if "\x00" in decoded:
            raise CFTCAdapterError("UNSUPPORTED_LAYOUT")
        reader = csv.DictReader(io.StringIO(decoded, newline=""), strict=True)
        headers = reader.fieldnames
        expected = {header for _, header in envelope.column_map}
        if headers is None or len(headers) != len(set(headers)):
            raise CFTCAdapterError("UNSUPPORTED_LAYOUT")
        present = {name for name, header in envelope.column_map if header in headers}
        if not _REQUIRED.issubset(present):
            raise CFTCAdapterError("SCHEMA_MISSING_COLUMN")
        if set(headers) != expected:
            raise CFTCAdapterError("UNSUPPORTED_LAYOUT")
        translated = []
        for source in reader:
            if len(translated) >= _MAX_ROWS or None in source:
                raise CFTCAdapterError("UNSUPPORTED_LAYOUT")
            row: dict[str, str] = {}
            for canonical, header in envelope.column_map:
                value = source.get(header)
                if value is None or (canonical in _REQUIRED and not value):
                    raise CFTCAdapterError("SCHEMA_MISSING_COLUMN")
                row[canonical] = value
            translated.append(row)
    except (UnicodeError, csv.Error):
        translated = None
    if translated is None:
        raise CFTCAdapterError("UNSUPPORTED_LAYOUT")
    if not translated:
        raise CFTCAdapterError("MISSING_FIELD")
    return translated


def _report_date(value: str) -> date:
    if _DATE_RE.fullmatch(value) is None:
        raise CFTCAdapterError("INVALID_REPORT_DATE")
    parsed: date | None = None
    with suppress(ValueError):
        parsed = date.fromisoformat(value)
    if parsed is None:
        raise CFTCAdapterError("INVALID_REPORT_DATE")
    return parsed


def _position(value: str, field: str, *, positive: bool = False) -> Decimal:
    parsed: Decimal | None = None
    code: str | None = None
    try:
        parsed = parse_decimal(value, field=field, min_value="0")
    except NumericError as exc:
        code = (
            "PRECISION_EXCEEDED"
            if exc.code == "PRECISION_EXCEEDED"
            else "DECIMAL_OUT_OF_BOUNDS"
            if exc.code == "MAGNITUDE_OUT_OF_BOUNDS"
            else "INVALID_POSITION"
        )
    if code is not None:
        raise CFTCAdapterError(code)
    assert parsed is not None
    if positive and parsed == 0:
        raise CFTCAdapterError("INVALID_POSITION")
    if parsed.as_integer_ratio()[1] != 1:
        raise CFTCAdapterError("INVALID_POSITION")
    return parsed


def parse_cftc_release(
    envelope: CFTCSourceEnvelopeV1, market_map: COTMarketMapV1
) -> CFTCAdaptedReleaseV1:
    """Verify a recorded CSV manifest and translate its single-market rows."""
    if type(envelope) is not CFTCSourceEnvelopeV1:
        raise CFTCAdapterError("INVALID_SOURCE")
    if (
        type(envelope.payload_bytes) is not bytes
        or type(envelope.file_sha256) is not str
        or hashlib.sha256(envelope.payload_bytes).hexdigest() != envelope.file_sha256
        or not _is_issued(envelope)
    ):
        raise CFTCAdapterError("SOURCE_HASH_MISMATCH")
    codes = _mapping_codes(envelope, market_map)
    rows = _read_rows(envelope)
    families = {row["report_family"] for row in rows}
    if len(families) > 1:
        raise CFTCAdapterError("MIXED_REPORT_FAMILY")
    if families != {_FAMILY}:
        raise CFTCAdapterError("REPORT_FAMILY_MISMATCH")
    unique: dict[tuple[date, str], COTReportVintageV1] = {}
    for row in rows:
        report_date = _report_date(row["report_date"])
        if report_date < market_map.effective_from or (
            market_map.effective_to is not None and report_date >= market_map.effective_to
        ):
            raise CFTCAdapterError("MAPPING_VERSION_NOT_EFFECTIVE")
        code = row["cftc_market_code"]
        if code not in codes:
            raise CFTCAdapterError("UNKNOWN_MARKET_CODE")
        constituent = codes[code]
        if "constituent_id" in row and row["constituent_id"] != constituent:
            raise CFTCAdapterError("MAPPING_AMBIGUOUS")
        report_ns = (report_date - date(1970, 1, 1)).days * 86_400_000_000_000
        if envelope.received_ns < report_ns:
            raise CFTCAdapterError("RELEASE_BEFORE_REPORT")
        if envelope.published_ns is not None and envelope.published_ns < report_ns:
            raise CFTCAdapterError("RELEASE_BEFORE_REPORT")
        vintage: COTReportVintageV1 | None = None
        with suppress(COTValidationError):
            vintage = COTReportVintageV1(
                cftc_market_code=code,
                constituent_id=constituent,
                report_date=report_date,
                report_family=_FAMILY,
                source="CFTC",
                revision=envelope.file_revision,
                is_preliminary=envelope.is_preliminary,
                published_ns=envelope.published_ns,
                received_ns=envelope.received_ns,
                available_ns=envelope.available_ns,
                mm_long=_position(row["mm_long"], "mm_long"),
                mm_short=_position(row["mm_short"], "mm_short"),
                open_interest=_position(row["open_interest"], "open_interest", positive=True),
                mm_spreading=_position(row["mm_spreading"], "mm_spreading"),
                units="contracts",
            )
        if vintage is None:
            raise CFTCAdapterError("INVALID_POSITION")
        key = (report_date, code)
        prior = unique.setdefault(key, vintage)
        if prior != vintage:
            raise CFTCAdapterError("SOURCE_CONFLICT")
    status: Literal["READY", "VINTAGE_UNKNOWN"] = (
        "VINTAGE_UNKNOWN" if envelope.published_ns is None else "READY"
    )
    return CFTCAdaptedReleaseV1(
        file_id=envelope.file_id,
        file_sha256=envelope.file_sha256,
        source_url=envelope.source_url,
        market_id=envelope.market_id,
        mapping_version=envelope.mapping_version,
        status=status,
        vintages=tuple(
            sorted(unique.values(), key=lambda item: (item.report_date, item.constituent_id))
        ),
        published_ns=envelope.published_ns,
        received_ns=envelope.received_ns,
        available_ns=envelope.available_ns,
        reason_codes=("VINTAGE_UNKNOWN",) if status == "VINTAGE_UNKNOWN" else (),
        _issuer=_ISSUER,
    )


def select_cftc_asof(
    releases: Iterable[CFTCAdaptedReleaseV1],
    market_map: COTMarketMapV1,
    asof_ns: int,
) -> CFTCAsOfViewV1:
    """Filter visibility before duplicate reconciliation and revision selection."""
    asof = _nonnegative_ns(asof_ns)
    if type(market_map) is not COTMarketMapV1:
        raise CFTCAdapterError("MAPPING_AMBIGUOUS")
    if type(market_map.effective_from) is not date or (
        market_map.effective_to is not None and type(market_map.effective_to) is not date
    ):
        raise CFTCAdapterError("MAPPING_AMBIGUOUS")
    if not isinstance(releases, Iterable) or isinstance(releases, (str, bytes)):
        raise CFTCAdapterError("INVALID_SOURCE")
    codes = market_map.constituent_codes
    if (
        len(codes) != len(market_map.constituent_ids)
        or {ident for ident, _ in codes} != set(market_map.constituent_ids)
        or len({ident for ident, _ in codes}) != len(codes)
        or len({code for _, code in codes}) != len(codes)
    ):
        raise CFTCAdapterError("MAPPING_AMBIGUOUS")
    expected_codes = dict(codes)
    visible_files: dict[str, CFTCAdaptedReleaseV1] = {}
    unknown = False
    for index, release in enumerate(releases):
        if index >= _MAX_ROWS:
            raise CFTCAdapterError("INVALID_SOURCE")
        if type(release) is not CFTCAdaptedReleaseV1 or not _is_issued(release):
            raise CFTCAdapterError("RESULT_NOT_ISSUED")
        if release.available_ns > asof or release.received_ns > asof:
            continue
        if release.published_ns is not None and release.published_ns > asof:
            continue
        if (
            release.market_id != market_map.market_id
            or release.mapping_version != market_map.version
        ):
            raise CFTCAdapterError("MAPPING_AMBIGUOUS")
        if release.published_ns is None:
            unknown = True
            continue
        prior = visible_files.setdefault(release.file_id, release)
        if prior != release:
            raise CFTCAdapterError("SOURCE_CONFLICT")
    unique: dict[tuple[date, str, str, int], COTReportVintageV1] = {}
    for release in visible_files.values():
        for vintage in release.vintages:
            if vintage.constituent_id not in expected_codes or (
                expected_codes[vintage.constituent_id] != vintage.cftc_market_code
            ):
                raise CFTCAdapterError("MAPPING_AMBIGUOUS")
            if vintage.report_date < market_map.effective_from or (
                market_map.effective_to is not None
                and vintage.report_date >= market_map.effective_to
            ):
                raise CFTCAdapterError("MAPPING_VERSION_NOT_EFFECTIVE")
            key = (vintage.report_date, vintage.constituent_id, vintage.source, vintage.revision)
            existing_vintage = unique.setdefault(key, vintage)
            if existing_vintage != vintage:
                raise CFTCAdapterError("SOURCE_CONFLICT")
    visible = tuple(
        sorted(
            unique.values(),
            key=lambda row: (row.report_date, row.constituent_id, row.revision, row.is_preliminary),
        )
    )
    by_key: dict[tuple[date, str], list[COTReportVintageV1]] = {}
    for row in visible:
        by_key.setdefault((row.report_date, row.constituent_id), []).append(row)
    selected: list[tuple[str, date, int]] = []
    revised_dates: dict[date, bool] = {}
    for (report_date, constituent), candidates in sorted(by_key.items()):
        finalized = [row for row in candidates if not row.is_preliminary]
        chosen = max(finalized or candidates, key=lambda row: row.revision)
        selected.append((constituent, report_date, chosen.revision))
        revised_dates[report_date] = revised_dates.get(report_date, False) or (
            len(candidates) > 1 or chosen.revision > 0
        )
    report_dates = sorted({row.report_date for row in visible})
    revised = revised_dates[report_dates[-1]] if report_dates else False
    gaps = tuple(
        current for previous, current in pairwise(report_dates) if (current - previous).days > 7
    )
    status: Literal["READY", "UNAVAILABLE", "VINTAGE_UNKNOWN"] = (
        "VINTAGE_UNKNOWN" if unknown else "READY" if visible else "UNAVAILABLE"
    )
    reasons = ("VINTAGE_UNKNOWN",) if unknown else (() if visible else ("NO_VISIBLE_RELEASE",))
    return CFTCAsOfViewV1(
        market_id=market_map.market_id,
        mapping_version=market_map.version,
        asof_ns=asof,
        status=status,
        visible_vintages=visible,
        selected_revision_ids=tuple(selected),
        is_revised=revised,
        gap_report_dates=gaps,
        reason_codes=reasons,
        _issuer=_ISSUER,
    )


__all__ = [
    "CFTCAdaptedReleaseV1",
    "CFTCAdapterError",
    "CFTCAsOfViewV1",
    "CFTCSourceEnvelopeV1",
    "parse_cftc_release",
    "select_cftc_asof",
]
