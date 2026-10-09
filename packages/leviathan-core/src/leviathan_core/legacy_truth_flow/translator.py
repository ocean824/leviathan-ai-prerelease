"""Pure legacy-first archived truth read mapping over injected snapshots."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Iterable
from dataclasses import fields
from datetime import UTC, datetime
from decimal import Decimal

from .models import (
    ArchivedTruthBoundaryError,
    ArchivedTruthErrorV1,
    ArchivedTruthPolicyV1,
    ArchivedTruthQueryV1,
    ArchivedTruthRecordViewV1,
    ArchivedTruthResultV1,
    ArchivedTruthWriteDecisionV1,
    LegacyTruthRecordV1,
    MappedTruthRecordV1,
    _canonical_decimal,
    _TruthSourceRecordV1,
)

_UTC_ISO = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,9})?(?:Z|\+00:00)$"
)
_SYMBOL = re.compile(r"^[A-Z][A-Z0-9.]{0,9}$")
_OSI = re.compile(r"^[A-Z0-9]{1,6} {0,5}[0-9]{6}[CP][0-9]{8}$")
_CURRENCY = re.compile(r"^[A-Z]{3}$")
_CURSOR = re.compile(r"^v1:([0-9]{1,12}):([a-f0-9]{64})$")
_NS_DAY = 86_400_000_000_000


def _utc_ns(value: str) -> int | None:
    if not _UTC_ISO.fullmatch(value):
        return None
    try:
        fixed = value.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(fixed)
        offset = parsed.utcoffset()
        if offset is None or offset.total_seconds() != 0:
            return None
        whole = fixed.split(".", 1)[0].removesuffix("+00:00")
        base = datetime.fromisoformat(whole).replace(tzinfo=UTC)
        fraction = fixed.split(".", 1)[1].split("+", 1)[0] if "." in fixed else ""
        delta = base - datetime(1970, 1, 1, tzinfo=UTC)
        return (delta.days * 86400 + delta.seconds) * 1_000_000_000 + int(
            fraction.ljust(9, "0") or "0"
        )
    except (OverflowError, ValueError):
        return None


def _decimal(value: Decimal | None) -> str | None:
    if value is None:
        return None
    return _canonical_decimal(value)


def _valid_osi(value: str) -> bool:
    if len(value) != 21 or not _OSI.fullmatch(value):
        return False
    try:
        datetime.strptime("20" + value[6:12], "%Y%m%d")
    except ValueError:
        return False
    return True


def _digest(payload: object) -> str:
    return hashlib.sha256(_canonical_bytes(payload)).hexdigest()


def _canonical_bytes(payload: object) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _semantic_payload(record: _TruthSourceRecordV1, status: str) -> dict[str, object]:
    """Exclude source and local-receipt identity for legacy/proxy checksum parity."""
    return {
        "tenant_id": record.tenant_id,
        "dataset": record.dataset,
        "symbol": record.symbol,
        "osi": record.osi,
        "timestamp_ns": record.timestamp_ns,
        "timestamp_precision": record.timestamp_precision,
        "side": record.side,
        "venue": record.venue,
        "currency": record.currency,
        "event_type": record.event_type,
        "price": _decimal(record.price),
        "size": _decimal(record.size),
        "value": _decimal(record.value),
        "liquidity_flag": record.liquidity_flag,
        "evidence_status": status,
        "embargo_until_ns": record.embargo_until_ns,
    }


def _headers(policy: ArchivedTruthPolicyV1) -> tuple[tuple[str, str], ...]:
    return (("Deprecation", "true"), ("Sunset", policy.sunset_utc))


def _failure(
    status: int,
    code: str,
    query: ArchivedTruthQueryV1,
    policy: ArchivedTruthPolicyV1,
    paths: tuple[str, ...] = (),
    migrate: bool = False,
) -> ArchivedTruthResultV1:
    return ArchivedTruthResultV1(
        status_code=status,
        headers=_headers(policy),
        error=ArchivedTruthErrorV1(
            code=code,
            trace_id=query.trace_id,
            field_paths=paths,
            migrate_to=policy.successor_base if migrate else None,
        ),
    )


def _validate(
    query: ArchivedTruthQueryV1, policy: ArchivedTruthPolicyV1
) -> tuple[int | None, int | None, tuple[str, ...]]:
    paths: list[str] = []
    start = _utc_ns(query.start_utc)
    end = _utc_ns(query.end_utc)
    if start is None or end is None or start > end or end - start > 31 * _NS_DAY:
        paths.extend(("start_utc", "end_utc"))
    if query.dataset == "order_flow":
        if query.symbol is None or not _SYMBOL.fullmatch(query.symbol) or query.osi is not None:
            paths.append("symbol")
    elif query.dataset == "options":
        if query.osi is None or not _valid_osi(query.osi) or query.symbol is not None:
            paths.append("osi")
    else:
        paths.append("dataset")
    if query.side is not None and query.side not in ("BUY", "SELL"):
        paths.append("side")
    if query.venue is not None and query.venue not in policy.allowed_venues:
        paths.append("venue")
    if query.currency is not None and (
        not _CURRENCY.fullmatch(query.currency)
        or query.currency not in policy.allowed_currencies
    ):
        paths.append("currency")
    if query.event_type is not None and query.event_type not in (
        "EXECUTIONS", "QUOTE_IMPACT", "OI_CHANGE"
    ):
        paths.append("event_type")
    if (
        isinstance(query.limit, bool)
        or not isinstance(query.limit, int)
        or not 1 <= query.limit <= 5000
    ):
        paths.append("limit")
    return start, end, tuple(sorted(set(paths)))


def _matching(
    records: Iterable[_TruthSourceRecordV1],
    query: ArchivedTruthQueryV1,
    start: int,
    end: int,
    expected_type: type[_TruthSourceRecordV1],
    field_path: str,
) -> tuple[_TruthSourceRecordV1, ...]:
    try:
        iterator = iter(records)
    except TypeError:
        raise ArchivedTruthBoundaryError("INVALID_RECORD_TYPE", (field_path,)) from None
    matched: list[_TruthSourceRecordV1] = []
    for record in iterator:
        if type(record) is not expected_type:
            raise ArchivedTruthBoundaryError("INVALID_RECORD_TYPE", (field_path,))
        if (
            record.tenant_id == query.tenant_id
            and record.dataset == query.dataset
            and start <= record.timestamp_ns <= end
            and (record.availability_ns is None or record.availability_ns <= end)
            and (query.symbol is None or record.symbol == query.symbol)
            and (query.osi is None or record.osi == query.osi)
            and (query.side is None or record.side == query.side)
            and (query.venue is None or record.venue == query.venue)
            and (query.currency is None or record.currency == query.currency)
            and (query.event_type is None or record.event_type == query.event_type)
        ):
            matched.append(record)
    return tuple(matched)


def _representation_etag(
    page: tuple[ArchivedTruthRecordViewV1, ...],
    headers: tuple[tuple[str, str], ...],
    fingerprint: str,
    offset: int,
    next_cursor: str | None,
    proxy_hit: bool,
) -> str:
    records: list[dict[str, object]] = []
    for record in page:
        representation: dict[str, object] = {}
        for field in fields(record):
            value = getattr(record, field.name)
            representation[field.name] = _decimal(value) if isinstance(value, Decimal) else value
        records.append(representation)
    body = _canonical_bytes({"data": records, "page": {"next_cursor": next_cursor}})
    metadata = _canonical_bytes({
        "headers": headers,
        "status_code": 200,
        "content_type": "application/json",
        "proxy_hit": proxy_hit,
        "fingerprint": fingerprint,
        "offset": offset,
    })
    return '"' + hashlib.sha256(body + b"\0" + metadata).hexdigest() + '"'


def _view(
    record: _TruthSourceRecordV1,
    source: str,
    end: int,
) -> ArchivedTruthRecordViewV1:
    status = record.evidence_status
    effective_status = status
    if record.embargo_until_ns is not None and record.embargo_until_ns > end:
        effective_status = "EMBARGOED"
    checksum = _digest(_semantic_payload(record, status))
    redact = effective_status in ("EMBARGOED", "UNENTITLED")
    return ArchivedTruthRecordViewV1(
        record_id=record.record_id,
        dataset=record.dataset,
        symbol=record.symbol,
        osi=record.osi,
        timestamp_ns=record.timestamp_ns,
        timestamp_precision=record.timestamp_precision,
        side=record.side,
        venue=record.venue,
        currency=record.currency,
        event_type=record.event_type,
        price=None if redact else record.price,
        size=None if redact else record.size,
        value=None if redact else record.value,
        liquidity_flag=None if redact else record.liquidity_flag,
        evidence_status=status,
        effective_status=effective_status,
        historical_verdict=None,
        confirmation_eligible=False,
        route_permitted=False,
        source="legacy" if source == "legacy" else "proxy",
        origin="LEGACY" if source == "legacy" else "PROXY",
        schema_version="legacy-1" if source == "legacy" else "mapped-v2",
        source_dataset=record.source_dataset,
        source_schema_version=record.source_schema_version,
        source_version=record.source_version,
        source_license=record.source_license,
        source_entitlement=record.source_entitlement,
        source_checksum=record.source_checksum,
        source_trace_id=record.source_trace_id,
        availability_ns=record.availability_ns,
        embargo_until_ns=record.embargo_until_ns,
        checksum=checksum,
    )


def _cursor_fingerprint(query: ArchivedTruthQueryV1, policy: ArchivedTruthPolicyV1) -> str:
    return _digest(
        {
            "snapshot_version": policy.snapshot_version,
            "tenant_id": query.tenant_id,
            "dataset": query.dataset,
            "start_utc": query.start_utc,
            "end_utc": query.end_utc,
            "symbol": query.symbol,
            "osi": query.osi,
            "side": query.side,
            "venue": query.venue,
            "currency": query.currency,
            "event_type": query.event_type,
            "limit": query.limit,
        }
    )


def translate_archived_truth(
    query: ArchivedTruthQueryV1,
    legacy_records: Iterable[LegacyTruthRecordV1],
    mapped_records: Callable[[], Iterable[MappedTruthRecordV1]] | None,
    policy: ArchivedTruthPolicyV1,
) -> ArchivedTruthResultV1:
    """Use legacy rows first; invoke an injected proxy snapshot supplier only if allowed."""
    if type(query) is not ArchivedTruthQueryV1:
        raise ArchivedTruthBoundaryError("INVALID_QUERY_TYPE", ("query",))
    if type(policy) is not ArchivedTruthPolicyV1:
        raise ArchivedTruthBoundaryError("INVALID_POLICY_TYPE", ("policy",))
    if mapped_records is not None and not callable(mapped_records):
        raise ArchivedTruthBoundaryError("INVALID_CALLBACK_TYPE", ("mapped_records",))
    if not policy.reads_enabled:
        return _failure(410, "ARCHIVED_TRUTH_SUNSET", query, policy, migrate=True)
    if not query.tenant_id or not query.read_scope_verified:
        return _failure(403, "AUTH_SCOPE_MISSING", query, policy)
    start, end, invalid = _validate(query, policy)
    if invalid or start is None or end is None:
        code = "INVALID_TIME_RANGE" if "start_utc" in invalid else "INVALID_IDENTIFIER"
        if invalid == ("limit",):
            code = "INVALID_REQUEST"
        return _failure(400, code, query, policy, invalid)
    fingerprint = _cursor_fingerprint(query, policy)
    offset = 0
    if query.cursor is not None:
        match = _CURSOR.fullmatch(query.cursor)
        if match is None or match.group(2) != fingerprint:
            return _failure(400, "INVALID_CURSOR", query, policy, ("cursor",))
        offset = int(match.group(1))
    legacy = _matching(legacy_records, query, start, end, LegacyTruthRecordV1, "legacy_records")
    source = "legacy"
    selected: tuple[_TruthSourceRecordV1, ...]
    if legacy:
        if not policy.legacy_dataset_permitted:
            return _failure(403, "DATASET_PERMISSION_MISSING", query, policy)
        selected = legacy
    else:
        if not policy.proxy_enabled or mapped_records is None:
            return _failure(404, "NOT_FOUND", query, policy)
        if not policy.new_dataset_permitted:
            return _failure(403, "FORBIDDEN_NEW_DATASET", query, policy)
        source = "proxy"
        selected = _matching(
            mapped_records(), query, start, end, MappedTruthRecordV1, "mapped_records"
        )
        if not selected:
            return _failure(404, "NOT_FOUND", query, policy)
    views = tuple(_view(record, source, end) for record in selected)
    by_key: dict[str, str] = {}
    unique: list[ArchivedTruthRecordViewV1] = []
    for record, view in zip(selected, views, strict=True):
        key = record.mapping_key if source == "proxy" else record.record_id
        if not key:
            return _failure(404, "NOT_FOUND", query, policy)
        previous = by_key.get(key)
        if previous is not None and previous != view.checksum:
            return _failure(422, "AMBIGUOUS_MAPPING", query, policy, ("mapping_key",))
        if previous is None:
            unique.append(view)
            by_key[key] = view.checksum
    ordered = tuple(sorted(unique, key=lambda item: (item.timestamp_ns, item.checksum)))
    if offset > len(ordered):
        return _failure(400, "INVALID_CURSOR", query, policy, ("cursor",))
    page = ordered[offset : offset + query.limit]
    next_offset = offset + len(page)
    next_cursor = f"v1:{next_offset}:{fingerprint}" if next_offset < len(ordered) else None
    headers = (
        *_headers(policy),
        ("Content-Type", "application/json"),
        ("X-Truth-Schema-Version", "legacy-1" if source == "legacy" else "mapped-v2"),
    )
    licenses = {item.source_license for item in page}
    if len(licenses) == 1 and None not in licenses:
        license_value = next(iter(licenses))
        assert license_value is not None
        headers = (*headers, ("X-Market-Data-License", license_value))
    etag = _representation_etag(
        page, headers, fingerprint, offset, next_cursor, source == "proxy"
    )
    headers = (*headers, ("ETag", etag))
    if query.if_none_match == etag:
        return ArchivedTruthResultV1(status_code=304, headers=headers, proxy_hit=source == "proxy")
    return ArchivedTruthResultV1(
        status_code=200,
        headers=headers,
        records=page,
        next_cursor=next_cursor,
        proxy_hit=source == "proxy",
    )


def deny_archived_truth_write(
    verb: str, policy: ArchivedTruthPolicyV1
) -> ArchivedTruthWriteDecisionV1:
    """Describe a 405 for any mutating archived-truth method."""
    if type(policy) is not ArchivedTruthPolicyV1:
        raise ArchivedTruthBoundaryError("INVALID_POLICY_TYPE", ("policy",))
    if not isinstance(verb, str):
        raise ArchivedTruthBoundaryError("INVALID_VERB_TYPE", ("verb",))
    del verb
    return ArchivedTruthWriteDecisionV1(
        status_code=405,
        code="METHOD_NOT_ALLOWED",
        allow="GET,HEAD",
        headers=(*_headers(policy), ("Allow", "GET,HEAD")),
    )
