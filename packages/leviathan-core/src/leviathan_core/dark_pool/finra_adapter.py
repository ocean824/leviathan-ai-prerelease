"""Offline parser for synthetic, delayed FINRA-shaped aggregate records.

This module translates explicit aggregate vintages into DP-001 context. It has
no transport, file access, or production source-verification path.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import InitVar, dataclass, field
from decimal import Decimal
from typing import Literal, cast

from leviathan_core.numeric import NumericError, parse_decimal, parse_int
from leviathan_core.seal import Issuer, SealError, require

from .models import AggregateContextV1, DarkLensError

_SCHEMA = "finra.aggregate.fixture.v1"
_MAX_UTC_NS = 253_402_300_799_999_999_999
_TIER_TO_VENUE = {"ATS": "ATS", "OTC": "FINRA-TRF"}
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/+-]{0,127}\Z", re.ASCII)
_DARK_CONTEXT_ISSUER = Issuer("dp002.dark_aggregate_context.v1")
_FACTORY_KEY = object()


@dataclass(frozen=True, slots=True, weakref_slot=True)
class DarkAggregateContextV1(AggregateContextV1):
    """Adapter-local sealed subtype carrying aggregate source provenance."""

    source_file_sha256: str = field(kw_only=True)
    api_revision: str = field(kw_only=True)
    tier: Literal["ATS", "OTC"] = field(kw_only=True)
    security_id: str = field(kw_only=True)
    period_start_ns: int = field(kw_only=True)
    period_end_ns: int = field(kw_only=True)
    metric_name: str = field(kw_only=True)
    metric_unit: str = field(kw_only=True)
    metric_value: Decimal = field(kw_only=True)
    received_ns: int = field(kw_only=True)
    publication_schedule_id: str = field(kw_only=True)
    revision_id: str = field(kw_only=True)
    supersedes_revision_id: str | None = field(kw_only=True)
    verification: Literal["SYNTHETIC_TEST"] = field(kw_only=True)
    license_status: Literal["SYNTHETIC_ONLY"] = field(kw_only=True)
    _factory_key: InitVar[object] = field(default=None, kw_only=True, repr=False, compare=False)

    def __init__(
        self,
        instrument_id: str,
        source_id: str,
        dataset_id: str,
        venue: str,
        native_id: str,
        event_ns: int,
        published_ns: int | None,
        available_ns: int | None,
        exchange_tz: str,
        calendar_version: str,
        release_vintage: str,
        entitlement_status: str = "UNVERIFIED",
        source_state: str = "AGGREGATE_ONLY",
        *,
        source_file_sha256: str,
        api_revision: str,
        tier: Literal["ATS", "OTC"],
        security_id: str,
        period_start_ns: int,
        period_end_ns: int,
        metric_name: str,
        metric_unit: str,
        metric_value: Decimal,
        received_ns: int,
        publication_schedule_id: str,
        revision_id: str,
        supersedes_revision_id: str | None,
        verification: Literal["SYNTHETIC_TEST"],
        license_status: Literal["SYNTHETIC_ONLY"],
        _factory_key: object = None,
    ) -> None:
        if _factory_key is not _FACTORY_KEY:
            raise DarkLensError("UNISSUED_CONTEXT", "context requires adapter issuance")
        try:
            require(self, _DARK_CONTEXT_ISSUER.tag)
        except SealError as exc:
            if exc.code != "SEAL_NOT_ISSUED":
                raise
        else:
            raise SealError("SEAL_FORBIDDEN_OPERATION")
        for name, value in (
            ("instrument_id", instrument_id),
            ("source_id", source_id),
            ("dataset_id", dataset_id),
            ("venue", venue),
            ("native_id", native_id),
            ("event_ns", event_ns),
            ("published_ns", published_ns),
            ("available_ns", available_ns),
            ("exchange_tz", exchange_tz),
            ("calendar_version", calendar_version),
            ("release_vintage", release_vintage),
            ("entitlement_status", entitlement_status),
            ("source_state", source_state),
            ("source_file_sha256", source_file_sha256),
            ("api_revision", api_revision),
            ("tier", tier),
            ("security_id", security_id),
            ("period_start_ns", period_start_ns),
            ("period_end_ns", period_end_ns),
            ("metric_name", metric_name),
            ("metric_unit", metric_unit),
            ("metric_value", metric_value),
            ("received_ns", received_ns),
            ("publication_schedule_id", publication_schedule_id),
            ("revision_id", revision_id),
            ("supersedes_revision_id", supersedes_revision_id),
            ("verification", verification),
            ("license_status", license_status),
        ):
            object.__setattr__(self, name, value)
        self.__post_init__(_factory_key)

    def __post_init__(self, _factory_key: object) -> None:
        if _factory_key is not _FACTORY_KEY:
            raise DarkLensError("UNISSUED_CONTEXT", "context requires adapter issuance")
        AggregateContextV1.__post_init__(self)
        if self.entitlement_status != "UNVERIFIED":
            raise DarkLensError("INVALID_ENTITLEMENT", "synthetic aggregate stays unverified")
        if self.verification != "SYNTHETIC_TEST" or self.license_status != "SYNTHETIC_ONLY":
            raise DarkLensError("INVALID_SOURCE", "only synthetic source provenance is supported")
        if self.source_state != "AGGREGATE_ONLY":
            raise DarkLensError("INVALID_SOURCE", "aggregate context must stay aggregate-only")
        if _SHA256_RE.fullmatch(self.source_file_sha256) is None:
            raise DarkLensError("INVALID_SOURCE_HASH", "source file hash must be lowercase SHA-256")
        for name in (
            "api_revision",
            "tier",
            "security_id",
            "metric_name",
            "metric_unit",
            "publication_schedule_id",
            "revision_id",
        ):
            _token(getattr(self, name), name)
        if self.tier not in _TIER_TO_VENUE:
            raise DarkLensError("INVALID_TIER", "tier must be ATS or OTC")
        if self.period_start_ns >= self.period_end_ns:
            raise DarkLensError("INVALID_PERIOD", "period start must precede period end")
        for name in ("period_start_ns", "period_end_ns", "received_ns"):
            _integer(getattr(self, name), name)
        try:
            canonical_metric = parse_decimal(self.metric_value, field="metric_value", min_value=0)
        except NumericError as exc:
            raise DarkLensError("INVALID_METRIC", "aggregate metric is invalid") from exc
        object.__setattr__(self, "metric_value", canonical_metric)
        if self.published_ns is None or self.available_ns is None:
            raise DarkLensError("INVALID_PUBLICATION", "aggregate times are required")
        if not self.period_end_ns <= self.published_ns <= self.received_ns <= self.available_ns:
            raise DarkLensError("INVALID_PUBLICATION", "aggregate publication order is invalid")
        if self.supersedes_revision_id is not None:
            _token(self.supersedes_revision_id, "supersedes_revision_id")


@dataclass(frozen=True, slots=True)
class _ParsedRow:
    source_file_sha256: str
    api_revision: str
    dataset_id: str
    tier: Literal["ATS", "OTC"]
    security_id: str
    period_start_ns: int
    period_end_ns: int
    metric_name: str
    metric_unit: str
    metric_value: Decimal
    published_ns: int
    received_ns: int
    available_ns: int
    publication_schedule_id: str
    revision_id: str
    supersedes_revision_id: str | None
    native_id: str

    def semantic_key(self) -> tuple[str, str, int, int, str, str]:
        return (
            self.tier,
            self.security_id,
            self.period_start_ns,
            self.period_end_ns,
            self.metric_name,
            self.metric_unit,
        )


def _invalid(code: str, message: str) -> DarkLensError:
    return DarkLensError(code, message)


def _mapping(value: object, field: str, keys: set[str]) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise _invalid("INVALID_ENVELOPE", f"{field} must be an object")
    if set(value) != keys:
        raise _invalid("INVALID_ENVELOPE", f"{field} has an invalid field set")
    return cast(Mapping[str, object], value)


def _token(value: object, field: str) -> str:
    if not isinstance(value, str) or _TOKEN_RE.fullmatch(value) is None:
        raise _invalid("INVALID_ENVELOPE", f"{field} has invalid syntax")
    return value


def _integer(value: object, field: str) -> int:
    try:
        return parse_int(value, field=field, min_value=0, max_value=_MAX_UTC_NS)
    except NumericError as exc:
        raise _invalid("INVALID_ENVELOPE", f"{field} must be a UTC nanosecond integer") from exc


def _visible_at(value: object, *, observed_ns: int) -> bool:
    """Validate row chronology, then apply the PIT visibility cutoff.

    Only the timestamp envelope is inspected for an unseen row. Its metric,
    source identity, schedule membership, and correction lineage are not
    allowed to influence this as-of view.
    """
    timestamp_fields = {
        "period_start_ns",
        "period_end_ns",
        "published_ns",
        "received_ns",
        "available_ns",
    }
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise _invalid("INVALID_ENVELOPE", "row must be an object")
    if not timestamp_fields.issubset(value):
        raise _invalid("INVALID_ENVELOPE", "row is missing timestamp fields")
    row = cast(Mapping[str, object], value)
    period_start_ns = _integer(row["period_start_ns"], "period_start_ns")
    period_end_ns = _integer(row["period_end_ns"], "period_end_ns")
    published_ns = _integer(row["published_ns"], "published_ns")
    received_ns = _integer(row["received_ns"], "received_ns")
    available_ns = _integer(row["available_ns"], "available_ns")
    if period_start_ns >= period_end_ns:
        raise _invalid("INVALID_PERIOD", "period start must precede period end")
    if not period_end_ns <= published_ns <= received_ns <= available_ns:
        raise _invalid(
            "INVALID_PUBLICATION", "publication, receipt and availability order is invalid"
        )
    return published_ns <= observed_ns and available_ns <= observed_ns


def _parsed_row(
    value: object,
    *,
    source_file_sha256: str,
    api_revision: str,
    dataset_id: str,
    tier: Literal["ATS", "OTC"],
    publication_schedule_id: str,
    schedule: Mapping[tuple[int, int], frozenset[int]],
    observed_ns: int,
) -> _ParsedRow:
    fields = {
        "security_id",
        "period_start_ns",
        "period_end_ns",
        "metric_name",
        "metric_unit",
        "metric_value",
        "published_ns",
        "received_ns",
        "available_ns",
        "revision_id",
        "supersedes_revision_id",
        "native_id",
    }
    row = _mapping(value, "row", fields)
    security_id = _token(row["security_id"], "security_id")
    period_start_ns = _integer(row["period_start_ns"], "period_start_ns")
    period_end_ns = _integer(row["period_end_ns"], "period_end_ns")
    if period_start_ns >= period_end_ns:
        raise _invalid("INVALID_PERIOD", "period start must precede period end")
    metric_name = _token(row["metric_name"], "metric_name")
    metric_unit = _token(row["metric_unit"], "metric_unit")
    try:
        metric_value = parse_decimal(row["metric_value"], field="metric_value", min_value=0)
    except NumericError as exc:
        raise _invalid("INVALID_METRIC", "aggregate metric is invalid") from exc

    published_ns = _integer(row["published_ns"], "published_ns")
    received_ns = _integer(row["received_ns"], "received_ns")
    available_ns = _integer(row["available_ns"], "available_ns")
    if not period_end_ns <= published_ns <= received_ns <= available_ns:
        raise _invalid(
            "INVALID_PUBLICATION", "publication, receipt and availability order is invalid"
        )
    if max(published_ns, received_ns, available_ns) > observed_ns:
        raise _invalid("FUTURE_PUBLICATION", "source timestamp exceeds injected observation time")
    scheduled_times = schedule.get((period_start_ns, period_end_ns), frozenset())
    if published_ns not in scheduled_times:
        raise _invalid(
            "PUBLICATION_SCHEDULE_MISMATCH", "publication lacks matching injected schedule"
        )

    revision_id = _token(row["revision_id"], "revision_id")
    supersedes_value = row["supersedes_revision_id"]
    supersedes_revision_id = (
        None if supersedes_value is None else _token(supersedes_value, "supersedes_revision_id")
    )
    native_id = _token(row["native_id"], "native_id")
    return _ParsedRow(
        source_file_sha256=source_file_sha256,
        api_revision=api_revision,
        dataset_id=dataset_id,
        tier=tier,
        security_id=security_id,
        period_start_ns=period_start_ns,
        period_end_ns=period_end_ns,
        metric_name=metric_name,
        metric_unit=metric_unit,
        metric_value=metric_value,
        published_ns=published_ns,
        received_ns=received_ns,
        available_ns=available_ns,
        publication_schedule_id=publication_schedule_id,
        revision_id=revision_id,
        supersedes_revision_id=supersedes_revision_id,
        native_id=native_id,
    )


def _validate_lineage(rows: tuple[_ParsedRow, ...]) -> tuple[_ParsedRow, ...]:
    by_semantic: dict[tuple[str, str, int, int, str, str], dict[str, _ParsedRow]] = {}
    by_native: dict[tuple[str, str], _ParsedRow] = {}
    for row in rows:
        native_key = (row.dataset_id, row.native_id)
        prior_native = by_native.get(native_key)
        if prior_native is not None:
            if prior_native != row:
                raise _invalid(
                    "CONFLICTING_DUPLICATE", "native id has conflicting aggregate content"
                )
            continue
        by_native[native_key] = row
        revisions = by_semantic.setdefault(row.semantic_key(), {})
        prior_revision = revisions.get(row.revision_id)
        if prior_revision is not None:
            if prior_revision != row:
                raise _invalid(
                    "CONFLICTING_DUPLICATE", "revision id has conflicting aggregate content"
                )
            continue
        revisions[row.revision_id] = row

    for revisions in by_semantic.values():
        children: set[str] = set()
        roots = [row for row in revisions.values() if row.supersedes_revision_id is None]
        if len(roots) != 1:
            raise _invalid(
                "INVALID_REVISION_LINEAGE", "aggregate vintage needs exactly one original"
            )
        for row in revisions.values():
            previous_id = row.supersedes_revision_id
            if previous_id is None:
                continue
            previous = revisions.get(previous_id)
            if previous is None:
                raise _invalid("ORPHAN_REVISION", "aggregate correction lacks its predecessor")
            if previous.published_ns > row.published_ns or previous_id in children:
                raise _invalid("INVALID_REVISION_LINEAGE", "revision chain is not append-only")
            children.add(previous_id)
        root_id = roots[0].revision_id
        for row in revisions.values():
            current = row
            visited: set[str] = set()
            while current.supersedes_revision_id is not None:
                if current.revision_id in visited:
                    raise _invalid("INVALID_REVISION_LINEAGE", "revision chain contains a cycle")
                visited.add(current.revision_id)
                current = revisions[current.supersedes_revision_id]
            if current.revision_id != root_id:
                raise _invalid("INVALID_REVISION_LINEAGE", "revision is disconnected from original")

    return tuple(
        sorted(
            by_native.values(),
            key=lambda row: (
                row.period_start_ns,
                row.period_end_ns,
                row.tier,
                row.security_id,
                row.metric_name,
                row.metric_unit,
                row.published_ns,
                row.revision_id,
                row.native_id,
            ),
        )
    )


def _issue_context(row: _ParsedRow) -> DarkAggregateContextV1:
    release_vintage = f"{row.period_start_ns}-{row.period_end_ns}:{row.revision_id}"
    try:
        result = DarkAggregateContextV1(
            instrument_id=row.security_id,
            source_id="FINRA",
            dataset_id=row.dataset_id,
            venue=_TIER_TO_VENUE[row.tier],
            native_id=row.native_id,
            event_ns=row.period_end_ns,
            published_ns=row.published_ns,
            available_ns=row.available_ns,
            exchange_tz="UTC",
            calendar_version="utc-aggregate-period-v1",
            release_vintage=release_vintage,
            entitlement_status="UNVERIFIED",
            source_state="AGGREGATE_ONLY",
            source_file_sha256=row.source_file_sha256,
            api_revision=row.api_revision,
            tier=row.tier,
            security_id=row.security_id,
            period_start_ns=row.period_start_ns,
            period_end_ns=row.period_end_ns,
            metric_name=row.metric_name,
            metric_unit=row.metric_unit,
            metric_value=row.metric_value,
            received_ns=row.received_ns,
            publication_schedule_id=row.publication_schedule_id,
            revision_id=row.revision_id,
            supersedes_revision_id=row.supersedes_revision_id,
            verification="SYNTHETIC_TEST",
            license_status="SYNTHETIC_ONLY",
            _factory_key=_FACTORY_KEY,
        )
        issued = _DARK_CONTEXT_ISSUER.issue(result)
        return require_dark_context(issued)
    except (DarkLensError, SealError, TypeError, ValueError):
        raise _invalid("INVALID_CONTEXT", "aggregate context failed issuance validation") from None


def require_dark_context(value: object) -> DarkAggregateContextV1:
    """Validate the seal before an adapter context is used or exported."""
    if type(value) is not DarkAggregateContextV1:
        raise _invalid("INVALID_CONTEXT", "expected a sealed dark aggregate context")
    try:
        return require(value, _DARK_CONTEXT_ISSUER.tag)
    except SealError:
        raise _invalid("INVALID_CONTEXT", "dark aggregate context seal is invalid") from None


def require_dark_aggregate_context(value: object) -> DarkAggregateContextV1:
    """Compatibility alias for the public adapter seal check."""
    return require_dark_context(value)


def parse_finra_aggregate_fixture(
    payload: Mapping[str, object], *, observed_ns: int
) -> tuple[DarkAggregateContextV1, ...]:
    """Parse a synthetic fixture mapping into sealed aggregate-only contexts.

    The explicit release table is injected by the fixture. No delay is inferred
    from the reporting period, and the observation clock is supplied by caller.
    """
    observed_ns = _integer(observed_ns, "observed_ns")
    envelope = _mapping(
        payload,
        "fixture",
        {
            "schema",
            "verification",
            "license_status",
            "source_file_sha256",
            "api_revision",
            "dataset_id",
            "tier",
            "schedule",
            "rows",
        },
    )
    if envelope["schema"] != _SCHEMA:
        raise _invalid("INVALID_ENVELOPE", "fixture schema is unsupported")
    if envelope["verification"] != "SYNTHETIC_TEST":
        raise _invalid("UNVERIFIED_SOURCE", "only synthetic test metadata is accepted")
    if envelope["license_status"] != "SYNTHETIC_ONLY":
        raise _invalid("UNLICENSED_SOURCE", "only synthetic fixture usage is permitted")
    source_file_sha256 = envelope["source_file_sha256"]
    if not isinstance(source_file_sha256, str) or _SHA256_RE.fullmatch(source_file_sha256) is None:
        raise _invalid("INVALID_SOURCE_HASH", "source file hash must be lowercase SHA-256")
    api_revision = _token(envelope["api_revision"], "api_revision")
    dataset_id = _token(envelope["dataset_id"], "dataset_id")
    tier_value = envelope["tier"]
    if not isinstance(tier_value, str) or tier_value not in _TIER_TO_VENUE:
        raise _invalid("INVALID_TIER", "tier must be ATS or OTC")
    tier = cast(Literal["ATS", "OTC"], tier_value)

    schedule_data = _mapping(envelope["schedule"], "schedule", {"schedule_id", "releases"})
    schedule_id = _token(schedule_data["schedule_id"], "schedule_id")
    releases = schedule_data["releases"]
    if not isinstance(releases, (list, tuple)):
        raise _invalid("INVALID_SCHEDULE", "release schedule must be a sequence")
    schedule_times: dict[tuple[int, int], set[int]] = {}
    for release_item in releases:
        release = _mapping(
            release_item,
            "release",
            {"period_start_ns", "period_end_ns", "published_ns"},
        )
        start = _integer(release["period_start_ns"], "period_start_ns")
        end = _integer(release["period_end_ns"], "period_end_ns")
        published = _integer(release["published_ns"], "published_ns")
        period = (start, end)
        times = schedule_times.setdefault(period, set())
        if start >= end or end > published or published in times:
            raise _invalid("INVALID_SCHEDULE", "release schedule entry is invalid or duplicated")
        times.add(published)
    schedule = {period: frozenset(times) for period, times in schedule_times.items()}

    raw_rows = envelope["rows"]
    if not isinstance(raw_rows, (list, tuple)):
        raise _invalid("INVALID_ENVELOPE", "rows must be a sequence")
    # Establish the as-of row set before parsing source identity/metrics or
    # reconciling revisions. An unseen correction cannot invalidate or alter
    # a view that predates its publication or availability.
    visible_raw_rows = tuple(
        raw for raw in raw_rows if _visible_at(raw, observed_ns=observed_ns)
    )
    rows = tuple(
        _parsed_row(
            raw,
            source_file_sha256=source_file_sha256,
            api_revision=api_revision,
            dataset_id=dataset_id,
            tier=tier,
            publication_schedule_id=schedule_id,
            schedule=schedule,
            observed_ns=observed_ns,
        )
        for raw in visible_raw_rows
    )
    ordered = _validate_lineage(rows)
    results = tuple(_issue_context(row) for row in ordered)
    return tuple(require_dark_context(item) for item in results)


__all__ = [
    "DarkAggregateContextV1",
    "parse_finra_aggregate_fixture",
    "require_dark_aggregate_context",
    "require_dark_context",
]
