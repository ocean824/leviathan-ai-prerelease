"""Source registry contribution and lossless INTEL payload for learned operations."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from leviathan_market_data.public_sources.api_anything_client import (
    CollectorSupervisor,
    PublicOperationRecordV1,
    PublicOperationResultV1,
)
from leviathan_market_data.public_sources.registry import PublicSourceV1


@dataclass(frozen=True, slots=True)
class _SourceRow:
    source_id: str
    endpoint: str
    tos_classification: str
    tos_url: str
    cadence_seconds: int
    factor_tags: tuple[str, ...]
    point_in_time_rule: str


_SOURCE_ROWS = (
    _SourceRow(
        "api_anything.calendar.fed",
        "https://www.federalreserve.gov/monetarypolicy/fomccalendars.htm",
        "ALLOWED",
        "https://www.federalreserve.gov/monetarypolicy/fomccalendars.htm",
        86400,
        ("event_risk",),
        "Fed page's publication/updated timestamp or first observed availability",
    ),
    _SourceRow(
        "api_anything.earnings.forward",
        "https://finance.yahoo.com/calendar/earnings/",
        "REVIEW",
        "https://finance.yahoo.com/",
        21600,
        ("earnings", "event_risk"),
        "Original calendar publication timestamp; no point-in-time record without knowable_at",
    ),
    _SourceRow(
        "api_anything.senate.efd.ptr",
        "https://efdsearch.senate.gov/search/",
        "REVIEW",
        "https://efdsearch.senate.gov/search/",
        86400,
        ("political_trades",),
        "Senate report filing/publication timestamp; transaction date is event metadata",
    ),
    _SourceRow(
        "api_anything.cboe.daily.stats",
        "https://www.cboe.com/us/indices/dashboard/putcall/",
        "REVIEW",
        "https://www.cboe.com/us/en/about/market-data/",
        86400,
        ("volatility",),
        "Cboe publication timestamp or conservative first observed availability",
    ),
    _SourceRow(
        "api_anything.cnn.fear_greed",
        "https://www.cnn.com/markets/fear-and-greed",
        "REVIEW",
        "https://www.cnn.com/markets/fear-and-greed",
        3600,
        ("sentiment",),
        "CNN source timestamp; missing timestamp abstains",
    ),
)


def _sources() -> tuple[PublicSourceV1, ...]:
    """Build using the writer-owned canonical metadata type."""
    return tuple(
        PublicSourceV1(
            source_id=row.source_id,
            endpoint=row.endpoint,
            format="api-anything typed JSON",
            auth="none; public pages only",
            tos_classification=row.tos_classification,
            tos_url=row.tos_url,
            tier=3,
            cadence=f"at most once per {row.cadence_seconds} seconds",
            point_in_time_rule=row.point_in_time_rule,
            factor_tags=row.factor_tags,
            redistribution=False,
        )
        for row in _SOURCE_ROWS
    )


PUBLIC_SOURCES = _sources()


def create_client(
    node_executable: str | Path,
    sidecar_script: str | Path,
    *,
    data_dir: str | Path,
) -> CollectorSupervisor:
    return CollectorSupervisor(node_executable, sidecar_script, data_dir=data_dir)


def intel_evidence_payload(record: PublicOperationRecordV1) -> dict[str, object]:
    """Return the complete deterministic source record INTEL binds into EvidenceRef."""
    return {
        "operation_id": record.operation_id,
        "template_version": record.template_version,
        "source_tier": record.source_tier,
        "source_id": record.source_id,
        "record_id": record.record_id,
        "fetched_at": record.fetched_at.astimezone(UTC).isoformat(),
        "first_seen_at": record.first_seen_at.astimezone(UTC).isoformat(),
        "as_of": record.as_of.astimezone(UTC).isoformat(),
        "event_at": record.event_at.astimezone(UTC).isoformat() if record.event_at else None,
        "published_at": (
            record.published_at.astimezone(UTC).isoformat() if record.published_at else None
        ),
        "available_at": (
            record.available_at.astimezone(UTC).isoformat() if record.available_at else None
        ),
        "knowable_at": (
            record.knowable_at.astimezone(UTC).isoformat() if record.knowable_at else None
        ),
        "factor_tags": list(record.factor_tags),
        "quality": record.quality,
        "status": record.status.value,
        "template_sha256": record.template_sha256,
        "approval_id": record.approval_id,
        "approval_deadline": record.approval_deadline.astimezone(UTC).isoformat(),
        "freshness_deadline": record.freshness_deadline.astimezone(UTC).isoformat(),
        "typed_values": record.data.model_dump(mode="json"),
        "values": dict(record.values),
        "redistribution": False,
        "record_digest": record.record_digest,
    }


def known_records(
    result: PublicOperationResultV1, decision_as_of: datetime
) -> tuple[PublicOperationRecordV1, ...]:
    return result.evidence_records(decision_as_of)


__all__ = ["PUBLIC_SOURCES", "create_client", "intel_evidence_payload", "known_records"]
