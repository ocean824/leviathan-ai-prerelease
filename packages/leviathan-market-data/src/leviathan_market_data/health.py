"""Observable source health, without implying trusted risk-gate authority."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from leviathan_market_data.schema import INT64_MAX, MarketDataValueError, NoCopy


@dataclass(frozen=True, slots=True)
class SourceHealthSnapshot(NoCopy):
    provider: str
    dataset: str
    venue: str
    instrument_id: str
    channel: str
    last_received_time_ns: int | None
    last_processed_time_ns: int | None
    last_provider_time_ns: int | None
    last_exchange_time_ns: int | None
    gap_count: int
    late_count: int
    node_clock_offset_ms: float | None
    node_drift_alert: bool
    node_publish_blocked: bool
    last_event_clock_adjusted: bool
    queued_count: int
    queue_pressure: float
    unhealthy: bool
    freshness: Literal["UNKNOWN", "DEGRADED"] = "UNKNOWN"
    dedupe_restart_unproven: bool = True
    faulted: bool = False
    fault_count: int = 0
    sequence_regression_count: int = 0

    def __post_init__(self) -> None:
        times = (self.last_received_time_ns, self.last_processed_time_ns,
                 self.last_provider_time_ns, self.last_exchange_time_ns)
        counts = (self.gap_count, self.late_count, self.queued_count,
                  self.fault_count, self.sequence_regression_count)
        booleans = (self.node_drift_alert, self.node_publish_blocked,
                    self.last_event_clock_adjusted, self.unhealthy,
                    self.dedupe_restart_unproven, self.faulted)
        if (any(value is not None and (type(value) is not int
                                       or not 0 < value <= INT64_MAX) for value in times)
                or any(type(value) is not int or value < 0 for value in counts)):
            raise MarketDataValueError("INVALID_INTEGER")
        if any(type(value) is not bool for value in booleans):
            raise MarketDataValueError("INVALID_BOOLEAN")
        if self.freshness not in ("UNKNOWN", "DEGRADED"):
            raise MarketDataValueError("INVALID_HEALTH")
        if (type(self.queue_pressure) not in (int, float)
                or not 0 <= self.queue_pressure <= 1):
            raise MarketDataValueError("INVALID_HEALTH")
        if self.node_clock_offset_ms is not None and (
            type(self.node_clock_offset_ms) not in (int, float)
            or self.node_clock_offset_ms != self.node_clock_offset_ms
            or abs(self.node_clock_offset_ms) == float("inf")
        ):
            raise MarketDataValueError("INVALID_HEALTH")


@dataclass(slots=True)
class _SourceHealth:
    last_received_time_ns: int | None = None
    last_processed_time_ns: int | None = None
    last_provider_time_ns: int | None = None
    last_exchange_time_ns: int | None = None
    gap_count: int = 0
    late_count: int = 0
    last_event_clock_adjusted: bool = False
    unhealthy: bool = False
    fault_count: int = 0
    sequence_regression_count: int = 0
