"""Pure, boundary-tested freshness rules for the fake live kernel."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal

from .models import EntitlementState, FreshnessState, LiveStateError, SourceState

_BACKOFF_MIN_NS = 200_000_000
_BACKOFF_MAX_NS = 5_000_000_000
_MAX_ENVELOPE_BYTES = 65_536


@dataclass(frozen=True, slots=True)
class FreshnessPolicyV1:
    """Construction-validated MD-004 thresholds; callers cannot loosen them."""

    stale_multiplier: int = 2
    gap_multiplier: int = 3
    drift_alert_ms: Decimal = Decimal("2")
    drift_block_ms: Decimal = Decimal("10")
    subscribe_limit_per_second: int = 10
    reconnect_min_ms: int = 200
    reconnect_max_ms: int = 5_000
    max_envelope_bytes: int = 65_536

    def __post_init__(self) -> None:
        if (
            type(self.stale_multiplier) is not int
            or self.stale_multiplier != 2
            or type(self.gap_multiplier) is not int
            or self.gap_multiplier != 3
            or type(self.subscribe_limit_per_second) is not int
            or self.subscribe_limit_per_second != 10
            or type(self.reconnect_min_ms) is not int
            or self.reconnect_min_ms != 200
            or type(self.reconnect_max_ms) is not int
            or self.reconnect_max_ms != 5_000
            or type(self.max_envelope_bytes) is not int
            or self.max_envelope_bytes != 65_536
            or type(self.drift_alert_ms) is not Decimal
            or not self.drift_alert_ms.is_finite()
            or self.drift_alert_ms != Decimal("2")
            or type(self.drift_block_ms) is not Decimal
            or not self.drift_block_ms.is_finite()
            or self.drift_block_ms != Decimal("10")
        ):
            raise LiveStateError("INVALID_POLICY")


def reconnect_backoff_ns(attempt: int, jitter_basis_points: int) -> int:
    """Return deterministic bounded jitter; no sleeper or random global is used."""
    if type(attempt) is not int or attempt < 0:
        raise LiveStateError("INVALID_POLICY")
    if type(jitter_basis_points) is not int or not 0 <= jitter_basis_points <= 10_000:
        raise LiveStateError("INVALID_POLICY")
    # Cap the exponent before expansion, then use integer arithmetic only.
    exponent = min(attempt, 5)
    ceiling = min(_BACKOFF_MIN_NS * (1 << exponent), _BACKOFF_MAX_NS)
    return _BACKOFF_MIN_NS + (ceiling - _BACKOFF_MIN_NS) * jitter_basis_points // 10_000


def validate_envelope_size(envelope: bytes) -> None:
    """Reject non-bytes or oversized input without parsing or echoing its content."""
    if type(envelope) is not bytes:
        raise LiveStateError("INVALID_ENVELOPE")
    if len(envelope) > _MAX_ENVELOPE_BYTES:
        raise LiveStateError("ENVELOPE_TOO_LARGE")


def evaluate_freshness(
    *,
    now_monotonic_ns: int,
    heartbeat_interval_ns: int,
    last_heartbeat_monotonic_ns: int | None,
    node_drift_ns: int | None,
    entitlement: EntitlementState,
    source_status: SourceState,
    halted: bool,
    active: bool,
    policy: FreshnessPolicyV1,
) -> tuple[FreshnessState, tuple[str, ...], int | None]:
    """Evaluate a stream using server monotonic time; unknown inputs fail closed."""
    age: int | None = None
    if last_heartbeat_monotonic_ns is not None:
        if now_monotonic_ns < last_heartbeat_monotonic_ns:
            return "STALE", ("MONOTONIC_CLOCK_REGRESSION",), None
        age = now_monotonic_ns - last_heartbeat_monotonic_ns
    if halted:
        return "HALTED", ("GLOBAL_HALT",), age
    if entitlement != "GRANTED":
        return "UNENTITLED", ("ENTITLEMENT_" + entitlement,), age
    if source_status == "HALTED":
        return "HALTED", ("SOURCE_HALTED",), age
    if source_status != "ACTIVE" or not active:
        return "DISCONNECTED", ("SOURCE_" + source_status,), age
    if last_heartbeat_monotonic_ns is None:
        return "UNKNOWN", ("HEARTBEAT_UNKNOWN",), None
    if age is not None and age > heartbeat_interval_ns * policy.gap_multiplier:
        return "STALE", ("HEARTBEAT_GAP",), age
    if age is not None and age > heartbeat_interval_ns * policy.stale_multiplier:
        return "STALE", ("HEARTBEAT_STALE",), age
    if node_drift_ns is None:
        return "UNKNOWN", ("CLOCK_DRIFT_UNKNOWN",), age
    magnitude_ns = abs(node_drift_ns)
    if magnitude_ns > 10_000_000:
        return "STALE", ("DRIFT_EXCEEDED",), age
    if magnitude_ns > 2_000_000:
        return "DEGRADED", ("CLOCK_DRIFT_ALERT",), age
    return "HEALTHY", (), age
