"""Closed, versioned reason vocabulary for the public HALT request surface."""

from __future__ import annotations

import re
from enum import StrEnum


class HaltReasonV1(StrEnum):
    """Static HALT reasons used by operators and integrated kernels."""

    OMEGA_KILL_SIGNAL = "omega_kill_signal"
    OPERATOR_HALT = "operator_halt"
    OPERATOR_HOLD = "operator_hold"
    RISK_LIMIT_BREACH = "risk_limit_breach"
    STALE_DATA = "stale_data"
    RECONCILIATION_DIVERGENCE = "reconciliation_divergence"
    AUDIT_SINK_FAILURE = "audit_sink_failure"
    TIAMAT_HASH_MISMATCH = "tiamat_hash_mismatch"
    DAILY_DRAWDOWN_BREACH = "daily_drawdown_breach"
    WEEKLY_DRAWDOWN_BREACH = "weekly_drawdown_breach"
    TRAILING_DRAWDOWN_BREACH = "trailing_drawdown_breach"
    LEGACY_STATE_UNKNOWN = "legacy_state_unknown"


class HaltReasonPatternV1(StrEnum):
    """Closed prefixes for content-addressed OMEGA HALT keys."""

    OMEGA_KILL = "omega_kill"
    OMEGA_BRIDGE_DISCONNECTED = "omega_bridge_disconnected"
    OMEGA_BRIDGE_DEGRADED = "omega_bridge_degraded"


_DYNAMIC_SUFFIX = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_STATIC_REASONS = frozenset(reason.value for reason in HaltReasonV1)
_DYNAMIC_PREFIXES = frozenset(reason.value for reason in HaltReasonPatternV1)


def is_known_halt_reason(value: object) -> bool:
    """Return whether a value is a declared static code or exact OMEGA key."""
    if isinstance(value, HaltReasonV1):
        return True
    if type(value) is not str:
        return False
    if value in _STATIC_REASONS:
        return True
    prefix, separator, suffix = value.partition(":")
    return (
        separator == ":"
        and prefix in _DYNAMIC_PREFIXES
        and _DYNAMIC_SUFFIX.fullmatch(suffix) is not None
    )


def is_static_halt_reason(value: object) -> bool:
    """Return whether a value is one of the closed, non-pattern reason codes."""
    if isinstance(value, HaltReasonV1):
        return True
    return type(value) is str and value in _STATIC_REASONS


__all__ = [
    "HaltReasonPatternV1",
    "HaltReasonV1",
    "is_known_halt_reason",
    "is_static_halt_reason",
]
