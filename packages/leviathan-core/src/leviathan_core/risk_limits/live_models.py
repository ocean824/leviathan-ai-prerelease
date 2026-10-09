"""Typed inputs and sealed results for the fake-first live guard."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, NoReturn, SupportsIndex

from leviathan_core.execution.broker_port_v1 import BrokerVenue, VenueIdentityV1

_MAX_NS = (1 << 63) - 1
_MAX_EVIDENCE_AGE_NS = 300_000_000_000


class LiveGuardInputError(ValueError):
    """Content-free, stable validation failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class _Frozen:
    __slots__ = ()

    def __copy__(self) -> NoReturn:
        raise TypeError("live guard evidence cannot be copied")

    def __deepcopy__(self, _memo: dict[int, object]) -> NoReturn:
        raise TypeError("live guard evidence cannot be copied")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> NoReturn:
        raise TypeError("live guard evidence cannot be serialized")


def _identifier(value: object, code: str = "INPUT_INVALID") -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > 128
        or value != value.strip()
        or not value.isascii()
        or any(not (char.isalnum() or char in "_.:/-") for char in value)
    ):
        raise LiveGuardInputError(code)
    return value


def _ns(value: object, *, minimum: int = 1) -> int:
    if type(value) is not int or not minimum <= value <= _MAX_NS:
        raise LiveGuardInputError("POLICY_OUT_OF_BOUNDS")
    return value


@dataclass(frozen=True, slots=True)
class LiveGuardPolicyV1(_Frozen):
    """Explicit per-account freshness policy; production values have no defaults."""

    account_id: str
    environment: str
    policy_revision: str
    venue_id: str
    strategy_id: str
    instrument_id: str
    broker_venue: BrokerVenue
    required_stream_keys: tuple[tuple[str, str, str, str, str, str], ...]
    live_switch_enabled: bool
    max_account_age_ns: int
    max_equity_age_ns: int
    max_stream_age_ns: int
    max_clock_skew_ns: int

    def __post_init__(self) -> None:
        _identifier(self.account_id)
        _identifier(self.policy_revision)
        _identifier(self.venue_id)
        _identifier(self.strategy_id)
        _identifier(self.instrument_id)
        if type(self.environment) is not str or self.environment not in {
            "PAPER",
            "DEMO",
            "LIVE",
        }:
            raise LiveGuardInputError("ENVIRONMENT_INVALID")
        if type(self.broker_venue) is not BrokerVenue:
            raise LiveGuardInputError("VENUE_INVALID")
        if type(self.live_switch_enabled) is not bool:
            raise LiveGuardInputError("POLICY_INVALID")
        if type(self.required_stream_keys) is not tuple or not self.required_stream_keys:
            raise LiveGuardInputError("STREAM_EVIDENCE_INVALID")
        for key in self.required_stream_keys:
            if type(key) is not tuple or len(key) != 6:
                raise LiveGuardInputError("STREAM_EVIDENCE_INVALID")
            for component in key:
                _identifier(component, "STREAM_EVIDENCE_INVALID")
                if component == "*":
                    raise LiveGuardInputError("STREAM_EVIDENCE_INVALID")
        if len(set(self.required_stream_keys)) != len(self.required_stream_keys):
            raise LiveGuardInputError("STREAM_EVIDENCE_INVALID")
        if not any(
            key[2] == self.venue_id and key[3] == self.instrument_id
            for key in self.required_stream_keys
        ):
            raise LiveGuardInputError("STREAM_COVERAGE_INCOMPLETE")
        _ns(self.max_account_age_ns)
        _ns(self.max_equity_age_ns)
        _ns(self.max_stream_age_ns)
        _ns(self.max_clock_skew_ns, minimum=0)
        if (
            self.max_account_age_ns > _MAX_EVIDENCE_AGE_NS
            or self.max_equity_age_ns > _MAX_EVIDENCE_AGE_NS
            or self.max_stream_age_ns > _MAX_EVIDENCE_AGE_NS
            or self.max_clock_skew_ns > 10_000_000
        ):
            raise LiveGuardInputError("POLICY_OUT_OF_BOUNDS")


@dataclass(frozen=True, slots=True)
class LiveGuardInputV1(_Frozen):
    """One synthetic or attested order assessment and all required evidence."""

    policy: LiveGuardPolicyV1
    order: Any
    state: Any
    hard_limits: Any
    sizing_evidence: Any
    account_view: Any
    venue_identity: VenueIdentityV1
    reconciliation: Any
    market_verdicts: tuple[object, ...]
    binding: object
    binding_request: object
    credential_status: object | None
    halt_store: object
    route_guard: object
    route_policy: object
    route_context: object

    def __post_init__(self) -> None:
        if type(self.policy) is not LiveGuardPolicyV1:
            raise LiveGuardInputError("POLICY_MISSING")
        if type(self.venue_identity) is not VenueIdentityV1:
            raise LiveGuardInputError("VENUE_INVALID")
        self.venue_identity.assert_sealed()
        if type(self.market_verdicts) is not tuple:
            raise LiveGuardInputError("STREAM_EVIDENCE_INVALID")


__all__ = ["LiveGuardInputError", "LiveGuardInputV1", "LiveGuardPolicyV1"]
