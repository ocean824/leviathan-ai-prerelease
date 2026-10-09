"""Immutable, provider-free input and output ports for the offline regime kernel."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import InitVar, dataclass, field, fields
from decimal import Decimal
from fractions import Fraction
from typing import Any, Literal

FactorKind = Literal["dealer", "flow", "dp", "macro"]
Readiness = Literal["READY", "DEGRADED", "HOLD"]
ResultStatus = Literal["SCORED", "PARTIAL", "INSUFFICIENT_DATA", "HISTORY_ONLY"]

FACTOR_KINDS: tuple[FactorKind, ...] = ("dealer", "flow", "dp", "macro")
DEFAULT_WEIGHT_VERSION = "regime-default-v1"
RELEASE_LAGS_NS = {
    "none": 0,
    "fixture-release": 0,
    "5m": 300_000_000_000,
    "15m": 900_000_000_000,
    "24h": 86_400_000_000_000,
    "48h": 172_800_000_000_000,
    "72h": 259_200_000_000_000,
}
_IDENTIFIER = re.compile(r"[A-Za-z0-9._:/-]+\Z")
_RESULT_ISSUER = object()


class RegimeError(ValueError):
    """Stable error code without embedding caller-controlled values."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class _NoCopy:
    __slots__ = ()

    def __copy__(self) -> None:
        raise RegimeError("IMMUTABLE_COPY")

    def __deepcopy__(self, memo: object) -> None:
        raise RegimeError("IMMUTABLE_COPY")

    def __reduce_ex__(self, protocol: object) -> str | tuple[Any, ...]:
        raise RegimeError("IMMUTABLE_COPY")


def _identifier(value: object) -> bool:
    return isinstance(value, str) and bool(_IDENTIFIER.fullmatch(value))


def _utc_ns(value: object) -> bool:
    return type(value) is int and value >= 0


def bounded_decimal(value: object) -> Decimal:
    """Validate before arithmetic, independent of the caller's Decimal context."""
    if not isinstance(value, Decimal) or not value.is_finite():
        raise RegimeError("DECIMAL_OUT_OF_BOUNDS")
    digits = list(value.as_tuple().digits)
    while len(digits) > 1 and digits[-1] == 0:
        digits.pop()
    if len(digits) > 34:
        raise RegimeError("PRECISION_EXCEEDED")
    if abs(value.adjusted()) > 38:
        raise RegimeError("DECIMAL_OUT_OF_BOUNDS")
    return value


def canonical_value(value: object) -> Decimal:
    """Store one exact Decimal representation for each numeric value."""
    validated = bounded_decimal(value)
    return Decimal(canonical_decimal(validated))


def canonical_decimal(value: Decimal) -> str:
    """Equal bounded Decimals share one context-free audit representation."""
    bounded_decimal(value)
    sign, digits_tuple, exponent = value.as_tuple()
    digits = list(digits_tuple)
    if all(digit == 0 for digit in digits):
        return "0"
    if not isinstance(exponent, int):
        raise RegimeError("DECIMAL_OUT_OF_BOUNDS")
    while digits[-1] == 0:
        digits.pop()
        exponent += 1
    return ("-" if sign else "") + "".join(map(str, digits)) + f"e{exponent}"


class RegimeSourceIdV1(str, _NoCopy):
    """Validated source identity; trust is supplied separately by a registry."""

    __slots__ = ()

    def __new__(cls, value: str) -> RegimeSourceIdV1:
        if not _identifier(value):
            raise RegimeError("SOURCE_INVALID")
        return str.__new__(cls, value)


@dataclass(frozen=True, slots=True)
class RegimeSourceRecordV1(_NoCopy):
    source_id: RegimeSourceIdV1
    trust_class: Literal["PIPELINE", "AGENT", "MODEL"]
    entitlement: Literal["LICENSED", "SYNTHETIC", "UNENTITLED"]
    allowed_interface_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.source_id, RegimeSourceIdV1):
            raise RegimeError("SOURCE_INVALID")
        if self.trust_class not in ("PIPELINE", "AGENT", "MODEL"):
            raise RegimeError("SOURCE_TYPE_INVALID")
        if self.entitlement not in ("LICENSED", "SYNTHETIC", "UNENTITLED"):
            raise RegimeError("ENTITLEMENT_INVALID")
        if (
            type(self.allowed_interface_ids) is not tuple
            or any(not _identifier(value) for value in self.allowed_interface_ids)
            or len(self.allowed_interface_ids) != len(set(self.allowed_interface_ids))
        ):
            raise RegimeError("INTERFACE_INVALID")
        object.__setattr__(self, "allowed_interface_ids", tuple(sorted(self.allowed_interface_ids)))


@dataclass(frozen=True, slots=True)
class RegimeSourceRegistryV1(_NoCopy):
    version: str
    records: tuple[RegimeSourceRecordV1, ...]

    def __post_init__(self) -> None:
        if not _identifier(self.version) or not isinstance(self.records, tuple):
            raise RegimeError("SOURCE_REGISTRY_INVALID")
        if any(not isinstance(record, RegimeSourceRecordV1) for record in self.records):
            raise RegimeError("SOURCE_REGISTRY_INVALID")
        ids = [record.source_id for record in self.records]
        if len(ids) != len(set(ids)):
            raise RegimeError("SOURCE_REGISTRY_INVALID")

    def lookup(self, source_id: RegimeSourceIdV1) -> RegimeSourceRecordV1 | None:
        return next((record for record in self.records if record.source_id == source_id), None)


@dataclass(frozen=True, slots=True)
class RegimeFactorV1(_NoCopy):
    kind: FactorKind
    value: Decimal
    source: RegimeSourceIdV1
    source_version: str
    semantic_digest: str
    event_ns: int
    available_ns: int
    baseline_available_ns: int
    valid: bool
    fresh_until_ns: int
    scope: str
    window_sec: int
    horizon_sec: int
    entitlement: str
    release_lag: str
    feature_available_ns: int | None = None
    upstream_interface_id: str | None = None
    release_lag_ns: int = 0
    entitled: bool = True
    quality: str = "GOOD"
    scope_key: str | None = None
    source_type: str = "PIPELINE"

    def __post_init__(self) -> None:
        if self.kind not in FACTOR_KINDS:
            raise RegimeError("FACTOR_KIND_INVALID")
        object.__setattr__(self, "value", canonical_value(self.value))
        object.__setattr__(self, "source", RegimeSourceIdV1(self.source))
        if type(self.valid) is not bool or type(self.entitled) is not bool:
            raise RegimeError("BOOLEAN_REQUIRED")
        if not all(_utc_ns(value) for value in (
            self.event_ns, self.available_ns, self.baseline_available_ns,
            self.fresh_until_ns, self.release_lag_ns,
        )):
            raise RegimeError("TIME_INVALID")
        if self.feature_available_ns is not None and not _utc_ns(self.feature_available_ns):
            raise RegimeError("TIME_INVALID")
        if type(self.window_sec) is not int or self.window_sec <= 0:
            raise RegimeError("WINDOW_INVALID")
        if type(self.horizon_sec) is not int or self.horizon_sec <= 0:
            raise RegimeError("HORIZON_INVALID")
        if not all(_identifier(value) for value in (
            self.source, self.source_version, self.semantic_digest,
        )):
            raise RegimeError("SOURCE_INVALID")
        if self.scope not in ("global", "class", "symbol"):
            raise RegimeError("SCOPE_INVALID")
        if self.scope_key is not None and not _identifier(self.scope_key):
            raise RegimeError("SCOPE_INVALID")
        if self.entitlement not in ("LICENSED", "SYNTHETIC", "UNENTITLED"):
            raise RegimeError("ENTITLEMENT_INVALID")
        if not isinstance(self.release_lag, str) or self.release_lag not in RELEASE_LAGS_NS:
            raise RegimeError("RELEASE_LAG_UNKNOWN")
        if self.source_type not in ("PIPELINE", "AGENT", "MODEL"):
            raise RegimeError("SOURCE_TYPE_INVALID")
        if self.quality not in ("GOOD", "BAD", "UNKNOWN"):
            raise RegimeError("QUALITY_INVALID")
        if self.upstream_interface_id is not None and not _identifier(self.upstream_interface_id):
            raise RegimeError("INTERFACE_INVALID")


@dataclass(frozen=True, slots=True)
class RegimeClockV1(_NoCopy):
    bar_id: str
    bar_index: int
    session_id: str
    symbol: str
    universe: str
    calendar_version: str
    asof_ns: int
    finalized: bool = True
    window_sec: int | None = None
    horizon_sec: int | None = None

    def __post_init__(self) -> None:
        if not all(_identifier(value) for value in (
            self.bar_id, self.session_id, self.symbol, self.universe, self.calendar_version,
        )):
            raise RegimeError("CLOCK_IDENTITY_INVALID")
        if not _utc_ns(self.bar_index) or not _utc_ns(self.asof_ns):
            raise RegimeError("CLOCK_INVALID")
        if type(self.finalized) is not bool:
            raise RegimeError("BOOLEAN_REQUIRED")
        if self.window_sec is not None and (
            type(self.window_sec) is not int or self.window_sec <= 0
        ):
            raise RegimeError("WINDOW_INVALID")
        if self.horizon_sec is not None and (
            type(self.horizon_sec) is not int or self.horizon_sec <= 0
        ):
            raise RegimeError("HORIZON_INVALID")


@dataclass(frozen=True, slots=True)
class RegimeWeightPolicyV1(_NoCopy):
    version: str = DEFAULT_WEIGHT_VERSION
    w_dealer: Decimal = Decimal("0.30")
    w_flow: Decimal = Decimal("0.30")
    w_dp: Decimal = Decimal("0.20")
    w_macro: Decimal = Decimal("0.20")
    k: Decimal = Decimal("3")
    status: Literal["ACTIVE", "PROPOSED"] = "ACTIVE"
    median_window: int = 30
    epsilon: Decimal = Decimal("0.000000001")

    def __post_init__(self) -> None:
        for name in ("w_dealer", "w_flow", "w_dp", "w_macro", "k", "epsilon"):
            object.__setattr__(self, name, canonical_value(getattr(self, name)))
        weights = self.weights
        if not _identifier(self.version) or self.status not in ("ACTIVE", "PROPOSED"):
            raise RegimeError("POLICY_OUT_OF_BOUNDS")
        for weight in weights:
            bounded_decimal(weight)
        bounded_decimal(self.k)
        bounded_decimal(self.epsilon)
        if any(abs(Fraction(weight)) > 2 for weight in weights):
            raise RegimeError("POLICY_OUT_OF_BOUNDS")
        if sum((abs(Fraction(weight)) for weight in weights), Fraction(0)) > 3:
            raise RegimeError("POLICY_OUT_OF_BOUNDS")
        if sum(weight != 0 for weight in weights) < 2:
            raise RegimeError("POLICY_OUT_OF_BOUNDS")
        if self.k != 3 or type(self.median_window) is not int or self.median_window != 30:
            raise RegimeError("POLICY_OUT_OF_BOUNDS")
        if self.epsilon != Decimal("0.000000001"):
            raise RegimeError("POLICY_OUT_OF_BOUNDS")
        if self.status == "ACTIVE" and (
            self.version != DEFAULT_WEIGHT_VERSION
            or weights != (Decimal("0.30"), Decimal("0.30"), Decimal("0.20"), Decimal("0.20"))
            or self.k != 3
            or self.median_window != 30
            or self.epsilon != Decimal("0.000000001")
        ):
            raise RegimeError("POLICY_OUT_OF_BOUNDS")

    @property
    def weights(self) -> tuple[Decimal, Decimal, Decimal, Decimal]:
        return (self.w_dealer, self.w_flow, self.w_dp, self.w_macro)


@dataclass(frozen=True, slots=True)
class RegimeSnapshotV1(_NoCopy):
    clock: RegimeClockV1
    factors: tuple[RegimeFactorV1, ...]
    record_available_ns: int
    signal_status: str = "UNKNOWN"
    truth_status: str = "UNKNOWN"
    flow_source: str | None = None
    flow_quality: str | None = None
    prior_result: RegimeResultV1 | None = None
    weight_version: str = DEFAULT_WEIGHT_VERSION

    def __post_init__(self) -> None:
        if not isinstance(self.clock, RegimeClockV1):
            raise RegimeError("CLOCK_INVALID")
        if not _utc_ns(self.record_available_ns) or self.record_available_ns < self.clock.asof_ns:
            raise RegimeError("RECORD_AVAILABILITY_INVALID")
        if not isinstance(self.factors, tuple) or any(
            not isinstance(factor, RegimeFactorV1) for factor in self.factors
        ):
            raise RegimeError("FACTORS_INVALID")
        if self.signal_status not in ("FINALIZED", "PROVISIONAL", "UNKNOWN"):
            raise RegimeError("SIGNAL_STATUS_INVALID")
        if self.truth_status not in ("PASS", "SOFT_FAIL", "HARD_FAIL", "UNKNOWN"):
            raise RegimeError("TRUTH_STATUS_INVALID")
        if self.flow_source is not None and not _identifier(self.flow_source):
            raise RegimeError("FLOW_SOURCE_INVALID")
        if self.flow_quality is not None and self.flow_quality not in ("GOOD", "BAD", "UNKNOWN"):
            raise RegimeError("FLOW_QUALITY_INVALID")
        if self.prior_result is not None and not isinstance(self.prior_result, RegimeResultV1):
            raise RegimeError("REVISION_INVALID")
        if self.prior_result is not None and (
            self.prior_result.clock.bar_id != self.clock.bar_id
            or self.prior_result.clock.bar_index != self.clock.bar_index
            or self.prior_result.clock.symbol != self.clock.symbol
            or self.prior_result.weight_version != self.weight_version
        ):
            raise RegimeError("REVISION_INVALID")
        if not _identifier(self.weight_version):
            raise RegimeError("WEIGHT_VERSION_INVALID")
        kinds = [factor.kind for factor in self.factors]
        if len(kinds) != len(set(kinds)):
            raise RegimeError("DUPLICATE_FACTOR")


def _result_content(value: object) -> object:
    if isinstance(value, Decimal):
        return canonical_decimal(value)
    if isinstance(value, RegimeResultV1):
        return value.content_digest
    if isinstance(value, (RegimeClockV1, RegimeFactorV1)):
        return {item.name: _result_content(getattr(value, item.name)) for item in fields(value)}
    if isinstance(value, tuple):
        return [_result_content(item) for item in value]
    if value is None or isinstance(value, (str, int, bool)):
        return value
    raise RegimeError("RESULT_INVALID")


@dataclass(frozen=True, slots=True)
class RegimeResultV1(_NoCopy):
    clock: RegimeClockV1
    composite_raw: Decimal | None
    composite_regime: int | None
    confidence: Decimal
    readiness: Readiness
    status: ResultStatus
    missing_factors: tuple[FactorKind, ...]
    reason_codes: tuple[str, ...]
    carried_forward: bool
    revision: int
    inputs_hash: str
    weight_version: str
    publish_current: bool
    previous_revision: int | None = None
    affected_results: tuple[RegimeResultV1, ...] = field(default_factory=tuple)
    factor_provenance: tuple[RegimeFactorV1, ...] = field(default_factory=tuple)
    evaluation_asof_ns: int = 0
    _issuer_token: InitVar[object] = None
    content_digest: str = field(init=False)

    def __post_init__(self, _issuer_token: object) -> None:
        if not isinstance(self.clock, RegimeClockV1):
            raise RegimeError("CLOCK_INVALID")
        if self.composite_raw is not None:
            object.__setattr__(self, "composite_raw", canonical_value(self.composite_raw))
        object.__setattr__(self, "confidence", canonical_value(self.confidence))
        if not isinstance(self.missing_factors, tuple) or not isinstance(self.reason_codes, tuple):
            raise RegimeError("RESULT_INVALID")
        if any(kind not in FACTOR_KINDS for kind in self.missing_factors) or any(
            not isinstance(code, str) for code in self.reason_codes
        ):
            raise RegimeError("RESULT_INVALID")
        if not isinstance(self.affected_results, tuple) or any(
            not isinstance(result, RegimeResultV1) for result in self.affected_results
        ):
            raise RegimeError("RESULT_INVALID")
        if not isinstance(self.factor_provenance, tuple) or any(
            not isinstance(factor, RegimeFactorV1) for factor in self.factor_provenance
        ):
            raise RegimeError("RESULT_INVALID")
        if type(self.carried_forward) is not bool or type(self.publish_current) is not bool:
            raise RegimeError("BOOLEAN_REQUIRED")
        if not _utc_ns(self.revision) or not _utc_ns(self.evaluation_asof_ns):
            raise RegimeError("RESULT_INVALID")
        if self.previous_revision is not None and not _utc_ns(self.previous_revision):
            raise RegimeError("RESULT_INVALID")
        if self.composite_regime is not None and (
            type(self.composite_regime) is not int or self.composite_regime not in (-2, -1, 0, 1, 2)
        ):
            raise RegimeError("RESULT_INVALID")
        if self.confidence < 0 or self.confidence > 1:
            raise RegimeError("RESULT_INVALID")
        if self.readiness not in ("READY", "DEGRADED", "HOLD") or self.status not in (
            "SCORED", "PARTIAL", "INSUFFICIENT_DATA", "HISTORY_ONLY",
        ):
            raise RegimeError("RESULT_INVALID")
        if (not self.clock.finalized or self.status == "HISTORY_ONLY") and self.publish_current:
            raise RegimeError("RESULT_INVALID")
        if not _identifier(self.weight_version) or not _identifier(self.inputs_hash):
            raise RegimeError("RESULT_INVALID")
        if self.composite_raw is None:
            if (self.status not in ("INSUFFICIENT_DATA", "HISTORY_ONLY")
                or self.confidence != 0 or self.readiness != "HOLD"
                or self.carried_forward != (self.composite_regime is not None)):
                raise RegimeError("RESULT_INVALID")
        elif (
            self.composite_regime is None or self.carried_forward
            or self.status == "INSUFFICIENT_DATA"
        ):
            raise RegimeError("RESULT_INVALID")
        if self.status == "SCORED" and self.missing_factors:
            raise RegimeError("RESULT_INVALID")
        if self.status == "PARTIAL" and (
            not self.missing_factors or "PARTIAL" not in self.reason_codes
        ):
            raise RegimeError("RESULT_INVALID")
        if self.status == "HISTORY_ONLY" and (
            self.readiness != "HOLD" or "HISTORY_ONLY" not in self.reason_codes
        ):
            raise RegimeError("RESULT_INVALID")
        if self.readiness == "READY" and (
            self.confidence < Decimal("0.7") or self.status != "SCORED"
            or self.missing_factors or any(
                code.startswith(("WARMUP", "TRUTH_", "SIGNAL_")) for code in self.reason_codes
            )
        ):
            raise RegimeError("RESULT_INVALID")
        if self.readiness == "DEGRADED" and (
            self.confidence < Decimal("0.4")
            or self.status in ("INSUFFICIENT_DATA", "HISTORY_ONLY")
        ):
            raise RegimeError("RESULT_INVALID")
        if self.confidence == 0 and self.readiness != "HOLD":
            raise RegimeError("RESULT_INVALID")
        if _issuer_token is not _RESULT_ISSUER:
            raise RegimeError("RESULT_SEALED")
        payload = {
            item.name: _result_content(getattr(self, item.name))
            for item in fields(self) if item.name != "content_digest"
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        object.__setattr__(self, "content_digest", hashlib.sha256(
            canonical.encode("utf-8"),
        ).hexdigest())

    @property
    def score(self) -> Decimal | None:
        return self.composite_raw

    @property
    def regime(self) -> int | None:
        return self.composite_regime
