"""Pure, point-in-time portfolio overlap and risk-rail checks.

Exposure components are signed fractions of NAV for a fully weighted strategy.
Gamma and heat are account-currency amounts for a fully weighted strategy.
The result is advisory and never authorizes activation or routing.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, fields, is_dataclass
from decimal import (
    ROUND_DOWN,
    ROUND_UP,
    Decimal,
    DivisionByZero,
    InvalidOperation,
    Overflow,
    localcontext,
)
from enum import StrEnum
from fractions import Fraction
from math import isqrt
from typing import Any, SupportsIndex

from leviathan_core.numeric import NumericError, canonical_json, parse_decimal, parse_int
from leviathan_core.numeric._context import numeric_context
from leviathan_core.portfolio.models import (
    HardCapsV1,
    SizingPolicyV1,
    SizingRequestV1,
)
from leviathan_core.portfolio.models import (
    canonical_hash as port001_canonical_hash,
)

_ID = re.compile(r"[A-Za-z0-9._:-]{1,64}\Z", re.ASCII)
_MAX_NS = 2**63 - 1
_ONE = Decimal(1)
_ZERO = Decimal(0)
_DAY_NS = 86_400_000_000_000
_WEIGHT_TOLERANCE = Fraction(1, 1_000_000)


class PortfolioInputError(ValueError):
    """Typed, content-free public error."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise PortfolioInputError(code)


def _id(value: object) -> str:
    _require(type(value) is str and _ID.fullmatch(value) is not None, "INVALID_ID")
    assert isinstance(value, str)
    return value


def _time(value: object) -> int:
    try:
        return parse_int(value, field="time", min_value=0, max_value=_MAX_NS)
    except NumericError:
        raise PortfolioInputError("INVALID_TIME") from None


def _decimal(
    value: object, *, min_value: Decimal | None = None, max_value: Decimal | None = None
) -> Decimal:
    _require(type(value) is Decimal, "INVALID_DECIMAL")
    try:
        result = parse_decimal(value, field="value")
    except NumericError as exc:
        code = "PRECISION_EXCEEDED" if exc.code == "MAGNITUDE_OUT_OF_BOUNDS" else exc.code
        raise PortfolioInputError(code) from None
    if min_value is not None:
        _require(result >= min_value, "OUT_OF_RANGE")
    if max_value is not None:
        _require(result <= max_value, "OUT_OF_RANGE")
    return result


def _derived_decimal(value: object) -> Decimal:
    """Validate a computed display value without applying input magnitude bounds."""
    _require(type(value) is Decimal and value.is_finite(), "INVALID_DERIVED_DECIMAL")
    assert isinstance(value, Decimal)
    if value.is_zero():
        return _ZERO
    decimal_tuple = value.as_tuple()
    coefficient = list(decimal_tuple.digits)
    exponent = decimal_tuple.exponent
    assert isinstance(exponent, int)
    while coefficient[-1] == 0:
        coefficient.pop()
        exponent += 1
    canonical = Decimal((decimal_tuple.sign, tuple(coefficient), exponent))
    _require(len(coefficient) <= 34 and abs(canonical.adjusted()) <= 500, "PRECISION_EXCEEDED")
    return canonical


def _decimal_text(value: Decimal) -> str:
    value = _derived_decimal(value)
    if value.is_zero():
        return "0"
    decimal_tuple = value.as_tuple()
    digits = "".join(str(digit) for digit in decimal_tuple.digits)
    exponent = decimal_tuple.exponent
    assert isinstance(exponent, int)
    while digits.endswith("0"):
        digits = digits[:-1]
        exponent += 1
    if exponent >= 0:
        result = digits + "0" * exponent
    elif len(digits) + exponent > 0:
        split = len(digits) + exponent
        result = digits[:split] + "." + digits[split:]
    else:
        result = "0." + "0" * -(len(digits) + exponent) + digits
    return ("-" if decimal_tuple.sign else "") + result


def _records(value: object, record_type: type[Any]) -> tuple[Any, ...]:
    _require(
        type(value) is tuple and all(type(item) is record_type for item in value), "INVALID_RECORDS"
    )
    assert isinstance(value, tuple)
    return value


def _display(value: Fraction) -> Decimal:
    """One final quotient rounded toward zero; cap decisions use the Fraction."""
    try:
        context = numeric_context(final_quotient=True)
        context.rounding = ROUND_DOWN
        context.Emin = -999999
        context.Emax = 999999
        with localcontext(context):
            result = Decimal(value.numerator) / Decimal(value.denominator)
        return _derived_decimal(result)
    except (NumericError, Overflow, DivisionByZero, InvalidOperation):
        raise PortfolioInputError("PRECISION_EXCEEDED") from None


def _breach_display(value: Fraction) -> Decimal:
    """Outward display keeps a positive exact breach visibly above its cap."""
    try:
        context = numeric_context(final_quotient=True)
        context.rounding = ROUND_UP
        context.Emin = -999999
        context.Emax = 999999
        with localcontext(context):
            result = Decimal(value.numerator) / Decimal(value.denominator)
        return _derived_decimal(result)
    except (NumericError, Overflow, DivisionByZero, InvalidOperation):
        raise PortfolioInputError("PRECISION_EXCEEDED") from None


def _hash(value: object) -> str:
    try:
        return hashlib.sha256(canonical_json(_plain(value))).hexdigest()
    except NumericError as exc:
        raise PortfolioInputError(exc.code) from None


def _plain(value: object) -> object:
    if isinstance(value, StrEnum):
        return value.value
    if type(value) is Decimal:
        return {"__decimal__": _decimal_text(value)}
    if type(value) is SizingRequestV1 or type(value) is SizingPolicyV1:
        return {"port001_canonical_hash": port001_canonical_hash(value)}
    if is_dataclass(value) and not isinstance(value, type):
        return {field.name: _plain(getattr(value, field.name)) for field in fields(value)}
    if type(value) is tuple:
        return [_plain(item) for item in value]
    return value


class _FrozenRecord:
    def __copy__(self) -> None:
        raise PortfolioInputError("FROZEN_RECORD")

    def __deepcopy__(self, memo: dict[int, object]) -> None:
        raise PortfolioInputError("FROZEN_RECORD")

    def __reduce_ex__(self, protocol: SupportsIndex) -> Any:
        raise PortfolioInputError("FROZEN_RECORD")


def _reject_assignment(self: object, name: str, value: object) -> None:
    raise PortfolioInputError("FROZEN_RECORD")


def _reject_deletion(self: object, name: str) -> None:
    raise PortfolioInputError("FROZEN_RECORD")


def _guard_assignment(*record_types: type[object]) -> None:
    # dataclass(frozen=True) generates its own setters. Replace those after
    # decoration so attempted assignment/deletion has one content-free type.
    for record_type in record_types:
        type.__setattr__(record_type, "__setattr__", _reject_assignment)
        type.__setattr__(record_type, "__delattr__", _reject_deletion)


class MissingDataPolicy(StrEnum):
    BLOCK = "block"
    CONSERVATIVE = "conservative"


class PortfolioStatus(StrEnum):
    PASS = "PASS"
    BLOCKED = "BLOCKED"
    QUARANTINE = "QUARANTINE"


@dataclass(frozen=True, slots=True)
class ExposureComponentV1(_FrozenRecord):
    key: str
    value: Decimal

    def __post_init__(self) -> None:
        _id(self.key)
        object.__setattr__(self, "value", _decimal(self.value))


@dataclass(frozen=True, slots=True)
class DerivedExposureV1(_FrozenRecord):
    key: str
    value: Decimal

    def __post_init__(self) -> None:
        _id(self.key)
        object.__setattr__(self, "value", _derived_decimal(self.value))


@dataclass(frozen=True, slots=True)
class PortfolioAllocationV1(_FrozenRecord):
    strategy_revision_hash: str
    weight: Decimal

    def __post_init__(self) -> None:
        _id(self.strategy_revision_hash)
        object.__setattr__(self, "weight", _decimal(self.weight, min_value=_ZERO, max_value=_ONE))
        _require(self.weight > 0, "INVALID_WEIGHT")


@dataclass(frozen=True, slots=True)
class PortfolioSpecV1(_FrozenRecord):
    portfolio_revision_hash: str
    nav: Decimal
    evaluation_ns: int
    allocations: tuple[PortfolioAllocationV1, ...]

    def __post_init__(self) -> None:
        _id(self.portfolio_revision_hash)
        object.__setattr__(self, "nav", _decimal(self.nav))
        _require(self.nav > 0, "INVALID_NAV")
        _time(self.evaluation_ns)
        allocations = _records(self.allocations, PortfolioAllocationV1)
        _require(0 < len(allocations) <= 500, "INVALID_ALLOCATIONS")
        ordered = tuple(sorted(allocations, key=lambda item: item.strategy_revision_hash))
        _require(
            len({item.strategy_revision_hash for item in ordered}) == len(ordered),
            "DUPLICATE_STRATEGY_REVISION",
        )
        total = sum((Fraction(item.weight) for item in ordered), Fraction())
        _require(abs(total - 1) <= _WEIGHT_TOLERANCE, "WEIGHTS_NOT_NORMALIZED")
        object.__setattr__(self, "allocations", ordered)


@dataclass(frozen=True, slots=True)
class SectorMappingV1(_FrozenRecord):
    symbol: str
    sector: str
    event_ns: int
    available_ns: int
    source_version: str
    remapped_from: str | None = None

    def __post_init__(self) -> None:
        _id(self.symbol)
        _id(self.sector)
        _id(self.source_version)
        if self.remapped_from is not None:
            _id(self.remapped_from)
            _require(self.remapped_from != self.sector, "INVALID_REMAP")
        _require(_time(self.event_ns) <= _time(self.available_ns), "INVALID_TIME")


@dataclass(frozen=True, slots=True)
class StrategyExposureV1(_FrozenRecord):
    strategy_revision_hash: str
    symbol_exposures: tuple[ExposureComponentV1, ...]
    factor_exposures: tuple[ExposureComponentV1, ...] | None
    beta: Decimal | None
    gamma: Decimal | None
    heat: Decimal
    event_ns: int
    available_ns: int
    source_version: str

    def __post_init__(self) -> None:
        _id(self.strategy_revision_hash)
        _id(self.source_version)
        symbols = _records(self.symbol_exposures, ExposureComponentV1)
        _require(bool(symbols), "MISSING_SYMBOL_EXPOSURE")
        _require(len({item.key for item in symbols}) == len(symbols), "DUPLICATE_SYMBOL")
        object.__setattr__(
            self, "symbol_exposures", tuple(sorted(symbols, key=lambda item: item.key))
        )
        if self.factor_exposures is not None:
            factors = _records(self.factor_exposures, ExposureComponentV1)
            _require(len({item.key for item in factors}) == len(factors), "DUPLICATE_FACTOR")
            object.__setattr__(
                self, "factor_exposures", tuple(sorted(factors, key=lambda item: item.key))
            )
        if self.beta is not None:
            object.__setattr__(self, "beta", _decimal(self.beta))
        if self.gamma is not None:
            object.__setattr__(self, "gamma", _decimal(self.gamma))
        object.__setattr__(self, "heat", _decimal(self.heat, min_value=_ZERO))
        _require(_time(self.event_ns) <= _time(self.available_ns), "INVALID_TIME")


@dataclass(frozen=True, slots=True)
class CorrelationSnapshotV1(_FrozenRecord):
    left_revision_hash: str
    right_revision_hash: str
    correlation: Decimal | None
    window_start_ns: int
    window_end_ns: int
    event_ns: int
    available_ns: int
    source_version: str

    def __post_init__(self) -> None:
        left, right = _id(self.left_revision_hash), _id(self.right_revision_hash)
        _require(left != right, "INVALID_CORRELATION_PAIR")
        object.__setattr__(self, "left_revision_hash", min(left, right))
        object.__setattr__(self, "right_revision_hash", max(left, right))
        if self.correlation is not None:
            object.__setattr__(
                self, "correlation", _decimal(self.correlation, min_value=-_ONE, max_value=_ONE)
            )
        start, end, event, available = (
            _time(self.window_start_ns),
            _time(self.window_end_ns),
            _time(self.event_ns),
            _time(self.available_ns),
        )
        _require(start < end <= event <= available, "INVALID_TIME")
        _id(self.source_version)


@dataclass(frozen=True, slots=True)
class ExposureSnapshotV1(_FrozenRecord):
    window_start_ns: int
    window_end_ns: int
    strategies: tuple[StrategyExposureV1, ...]
    correlations: tuple[CorrelationSnapshotV1, ...]
    sector_map: tuple[SectorMappingV1, ...]

    def __post_init__(self) -> None:
        _require(_time(self.window_start_ns) < _time(self.window_end_ns), "INVALID_WINDOW")
        object.__setattr__(
            self,
            "strategies",
            tuple(
                sorted(
                    _records(self.strategies, StrategyExposureV1),
                    key=lambda item: (
                        item.strategy_revision_hash,
                        item.available_ns,
                        item.event_ns,
                        item.source_version,
                    ),
                )
            ),
        )
        object.__setattr__(
            self,
            "correlations",
            tuple(
                sorted(
                    _records(self.correlations, CorrelationSnapshotV1),
                    key=lambda item: (
                        item.left_revision_hash,
                        item.right_revision_hash,
                        item.available_ns,
                        item.event_ns,
                        item.source_version,
                    ),
                )
            ),
        )
        object.__setattr__(
            self,
            "sector_map",
            tuple(
                sorted(
                    _records(self.sector_map, SectorMappingV1),
                    key=lambda item: (
                        item.symbol,
                        item.available_ns,
                        item.event_ns,
                        item.source_version,
                    ),
                )
            ),
        )


@dataclass(frozen=True, slots=True)
class OverlapPolicyV1(_FrozenRecord):
    policy_version: str
    overlap_threshold: Decimal
    correlation_limit: Decimal
    window_ns: int
    max_age_ns: int
    missing_data: MissingDataPolicy
    assumed_beta: Decimal
    assumed_correlation: Decimal
    assumed_gamma: Decimal
    caps: HardCapsV1
    net_gamma_cap: Decimal

    def __post_init__(self) -> None:
        _id(self.policy_version)
        for name in ("overlap_threshold", "correlation_limit"):
            object.__setattr__(
                self, name, _decimal(getattr(self, name), min_value=_ZERO, max_value=_ONE)
            )
        _require(0 < _time(self.window_ns) <= _DAY_NS * 365, "POLICY_OUT_OF_BOUNDS")
        _require(_time(self.max_age_ns) <= _DAY_NS, "POLICY_OUT_OF_BOUNDS")
        _require(type(self.missing_data) is MissingDataPolicy, "INVALID_POLICY")
        object.__setattr__(self, "assumed_beta", _decimal(self.assumed_beta))
        object.__setattr__(self, "assumed_correlation", _decimal(self.assumed_correlation))
        object.__setattr__(self, "assumed_gamma", _decimal(self.assumed_gamma, min_value=_ZERO))
        object.__setattr__(self, "net_gamma_cap", _decimal(self.net_gamma_cap, min_value=_ZERO))
        _require(
            self.assumed_beta == 1 and self.assumed_correlation == Decimal("0.8"),
            "POLICY_OUT_OF_BOUNDS",
        )
        _require(
            self.assumed_gamma > 0 and self.assumed_gamma >= self.net_gamma_cap,
            "POLICY_OUT_OF_BOUNDS",
        )
        _require(type(self.caps) is HardCapsV1, "INVALID_POLICY")
        caps = self.caps
        _require(
            caps.per_symbol_notional <= caps.per_sector_notional <= caps.gross_notional
            and caps.net_notional <= caps.gross_notional,
            "INVALID_CAP_HIERARCHY",
        )


@dataclass(frozen=True, slots=True)
class OverlapDriverV1(_FrozenRecord):
    kind: str
    key: str
    contribution: Decimal

    def __post_init__(self) -> None:
        _require(self.kind in ("symbol", "sector", "factor", "beta"), "INVALID_DRIVER")
        _id(self.key)
        object.__setattr__(self, "contribution", _derived_decimal(self.contribution))


@dataclass(frozen=True, slots=True)
class OverlapPairV1(_FrozenRecord):
    left_revision_hash: str
    right_revision_hash: str
    score: Decimal
    blocked: bool
    drivers: tuple[OverlapDriverV1, ...]

    def __post_init__(self) -> None:
        _require(_id(self.left_revision_hash) < _id(self.right_revision_hash), "INVALID_PAIR")
        object.__setattr__(self, "score", _derived_decimal(self.score))
        _require(-_ONE <= self.score <= _ONE, "INVALID_PAIR")
        _require(type(self.blocked) is bool, "INVALID_BOOLEAN")
        _records(self.drivers, OverlapDriverV1)


@dataclass(frozen=True, slots=True)
class CorrelationPairV1(_FrozenRecord):
    left_revision_hash: str
    right_revision_hash: str
    correlation: Decimal
    violated: bool
    assumed: bool

    def __post_init__(self) -> None:
        _require(_id(self.left_revision_hash) < _id(self.right_revision_hash), "INVALID_PAIR")
        object.__setattr__(self, "correlation", _derived_decimal(self.correlation))
        _require(-_ONE <= self.correlation <= _ONE, "INVALID_PAIR")
        _require(type(self.violated) is bool and type(self.assumed) is bool, "INVALID_BOOLEAN")


@dataclass(frozen=True, slots=True)
class BreachV1(_FrozenRecord):
    code: str
    subject: str
    observed: Decimal | None
    limit: Decimal | None

    def __post_init__(self) -> None:
        _id(self.code)
        _require(
            type(self.subject) is str
            and 1 <= len(self.subject) <= 192
            and all(32 <= ord(character) < 127 for character in self.subject),
            "INVALID_BREACH",
        )
        if self.observed is not None:
            object.__setattr__(self, "observed", _derived_decimal(self.observed))
        if self.limit is not None:
            object.__setattr__(self, "limit", _decimal(self.limit))


@dataclass(frozen=True, slots=True)
class PortfolioCheckV1(_FrozenRecord):
    status: PortfolioStatus
    overlap_pairs: tuple[OverlapPairV1, ...]
    correlation_pairs: tuple[CorrelationPairV1, ...]
    breaches: tuple[BreachV1, ...]
    assumptions: tuple[str, ...]
    symbol_exposures: tuple[DerivedExposureV1, ...]
    sector_exposures: tuple[DerivedExposureV1, ...]
    gross_notional: Decimal
    net_notional: Decimal
    net_gamma: Decimal
    heat: Decimal
    max_offdiag: Decimal | None
    input_hash: str
    policy_hash: str
    trace: tuple[str, ...]

    def __post_init__(self) -> None:
        _require(type(self.status) is PortfolioStatus, "INVALID_CHECK")
        for name, record_type in (
            ("overlap_pairs", OverlapPairV1),
            ("correlation_pairs", CorrelationPairV1),
            ("breaches", BreachV1),
            ("symbol_exposures", DerivedExposureV1),
            ("sector_exposures", DerivedExposureV1),
        ):
            _records(getattr(self, name), record_type)
        for name in ("gross_notional", "net_notional", "net_gamma", "heat"):
            object.__setattr__(self, name, _derived_decimal(getattr(self, name)))
        if self.max_offdiag is not None:
            object.__setattr__(self, "max_offdiag", _derived_decimal(self.max_offdiag))
            _require(-_ONE <= self.max_offdiag <= _ONE, "INVALID_CHECK")
        for name in ("assumptions", "trace"):
            value = getattr(self, name)
            _require(
                type(value) is tuple
                and all(type(item) is str and len(item) <= 256 for item in value),
                "INVALID_CHECK",
            )
        for value in (self.input_hash, self.policy_hash):
            _require(
                type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None,
                "INVALID_CHECK",
            )

    @property
    def blocked(self) -> bool:
        return self.status is not PortfolioStatus.PASS

    def canonical_bytes(self) -> bytes:
        return canonical_json(_plain(self))


def _visible_latest(records: tuple[Any, ...], evaluation_ns: int, key_name: str) -> dict[Any, Any]:
    """Filter availability first, then reconcile visible revisions."""
    chosen: dict[Any, Any] = {}
    for record in records:
        if record.available_ns > evaluation_ns or record.event_ns > evaluation_ns:
            continue
        if key_name == "strategy":
            key: Any = record.strategy_revision_hash
        elif key_name == "sector":
            key = record.symbol
        else:
            key = (record.left_revision_hash, record.right_revision_hash)
        previous = chosen.get(key)
        if previous is None:
            chosen[key] = record
            continue
        current_order = (record.available_ns, record.event_ns, record.source_version)
        previous_order = (previous.available_ns, previous.event_ns, previous.source_version)
        if current_order == previous_order and record != previous:
            raise PortfolioInputError("SNAPSHOT_CONFLICT")
        if current_order > previous_order:
            chosen[key] = record
    return chosen


def _score_and_drivers(
    left: dict[str, Fraction], right: dict[str, Fraction], threshold: Fraction
) -> tuple[Decimal, bool, tuple[OverlapDriverV1, ...]]:
    keys = sorted(set(left) | set(right))
    dot = sum((left.get(key, Fraction()) * right.get(key, Fraction()) for key in keys), Fraction())
    left_norm = sum((value * value for value in left.values()), Fraction())
    right_norm = sum((value * value for value in right.values()), Fraction())
    _require(left_norm > 0 and right_norm > 0, "MISSING_OVERLAP_VECTOR")
    blocked = dot >= 0 and dot * dot >= threshold * threshold * left_norm * right_norm
    radicand = dot * dot / (left_norm * right_norm)
    scale = 10**40
    display_root = isqrt(radicand.numerator * scale * scale // radicand.denominator)
    score = _display(Fraction(display_root if dot >= 0 else -display_root, scale))
    products = [
        (key, left.get(key, Fraction()) * right.get(key, Fraction()))
        for key in keys
        if left.get(key, Fraction()) * right.get(key, Fraction()) != 0
    ]
    products.sort(key=lambda item: (-abs(item[1]), item[0]))
    drivers = tuple(
        OverlapDriverV1(key.split(":", 1)[0], key.split(":", 1)[1], _display(value))
        for key, value in products
    )
    return score, blocked, drivers


def _breach(
    code: str, subject: str, observed: Fraction | None = None, limit: Decimal | None = None
) -> BreachV1:
    return BreachV1(
        code,
        subject,
        _breach_display(observed) if observed is not None else None,
        limit,
    )


def _evaluate_portfolio_with_eligible(
    spec: PortfolioSpecV1, snapshot: ExposureSnapshotV1, policy: OverlapPolicyV1
) -> tuple[PortfolioCheckV1, tuple[StrategyExposureV1, ...], Fraction]:
    """Compute the check and its one shared eligible exposure set."""
    _require(
        type(spec) is PortfolioSpecV1
        and type(snapshot) is ExposureSnapshotV1
        and type(policy) is OverlapPolicyV1,
        "INVALID_INPUT",
    )
    _require(
        snapshot.window_end_ns <= spec.evaluation_ns
        and snapshot.window_end_ns - snapshot.window_start_ns == policy.window_ns,
        "INVALID_WINDOW",
    )
    strategy_records = _visible_latest(snapshot.strategies, spec.evaluation_ns, "strategy")
    correlation_records = _visible_latest(snapshot.correlations, spec.evaluation_ns, "correlation")
    sector_records = _visible_latest(snapshot.sector_map, spec.evaluation_ns, "sector")
    selected_strategies: list[StrategyExposureV1] = []
    breaches: list[BreachV1] = []
    assumptions: list[str] = []
    trace: list[str] = ["PORT-002:overlap-v1", "availability_filter_before_reconciliation"]
    weights_total = sum((Fraction(item.weight) for item in spec.allocations), Fraction())
    weight_by_revision = {
        item.strategy_revision_hash: Fraction(item.weight) / weights_total
        for item in spec.allocations
    }
    for allocation in spec.allocations:
        record = strategy_records.get(allocation.strategy_revision_hash)
        if record is None:
            breaches.append(_breach("MISSING_EXPOSURE", allocation.strategy_revision_hash))
            continue
        if spec.evaluation_ns - record.event_ns > policy.max_age_ns:
            breaches.append(_breach("STALE_EXPOSURE", allocation.strategy_revision_hash))
            continue
        if record.event_ns < snapshot.window_start_ns:
            breaches.append(_breach("OUT_OF_WINDOW_EXPOSURE", allocation.strategy_revision_hash))
            continue
        selected_strategies.append(record)
    if spec.evaluation_ns - snapshot.window_end_ns > policy.max_age_ns:
        breaches.append(_breach("STALE_WINDOW", "portfolio"))

    symbol_fractions: dict[str, Fraction] = {}
    symbol_gross_fractions: dict[str, Fraction] = {}
    sector_gross_fractions: dict[str, Fraction] = {}
    vectors: dict[str, dict[str, Fraction]] = {}
    known_gamma_total = Fraction()
    missing_gamma_bound = Fraction()
    heat_total = Fraction()
    used_sectors: dict[str, SectorMappingV1] = {}
    for record in selected_strategies:
        weight = weight_by_revision[record.strategy_revision_hash]
        symbols = {item.key: Fraction(item.value) for item in record.symbol_exposures}
        vector = {"symbol:" + key: value for key, value in symbols.items()}
        sector_by_strategy: dict[str, Fraction] = {}
        for symbol, value in sorted(symbols.items()):
            sector_record = sector_records.get(symbol)
            if sector_record is None:
                breaches.append(_breach("UNKNOWN_SYMBOL", symbol))
                continue
            if spec.evaluation_ns - sector_record.event_ns > policy.max_age_ns:
                breaches.append(_breach("STALE_SECTOR", symbol))
                continue
            used_sectors[symbol] = sector_record
            sector_by_strategy[sector_record.sector] = (
                sector_by_strategy.get(sector_record.sector, Fraction()) + value
            )
            symbol_fractions[symbol] = symbol_fractions.get(symbol, Fraction()) + weight * value
            symbol_gross_fractions[symbol] = symbol_gross_fractions.get(symbol, Fraction()) + abs(
                weight * value
            )
            sector_gross_fractions[sector_record.sector] = sector_gross_fractions.get(
                sector_record.sector, Fraction()
            ) + abs(weight * value)
        for sector, value in sector_by_strategy.items():
            vector["sector:" + sector] = value
        if record.factor_exposures is None:
            if policy.missing_data is MissingDataPolicy.BLOCK:
                breaches.append(_breach("MISSING_FACTOR", record.strategy_revision_hash))
            else:
                assumptions.append("FACTOR_BETA_1:" + record.strategy_revision_hash)
                vector["factor:beta"] = Fraction(policy.assumed_beta)
        else:
            vector.update(
                {"factor:" + item.key: Fraction(item.value) for item in record.factor_exposures}
            )
        if record.beta is None:
            if policy.missing_data is MissingDataPolicy.BLOCK:
                breaches.append(_breach("MISSING_BETA", record.strategy_revision_hash))
            else:
                assumptions.append("BETA_1:" + record.strategy_revision_hash)
                vector["beta:market"] = Fraction(policy.assumed_beta)
        else:
            vector["beta:market"] = Fraction(record.beta)
        if record.gamma is None:
            if policy.missing_data is MissingDataPolicy.BLOCK:
                breaches.append(_breach("MISSING_GAMMA", record.strategy_revision_hash))
            else:
                assumptions.append("GAMMA_POLICY:" + record.strategy_revision_hash)
                missing_gamma_bound += weight * Fraction(policy.assumed_gamma)
        else:
            known_gamma_total += weight * Fraction(record.gamma)
        heat_total += weight * Fraction(record.heat)
        vectors[record.strategy_revision_hash] = vector

    symbols_notional = {
        symbol: Fraction(spec.nav) * value for symbol, value in symbol_fractions.items()
    }
    # Gross caps retain per-strategy absolute contributions. Opposite strategy
    # exposures on the same symbol do not silently erase risk.
    symbol_gross = {
        symbol: Fraction(spec.nav) * value for symbol, value in symbol_gross_fractions.items()
    }
    sector_gross = {
        sector: Fraction(spec.nav) * value for sector, value in sector_gross_fractions.items()
    }
    gross = sum(symbol_gross.values(), Fraction())
    net = abs(sum(symbols_notional.values(), Fraction()))
    caps = policy.caps
    for symbol, value in sorted(symbol_gross.items()):
        if value > Fraction(caps.per_symbol_notional):
            breaches.append(_breach("SYMBOL_CAP", symbol, value, caps.per_symbol_notional))
    for sector, value in sorted(sector_gross.items()):
        if value > Fraction(caps.per_sector_notional):
            breaches.append(_breach("SECTOR_CAP", sector, value, caps.per_sector_notional))
    if gross > Fraction(caps.gross_notional):
        breaches.append(_breach("GROSS_CAP", "portfolio", gross, caps.gross_notional))
    if net > Fraction(caps.net_notional):
        breaches.append(_breach("NET_CAP", "portfolio", net, caps.net_notional))
    if gross > Fraction(spec.nav) * Fraction(caps.max_leverage):
        breaches.append(
            _breach("LEVERAGE_CAP", "portfolio", gross / Fraction(spec.nav), caps.max_leverage)
        )
    worst_gamma = abs(known_gamma_total) + missing_gamma_bound
    if worst_gamma > Fraction(policy.net_gamma_cap):
        breaches.append(_breach("GAMMA_CAP", "portfolio", worst_gamma, policy.net_gamma_cap))
    gamma_display = -worst_gamma if known_gamma_total < 0 else worst_gamma
    if heat_total > Fraction(caps.portfolio_heat):
        breaches.append(_breach("HEAT_CAP", "portfolio", heat_total, caps.portfolio_heat))

    overlap_pairs: list[OverlapPairV1] = []
    correlation_pairs: list[CorrelationPairV1] = []
    selected_correlations: list[CorrelationSnapshotV1] = []
    revisions = tuple(item.strategy_revision_hash for item in spec.allocations)
    max_offdiag: Fraction | None = None
    for index, left in enumerate(revisions):
        for right in revisions[index + 1 :]:
            if left in vectors and right in vectors:
                try:
                    score, blocked, drivers = _score_and_drivers(
                        vectors[left], vectors[right], Fraction(policy.overlap_threshold)
                    )
                except PortfolioInputError as exc:
                    if exc.code != "MISSING_OVERLAP_VECTOR":
                        raise
                    overlap_pairs.append(OverlapPairV1(left, right, _ZERO, True, ()))
                    breaches.append(_breach("UNDEFINED_OVERLAP", left + ":" + right))
                else:
                    overlap_pairs.append(OverlapPairV1(left, right, score, blocked, drivers))
                    if blocked:
                        breaches.append(
                            _breach(
                                "OVERLAP_THRESHOLD",
                                left + ":" + right,
                                limit=policy.overlap_threshold,
                            )
                        )
            record = correlation_records.get((left, right))
            assumed = False
            if (
                record is None
                or record.correlation is None
                or record.window_start_ns != snapshot.window_start_ns
                or record.window_end_ns != snapshot.window_end_ns
                or spec.evaluation_ns - record.event_ns > policy.max_age_ns
            ):
                if policy.missing_data is MissingDataPolicy.BLOCK:
                    breaches.append(_breach("MISSING_OR_STALE_CORRELATION", left + ":" + right))
                    continue
                correlation = Fraction(policy.assumed_correlation)
                assumptions.append("CORRELATION_0.8:" + left + ":" + right)
                assumed = True
            else:
                correlation = Fraction(record.correlation)
                selected_correlations.append(record)
            max_offdiag = correlation if max_offdiag is None else max(max_offdiag, correlation)
            violated = correlation > Fraction(policy.correlation_limit)
            correlation_pairs.append(
                CorrelationPairV1(left, right, _display(correlation), violated, assumed)
            )
            if violated:
                breaches.append(
                    _breach(
                        "CORRELATION_LIMIT",
                        left + ":" + right,
                        correlation,
                        policy.correlation_limit,
                    )
                )

    ordered_breaches = tuple(sorted(breaches, key=lambda item: (item.code, item.subject)))
    remapped = any(item.remapped_from is not None for item in used_sectors.values())
    status = (
        PortfolioStatus.QUARANTINE
        if ordered_breaches and remapped
        else PortfolioStatus.BLOCKED
        if ordered_breaches
        else PortfolioStatus.PASS
    )
    input_hash = _hash(
        (
            spec,
            snapshot.window_start_ns,
            snapshot.window_end_ns,
            tuple(sorted(selected_strategies, key=lambda item: item.strategy_revision_hash)),
            tuple(
                sorted(
                    selected_correlations,
                    key=lambda item: (item.left_revision_hash, item.right_revision_hash),
                )
            ),
            tuple(sorted(used_sectors.values(), key=lambda item: item.symbol)),
        )
    )
    trace.extend(
        (
            "weights_normalized_exactly",
            "cosine_threshold_compared_exactly",
            "caps_compared_exactly",
            "status:" + status.value,
        )
    )
    check = PortfolioCheckV1(
        status=status,
        overlap_pairs=tuple(overlap_pairs),
        correlation_pairs=tuple(correlation_pairs),
        breaches=ordered_breaches,
        assumptions=tuple(sorted(assumptions)),
        symbol_exposures=tuple(
            DerivedExposureV1(symbol, _display(value))
            for symbol, value in sorted(symbols_notional.items())
        ),
        sector_exposures=tuple(
            DerivedExposureV1(sector, _display(value))
            for sector, value in sorted(sector_gross.items())
        ),
        gross_notional=_display(gross),
        net_notional=_display(net),
        net_gamma=_display(gamma_display),
        heat=_display(heat_total),
        max_offdiag=_display(max_offdiag) if max_offdiag is not None else None,
        input_hash=input_hash,
        policy_hash=_hash(policy),
        trace=tuple(trace),
    )
    return check, tuple(selected_strategies), worst_gamma


def evaluate_portfolio(
    spec: PortfolioSpecV1, snapshot: ExposureSnapshotV1, policy: OverlapPolicyV1
) -> PortfolioCheckV1:
    """Evaluate a pinned portfolio without mutating revisions or publishing intents."""
    check, _, _ = _evaluate_portfolio_with_eligible(spec, snapshot, policy)
    return check


_guard_assignment(
    ExposureComponentV1,
    DerivedExposureV1,
    PortfolioAllocationV1,
    PortfolioSpecV1,
    SectorMappingV1,
    StrategyExposureV1,
    CorrelationSnapshotV1,
    ExposureSnapshotV1,
    OverlapPolicyV1,
    OverlapDriverV1,
    OverlapPairV1,
    CorrelationPairV1,
    BreachV1,
    PortfolioCheckV1,
)
