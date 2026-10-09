"""Advisory, capped rebalance proposals; never an order or route permit."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from enum import StrEnum
from fractions import Fraction
from typing import Any, SupportsIndex

from leviathan_core.numeric import NumericError, exact_mul
from leviathan_core.portfolio.models import (
    HardCapsV1,
    ObservationV1,
    PositionV1,
    SectorEntryV1,
    SizingPolicyV1,
    SizingRequestV1,
    SizingStatus,
)
from leviathan_core.portfolio.overlap import (
    ExposureSnapshotV1,
    OverlapPolicyV1,
    PortfolioCheckV1,
    PortfolioInputError,
    PortfolioSpecV1,
    PortfolioStatus,
    StrategyExposureV1,
    _decimal,
    _derived_decimal,
    _display,
    _evaluate_portfolio_with_eligible,
    _guard_assignment,
    _hash,
    _id,
    _records,
    _require,
    _time,
    _visible_latest,
)
from leviathan_core.portfolio.sizing import size

_ZERO = Decimal(0)
_ONE = Decimal(1)


class RebalanceStatus(StrEnum):
    PROPOSED = "PROPOSED"
    NO_PROPOSAL = "NO_PROPOSAL"
    BLOCKED = "BLOCKED"


class RebalanceAction(StrEnum):
    INCREASE = "INCREASE"
    REDUCE = "REDUCE"
    CLOSE = "CLOSE"


class _FrozenRecord:
    def __copy__(self) -> None:
        raise PortfolioInputError("FROZEN_RECORD")

    def __deepcopy__(self, memo: dict[int, object]) -> None:
        raise PortfolioInputError("FROZEN_RECORD")

    def __reduce_ex__(self, protocol: SupportsIndex) -> str | tuple[Any, ...]:
        raise PortfolioInputError("FROZEN_RECORD")


@dataclass(frozen=True, slots=True)
class RebalanceLotV1(_FrozenRecord):
    lot_id: str
    quantity: Decimal
    opened_ns: int

    def __post_init__(self) -> None:
        _id(self.lot_id)
        object.__setattr__(self, "quantity", _decimal(self.quantity))
        _require(self.quantity != 0, "INVALID_LOT")
        _time(self.opened_ns)


@dataclass(frozen=True, slots=True)
class RebalanceInstrumentV1(_FrozenRecord):
    symbol: str
    current_quantity: Decimal
    lot_step: Decimal
    sizing_request: SizingRequestV1
    sizing_policy: SizingPolicyV1
    fifo_lots: tuple[RebalanceLotV1, ...]
    cooldown_until_ns: int
    stop_breach: bool

    def __post_init__(self) -> None:
        _id(self.symbol)
        object.__setattr__(self, "current_quantity", _decimal(self.current_quantity))
        object.__setattr__(self, "lot_step", _decimal(self.lot_step))
        _require(self.lot_step > 0, "INVALID_LOT")
        _require(
            (Fraction(self.current_quantity) / Fraction(self.lot_step)).denominator == 1,
            "INVALID_LOT_MULTIPLE",
        )
        _require(
            type(self.sizing_request) is SizingRequestV1
            and type(self.sizing_policy) is SizingPolicyV1,
            "INVALID_SIZING_INPUT",
        )
        lots = _records(self.fifo_lots, RebalanceLotV1)
        _require(len({lot.lot_id for lot in lots}) == len(lots), "DUPLICATE_LOT")
        _require(
            sum((Fraction(lot.quantity) for lot in lots), Fraction())
            == Fraction(self.current_quantity),
            "POSITION_LOT_MISMATCH",
        )
        if self.current_quantity != 0:
            _require(
                all(Fraction(lot.quantity) * Fraction(self.current_quantity) > 0 for lot in lots),
                "POSITION_LOT_MISMATCH",
            )
        object.__setattr__(
            self, "fifo_lots", tuple(sorted(lots, key=lambda lot: (lot.opened_ns, lot.lot_id)))
        )
        _time(self.cooldown_until_ns)
        _require(type(self.stop_breach) is bool, "INVALID_BOOLEAN")


@dataclass(frozen=True, slots=True)
class RebalanceRequestV1(_FrozenRecord):
    spec: PortfolioSpecV1
    snapshot: ExposureSnapshotV1
    policy: OverlapPolicyV1
    instruments: tuple[RebalanceInstrumentV1, ...]
    drift_threshold: Decimal
    periodic_tick: bool
    auto_reweight: bool
    long_enabled: bool
    short_enabled: bool
    fifo_netting: bool

    def __post_init__(self) -> None:
        _require(
            type(self.spec) is PortfolioSpecV1
            and type(self.snapshot) is ExposureSnapshotV1
            and type(self.policy) is OverlapPolicyV1,
            "INVALID_INPUT",
        )
        instruments = _records(self.instruments, RebalanceInstrumentV1)
        _require(len(instruments) <= 500, "INVALID_INSTRUMENTS")
        _require(
            len({item.symbol for item in instruments}) == len(instruments), "DUPLICATE_INSTRUMENT"
        )
        _require(
            len({item.sizing_request.tenant_id for item in instruments}) <= 1
            and len({item.sizing_request.account_currency for item in instruments}) <= 1
            and all(
                item.sizing_request.portfolio_revision_hash == self.spec.portfolio_revision_hash
                and item.sizing_request.evaluation_ns == self.spec.evaluation_ns
                and type(item.sizing_request.equity) is ObservationV1
                and item.sizing_request.equity.value == self.spec.nav
                for item in instruments
            ),
            "SIZING_LINK_MISMATCH",
        )
        object.__setattr__(
            self, "instruments", tuple(sorted(instruments, key=lambda item: item.symbol))
        )
        object.__setattr__(
            self, "drift_threshold", _decimal(self.drift_threshold, min_value=_ZERO, max_value=_ONE)
        )
        for name in (
            "periodic_tick",
            "auto_reweight",
            "long_enabled",
            "short_enabled",
            "fifo_netting",
        ):
            _require(type(getattr(self, name)) is bool, "INVALID_BOOLEAN")


@dataclass(frozen=True, slots=True)
class LotConsumptionV1(_FrozenRecord):
    lot_id: str
    quantity: Decimal

    def __post_init__(self) -> None:
        _id(self.lot_id)
        object.__setattr__(self, "quantity", _derived_decimal(self.quantity))
        _require(self.quantity > 0, "INVALID_LOT")


@dataclass(frozen=True, slots=True)
class RebalanceCandidateV1(_FrozenRecord):
    symbol: str
    action: RebalanceAction
    side: str
    quantity: Decimal
    current_quantity: Decimal
    target_quantity: Decimal
    notional: Decimal
    fifo_consumed: tuple[LotConsumptionV1, ...]
    reasons: tuple[str, ...]

    def __post_init__(self) -> None:
        _id(self.symbol)
        _require(
            type(self.action) is RebalanceAction and self.side in ("BUY", "SELL"),
            "INVALID_CANDIDATE",
        )
        for name in ("quantity", "current_quantity", "target_quantity", "notional"):
            object.__setattr__(self, name, _derived_decimal(getattr(self, name)))
        _require(self.quantity > 0 and self.notional > 0, "INVALID_CANDIDATE")
        _records(self.fifo_consumed, LotConsumptionV1)
        _require(
            type(self.reasons) is tuple and all(type(item) is str for item in self.reasons),
            "INVALID_CANDIDATE",
        )


@dataclass(frozen=True, slots=True)
class RebalanceProposalV1(_FrozenRecord):
    status: RebalanceStatus
    candidates: tuple[RebalanceCandidateV1, ...]
    reasons: tuple[str, ...]
    input_hash: str
    check_hash: str
    trace: tuple[str, ...]

    def __post_init__(self) -> None:
        _require(type(self.status) is RebalanceStatus, "INVALID_PROPOSAL")
        _records(self.candidates, RebalanceCandidateV1)
        for value in (self.reasons, self.trace):
            _require(
                type(value) is tuple and all(type(item) is str for item in value),
                "INVALID_PROPOSAL",
            )
        _require(
            type(self.input_hash) is str
            and len(self.input_hash) == 64
            and type(self.check_hash) is str
            and len(self.check_hash) == 64,
            "INVALID_PROPOSAL",
        )


def _lots_quantity(lot_count: int, lot_step: Decimal) -> Decimal:
    try:
        return exact_mul(lot_step, lot_count)
    except NumericError as exc:
        raise PortfolioInputError(exc.code) from None


def _exact_fraction_decimal(value: Fraction) -> Decimal:
    """Render a finite rational exactly, or deny before a rounded notional escapes."""
    denominator = value.denominator
    twos = 0
    fives = 0
    while denominator % 2 == 0:
        denominator //= 2
        twos += 1
    while denominator % 5 == 0:
        denominator //= 5
        fives += 1
    _require(denominator == 1, "PRECISION_EXCEEDED")
    scale = max(twos, fives)
    coefficient = abs(value.numerator) * 2 ** (scale - twos) * 5 ** (scale - fives)
    digits = tuple(int(digit) for digit in str(coefficient))
    decimal = Decimal((int(value < 0), digits, -scale))
    return _derived_decimal(decimal)


def _fifo_consumption(
    instrument: RebalanceInstrumentV1, quantity: Decimal
) -> tuple[LotConsumptionV1, ...]:
    remaining = Fraction(quantity)
    consumed: list[LotConsumptionV1] = []
    for lot in instrument.fifo_lots:
        taken = min(remaining, abs(Fraction(lot.quantity)))
        if taken > 0:
            consumed.append(LotConsumptionV1(lot.lot_id, _display(taken)))
            remaining -= taken
        if remaining == 0:
            break
    _require(remaining == 0, "POSITION_LOT_MISMATCH")
    return tuple(consumed)


def _target_fractions(
    spec: PortfolioSpecV1, eligible: tuple[StrategyExposureV1, ...]
) -> dict[str, Fraction]:
    selected = {item.strategy_revision_hash: item for item in eligible}
    total_weight = sum((Fraction(item.weight) for item in spec.allocations), Fraction())
    symbols: dict[str, Fraction] = {}
    for allocation in spec.allocations:
        record = selected.get(allocation.strategy_revision_hash)
        _require(record is not None, "MISSING_EXPOSURE")
        assert record is not None
        weight = Fraction(allocation.weight) / total_weight
        for exposure in record.symbol_exposures:
            symbols[exposure.key] = symbols.get(exposure.key, Fraction()) + weight * Fraction(
                exposure.value
            )
    return symbols


def _joint_values(
    request: RebalanceRequestV1,
) -> tuple[dict[str, Fraction], dict[str, Fraction], dict[str, str], HardCapsV1]:
    """Pin the complete current portfolio before checking combined deltas."""
    selected_sectors = _visible_latest(
        request.snapshot.sector_map, request.spec.evaluation_ns, "sector"
    )
    units: dict[str, Fraction] = {}
    losses: dict[str, Fraction] = {}
    sectors: dict[str, str] = {}
    policies = [request.policy.caps, *(item.sizing_policy.caps for item in request.instruments)]
    cap_names = (
        "per_symbol_notional",
        "per_sector_notional",
        "gross_notional",
        "net_notional",
        "max_leverage",
        "per_trade_loss",
        "portfolio_heat",
    )
    for instrument in request.instruments:
        symbol = instrument.symbol
        sizing = instrument.sizing_request
        sector = selected_sectors.get(symbol)
        _require(
            sector is not None
            and request.spec.evaluation_ns - sector.event_ns <= request.policy.max_age_ns,
            "SIZING_SECTOR_MISMATCH",
        )
        assert sector is not None
        sectors[symbol] = sector.sector
        for observation in (
            sizing.price,
            sizing.fx_to_account,
            sizing.worst_case_loss_per_unit,
        ):
            _require(type(observation) is ObservationV1, "MISSING_JOINT_VALUATION")
            _require(
                observation.validation_status == "VALIDATED"
                and bool(observation.source_id)
                and bool(observation.source_version)
                and observation.event_ns <= observation.available_ns <= request.spec.evaluation_ns
                and request.spec.evaluation_ns - observation.event_ns <= request.policy.max_age_ns,
                "STALE_JOINT_VALUATION",
            )
        price = _decimal(sizing.price.value)
        fx = _decimal(sizing.fx_to_account.value)
        multiplier = _decimal(sizing.contract_multiplier)
        loss = _decimal(sizing.worst_case_loss_per_unit.value)
        _require(price > 0 and fx > 0 and multiplier > 0 and loss > 0, "INVALID_JOINT_VALUATION")
        units[symbol] = Fraction(price) * Fraction(fx) * Fraction(multiplier)
        losses[symbol] = Fraction(loss) * Fraction(fx) * Fraction(multiplier)
    caps = HardCapsV1(*(min(getattr(policy, name) for policy in policies) for name in cap_names))
    return units, losses, sectors, caps


def _joint_cap_ok(
    positions: dict[str, Fraction],
    units: dict[str, Fraction],
    losses: dict[str, Fraction],
    sectors: dict[str, str],
    caps: HardCapsV1,
    nav: Decimal,
    gamma_bound: Fraction,
    gamma_cap: Decimal,
) -> bool:
    notionals = {symbol: quantity * units[symbol] for symbol, quantity in positions.items()}
    sector_gross: dict[str, Fraction] = {}
    for symbol, value in notionals.items():
        sector = sectors[symbol]
        sector_gross[sector] = sector_gross.get(sector, Fraction()) + abs(value)
    gross = sum((abs(value) for value in notionals.values()), Fraction())
    net = abs(sum(notionals.values(), Fraction()))
    heat = sum(
        (abs(quantity) * losses[symbol] for symbol, quantity in positions.items()), Fraction()
    )
    return (
        all(abs(value) <= Fraction(caps.per_symbol_notional) for value in notionals.values())
        and all(value <= Fraction(caps.per_sector_notional) for value in sector_gross.values())
        and gross <= Fraction(caps.gross_notional)
        and net <= Fraction(caps.net_notional)
        and gross <= Fraction(nav) * Fraction(caps.max_leverage)
        and heat <= Fraction(caps.portfolio_heat)
        and gamma_bound <= Fraction(gamma_cap)
    )


def _joint_lot_limit(
    symbol: str,
    direction: int,
    candidate_lots: int,
    lot: Fraction,
    positions: dict[str, Fraction],
    units: dict[str, Fraction],
    losses: dict[str, Fraction],
    sectors: dict[str, str],
    caps: HardCapsV1,
    nav: Decimal,
    gamma_bound: Fraction,
    gamma_cap: Decimal,
) -> int:
    """Find the largest safe lot count from an initially compliant state."""

    def safe(count: int) -> bool:
        trial = dict(positions)
        trial[symbol] += direction * count * lot
        return count * lot * losses[symbol] <= Fraction(caps.per_trade_loss) and _joint_cap_ok(
            trial, units, losses, sectors, caps, nav, gamma_bound, gamma_cap
        )

    if safe(candidate_lots):
        return candidate_lots
    if not safe(0):
        return 0
    lower, upper = 0, candidate_lots
    while lower + 1 < upper:
        middle = (lower + upper) // 2
        if safe(middle):
            lower = middle
        else:
            upper = middle
    return lower


def _validate_sizing_link(
    instrument: RebalanceInstrumentV1, request: RebalanceRequestV1, expected_side: str
) -> Fraction:
    sizing_request = instrument.sizing_request
    sizing_policy = instrument.sizing_policy
    spec = request.spec
    _require(
        sizing_request.instrument == instrument.symbol
        and sizing_request.portfolio_revision_hash == spec.portfolio_revision_hash
        and sizing_request.strategy_revision_hash
        in {item.strategy_revision_hash for item in spec.allocations}
        and sizing_request.evaluation_ns == spec.evaluation_ns
        and sizing_request.side == expected_side
        and sizing_request.lot_step == instrument.lot_step
        and sizing_request.risk_rail_policy_digest == sizing_policy.policy_digest,
        "SIZING_LINK_MISMATCH",
    )
    _require(type(sizing_request.equity) is ObservationV1, "SIZING_LINK_MISMATCH")
    _require(sizing_request.equity.value == spec.nav, "SIZING_LINK_MISMATCH")
    expected_positions = {
        item.symbol: item for item in request.instruments if item.current_quantity != 0
    }
    _require(
        type(sizing_request.positions) is tuple
        and all(type(item) is PositionV1 for item in sizing_request.positions),
        "SIZING_LINK_MISMATCH",
    )
    position_by_symbol = {item.instrument: item for item in sizing_request.positions}
    _require(
        len(position_by_symbol) == len(sizing_request.positions)
        and set(position_by_symbol) == set(expected_positions),
        "SIZING_LINK_MISMATCH",
    )
    for symbol, expected in expected_positions.items():
        position = position_by_symbol[symbol]
        reference = expected.sizing_request
        _require(
            position.quantity == expected.current_quantity
            and type(position.price) is ObservationV1
            and type(position.fx_to_account) is ObservationV1
            and type(position.loss_per_unit) is ObservationV1
            and type(reference.price) is ObservationV1
            and type(reference.fx_to_account) is ObservationV1
            and position.price.value == reference.price.value
            and position.fx_to_account.value == reference.fx_to_account.value
            and type(reference.worst_case_loss_per_unit) is ObservationV1
            and position.loss_per_unit.value == reference.worst_case_loss_per_unit.value
            and position.contract_multiplier == reference.contract_multiplier,
            "SIZING_LINK_MISMATCH",
        )
    _require(
        type(sizing_request.sector_map) is tuple
        and all(type(item) is SectorEntryV1 for item in sizing_request.sector_map),
        "SIZING_LINK_MISMATCH",
    )
    selected_sectors = _visible_latest(request.snapshot.sector_map, spec.evaluation_ns, "sector")
    sector_by_symbol = {item.instrument: item for item in sizing_request.sector_map}
    _require(
        len(sector_by_symbol) == len(sizing_request.sector_map)
        and set(sector_by_symbol) >= set(expected_positions) | {instrument.symbol},
        "SIZING_LINK_MISMATCH",
    )
    for symbol, entry in sector_by_symbol.items():
        selected = selected_sectors.get(symbol)
        _require(
            selected is not None
            and entry.sector == selected.sector
            and spec.evaluation_ns - selected.event_ns <= request.policy.max_age_ns,
            "SIZING_SECTOR_MISMATCH",
        )
    _require(
        type(sizing_request.price) is ObservationV1
        and type(sizing_request.fx_to_account) is ObservationV1,
        "SIZING_LINK_MISMATCH",
    )
    price = _decimal(sizing_request.price.value)
    fx = _decimal(sizing_request.fx_to_account.value)
    multiplier = _decimal(sizing_request.contract_multiplier)
    _require(price > 0 and fx > 0 and multiplier > 0, "SIZING_LINK_MISMATCH")
    return Fraction(price) * Fraction(fx) * Fraction(multiplier)


def _proposal(
    status: RebalanceStatus,
    candidates: tuple[RebalanceCandidateV1, ...],
    reasons: tuple[str, ...],
    request: RebalanceRequestV1,
    check: PortfolioCheckV1,
    trace: tuple[str, ...],
) -> RebalanceProposalV1:
    return RebalanceProposalV1(
        status=status,
        candidates=candidates,
        reasons=reasons,
        input_hash=_hash(
            (
                check.input_hash,
                check.policy_hash,
                request.instruments,
                request.drift_threshold,
                request.periodic_tick,
                request.auto_reweight,
                request.long_enabled,
                request.short_enabled,
                request.fifo_netting,
            )
        ),
        check_hash=_hash(check),
        trace=trace,
    )


def propose_rebalance(request: RebalanceRequestV1, check: PortfolioCheckV1) -> RebalanceProposalV1:
    """Propose lot-rounded deltas capped again by PORT-001; no activation or publish."""
    _require(
        type(request) is RebalanceRequestV1 and type(check) is PortfolioCheckV1, "INVALID_INPUT"
    )
    recalculated, eligible, gamma_bound = _evaluate_portfolio_with_eligible(
        request.spec, request.snapshot, request.policy
    )
    _require(check == recalculated, "CHECK_MISMATCH")
    trace: list[str] = [
        "PORT-002:rebalance-v1",
        "check_recomputed",
        "shared_eligible_exposures",
        "PORT-001_size_required",
    ]
    if check.status is PortfolioStatus.BLOCKED:
        reason = "AUTO_REWEIGHT_UNPROVEN" if request.auto_reweight else "PORTFOLIO_CHECK_BLOCKED"
        return _proposal(RebalanceStatus.BLOCKED, (), (reason,), request, check, tuple(trace))
    if len(eligible) != len(request.spec.allocations):
        return _proposal(
            RebalanceStatus.BLOCKED,
            (),
            ("INCOMPLETE_ELIGIBLE_EXPOSURES",),
            request,
            check,
            tuple(trace),
        )
    if gamma_bound > Fraction(request.policy.net_gamma_cap):
        # Strategy gamma has no instrument attribution in PORT-002. A symbol
        # close cannot prove that this breach falls, so no cure is claimed.
        return _proposal(
            RebalanceStatus.BLOCKED,
            (),
            ("GAMMA_REDUCTION_UNPROVEN",),
            request,
            check,
            tuple(trace),
        )

    targets = _target_fractions(request.spec, eligible)
    by_symbol = {item.symbol: item for item in request.instruments}
    _require(set(targets) <= set(by_symbol), "MISSING_INSTRUMENT")
    units, losses, sectors, joint_caps = _joint_values(request)
    simulated_positions = {
        item.symbol: Fraction(item.current_quantity) for item in request.instruments
    }
    candidates: list[RebalanceCandidateV1] = []
    reasons: list[str] = []
    for instrument in request.instruments:
        symbol = instrument.symbol
        desired_notional = Fraction(request.spec.nav) * targets.get(symbol, Fraction())
        sizing_request = instrument.sizing_request
        unit = units[symbol]
        lot = Fraction(instrument.lot_step)
        target_lots = abs(desired_notional) // (unit * lot)
        target_quantity = _lots_quantity(int(target_lots), instrument.lot_step)
        if desired_notional < 0:
            target_quantity = target_quantity.copy_negate()
        current = instrument.current_quantity
        if current == target_quantity:
            continue
        drift = abs(desired_notional - Fraction(current) * unit) / Fraction(request.spec.nav)
        if not request.periodic_tick and drift < Fraction(request.drift_threshold):
            reasons.append("BELOW_DRIFT_THRESHOLD:" + symbol)
            continue
        desired_delta = Fraction(target_quantity) - Fraction(current)
        if current != 0 and target_quantity != 0 and (current > 0) != (target_quantity > 0):
            desired_delta = -Fraction(current)  # Close first; never flip in one proposal.
        if desired_delta == 0:
            continue
        increasing = current == 0 or (
            target_quantity != 0
            and (target_quantity > 0) == (current > 0)
            and abs(target_quantity) > abs(current)
        )
        if increasing:
            if check.status is PortfolioStatus.QUARANTINE:
                reasons.append("QUARANTINE_NEW_ENTRY:" + symbol)
                continue
            resulting_sign = 1 if desired_delta > 0 else -1
            if (resulting_sign > 0 and not request.long_enabled) or (
                resulting_sign < 0 and not request.short_enabled
            ):
                reasons.append("SIDE_DISABLED:" + symbol)
                continue
            if instrument.stop_breach or request.spec.evaluation_ns < instrument.cooldown_until_ns:
                reasons.append("COOLDOWN_OR_STOP:" + symbol)
                continue
        elif not request.fifo_netting:
            reasons.append("FIFO_REQUIRED:" + symbol)
            continue
        side = "BUY" if desired_delta > 0 else "SELL"
        _require(_validate_sizing_link(instrument, request, side) == unit, "SIZING_LINK_MISMATCH")
        sizing_result = size(sizing_request, instrument.sizing_policy)
        if sizing_result.status is not SizingStatus.SIZE or sizing_result.proposed_quantity <= 0:
            reasons.append("PORT001_NO_SIZE:" + symbol)
            continue
        capped_lots = min(
            abs(desired_delta) // lot,
            Fraction(sizing_result.proposed_quantity) // lot,
        )
        capped_lots = _joint_lot_limit(
            symbol,
            1 if side == "BUY" else -1,
            capped_lots,
            lot,
            simulated_positions,
            units,
            losses,
            sectors,
            joint_caps,
            request.spec.nav,
            gamma_bound,
            request.policy.net_gamma_cap,
        )
        if capped_lots <= 0:
            reasons.append("BELOW_LOT_OR_JOINT_CAP:" + symbol)
            continue
        quantity = _lots_quantity(int(capped_lots), instrument.lot_step)
        _require(
            Fraction(quantity) * unit
            <= Fraction(instrument.sizing_policy.caps.per_symbol_notional),
            "PORT001_CAP_VIOLATION",
        )
        simulated_positions[symbol] += (1 if side == "BUY" else -1) * Fraction(quantity)
        notional = _exact_fraction_decimal(Fraction(quantity) * unit)
        if increasing:
            action = RebalanceAction.INCREASE
            consumed: tuple[LotConsumptionV1, ...] = ()
        else:
            action = (
                RebalanceAction.CLOSE
                if Fraction(quantity) == abs(Fraction(current))
                else RebalanceAction.REDUCE
            )
            consumed = _fifo_consumption(instrument, quantity)
        candidates.append(
            RebalanceCandidateV1(
                symbol=symbol,
                action=action,
                side=side,
                quantity=quantity,
                current_quantity=current,
                target_quantity=target_quantity,
                notional=notional,
                fifo_consumed=consumed,
                reasons=("PORT001_CAPPED", *(hit.code for hit in sizing_result.cap_hits)),
            )
        )
    if candidates:
        status = RebalanceStatus.PROPOSED
    elif check.status is PortfolioStatus.QUARANTINE:
        status = RebalanceStatus.BLOCKED
        reasons.append("QUARANTINE_NO_SAFE_REDUCTION")
    else:
        status = RebalanceStatus.NO_PROPOSAL
    trace.extend(
        (
            "target_from_weighted_exposures",
            "drift_exact",
            "joint_caps_compared_exactly",
            "lot_floor_toward_zero",
            "status:" + status.value,
        )
    )
    return _proposal(
        status,
        tuple(candidates),
        tuple(sorted(reasons)),
        request,
        check,
        tuple(trace),
    )


_guard_assignment(
    RebalanceLotV1,
    RebalanceInstrumentV1,
    RebalanceRequestV1,
    LotConsumptionV1,
    RebalanceCandidateV1,
    RebalanceProposalV1,
)
