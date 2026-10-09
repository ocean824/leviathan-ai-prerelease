"""Pure capped Kelly and conservative portfolio-heat sizing advisory."""

from __future__ import annotations

import hashlib
from dataclasses import fields, is_dataclass, replace
from decimal import Decimal
from fractions import Fraction

from leviathan_core.numeric import (
    NumericError,
    Ratio,
    canonical_json,
    exact_mul,
    parse_decimal,
    parse_int,
)
from leviathan_core.risk_limits.kernel import assess_limits
from leviathan_core.risk_limits.models import (
    FxRateV1,
    PositionV1,
    RiskStateV1,
    VerifiedHardLimitsV1,
    WorkingOrderV1,
)
from leviathan_core.risk_limits.sizing_models import (
    CorrelationClusterV1,
    SizingDecisionV1,
    SizingEvidenceError,
    SizingEvidenceV1,
    StopLossV1,
    ValidationStatus,
    _id,
    _mint_decision,
)

_ZERO = Decimal(0)
_ONE = Decimal(1)
_MAX_AGE_NS = 300_000_000_000
_MAX_LOTS = 10**38
_QUANTITY_REDUCIBLE_REASONS = frozenset(
    {
        "max_order_quantity_exceeded",
        "max_order_notional_exceeded",
        "max_projected_position_exceeded",
        "max_gross_exposure_exceeded",
        "max_net_exposure_exceeded",
        "max_leverage_exceeded",
        "buying_power_exceeded",
    }
)


class _DenyError(Exception):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _plain(value: object, *, safe: bool = False, as_of_ns: int | None = None) -> object:
    if is_dataclass(value) and not isinstance(value, type):
        document: dict[str, object] = {}
        for dataclass_field in fields(value):
            member = getattr(value, dataclass_field.name)
            if (
                isinstance(value, SizingEvidenceV1)
                and dataclass_field.name in ("correlations", "stops")
                and type(member) is tuple
                and as_of_ns is not None
            ):
                member = tuple(
                    item
                    for item in member
                    if not (
                        isinstance(item, (CorrelationClusterV1, StopLossV1))
                        and type(item.received_ns) is int
                        and item.received_ns > as_of_ns
                    )
                )
            document[dataclass_field.name] = _plain(member, safe=safe, as_of_ns=as_of_ns)
        if isinstance(value, RiskStateV1):
            for field in (
                "positions",
                "committed_orders",
                "reserved_orders",
                "fx_rates",
                "rolling_rate_counts",
            ):
                records = document[field]
                if isinstance(records, list):
                    document[field] = sorted(records, key=canonical_json)
        if isinstance(value, SizingEvidenceV1):
            for name in ("correlations", "stops"):
                records = document[name]
                if isinstance(records, list):
                    document[name] = sorted(records, key=canonical_json)
        return document
    if type(value) is tuple:
        if len(value) > 4096:
            if safe:
                return {"oversized_tuple_identity": id(value), "length": len(value)}
            raise TypeError("oversized sizing evidence")
        return [_plain(item, safe=safe, as_of_ns=as_of_ns) for item in value]
    if type(value) is ValidationStatus:
        return value.value
    if type(value) is Decimal and safe:
        parts = value.as_tuple()
        return {
            "decimal_sign": parts.sign,
            "decimal_coefficient_sha256": hashlib.sha256(bytes(parts.digits)).hexdigest(),
            "decimal_digits": len(parts.digits),
            "decimal_exponent": parts.exponent,
        }
    if type(value) in (str, int, bool, Decimal) or value is None:
        return value
    return {
        "unsupported_type": f"{type(value).__module__}.{type(value).__qualname__}",
        "unsupported_identity": id(value),
    }


def _digest(
    evidence: SizingEvidenceV1 | None,
    hard_limits: VerifiedHardLimitsV1 | None,
    as_of_ns: object,
    status: str,
    quantity: Decimal,
    reasons: tuple[str, ...],
) -> str:
    try:
        payload = {
            "schema": "RISK-004-v1",
            "evidence": _plain(evidence, as_of_ns=as_of_ns if type(as_of_ns) is int else None),
            "hard_limits_verification": _plain(hard_limits.verification)
            if isinstance(hard_limits, VerifiedHardLimitsV1)
            else None,
            "hard_limits_policies": _plain(hard_limits.policies)
            if type(hard_limits) is VerifiedHardLimitsV1
            else _plain(hard_limits),
            "as_of_ns": as_of_ns,
            "status": status,
            "max_quantity": quantity,
            "reason_codes": reasons,
        }
        encoded = canonical_json(payload)
    except (AttributeError, NumericError, TypeError, ValueError):
        try:
            encoded = canonical_json(
                {
                    "schema": "RISK-004-v1-invalid",
                    "evidence": _plain(
                        evidence,
                        safe=True,
                        as_of_ns=as_of_ns if type(as_of_ns) is int else None,
                    ),
                    "hard_limits_verification": _plain(hard_limits.verification, safe=True)
                    if isinstance(hard_limits, VerifiedHardLimitsV1)
                    else _plain(hard_limits, safe=True),
                    "hard_limits_policies": _plain(hard_limits.policies, safe=True)
                    if type(hard_limits) is VerifiedHardLimitsV1
                    else _plain(hard_limits, safe=True),
                    "as_of_ns": _plain(as_of_ns, safe=True),
                    "status": status,
                    "max_quantity": _plain(quantity, safe=True),
                    "reason_codes": reasons,
                }
            )
        except (AttributeError, NumericError, TypeError, ValueError):
            encoded = canonical_json(
                {
                    "schema": "RISK-004-v1-unreadable",
                    "evidence_identity": id(evidence),
                    "hard_limits_identity": id(hard_limits),
                    "as_of_ns_identity": id(as_of_ns),
                    "status": status,
                    "reason_codes": reasons,
                }
            )
    return hashlib.sha256(encoded).hexdigest()


def _fresh(event_ns: object, received_ns: object, as_of_ns: int) -> bool:
    return (
        type(event_ns) is int
        and type(received_ns) is int
        and 0 <= event_ns <= received_ns <= as_of_ns
        and as_of_ns - event_ns <= _MAX_AGE_NS
    )


def _valid_time(event_ns: object, received_ns: object, as_of_ns: int) -> bool:
    return (
        type(event_ns) is int
        and type(received_ns) is int
        and 0 <= event_ns <= received_ns <= as_of_ns
    )


def _fx(currency: str, evidence: SizingEvidenceV1, as_of_ns: int) -> Decimal:
    state = evidence.state
    if currency == state.base_currency:
        return _ONE
    rates = state.fx_rates
    if type(rates) is not tuple:
        raise _DenyError("FX_MISSING")
    if len(rates) > 4096:
        raise _DenyError("FX_OVERSIZED")
    matches = tuple(rate for rate in rates if type(rate) is FxRateV1 and rate.currency == currency)
    if len(matches) != 1 or matches[0].base_currency != state.base_currency:
        raise _DenyError("FX_MISSING" if not matches else "FX_AMBIGUOUS")
    rate = matches[0]
    if not _fresh(rate.source_ns, rate.ingest_ns, as_of_ns):
        raise _DenyError("FX_STALE")
    try:
        conversion = parse_decimal(rate.base_units_per_unit, field="fx", min_value=_ZERO)
    except NumericError:
        raise _DenyError("FX_INVALID") from None
    if conversion == 0:
        raise _DenyError("FX_INVALID")
    return conversion


def _unit(
    price: Decimal, multiplier: Decimal, currency: str, evidence: SizingEvidenceV1, as_of_ns: int
) -> Decimal:
    price = parse_decimal(price, field="price", min_value=_ZERO)
    multiplier = parse_decimal(multiplier, field="multiplier", min_value=_ZERO)
    if price == 0 or multiplier == 0:
        raise _DenyError("PRICE_INVALID")
    return exact_mul(exact_mul(price, multiplier), _fx(currency, evidence, as_of_ns))


def _clusters(evidence: SizingEvidenceV1, as_of_ns: int) -> dict[str, str]:
    entries = evidence.correlations
    if type(entries) is not tuple or not entries:
        raise _DenyError("CORRELATION_MISSING")
    if len(entries) > 4096:
        raise _DenyError("CORRELATION_OVERSIZED")
    mapping: dict[str, str] = {}
    for item in entries:
        if type(item) is not CorrelationClusterV1:
            raise _DenyError("CORRELATION_INVALID")
        if type(item.received_ns) is int and item.received_ns > as_of_ns:
            continue
        item.__post_init__()
        if not _valid_time(item.event_ns, item.received_ns, as_of_ns):
            raise _DenyError("CORRELATION_UNVERIFIED")
        if item.instrument_id in mapping:
            raise _DenyError("CORRELATION_AMBIGUOUS")
        if type(item.validation_status) is not ValidationStatus or (
            item.validation_status is not ValidationStatus.VALIDATED
        ):
            raise _DenyError("CORRELATION_UNVERIFIED")
        mapping[item.instrument_id] = item.cluster_id
    return mapping


def _exposure(
    evidence: SizingEvidenceV1, as_of_ns: int, clusters: dict[str, str]
) -> tuple[Fraction, dict[str, Fraction], Fraction, Fraction]:
    state = evidence.state
    if (
        type(state.positions) is not tuple
        or type(state.committed_orders) is not tuple
        or type(state.reserved_orders) is not tuple
    ):
        raise _DenyError("POSITION_STATE_MISSING")
    if any(
        len(records) > 4096
        for records in (state.positions, state.committed_orders, state.reserved_orders)
    ):
        raise _DenyError("POSITION_STATE_OVERSIZED")
    heat = Fraction(0)
    by_cluster: dict[str, Fraction] = {}
    stops: dict[tuple[str, str | None, str | None], StopLossV1] = {}
    if evidence.stops is not None:
        if type(evidence.stops) is not tuple or len(evidence.stops) > 4096:
            raise _DenyError("STOP_EVIDENCE_INVALID")
        for stop in evidence.stops:
            if type(stop) is not StopLossV1:
                raise _DenyError("STOP_EVIDENCE_INVALID")
            if type(stop.received_ns) is int and stop.received_ns > as_of_ns:
                continue
            stop.__post_init__()
            key = stop.instrument_id, stop.request_id, stop.attempt_id
            if key in stops:
                raise _DenyError("STOP_AMBIGUOUS")
            stops[key] = stop

    def loss_unit(
        instrument: str,
        request_id: str | None,
        attempt_id: str | None,
        notional_unit: Decimal,
        multiplier: Decimal,
        currency: str,
    ) -> Decimal:
        stop = stops.get((instrument, request_id, attempt_id))
        if (
            stop is None
            or type(stop.validation_status) is not ValidationStatus
            or stop.validation_status is not ValidationStatus.VALIDATED
            or not _valid_time(stop.event_ns, stop.received_ns, as_of_ns)
        ):
            return notional_unit
        return exact_mul(
            exact_mul(stop.loss_per_unit, multiplier), _fx(currency, evidence, as_of_ns)
        )

    def add(instrument: str, quantity: Decimal, unit: Decimal) -> None:
        nonlocal heat
        cluster = clusters.get(instrument)
        if cluster is None:
            raise _DenyError("CORRELATION_MISSING")
        loss = abs(Fraction(quantity)) * Fraction(unit)
        heat += loss
        by_cluster[cluster] = by_cluster.get(cluster, Fraction(0)) + loss

    seen_positions: set[str] = set()
    for position in state.positions:
        if type(position) is not PositionV1 or position.instrument_id in seen_positions:
            raise _DenyError("POSITION_STATE_INVALID")
        seen_positions.add(position.instrument_id)
        if not _fresh(position.price_source_ns, position.price_ingest_ns, as_of_ns):
            raise _DenyError("PRICE_STALE")
        quantity = parse_decimal(position.quantity, field="quantity")
        unit = _unit(
            position.mark_price, position.contract_multiplier, position.currency, evidence, as_of_ns
        )
        add(
            position.instrument_id,
            quantity,
            loss_unit(
                position.instrument_id,
                None,
                None,
                unit,
                position.contract_multiplier,
                position.currency,
            ),
        )

    committed: dict[tuple[str, str], WorkingOrderV1] = {}
    for working in (*state.committed_orders, *state.reserved_orders):
        if type(working) is not WorkingOrderV1:
            raise _DenyError("WORKING_ORDER_INVALID")
        working_key = working.request_id, working.attempt_id
        previous = committed.get(working_key)
        if previous is not None:
            if previous != working:
                raise _DenyError("WORKING_ORDER_CONFLICT")
            continue
        committed[working_key] = working
        if not _fresh(working.price_source_ns, working.price_ingest_ns, as_of_ns):
            raise _DenyError("PRICE_STALE")
        quantity = parse_decimal(working.quantity, field="quantity", min_value=_ZERO)
        unit = _unit(
            working.price, working.contract_multiplier, working.currency, evidence, as_of_ns
        )
        add(
            working.instrument_id,
            quantity,
            loss_unit(
                working.instrument_id,
                working.request_id,
                working.attempt_id,
                unit,
                working.contract_multiplier,
                working.currency,
            ),
        )

    order = evidence.order
    if not _fresh(order.price_source_ns, order.price_ingest_ns, as_of_ns):
        raise _DenyError("PRICE_STALE")
    if order.instrument_id not in clusters:
        raise _DenyError("CORRELATION_MISSING")
    notional_unit = _unit(
        order.price, order.contract_multiplier, order.currency, evidence, as_of_ns
    )
    candidate_loss_unit = loss_unit(
        order.instrument_id,
        order.request_id,
        order.attempt_id,
        notional_unit,
        order.contract_multiplier,
        order.currency,
    )
    return heat, by_cluster, Fraction(notional_unit), Fraction(candidate_loss_unit)


def _kelly(evidence: SizingEvidenceV1, as_of_ns: int) -> Fraction:
    payoff = evidence.payoff
    if payoff is None:
        raise _DenyError("PAYOFF_MISSING")
    if payoff.strategy_id != evidence.order.strategy_id or not _valid_time(
        payoff.event_ns, payoff.received_ns, as_of_ns
    ):
        raise _DenyError("PAYOFF_UNVERIFIED")
    if (
        type(payoff.validation_status) is not ValidationStatus
        or payoff.validation_status is not ValidationStatus.VALIDATED
        or payoff.sample_count <= 0
    ):
        raise _DenyError("PAYOFF_UNVERIFIED")
    if payoff.uncertainty_fraction != 0:
        raise _DenyError("PAYOFF_UNCERTAIN")
    if payoff.win_payoff <= 0 or payoff.loss_payoff <= 0:
        raise _DenyError("PAYOFF_INVALID")
    probability = Fraction(parse_decimal(payoff.win_probability, field="probability"))
    odds = Fraction(parse_decimal(payoff.win_payoff, field="payoff")) / Fraction(
        parse_decimal(payoff.loss_payoff, field="payoff")
    )
    fraction = probability - (1 - probability) / odds
    exact_fraction = Ratio(fraction.numerator, fraction.denominator)
    if exact_fraction.le(0):
        raise _DenyError("KELLY_NONPOSITIVE")
    assert evidence.policy is not None
    cap = Fraction(evidence.policy.kelly_fraction_cap)
    return min(fraction, cap)


def _sized_quantity(lots: int, lot_step: Decimal) -> Decimal:
    if not 0 <= lots <= _MAX_LOTS:
        raise _DenyError("COMPUTATION_BOUND")
    return exact_mul(lots, lot_step)


def size_portfolio(
    evidence: SizingEvidenceV1 | None,
    hard_limits: VerifiedHardLimitsV1 | None,
    as_of_ns: int,
) -> SizingDecisionV1:
    """Return a bounded advisory quantity; every candidate must pass RISK-002."""
    input_revision = (
        evidence.state.last_committed_event_id
        if isinstance(evidence, SizingEvidenceV1) and _id(evidence.state.last_committed_event_id)
        else None
    )
    policy_revision = (
        evidence.policy.revision
        if isinstance(evidence, SizingEvidenceV1)
        and evidence.policy is not None
        and _id(evidence.policy.revision)
        else None
    )

    def finish(status: str, quantity: Decimal, reasons: tuple[str, ...]) -> SizingDecisionV1:
        digest = _digest(evidence, hard_limits, as_of_ns, status, quantity, reasons)
        safe_as_of = as_of_ns if type(as_of_ns) is int and 0 <= as_of_ns <= 2**63 - 1 else 0
        return _mint_decision(
            status, quantity, reasons, input_revision, policy_revision, digest, safe_as_of
        )

    try:
        parse_int(as_of_ns, field="as_of_ns", min_value=0, max_value=2**63 - 1)
        if type(evidence) is not SizingEvidenceV1:
            raise _DenyError("EVIDENCE_MISSING")
        if type(hard_limits) is not VerifiedHardLimitsV1:
            raise _DenyError("HARD_LIMITS_MISSING")
        evidence.__post_init__()
        evidence.equity.__post_init__()
        if evidence.payoff is not None:
            evidence.payoff.__post_init__()
        policy = evidence.policy
        if policy is None:
            raise _DenyError("POLICY_MISSING")
        policy.__post_init__()
        order, state, equity = evidence.order, evidence.state, evidence.equity
        if (
            policy.account_id != order.account_id
            or policy.strategy_id != order.strategy_id
            or equity.account_id != order.account_id
            or state.account_id != order.account_id
            or state.environment != order.environment
        ):
            raise _DenyError("ACCOUNT_MISMATCH")
        if not policy.effective_from_ns <= as_of_ns < policy.effective_until_ns:
            raise _DenyError("POLICY_STALE")
        if (
            equity.state_event_id != state.last_committed_event_id
            or state.equity != equity.equity
            or state.buying_power != equity.buying_power
            or equity.event_ns != state.equity_source_ns
            or equity.received_ns != state.equity_ingest_ns
        ):
            raise _DenyError("EQUITY_INCONSISTENT")
        if not _fresh(equity.event_ns, equity.received_ns, as_of_ns):
            raise _DenyError("EQUITY_STALE")
        if not _fresh(state.source_ns, state.ingest_ns, as_of_ns):
            raise _DenyError("BROKER_STATE_STALE")
        if state.account_status != "ACTIVE":
            raise _DenyError("ACCOUNT_INACTIVE")
        if equity.buying_power <= 0:
            raise _DenyError("BUYING_POWER_EXHAUSTED")
        clusters = _clusters(evidence, as_of_ns)
        heat, by_cluster, unit, candidate_loss_unit = _exposure(evidence, as_of_ns, clusters)
        step = Fraction(policy.lot_step)
        requested = Fraction(parse_decimal(order.quantity, field="quantity", min_value=_ZERO))
        if requested <= 0:
            raise _DenyError("QUANTITY_INVALID")
        requested_lots = requested // step
        if requested_lots > _MAX_LOTS:
            raise _DenyError("COMPUTATION_BOUND")
        fraction = _kelly(evidence, as_of_ns)
        kelly_lots = min(requested_lots, (Fraction(equity.equity) * fraction / unit) // step)
        if kelly_lots <= 0:
            raise _DenyError("KELLY_BELOW_LOT")
        reasons: set[str] = set()
        if kelly_lots < requested_lots:
            reasons.add("KELLY_REDUCED")
        heat_cap = Fraction(equity.equity) * Fraction(policy.portfolio_heat_fraction_cap)
        cluster_cap = Fraction(equity.equity) * Fraction(policy.cluster_heat_fraction_cap)
        order_cluster = clusters[order.instrument_id]
        if heat > heat_cap:
            raise _DenyError("PORTFOLIO_HEAT_EXCEEDED")
        if any(cluster_heat > cluster_cap for cluster_heat in by_cluster.values()):
            raise _DenyError("CLUSTER_HEAT_EXCEEDED")
        heat_lots = kelly_lots
        if candidate_loss_unit > 0:
            heat_lots = min(
                heat_lots,
                (heat_cap - heat) // (step * candidate_loss_unit),
                (cluster_cap - by_cluster.get(order_cluster, Fraction(0)))
                // (step * candidate_loss_unit),
            )
        if heat_lots < kelly_lots:
            reasons.add("HEAT_REDUCED")
        if heat_lots <= 0:
            if heat_cap - heat < step * candidate_loss_unit:
                raise _DenyError("PORTFOLIO_HEAT_EXCEEDED")
            raise _DenyError("CLUSTER_HEAT_EXCEEDED")

        def hard_check(lots: int) -> tuple[bool, tuple[str, ...]]:
            quantity = _sized_quantity(lots, policy.lot_step)
            candidate = replace(order, quantity=quantity)
            assessment = assess_limits(candidate, hard_limits, state, as_of_ns)
            return assessment.decision == "ALLOW", assessment.reason_codes

        allowed, hard_reasons = hard_check(heat_lots)
        if allowed:
            final_lots = heat_lots
        else:
            if not hard_reasons or any(
                code not in _QUANTITY_REDUCIBLE_REASONS for code in hard_reasons
            ):
                raise _DenyError("HARD_LIMIT_DENY")
            low, high = 0, heat_lots
            while low < high:
                middle = (low + high + 1) // 2
                candidate_ok, _ = hard_check(middle)
                if candidate_ok:
                    low = middle
                else:
                    high = middle - 1
            final_lots = low
            if final_lots <= 0 or not hard_check(final_lots)[0]:
                raise _DenyError("HARD_LIMIT_DENY")
            reasons.add("HARD_LIMIT_REDUCED")
        quantity = _sized_quantity(final_lots, policy.lot_step)
        if quantity <= 0 or quantity > order.quantity:
            raise _DenyError("POSTCONDITION_FAILED")
        return finish("SIZE", quantity, tuple(sorted(reasons)) or ("SIZE_APPROVED",))
    except _DenyError as error:
        return finish("DENY", _ZERO, (error.code,))
    except (NumericError, SizingEvidenceError) as error:
        return finish("DENY", _ZERO, (error.code,))
    except (ArithmeticError, AttributeError, TypeError, ValueError):
        return finish("DENY", _ZERO, ("INPUT_INVALID",))
