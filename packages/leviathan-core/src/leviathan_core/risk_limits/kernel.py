"""Pure, fail-closed hard-limit assessment; no order, clock or store access."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Callable
from dataclasses import asdict
from decimal import (
    ROUND_HALF_EVEN,
    Context,
    Decimal,
    DivisionByZero,
    Inexact,
    InvalidOperation,
    Overflow,
    Underflow,
    localcontext,
)
from typing import Any, cast

from leviathan_core.risk_limits.models import (
    DatedInstrumentV1,
    FxRateV1,
    HardLimitsV1,
    LimitAssessmentV1,
    PolicyVerificationV1,
    PolicyVerifier,
    PositionV1,
    ProjectedOrderV1,
    RiskStateV1,
    RollingRateCountV1,
    VerifiedHardLimitsV1,
    WorkingOrderV1,
)

_DECIMAL_CAPS = (
    "max_order_quantity",
    "max_order_notional",
    "max_projected_position",
    "max_gross_exposure",
    "max_net_exposure",
    "max_leverage",
    "max_daily_loss",
)
_SCOPES = frozenset(("ACCOUNT", "STRATEGY", "VENUE", "INSTRUMENT"))
_DECIMAL_TEXT = re.compile(r"(?:0|[1-9][0-9]*)(?:\.[0-9]+)?", re.ASCII)
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]*", re.ASCII)
_CURRENCY = re.compile(r"[A-Z0-9]{3,8}", re.ASCII)
_ARITHMETIC_CONTEXT = Context(
    prec=34,
    rounding=ROUND_HALF_EVEN,
    Emin=-999999,
    Emax=999999,
    traps=[Inexact, Overflow, Underflow, InvalidOperation, DivisionByZero],
)


def _envelope_operations() -> tuple[
    Callable[[tuple[HardLimitsV1, ...], PolicyVerificationV1], VerifiedHardLimitsV1],
    Callable[[object], bool],
]:
    # The seal is held only in these closures, not in a serializable model.
    seal = object()

    def mint(
        policies: tuple[HardLimitsV1, ...], verification: PolicyVerificationV1
    ) -> VerifiedHardLimitsV1:
        envelope = object.__new__(VerifiedHardLimitsV1)
        object.__setattr__(envelope, "_policies", policies)
        object.__setattr__(envelope, "_verification", verification)
        object.__setattr__(envelope, "_seal", seal)
        envelope.__post_init__()
        return envelope

    def valid(value: object) -> bool:
        return isinstance(value, VerifiedHardLimitsV1) and getattr(value, "_seal", None) is seal

    return mint, valid


_mint_envelope, _valid_envelope = _envelope_operations()
del _envelope_operations


def _policy_digest(policies: tuple[HardLimitsV1, ...]) -> str:
    documents = []
    for item in policies:
        document = asdict(item)
        for cap in _DECIMAL_CAPS:
            value = _strict_decimal(document[cap], text=True)
            if value is not None:
                document[cap] = _decimal_text(value)
        documents.append(json.dumps(document, sort_keys=True, separators=(",", ":")))
    encoded = json.dumps(sorted(documents), separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def verify_hard_limits(
    policies: tuple[HardLimitsV1, ...], verifier: PolicyVerifier
) -> VerifiedHardLimitsV1:
    """Mint an envelope only after a trusted verifier attests exact policy bytes.

    The caller must supply a trusted adapter. This function checks the adapter's
    binding to the exact immutable snapshot but does not implement signatures.
    """
    if (
        not isinstance(policies, tuple)
        or not policies
        or any(not isinstance(item, HardLimitsV1) for item in policies)
        or any(not _policy_shape(item) for item in policies)
    ):
        raise ValueError("policy snapshot is missing or invalid")
    digest = _policy_digest(policies)
    verification = verifier.verify(policies, digest)
    if (
        not isinstance(verification, PolicyVerificationV1)
        or not verification.verifier_id
        or not verification.key_id
        or not isinstance(verification.policy_digest, str)
        or not hmac.compare_digest(verification.policy_digest, digest)
    ):
        raise ValueError("policy verification failed")
    return _mint_envelope(policies, verification)


def _bounded_decimal(value: object, *, text: bool = False) -> Decimal | None:
    if text:
        if not isinstance(value, str) or _DECIMAL_TEXT.fullmatch(value) is None:
            return None
        try:
            result = Decimal(value)
        except (ArithmeticError, ValueError):
            return None
    elif type(value) is Decimal:
        result = value
    else:
        return None
    if not result.is_finite():
        return None
    if _significant_digits(result) > 34 or abs(result.adjusted()) > 38:
        return None
    return result


def _significant_digits(value: Decimal) -> int:
    digits = value.as_tuple().digits
    return len(digits) - _trailing_zeros(digits)


def _trailing_zeros(digits: tuple[int, ...]) -> int:
    count = 0
    for digit in reversed(digits):
        if digit != 0:
            break
        count += 1
    return min(count, len(digits) - 1)


def _precision_exceeded(value: object, *, text: bool = False) -> bool:
    if text:
        if not isinstance(value, str) or _DECIMAL_TEXT.fullmatch(value) is None:
            return False
        candidate = Decimal(value)
    elif type(value) is Decimal:
        candidate = value
    else:
        return False
    return candidate.is_finite() and _significant_digits(candidate) > 34


def _strict_decimal(value: object, *, text: bool = False, positive: bool = False) -> Decimal | None:
    result = _bounded_decimal(value, text=text)
    if result is None or result < 0 or (positive and result == 0):
        return None
    return result


def _ns(value: object) -> bool:
    return type(value) is int and value >= 0


def _id(value: object) -> bool:
    return isinstance(value, str) and _IDENTIFIER.fullmatch(value) is not None


def _currency(value: object) -> bool:
    return isinstance(value, str) and _CURRENCY.fullmatch(value) is not None


def _fresh(source: object, ingest: object, as_of: int, max_age: int) -> bool:
    if not _ns(source) or not _ns(ingest):
        return False
    source_ns = cast(int, source)
    ingest_ns = cast(int, ingest)
    return source_ns <= ingest_ns <= as_of and as_of - source_ns <= max_age


def _policy_shape(policy: HardLimitsV1) -> bool:
    if (
        type(policy.version) is not int
        or policy.version != 1
        or not all(_id(value) for value in (policy.revision, policy.environment, policy.account_id))
        or policy.scope not in _SCOPES
        or not _ns(policy.effective_from_ns)
        or not _ns(policy.effective_until_ns)
        or policy.effective_from_ns >= policy.effective_until_ns
        or not _currency(policy.limit_currency)
        or type(policy.priority) is not int
        or policy.priority < 0
        or (
            policy.max_data_age_ns is not None
            and (not _ns(policy.max_data_age_ns) or policy.max_data_age_ns > 300_000_000_000)
        )
    ):
        return False
    selectors = (policy.strategy_id, policy.venue_id, policy.instrument_id)
    expected = {
        "ACCOUNT": (False, False, False),
        "STRATEGY": (True, False, False),
        "VENUE": (False, True, False),
        "INSTRUMENT": (False, False, True),
    }[policy.scope]
    if tuple(value is not None for value in selectors) != expected:
        return False
    if any(value is not None and value != "*" and not _id(value) for value in selectors):
        return False
    for cap in _DECIMAL_CAPS:
        value = getattr(policy, cap)
        if value is not None and _strict_decimal(value, text=True) is None:
            return False
    if policy.max_order_rate is not None and (
        type(policy.max_order_rate) is not int or policy.max_order_rate < 0
    ):
        return False
    if policy.order_rate_window_ns is not None and (
        not _ns(policy.order_rate_window_ns) or policy.order_rate_window_ns == 0
    ):
        return False
    if (policy.max_order_rate is None) != (policy.order_rate_window_ns is None):
        return False
    if policy.scope == "ACCOUNT":
        if any(getattr(policy, cap) is None for cap in _DECIMAL_CAPS):
            return False
        if (
            policy.max_order_rate is None
            or policy.order_rate_window_ns is None
            or policy.max_data_age_ns is None
            or not policy.allowed_strategies
            or not policy.allowed_venues
            or not policy.allowed_instruments
        ):
            return False
    # A scoped rule may carry explicit allowlists too; those only narrow the
    # account allowlist when the rule matches the order.
    if policy.allowed_strategies is not None and type(policy.allowed_strategies) is not tuple:
        return False
    if policy.allowed_venues is not None and type(policy.allowed_venues) is not tuple:
        return False
    if policy.allowed_instruments is not None and type(policy.allowed_instruments) is not tuple:
        return False
    if policy.allowed_strategies is not None and any(
        item != "*" and not _id(item) for item in policy.allowed_strategies
    ):
        return False
    if policy.allowed_venues is not None and any(
        item != "*" and not _id(item) for item in policy.allowed_venues
    ):
        return False
    return not (
        policy.allowed_instruments is not None
        and any(
            not isinstance(item, DatedInstrumentV1)
            or (item.instrument_id != "*" and not _id(item.instrument_id))
            or not _ns(item.effective_from_ns)
            or not _ns(item.effective_until_ns)
            or item.effective_from_ns >= item.effective_until_ns
            for item in policy.allowed_instruments
        )
    )


def _matches_selector(policy: HardLimitsV1, order: ProjectedOrderV1) -> bool:
    return (
        policy.scope == "ACCOUNT"
        or (policy.scope == "STRATEGY" and policy.strategy_id in (order.strategy_id, "*"))
        or (policy.scope == "VENUE" and policy.venue_id in (order.venue_id, "*"))
        or (policy.scope == "INSTRUMENT" and policy.instrument_id in (order.instrument_id, "*"))
    )


def _decimal_text(value: Decimal) -> str:
    if value == 0:
        return "0"
    formatted = format(value, "f")
    return formatted.rstrip("0").rstrip(".") if "." in formatted else formatted


def _snapshot_digest(order: ProjectedOrderV1, state: RiskStateV1) -> str | None:
    """Commit to the complete order and state, independent of record permutation."""

    def encode(value: object) -> str:
        if isinstance(value, Decimal):
            return _decimal_text(value)
        raise TypeError("unsupported evidence value")

    try:
        order_fields = asdict(order)
        state_fields = asdict(state)
        for field in (
            "positions",
            "committed_orders",
            "reserved_orders",
            "fx_rates",
            "rolling_rate_counts",
        ):
            records = state_fields[field]
            if records is not None:
                state_fields[field] = sorted(
                    records,
                    key=lambda item: json.dumps(
                        item,
                        sort_keys=True,
                        default=encode,
                        allow_nan=False,
                        separators=(",", ":"),
                    ),
                )
        encoded = json.dumps(
            {"order": order_fields, "state": state_fields},
            sort_keys=True,
            default=encode,
            allow_nan=False,
            separators=(",", ","),
        ).encode("utf-8")
    except (AttributeError, TypeError, ValueError):
        return None
    return hashlib.sha256(encoded).hexdigest()


def _evidence_precision_exceeded(
    order: ProjectedOrderV1, state: RiskStateV1, policies: tuple[HardLimitsV1, ...]
) -> bool:
    numbers: list[object] = [
        order.quantity,
        order.price,
        order.contract_multiplier,
        state.equity,
        state.buying_power,
        state.realized_pnl,
        state.unrealized_pnl,
    ]
    for policy in policies:
        if not isinstance(policy, HardLimitsV1):
            continue
        if any(_precision_exceeded(getattr(policy, cap), text=True) for cap in _DECIMAL_CAPS):
            return True
    for position in state.positions or ():
        if isinstance(position, PositionV1):
            numbers.extend((position.quantity, position.mark_price, position.contract_multiplier))
    for working in (state.committed_orders or ()) + (state.reserved_orders or ()):
        if isinstance(working, WorkingOrderV1):
            numbers.extend((working.quantity, working.price, working.contract_multiplier))
    for rate in state.fx_rates or ():
        if isinstance(rate, FxRateV1):
            numbers.append(rate.base_units_per_unit)
    return any(_precision_exceeded(number) for number in numbers)


def _finish(
    decision: str,
    reasons: set[str],
    revisions: tuple[str, ...],
    observed: dict[str, Decimal | int | str],
    projected: dict[str, Decimal | int | str],
    state_event_id: str | None,
    order: ProjectedOrderV1 | None,
    policy_digest: str | None,
    input_digest: str | None,
    as_of_ns: int,
) -> LimitAssessmentV1:
    def items(source: dict[str, Decimal | int | str]) -> tuple[tuple[str, str], ...]:
        return tuple(
            sorted(
                (key, _decimal_text(value) if isinstance(value, Decimal) else str(value))
                for key, value in source.items()
            )
        )

    obs = items(observed)
    proj = items(projected)
    codes = tuple(sorted(reasons)) if decision == "DENY" else ("within_hard_limits",)
    evidence = {
        "as_of_ns": as_of_ns if _ns(as_of_ns) else "invalid",
        "decision": decision,
        "reasons": codes,
        "revisions": revisions,
        "observed": obs,
        "projected": proj,
        "state_event_id": state_event_id if isinstance(state_event_id, str) else None,
        "request_id": order.request_id
        if isinstance(order, ProjectedOrderV1) and isinstance(order.request_id, str)
        else None,
        "attempt_id": order.attempt_id
        if isinstance(order, ProjectedOrderV1) and isinstance(order.attempt_id, str)
        else None,
        "policy_digest": policy_digest,
        "input_digest": input_digest,
    }
    digest = hashlib.sha256(
        json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return LimitAssessmentV1(decision, codes, revisions, obs, proj, state_event_id, digest)


def _fx_to_base(currency: str, state: RiskStateV1, as_of: int, max_age: int) -> Decimal:
    if currency == state.base_currency:
        return Decimal(1)
    rates = [item for item in state.fx_rates or () if item.currency == currency]
    if len(rates) != 1:
        raise ValueError("fx_missing")
    rate = rates[0]
    if rate.base_currency != state.base_currency or not _currency(rate.currency):
        raise ValueError("currency_mismatch")
    result = _strict_decimal(rate.base_units_per_unit, positive=True)
    if result is None or not _id(rate.source_id):
        raise ValueError("fx_invalid")
    if not _fresh(rate.source_ns, rate.ingest_ns, as_of, max_age):
        raise ValueError("fx_stale")
    return result


def _valid_position(item: PositionV1, as_of: int, max_age: int) -> bool:
    return (
        _id(item.instrument_id)
        and _bounded_decimal(item.quantity) is not None
        and _strict_decimal(item.mark_price, positive=True) is not None
        and _strict_decimal(item.contract_multiplier, positive=True) is not None
        and _currency(item.currency)
        and _id(item.price_source_id)
        and _fresh(item.price_source_ns, item.price_ingest_ns, as_of, max_age)
    )


def _valid_working(item: WorkingOrderV1, as_of: int, max_age: int) -> bool:
    return (
        all(_id(value) for value in (item.request_id, item.attempt_id, item.instrument_id))
        and item.side in ("BUY", "SELL")
        and _strict_decimal(item.quantity, positive=True) is not None
        and _strict_decimal(item.price, positive=True) is not None
        and _strict_decimal(item.contract_multiplier, positive=True) is not None
        and _currency(item.currency)
        and _id(item.price_source_id)
        and _fresh(item.price_source_ns, item.price_ingest_ns, as_of, max_age)
    )


def _projected_exposure(
    order: ProjectedOrderV1, state: RiskStateV1, as_of: int, max_age: int
) -> tuple[Decimal, Decimal, Decimal]:
    """Return worst position quantity, gross and absolute net in base currency."""
    positions = state.positions or ()
    working: tuple[WorkingOrderV1, ...] = (state.committed_orders or ()) + (
        state.reserved_orders or ()
    )
    if any(
        not isinstance(item, PositionV1) or not _valid_position(item, as_of, max_age)
        for item in positions
    ):
        raise ValueError("price_invalid")
    if any(
        not isinstance(item, WorkingOrderV1) or not _valid_working(item, as_of, max_age)
        for item in working
    ):
        raise ValueError("price_invalid")
    if len({item.instrument_id for item in positions}) != len(positions):
        raise ValueError("state_ambiguous")
    unique_working: dict[tuple[str, str], WorkingOrderV1] = {}
    for item in working:
        identity = (item.request_id, item.attempt_id)
        previous = unique_working.get(identity)
        if previous is not None and previous != item:
            raise ValueError("state_inconsistent")
        unique_working[identity] = item
    if (order.request_id, order.attempt_id) in unique_working:
        raise ValueError("order_duplicate")

    # Every order is a commitment. Aggregate all BUY and SELL possibilities; the
    # larger absolute endpoint bounds any fill ordering or partial fill.
    instruments: dict[str, dict[str, Any]] = {}
    for position in positions:
        instruments[position.instrument_id] = {
            "quantity": position.quantity,
            "buy": Decimal(0),
            "sell": Decimal(0),
            "price": position.mark_price,
            "multiplier": position.contract_multiplier,
            "currency": position.currency,
        }
    for commitment in cast(
        list[WorkingOrderV1 | ProjectedOrderV1], [*unique_working.values(), order]
    ):
        record = instruments.setdefault(
            commitment.instrument_id,
            {
                "quantity": Decimal(0),
                "buy": Decimal(0),
                "sell": Decimal(0),
                "price": commitment.price,
                "multiplier": commitment.contract_multiplier,
                "currency": commitment.currency,
            },
        )
        if (
            commitment.contract_multiplier != record["multiplier"]
            or commitment.currency != record["currency"]
        ):
            raise ValueError("state_inconsistent")
        record["price"] = max(record["price"], commitment.price)
        record["buy" if commitment.side == "BUY" else "sell"] += commitment.quantity

    position_quantity = Decimal(0)
    gross = Decimal(0)
    net_low = Decimal(0)
    net_high = Decimal(0)
    for instrument_id, record in instruments.items():
        low = record["quantity"] - record["sell"]
        high = record["quantity"] + record["buy"]
        magnitude = max(abs(low), abs(high))
        if instrument_id == order.instrument_id:
            position_quantity = magnitude
        unit_base = (
            record["price"]
            * record["multiplier"]
            * _fx_to_base(record["currency"], state, as_of, max_age)
        )
        gross += magnitude * unit_base
        net_low += low * unit_base
        net_high += high * unit_base
    return position_quantity, gross, max(abs(net_low), abs(net_high))


def assess_limits(
    order: ProjectedOrderV1 | None,
    policies: VerifiedHardLimitsV1 | None,
    state: RiskStateV1 | None,
    as_of_ns: int,
) -> LimitAssessmentV1:
    """Assess one OMS request without ambient Decimal rounding or side effects."""
    with localcontext(_ARITHMETIC_CONTEXT):
        # Rounded intermediate values must never turn a hard breach into ALLOW.
        return _assess_limits_impl(order, policies, state, as_of_ns)


def _assess_limits_impl(
    order: ProjectedOrderV1 | None,
    policies: VerifiedHardLimitsV1 | None,
    state: RiskStateV1 | None,
    as_of_ns: int,
) -> LimitAssessmentV1:
    """Assess one OMS request against verified hard limits and a complete snapshot.

    Every uncertainty returns DENY. The function neither caches ALLOW nor grants
    submission permission; a caller must rerun it against current state.
    """
    reasons: set[str] = set()
    revisions: tuple[str, ...] = ()
    observed: dict[str, Decimal | int | str] = {}
    projected: dict[str, Decimal | int | str] = {}
    event_id = state.last_committed_event_id if isinstance(state, RiskStateV1) else None
    policy_hash: str | None = None
    input_hash: str | None = None

    def deny(reason: str) -> LimitAssessmentV1:
        reasons.add(reason)
        return _finish(
            "DENY",
            reasons,
            revisions,
            observed,
            projected,
            event_id,
            order,
            policy_hash,
            input_hash,
            as_of_ns,
        )

    try:
        if not _ns(as_of_ns):
            return deny("as_of_invalid")
        if not _valid_envelope(policies):
            return deny("policy_unverified")
        assert policies is not None
        policy_hash = policies.verification.policy_digest
        if not hmac.compare_digest(_policy_digest(policies.policies), policy_hash):
            return deny("policy_tampered")
        if not isinstance(order, ProjectedOrderV1):
            return deny("order_invalid")
        if not isinstance(state, RiskStateV1):
            return deny("state_missing")
        input_hash = _snapshot_digest(order, state)
        if _evidence_precision_exceeded(order, state, policies.policies):
            return deny("PRECISION_EXCEEDED")
        if (
            not all(
                _id(value)
                for value in (
                    order.environment,
                    order.account_id,
                    order.request_id,
                    order.attempt_id,
                    order.strategy_id,
                    order.venue_id,
                    order.instrument_id,
                    order.price_source_id,
                )
            )
            or order.side not in ("BUY", "SELL")
            or _strict_decimal(order.quantity, positive=True) is None
            or _strict_decimal(order.price, positive=True) is None
            or _strict_decimal(order.contract_multiplier, positive=True) is None
            or not _currency(order.currency)
            or type(order.is_manual) is not bool
            or any(
                value is not None and not isinstance(value, str)
                for value in (order.override_token, order.role, order.agent_instruction)
            )
        ):
            return deny("order_invalid")
        if order.account_id != state.account_id:
            return deny("account_mismatch")
        if order.environment != state.environment:
            return deny("environment_mismatch")
        if state.account_status != "ACTIVE":
            return deny("account_inactive")
        if not all(
            _id(value)
            for value in (state.account_id, state.environment, state.last_committed_event_id)
        ):
            return deny("state_invalid")

        related = tuple(
            item
            for item in policies.policies
            if item.account_id == order.account_id and item.environment == order.environment
        )
        if not related:
            return deny("policy_missing")
        if any(not _policy_shape(item) for item in related):
            return deny("policy_invalid")
        if len({item.revision for item in related}) != len(related):
            return deny("policy_ambiguous")
        applicable = tuple(item for item in related if _matches_selector(item, order))
        if any(
            not (item.effective_from_ns <= as_of_ns < item.effective_until_ns)
            for item in applicable
        ):
            return deny("policy_stale")
        accounts = tuple(item for item in applicable if item.scope == "ACCOUNT")
        if len(accounts) != 1:
            return deny("policy_ambiguous" if accounts else "policy_missing")
        revisions = tuple(sorted(item.revision for item in applicable))
        for rule in applicable:
            if rule.allowed_strategies is not None and (
                order.strategy_id not in rule.allowed_strategies
                and "*" not in rule.allowed_strategies
            ):
                return deny("scope_not_allowed")
            if rule.allowed_venues is not None and (
                order.venue_id not in rule.allowed_venues and "*" not in rule.allowed_venues
            ):
                return deny("scope_not_allowed")
            if rule.allowed_instruments is not None and not any(
                item.instrument_id in (order.instrument_id, "*")
                and item.effective_from_ns <= as_of_ns < item.effective_until_ns
                for item in rule.allowed_instruments
            ):
                return deny("instrument_not_allowed")

        max_age = min(
            item.max_data_age_ns for item in applicable if item.max_data_age_ns is not None
        )
        if not _fresh(state.source_ns, state.ingest_ns, as_of_ns, max_age) or not _fresh(
            state.equity_source_ns, state.equity_ingest_ns, as_of_ns, max_age
        ):
            return deny("state_stale")
        if not _fresh(order.price_source_ns, order.price_ingest_ns, as_of_ns, max_age):
            return deny("price_stale")
        if (
            not _currency(state.base_currency)
            or _strict_decimal(state.equity, positive=True) is None
            or _strict_decimal(state.buying_power) is None
            or _bounded_decimal(state.realized_pnl) is None
            or _bounded_decimal(state.unrealized_pnl) is None
            or any(
                value is None
                for value in (
                    state.positions,
                    state.committed_orders,
                    state.reserved_orders,
                    state.fx_rates,
                    state.rolling_rate_counts,
                )
            )
            or any(
                type(value) is not tuple
                for value in (
                    state.positions,
                    state.committed_orders,
                    state.reserved_orders,
                    state.fx_rates,
                    state.rolling_rate_counts,
                )
            )
        ):
            return deny("state_incomplete")
        assert state.equity is not None and state.buying_power is not None
        assert state.realized_pnl is not None and state.unrealized_pnl is not None
        assert state.positions is not None and state.committed_orders is not None
        assert state.reserved_orders is not None
        assert state.fx_rates is not None and state.rolling_rate_counts is not None
        if any(
            len(items) > 4096
            for items in (
                state.positions,
                state.committed_orders,
                state.reserved_orders,
                state.fx_rates,
                state.rolling_rate_counts,
            )
        ):
            return deny("state_oversized")
        # Reject ambiguous FX and rolling-count snapshots before any comparison.
        if any(not isinstance(rate, FxRateV1) for rate in state.fx_rates) or len(
            {rate.currency for rate in state.fx_rates}
        ) != len(state.fx_rates):
            return deny("fx_ambiguous")
        if any(
            not isinstance(item, RollingRateCountV1)
            or not _ns(item.window_ns)
            or item.window_ns == 0
            or type(item.count) is not int
            or item.count < 0
            or not _ns(item.as_of_ns)
            for item in state.rolling_rate_counts
        ):
            return deny("rate_state_invalid")
        if any(item.as_of_ns != as_of_ns for item in state.rolling_rate_counts):
            return deny("rate_counter_stale")
        counts = {item.window_ns: item for item in state.rolling_rate_counts}
        if len(counts) != len(state.rolling_rate_counts):
            return deny("rate_ambiguous")

        position_qty, gross_base, net_base = _projected_exposure(order, state, as_of_ns, max_age)
        order_base = (
            order.quantity
            * order.price
            * order.contract_multiplier
            * _fx_to_base(order.currency, state, as_of_ns, max_age)
        )
        daily_loss_base = max(Decimal(0), -(state.realized_pnl + state.unrealized_pnl))
        # This quotient is only reported as evidence. The limit comparison below
        # uses exact multiplication and remains subject to the Inexact trap.
        with localcontext() as display_context:
            display_context.traps[Inexact] = False
            leverage = gross_base / state.equity
        observed.update(
            {
                "equity_base": state.equity,
                "buying_power_base": state.buying_power,
                "daily_loss_base": daily_loss_base,
            }
        )
        projected.update(
            {
                "order_quantity": order.quantity,
                "order_notional_base": order_base,
                "position_quantity": position_qty,
                "gross_exposure_base": gross_base,
                "net_exposure_base": net_base,
                "leverage": leverage,
            }
        )
        if order_base > state.buying_power:
            reasons.add("buying_power_exceeded")

        for policy in applicable:
            policy_fx = _fx_to_base(policy.limit_currency, state, as_of_ns, max_age)
            policy_values = {
                "max_order_quantity": order.quantity,
                "max_order_notional": order_base,
                "max_projected_position": position_qty,
                "max_gross_exposure": gross_base,
                "max_net_exposure": net_base,
                "max_leverage": gross_base,
                "max_daily_loss": daily_loss_base,
            }
            for cap, value in policy_values.items():
                raw = getattr(policy, cap)
                if raw is None:
                    continue
                threshold = Decimal(raw)
                if cap == "max_leverage":
                    ceiling = threshold * state.equity
                elif cap in ("max_order_quantity", "max_projected_position"):
                    ceiling = threshold
                else:
                    ceiling = threshold * policy_fx
                if value > ceiling:
                    reasons.add(cap + "_exceeded")
            if policy.max_order_rate is not None:
                assert policy.order_rate_window_ns is not None
                count = counts.get(policy.order_rate_window_ns)
                if count is None:
                    reasons.add("rate_state_missing")
                else:
                    projected["order_rate_" + str(policy.order_rate_window_ns)] = count.count + 1
                    if count.count + 1 > policy.max_order_rate:
                        reasons.add("order_rate_exceeded")
        return _finish(
            "DENY" if reasons else "ALLOW",
            reasons,
            revisions,
            observed,
            projected,
            event_id,
            order,
            policy_hash,
            input_hash,
            as_of_ns,
        )
    except (ArithmeticError, AttributeError, KeyError, TypeError, ValueError) as error:
        # Expected incomplete evidence is classified; nothing escapes as an ALLOW.
        if isinstance(error, (Inexact, Overflow, Underflow)):
            return deny("PRECISION_EXCEEDED")
        code = str(error)
        return deny(
            code
            if code
            in {
                "fx_missing",
                "fx_invalid",
                "fx_stale",
                "currency_mismatch",
                "price_invalid",
                "state_ambiguous",
                "state_inconsistent",
                "order_duplicate",
            }
            else "input_invalid"
        )
