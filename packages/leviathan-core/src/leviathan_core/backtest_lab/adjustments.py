"""Causal back-adjustment with fixed Decimal arithmetic and immutable action inputs."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import date, timedelta
from decimal import (
    ROUND_HALF_EVEN,
    Clamped,
    Context,
    Decimal,
    DecimalException,
    DivisionByZero,
    FloatOperation,
    Inexact,
    InvalidOperation,
    Overflow,
    Subnormal,
    Underflow,
    localcontext,
)
from fractions import Fraction
from hashlib import sha256

from leviathan_core.numeric import NumericError, Ratio, quotient_final

from .events import (
    AdjustmentError,
    AdjustmentJournalEntryV1,
    AdjustmentPolicyV1,
    BookLevelV1,
    CorporateActionSnapshotV1,
    CorporateActionV1,
    EventClockError,
    EventValidationError,
    MarketEventV1,
    PrecisionExceededError,
)


def _arithmetic_context() -> Context:
    context = Context(prec=34, rounding=ROUND_HALF_EVEN, Emin=-38, Emax=38)
    for signal in (
        Clamped, DivisionByZero, FloatOperation, Inexact, InvalidOperation, Overflow,
        Subnormal, Underflow,
    ):
        context.traps[signal] = True
    return context


def canonical_decimal(
    value: object, field: str, error_type: type[EventClockError] = EventValidationError
) -> Decimal:
    """Normalize exact numeric value without consulting the caller's Decimal context."""
    if type(value) is not Decimal or not value.is_finite():
        raise error_type(f"{field} must be a finite Decimal")
    sign, digits, exponent = value.as_tuple()
    if not isinstance(exponent, int):
        raise error_type(f"{field} is not a finite Decimal")
    if not any(digits):
        return Decimal(0)
    if abs(value.adjusted()) > 38:
        raise error_type(f"{field} adjusted exponent is out of bounds")
    canonical_digits = list(digits)
    while len(canonical_digits) > 1 and canonical_digits[-1] == 0:
        canonical_digits.pop()
        exponent += 1
    if len(canonical_digits) > 34:
        raise PrecisionExceededError("PRECISION_EXCEEDED Decimal input")
    return Decimal((sign, tuple(canonical_digits), exponent))


def canonical_decimal_text(value: Decimal) -> str:
    return str(canonical_decimal(value, "decimal"))


def checked_arithmetic(
    left: Decimal, right: Decimal, operation: str, field: str
) -> Decimal:
    failure: str | None = None
    try:
        with localcontext(_arithmetic_context()):
            if operation == "multiply":
                result = left * right
            elif operation == "divide":
                result = left / right
            elif operation == "subtract":
                result = left - right
            else:
                raise AdjustmentError("unknown Decimal operation")
        return canonical_decimal(result, field, AdjustmentError)
    except Inexact:
        failure = "precision"
    except DecimalException:
        failure = "representation"
    if failure == "precision":
        raise PrecisionExceededError("PRECISION_EXCEEDED Decimal arithmetic") from None
    raise AdjustmentError(f"{field} cannot be represented in fixed Decimal context") from None


def _final_decimal(value: Fraction, field: str) -> Decimal:
    """Compose exactly, then perform only the final quotient conversion."""
    failure: str | None = None
    try:
        result = quotient_final(Ratio(value.numerator, value.denominator), 1)
    except NumericError as error:
        failure = error.code
    if failure == "PRECISION_EXCEEDED":
        raise PrecisionExceededError("PRECISION_EXCEEDED final adjustment") from None
    if failure is not None:
        raise AdjustmentError(f"{field} is outside final Decimal bounds") from None
    return canonical_decimal(result, field, AdjustmentError)


def _factor_value(value: Fraction) -> Decimal | Ratio:
    """Expose bounded Decimal factors, retaining an exact ratio when needed."""
    try:
        return _final_decimal(value, "factor")
    except AdjustmentError:
        return Ratio(value.numerator, value.denominator)


def _factor_text(value: Decimal | Ratio) -> str:
    if isinstance(value, Ratio):
        return f"{value.numerator}/{value.denominator}"
    return canonical_decimal_text(value)


def _positive(value: object, field: str) -> Decimal:
    decimal = canonical_decimal(value, field, AdjustmentError)
    if decimal <= 0:
        raise AdjustmentError(f"{field} must be positive")
    return decimal


def _day_utc(timestamp_ns: int) -> str:
    try:
        day = (date(1970, 1, 1) + timedelta(days=timestamp_ns // 86_400_000_000_000)).isoformat()
    except (OverflowError, ValueError):
        invalid = True
    else:
        invalid = False
    if invalid:
        raise AdjustmentError("action date is outside supported UTC range") from None
    return day


def validate_action(event: MarketEventV1, *, total_return: bool) -> CorporateActionV1:
    action = event.action
    if action is None or event.kind != "corporate_action":
        raise AdjustmentError("corporate action snapshot contains a non-action event")
    if (
        type(action.effective_ns) is not int
        or type(action.announced_ns) is not int
        or type(action.available_ns) is not int
        or action.effective_ns < 0
        or action.announced_ns < 0
        or action.available_ns < 0
    ):
        raise AdjustmentError("action times must be UTC nanosecond integers")
    if action.announced_ns > action.available_ns:
        raise AdjustmentError("action availability precedes announcement")
    if event.event_ns != action.effective_ns or event.available_ns != action.available_ns:
        raise AdjustmentError("action event times differ from its immutable payload")
    if action.action == "split":
        _positive(action.split_ratio, "split_ratio")
        if any(
            item is not None for item in (
                action.cash_amount, action.cash_currency, action.fx_rate, action.fx_pair,
                action.reference_price, action.price_currency,
            )
        ):
            raise AdjustmentError("split contains dividend-only fields")
    elif action.action == "dividend":
        _positive(action.cash_amount, "cash_amount")
        if not action.cash_currency or action.split_ratio is not None:
            raise AdjustmentError("dividend requires cash currency and no split ratio")
        if action.fx_rate is not None:
            _positive(action.fx_rate, "fx_rate")
        if action.reference_price is not None:
            _positive(action.reference_price, "reference_price")
        if total_return:
            rate = _positive(action.fx_rate, "fx_rate")
            _positive(action.reference_price, "reference_price")
            if not action.price_currency or action.fx_pair != (
                f"{action.cash_currency}/{action.price_currency}"
            ):
                raise AdjustmentError("dividend requires declared price currency and FX pair")
            if action.cash_currency == action.price_currency and rate != Decimal(1):
                raise AdjustmentError("same-currency dividend must declare FX rate 1")
    else:
        raise AdjustmentError("unknown corporate action")
    return action


@dataclass(frozen=True, slots=True)
class _Factor:
    price: Fraction
    size: Fraction


class AdjustmentEngine:
    """Back-adjust a run on the action snapshot known by its evaluation time."""

    def __init__(
        self,
        policy: AdjustmentPolicyV1,
        snapshot: CorporateActionSnapshotV1 | None,
        evaluation_ns: int,
    ) -> None:
        self.policy = policy
        self.snapshot = snapshot
        self.evaluation_ns = evaluation_ns
        self.journal: list[AdjustmentJournalEntryV1] = []
        self.journal_digest = sha256(b"").hexdigest()
        self._journal_keys: set[tuple[str, str, str]] = set()
        self._actions: dict[str, list[MarketEventV1]] = {}
        if snapshot is not None:
            for event in snapshot.actions:
                validate_action(event, total_return=policy.mode == "split_plus_dividend")
                self._actions.setdefault(event.instrument, []).append(event)
            for actions in self._actions.values():
                actions.sort(key=lambda item: (item.event_ns, item.source, item.source_id))

    @staticmethod
    def _factor(action: CorporateActionV1, mode: str) -> _Factor:
        if action.action == "split":
            ratio = _positive(action.split_ratio, "split_ratio")
            return _Factor(Fraction(1) / Fraction(ratio), Fraction(ratio))
        if mode == "split_plus_dividend":
            reference = _positive(action.reference_price, "reference_price")
            cash = _positive(action.cash_amount, "cash_amount")
            fx_rate = _positive(action.fx_rate, "fx_rate")
            net = Fraction(reference) - Fraction(cash) * Fraction(fx_rate)
            if net <= 0:
                raise AdjustmentError("dividend exceeds reference price")
            return _Factor(net / Fraction(reference), Fraction(1))
        return _Factor(Fraction(1), Fraction(1))

    def adjust(
        self, event: MarketEventV1
    ) -> tuple[
        Decimal | None, Decimal | None, Decimal | Ratio,
        tuple[BookLevelV1, ...], tuple[str, ...],
        tuple[Decimal | None, Decimal | None, Decimal | None, Decimal | None],
    ]:
        price_factor = Fraction(1)
        size_factor = Fraction(1)
        applied: list[str] = []
        pending_journal: list[tuple[MarketEventV1, _Factor]] = []
        if self.policy.mode != "raw":
            for action_event in self._actions.get(event.instrument, ()):
                action = action_event.action
                if action is None or action.effective_ns <= event.event_ns:
                    continue
                observation_ns = (
                    max(event.event_ns, event.available_ns)
                    if self.policy.view == "PIT" else self.evaluation_ns
                )
                if (
                    action_event.available_ns > observation_ns
                    or action.effective_ns > observation_ns
                ):
                    continue
                if action.action == "dividend" and self.policy.mode != "split_plus_dividend":
                    continue
                factor = self._factor(action, self.policy.mode)
                price_factor *= factor.price
                size_factor *= factor.size
                action_id = _action_identity(action_event)
                applied.append(action_id)
                pending_journal.append((action_event, factor))
        price = (
            _final_decimal(Fraction(event.price) * price_factor, "adjusted price")
            if event.price is not None else None
        )
        size = (
            _final_decimal(Fraction(event.size) * size_factor, "adjusted size")
            if event.size is not None else None
        )
        levels = tuple(
            BookLevelV1(
                level.side,
                _final_decimal(Fraction(level.price) * price_factor, "adjusted book price"),
                _final_decimal(Fraction(level.size) * size_factor, "adjusted book size"),
            ) for level in event.levels
        )
        quote_values: list[Decimal | None] = []
        for value, quote_factor in (
            (event.bid_price, price_factor), (event.bid_size, size_factor),
            (event.ask_price, price_factor), (event.ask_size, size_factor),
        ):
            quote_values.append(
                _final_decimal(Fraction(value) * quote_factor, "adjusted quote")
                if value is not None else None
            )
        for action_event, factor in pending_journal:
            self._journal(event, action_event, factor)
        return (
            price, size, _factor_value(price_factor), levels, tuple(applied),
            (quote_values[0], quote_values[1], quote_values[2], quote_values[3]),
        )

    def _journal(self, event: MarketEventV1, action_event: MarketEventV1, factor: _Factor) -> None:
        action = action_event.action
        if action is None:
            raise AdjustmentError("missing corporate action payload")
        day = _day_utc(event.event_ns)
        action_identity = _action_identity(action_event)
        key = (event.instrument, day, action_identity)
        if key in self._journal_keys:
            return
        self._journal_keys.add(key)
        entry = AdjustmentJournalEntryV1(
            event.instrument, day, action_event.source_id, action.action,
            action.effective_ns,
            _factor_value(factor.price), _factor_value(factor.size),
            self.policy.version, self.snapshot.snapshot_id if self.snapshot is not None else "",
            action_identity,
        )
        self.journal.append(entry)
        payload = json.dumps(
            [
                entry.instrument, entry.day_utc, entry.action_identity, entry.action,
                entry.activation_ns, _factor_text(entry.price_factor),
                _factor_text(entry.size_factor), entry.adjustment_version,
                entry.snapshot_id,
            ],
            ensure_ascii=True, separators=(",", ":"),
        ).encode("ascii")
        self.journal_digest = sha256(bytes.fromhex(self.journal_digest) + payload).hexdigest()


def _action_identity(event: MarketEventV1) -> str:
    return json.dumps(
        [event.source, event.source_id, event.correction_key],
        ensure_ascii=True, separators=(",", ":"),
    )
