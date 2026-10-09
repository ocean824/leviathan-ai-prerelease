"""The numeric kernel's independent Decimal context."""

from decimal import ROUND_HALF_EVEN, Context, DivisionByZero, Inexact, InvalidOperation, Overflow


def numeric_context(*, final_quotient: bool = False) -> Context:
    """Return a fresh context, unaffected by a caller's ambient settings."""
    traps = [Overflow, InvalidOperation, DivisionByZero]
    if not final_quotient:
        traps.append(Inexact)
    return Context(prec=34, rounding=ROUND_HALF_EVEN, Emin=-38, Emax=38, traps=traps)
