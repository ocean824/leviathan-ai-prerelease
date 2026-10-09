"""TradeJournalRecord — Memory / Review contract.

The replayable post-trade record. Every completed trade must end in a
journal record, and every BLOCKED trade must still be journaled —
blocked outcomes carry no entry/exit but preserve the decision trail.
"""

from decimal import Decimal
from typing import Any

from pydantic import model_validator

from leviathan_core.schemas.base import LeviathanModel
from leviathan_core.schemas.enums import TradeOutcome
from leviathan_core.seal import Issuer, SealError
from leviathan_core.seal import require as _require_sealed


class TradeJournalRecord(LeviathanModel):
    trade_id: str
    setup_id: str
    decision_id: str
    entry: Decimal | None = None
    exit: Decimal | None = None
    mae: Decimal | None = None
    mfe: Decimal | None = None
    outcome: TradeOutcome
    post_trade_notes: str = ""

    def __init__(self, **data: Any) -> None:
        _reject_issued_reinitialization(self)
        super().__init__(**data)

    @model_validator(mode="after")
    def _executed_trades_carry_prices(self) -> "TradeJournalRecord":
        if self.outcome is not TradeOutcome.BLOCKED and (self.entry is None or self.exit is None):
            raise ValueError("non-blocked outcomes require entry and exit prices")
        return self


_TRADE_JOURNAL_ISSUER = Issuer("c101.trade_journal_record.v1")


def _reject_issued_reinitialization(value: object) -> None:
    try:
        _require_sealed(value, _TRADE_JOURNAL_ISSUER.tag)
    except SealError as exc:
        if exc.args == ("SEAL_NOT_ISSUED",):
            return
        raise SealError("SEAL_FORBIDDEN_OPERATION") from None
    raise SealError("SEAL_FORBIDDEN_OPERATION")


def _issue_trade_journal_record(value: TradeJournalRecord) -> TradeJournalRecord:
    """Issue a journal record at the C-101 pipeline boundary."""
    if type(value) is not TradeJournalRecord:
        raise SealError("SEAL_INVALID_MODEL")
    if _TRADE_JOURNAL_ISSUER.issued_here(value):
        return value
    return _TRADE_JOURNAL_ISSUER.issue(value)


def require_trade_journal_record(value: object) -> TradeJournalRecord:
    """Require an exact, unmodified journal record issued by this kernel."""
    if type(value) is not TradeJournalRecord:
        raise SealError("SEAL_INVALID_MODEL")
    return _require_sealed(value, _TRADE_JOURNAL_ISSUER.tag)
