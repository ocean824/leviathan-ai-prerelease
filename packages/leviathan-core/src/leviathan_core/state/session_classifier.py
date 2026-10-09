"""Session classification — time-of-day as a first-class edge (MERMAID).

Windows are defined in UTC against standard futures/FX session structure.
Session quality scores encode the doctrine: NY overlap is prime,
midday is dead-time where breakout quality collapses.
"""

import math
from datetime import UTC, datetime, time
from decimal import Decimal

from pydantic import Field, field_validator

from leviathan_core.numeric import parse_decimal
from leviathan_core.numeric.errors import NumericError
from leviathan_core.schemas import SessionLabel
from leviathan_core.schemas.base import LeviathanModel

# (start_inclusive, end_exclusive, label, quality 0..1) in UTC.
_WINDOWS: tuple[tuple[time, time, SessionLabel, Decimal], ...] = (
    (time(0, 0), time(7, 0), SessionLabel.ASIAN, Decimal("0.45")),
    (time(7, 0), time(9, 0), SessionLabel.LONDON_OPEN, Decimal("0.85")),
    (time(9, 0), time(12, 30), SessionLabel.LONDON_CONTINUATION, Decimal("0.65")),
    (time(12, 30), time(14, 30), SessionLabel.NY_OPEN, Decimal("0.90")),
    (time(14, 30), time(16, 0), SessionLabel.NY_OVERLAP, Decimal("1.00")),
    (time(16, 0), time(18, 30), SessionLabel.NY_MIDDAY, Decimal("0.35")),
    (time(18, 30), time(21, 0), SessionLabel.NY_CLOSE, Decimal("0.60")),
    (time(21, 0), time(23, 59, 59, 999999), SessionLabel.ROLLOVER, Decimal("0.20")),
)


class SessionContext(LeviathanModel):
    label: SessionLabel
    quality: Decimal = Field(ge=Decimal("0"), le=Decimal("1"))
    is_dead_time: bool

    @field_validator("quality", mode="before")
    @classmethod
    def _validate_quality(cls, value: object) -> Decimal:
        if type(value) is float:
            if not math.isfinite(value):
                raise ValueError("quality must be finite")
            value = str(value)
        try:
            return parse_decimal(
                value, field="quality", min_value=Decimal("0"), max_value=Decimal("1")
            )
        except NumericError as exc:
            raise ValueError("quality is not a bounded exact decimal") from exc


def classify_session(at: datetime) -> SessionContext:
    if at.tzinfo is None:
        raise ValueError("session classification requires a tz-aware datetime")
    probe = at.astimezone(UTC).time()
    for start, end, label, quality in _WINDOWS:
        if start <= probe < end:
            return SessionContext(
                label=label, quality=quality, is_dead_time=quality < Decimal("0.4")
            )
    quality = Decimal("0.20")
    return SessionContext(label=SessionLabel.ROLLOVER, quality=quality, is_dead_time=True)
