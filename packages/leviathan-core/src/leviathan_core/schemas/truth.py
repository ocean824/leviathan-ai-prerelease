"""TruthValidationResult — Truth Domain contract.

Confirmation or rejection from order-flow, options, event-risk, and
sentiment layers. Sentiment is a bounded modifier: it may tilt, never
override, order-book truth.
"""

import math
from decimal import Decimal

from pydantic import Field, field_validator

from leviathan_core.numeric import parse_decimal
from leviathan_core.numeric.errors import NumericError
from leviathan_core.schemas.base import LeviathanModel
from leviathan_core.schemas.enums import EventRisk, OrderbookBias, TruthStatus


class TruthValidationResult(LeviathanModel):
    setup_id: str
    orderbook_bias: OrderbookBias
    options_context: str
    event_risk: EventRisk
    sentiment_modifier: Decimal = Field(ge=Decimal("-0.25"), le=Decimal("0.25"))
    truth_status: TruthStatus
    notes: str = ""

    @field_validator("sentiment_modifier", mode="before")
    @classmethod
    def _validate_sentiment_modifier(cls, value: object) -> Decimal:
        # Preserve legacy JSON-number inputs while keeping the model value exact.
        if type(value) is float:
            if not math.isfinite(value):
                raise ValueError("sentiment_modifier must be finite")
            value = str(value)
        try:
            return parse_decimal(
                value,
                field="sentiment_modifier",
                min_value=Decimal("-0.25"),
                max_value=Decimal("0.25"),
            )
        except NumericError as exc:
            raise ValueError("sentiment_modifier is not a bounded exact decimal") from exc
