"""DecisionPacket — Decision Domain contract.

Encodes the system's approved, rejected, or deferred decision. The
Decision Domain may not ignore Truth status; that rule is enforced in
leviathan_core.contracts.
"""

import math
from decimal import Decimal

from pydantic import Field, field_validator

from leviathan_core.numeric import parse_decimal
from leviathan_core.numeric.errors import NumericError
from leviathan_core.schemas.base import LeviathanModel
from leviathan_core.schemas.enums import Direction, Permission


class DecisionPacket(LeviathanModel):
    decision_id: str
    setup_id: str
    permission: Permission
    direction: Direction
    confidence: Decimal = Field(ge=Decimal("0"), le=Decimal("1"))
    entry_style: str
    scaling_allowed: bool
    justification: str

    @field_validator("confidence", mode="before")
    @classmethod
    def _validate_confidence(cls, value: object) -> Decimal:
        # JSON fixtures historically encode this field as a JSON number. Convert
        # finite legacy floats through their shortest decimal spelling before
        # applying NUM-001; never import the binary float expansion.
        if type(value) is float:
            if not math.isfinite(value):
                raise ValueError("confidence must be finite")
            value = str(value)
        try:
            return parse_decimal(
                value, field="confidence", min_value=Decimal("0"), max_value=Decimal("1")
            )
        except NumericError as exc:
            raise ValueError("confidence is not a bounded exact decimal") from exc
