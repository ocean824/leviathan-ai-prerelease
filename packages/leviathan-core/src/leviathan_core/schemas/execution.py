"""ExecutionIntent — Execution Layer contract.

The trade plan routed into paper simulation or live execution.
Execution may not create its own thesis: an intent must reference an
approved DecisionPacket and the frozen RiskSnapshot it was authorized
under (enforced in leviathan_core.contracts).
"""

from decimal import Decimal

from pydantic import Field

from leviathan_core.schemas.base import LeviathanModel
from leviathan_core.schemas.enums import BrokerPath, OrderType, TimeInForce


class ExecutionIntent(LeviathanModel):
    decision_id: str
    risk_session_id: str = Field(
        description="session_id of the frozen RiskSnapshot this intent was authorized under."
    )
    broker_path: BrokerPath
    order_type: OrderType
    size: Decimal = Field(gt=0)
    stop_loss: Decimal = Field(gt=0)
    take_profit: Decimal = Field(gt=0)
    time_in_force: TimeInForce
