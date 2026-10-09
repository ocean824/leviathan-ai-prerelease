"""Explicit LIVE request construction stays outside untrusted payload parsing."""

from __future__ import annotations

from decimal import Decimal
from typing import Any

import pytest

from leviathan_core.execution.order_models import OMSValidationError, OrderRequest


def _values() -> dict[str, Any]:
    return {
        "project_id": "leviathan-ai",
        "environment": "live",
        "account_id": "live-account-1",
        "venue": "ALPACA",
        "instrument_id": "NQ-202612",
        "native_contract_id": "contract-1",
        "side": "BUY",
        "quantity": Decimal("1"),
        "order_type": "LIMIT",
        "time_in_force": "DAY",
        "client_order_id": None,
        "intent_idempotency_key": "live-intent-1",
        "attempt": 1,
        "strategy_id": "strategy-1",
        "risk_policy_digest": "a" * 64,
        "actor_id": "operator-1",
        "capability": "live-submit",
        "limit_price": Decimal("100"),
    }


def test_default_and_persisted_request_construction_reject_live() -> None:
    values = _values()
    with pytest.raises(OMSValidationError) as exc_info:
        OrderRequest(**values)
    assert exc_info.value.code == "NON_LIVE_SCOPE_REQUIRED"

    with pytest.raises(OMSValidationError) as stored_error:
        OrderRequest.from_payload({key: str(value) for key, value in values.items()})
    assert stored_error.value.code == "NON_LIVE_SCOPE_REQUIRED"

    with pytest.raises(TypeError):
        OrderRequest(**values, _live_activation=True)  # type: ignore[call-arg]


def test_explicit_activation_factory_constructs_non_wire_live_request() -> None:
    request = OrderRequest._from_live_activation(**_values())

    assert request.environment == "live"
    assert request.payload()["environment"] == "live"
    assert "_live_activation" not in request.payload()
    request.__post_init__()
