"""Independent cycle-1 acceptance for the predicate-only LIVE dispatch gate."""

from __future__ import annotations

from datetime import date
from decimal import Decimal
from types import SimpleNamespace
from typing import Any, cast

import pytest

from leviathan_api.routers.orders import (
    LiveSubmitCandidateV1,
    OrderRuntime,
    _evaluate_dispatch,
)
from leviathan_api.state import AppState
from leviathan_core.execution.broker_port_v1 import BrokerVenue
from leviathan_core.execution.oms import OrderGatewayActor
from leviathan_core.execution.order_models import OrderRequest, OrderSnapshot, OrderState
from leviathan_vault.trading_bindings import TradingAccountBindingV1

ACCOUNT = "acceptance-live-account"
VENUE = BrokerVenue.ALPACA.value
INSTRUMENT = "NQ-202612"
STRATEGY = "acceptance-live-strategy"


class _Gate:
    def __init__(self, result: object = True, *, raises: bool = False) -> None:
        self.result = result
        self.raises = raises
        self.calls: list[str] = []

    def live_account_enabled(self, account_id: str) -> bool:
        self.calls.append(account_id)
        if self.raises:
            raise RuntimeError("synthetic gate failure")
        return cast(bool, self.result)


class _RecordingProvider:
    def __init__(self) -> None:
        self.submits: list[LiveSubmitCandidateV1] = []

    def dispatch(self, candidate: LiveSubmitCandidateV1) -> None:
        self.submits.append(candidate)


def _live_binding() -> TradingAccountBindingV1:
    return TradingAccountBindingV1(
        project_id="leviathan-ai",
        environment="live",
        broker="ALPACA",
        adapter_protocol="acceptance-fake",
        adapter_version="1",
        account_ref=ACCOUNT,
        session_ref="acceptance-live-session",
        venue_allowlist=(VENUE,),
        instrument_allowlist=(INSTRUMENT,),
        instrument_mapping_revision="mapping-v1",
        instrument_mapping_date=date(2026, 10, 1),
        strategy_allowlist=(STRATEGY,),
        hard_risk_limit_revision="risk-v1",
        session_mode="live",
        operator_session_required=True,
    )


def _paper_binding() -> TradingAccountBindingV1:
    return TradingAccountBindingV1(
        project_id="leviathan-ai",
        environment="development",
        broker="ALPACA",
        adapter_protocol="acceptance-paper-fake",
        adapter_version="1",
        account_ref="acceptance-paper-account",
        session_ref="acceptance-paper-session",
        venue_allowlist=(VENUE,),
        instrument_allowlist=(INSTRUMENT,),
        instrument_mapping_revision="mapping-v1",
        instrument_mapping_date=date(2026, 10, 1),
        strategy_allowlist=("acceptance-paper-strategy",),
        hard_risk_limit_revision="risk-v1",
        session_mode="paper",
        operator_session_required=True,
    )


def _runtime(
    monkeypatch: pytest.MonkeyPatch,
    *,
    gate: _Gate | None,
    recovery_status: str = "READY",
    halted: bool = False,
) -> tuple[OrderRuntime, AppState, list[tuple[str, str, str, str, str]]]:
    # This contract slice tests the authorization predicate itself. The unrelated
    # actor/configuration precondition is held true; there is no real broker.
    monkeypatch.setattr(OrderRuntime, "configured", property(lambda _self: True))
    binding = _live_binding()
    binding_calls: list[tuple[str, str, str, str, str]] = []

    def binding_source(scope: tuple[str, str, str, str, str]) -> TradingAccountBindingV1 | None:
        binding_calls.append(scope)
        expected = ("live", ACCOUNT, VENUE, INSTRUMENT, STRATEGY)
        return binding if scope == expected else None

    runtime = OrderRuntime(
        actor=cast(OrderGatewayActor, object()),
        bindings=(_paper_binding(),),
        credential_statuses={},
        native_contracts={(VENUE, INSTRUMENT): "acceptance-contract"},
        operator_authorizer=lambda _request: True,
        evidence_source=lambda _snapshot: cast(Any, None),
        live_gate=gate,
        binding_source=binding_source,
    )
    runtime.recovery_status = recovery_status
    state = cast(
        AppState,
        SimpleNamespace(
            halts=SimpleNamespace(fault_code=None, halted=halted),
            killed_providers=set(),
        ),
    )
    return runtime, state, binding_calls


def _candidate() -> LiveSubmitCandidateV1:
    return LiveSubmitCandidateV1(
        account_id=ACCOUNT,
        venue=VENUE,
        instrument_id=INSTRUMENT,
        strategy_id=STRATEGY,
    )


def _submit(
    runtime: OrderRuntime,
    state: AppState,
    provider: _RecordingProvider,
) -> str:
    candidate = _candidate()
    decision = _evaluate_dispatch(runtime, state, "SUBMIT", candidate)
    if decision == "ALLOW":
        provider.dispatch(candidate)
    return decision


def test_valid_live_gate_binding_and_ready_recovery_reach_only_fake_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gate = _Gate(True)
    runtime, state, binding_calls = _runtime(monkeypatch, gate=gate)
    provider = _RecordingProvider()

    assert _submit(runtime, state, provider) == "ALLOW"
    assert gate.calls == [ACCOUNT]
    assert len(binding_calls) == 1
    assert len(provider.submits) == 1


def test_missing_gate_denies_before_binding_or_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    missing_runtime, state, missing_binding_calls = _runtime(monkeypatch, gate=None)
    missing_provider = _RecordingProvider()
    assert _submit(missing_runtime, state, missing_provider) == "DENY_SCOPE"
    assert missing_binding_calls == []
    assert missing_provider.submits == []


def test_false_gate_denies_before_binding_or_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    false_gate = _Gate(False)
    false_runtime, false_state, false_binding_calls = _runtime(monkeypatch, gate=false_gate)
    false_provider = _RecordingProvider()
    assert _submit(false_runtime, false_state, false_provider) == "DENY_SCOPE"
    assert false_gate.calls == [ACCOUNT]
    assert false_binding_calls == []
    assert false_provider.submits == []


def test_halt_with_true_gate_denies_before_gate_binding_or_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gate = _Gate(True)
    runtime, state, binding_calls = _runtime(monkeypatch, gate=gate, halted=True)
    provider = _RecordingProvider()

    assert _submit(runtime, state, provider) == "DENY_HALT"
    assert gate.calls == []
    assert binding_calls == []
    assert provider.submits == []


def test_raising_gate_fails_closed_without_binding_or_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gate = _Gate(True, raises=True)
    runtime, state, binding_calls = _runtime(monkeypatch, gate=gate)
    provider = _RecordingProvider()

    assert _submit(runtime, state, provider) == "DENY_SCOPE"
    assert gate.calls == [ACCOUNT]
    assert binding_calls == []
    assert provider.submits == []


def test_live_recovery_unknown_denies_even_with_true_gate_and_valid_binding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gate = _Gate(True)
    runtime, state, binding_calls = _runtime(
        monkeypatch,
        gate=gate,
        recovery_status="UNKNOWN",
    )
    provider = _RecordingProvider()

    assert _submit(runtime, state, provider) == "DENY_SCOPE"
    assert gate.calls == [ACCOUNT]
    assert binding_calls == []
    assert provider.submits == []


def test_paper_cancel_does_not_consult_or_depend_on_live_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gate = _Gate(False, raises=True)
    runtime, state, _ = _runtime(monkeypatch, gate=gate, recovery_status="UNKNOWN")
    paper = _paper_binding()
    request = OrderRequest(
        project_id="leviathan-ai",
        environment="paper",
        account_id=paper.account_ref,
        venue=VENUE,
        instrument_id=INSTRUMENT,
        native_contract_id="acceptance-paper-contract",
        side="BUY",
        quantity=Decimal("1"),
        order_type="LIMIT",
        time_in_force="DAY",
        client_order_id=None,
        intent_idempotency_key="acceptance-paper-cancel",
        attempt=1,
        strategy_id="acceptance-paper-strategy",
        risk_policy_digest="b" * 64,
        actor_id="acceptance-paper-operator",
        capability="paper-submit",
        limit_price=Decimal("100"),
    )
    snapshot = OrderSnapshot(
        order_id="acceptance-paper-order",
        request=request,
        state=OrderState.WORKING,
        version=1,
        venue_order_id="paper-venue-order",
        filled_quantity=Decimal("0"),
        discrepancies=(),
        submit_attempted=True,
        cancel_attempted=False,
    )

    assert _evaluate_dispatch(runtime, state, "CANCEL", snapshot) == "ALLOW"
    assert gate.calls == []
