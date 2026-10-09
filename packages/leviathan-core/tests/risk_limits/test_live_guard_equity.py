"""Focused RISK-003 checks for AV-EQUITY-001 evidence adoption."""

from __future__ import annotations

from dataclasses import replace
from decimal import Decimal
from pathlib import Path

import pytest
from test_live_guard_acceptance import (
    ACCOUNT,
    AS_OF_NS,
    BROKER,
    FRESH_NS,
    MAX_AGE_NS,
    _decision,
    _input,
)

from leviathan_core.execution.broker_port_v1 import (
    EquityEvidenceKindV1,
    _issue_account_view,
    _issue_equity_evidence,
)
from leviathan_core.execution.reconciliation import (
    LocalLedgerEvidenceV1,
    build_broker_snapshot,
    reconcile_account,
)
from leviathan_core.risk_limits.live_guard import (
    _unissued_equity_evidence_error,
    _validate_equity_evidence,
)


def _with_equity(
    value,
    *,
    currency: str = "USD",
    amount: Decimal = Decimal("100000"),
    kind: EquityEvidenceKindV1 = EquityEvidenceKindV1.NET_LIQUIDATION,
    observed_at_ns: int = FRESH_NS,
):
    previous = value.account_view
    equity = _issue_equity_evidence(
        currency,
        amount,
        kind,
        observed_at_ns,
        "synthetic-equity-adapter-v1",
    )
    account_view = _issue_account_view(
        previous.account_id,
        previous.open_orders,
        previous.positions,
        previous.broker_revision,
        previous.executions,
        previous.executions_since,
        complete=True,
        balances=previous.balances,
        broker_observed_at=previous.broker_observed_at,
        session_id=previous.session_id,
        equity=equity,
    )
    observed_at_ns = value.reconciliation.observed_at_ns
    snapshot = build_broker_snapshot(
        account_view,
        value.venue_identity,
        observed_at_ns=observed_at_ns,
    )
    ledger = LocalLedgerEvidenceV1(
        environment=value.reconciliation.environment,
        account_id=ACCOUNT,
        orders=(),
        executions=(),
        positions=(),
        ledger_revision=1,
        venue=BROKER,
        complete=True,
        balances=(("USD", Decimal("100000")),),
        previous_session_id="synthetic-session-003",
    )
    reconciliation = reconcile_account(
        snapshot,
        ledger,
        value.venue_identity,
        now_ns=AS_OF_NS,
        max_age_ns=MAX_AGE_NS,
    )
    return replace(value, account_view=account_view, reconciliation=reconciliation)


def _live_input(tmp_path: Path):
    return _input(
        tmp_path,
        environment="LIVE",
        live_switch_enabled=True,
        verified_balances=True,
    )


@pytest.mark.parametrize(
    "kind",
    [EquityEvidenceKindV1.NET_LIQUIDATION, EquityEvidenceKindV1.TOTAL_EQUITY],
)
def test_live_accepts_issued_base_currency_equity_matching_state_and_reconciliation(
    tmp_path: Path, kind: EquityEvidenceKindV1
) -> None:
    value = _with_equity(_live_input(tmp_path), kind=kind)

    # Current CL-RECON-SESSION leaves the integration's LIVE status gate
    # unverified. Exercise the equity predicate itself without changing that gate.
    assert _validate_equity_evidence(value, FRESH_NS) is None


@pytest.mark.parametrize(
    "change",
    [
        {"currency": "EUR"},
        {"observed_at_ns": FRESH_NS - 1},
    ],
)
def test_live_denies_equity_with_wrong_currency_or_observation_time(
    tmp_path: Path, change: dict[str, object]
) -> None:
    value = _with_equity(_live_input(tmp_path), **change)

    assert _validate_equity_evidence(value, FRESH_NS) == "EQUITY_EVIDENCE_UNAVAILABLE"


def test_live_denies_missing_equity_evidence(tmp_path: Path) -> None:
    # Use the existing account snapshot without an equity field.
    # The guard reaches reconciliation only when every surrounding LIVE input
    # gate is satisfied; _live_input creates that evidence bundle.
    value = _live_input(tmp_path)
    assert _validate_equity_evidence(value, FRESH_NS) == "EQUITY_EVIDENCE_UNAVAILABLE"


def test_live_denies_exact_equity_amount_disagreement(tmp_path: Path) -> None:
    value = _with_equity(_live_input(tmp_path), amount=Decimal("99999"))

    assert _validate_equity_evidence(value, FRESH_NS) == "EQUITY_MISMATCH"


def test_live_denies_tampered_equity_as_unavailable(tmp_path: Path) -> None:
    value = _with_equity(_live_input(tmp_path))
    object.__setattr__(value.account_view.equity, "amount", Decimal("99999"))

    assert _unissued_equity_evidence_error(value) == "EQUITY_EVIDENCE_UNAVAILABLE"
    result = _decision(value)
    assert result.decision == "DENY"
    assert result.reason_codes == ("EQUITY_EVIDENCE_UNAVAILABLE",)


def test_live_denies_unknown_equity_kind_as_unavailable(tmp_path: Path) -> None:
    value = _with_equity(_live_input(tmp_path))
    object.__setattr__(value.account_view.equity, "kind", "ACCOUNT_BALANCE")

    result = _decision(value)

    assert result.decision == "DENY"
    assert result.reason_codes == ("EQUITY_EVIDENCE_UNAVAILABLE",)


def test_live_public_guard_keeps_unverified_reconciliation_gate_first(
    tmp_path: Path,
) -> None:
    value = _live_input(tmp_path)

    result = _decision(value)

    assert result.decision == "DENY"
    assert result.reason_codes == ("ACCOUNT_V13_UNVERIFIED",)
