"""Independent acceptance tests for RISK-003 aggregate equity evidence."""

from __future__ import annotations

from dataclasses import replace
from decimal import Decimal
from pathlib import Path
from runpy import run_path

import pytest
from test_live_guard_acceptance import (
    ACCOUNT,
    AS_OF_NS,
    BROKER,
    MAX_AGE_NS,
)
from test_live_guard_acceptance import (
    _input as _baseline_input,
)

from leviathan_core.execution.broker_port import FakeBrokerPort
from leviathan_core.execution.broker_port_v1 import (
    BrokerEnvironment,
    EquityEvidenceKindV1,
    EquityEvidenceV1,
    _issue_account_view,
    _issue_equity_evidence,
)
from leviathan_core.execution.broker_reconciliation import FakeBrokerReconciliation
from leviathan_core.execution.reconciliation import (
    LocalLedgerEvidenceV1,
    VerificationStatus,
    build_broker_snapshot,
    reconcile_account,
)
from leviathan_core.risk_limits.live_guard import (
    validate_live_guard,
)

issue_verified_session_start_anchor = run_path(
    str(Path(__file__).resolve().parents[1] / "execution" / "session_anchor_support.py")
)["issue_verified_session_start_anchor"]


def _fake_equity(account_id: str = ACCOUNT) -> EquityEvidenceV1:
    """Use the deterministic paper broker's declared aggregate equity value."""
    broker = FakeBrokerPort(FakeBrokerReconciliation(), account_id=account_id)
    view = broker.read_account_view(account_id)
    assert view.equity is not None
    assert view.equity.amount == Decimal("100000")
    return view.equity


def _issue_test_equity(
    value,
    *,
    kind: EquityEvidenceKindV1 = EquityEvidenceKindV1.TOTAL_EQUITY,
    currency: str = "USD",
    amount: Decimal | None = None,
    observed_at_ns: int | None = None,
) -> EquityEvidenceV1:
    fake_equity = _fake_equity(value.account_view.account_id)
    return _issue_equity_evidence(
        currency,
        fake_equity.amount if amount is None else amount,
        kind,
        value.reconciliation.observed_at_ns if observed_at_ns is None else observed_at_ns,
        fake_equity.semantics_declared_by,
    )


def _input_with_equity(tmp_path: Path, equity: EquityEvidenceV1 | None):
    """Rebuild the sealed account/reconciliation pair with the supplied evidence."""
    value = _baseline_input(
        tmp_path,
        environment="LIVE",
        live_switch_enabled=True,
        verified_balances=True,
    )
    prior_view = value.account_view
    account_view = _issue_account_view(
        prior_view.account_id,
        prior_view.open_orders,
        prior_view.positions,
        prior_view.broker_revision,
        prior_view.executions,
        prior_view.executions_since,
        complete=True,
        balances=prior_view.balances,
        broker_observed_at=prior_view.broker_observed_at,
        session_id=prior_view.session_id,
        equity=equity,
    )
    observed_at_ns = value.reconciliation.observed_at_ns
    snapshot = build_broker_snapshot(
        account_view,
        value.venue_identity,
        observed_at_ns=observed_at_ns,
    )
    ledger = LocalLedgerEvidenceV1(
        environment=BrokerEnvironment.LIVE,
        account_id=prior_view.account_id,
        orders=(),
        executions=(),
        positions=(),
        ledger_revision=1,
        venue=BROKER,
        complete=True,
        balances=(("USD", Decimal("100000")),),
        previous_session_id=prior_view.session_id,
    )
    session_start_anchor = issue_verified_session_start_anchor(
        BrokerEnvironment.LIVE,
        prior_view.account_id,
        BROKER,
        prior_view.session_id,
    )
    reconciliation = reconcile_account(
        snapshot,
        ledger,
        value.venue_identity,
        now_ns=AS_OF_NS,
        max_age_ns=MAX_AGE_NS,
        session_start_anchor=session_start_anchor,
    )
    return replace(value, account_view=account_view, reconciliation=reconciliation)


def _decide(value):
    return validate_live_guard(value, clock_ns=lambda: AS_OF_NS)


@pytest.mark.parametrize(
    "kind",
    [EquityEvidenceKindV1.NET_LIQUIDATION, EquityEvidenceKindV1.TOTAL_EQUITY],
)
def test_issued_exact_base_currency_equity_allows_with_verified_reconciliation(
    tmp_path: Path, kind: EquityEvidenceKindV1
) -> None:
    baseline = _baseline_input(
        tmp_path,
        environment="LIVE",
        live_switch_enabled=True,
        verified_balances=True,
    )
    equity = _issue_test_equity(baseline, kind=kind)
    value = _input_with_equity(tmp_path, equity)

    equity.assert_sealed()
    assert equity.currency == value.state.base_currency == "USD"
    assert equity.amount == value.state.equity == Decimal("100000")
    assert equity.broker_observed_at_ns == value.reconciliation.observed_at_ns
    assert value.state.equity_source_ns == value.reconciliation.observed_at_ns
    assert value.reconciliation.balances_status is VerificationStatus.VERIFIED
    assert value.reconciliation.session_status is VerificationStatus.VERIFIED
    assert value.reconciliation.balances_status is VerificationStatus.VERIFIED

    decision = _decide(value)
    assert decision.decision == "ALLOW"
    assert decision.reason_codes == ("ELIGIBLE",)


@pytest.mark.parametrize(
    "invalidity",
    ["wrong-currency", "observation-time", "unknown-kind", "unissued"],
)
def test_invalid_equity_evidence_is_unavailable(tmp_path: Path, invalidity: str) -> None:
    baseline = _baseline_input(
        tmp_path,
        environment="LIVE",
        live_switch_enabled=True,
        verified_balances=True,
    )
    if invalidity == "wrong-currency":
        equity = _issue_test_equity(baseline, currency="EUR")
    elif invalidity == "observation-time":
        equity = _issue_test_equity(
            baseline,
            observed_at_ns=baseline.reconciliation.observed_at_ns - 1,
        )
    else:
        equity = _issue_test_equity(baseline)

    value = _input_with_equity(tmp_path, equity)
    if invalidity == "unknown-kind":
        object.__setattr__(value.account_view.equity, "kind", "UNRECOGNIZED")
    elif invalidity == "unissued":
        object.__setattr__(
            value.account_view.equity,
            "semantics_declared_by",
            "tampered-after-issue",
        )

    decision = _decide(value)
    assert decision.decision == "DENY"
    assert decision.reason_codes == ("EQUITY_EVIDENCE_UNAVAILABLE",)


def test_absent_equity_is_unavailable_for_live(tmp_path: Path) -> None:
    value = _input_with_equity(tmp_path, None)
    assert value.account_view.equity is None
    assert value.reconciliation.session_status is VerificationStatus.VERIFIED
    decision = _decide(value)
    assert decision.decision == "DENY"
    assert decision.reason_codes == ("EQUITY_EVIDENCE_UNAVAILABLE",)


def test_live_unverified_reconciliation_still_denies_before_equity_gate(
    tmp_path: Path,
) -> None:
    value = _baseline_input(
        tmp_path,
        environment="LIVE",
        live_switch_enabled=True,
        verified_balances=True,
    )

    assert value.reconciliation.balances_status is VerificationStatus.VERIFIED
    assert value.reconciliation.session_status is VerificationStatus.UNVERIFIED
    decision = _decide(value)
    assert decision.decision == "DENY"
    assert decision.reason_codes == ("ACCOUNT_V13_UNVERIFIED",)


def test_exact_amount_disagreement_is_equity_mismatch(tmp_path: Path) -> None:
    baseline = _baseline_input(
        tmp_path,
        environment="LIVE",
        live_switch_enabled=True,
        verified_balances=True,
    )
    equity = _issue_test_equity(baseline, amount=Decimal("100000.01"))
    value = _input_with_equity(tmp_path, equity)

    decision = _decide(value)
    assert decision.decision == "DENY"
    assert decision.reason_codes == ("EQUITY_MISMATCH",)


@pytest.mark.parametrize("environment", ["PAPER", "DEMO"])
def test_paper_and_demo_remain_eligible_without_equity_evidence(
    tmp_path: Path, environment: str
) -> None:
    value = _baseline_input(tmp_path, environment=environment)

    assert value.account_view.equity is None
    decision = _decide(value)
    assert decision.decision == "ALLOW"
    assert decision.reason_codes == ("ELIGIBLE",)
