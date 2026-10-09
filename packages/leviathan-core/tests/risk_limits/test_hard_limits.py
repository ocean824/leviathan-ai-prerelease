"""Focused RISK-002 unit checks with synthetic policies and account state."""

from dataclasses import replace
from decimal import Decimal, Rounded, localcontext

import pytest

from leviathan_core.risk_limits import (
    DatedInstrumentV1,
    FxRateV1,
    HardLimitsV1,
    PolicyVerificationV1,
    PositionV1,
    ProjectedOrderV1,
    RiskStateV1,
    RollingRateCountV1,
    VerifiedHardLimitsV1,
    WorkingOrderV1,
    assess_limits,
    verify_hard_limits,
)

NOW = 10_000_000_000
D = Decimal


class _TestVerifier:
    def verify(
        self, policies: tuple[HardLimitsV1, ...], policy_digest: str
    ) -> PolicyVerificationV1:
        assert policies
        return PolicyVerificationV1("synthetic-test-verifier", "synthetic-key", policy_digest)


def _policy(**changes: object) -> HardLimitsV1:
    policy = HardLimitsV1(
        version=1,
        revision="account-1",
        environment="paper",
        account_id="acct-1",
        scope="ACCOUNT",
        effective_from_ns=NOW - 1_000,
        effective_until_ns=NOW + 1_000,
        limit_currency="USD",
        allowed_strategies=("strat-1",),
        allowed_venues=("venue-1",),
        allowed_instruments=(DatedInstrumentV1("ABC", NOW - 100, NOW + 100),),
        max_order_quantity="10",
        max_order_notional="1000",
        max_projected_position="10",
        max_gross_exposure="1000",
        max_net_exposure="1000",
        max_leverage="1",
        max_daily_loss="100",
        max_order_rate=5,
        order_rate_window_ns=1_000,
        max_data_age_ns=100,
    )
    return replace(policy, **changes)


def _order(**changes: object) -> ProjectedOrderV1:
    order = ProjectedOrderV1(
        environment="paper",
        account_id="acct-1",
        request_id="req-1",
        attempt_id="try-1",
        strategy_id="strat-1",
        venue_id="venue-1",
        instrument_id="ABC",
        side="BUY",
        quantity=D("10"),
        price=D("100"),
        contract_multiplier=D("1"),
        currency="USD",
        price_source_ns=NOW,
        price_ingest_ns=NOW,
        price_source_id="synthetic-price",
    )
    return replace(order, **changes)


def _state(**changes: object) -> RiskStateV1:
    state = RiskStateV1(
        environment="paper",
        account_id="acct-1",
        account_status="ACTIVE",
        source_ns=NOW,
        ingest_ns=NOW,
        last_committed_event_id="evt-1",
        base_currency="USD",
        equity=D("2000"),
        buying_power=D("2000"),
        equity_source_ns=NOW,
        equity_ingest_ns=NOW,
        realized_pnl=D("0"),
        unrealized_pnl=D("0"),
        positions=(),
        committed_orders=(),
        reserved_orders=(),
        fx_rates=(),
        rolling_rate_counts=(RollingRateCountV1(1_000, 0, NOW),),
    )
    return replace(state, **changes)


def _verified(*policies: HardLimitsV1) -> VerifiedHardLimitsV1:
    return verify_hard_limits(tuple(policies), _TestVerifier())


def test_exact_cap_passes_and_one_lot_above_denies_even_with_override_claims() -> None:
    envelope = _verified(_policy())
    allowed = assess_limits(_order(), envelope, _state(), NOW)
    assert allowed.decision == "ALLOW"
    assert allowed.reason_codes == ("within_hard_limits",)
    assert allowed.matched_policy_revisions == ("account-1",)
    assert len(allowed.evidence_digest) == 64

    above = _order(
        quantity=D("11"),
        override_token="untrusted",
        is_manual=True,
        role="ADMIN",
        agent_instruction="approve",
    )
    denied = assess_limits(above, envelope, _state(), NOW)
    assert denied.decision == "DENY"
    assert "max_order_quantity_exceeded" in denied.reason_codes


@pytest.mark.parametrize(
    "missing",
    [
        "max_order_quantity",
        "max_order_notional",
        "max_projected_position",
        "max_gross_exposure",
        "max_net_exposure",
        "max_leverage",
        "max_daily_loss",
        "max_order_rate",
        "order_rate_window_ns",
        "max_data_age_ns",
        "allowed_strategies",
        "allowed_venues",
        "allowed_instruments",
    ],
)
def test_absent_account_cap_or_allowlist_denies(missing: str) -> None:
    with pytest.raises(ValueError, match="POLICY_INCOMPLETE"):
        _policy(**{missing: None})


def test_ambient_rounded_trap_cannot_deny_display_only_leverage() -> None:
    envelope = _verified(_policy())
    with localcontext() as ambient:
        ambient.traps[Rounded] = True
        verdict = assess_limits(
            _order(quantity=D("1"), price=D("1")),
            envelope,
            _state(equity=D("3"), buying_power=D("3")),
            NOW,
        )
    assert verdict.decision == "ALLOW"


def test_optional_scopes_only_narrow_and_policy_input_order_is_canonical() -> None:
    account = _policy(
        max_order_quantity="100",
        max_order_notional="10000",
        max_projected_position="100",
        max_gross_exposure="10000",
        max_net_exposure="10000",
    )
    wildcard = replace(
        account,
        revision="wildcard",
        scope="INSTRUMENT",
        instrument_id="*",
        allowed_strategies=None,
        allowed_venues=None,
        allowed_instruments=None,
        max_order_quantity="20",
    )
    exact = replace(wildcard, revision="exact", instrument_id="ABC", max_order_quantity="9")
    first = assess_limits(_order(), _verified(account, wildcard, exact), _state(), NOW)
    second = assess_limits(_order(), _verified(exact, account, wildcard), _state(), NOW)
    assert first.decision == "DENY"
    assert "max_order_quantity_exceeded" in first.reason_codes
    assert first.evidence_digest == second.evidence_digest


def test_open_orders_count_in_worst_case_position_and_gross() -> None:
    existing = WorkingOrderV1(
        request_id="req-old",
        attempt_id="try-old",
        instrument_id="ABC",
        side="BUY",
        quantity=D("6"),
        price=D("100"),
        contract_multiplier=D("1"),
        currency="USD",
        price_source_ns=NOW,
        price_ingest_ns=NOW,
        price_source_id="synthetic-price",
    )
    state = _state(committed_orders=(existing,))
    verdict = assess_limits(_order(), _verified(_policy()), state, NOW)
    assert verdict.decision == "DENY"
    assert "max_projected_position_exceeded" in verdict.reason_codes
    assert "max_gross_exposure_exceeded" in verdict.reason_codes


def test_stale_equity_missing_fx_and_rate_count_fail_closed() -> None:
    assert assess_limits(
        _order(), _verified(_policy()), _state(equity_source_ns=NOW - 101), NOW
    ).reason_codes == ("state_stale",)
    euro_order = _order(currency="EUR")
    assert assess_limits(euro_order, _verified(_policy()), _state(), NOW).reason_codes == (
        "fx_missing",
    )
    fx = FxRateV1("EUR", "USD", D("1.1"), NOW - 101, NOW, "synthetic-fx")
    assert assess_limits(
        euro_order, _verified(_policy()), _state(fx_rates=(fx,)), NOW
    ).reason_codes == ("fx_stale",)
    assert assess_limits(
        _order(), _verified(_policy()), _state(rolling_rate_counts=()), NOW
    ).reason_codes == ("rate_state_missing",)


def test_plain_or_forged_envelope_and_mismatched_verifier_digest_deny() -> None:
    with pytest.raises(TypeError):
        VerifiedHardLimitsV1()  # type: ignore[call-arg]
    forged = object.__new__(VerifiedHardLimitsV1)
    assert assess_limits(_order(), forged, _state(), NOW).reason_codes == ("policy_unverified",)

    class WrongDigest:
        def verify(
            self, policies: tuple[HardLimitsV1, ...], policy_digest: str
        ) -> PolicyVerificationV1:
            return PolicyVerificationV1("synthetic", "key", "0" * 64)

    with pytest.raises(ValueError, match="verification failed"):
        verify_hard_limits((_policy(),), WrongDigest())


def test_decimal_precision_at_exact_boundary_and_one_smallest_unit() -> None:
    tiny = D("0.0000000000000000000000001")
    policy = _policy(
        max_order_quantity="1.0000000000000000000000001",
        max_order_notional="1000",
        max_projected_position="10",
    )
    with localcontext() as context:
        context.prec = 128
        exact = _order(quantity=D("1") + tiny)
        above = replace(exact, quantity=exact.quantity + tiny)
    envelope = _verified(policy)
    assert assess_limits(exact, envelope, _state(), NOW).decision == "ALLOW"
    assert (
        "max_order_quantity_exceeded" in assess_limits(above, envelope, _state(), NOW).reason_codes
    )


def test_existing_position_and_sell_commitment_use_worst_case_endpoint() -> None:
    position = PositionV1("ABC", D("-5"), D("100"), D("1"), "USD", NOW, NOW, "synthetic-price")
    sell = WorkingOrderV1(
        "req-old",
        "try-old",
        "ABC",
        "SELL",
        D("6"),
        D("100"),
        D("1"),
        "USD",
        NOW,
        NOW,
        "synthetic-price",
    )
    verdict = assess_limits(
        _order(quantity=D("1")),
        _verified(_policy()),
        _state(positions=(position,), reserved_orders=(sell,)),
        NOW,
    )
    assert verdict.decision == "DENY"
    assert "max_projected_position_exceeded" in verdict.reason_codes


def test_evidence_digest_binds_full_provenance_even_when_totals_match() -> None:
    envelope = _verified(_policy())
    baseline = assess_limits(_order(), envelope, _state(), NOW)
    changed_state = assess_limits(_order(), envelope, _state(source_ns=NOW - 1), NOW)
    changed_order = assess_limits(
        _order(price_source_id="second-synthetic-price"), envelope, _state(), NOW
    )
    assert baseline.decision == changed_state.decision == changed_order.decision == "ALLOW"
    assert (
        baseline.projected_values
        == changed_state.projected_values
        == changed_order.projected_values
    )
    assert (
        len(
            {baseline.evidence_digest, changed_state.evidence_digest, changed_order.evidence_digest}
        )
        == 3
    )
