"""Independent synthetic-only contract tests for the RISK-003 live guard."""

from __future__ import annotations

import hashlib
import inspect
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from pathlib import Path

import pytest

from leviathan_core.execution.broker_port_v1 import (
    BrokerEnvironment,
    BrokerVenue,
    _issue_account_view,
    _issue_balance,
    _issue_venue_identity,
)
from leviathan_core.execution.reconciliation import (
    LocalLedgerEvidenceV1,
    VerificationStatus,
    build_broker_snapshot,
    reconcile_account,
)
from leviathan_core.risk.halt import HaltAuthority
from leviathan_core.risk.halt_store import (
    HaltStore,
    ProfileClassification,
    ProfileEvidence,
    ProvisionResult,
)
from leviathan_core.risk.policy import load_risk_policy
from leviathan_core.risk.route_guard import RouteGuard
from leviathan_core.risk_limits.kernel import verify_hard_limits
from leviathan_core.risk_limits.live_guard import (
    LiveGuardDecisionV1,
    _equity_evidence_error,
    _verification_statuses_allow,
    validate_live_guard,
)
from leviathan_core.risk_limits.live_models import LiveGuardInputV1, LiveGuardPolicyV1
from leviathan_core.risk_limits.models import (
    DatedInstrumentV1,
    HardLimitsV1,
    PolicyVerificationV1,
    ProjectedOrderV1,
    RiskStateV1,
    RollingRateCountV1,
)
from leviathan_core.risk_limits.sizing_models import (
    CorrelationClusterV1,
    EquitySnapshotV1,
    PayoffEstimateV1,
    SizingEvidenceV1,
    SizingPolicyV1,
)
from leviathan_core.schemas.risk import KillState, RequiredStream, RiskGateContext, StreamFreshness
from leviathan_market_data.live.models import _issue_verdict
from leviathan_vault.client import VaultStatus
from leviathan_vault.trading_bindings import BindingRequestV1, TradingAccountBindingV1

ACCOUNT = "synthetic-risk-account-003"
STRATEGY = "synthetic-risk-strategy"
VENUE = "SYNTHETIC_VENUE"
INSTRUMENT = "SYNTH-003"
REVISION = "synthetic-hard-limits-v1"
BROKER = BrokerVenue.IBKR_TWS
AT = datetime(2026, 10, 6, 15, 0, tzinfo=UTC)
EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
AS_OF_NS = int((AT - EPOCH).total_seconds()) * 1_000_000_000
FRESH_NS = AS_OF_NS - 1_000_000_000
MAX_AGE_NS = 300_000_000_000
STREAM = ("synthetic-md", "quotes", VENUE, INSTRUMENT, "top", "session-003")
HEDGE = ("synthetic-md", "quotes", VENUE, "SYNTH-HEDGE-003", "top", "session-003")
ROOT = Path(__file__).resolve().parents[4]
RISK_LOCK = ROOT / "tests" / "fixtures" / "risk_lock" / "risk_governance.lock.yaml"


class _TestOnlyVerifier:
    """A local verifier for synthetic policy fixtures; never used by production."""

    def verify(
        self, policies: tuple[HardLimitsV1, ...], policy_digest: str
    ) -> PolicyVerificationV1:
        assert policies
        return PolicyVerificationV1(
            verifier_id="synthetic-risk003-verifier",
            key_id="synthetic-risk003-key",
            policy_digest=policy_digest,
        )


def _broker_env(environment: str) -> BrokerEnvironment:
    return {
        "PAPER": BrokerEnvironment.PAPER,
        "DEMO": BrokerEnvironment.DEMO,
        "LIVE": BrokerEnvironment.LIVE,
    }[environment]


def _halt_store(tmp_path: Path, *, active: bool = False) -> HaltStore:
    data_root = tmp_path / f"halt-root-{len(tuple(tmp_path.glob('halt-root-*')))}"
    data_root.mkdir()
    path = data_root / "risk003-halt.sqlite3"
    evidence = ProfileEvidence(
        ProfileClassification.NEVER_PROVISIONED,
        verified=True,
        references=("synthetic:halt-profile-metadata",),
    )
    assert HaltStore.provision_new(path, data_root, evidence) is ProvisionResult.CREATED
    store = HaltStore(path, data_root)
    if active:
        HaltAuthority(store).engage("synthetic-review-halt")
    return store


def _hard_limits(environment: str, *, revision: str = REVISION) -> object:
    policy = HardLimitsV1(
        version=1,
        revision=revision,
        environment=environment.lower(),
        account_id=ACCOUNT,
        scope="ACCOUNT",
        effective_from_ns=0,
        effective_until_ns=AS_OF_NS + 100_000_000_000,
        limit_currency="USD",
        allowed_strategies=(STRATEGY,),
        allowed_venues=(VENUE,),
        allowed_instruments=(
            DatedInstrumentV1(INSTRUMENT, 0, AS_OF_NS + 100_000_000_000),
        ),
        max_order_quantity="10",
        max_order_notional="10000",
        max_projected_position="10",
        max_gross_exposure="1000000",
        max_net_exposure="1000000",
        max_leverage="10",
        max_daily_loss="100000",
        max_order_rate=10,
        order_rate_window_ns=60_000_000_000,
        max_data_age_ns=MAX_AGE_NS,
    )
    return verify_hard_limits((policy,), _TestOnlyVerifier())


def _order(environment: str) -> ProjectedOrderV1:
    return ProjectedOrderV1(
        environment=environment.lower(),
        account_id=ACCOUNT,
        request_id="synthetic-request-003",
        attempt_id="synthetic-attempt-003",
        strategy_id=STRATEGY,
        venue_id=VENUE,
        instrument_id=INSTRUMENT,
        side="BUY",
        quantity=Decimal("1"),
        price=Decimal("10"),
        contract_multiplier=Decimal("1"),
        currency="USD",
        price_source_ns=FRESH_NS,
        price_ingest_ns=AS_OF_NS - 500_000_000,
        price_source_id="synthetic-price-003",
    )


def _state(environment: str, *, equity_source_ns: int = FRESH_NS) -> RiskStateV1:
    return RiskStateV1(
        environment=environment.lower(),
        account_id=ACCOUNT,
        account_status="ACTIVE",
        source_ns=FRESH_NS,
        ingest_ns=AS_OF_NS - 500_000_000,
        last_committed_event_id="synthetic-state-event-003",
        base_currency="USD",
        equity=Decimal("100000"),
        buying_power=Decimal("100000"),
        equity_source_ns=equity_source_ns,
        equity_ingest_ns=AS_OF_NS - 500_000_000,
        realized_pnl=Decimal("0"),
        unrealized_pnl=Decimal("0"),
        positions=(),
        committed_orders=(),
        reserved_orders=(),
        fx_rates=(),
        rolling_rate_counts=(RollingRateCountV1(60_000_000_000, 0, AS_OF_NS),),
    )


def _sizing(
    order: ProjectedOrderV1,
    state: RiskStateV1,
    *,
    equity_event_ns: int = FRESH_NS,
    equity_received_ns: int = AS_OF_NS - 500_000_000,
) -> SizingEvidenceV1:
    return SizingEvidenceV1(
        order=order,
        state=state,
        equity=EquitySnapshotV1(
            account_id=ACCOUNT,
            state_event_id="synthetic-state-event-003",
            broker_source_id="synthetic-broker-003",
            equity=Decimal("100000"),
            buying_power=Decimal("100000"),
            event_ns=equity_event_ns,
            received_ns=equity_received_ns,
        ),
        payoff=PayoffEstimateV1(
            strategy_id=STRATEGY,
            win_probability=Decimal("0.6"),
            win_payoff=Decimal("1"),
            loss_payoff=Decimal("1"),
            sample_count=100,
            uncertainty_fraction=Decimal("0"),
            source_id="synthetic-payoff-003",
            revision="synthetic-payoff-v1",
            event_ns=FRESH_NS,
            received_ns=AS_OF_NS - 500_000_000,
            validation_status="VALIDATED",
        ),
        correlations=(
            CorrelationClusterV1(
                instrument_id=INSTRUMENT,
                cluster_id="synthetic-cluster-003",
                source_id="synthetic-correlation-003",
                revision="synthetic-correlation-v1",
                event_ns=FRESH_NS,
                received_ns=AS_OF_NS - 500_000_000,
                validation_status="VALIDATED",
            ),
        ),
        policy=SizingPolicyV1(
            revision="synthetic-sizing-v1",
            account_id=ACCOUNT,
            strategy_id=STRATEGY,
            effective_from_ns=0,
            effective_until_ns=AS_OF_NS + 100_000_000_000,
            kelly_fraction_cap=Decimal("0.5"),
            portfolio_heat_fraction_cap=Decimal("0.5"),
            cluster_heat_fraction_cap=Decimal("0.5"),
            lot_step=Decimal("1"),
        ),
        stops=None,
    )


def _account_and_reconciliation(
    environment: str,
    *,
    observed_at_ns: int = FRESH_NS,
    account_id: str = ACCOUNT,
    verified_balances: bool = False,
):
    env = _broker_env(environment)
    broker_time = EPOCH + timedelta(microseconds=observed_at_ns // 1_000)
    account_view = _issue_account_view(
        account_id,
        (),
        (),
        7,
        (),
        AT - timedelta(minutes=5),
        complete=True,
        balances=(
            (_issue_balance("USD", Decimal("100000")),) if verified_balances else None
        ),
        broker_observed_at=broker_time,
        session_id="synthetic-session-003",
    )
    venue_identity = _issue_venue_identity(BROKER, env, account_id)
    snapshot = build_broker_snapshot(account_view, venue_identity, observed_at_ns=observed_at_ns)
    ledger = LocalLedgerEvidenceV1(
        environment=env,
        account_id=account_id,
        orders=(),
        executions=(),
        positions=(),
        ledger_revision=1,
        venue=BROKER,
        complete=True,
        balances=(
            (("USD", Decimal("100000")),) if verified_balances else None
        ),
        previous_session_id=("synthetic-session-003" if verified_balances else None),
    )
    reconciliation = reconcile_account(
        snapshot,
        ledger,
        venue_identity,
        now_ns=AS_OF_NS,
        max_age_ns=MAX_AGE_NS,
    )
    return account_view, venue_identity, reconciliation


def _binding(environment: str, *, can_read: bool = True, account_ref: str | None = None):
    env = "live" if environment == "LIVE" else "development"
    mode = environment.lower()
    account_ref = account_ref or "synthetic-broker-account-003"
    session_ref = "synthetic-broker-session-003"
    credential_name = "IBKR_TWS_LIVE" if environment == "LIVE" else "IBKR_TWS_PAPER"
    credential_ref = f"vault://leviathan-ai/{env}/{credential_name}"
    binding = TradingAccountBindingV1(
        project_id="leviathan-ai",
        environment=env,
        broker=BROKER.value,
        adapter_protocol="tws-gateway",
        adapter_version="synthetic-v1",
        account_ref=account_ref,
        session_ref=session_ref,
        venue_allowlist=(VENUE,),
        instrument_allowlist=(INSTRUMENT,),
        instrument_mapping_revision="synthetic-map-v1",
        instrument_mapping_date=date(2026, 10, 1),
        strategy_allowlist=(STRATEGY,),
        hard_risk_limit_revision=REVISION,
        session_mode=mode,
        credential_ref=credential_ref,
        can_read=can_read,
        can_submit=False,
    )
    request = BindingRequestV1(
        environment=env,
        broker=BROKER.value,
        account_ref=account_ref,
        session_ref=session_ref,
        venue=VENUE,
        instrument=INSTRUMENT,
        instrument_mapping_revision="synthetic-map-v1",
        strategy_id=STRATEGY,
        hard_risk_limit_revision=REVISION,
        session_mode=mode,
        binding_revision=1,
        credential_revision=1,
        checked_at=AT,
        want_submit=False,
    )
    status = VaultStatus(
        name=credential_name,
        scope="leviathan-ai",
        environment=env,
    )
    return binding, request, status


def _route_evidence():
    lock = RISK_LOCK.read_bytes()
    policy = load_risk_policy(RISK_LOCK)
    stream = RequiredStream(stream_id="bars.1m", symbol=INSTRUMENT, provider="synthetic-md")
    context = RiskGateContext(
        as_of=AT,
        required=(stream,),
        observed=(
            StreamFreshness(
                stream_id=stream.stream_id,
                symbol=stream.symbol,
                provider=stream.provider,
                source_ts=AT,
                exchange_ts=AT,
                received_at=AT,
            ),
        ),
        kill=KillState(),
        max_staleness_ms=300_000,
        max_clock_skew_ms=10,
    )
    return RouteGuard(RISK_LOCK, hashlib.sha256(lock).hexdigest()), policy, context


def _verdict(
    key=STREAM,
    *,
    evaluated_ns: int = FRESH_NS,
    state: str = "HEALTHY",
    node_drift_ms: Decimal = Decimal("0"),
):
    return _issue_verdict(
        stream_key=key,
        state=state,
        evaluated_utc_ns=evaluated_ns,
        publication_allowed=True,
        execution_eligible=False,
        heartbeat_age_ns=AS_OF_NS - evaluated_ns,
        node_drift_ms=node_drift_ms,
        reason_codes=(),
    )


def _input(
    tmp_path: Path,
    *,
    environment: str = "PAPER",
    live_switch_enabled: bool = False,
    stream_keys: tuple[tuple[str, str, str, str, str, str], ...] = (STREAM,),
    verdicts=None,
    halt_active: bool = False,
    account_age_ns: int = FRESH_NS,
    equity_age_ns: int = FRESH_NS,
    account_id: str = ACCOUNT,
    policy_revision: str = REVISION,
    policy_environment: str | None = None,
    route_manual: bool = False,
    agent_role: str | None = None,
    verified_balances: bool = False,
) -> LiveGuardInputV1:
    policy = LiveGuardPolicyV1(
        account_id=ACCOUNT,
        environment=environment,
        policy_revision=policy_revision,
        venue_id=VENUE,
        strategy_id=STRATEGY,
        instrument_id=INSTRUMENT,
        broker_venue=BROKER,
        required_stream_keys=stream_keys,
        live_switch_enabled=live_switch_enabled,
        max_account_age_ns=MAX_AGE_NS,
        max_equity_age_ns=MAX_AGE_NS,
        max_stream_age_ns=MAX_AGE_NS,
        max_clock_skew_ns=10_000_000,
    )
    order = _order(environment)
    if route_manual or agent_role is not None:
        order = replace(order, is_manual=route_manual, role=agent_role)
    state = _state(environment, equity_source_ns=equity_age_ns)
    account_view, venue_identity, reconciliation = _account_and_reconciliation(
        environment,
        observed_at_ns=account_age_ns,
        account_id=account_id,
        verified_balances=verified_balances,
    )
    binding, binding_request, credential_status = _binding(environment)
    route_guard, route_policy, route_context = _route_evidence()
    return LiveGuardInputV1(
        policy=policy,
        order=order,
        state=state,
        hard_limits=_hard_limits(policy_environment or environment),
        sizing_evidence=_sizing(
            order,
            state,
            equity_event_ns=state.equity_source_ns,
            equity_received_ns=state.equity_ingest_ns,
        ),
        account_view=account_view,
        venue_identity=venue_identity,
        reconciliation=reconciliation,
        market_verdicts=tuple(verdicts if verdicts is not None else (_verdict(),)),
        binding=binding,
        binding_request=binding_request,
        credential_status=credential_status,
        halt_store=_halt_store(tmp_path, active=halt_active),
        route_guard=route_guard,
        route_policy=route_policy,
        route_context=route_context,
    )


def _decision(
    value: LiveGuardInputV1, *, clock_ns: Callable[[], int] = lambda: AS_OF_NS
) -> LiveGuardDecisionV1:
    result = validate_live_guard(value, clock_ns=clock_ns)
    assert type(result) is LiveGuardDecisionV1
    return result


@pytest.mark.parametrize("environment", ["PAPER", "DEMO"])
def test_fresh_injected_non_live_evidence_is_eligible_but_never_activates_or_dispatches(
    tmp_path: Path, environment: str
) -> None:
    result = _decision(_input(tmp_path, environment=environment))

    assert result.decision == "ALLOW"
    assert result.reason_codes == ("ELIGIBLE",)
    assert result.evidence_digest
    assert not hasattr(result, "dispatch")
    assert not hasattr(result, "activation")


def test_live_never_promotes_current_unverified_v13_reconciliation(tmp_path: Path) -> None:
    value = _input(tmp_path, environment="LIVE", live_switch_enabled=True)

    assert value.reconciliation.balances_status is VerificationStatus.UNVERIFIED
    result = _decision(value)
    assert result.decision == "DENY"
    assert result.reason_codes == ("ACCOUNT_V13_UNVERIFIED",)


def test_live_requires_both_exact_verified_reconciliation_statuses() -> None:
    assert _verification_statuses_allow(
        "LIVE", VerificationStatus.VERIFIED, VerificationStatus.VERIFIED
    )
    assert not _verification_statuses_allow(
        "LIVE", VerificationStatus.UNVERIFIED, VerificationStatus.VERIFIED
    )
    assert not _verification_statuses_allow(
        "LIVE", VerificationStatus.VERIFIED, VerificationStatus.UNVERIFIED
    )
    assert not _verification_statuses_allow(
        "LIVE", VerificationStatus.UNVERIFIED, VerificationStatus.UNVERIFIED
    )


def test_live_has_no_total_equity_semantics_for_per_currency_balances() -> None:
    assert _equity_evidence_error("LIVE") == "EQUITY_EVIDENCE_UNAVAILABLE"
    assert _equity_evidence_error("PAPER") is None
    assert _equity_evidence_error("DEMO") is None


def test_real_cl_recon_verified_balances_with_unverified_session_still_deny_live(
    tmp_path: Path,
) -> None:
    value = _input(
        tmp_path,
        environment="LIVE",
        live_switch_enabled=True,
        verified_balances=True,
    )

    assert value.reconciliation.balances_status is VerificationStatus.VERIFIED
    assert value.reconciliation.session_status is VerificationStatus.UNVERIFIED
    result = _decision(value)
    assert result.decision == "DENY"
    assert result.reason_codes == ("ACCOUNT_V13_UNVERIFIED",)


def test_disabled_live_switch_and_active_halt_are_independent_denials(tmp_path: Path) -> None:
    switch_off = _decision(_input(tmp_path, environment="LIVE", live_switch_enabled=False))
    assert switch_off.decision == "DENY"
    assert switch_off.reason_codes == ("LIVE_SWITCH_DISABLED",)

    halted = _decision(_input(tmp_path, halt_active=True))
    assert halted.decision == "DENY"
    assert halted.reason_codes == ("HALT_ACTIVE_OR_UNKNOWN",)


@pytest.mark.parametrize(
    ("verdicts", "expected"),
    [
        ((), "STREAM_EVIDENCE_DENIED"),
        ((_verdict(key=HEDGE),), "STREAM_EVIDENCE_DENIED"),
        ((_verdict(evaluated_ns=FRESH_NS - MAX_AGE_NS - 1),), "STREAM_EVIDENCE_DENIED"),
        ((_verdict(state="UNKNOWN"),), "STREAM_EVIDENCE_DENIED"),
        ((_verdict(state="DEGRADED"),), "STREAM_EVIDENCE_DENIED"),
        ((_verdict(node_drift_ms=Decimal("10.001")),), "STREAM_EVIDENCE_DENIED"),
    ],
)
def test_missing_unknown_and_stale_streams_deny(
    tmp_path: Path, verdicts, expected: str
) -> None:
    assert _decision(_input(tmp_path, verdicts=verdicts)).reason_codes == (expected,)


def test_policy_requires_explicit_exact_non_wildcard_stream_coverage() -> None:
    with pytest.raises(ValueError):
        LiveGuardPolicyV1(
            account_id=ACCOUNT,
            environment="PAPER",
            policy_revision=REVISION,
            venue_id=VENUE,
            strategy_id=STRATEGY,
            instrument_id=INSTRUMENT,
            broker_venue=BROKER,
            required_stream_keys=(("synthetic-md", "quotes", VENUE, "*", "top", "session-003"),),
            live_switch_enabled=False,
            max_account_age_ns=MAX_AGE_NS,
            max_equity_age_ns=MAX_AGE_NS,
            max_stream_age_ns=MAX_AGE_NS,
            max_clock_skew_ns=10_000_000,
        )


def test_unknown_account_and_mismatched_injected_policy_deny(tmp_path: Path) -> None:
    wrong_account = _decision(_input(tmp_path, account_id="synthetic-other-account"))
    assert wrong_account.decision == "DENY"
    assert wrong_account.reason_codes == ("ACCOUNT_SCOPE_MISMATCH",)

    wrong_policy = _decision(_input(tmp_path, policy_environment="demo"))
    assert wrong_policy.decision == "DENY"
    assert wrong_policy.reason_codes == ("HARD_POLICY_MISMATCH",)


def test_substituted_guard_policy_account_or_revision_denies_before_route_gate(
    tmp_path: Path,
) -> None:
    value = _input(tmp_path)
    wrong_account_policy = replace(value.policy, account_id="synthetic-substitute-account")
    wrong_account = _decision(replace(value, policy=wrong_account_policy))
    assert wrong_account.decision == "DENY"
    assert wrong_account.reason_codes == ("ACCOUNT_SCOPE_MISMATCH",)

    wrong_revision_value = replace(
        value,
        hard_limits=_hard_limits("PAPER", revision="substituted-revision"),
        route_guard=object(),
        route_policy=object(),
        route_context=object(),
    )
    wrong_revision = _decision(wrong_revision_value)
    assert wrong_revision.decision == "DENY"
    assert wrong_revision.reason_codes == ("HARD_POLICY_MISMATCH",)
    assert not hasattr(wrong_revision, "permit")
    assert not hasattr(wrong_revision, "dispatch")


def test_canonical_halt_denies_before_downstream_route_checks(tmp_path: Path) -> None:
    value = _input(tmp_path, halt_active=True)
    result = _decision(
        replace(value, route_guard=object(), route_policy=object(), route_context=object())
    )
    assert result.decision == "DENY"
    assert result.reason_codes == ("HALT_ACTIVE_OR_UNKNOWN",)
    assert not hasattr(result, "permit")


def test_unavailable_empty_halt_store_fails_closed_without_a_permit(tmp_path: Path) -> None:
    value = _input(tmp_path)
    store = value.halt_store
    store.close()
    store.path.unlink()

    result = _decision(value)
    assert result.decision == "DENY"
    assert result.reason_codes == ("EVIDENCE_INVALID",)
    assert not hasattr(result, "permit")


def test_stale_account_observation_denies_at_strict_boundary(tmp_path: Path) -> None:
    stale_ns = FRESH_NS - MAX_AGE_NS - 1
    result = _decision(_input(tmp_path, account_age_ns=stale_ns))
    assert result.decision == "DENY"
    assert result.reason_codes == ("ACCOUNT_RECONCILIATION_DENIED",)


def test_replayed_bundle_denies_under_trusted_clock_and_has_no_caller_as_of(
    tmp_path: Path,
) -> None:
    assert "as_of_ns" not in inspect.signature(LiveGuardInputV1).parameters
    assert "as_of_ns" not in inspect.signature(validate_live_guard).parameters

    value = _input(tmp_path)
    assert not hasattr(value, "as_of_ns")
    three_days_later = AS_OF_NS + 3 * 24 * 60 * 60 * 1_000_000_000
    result = _decision(value, clock_ns=lambda: three_days_later)
    assert result.decision == "DENY"
    assert result.reason_codes != ("ELIGIBLE",)


def test_stale_equity_snapshot_denies(tmp_path: Path) -> None:
    result = _decision(
        _input(tmp_path, equity_age_ns=FRESH_NS - MAX_AGE_NS - 1)
    )
    assert result.decision == "DENY"
    assert result.reason_codes == ("ACCOUNT_EQUITY_STALE",)


def test_equity_source_timestamp_must_match_broker_observation(tmp_path: Path) -> None:
    value = _input(tmp_path)
    mismatched_state = replace(value.state, equity_source_ns=FRESH_NS - 1)
    result = _decision(replace(value, state=mismatched_state))
    assert result.decision == "DENY"
    assert result.reason_codes == ("ACCOUNT_EQUITY_STALE",)


def test_reconcile_digest_must_match_the_recomputed_account_view_snapshot(
    tmp_path: Path,
) -> None:
    value = _input(tmp_path)
    view = value.account_view
    substituted_view = _issue_account_view(
        view.account_id,
        view.open_orders,
        view.positions,
        view.broker_revision + 1,
        view.executions,
        view.executions_since,
        complete=True,
        balances=view.balances,
        broker_observed_at=view.broker_observed_at,
        session_id=view.session_id,
    )
    result = _decision(replace(value, account_view=substituted_view))
    assert result.decision == "DENY"
    assert result.reason_codes == ("ACCOUNT_SNAPSHOT_MISMATCH",)


def test_exact_300_second_equity_observation_boundary_is_fresh(tmp_path: Path) -> None:
    boundary_ns = AS_OF_NS - MAX_AGE_NS
    result = _decision(
        _input(
            tmp_path,
            account_age_ns=boundary_ns,
            equity_age_ns=boundary_ns,
        )
    )
    assert result.decision == "ALLOW"
    assert result.reason_codes == ("ELIGIBLE",)


def test_equity_observation_one_nanosecond_over_limit_uses_equity_stale_reason(
    tmp_path: Path,
) -> None:
    over_boundary_ns = AS_OF_NS - MAX_AGE_NS - 1
    result = _decision(
        _input(
            tmp_path,
            account_age_ns=over_boundary_ns,
            equity_age_ns=over_boundary_ns,
        )
    )
    assert result.decision == "DENY"
    assert result.reason_codes == ("ACCOUNT_EQUITY_STALE",)


@pytest.mark.parametrize(
    ("route_manual", "agent_role", "expected"),
    [
        (True, None, "MANUAL_ROUTE_DENIED"),
        (False, "agent", "AGENT_ROUTE_DENIED"),
    ],
)
def test_manual_or_agent_instruction_route_cannot_become_eligible(
    tmp_path: Path, route_manual: bool, agent_role: str | None, expected: str
) -> None:
    result = _decision(
        _input(tmp_path, route_manual=route_manual, agent_role=agent_role)
    )
    assert result.decision == "DENY"
    assert result.reason_codes == (expected,)
