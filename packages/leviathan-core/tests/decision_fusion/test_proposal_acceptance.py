"""Independent contract acceptance tests for decision composition and replay."""

from __future__ import annotations

import copy
import hashlib
import json
import pickle
import subprocess
import sys
from dataclasses import FrozenInstanceError, fields, replace
from datetime import UTC, datetime
from decimal import Decimal, localcontext
from pathlib import Path
from typing import Any

import pytest

from leviathan_core.decision_fusion.models import FeatureAttributionV1, FusionResultV1
from leviathan_core.decision_fusion.proposal import (
    DecisionAction,
    DecisionContextV1,
    DecisionFrozenError,
    DecisionIdentityV1,
    DecisionInputError,
    DecisionInputLinkV1,
    DecisionPolicyV1,
    DecisionReason,
    DecisionStatus,
    _issue_link_from_verified_sources,
    compose,
)
from leviathan_core.decision_fusion.replay import DecisionFixtureV1, replay
from leviathan_core.feature_store.models import FeatureLineageV1, FeatureResultV1
from leviathan_core.numeric import exact_add, exact_mul
from leviathan_core.portfolio.models import (
    ExposureSnapshotV1 as SizingExposureSnapshotV1,
)
from leviathan_core.portfolio.models import (
    HardCapsV1,
    SizingResultV1,
    SizingStatus,
)
from leviathan_core.portfolio.overlap import PortfolioCheckV1, PortfolioStatus
from leviathan_core.truth.verdict.models import TruthSource, TruthVerdictV1, Verdict

D = Decimal
D1 = Decimal("1")
D0 = Decimal("0")
D_TENTH = Decimal("0.1")
NOW_NS = 1_000_000_000
H = "a" * 64
STAGES = (
    "BINDINGS",
    "FUSION",
    "FEATURE_TRUTH",
    "PORTFOLIO",
    "SIZING",
    "GUARDS",
    "ACTION",
    "MODE",
)
HERE = Path(__file__).parent
PINS = json.loads((HERE / "fixtures" / "proposal" / "replay_fixture_pins.json").read_text())


def _caps(**overrides: Decimal) -> HardCapsV1:
    values = {
        "per_symbol_notional": D("1000"),
        "per_sector_notional": D("1000"),
        "gross_notional": D("2000"),
        "net_notional": D("2000"),
        "max_leverage": D("2"),
        "per_trade_loss": D("100"),
        "portfolio_heat": D("100"),
    }
    values.update(overrides)
    return HardCapsV1(**values)


def _bundle(
    *,
    fusion_status: str = "CAPITAL_CANDIDATE",
    fusion_evaluation_ns: int = NOW_NS,
    sizing_status: SizingStatus = SizingStatus.SIZE,
    quantity: Decimal = D1,
    sizing_exposures: SizingExposureSnapshotV1 | None = None,
    portfolio_status: PortfolioStatus = PortfolioStatus.PASS,
    portfolio_max_corr: Decimal | None = D_TENTH,
    feature_found: bool = True,
    feature_hash: str | None = H,
    feature_asof_ns: int = NOW_NS,
    feature_event_ns: int | None = NOW_NS,
    feature_available_ns: int | None = NOW_NS,
    truth_verdict: Verdict = Verdict.PASS,
    truth_hash: str = H,
    identity_truth_hash: str = H,
    truth_evaluation_ns: int = NOW_NS,
    policy_caps: HardCapsV1 | None = None,
    policy_values: dict[str, Any] | None = None,
    context_values: dict[str, Any] | None = None,
) -> tuple[FusionResultV1, SizingResultV1, PortfolioCheckV1, DecisionContextV1]:
    attributions = tuple(
        FeatureAttributionV1(feature=f"feature-{index}", contribution=f"0.{index}")
        for index in range(1, 8)
    )
    fusion = FusionResultV1(
        status=fusion_status,
        idempotency_check="NOT_PERFORMED",
        reason_codes=() if fusion_status == "CAPITAL_CANDIDATE" else ("BELOW_THRESHOLD",),
        layer_verdicts=(),
        layer_scores=(),
        attributions=attributions,
        rationale="synthetic four-layer candidate",
        evaluation_ns=fusion_evaluation_ns,
        input_hash=H,
        policy_hash=H,
        idempotency_key=H,
    )
    effective_context = context_values or {}
    current_quantity = effective_context.get("current_quantity", D(0))
    side = effective_context.get("side", "BUY")
    price = effective_context.get("price", D("100"))
    contract_multiplier = effective_context.get("contract_multiplier", D(1))
    signed_quantity = quantity if side == "BUY" else exact_mul(quantity, D(-1))
    target_quantity = exact_add(current_quantity, signed_quantity)
    target_net_notional = exact_mul(
        exact_mul(target_quantity, price), contract_multiplier
    )
    target_gross_notional = target_net_notional.copy_abs()
    exposures = sizing_exposures or SizingExposureSnapshotV1(
        symbol_notional=target_gross_notional,
        sector_notional=target_gross_notional,
        gross_notional=target_gross_notional,
        net_notional=target_net_notional,
        leverage=exact_mul(target_gross_notional, D("0.001")),
        projected_worst_case_loss=D("10"),
        portfolio_heat=D("10"),
    )
    sizing = SizingResultV1(
        status=sizing_status,
        proposed_quantity=quantity,
        unclamped_quantity=quantity,
        reasons=(),
        cap_hits=(),
        exposures=exposures,
        input_hash=H,
        policy_hash=H,
        as_of_age_ns=0,
        calculation_trace=(),
    )
    portfolio = PortfolioCheckV1(
        status=portfolio_status,
        overlap_pairs=(),
        correlation_pairs=(),
        breaches=(),
        assumptions=(),
        symbol_exposures=(),
        sector_exposures=(),
        gross_notional=target_gross_notional,
        net_notional=target_net_notional,
        net_gamma=D(0),
        heat=D(10),
        max_offdiag=portfolio_max_corr,
        input_hash=H,
        policy_hash=H,
        trace=(),
    )
    identity = DecisionIdentityV1(
        tenant_id="synthetic-tenant",
        strategy_revision_hash="b" * 64,
        portfolio_revision_hash="c" * 64,
        symbol="SYNTH",
        evaluation_ns=NOW_NS,
        window_id="window-1",
        feature_snapshot_hash=H,
        truth_hash=identity_truth_hash,
    )
    feature = FeatureResultV1(
        found=feature_found,
        feature_name="signal",
        feature_version="v1",
        instrument_id="SYNTH",
        asof_ns=feature_asof_ns,
        value_decimal=D(1) if feature_found else None,
        event_time_ns=feature_event_ns,
        availability_ns=feature_available_ns,
        definition_hash=H,
        observation_hash=feature_hash if feature_found else None,
        lineage=FeatureLineageV1(
            definition_sha256=H,
            observation_sha256=feature_hash if feature_found else None,
        ),
    )
    truth_seconds, truth_remainder = divmod(truth_evaluation_ns, 1_000_000_000)
    truth = TruthVerdictV1(
        verdict=truth_verdict,
        reason_codes=(),
        data_freshness_ms={source: None for source in TruthSource},
        source_timestamps={source: None for source in TruthSource},
        evaluation_ts=datetime.fromtimestamp(truth_seconds, tz=UTC).replace(
            microsecond=truth_remainder // 1000
        ),
        policy_id="truth-policy",
        policy_version="v1",
        trace_id="synthetic-trace",
        hash_id=truth_hash,
    )
    caps = policy_caps or _caps()
    policy_data: dict[str, Any] = {
        "policy_id": "decision-policy-v1",
        "policy_version": "v1",
        "max_metric_age_ns": 100,
        "min_volatility": D("0.1"),
        "max_volatility": D("0.5"),
        "max_correlation": D("0.8"),
        "max_position_quantity": D("10"),
        "hard_caps": caps,
        "live_fallback": "BLOCK",
        "long_enabled": True,
        "short_enabled": True,
        "fifo_netting_supported": True,
    }
    if policy_values:
        policy_data.update(policy_values)
    policy = DecisionPolicyV1(**policy_data)

    fusion_link, sizing_link, portfolio_link = _issue_link_from_verified_sources(
        identity, fusion, sizing, portfolio
    )

    context_data: dict[str, Any] = {
        "identity": identity,
        "fusion_link": fusion_link,
        "sizing_link": sizing_link,
        "portfolio_link": portfolio_link,
        "feature": feature,
        "truth": truth,
        "policy": policy,
        "side": "BUY",
        "current_quantity": D(0),
        "price": D(100),
        "contract_multiplier": D(1),
        "lot_step": D(1),
        "min_notional": D(100),
        "rolling_volatility": D("0.2"),
        "risk_metrics_available_ns": NOW_NS,
        "cooldown_until_ns": 0,
        "stop_breach": False,
        "global_risk_off": False,
        "market_halt": False,
        "requested_mode": "sim",
        "bridge_healthy": True,
        "oms_healthy": True,
    }
    if effective_context:
        context_data.update(effective_context)
    return fusion, sizing, portfolio, DecisionContextV1(**context_data)


def _proposal(**kwargs: Any):
    fusion, sizing, portfolio, context = _bundle(**kwargs)
    return compose(fusion, sizing, portfolio, context)


def _public_link(
    source_kind: str,
    identity: DecisionIdentityV1,
    result: FusionResultV1 | SizingResultV1 | PortfolioCheckV1,
    *,
    identity_hash: str | None = None,
    result_hash: str | None = None,
) -> DecisionInputLinkV1:
    return DecisionInputLinkV1(
        source_kind=source_kind,
        identity_hash=identity.canonical_hash() if identity_hash is None else identity_hash,
        input_hash=result.input_hash,
        result_hash=(
            hashlib.sha256(result.canonical_bytes()).hexdigest()
            if result_hash is None
            else result_hash
        ),
        tenant_id=identity.tenant_id,
        strategy_revision_hash=identity.strategy_revision_hash,
        portfolio_revision_hash=identity.portfolio_revision_hash,
        symbol=identity.symbol,
        evaluation_ns=identity.evaluation_ns,
        window_id=identity.window_id,
        feature_snapshot_hash=identity.feature_snapshot_hash,
        truth_hash=identity.truth_hash,
    )


def _no_intent(
    result: Any, reason: DecisionReason, *, unchanged_target: Decimal = D0
) -> None:
    assert result.status is DecisionStatus.NO_INTENT
    assert result.action is DecisionAction.NONE
    assert result.effective_mode == "none"
    assert result.qty_delta == 0
    assert result.target_quantity == unchanged_target
    assert result.notional == 0
    assert result.projected_exposures is None
    assert reason in result.reason_codes
    assert result.reason_codes == tuple(sorted(set(result.reason_codes)))


def _pins() -> tuple[str, str]:
    bars = PINS["c102_bars_payload"].encode("utf-8")
    lock = PINS["c102_lock_payload"].encode("utf-8")
    return hashlib.sha256(bars).hexdigest(), hashlib.sha256(lock).hexdigest()


def _replay_bytes() -> str:
    fusion, sizing, portfolio, context = _bundle()
    bars_hash, lock_hash = _pins()
    fixture = DecisionFixtureV1(
        PINS["fixture_id"], bars_hash, lock_hash, fusion, sizing, portfolio, context
    )
    return replay(fixture).canonical_bytes().hex()


def test_valid_candidate_proposes_exact_open_with_complete_ordered_trace() -> None:
    proposal = _proposal()
    assert proposal.status is DecisionStatus.PROPOSED
    assert proposal.action is DecisionAction.OPEN
    assert proposal.requested_mode == proposal.effective_mode == "sim"
    assert proposal.qty_delta == D(1)
    assert proposal.target_quantity == D(1)
    assert proposal.notional == D(100)
    assert proposal.lot_multiple and proposal.min_notional_met
    assert proposal.attributions == _bundle()[0].attributions[:5]
    assert len(proposal.attributions) == 5
    assert tuple(step.stage for step in proposal.trace) == STAGES
    assert all(step.status == "PASS" for step in proposal.trace)
    assert proposal.reason_codes == ()
    assert proposal.canonical_bytes() == _proposal().canonical_bytes()


@pytest.mark.parametrize(
    ("current", "side", "qty", "expected_action", "expected_delta", "expected_target"),
    [
        (D(5), "BUY", D(2), DecisionAction.INCREASE, D(2), D(7)),
        (D(5), "SELL", D(2), DecisionAction.REDUCE, D(-2), D(3)),
        (D(5), "SELL", D(5), DecisionAction.CLOSE, D(-5), D(0)),
    ],
)
def test_position_action_transitions_preserve_sign_and_never_cross_zero(
    current: Decimal,
    side: str,
    qty: Decimal,
    expected_action: DecisionAction,
    expected_delta: Decimal,
    expected_target: Decimal,
) -> None:
    proposal = _proposal(
        quantity=qty,
        context_values={"current_quantity": current, "side": side},
    )
    assert proposal.status is DecisionStatus.PROPOSED
    assert proposal.action is expected_action
    assert proposal.qty_delta == expected_delta
    assert proposal.target_quantity == expected_target


def test_reducer_that_would_cross_zero_is_denied_not_reversed_into_new_exposure() -> None:
    proposal = _proposal(
        quantity=D(6),
        context_values={"current_quantity": D(5), "side": "SELL"},
    )
    _no_intent(proposal, DecisionReason.REDUCER_CROSS_ZERO, unchanged_target=D(5))


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"fusion_status": "NO_INTENT"}, DecisionReason.FUSION_NO_CANDIDATE),
        ({"portfolio_status": PortfolioStatus.BLOCKED}, DecisionReason.PORTFOLIO_BLOCKED),
        ({"sizing_status": SizingStatus.NO_SIZE, "quantity": D(0)}, DecisionReason.NO_SIZE),
        ({"quantity": D(0)}, DecisionReason.NO_SIZE),
        ({"feature_found": False}, DecisionReason.FEATURE_MISSING),
        ({"feature_hash": "d" * 64}, DecisionReason.FEATURE_ASOF_MISMATCH),
        ({"feature_asof_ns": NOW_NS - 1}, DecisionReason.FEATURE_ASOF_MISMATCH),
        ({"feature_available_ns": NOW_NS + 1}, DecisionReason.FEATURE_ASOF_MISMATCH),
        ({"truth_verdict": Verdict.HARD_FAIL}, DecisionReason.TRUTH_REJECTED),
        ({"truth_evaluation_ns": NOW_NS - 1}, DecisionReason.TRUTH_ASOF_MISMATCH),
        ({"truth_hash": "d" * 64}, DecisionReason.TRUTH_ASOF_MISMATCH),
        ({"identity_truth_hash": "e" * 64}, DecisionReason.TRUTH_ASOF_MISMATCH),
        ({"context_values": {"risk_metrics_available_ns": None}}, DecisionReason.STALE_METRICS),
        (
            {"context_values": {"risk_metrics_available_ns": NOW_NS + 1}},
            DecisionReason.STALE_METRICS,
        ),
        ({"context_values": {"rolling_volatility": D("0.6")}}, DecisionReason.VOLATILITY_BREACH),
        ({"portfolio_max_corr": D("0.9")}, DecisionReason.CORRELATION_BREACH),
        ({"policy_values": {"max_position_quantity": D("0.5")}}, DecisionReason.POSITION_BREACH),
        ({"policy_caps": _caps(gross_notional=D("50"))}, DecisionReason.CAP_BREACH),
        ({"context_values": {"cooldown_until_ns": NOW_NS + 1}}, DecisionReason.COOLDOWN),
        ({"context_values": {"stop_breach": True}}, DecisionReason.STOP_BREACH),
        ({"context_values": {"global_risk_off": True}}, DecisionReason.RISK_OFF),
        ({"context_values": {"market_halt": True}}, DecisionReason.MARKET_HALT),
        (
            {
                "quantity": D("1.5"),
                "context_values": {"lot_step": D(1)},
            },
            DecisionReason.LOT_STEP_BREACH,
        ),
        ({"context_values": {"min_notional": D("101")}}, DecisionReason.MIN_NOTIONAL),
        ({"policy_values": {"long_enabled": False}}, DecisionReason.LONG_DISABLED),
        (
            {"context_values": {"side": "SELL"}, "policy_values": {"short_enabled": False}},
            DecisionReason.SHORT_DISABLED,
        ),
    ],
)
def test_every_veto_fails_closed_with_zero_delta(
    changes: dict[str, Any], reason: DecisionReason
) -> None:
    proposal = _proposal(**changes)
    _no_intent(proposal, reason)


def test_missing_and_mismatched_binding_hashes_fail_closed() -> None:
    fusion, sizing, portfolio, context = _bundle()
    wrong_fusion_link = _public_link(
        "FUSION", context.identity, fusion, result_hash="e" * 64
    )
    broken = replace(context, fusion_link=wrong_fusion_link)
    proposal = compose(fusion, sizing, portfolio, broken)
    _no_intent(proposal, DecisionReason.CONTEXT_MISMATCH)

    wrong_identity_link = _public_link(
        "SIZING", context.identity, sizing, identity_hash="f" * 64
    )
    broken = replace(context, sizing_link=wrong_identity_link)
    proposal = compose(fusion, sizing, portfolio, broken)
    _no_intent(proposal, DecisionReason.CONTEXT_MISMATCH)

    fusion, sizing, portfolio, context = _bundle()
    fusion = FusionResultV1(
        status=fusion.status,
        idempotency_check=fusion.idempotency_check,
        reason_codes=fusion.reason_codes,
        layer_verdicts=fusion.layer_verdicts,
        layer_scores=fusion.layer_scores,
        attributions=fusion.attributions,
        rationale=fusion.rationale,
        evaluation_ns=NOW_NS - 1,
        input_hash=fusion.input_hash,
        policy_hash=fusion.policy_hash,
        idempotency_key=fusion.idempotency_key,
    )
    _no_intent(compose(fusion, sizing, portfolio, context), DecisionReason.CONTEXT_MISMATCH)


def test_publicly_rebuilt_links_cannot_relabel_verified_tenant_identity() -> None:
    fusion, sizing, portfolio, context = _bundle()
    relabelled = replace(context.identity, tenant_id="attacker-tenant")
    broken = replace(
        context,
        identity=relabelled,
        fusion_link=_public_link("FUSION", relabelled, fusion),
        sizing_link=_public_link("SIZING", relabelled, sizing),
        portfolio_link=_public_link("PORTFOLIO", relabelled, portfolio),
    )
    _no_intent(compose(fusion, sizing, portfolio, broken), DecisionReason.CONTEXT_MISMATCH)


def test_valid_reducer_requires_fifo_support_and_declared_live_fallback_is_visible() -> None:
    _no_intent(
        _proposal(
            quantity=D(2),
            context_values={"current_quantity": D(5), "side": "SELL"},
            policy_values={"fifo_netting_supported": False},
        ),
        DecisionReason.FIFO_UNSUPPORTED,
        unchanged_target=D(5),
    )
    fallback = _proposal(
        context_values={"requested_mode": "live", "bridge_healthy": False},
        policy_values={"live_fallback": "SIM"},
    )
    assert fallback.status is DecisionStatus.PROPOSED
    assert fallback.requested_mode == "live" and fallback.effective_mode == "sim"
    assert DecisionReason.LIVE_FALLBACK_SIM in fallback.reason_codes
    blocked = _proposal(
        context_values={"requested_mode": "live", "oms_healthy": False},
        policy_values={"live_fallback": "BLOCK"},
    )
    _no_intent(blocked, DecisionReason.MODE_UNAVAILABLE)


def test_exact_lot_minimum_and_hard_cap_equalities_are_accepted() -> None:
    proposal = _proposal(
        context_values={"min_notional": D("100"), "lot_step": D(1)},
        sizing_exposures=SizingExposureSnapshotV1(
            symbol_notional=D("1000"),
            sector_notional=D("1000"),
            gross_notional=D("2000"),
            net_notional=D("2000"),
            leverage=D(2),
            projected_worst_case_loss=D("100"),
            portfolio_heat=D("100"),
        ),
    )
    assert proposal.status is DecisionStatus.PROPOSED
    assert proposal.notional == D("100")
    assert proposal.lot_multiple and proposal.min_notional_met


@pytest.mark.parametrize(
    "exposure_override",
    [
        {"symbol_notional": D("1001")},
        {"sector_notional": D("1001")},
        {"gross_notional": D("2001")},
        {"net_notional": D("2001")},
        {"leverage": D("2.1")},
        {"projected_worst_case_loss": D("101")},
        {"portfolio_heat": D("101")},
    ],
)
def test_each_port001_hard_cap_is_independently_enforced(
    exposure_override: dict[str, Decimal],
) -> None:
    baseline = SizingExposureSnapshotV1(
        symbol_notional=D("100"),
        sector_notional=D("100"),
        gross_notional=D("100"),
        net_notional=D("100"),
        leverage=D("0.1"),
        projected_worst_case_loss=D("10"),
        portfolio_heat=D("10"),
    )
    over = replace(baseline, **exposure_override)
    _no_intent(
        _proposal(sizing_exposures=over),
        DecisionReason.CAP_BREACH,
    )


def test_reported_at_cap_gross_cannot_hide_over_cap_proposed_position() -> None:
    reported = SizingExposureSnapshotV1(
        symbol_notional=D("100"),
        sector_notional=D("100"),
        gross_notional=D("100"),
        net_notional=D("100"),
        leverage=D("0.1"),
        projected_worst_case_loss=D("10"),
        portfolio_heat=D("10"),
    )
    proposal = _proposal(
        quantity=D("5"),
        sizing_exposures=reported,
        policy_caps=_caps(gross_notional=D("100")),
    )
    _no_intent(proposal, DecisionReason.CAP_BREACH)


def test_valid_offset_portfolio_is_proposed_with_freshly_issued_exact_links() -> None:
    offset_exposures = SizingExposureSnapshotV1(
        symbol_notional=D("100"),
        sector_notional=D("100"),
        gross_notional=D("200"),
        net_notional=D("0"),
        leverage=D("0.2"),
        projected_worst_case_loss=D("10"),
        portfolio_heat=D("10"),
    )
    fusion, sizing, portfolio, context = _bundle(sizing_exposures=offset_exposures)
    # The account also holds an offsetting short: gross is 200 while net is zero.
    portfolio = replace(portfolio, gross_notional=D("200"), net_notional=D("0"))
    links = _issue_link_from_verified_sources(context.identity, fusion, sizing, portfolio)
    context = replace(
        context,
        fusion_link=links[0],
        sizing_link=links[1],
        portfolio_link=links[2],
    )

    proposal = compose(fusion, sizing, portfolio, context)

    assert proposal.status is DecisionStatus.PROPOSED
    assert proposal.action is DecisionAction.OPEN
    assert proposal.target_quantity == D(1)
    assert proposal.projected_exposures is not None
    assert proposal.projected_exposures.symbol_notional == D("100")
    assert proposal.projected_exposures.sector_notional == D("100")
    assert proposal.projected_exposures.gross_notional == D("200")
    assert proposal.projected_exposures.net_notional == D("0")


def test_replay_pins_fixture_hashes_and_is_byte_stable_across_processes() -> None:
    fusion, sizing, portfolio, context = _bundle()
    bars_hash, lock_hash = _pins()
    fixture = DecisionFixtureV1(
        PINS["fixture_id"], bars_hash, lock_hash, fusion, sizing, portfolio, context
    )
    trace = replay(fixture)
    encoded = trace.canonical_bytes()
    assert trace.fixture_id == PINS["fixture_id"]
    assert (trace.c102_bars_sha256, trace.c102_lock_sha256) == (bars_hash, lock_hash)
    assert trace.proposal.canonical_bytes() == compose(
        fusion, sizing, portfolio, context
    ).canonical_bytes()
    changed_fixture = replace(fixture, c102_bars_sha256="f" * 64)
    changed_trace = replay(changed_fixture)
    assert changed_trace.canonical_bytes() != encoded
    assert changed_trace.c102_bars_sha256 == "f" * 64

    script = (
        "import sys; "
        f"sys.path.insert(0, {str(HERE)!r}); "
        "from test_proposal_acceptance import _replay_bytes; "
        "print(_replay_bytes())"
    )
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=HERE.parents[3],
        check=True,
        capture_output=True,
        text=True,
    )
    assert completed.stdout.strip() == encoded.hex()


def test_sealed_outputs_reject_public_forgery_and_serialization_bypasses() -> None:
    fusion, sizing, portfolio, context = _bundle()
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(DecisionFrozenError):
            operation(context.identity)
    with pytest.raises(DecisionInputError) as bool_time:
        DecisionIdentityV1("tenant", H, H, "SYNTH", True, "window", H, H)
    assert bool_time.value.code == "INVALID_TIMESTAMP"
    proposal = compose(fusion, sizing, portfolio, context)
    trace = replay(
        DecisionFixtureV1(PINS["fixture_id"], *_pins(), fusion, sizing, portfolio, context)
    )
    original = proposal.canonical_bytes()
    with pytest.raises(DecisionInputError) as forged:
        replace(proposal, rationale="forged public twin")
    assert forged.value.code == "UNISSUED_PROPOSAL"
    with pytest.raises(DecisionInputError) as forged_trace:
        replace(trace)
    assert forged_trace.value.code == "UNISSUED_TRACE"
    for value in (proposal, trace):
        for operation in (copy.copy, copy.deepcopy, pickle.dumps):
            with pytest.raises(DecisionFrozenError):
                operation(value)
    for value, field_name in ((proposal, "rationale"), (trace, "fixture_id")):
        with pytest.raises((FrozenInstanceError, TypeError)) as caught:
            setattr(value, field_name, "SECRET frozen canary")
        assert "SECRET frozen canary" not in str(caught.value)
        if value is proposal:
            assert value.canonical_bytes() == original
        else:
            assert value.canonical_bytes()


def test_public_identity_policy_and_frozen_records_reject_invalid_mutation() -> None:
    secret = "SECRET bad identity"
    with pytest.raises(DecisionInputError) as caught:
        DecisionIdentityV1(secret, H, H, "SYNTH", NOW_NS, "window", H, H)
    assert caught.value.code == "INVALID_ID"
    assert secret not in str(caught.value)
    assert str(caught.value) == caught.value.args[0]
    with pytest.raises(DecisionInputError) as bad_digest:
        DecisionIdentityV1("tenant", "A" * 64, H, "SYNTH", NOW_NS, "window", H, H)
    assert bad_digest.value.code == "INVALID_DIGEST"

    fusion, sizing, portfolio, context = _bundle()
    proposal = compose(fusion, sizing, portfolio, context)
    with pytest.raises(DecisionInputError) as non_decimal:
        replace(context, price=100.0)
    assert non_decimal.value.code == "INVALID_DECIMAL"
    with pytest.raises(FrozenInstanceError):
        del proposal.status
    with pytest.raises((FrozenInstanceError, TypeError)) as frozen:
        setattr(proposal, secret, secret)
    assert secret not in str(frozen.value)
    assert proposal.canonical_bytes()
    with pytest.raises(DecisionInputError) as invalid_policy:
        replace(context.policy, min_volatility=D("0.6"), max_volatility=D("0.5"))
    assert invalid_policy.value.code == "POLICY_OUT_OF_BOUNDS"
    with pytest.raises(DecisionInputError) as non_boolean_policy:
        replace(context.policy, long_enabled=1)
    assert non_boolean_policy.value.code == "INVALID_BOOLEAN"
    with pytest.raises(DecisionInputError) as unbounded_metric_age:
        replace(context.policy, max_metric_age_ns=2**63 - 1)
    assert unbounded_metric_age.value.code == "POLICY_OUT_OF_BOUNDS"
    with pytest.raises(DecisionInputError):
        replace(context.policy, min_volatility=D("1e1000000"))


def test_canonical_input_hash_tracks_input_while_idempotency_key_is_semantic() -> None:
    original = _proposal()
    changed = _proposal(context_values={"price": D("101")})
    assert changed.input_hash != original.input_hash
    assert changed.idempotency_key == original.idempotency_key


def test_exact_proposal_arithmetic_is_independent_of_ambient_decimal_precision() -> None:
    quantity = D("1.234567890123456789")
    values = {
        "quantity": quantity,
        "context_values": {
            "price": D("123.4567"),
            "lot_step": D("0.000000000000000001"),
            "min_notional": D(0),
        },
    }
    ordinary = _proposal(**values)
    with localcontext() as context:
        context.prec = 2
        low_precision = _proposal(**values)
    assert low_precision.qty_delta == quantity
    assert low_precision.notional == quantity * D("123.4567")
    assert low_precision.canonical_bytes() == ordinary.canonical_bytes()


def test_reinitialization_of_issued_proposal_cannot_change_its_content() -> None:
    proposal = _proposal()
    original = proposal.canonical_bytes()
    values = {field.name: getattr(proposal, field.name) for field in fields(proposal)}
    values["rationale"] = "SECRET reinitialization attempt"
    with pytest.raises(DecisionInputError) as caught:
        proposal.__init__(**values)
    assert caught.value.code
    assert "SECRET reinitialization attempt" not in str(caught.value)
    assert "SECRET reinitialization attempt" not in repr(caught.value.args)
    assert proposal.canonical_bytes() == original


def test_no_route_or_oms_authority_is_present_in_advisory_proposal() -> None:
    proposal = _proposal()
    names = {field.name for field in fields(proposal)}
    assert not names.intersection({"order", "route_permit", "broker_command", "oms_intent"})
    assert proposal.action is DecisionAction.OPEN
