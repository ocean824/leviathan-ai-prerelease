"""Writer-owned unit checks for the DEC-002 advisory kernel."""

import copy
import pickle
from dataclasses import FrozenInstanceError, fields, replace
from datetime import UTC, datetime
from decimal import Decimal, localcontext

import pytest

from leviathan_core.decision_fusion.models import FusionResultV1
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
from leviathan_core.portfolio.models import (
    ExposureSnapshotV1,
    HardCapsV1,
    SizingResultV1,
    SizingStatus,
)
from leviathan_core.portfolio.overlap import PortfolioCheckV1, PortfolioStatus
from leviathan_core.seal import SealError
from leviathan_core.truth.verdict.models import TruthSource, TruthVerdictV1, Verdict

D = Decimal
H = "a" * 64
NOW_NS = 1_000_000_000


def _inputs() -> tuple[FusionResultV1, SizingResultV1, PortfolioCheckV1, DecisionContextV1]:
    fusion = FusionResultV1(
        status="CAPITAL_CANDIDATE",
        idempotency_check="NOT_PERFORMED",
        reason_codes=(),
        layer_verdicts=(),
        layer_scores=(),
        attributions=(),
        rationale="candidate",
        evaluation_ns=NOW_NS,
        input_hash=H,
        policy_hash=H,
        idempotency_key=H,
    )
    caps = HardCapsV1(D(1000), D(1000), D(2000), D(2000), D(2), D(100), D(100))
    exposures = ExposureSnapshotV1(D(100), D(100), D(100), D(100), D("0.1"), D(10), D(10))
    sizing = SizingResultV1(
        status=SizingStatus.SIZE,
        proposed_quantity=D(1),
        unclamped_quantity=D(1),
        reasons=(),
        cap_hits=(),
        exposures=exposures,
        input_hash=H,
        policy_hash=H,
        as_of_age_ns=0,
        calculation_trace=(),
    )
    portfolio = PortfolioCheckV1(
        status=PortfolioStatus.PASS,
        overlap_pairs=(),
        correlation_pairs=(),
        breaches=(),
        assumptions=(),
        symbol_exposures=(),
        sector_exposures=(),
        gross_notional=D(100),
        net_notional=D(100),
        net_gamma=D(0),
        heat=D(10),
        max_offdiag=D("0.1"),
        input_hash=H,
        policy_hash=H,
        trace=(),
    )
    feature = FeatureResultV1(
        found=True,
        feature_name="signal",
        feature_version="v1",
        instrument_id="ABC",
        asof_ns=NOW_NS,
        value_decimal=D(1),
        event_time_ns=NOW_NS,
        availability_ns=NOW_NS,
        definition_hash=H,
        observation_hash=H,
        lineage=FeatureLineageV1(definition_sha256=H, observation_sha256=H),
    )
    truth = TruthVerdictV1(
        verdict=Verdict.PASS,
        reason_codes=(),
        data_freshness_ms={source: None for source in TruthSource},
        source_timestamps={source: None for source in TruthSource},
        evaluation_ts=datetime(1970, 1, 1, 0, 0, 1, tzinfo=UTC),
        policy_id="truth",
        policy_version="1",
        trace_id="trace",
        hash_id=H,
    )
    identity = DecisionIdentityV1("tenant", H, H, "ABC", NOW_NS, "window", H, H)
    fusion_link, sizing_link, portfolio_link = _issue_link_from_verified_sources(
        identity, fusion, sizing, portfolio,
    )

    policy = DecisionPolicyV1(
        "policy", "1", 100, D("0.1"), D("0.5"), D("0.8"), D(10),
        caps, "BLOCK", True, True, True,
    )
    context = DecisionContextV1(
        identity, fusion_link, sizing_link, portfolio_link, feature, truth, policy,
        "BUY", D(0), D(100), D(1), D(1), D(100), D("0.2"), NOW_NS, 0,
        False, False, False, "sim", True, True,
    )
    return fusion, sizing, portfolio, context


def test_proposal_and_replay_are_deterministic() -> None:
    fusion, sizing, portfolio, context = _inputs()
    result = compose(fusion, sizing, portfolio, context)
    assert result.status is DecisionStatus.PROPOSED
    assert result.action is DecisionAction.OPEN
    assert result.qty_delta == D(1)
    assert result.reason_codes == ()
    assert result.canonical_bytes() == compose(fusion, sizing, portfolio, context).canonical_bytes()
    fixture = DecisionFixtureV1("fixture", H, H, fusion, sizing, portfolio, context)
    assert replay(fixture).canonical_bytes() == replay(fixture).canonical_bytes()


def test_risk_veto_withholds_intent() -> None:
    fusion, sizing, portfolio, context = _inputs()
    result = compose(fusion, sizing, portfolio, replace(context, global_risk_off=True))
    assert result.status is DecisionStatus.NO_INTENT
    assert result.action is DecisionAction.NONE
    assert result.qty_delta == 0
    assert DecisionReason.RISK_OFF in result.reason_codes


def test_issued_result_denies_copy_replace_tamper_and_reinit() -> None:
    fusion, sizing, portfolio, context = _inputs()
    proposal = compose(fusion, sizing, portfolio, context)
    trace = replay(DecisionFixtureV1("fixture", H, H, fusion, sizing, portfolio, context))
    for issued in (proposal, trace):
        before = issued.canonical_bytes()
        with pytest.raises(DecisionFrozenError):
            copy.copy(issued)
        with pytest.raises(DecisionFrozenError):
            copy.deepcopy(issued)
        with pytest.raises(DecisionFrozenError):
            pickle.dumps(issued)
        with pytest.raises(DecisionInputError):
            replace(issued)
        with pytest.raises(DecisionInputError):
            replace(issued, _issuer=object())
        with pytest.raises(DecisionInputError):
            issued.__post_init__(None)
        values = {field.name: getattr(issued, field.name) for field in fields(issued)}
        values["rationale" if issued is proposal else "fixture_id"] = "SECRET canary"
        with pytest.raises(DecisionInputError) as rejected:
            issued.__init__(**values)
        assert "SECRET canary" not in str(rejected.value)
        assert issued.canonical_bytes() == before
    with pytest.raises(FrozenInstanceError) as assigned:
        proposal.rationale = "SECRET canary"  # type: ignore[misc]
    assert "SECRET canary" not in str(assigned.value)
    with pytest.raises(FrozenInstanceError) as deleted:
        del proposal.rationale  # type: ignore[misc]
    assert "SECRET canary" not in str(deleted.value)
    object.__setattr__(proposal, "qty_delta", D(500))
    with pytest.raises(SealError):
        proposal.canonical_bytes()


def test_reported_exposure_cannot_hide_excess_quantity() -> None:
    fusion, sizing, portfolio, context = _inputs()
    altered = replace(sizing, proposed_quantity=D(11))
    _, changed_link, _ = _issue_link_from_verified_sources(
        context.identity, fusion, altered, portfolio,
    )
    result = compose(fusion, altered, portfolio, replace(context, sizing_link=changed_link))
    assert result.status is DecisionStatus.NO_INTENT
    assert DecisionReason.CAP_BREACH in result.reason_codes


def test_ambient_decimal_context_does_not_change_signed_quantity() -> None:
    fusion, sizing, portfolio, context = _inputs()
    sell = replace(context, side="SELL", current_quantity=D(2))
    expected = compose(fusion, sizing, portfolio, sell).canonical_bytes()
    with localcontext() as decimal_context:
        decimal_context.prec = 2
        decimal_context.Emax = 2
        actual = compose(fusion, sizing, portfolio, sell).canonical_bytes()
    assert actual == expected


def test_reported_gross_cannot_hide_computed_target() -> None:
    fusion, sizing, portfolio, context = _inputs()
    altered = replace(sizing, proposed_quantity=D(5))
    _, link, _ = _issue_link_from_verified_sources(
        context.identity, fusion, altered, portfolio,
    )
    caps = replace(context.policy.hard_caps, per_symbol_notional=D(1000),
                   per_sector_notional=D(1000), gross_notional=D(100))
    changed = replace(context, sizing_link=link, policy=replace(context.policy, hard_caps=caps))
    result = compose(fusion, altered, portfolio, changed)
    assert result.status is DecisionStatus.NO_INTENT
    assert DecisionReason.CAP_BREACH in result.reason_codes


def test_offset_portfolio_net_may_be_below_symbol_notional() -> None:
    fusion, sizing, portfolio, context = _inputs()
    assert sizing.exposures is not None
    hedged_exposures = replace(sizing.exposures, gross_notional=D(200), net_notional=D(0))
    hedged_sizing = replace(sizing, exposures=hedged_exposures)
    hedged_portfolio = replace(portfolio, gross_notional=D(200), net_notional=D(0))
    links = _issue_link_from_verified_sources(
        context.identity, fusion, hedged_sizing, hedged_portfolio,
    )
    hedged_context = replace(
        context, fusion_link=links[0], sizing_link=links[1], portfolio_link=links[2],
    )
    result = compose(fusion, hedged_sizing, hedged_portfolio, hedged_context)
    assert result.status is DecisionStatus.PROPOSED
    assert DecisionReason.CAP_BREACH not in result.reason_codes


def test_metric_age_policy_cannot_exceed_governed_ceiling() -> None:
    *_, context = _inputs()
    with pytest.raises(DecisionInputError) as caught:
        replace(context.policy, max_metric_age_ns=2**63 - 1)
    assert caught.value.code == "POLICY_OUT_OF_BOUNDS"


def test_unissued_or_relabelled_link_withholds_intent() -> None:
    fusion, sizing, portfolio, context = _inputs()
    link_fields = context.fusion_link.model_dump(mode="python")
    unissued = DecisionInputLinkV1(**link_fields)
    unissued_result = compose(fusion, sizing, portfolio, replace(context, fusion_link=unissued))
    assert unissued_result.status is DecisionStatus.NO_INTENT
    assert DecisionReason.CONTEXT_MISMATCH in unissued_result.reason_codes

    relabelled_identity = replace(context.identity, tenant_id="other-tenant")
    relabelled = replace(context, identity=relabelled_identity)
    relabelled_result = compose(fusion, sizing, portfolio, relabelled)
    assert relabelled_result.status is DecisionStatus.NO_INTENT
    assert DecisionReason.CONTEXT_MISMATCH in relabelled_result.reason_codes
