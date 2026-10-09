"""Worker-owned boundary checks for the offline prediction-market kernel."""

import copy
import pickle
from dataclasses import replace
from decimal import Decimal, localcontext

import pytest

from leviathan_core.prediction_markets import (
    FXRateV1,
    MappingRuleV1,
    PredictionError,
    PredictionMarketIdentityV1,
    PredictionSourceRecordV1,
    ResolutionEventV1,
    map_event,
    normalize,
    require_mapping,
    require_prior,
)
from leviathan_core.prediction_markets.models import _issue_recorded_resolution
from leviathan_core.seal import SealError

NOW = 40_000_000_000


def _quote(
    outcome_id: str,
    price: str,
    *,
    depth: str | None = "1000",
    age_ns: int = 0,
    access_class: str = "PUBLIC",
    currency: str = "USD",
    status: str = "ACTIVE",
    fee_rate: str = "0",
    source_id: str = "recorded-source",
    raw_digest: str | None = "a" * 64,
) -> PredictionSourceRecordV1:
    event_ns = NOW - age_ns
    return PredictionSourceRecordV1(
        venue="KALSHI",
        source_id=source_id,
        contract_id="market-1",
        outcome_id=outcome_id,
        raw_quote_digest=raw_digest,
        access_class=access_class,
        entitlement_ref="ent-1" if access_class == "AUTHENTICATED" else None,
        account_ref="acct-1" if access_class == "AUTHENTICATED" else None,
        event_ns=event_ns,
        received_ns=event_ns,
        available_ns=event_ns,
        market_status=status,
        resolution_version="v1" if status == "RESOLVED" else None,
        currency=currency,
        bid=Decimal(price),
        ask=Decimal(price),
        depth_1pct=Decimal(depth) if depth is not None else None,
        depth_2pct=Decimal(depth) if depth is not None else None,
        fee_rate=Decimal(fee_rate),
        volatility=Decimal(0),
        source_reliability=Decimal(1),
    )


def _prior(*rows: PredictionSourceRecordV1):
    return normalize(rows, outcome_ids=("NO", "YES"), asof_ns=NOW)


def test_binary_vector_fee_adjustment_and_permutation() -> None:
    yes = _quote("YES", "0.4", fee_rate="0.1")
    no = _quote("NO", "0.6")
    prior = _prior(yes, no)
    assert prior == _prior(no, yes)
    assert [item.outcome_id for item in prior.outcomes] == ["NO", "YES"]
    assert prior.outcomes[1].probability > Decimal("0.4")
    assert sum(item.probability for item in prior.outcomes) == Decimal(1)
    assert not prior.hedge_eligible
    assert require_prior(prior) is prior


def test_multi_outcome_normalization_is_complete_and_bounded() -> None:
    rows = (_quote("A", "0.5"), _quote("B", "0.5"), _quote("C", "0.5"))
    prior = normalize(rows, outcome_ids=("C", "B", "A"), asof_ns=NOW)
    assert len(prior.outcomes) == 3
    assert all(item.probability > 0 for item in prior.outcomes)
    assert abs(sum(item.probability for item in prior.outcomes) - 1) <= Decimal("0.000001")
    with pytest.raises(PredictionError, match="OUTCOME_MISSING"):
        normalize(rows[:-1], outcome_ids=("A", "B", "C"), asof_ns=NOW)


def test_confidence_monotonicity_stale_boundary_and_missing_depth() -> None:
    low = _prior(_quote("NO", "0.5", depth="1"), _quote("YES", "0.5", depth="1"))
    high = _prior(_quote("NO", "0.5", depth="10000"), _quote("YES", "0.5", depth="10000"))
    assert high.confidence >= low.confidence
    at_boundary = _prior(_quote("NO", "0.5", age_ns=30_000_000_000), _quote("YES", "0.5"))
    beyond = _prior(_quote("NO", "0.5", age_ns=30_000_000_001), _quote("YES", "0.5"))
    assert "STALE_QUOTE" not in at_boundary.quality_flags
    assert "STALE_QUOTE" in beyond.quality_flags
    assert beyond.confidence == 0
    missing = _prior(_quote("NO", "0.5", depth=None), _quote("YES", "0.5", depth=None))
    assert "MISSING_LIQUIDITY" in missing.quality_flags
    assert missing.confidence < Decimal("0.2")


def test_access_fx_and_source_provenance_never_grant_hedging() -> None:
    public = _quote("NO", "0.4", currency="USDC")
    auth = _quote("YES", "0.6", access_class="AUTHENTICATED", currency="USDC")
    missing = _prior(public, auth)
    assert {"FX_MISSING", "MIXED_ACCESS"} <= set(missing.quality_flags)
    assert not missing.hedge_eligible
    fx = FXRateV1("USDC", "USD", Decimal("1"), NOW, NOW, "fx-source", "fx-v1")
    present = normalize((public, auth), outcome_ids=("NO", "YES"), asof_ns=NOW, fx_rates=(fx,))
    assert "FX_MISSING" not in present.quality_flags
    assert len(present.conversion_versions) == 1
    assert present.confidence >= missing.confidence
    assert present.source_refs[1].account_ref == "acct-1"
    assert present.source_refs[1].conversion_ref == fx


def test_asof_filter_and_same_time_conflict() -> None:
    old = _quote("YES", "0.5", age_ns=2)
    no = _quote("NO", "0.5", age_ns=2)
    future = replace(
        old,
        bid=Decimal("0.9"),
        ask=Decimal("0.9"),
        event_ns=NOW + 1,
        received_ns=NOW + 1,
        available_ns=NOW + 1,
    )
    early = normalize((old, no), outcome_ids=("NO", "YES"), asof_ns=NOW)
    assert normalize((old, no, future), outcome_ids=("NO", "YES"), asof_ns=NOW) == early
    conflicting = replace(old, bid=Decimal("0.4"), ask=Decimal("0.4"))
    with pytest.raises(PredictionError, match="QUOTE_CONFLICT"):
        normalize((old, conflicting, no), outcome_ids=("NO", "YES"), asof_ns=NOW)


def test_resolution_requires_issued_versioned_evidence() -> None:
    rows = (_quote("NO", "0.4", status="RESOLVED"), _quote("YES", "0.6", status="RESOLVED"))
    unverified = _prior(*rows)
    assert "RESOLUTION_UNVERIFIED" in unverified.quality_flags
    assert unverified.confidence == 0
    with pytest.raises(PredictionError, match="UNVERIFIED_RESOLUTION"):
        ResolutionEventV1("KALSHI", "market-1", "YES", "v1", NOW, NOW, False, "proof")
    resolved = _issue_recorded_resolution(
        venue="KALSHI",
        contract_id="market-1",
        winning_outcome_id="YES",
        version="v1",
        event_ns=NOW,
        available_ns=NOW,
        disputed=False,
        verification_ref="recorded-proof",
    )
    final = normalize(rows, outcome_ids=("NO", "YES"), asof_ns=NOW, resolution=resolved)
    assert tuple(item.probability for item in final.outcomes) == (Decimal("0.4"), Decimal("0.6"))
    assert "RESOLUTION_UNVERIFIED" in final.quality_flags
    assert "RESOLUTION_VERIFIED" not in final.quality_flags
    assert final.resolution_identity is not None
    disputed = _issue_recorded_resolution(
        venue="KALSHI",
        contract_id="market-1",
        winning_outcome_id=None,
        version="v1",
        event_ns=NOW,
        available_ns=NOW,
        disputed=True,
        verification_ref="dispute-proof",
    )
    paused = normalize(rows, outcome_ids=("NO", "YES"), asof_ns=NOW, resolution=disputed)
    assert "RESOLUTION_DISPUTED" in paused.quality_flags
    assert paused.confidence == 0


def test_mapping_priority_conflict_and_explicit_one_to_many() -> None:
    market = PredictionMarketIdentityV1(
        "KALSHI", "market-1", "Fed hike in September", ("Fed",), NOW
    )
    rules = (
        MappingRuleV1("pattern", "KALSHI", None, "PATTERN", "Fed", "EVENT_A", "D7", "r1", NOW),
        MappingRuleV1("tag", "KALSHI", None, "EXACT_TAG", "Fed", "EVENT_B", "D7", "r1", NOW),
        MappingRuleV1(
            "manual", "KALSHI", "market-1", "MANUAL", "market-1", "EVENT_C", "D7", "r1", NOW
        ),
    )
    mapped = map_event(market, reversed(rules), asof_ns=NOW)
    assert mapped.targets == ("EVENT_C",)
    assert mapped.priority == "MANUAL"
    assert require_mapping(mapped) is mapped
    tie = map_event(
        market,
        (*rules[:1], replace(rules[0], rule_id="pattern2", internal_event_id="EVENT_D")),
        asof_ns=NOW,
    )
    assert tie.status == "CONFLICT"
    assert tie.targets == ()
    assert tie.audit_intents[0].reason == "MAPPING_CONFLICT"
    grouped = map_event(
        market,
        (
            replace(rules[2], manual_group="group-1"),
            replace(
                rules[2], rule_id="manual2", internal_event_id="EVENT_D", manual_group="group-1"
            ),
        ),
        asof_ns=NOW,
    )
    assert grouped.targets == ("EVENT_C", "EVENT_D")
    assert grouped.target_horizons == (("EVENT_C", "D7"), ("EVENT_D", "D7"))


def test_unrelated_and_future_mapping_rules_cannot_change_asof() -> None:
    market = PredictionMarketIdentityV1("KALSHI", "market-1", "Fed hike", ("Fed",), NOW)
    base = MappingRuleV1("base", "KALSHI", None, "EXACT_TAG", "Fed", "EVENT_A", "D7", "r1", NOW)
    future = replace(base, rule_id="future", internal_event_id="EVENT_B", available_ns=NOW + 1)
    other = replace(base, venue="POLYMARKET", rule_id="other", internal_event_id="EVENT_C")
    expected = map_event(market, (base,), asof_ns=NOW)
    assert map_event(market, (future, other, base), asof_ns=NOW) == expected


def test_ambient_decimal_context_cannot_change_prior() -> None:
    rows = (_quote("NO", "0.5", fee_rate="0.01"), _quote("YES", "0.5"))
    expected = _prior(*rows)
    with localcontext() as ctx:
        ctx.prec = 6
        ctx.Emax = 5
        assert _prior(*rows) == expected


def test_issued_results_reject_replace_and_tamper() -> None:
    prior = _prior(_quote("NO", "0.5"), _quote("YES", "0.5"))
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(PredictionError, match="FROZEN_RECORD"):
            operation(prior)
    with pytest.raises(PredictionError, match="UNISSUED_RESULT"):
        replace(prior, confidence=Decimal(1))
    object.__setattr__(prior, "confidence", Decimal(1))
    with pytest.raises(SealError):
        require_prior(prior)


def test_bool_timestamp_crossed_quote_and_precision_are_typed() -> None:
    row = _quote("NO", "0.5")
    with pytest.raises(PredictionError, match="INVALID_INTEGER"):
        replace(row, event_ns=True)
    with pytest.raises(PredictionError, match="CROSSED_QUOTE"):
        replace(row, bid=Decimal("0.7"), ask=Decimal("0.6"))
    with pytest.raises(PredictionError, match="PRECISION_EXCEEDED"):
        replace(row, bid=Decimal("0.12345678901234567890123456789012345"))
    with pytest.raises(PredictionError, match="MAGNITUDE_OUT_OF_BOUNDS"):
        replace(row, depth_2pct=Decimal("1E+100000"))


def test_future_foreign_rows_cannot_change_an_earlier_prior() -> None:
    no, yes = _quote("NO", "0.4"), _quote("YES", "0.6")
    base = _prior(no, yes)
    future_foreign = replace(
        no,
        contract_id="other-market",
        event_ns=NOW + 1,
        received_ns=NOW + 1,
        available_ns=NOW + 1,
    )
    future_outcome = replace(future_foreign, contract_id="market-1", outcome_id="MAYBE")
    assert _prior(no, yes, future_foreign, future_outcome) == base


def test_metadata_time_and_identity_calibration_reject_lookahead_claims() -> None:
    market = PredictionMarketIdentityV1("KALSHI", "market-1", "New tag", ("NEW",), NOW + 1)
    with pytest.raises(PredictionError, match="METADATA_NOT_AVAILABLE"):
        map_event(market, (), asof_ns=NOW)
    with pytest.raises(PredictionError, match="CALIBRATION_VERSION_UNSUPPORTED"):
        normalize(
            (_quote("NO", "0.4"), _quote("YES", "0.6")),
            outcome_ids=("NO", "YES"),
            asof_ns=NOW,
            calibration_revision="platt-v99",
        )


def test_resolution_and_fx_provenance_bind_the_full_record() -> None:
    rows = (_quote("NO", "0.4", status="RESOLVED"), _quote("YES", "0.6", status="RESOLVED"))
    first = _issue_recorded_resolution(
        venue="KALSHI",
        contract_id="market-1",
        winning_outcome_id="YES",
        version="v1",
        event_ns=NOW,
        available_ns=NOW,
        disputed=False,
        verification_ref="recorded-a",
    )
    # A direct replacement cannot inherit the private issuance capability.
    assert first.verification_status == "UNVERIFIED"
    with pytest.raises(PredictionError, match="UNVERIFIED_RESOLUTION"):
        replace(first, verification_ref="recorded-b")
    other = _issue_recorded_resolution(
        venue="KALSHI",
        contract_id="market-1",
        winning_outcome_id="YES",
        version="v1",
        event_ns=NOW,
        available_ns=NOW,
        disputed=False,
        verification_ref="recorded-b",
    )
    left = normalize(rows, outcome_ids=("NO", "YES"), asof_ns=NOW, resolution=first)
    right = normalize(rows, outcome_ids=("NO", "YES"), asof_ns=NOW, resolution=other)
    assert left.outcomes == right.outcomes
    assert left.resolution_identity != right.resolution_identity
    assert left.result_version != right.result_version
    assert "RESOLUTION_VERIFIED" not in left.quality_flags

    usdc_rows = (_quote("NO", "0.4", currency="USDC"), _quote("YES", "0.6", currency="USDC"))
    fx_a = FXRateV1("USDC", "USD", Decimal(1), NOW, NOW, "a:b", "c")
    fx_b = FXRateV1("USDC", "USD", Decimal(1), NOW, NOW, "a", "b:c")
    prior_a = normalize(usdc_rows, outcome_ids=("NO", "YES"), asof_ns=NOW, fx_rates=(fx_a,))
    prior_b = normalize(usdc_rows, outcome_ids=("NO", "YES"), asof_ns=NOW, fx_rates=(fx_b,))
    assert prior_a.source_refs[0].conversion_ref == fx_a
    assert prior_b.source_refs[0].conversion_ref == fx_b
    assert prior_a.result_version != prior_b.result_version


def test_iterable_limit_and_reinit_are_content_free_and_pre_mutation() -> None:
    no, yes = _quote("NO", "0.4"), _quote("YES", "0.6")

    def overflowing_rows():
        for _ in range(257):
            yield no
        raise RuntimeError("overconsumed-source")

    with pytest.raises(PredictionError, match="SOURCE_INPUT_INVALID"):
        normalize(overflowing_rows(), outcome_ids=("NO", "YES"), asof_ns=NOW)

    market = PredictionMarketIdentityV1("KALSHI", "market-1", "title", (), NOW)
    rule = MappingRuleV1("rule", "KALSHI", None, "PATTERN", "title", "EVENT", "D7", "r1", NOW)

    def overflowing_rules():
        for _ in range(257):
            yield rule
        raise RuntimeError("overconsumed-rule")

    with pytest.raises(PredictionError, match="MAPPING_INPUT_INVALID"):
        map_event(market, overflowing_rules(), asof_ns=NOW)

    prior = _prior(no, yes)
    mapped = map_event(market, (rule,), asof_ns=NOW)
    resolution = _issue_recorded_resolution(
        venue="KALSHI",
        contract_id="market-1",
        winning_outcome_id="YES",
        version="v1",
        event_ns=NOW,
        available_ns=NOW,
        disputed=False,
        verification_ref="recorded",
    )
    for issued in (prior, mapped, resolution):
        with pytest.raises(PredictionError):
            issued.__init__(contract_id="forged")
        assert issued.contract_id == "market-1"
