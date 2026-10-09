"""Independent acceptance tests for PRED-001 contract behavior."""

from __future__ import annotations

import copy
import gc
import pickle
from dataclasses import fields, replace
from decimal import Decimal, localcontext

import pytest

from leviathan_core.prediction_markets import (
    FXRateV1,
    MappingDecisionV1,
    MappingRuleV1,
    NormalizedPriorV1,
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

ASOF = 40_000_000_000
QUOTE = ASOF - 5_000_000_000
OUTCOMES = ("NO", "YES")
CANARY = "secret-canary-should-not-escape"


def _quote(
    outcome: str,
    price: str = "0.5",
    *,
    bid: str | None = None,
    ask: str | None = None,
    age: int = 0,
    available: int | None = None,
    currency: str = "USD",
    depth1: str | None = "1000",
    depth2: str | None = "1000",
    fee: str = "0",
    status: str = "ACTIVE",
    access: str = "PUBLIC",
    source: str = "synthetic-source",
    digest: str | None = "a" * 64,
    resolution_version: str | None = None,
) -> PredictionSourceRecordV1:
    event_ns = QUOTE - age
    received_ns = event_ns
    available_ns = received_ns if available is None else available
    return PredictionSourceRecordV1(
        venue="KALSHI",
        source_id=source,
        contract_id="contract-1",
        outcome_id=outcome,
        raw_quote_digest=digest,
        access_class=access,
        entitlement_ref="entitlement-1" if access == "AUTHENTICATED" else None,
        account_ref="account-1" if access == "AUTHENTICATED" else None,
        event_ns=event_ns,
        received_ns=received_ns,
        available_ns=available_ns,
        market_status=status,
        resolution_version=resolution_version,
        currency=currency,
        bid=Decimal(price if bid is None else bid),
        ask=Decimal(price if ask is None else ask),
        depth_1pct=Decimal(depth1) if depth1 is not None else None,
        depth_2pct=Decimal(depth2) if depth2 is not None else None,
        fee_rate=Decimal(fee),
        volatility=Decimal("0.1"),
        source_reliability=Decimal("0.9"),
    )


def _prior(*rows: PredictionSourceRecordV1, asof: int = ASOF, **kwargs):
    return normalize(rows, outcome_ids=OUTCOMES, asof_ns=asof, **kwargs)


def _raises_code(call, code: str) -> PredictionError:
    with pytest.raises(PredictionError) as caught:
        call()
    assert caught.value.code == code
    return caught.value


def test_complete_binary_and_multiclass_vectors_are_sorted_bounded_and_replayable():
    rows = (
        _quote("YES", bid="0.3", ask="0.5", fee="0.1"),
        _quote("NO", bid="0.5", ask="0.7"),
    )
    prior = _prior(*rows)
    assert prior == _prior(*reversed(rows))
    assert tuple(item.outcome_id for item in prior.outcomes) == OUTCOMES
    assert sum((item.probability for item in prior.outcomes), Decimal(0)) == Decimal(1)
    assert all(Decimal(0) <= item.probability <= Decimal(1) for item in prior.outcomes)
    assert tuple(item.probability for item in prior.outcomes) == (
        Decimal("0.5769230769230769230769230769230769"),
        Decimal("0.4230769230769230769230769230769231"),
    )
    assert prior.hedge_eligible is False

    tri = tuple(_quote(key, "0.25") for key in ("A", "B", "C"))
    multi = normalize(tri, outcome_ids=("C", "A", "B"), asof_ns=ASOF)
    assert tuple(item.outcome_id for item in multi.outcomes) == ("A", "B", "C")
    assert abs(
        sum((item.probability for item in multi.outcomes), Decimal(0)) - Decimal(1)
    ) <= Decimal("0.000001")
    _raises_code(
        lambda: normalize(tri[:2], outcome_ids=("A", "B", "C"), asof_ns=ASOF),
        "OUTCOME_MISSING",
    )


def test_asof_filter_precedes_quote_reconciliation_and_does_not_mutate_inputs():
    visible = (_quote("NO"), _quote("YES"))
    future = replace(
        visible[1],
        bid=Decimal("0.9"),
        ask=Decimal("0.9"),
        event_ns=ASOF + 1,
        received_ns=ASOF + 2,
        available_ns=ASOF + 3,
    )
    expected = _prior(*visible)
    actual = _prior(*visible, future)
    assert actual == expected
    assert visible[1].bid == Decimal("0.5")

    same_time_conflict = replace(visible[1], bid=Decimal("0.4"), ask=Decimal("0.4"))
    _raises_code(lambda: _prior(*visible, same_time_conflict), "QUOTE_CONFLICT")


def test_late_visible_quote_is_labelled_and_future_quote_cannot_suppress_it():
    base_no = _quote("NO")
    base_yes = _quote("YES")
    late_yes = replace(
        base_yes,
        source_id="later-arrival",
        event_ns=base_yes.event_ns - 10,
        received_ns=ASOF - 1,
        available_ns=ASOF - 1,
    )
    selected = _prior(base_no, base_yes, late_yes)
    assert "LATE_QUOTE" in selected.quality_flags
    hidden = replace(late_yes, event_ns=ASOF + 1, received_ns=ASOF + 2, available_ns=ASOF + 3)
    assert _prior(base_no, base_yes, hidden) == _prior(base_no, base_yes)


@pytest.mark.parametrize(
    ("age", "stale"),
    [(25_000_000_000, False), (25_000_000_001, True)],
)
def test_staleness_boundary_and_nonactive_status_never_look_eligible(age, stale):
    prior = _prior(_quote("NO", age=age), _quote("YES"))
    assert ("STALE_QUOTE" in prior.quality_flags) is stale
    if stale:
        assert prior.confidence == 0
    paused = _prior(_quote("NO", status="PAUSED"), _quote("YES", status="PAUSED"))
    assert "MARKET_PAUSED" in paused.quality_flags
    assert paused.confidence == 0


def test_confidence_uses_both_depth_buckets_and_moves_monotonically():
    thin = _prior(_quote("NO", depth1="10", depth2="20"), _quote("YES", depth1="10", depth2="20"))
    deep = _prior(
        _quote("NO", depth1="1000", depth2="2000"), _quote("YES", depth1="1000", depth2="2000")
    )
    one_bucket = _prior(
        _quote("NO", depth1="10", depth2="2000"), _quote("YES", depth1="10", depth2="2000")
    )
    assert deep.confidence > thin.confidence
    assert one_bucket.confidence > thin.confidence
    missing = _prior(_quote("NO", depth2=None), _quote("YES", depth2=None))
    assert "MISSING_LIQUIDITY" in missing.quality_flags
    assert missing.confidence < Decimal("0.2")


def test_access_and_entitlement_provenance_are_preserved_without_permission_inference():
    public = _quote("NO")
    authenticated = _quote("YES", access="AUTHENTICATED", source="auth-source")
    mixed = _prior(public, authenticated)
    assert "MIXED_ACCESS" in mixed.quality_flags
    assert mixed.hedge_eligible is False
    assert tuple(ref.outcome_id for ref in mixed.source_refs) == OUTCOMES
    yes_ref = mixed.source_refs[1]
    assert (yes_ref.source_id, yes_ref.access_class) == ("auth-source", "AUTHENTICATED")
    assert (yes_ref.entitlement_ref, yes_ref.account_ref) == ("entitlement-1", "account-1")
    assert yes_ref.raw_quote_digest == "a" * 64
    assert (yes_ref.event_ns, yes_ref.available_ns, yes_ref.currency) == (
        authenticated.event_ns,
        authenticated.available_ns,
        "USD",
    )


def test_missing_quote_or_fx_provenance_is_explicit_and_confidence_is_capped():
    no_digest = _prior(_quote("NO", digest=None), _quote("YES"))
    assert "QUOTE_PROVENANCE_MISSING" in no_digest.quality_flags
    assert no_digest.confidence == 0
    usdc = (_quote("NO", currency="USDC"), _quote("YES", currency="USDC"))
    missing = _prior(*usdc)
    assert "FX_MISSING" in missing.quality_flags
    assert missing.confidence <= Decimal("0.1")

    fx = FXRateV1("USDC", "USD", Decimal("1.01"), QUOTE - 1, QUOTE - 1, "fx-feed", "v2")
    converted = _prior(*usdc, fx_rates=(fx,))
    assert "FX_MISSING" not in converted.quality_flags
    assert len(converted.conversion_versions) == 1
    assert len(converted.conversion_versions[0]) == 64
    assert all(ref.conversion_ref == fx for ref in converted.source_refs)


def test_fx_must_be_available_at_quote_time_and_equal_time_conflict_is_typed():
    row = _quote("NO", currency="USDC")
    other = _quote("YES", currency="USDC")
    future_fx = FXRateV1("USDC", "USD", Decimal("1"), QUOTE - 1, QUOTE + 1, "fx", "v1")
    prior = _prior(row, other, fx_rates=(future_fx,))
    assert "FX_MISSING" in prior.quality_flags
    assert prior.source_refs[0].conversion_ref is None

    fx_a = FXRateV1("USDC", "USD", Decimal("1"), QUOTE - 1, QUOTE - 1, "fx-a", "v1")
    fx_b = FXRateV1("USDC", "USD", Decimal("1.1"), QUOTE - 1, QUOTE - 1, "fx-b", "v2")
    _raises_code(lambda: _prior(row, other, fx_rates=(fx_a, fx_b)), "FX_CONFLICT")


def test_identity_calibration_is_versioned_and_unsupported_calibration_is_rejected():
    base = _prior(_quote("NO"), _quote("YES"))
    versioned = normalize(
        (_quote("NO"), _quote("YES")),
        outcome_ids=OUTCOMES,
        asof_ns=ASOF,
        mapping_revision="taxonomy-v3",
    )
    assert base.calibration_revision == "identity-v1"
    assert base.calibration_id == "IDENTITY"
    assert versioned.calibration_revision == "identity-v1"
    assert versioned.calibration_id == "IDENTITY"
    assert versioned.mapping_revision == "taxonomy-v3"
    _raises_code(
        lambda: normalize(
            (_quote("NO"), _quote("YES")),
            outcome_ids=OUTCOMES,
            asof_ns=ASOF,
            calibration_revision="platt-v99",
        ),
        "CALIBRATION_VERSION_UNSUPPORTED",
    )
    _raises_code(
        lambda: normalize(
            (_quote("NO"), _quote("YES")),
            outcome_ids=OUTCOMES,
            asof_ns=ASOF,
            calibration_id="unreviewed-model",
        ),
        "CALIBRATION_UNSUPPORTED",
    )


def test_resolution_cannot_be_caller_asserted_or_advanced_before_availability():
    rows = (
        _quote("NO", status="RESOLVED", resolution_version="res-v1"),
        _quote("YES", status="RESOLVED", resolution_version="res-v1"),
    )
    unknown = _prior(*rows)
    assert "RESOLUTION_UNVERIFIED" in unknown.quality_flags
    assert unknown.confidence == 0
    with pytest.raises(PredictionError) as raw:
        ResolutionEventV1("KALSHI", "contract-1", "YES", "res-v1", ASOF, ASOF, False, "proof")
    assert raw.value.code == "UNVERIFIED_RESOLUTION"

    verified = _issue_recorded_resolution(
        venue="KALSHI",
        contract_id="contract-1",
        winning_outcome_id="YES",
        version="res-v1",
        event_ns=ASOF,
        available_ns=ASOF + 1,
        disputed=False,
        verification_ref="synthetic-proof",
    )
    before = normalize(rows, outcome_ids=OUTCOMES, asof_ns=ASOF, resolution=verified)
    assert "RESOLUTION_UNVERIFIED" in before.quality_flags
    assert "RESOLUTION_VERIFIED" not in before.quality_flags
    assert before.resolution_identity is None
    after = normalize(rows, outcome_ids=OUTCOMES, asof_ns=ASOF + 1, resolution=verified)
    assert tuple(item.probability for item in after.outcomes) == tuple(
        item.probability for item in unknown.outcomes
    )
    assert "RESOLUTION_VERIFIED" not in after.quality_flags
    assert "RESOLUTION_UNVERIFIED" in after.quality_flags
    assert after.resolution_identity is not None

    disputed = _issue_recorded_resolution(
        venue="KALSHI",
        contract_id="contract-1",
        winning_outcome_id=None,
        version="res-v1",
        event_ns=ASOF,
        available_ns=ASOF,
        disputed=True,
        verification_ref="synthetic-dispute",
    )
    contested = normalize(rows, outcome_ids=OUTCOMES, asof_ns=ASOF, resolution=disputed)
    assert "RESOLUTION_DISPUTED" in contested.quality_flags
    assert contested.confidence == 0
    assert "RESOLUTION_VERIFIED" not in contested.quality_flags
    assert all(item.probability not in (Decimal(0), Decimal(1)) for item in contested.outcomes)


def test_synthetic_resolution_identity_is_canonical_and_never_verified():
    rows = (
        _quote("NO", status="RESOLVED", resolution_version="res-v1"),
        _quote("YES", status="RESOLVED", resolution_version="res-v1"),
    )
    evidence_a = _issue_recorded_resolution(
        venue="KALSHI",
        contract_id="contract-1",
        winning_outcome_id="YES",
        version="res-v1",
        event_ns=ASOF - 1,
        available_ns=ASOF - 1,
        disputed=False,
        verification_ref="synthetic-proof-a",
    )
    evidence_b = _issue_recorded_resolution(
        venue="KALSHI",
        contract_id="contract-1",
        winning_outcome_id="YES",
        version="res-v1",
        event_ns=ASOF,
        available_ns=ASOF,
        disputed=False,
        verification_ref="synthetic-proof-b",
    )
    result_a = normalize(rows, outcome_ids=OUTCOMES, asof_ns=ASOF, resolution=evidence_a)
    result_b = normalize(rows, outcome_ids=OUTCOMES, asof_ns=ASOF, resolution=evidence_b)
    assert evidence_a.verification_status == "UNVERIFIED"
    assert evidence_b.verification_status == "UNVERIFIED"
    assert result_a.resolution_identity is not None
    assert result_b.resolution_identity is not None
    assert len(result_a.resolution_identity) == 64
    assert result_a.resolution_identity != result_b.resolution_identity
    assert result_a.result_version != result_b.result_version
    for result in (result_a, result_b):
        assert "RESOLUTION_UNVERIFIED" in result.quality_flags
        assert "RESOLUTION_VERIFIED" not in result.quality_flags
        assert all(item.probability not in (Decimal(0), Decimal(1)) for item in result.outcomes)


def test_mapping_priority_manual_tag_pattern_and_conflict_audit():
    market = PredictionMarketIdentityV1(
        "KALSHI", "contract-1", "Policy change in June", ("policy",), ASOF
    )
    pattern = MappingRuleV1("p", "KALSHI", None, "PATTERN", "Policy", "EVENT-P", "D30", "r1", ASOF)
    tag = MappingRuleV1("t", "KALSHI", None, "EXACT_TAG", "policy", "EVENT-T", "D30", "r1", ASOF)
    manual = MappingRuleV1(
        "m", "KALSHI", "contract-1", "MANUAL", "contract-1", "EVENT-M", "D30", "r1", ASOF
    )
    decision = map_event(market, (pattern, tag, manual), asof_ns=ASOF)
    assert decision.targets == ("EVENT-M",)
    assert decision.priority == "MANUAL"
    assert require_mapping(decision) is decision

    tie = map_event(
        market,
        (tag, replace(tag, rule_id="t2", internal_event_id="EVENT-TWO")),
        asof_ns=ASOF,
    )
    assert tie.status == "CONFLICT"
    assert tie.targets == ()
    assert tie.audit_intents and tie.audit_intents[0].reason == "MAPPING_CONFLICT"
    assert map_event(market, (manual, tag, pattern), asof_ns=ASOF) == decision


def test_market_metadata_requires_an_asof_clock_and_future_metadata_is_rejected():
    rule = MappingRuleV1("tag", "KALSHI", None, "EXACT_TAG", "NEW_TAG", "EV-NEW", "D7", "r1", ASOF)
    with pytest.raises(TypeError):
        PredictionMarketIdentityV1("KALSHI", "contract-1", "New policy", ("NEW_TAG",))
    for missing_clock in (None, True):
        with pytest.raises(PredictionError):
            PredictionMarketIdentityV1(
                "KALSHI", "contract-1", "New policy", ("NEW_TAG",), missing_clock
            )

    future_vintage = PredictionMarketIdentityV1(
        "KALSHI", "contract-1", "New policy", ("NEW_TAG",), ASOF + 1
    )
    with pytest.raises(PredictionError) as caught:
        map_event(future_vintage, (rule,), asof_ns=ASOF)
    assert caught.value.code == "METADATA_NOT_AVAILABLE"
    assert caught.value.field == "market"
    assert map_event(future_vintage, (rule,), asof_ns=ASOF + 1).targets == ("EV-NEW",)


def test_mapping_explicit_manual_group_preserves_each_target_horizon():
    market = PredictionMarketIdentityV1("KALSHI", "contract-1", "Election", ("election",), ASOF)
    rules = (
        MappingRuleV1(
            "m1", "KALSHI", "contract-1", "MANUAL", "contract-1", "EV-A", "D7", "r2", ASOF, "bundle"
        ),
        MappingRuleV1(
            "m2",
            "KALSHI",
            "contract-1",
            "MANUAL",
            "contract-1",
            "EV-B",
            "D30",
            "r2",
            ASOF,
            "bundle",
        ),
    )
    result = map_event(market, rules, asof_ns=ASOF)
    assert result.targets == ("EV-A", "EV-B")
    assert result.target_horizons == (("EV-A", "D7"), ("EV-B", "D30"))


def test_mapping_asof_revision_and_market_identity_are_enforced():
    market = PredictionMarketIdentityV1("KALSHI", "contract-1", "Election", ("election",), ASOF)
    old = MappingRuleV1(
        "rule", "KALSHI", "contract-1", "MANUAL", "contract-1", "EV-OLD", "D7", "r1", ASOF - 1
    )
    future = replace(old, internal_event_id="EV-NEW", revision="r2", available_ns=ASOF + 1)
    before = map_event(market, (old,), asof_ns=ASOF)
    assert map_event(market, (future, old), asof_ns=ASOF) == before
    after = map_event(market, (future, old), asof_ns=ASOF + 1)
    assert after.targets == ("EV-NEW",)
    wrong_market_rule = replace(old, venue="POLYMARKET", rule_id="other")
    assert map_event(market, (wrong_market_rule,), asof_ns=ASOF).targets == ()


@pytest.mark.parametrize(
    ("mutator", "code"),
    [
        (lambda row: replace(row, event_ns=True), "INVALID_INTEGER"),
        (
            lambda row: replace(row, bid=Decimal("0.12345678901234567890123456789012345")),
            "PRECISION_EXCEEDED",
        ),
        (lambda row: replace(row, depth_2pct=Decimal("1e100000")), "MAGNITUDE_OUT_OF_BOUNDS"),
        (lambda row: replace(row, bid=Decimal("0.8"), ask=Decimal("0.7")), "CROSSED_QUOTE"),
    ],
)
def test_numeric_contract_rejects_bool_precision_magnitude_and_invalid_market(mutator, code):
    _raises_code(lambda: mutator(_quote("NO")), code)


def test_decimal_values_and_ambient_context_do_not_change_exact_result():
    rows = (
        _quote("NO", "0.33333333333333333333333333333333"),
        _quote("YES", "0.66666666666666666666666666666667"),
    )
    expected = _prior(*rows)
    with localcontext() as ctx:
        ctx.prec = 6
        ctx.Emax = 6
        assert _prior(*rows) == expected
    assert sum((item.probability for item in expected.outcomes), Decimal(0)) == Decimal(1)


def test_equivalent_decimal_scales_have_the_same_canonical_result_identity():
    ordinary = _prior(_quote("NO", "0.5"), _quote("YES", "0.5"))
    scaled = _prior(_quote("NO", "0.5000"), _quote("YES", "0.50000"))
    assert ordinary == scaled
    assert ordinary.result_version == scaled.result_version


def test_public_typed_errors_do_not_echo_untrusted_text():
    bad = CANARY + " invalid token"
    with pytest.raises(PredictionError) as caught:
        replace(_quote("NO"), source_id=bad)
    err = caught.value
    assert err.code == "INVALID_TOKEN"
    assert bad not in str(err)
    assert bad not in repr(err.args)


def test_frozen_input_records_reject_copy_deepcopy_pickle_and_mutation():
    row = _quote("NO")
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(PredictionError) as caught:
            operation(row)
        assert caught.value.code == "FROZEN_RECORD"
    with pytest.raises((AttributeError, TypeError)):
        row.bid = Decimal("0.1")  # type: ignore[misc]
    with pytest.raises((AttributeError, TypeError)):
        del row.bid  # type: ignore[misc]


def test_prior_issuance_cannot_be_forged_reinitialized_replaced_or_tampered():
    prior = _prior(_quote("NO"), _quote("YES"))
    assert require_prior(prior) is prior
    assert "_issuer" not in NormalizedPriorV1.__slots__
    original_confidence = prior.confidence
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(PredictionError) as caught:
            operation(prior)
        assert caught.value.code == "FROZEN_RECORD"
    with pytest.raises(PredictionError) as caught:
        replace(prior, confidence=Decimal(1))
    assert caught.value.code == "UNISSUED_RESULT"
    assert prior.confidence == original_confidence
    with pytest.raises(PredictionError) as caught:
        NormalizedPriorV1(
            venue=prior.venue,
            contract_id=prior.contract_id,
            outcomes=prior.outcomes,
            source_refs=prior.source_refs,
            confidence=prior.confidence,
            source_ids=prior.source_ids,
            raw_quote_digests=prior.raw_quote_digests,
            access_classes=prior.access_classes,
            quote_age_ns=prior.quote_age_ns,
            conversion_versions=prior.conversion_versions,
            calibration_revision=prior.calibration_revision,
            mapping_revision=prior.mapping_revision,
            quality_flags=prior.quality_flags,
            market_status=prior.market_status,
            asof_ns=prior.asof_ns,
            result_version=prior.result_version,
            resolution_identity=prior.resolution_identity,
            calibration_id=prior.calibration_id,
        )
    assert caught.value.code == "UNISSUED_RESULT"
    with pytest.raises(PredictionError) as caught:
        prior.__init__(
            prior.venue,
            prior.contract_id,
            prior.outcomes,
            prior.source_refs,
            prior.confidence,
            prior.source_ids,
            prior.raw_quote_digests,
            prior.access_classes,
            prior.quote_age_ns,
            prior.conversion_versions,
            prior.calibration_revision,
            prior.mapping_revision,
            prior.quality_flags,
            prior.market_status,
            prior.asof_ns,
            prior.result_version,
        )
    assert caught.value.code == "UNISSUED_RESULT"
    object.__setattr__(prior, "confidence", Decimal(1))
    with pytest.raises(SealError):
        require_prior(prior)


def test_issued_prior_attribute_assignment_and_deletion_are_rejected():
    prior = _prior(_quote("NO"), _quote("YES"))
    with pytest.raises((AttributeError, TypeError)) as assigned:
        prior.confidence = CANARY  # type: ignore[misc]
    assert CANARY not in str(assigned.value)
    with pytest.raises((AttributeError, TypeError)):
        del prior.confidence  # type: ignore[misc]


def test_equal_but_distinct_issued_priors_keep_identity_issuance_after_gc():
    first = _prior(_quote("NO"), _quote("YES"))
    second = _prior(_quote("NO"), _quote("YES"))
    assert first == second
    assert first is not second
    assert require_prior(first) is first
    assert require_prior(second) is second
    del first
    gc.collect()
    assert require_prior(second) is second


def test_mapping_issuance_is_required_and_future_or_tied_replay_is_deterministic():
    market = PredictionMarketIdentityV1("KALSHI", "contract-1", "Policy", ("policy",), ASOF)
    rule = MappingRuleV1("r", "KALSHI", None, "EXACT_TAG", "policy", "EV-1", "D7", "v1", ASOF)
    result = map_event(market, (rule,), asof_ns=ASOF)
    assert require_mapping(result) is result
    assert map_event(market, (rule,), asof_ns=ASOF) == result
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(PredictionError):
            operation(result)
    with pytest.raises(PredictionError) as caught:
        replace(result, targets=("FORGED",))
    assert caught.value.code == "UNISSUED_RESULT"
    with pytest.raises(PredictionError) as caught:
        MappingDecisionV1(
            venue=result.venue,
            contract_id=result.contract_id,
            status=result.status,
            targets=result.targets,
            target_horizons=result.target_horizons,
            priority=result.priority,
            matched_rule_ids=result.matched_rule_ids,
            audit_intents=result.audit_intents,
            mapping_revision=result.mapping_revision,
            asof_ns=result.asof_ns,
            result_version=result.result_version,
        )
    assert caught.value.code == "UNISSUED_RESULT"


@pytest.mark.parametrize("foreign_kind", ["contract", "outcome"])
def test_future_foreign_or_unexpected_outcome_rows_cannot_reject_earlier_asof(foreign_kind):
    base = (_quote("NO"), _quote("YES"))
    future = replace(
        base[1],
        contract_id="another-contract" if foreign_kind == "contract" else base[1].contract_id,
        outcome_id="THIRD" if foreign_kind == "outcome" else base[1].outcome_id,
        event_ns=ASOF + 1,
        received_ns=ASOF + 2,
        available_ns=ASOF + 3,
    )
    earlier = _prior(*base)
    after_insertion = _prior(*base, future)
    assert after_insertion == earlier
    assert after_insertion.result_version == earlier.result_version


def test_prior_reinitialization_rejects_before_any_field_changes():
    prior = _prior(_quote("NO"), _quote("YES"))
    with pytest.raises(PredictionError):
        values = {field.name: getattr(prior, field.name) for field in fields(prior)}
        values["contract_id"] = "other-contract"
        prior.__init__(**values)
    assert prior.contract_id == "contract-1"
    assert require_prior(prior) is prior


def test_mapping_reinitialization_rejects_before_any_field_changes():
    market = PredictionMarketIdentityV1("KALSHI", "contract-1", "Policy", ("policy",), ASOF)
    rule = MappingRuleV1("r", "KALSHI", None, "EXACT_TAG", "policy", "EV-1", "D7", "v1", ASOF)
    decision = map_event(market, (rule,), asof_ns=ASOF)
    with pytest.raises(PredictionError):
        values = {field.name: getattr(decision, field.name) for field in fields(decision)}
        values["contract_id"] = "other-contract"
        decision.__init__(**values)
    assert decision.contract_id == "contract-1"
    assert require_mapping(decision) is decision


def test_resolution_reinitialization_rejects_before_any_field_changes():
    resolution = _issue_recorded_resolution(
        venue="KALSHI",
        contract_id="contract-1",
        winning_outcome_id="YES",
        version="res-v1",
        event_ns=ASOF,
        available_ns=ASOF,
        disputed=False,
        verification_ref="synthetic-proof",
    )
    with pytest.raises(PredictionError):
        values = {field.name: getattr(resolution, field.name) for field in fields(resolution)}
        values["contract_id"] = "other-contract"
        resolution.__init__(**values)
    assert resolution.contract_id == "contract-1"
    resolved_rows = (
        _quote("NO", status="RESOLVED", resolution_version="res-v1"),
        _quote("YES", status="RESOLVED", resolution_version="res-v1"),
    )
    assert (
        "RESOLUTION_UNVERIFIED"
        in normalize(
            resolved_rows, outcome_ids=OUTCOMES, asof_ns=ASOF, resolution=resolution
        ).quality_flags
    )


def test_fx_reference_encoding_distinguishes_colon_colliding_id_version_pairs():
    rows = (_quote("NO", currency="USDC"), _quote("YES", currency="USDC"))
    first = FXRateV1("USDC", "USD", Decimal("1"), QUOTE - 1, QUOTE - 1, "a:b", "c")
    second = FXRateV1("USDC", "USD", Decimal("1"), QUOTE - 1, QUOTE - 1, "a", "b:c")
    result_first = _prior(*rows, fx_rates=(first,))
    result_second = _prior(*rows, fx_rates=(second,))
    assert result_first.source_refs != result_second.source_refs
    assert result_first.result_version != result_second.result_version


def test_quote_iterator_stops_at_257th_item_with_content_free_limit_error():
    quote = _quote("NO")
    consumed_quotes = 0

    def quote_rows():
        nonlocal consumed_quotes
        for _ in range(257):
            consumed_quotes += 1
            yield quote
        raise RuntimeError(CANARY)

    with pytest.raises(PredictionError) as quote_error:
        normalize(quote_rows(), outcome_ids=OUTCOMES, asof_ns=ASOF)
    assert consumed_quotes == 257
    assert CANARY not in str(quote_error.value)
    assert CANARY not in repr(quote_error.value.args)


def test_rule_iterator_stops_at_257th_item_with_content_free_limit_error():
    market = PredictionMarketIdentityV1("KALSHI", "contract-1", "Policy", ("policy",), ASOF)
    rule = MappingRuleV1("r", "KALSHI", None, "EXACT_TAG", "policy", "EV-1", "D7", "v1", ASOF)
    consumed_rules = 0

    def rules():
        nonlocal consumed_rules
        for _ in range(257):
            consumed_rules += 1
            yield rule
        raise RuntimeError(CANARY)

    with pytest.raises(PredictionError) as rule_error:
        map_event(market, rules(), asof_ns=ASOF)
    assert consumed_rules == 257
    assert CANARY not in str(rule_error.value)
    assert CANARY not in repr(rule_error.value.args)


def test_identity_calibration_cannot_claim_an_unbound_model_revision():
    result = _prior(_quote("NO"), _quote("YES"))
    assert result.calibration_revision == "identity-v1"
    with pytest.raises(PredictionError):
        normalize(
            (_quote("NO"), _quote("YES")),
            outcome_ids=OUTCOMES,
            asof_ns=ASOF,
            calibration_id="IDENTITY",
            calibration_revision="platt-v99",
        )
