from __future__ import annotations

from datetime import UTC, datetime

import pytest

from leviathan_api.public_source_factor_adapters import PublicSourceFactorAdapterV1
from leviathan_core.intel.models import (
    FactorAbstentionV1,
    FactorFreshnessPolicyV1,
    FactorScoreV1,
    unix_ns,
)
from leviathan_market_data.public_sources import PublicEvidenceV1, PublicSourceError

NOW = datetime(2026, 10, 9, 12, tzinfo=UTC)


def evidence(
    source_id: str,
    values: tuple[tuple[str, str], ...],
    *,
    knowable_at: datetime | None = NOW,
    fetched_at: datetime = NOW,
    as_of: datetime = datetime(2026, 10, 8, tzinfo=UTC),
    tags: tuple[str, ...] = (),
) -> PublicEvidenceV1:
    if not tags:
        tags = {
            "sec.edgar.form4": ("insider_activity",),
            "sec.edgar.13f": ("insider_activity",),
            "sec.edgar.13dg": ("insider_activity",),
            "house.ptr.bulk": ("political_trades", "insider_activity"),
            "finra.ats_weekly": ("dark_pool", "off_exchange"),
            "finra.otc.weekly": ("dark_pool", "off_exchange"),
            "finra.regsho.daily": ("short_activity",),
            "finra.short_interest": ("short_activity",),
            "cftc.cot.legacy": ("positioning",),
            "treasury.yield_curve": ("rates_macro",),
            "treasury.fiscal_data": ("rates_macro",),
            "nyfed.markets": ("rates_macro",),
            "bls.public_api": ("rates_macro",),
            "fed.fomc": ("rates_macro",),
            "coinbase.derivatives_us": ("positioning",),
        }[source_id]
    return PublicEvidenceV1(
        1,
        source_id,
        "record-1",
        fetched_at,
        as_of,
        knowable_at,
        tags,
        values,
    )


def test_form4_open_market_transaction_emits_factor_score_with_digest() -> None:
    record = evidence(
        "sec.edgar.form4",
        (
            ("cik", "0000000001"),
            ("transaction_code", "P"),
            ("shares", "100"),
            ("price", "10"),
        ),
    )
    outcome = PublicSourceFactorAdapterV1().evaluate_record(
        record, decision_as_of_ns=unix_ns(NOW), freshness="fresh"
    )
    assert isinstance(outcome, FactorScoreV1)
    assert outcome.factor_id == "public.sec.edgar.form4.insider_activity.v1"
    assert outcome.family == "insider"
    assert outcome.direction == "long"
    assert outcome.strength == "0.000999000999000999000999000999"
    assert outcome.evidence_refs[0].record_digest == record.record_digest
    assert outcome.evidence_refs[0].source_record_key == record.record_id
    assert outcome.evidence_refs[0].source_event_ns == unix_ns(record.as_of)
    assert outcome.evidence_refs[0].as_of_ns == unix_ns(record.knowable_at)  # type: ignore[arg-type]


def test_form4_non_open_market_transaction_abstains() -> None:
    record = evidence(
        "sec.edgar.form4",
        (("transaction_code", "A"), ("shares", "100"), ("price", "10")),
    )
    outcome = PublicSourceFactorAdapterV1().evaluate_record(
        record, decision_as_of_ns=unix_ns(NOW), freshness="fresh"
    )
    assert isinstance(outcome, FactorAbstentionV1)
    assert outcome.reason == "INSUFFICIENT_EVIDENCE"


def test_regsho_volume_ratio_is_neutral_activity_not_directional_alpha() -> None:
    record = evidence(
        "finra.regsho.daily",
        (("symbol", "XYZ"), ("short_volume", "100"), ("total_volume", "400")),
    )
    outcome = PublicSourceFactorAdapterV1().evaluate_record(
        record, decision_as_of_ns=unix_ns(NOW), freshness="fresh"
    )
    assert isinstance(outcome, FactorScoreV1)
    assert outcome.factor_id == "public.finra.regsho.daily.short_activity.v1"
    assert outcome.family == "volume"
    assert outcome.direction == "neutral"
    assert outcome.strength == "0.25"


def test_finra_short_interest_uses_change_and_keeps_sign_explicit() -> None:
    record = evidence(
        "finra.short_interest",
        (
            ("issueSymbolIdentifier", "XYZ"),
            ("currentShortPositionQuantity", "150"),
            ("previousShortPositionQuantity", "100"),
        ),
    )
    outcome = PublicSourceFactorAdapterV1().evaluate_record(
        record, decision_as_of_ns=unix_ns(NOW), freshness="fresh"
    )
    assert isinstance(outcome, FactorScoreV1)
    assert outcome.family == "volume"
    assert outcome.direction == "short"
    assert outcome.strength == "0.2"


def test_dark_pool_weekly_total_abstains_without_signed_flow() -> None:
    record = evidence(
        "finra.ats_weekly",
        (("symbol", "XYZ"), ("shares", "1000000"), ("trades", "200")),
    )
    outcome = PublicSourceFactorAdapterV1().evaluate_record(
        record, decision_as_of_ns=unix_ns(NOW), freshness="fresh"
    )
    assert isinstance(outcome, FactorAbstentionV1)
    assert outcome.factor_id == "public.finra.ats_weekly.dark_pool.v1"
    assert outcome.family == "dark_pool"
    assert outcome.reason == "INSUFFICIENT_EVIDENCE"


def test_cot_net_positions_are_normalized_by_open_interest() -> None:
    record = evidence(
        "cftc.cot.legacy",
        (
            ("contract_code", "000001"),
            ("commercial_long", "400"),
            ("commercial_short", "350"),
            ("open_interest", "1000"),
        ),
    )
    outcome = PublicSourceFactorAdapterV1().evaluate_record(
        record, decision_as_of_ns=unix_ns(NOW), freshness="fresh"
    )
    assert isinstance(outcome, FactorScoreV1)
    assert outcome.factor_id == "public.cftc.cot.legacy.positioning.v1"
    assert outcome.family == "macro"
    assert outcome.direction == "long"
    assert outcome.strength == "0.05"


def test_rates_observation_and_sec_filing_metadata_abstain_without_a_defensible_factor() -> None:
    adapter = PublicSourceFactorAdapterV1()
    for record in (
        evidence("treasury.yield_curve", (("BC_10YEAR", "4.10"),)),
        evidence("sec.edgar.13f", (("form", "13F-HR"), ("reportDate", "2026-09-30"))),
    ):
        outcome = adapter.evaluate_record(
            record, decision_as_of_ns=unix_ns(NOW), freshness="fresh"
        )
        assert isinstance(outcome, FactorAbstentionV1)
        assert outcome.reason == "INSUFFICIENT_EVIDENCE"


def test_unknown_availability_abstains_and_future_evidence_hard_fails() -> None:
    adapter = PublicSourceFactorAdapterV1()
    unknown = evidence(
        "finra.regsho.daily",
        (("symbol", "XYZ"), ("short_volume", "100"), ("total_volume", "400")),
        knowable_at=None,
    )
    result = adapter.evaluate_record(
        unknown, decision_as_of_ns=unix_ns(NOW), freshness="fresh"
    )
    assert isinstance(result, FactorAbstentionV1)
    assert result.freshness == "unknown"
    assert result.reason == "UNKNOWN_FRESHNESS"
    future = evidence(
        "finra.regsho.daily",
        (("symbol", "XYZ"), ("short_volume", "100"), ("total_volume", "400")),
        fetched_at=datetime(2026, 10, 10, tzinfo=UTC),
        as_of=datetime(2026, 10, 10, tzinfo=UTC),
    )
    with pytest.raises(PublicSourceError, match="FUTURE_DATED_EVIDENCE"):
        adapter.evaluate_record(future, decision_as_of_ns=unix_ns(NOW), freshness="fresh")


def test_coinbase_funding_sign_is_the_futures_payment_side() -> None:
    record = evidence(
        "coinbase.derivatives_us",
        (("symbol", "BIPZ30"), ("funding_rate", "0.0001")),
        tags=("positioning", "crypto_market"),
    )
    outcome = PublicSourceFactorAdapterV1().evaluate_record(
        record, decision_as_of_ns=unix_ns(NOW), freshness="fresh"
    )
    assert isinstance(outcome, FactorScoreV1)
    assert outcome.factor_id == "public.coinbase.derivatives_us.crypto_funding.v1"
    assert outcome.direction == "short"
    assert outcome.strength == "0.0001"


def test_record_batch_is_independent_and_bounded() -> None:
    record = evidence(
        "finra.regsho.daily",
        (("symbol", "XYZ"), ("short_volume", "100"), ("total_volume", "400")),
    )
    outcomes = PublicSourceFactorAdapterV1().evaluate_records(
        (record, record), decision_as_of_ns=unix_ns(NOW), freshness="fresh"
    )
    assert len(outcomes) == 2
    with pytest.raises(PublicSourceError, match="TOO_MANY_EVIDENCE_REFS"):
        PublicSourceFactorAdapterV1().evaluate_records(
            (record,) * 129, decision_as_of_ns=unix_ns(NOW), freshness="fresh"
        )


def test_freshness_policy_must_bind_the_source_specific_factor_id() -> None:
    record = evidence(
        "finra.regsho.daily",
        (("symbol", "XYZ"), ("short_volume", "100"), ("total_volume", "400")),
    )
    wrong_policy = FactorFreshnessPolicyV1(
        factor_id="public.finra.short_interest.short_activity.v1",
        policy_version="test/1",
        allow_unknown_freshness=False,
    )
    with pytest.raises(PublicSourceError, match="FACTOR_FRESHNESS_POLICY_MISMATCH"):
        PublicSourceFactorAdapterV1().evaluate_record(
            record,
            decision_as_of_ns=unix_ns(NOW),
            freshness="fresh",
            policy=wrong_policy,
        )
