from __future__ import annotations

from datetime import UTC, datetime

import pytest

from leviathan_api.public_sources_intel import (
    NormalizedPublicFactorV1,
    PublicFactorScoreAdapterV1,
    issue_public_as_of_context,
)
from leviathan_core.intel.models import FactorAbstentionV1, FactorScoreV1, unix_ns
from leviathan_market_data.public_sources import PublicEvidenceV1, PublicSourceError

NOW = datetime(2026, 10, 9, 12, tzinfo=UTC)


def record(*, knowable_at: datetime | None = NOW) -> PublicEvidenceV1:
    return PublicEvidenceV1(
        source_tier=1,
        source_id="sec.edgar.form4",
        record_id="0001:accession:1",
        fetched_at=NOW,
        as_of=datetime(2026, 10, 8, tzinfo=UTC),
        knowable_at=knowable_at,
        factor_tags=("insider_activity",),
        values=(("transaction_code", "P"),),
    )


def test_public_evidence_binds_to_issued_factor_score() -> None:
    evidence = record()
    context = issue_public_as_of_context(
        (evidence,), decision_as_of_ns=unix_ns(NOW), freshness="fresh"
    )
    snapshot = NormalizedPublicFactorV1(
        factor_id="public.insider_activity.v1",
        family="insider",
        instrument="XYZ",
        venue="SEC",
        decision_as_of_ns=unix_ns(NOW),
        source_event_ns=unix_ns(evidence.as_of),
        direction="long",
        strength="0.5",
        reliability="0.8",
        method="public.insider.transaction-code",
        method_version="1",
        evidence=(evidence,),
        freshness="fresh",
    )
    result = PublicFactorScoreAdapterV1().evaluate(snapshot, context)
    assert isinstance(result, FactorScoreV1)
    assert result.evidence_refs[0].record_digest == evidence.record_digest
    assert result.evidence_refs[0].as_of_ns == unix_ns(evidence.knowable_at)  # type: ignore[arg-type]


def test_public_factor_missing_knowable_time_abstains() -> None:
    evidence = record(knowable_at=None)
    context = issue_public_as_of_context(
        (evidence,), decision_as_of_ns=unix_ns(NOW), freshness="fresh"
    )
    snapshot = NormalizedPublicFactorV1(
        factor_id="public.insider_activity.v1",
        family="insider",
        instrument="XYZ",
        venue="SEC",
        decision_as_of_ns=unix_ns(NOW),
        source_event_ns=unix_ns(evidence.as_of),
        direction="long",
        strength="0.5",
        reliability="0.8",
        method="public.insider.transaction-code",
        method_version="1",
        evidence=(evidence,),
        freshness="fresh",
    )
    result = PublicFactorScoreAdapterV1().evaluate(snapshot, context)
    assert isinstance(result, FactorAbstentionV1)
    assert result.freshness == "unknown"


def test_public_context_rejects_future_observation_time() -> None:
    later = NOW.replace(day=10)
    with pytest.raises(PublicSourceError, match="FUTURE_DATED_EVIDENCE"):
        future = PublicEvidenceV1(
            1,
            "sec.edgar.form4",
            "future",
            NOW,
            later,
            NOW,
            ("insider_activity",),
            (),
        )
        issue_public_as_of_context((future,), decision_as_of_ns=unix_ns(NOW), freshness="fresh")
