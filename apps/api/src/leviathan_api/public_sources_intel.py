"""Vault-backed source client construction and issued FactorScoreV1 binding."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

from leviathan_core.intel.models import (
    AsOfContextV1,
    Direction,
    EvidenceRefV1,
    FactorAbstentionV1,
    FactorFamily,
    FactorFreshnessPolicyV1,
    FactorOutcomeV1,
    FactorScoreV1,
    Freshness,
    issue_as_of_context,
    require_as_of_context,
    unix_ns,
)
from leviathan_market_data.public_sources import (
    PublicEvidenceV1,
    PublicSourceError,
    PublicSourcesClient,
)

from .market_data_runtime_config import MarketDataRuntimeConfigV1

VaultRefResolver = Callable[[str, str], str]


def create_public_sources_client(
    config: MarketDataRuntimeConfigV1,
    *,
    vault_ref_resolver: VaultRefResolver | None,
) -> PublicSourcesClient:
    """Create only from startup config; FINRA secrets are resolved through project vault refs."""
    if type(config) is not MarketDataRuntimeConfigV1 or not config.public_sources.enabled:
        raise PublicSourceError("PUBLIC_SOURCES_DISABLED")
    settings = config.public_sources
    if settings.sec_user_agent is None:
        raise PublicSourceError("SEC_USER_AGENT_REQUIRED")
    return PublicSourcesClient.from_vault(
        sec_user_agent=settings.sec_user_agent,
        vault_ref_resolver=vault_ref_resolver,
        finra_enabled=settings.finra_enabled,
        sec_rate_per_second=settings.sec_requests_per_second,
        http_timeout_seconds=settings.http_timeout_seconds,
        http_max_retries=settings.http_max_retries,
        coinbase_derivatives_enabled=settings.coinbase_derivatives_enabled,
    )


def evidence_ref_from_public_source(value: PublicEvidenceV1) -> EvidenceRefV1:
    """Bind a source-native event/availability pair and digest into INTEL's contract."""
    if type(value) is not PublicEvidenceV1 or value.redistribution is not False:
        raise PublicSourceError("INVALID_PUBLIC_EVIDENCE")
    if value.knowable_at is None:
        raise PublicSourceError("UNKNOWN_AVAILABILITY")
    return EvidenceRefV1(
        source=value.source_id,
        record_digest=value.record_digest,
        as_of_ns=unix_ns(value.knowable_at),
        source_event_ns=unix_ns(value.as_of),
        source_record_key=value.record_id,
        native_sequence=value.native_sequence,
        provider_session_id=value.provider_session_id,
    )


def issue_public_as_of_context(
    records: tuple[PublicEvidenceV1, ...], *, decision_as_of_ns: int, freshness: Freshness
) -> AsOfContextV1:
    """Issue a bounded and chronologically checked context for public-source factors."""
    if type(records) is not tuple or len(records) > 128:
        raise PublicSourceError("TOO_MANY_EVIDENCE_REFS")
    available_records = tuple(row for row in records if row.knowable_at is not None)
    effective_freshness = "unknown" if len(available_records) != len(records) else freshness
    refs = tuple(
        sorted(
            (evidence_ref_from_public_source(row) for row in available_records),
            key=lambda ref: (ref.source, ref.record_digest),
        )
    )
    if len({(ref.source, ref.record_digest) for ref in refs}) != len(refs):
        raise PublicSourceError("DUPLICATE_EVIDENCE_REF")
    try:
        return issue_as_of_context(
            decision_as_of_ns=decision_as_of_ns,
            freshness=effective_freshness,
            evidence_refs=refs,
        )
    except ValueError as exc:
        if "FUTURE" in str(exc):
            raise PublicSourceError("FUTURE_DATED_EVIDENCE") from None
        raise PublicSourceError("INVALID_ASOF_CONTEXT") from None


@dataclass(frozen=True, slots=True)
class NormalizedPublicFactorV1:
    """Already normalized factor values paired with source records and a sealed context."""

    factor_id: str
    family: FactorFamily
    instrument: str
    venue: str
    decision_as_of_ns: int
    source_event_ns: int
    direction: Direction
    strength: str
    reliability: str
    method: str
    method_version: str
    evidence: tuple[PublicEvidenceV1, ...]
    freshness: Freshness


class PublicFactorScoreAdapterV1:
    """Turn a normalized public-source snapshot into FactorScore or fail-closed abstention."""

    def evaluate(
        self,
        snapshot: NormalizedPublicFactorV1,
        context: AsOfContextV1,
        policy: FactorFreshnessPolicyV1 | None = None,
    ) -> FactorOutcomeV1:
        if type(snapshot) is not NormalizedPublicFactorV1:
            raise PublicSourceError("INVALID_FACTOR_SNAPSHOT")
        issued = require_as_of_context(context)
        expected = issue_public_as_of_context(
            snapshot.evidence,
            decision_as_of_ns=snapshot.decision_as_of_ns,
            freshness=snapshot.freshness,
        )
        if (
            issued.decision_as_of_ns != expected.decision_as_of_ns
            or issued.freshness != expected.freshness
            or issued.evidence_refs != expected.evidence_refs
            or snapshot.source_event_ns > snapshot.decision_as_of_ns
        ):
            raise PublicSourceError("FACTOR_CONTEXT_MISMATCH")
        selected = policy or FactorFreshnessPolicyV1(
            factor_id=snapshot.factor_id,
            policy_version="public-source/1",
            allow_unknown_freshness=False,
        )
        if (
            type(selected) is not FactorFreshnessPolicyV1
            or selected.factor_id != snapshot.factor_id
        ):
            raise PublicSourceError("FACTOR_FRESHNESS_POLICY_MISMATCH")
        reason: (
            Literal[
                "MISSING_EVIDENCE", "STALE_EVIDENCE", "UNKNOWN_FRESHNESS", "INSUFFICIENT_EVIDENCE"
            ]
            | None
        ) = None
        if issued.freshness == "unknown" and not selected.allow_unknown_freshness:
            reason = "UNKNOWN_FRESHNESS"
        elif not issued.evidence_refs:
            reason = "MISSING_EVIDENCE"
        elif issued.freshness == "stale":
            reason = "STALE_EVIDENCE"
        if reason is not None:
            return FactorAbstentionV1(
                factor_id=snapshot.factor_id,
                family=snapshot.family,
                instrument=snapshot.instrument,
                venue=snapshot.venue,
                as_of_ns=issued.decision_as_of_ns,
                source_event_ns=snapshot.source_event_ns,
                freshness=issued.freshness,
                method=snapshot.method,
                method_version=snapshot.method_version,
                evidence_refs=issued.evidence_refs,
                reason=reason,
                freshness_policy_version=selected.policy_version,
                freshness_policy=selected if selected.allow_unknown_freshness else None,
                unknown_freshness_allowed=selected.allow_unknown_freshness
                and issued.freshness == "unknown",
            )
        return FactorScoreV1(
            factor_id=snapshot.factor_id,
            family=snapshot.family,
            instrument=snapshot.instrument,
            venue=snapshot.venue,
            as_of_ns=issued.decision_as_of_ns,
            source_event_ns=snapshot.source_event_ns,
            freshness=issued.freshness,
            method=snapshot.method,
            method_version=snapshot.method_version,
            evidence_refs=issued.evidence_refs,
            direction=snapshot.direction,
            strength=snapshot.strength,
            reliability=snapshot.reliability,
            freshness_policy_version=selected.policy_version,
            freshness_policy=selected if selected.allow_unknown_freshness else None,
            unknown_freshness_allowed=selected.allow_unknown_freshness
            and issued.freshness == "unknown",
        )


__all__ = [
    "NormalizedPublicFactorV1",
    "PublicFactorScoreAdapterV1",
    "create_public_sources_client",
    "evidence_ref_from_public_source",
    "issue_public_as_of_context",
]
