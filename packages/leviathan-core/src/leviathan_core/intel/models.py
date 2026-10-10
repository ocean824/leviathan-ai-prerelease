"""Immutable point-in-time factor contracts and provenance adapters."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Literal, Protocol

from pydantic import Field, field_validator, model_validator

from leviathan_core.decision_fusion.models import FusionModelV1, LayerObservationV1
from leviathan_core.feature_store.models import FeatureResultV1, require_feature_result
from leviathan_core.numeric import canonical_json
from leviathan_core.seal import Issuer, SealError, require

FactorFamily = Literal[
    "book_l2_l3",
    "order_flow",
    "structure",
    "volume",
    "momentum",
    "gex",
    "dex",
    "dark_pool",
    "insider",
    "macro",
    "regime",
    "indicator",
    "prediction_market",
    "doctrine",
]
Direction = Literal["long", "short", "neutral"]
Freshness = Literal["fresh", "stale", "unknown"]
AbstentionReason = Literal[
    "MISSING_EVIDENCE",
    "STALE_EVIDENCE",
    "UNKNOWN_FRESHNESS",
    "INSUFFICIENT_EVIDENCE",
    "MISSING_DELTA",
    "KERNEL_REJECTED",
]

_CONTEXT_TAG = "intel001.asof_context.v1"
_CONTEXT_ISSUER = Issuer(_CONTEXT_TAG)


def _identifier(value: str) -> str:
    if not value or len(value) > 128 or value != value.strip():
        raise ValueError("INVALID_INTEL_INPUT")
    if any(not (char.isascii() and (char.isalnum() or char in "._:-/")) for char in value):
        raise ValueError("INVALID_INTEL_INPUT")
    return value


class EvidenceRefV1(FusionModelV1):
    """A bounded source reference; issuer fields preserve existing seal provenance."""

    source: str
    record_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    as_of_ns: int = Field(ge=0)
    source_event_ns: int = Field(ge=0)
    source_record_key: str | None = None
    native_sequence: int | None = None
    provider_session_id: str | None = None
    issuer_tag: str | None = None
    seal_reference: str | None = None

    @field_validator("source", "issuer_tag", "seal_reference")
    @classmethod
    def _validate_identifiers(cls, value: str | None) -> str | None:
        return _identifier(value) if value is not None else None

    @field_validator("source_record_key", "provider_session_id")
    @classmethod
    def _optional_ids(cls, value: str | None) -> str | None:
        return _identifier(value) if value is not None else None

    @field_validator("as_of_ns", "source_event_ns", mode="before")
    @classmethod
    def _exact_ns(cls, value: object) -> object:
        if type(value) is not int or value < 0:
            raise ValueError("INVALID_INTEL_TIME")
        return value

    @field_validator("native_sequence", mode="before")
    @classmethod
    def _exact_sequence(cls, value: object) -> object:
        if value is not None and (type(value) is not int or value < 0):
            raise ValueError("INVALID_INTEL_SEQUENCE")
        return value

    @model_validator(mode="after")
    def _seal_reference_pair(self) -> EvidenceRefV1:
        if (self.issuer_tag is None) != (self.seal_reference is None):
            raise ValueError("INVALID_SEAL_REFERENCE")
        return self


class AsOfContextV1(FusionModelV1):
    """Issued decision-time view wrapping existing kernel evidence references."""

    decision_as_of_ns: int = Field(ge=0)
    freshness: Freshness
    evidence_refs: tuple[EvidenceRefV1, ...]

    @field_validator("decision_as_of_ns", mode="before")
    @classmethod
    def _exact_as_of(cls, value: object) -> object:
        if type(value) is not int or value < 0:
            raise ValueError("INVALID_INTEL_TIME")
        return value

    @model_validator(mode="after")
    def _bounded_evidence(self) -> AsOfContextV1:
        if len(self.evidence_refs) > 128:
            raise ValueError("TOO_MANY_EVIDENCE_REFS")
        if any(
            ref.as_of_ns > self.decision_as_of_ns or ref.source_event_ns > self.decision_as_of_ns
            for ref in self.evidence_refs
        ):
            raise ValueError("FUTURE_EVIDENCE")
        keys = tuple((ref.source, ref.record_digest) for ref in self.evidence_refs)
        if keys != tuple(sorted(set(keys))):
            raise ValueError("EVIDENCE_ORDER_INVALID")
        return self


class AsOfContextError(ValueError):
    code = "ASOF_CONTEXT_UNTRUSTED"

    def __init__(self) -> None:
        super().__init__(self.code)


class FutureEvidenceError(ValueError):
    code = "FUTURE_EVIDENCE"

    def __init__(self) -> None:
        super().__init__(self.code)


class FactorFreshnessPolicyV1(FusionModelV1):
    """Explicit versioned policy for whether a factor may score unknown freshness."""

    factor_id: str
    policy_version: str
    allow_unknown_freshness: bool = False

    @field_validator("factor_id", "policy_version")
    @classmethod
    def _policy_identifiers(cls, value: str) -> str:
        return _identifier(value)

    @field_validator("allow_unknown_freshness", mode="before")
    @classmethod
    def _strict_policy_bool(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("INVALID_INTEL_INPUT")
        return value


def issue_as_of_context(
    *,
    decision_as_of_ns: int,
    freshness: Freshness,
    evidence_refs: tuple[EvidenceRefV1, ...],
) -> AsOfContextV1:
    """Validate and seal a point-in-time wrapper without replacing source issuers."""
    if type(decision_as_of_ns) is not int or decision_as_of_ns < 0:
        raise ValueError("INVALID_INTEL_TIME")
    if any(
        ref.as_of_ns > decision_as_of_ns or ref.source_event_ns > decision_as_of_ns
        for ref in evidence_refs
    ):
        raise FutureEvidenceError()
    context = AsOfContextV1(
        decision_as_of_ns=decision_as_of_ns,
        freshness=freshness,
        evidence_refs=evidence_refs,
    )
    return _CONTEXT_ISSUER.issue(context)


def require_as_of_context(value: object) -> AsOfContextV1:
    if type(value) is not AsOfContextV1:
        raise AsOfContextError()
    try:
        require(value, _CONTEXT_TAG)
    except SealError:
        raise AsOfContextError() from None
    return value


def evidence_from_feature_result(value: FeatureResultV1) -> EvidenceRefV1 | None:
    """Use FEAT-001's issued observation hash and seal rather than re-hashing it."""
    issued = require_feature_result(value)
    if not issued.found or issued.observation_hash is None or issued.event_time_ns is None:
        return None
    return EvidenceRefV1(
        source=f"feature:{issued.feature_name}:{issued.feature_version}",
        record_digest=issued.observation_hash,
        as_of_ns=issued.availability_ns if issued.availability_ns is not None else issued.asof_ns,
        source_event_ns=issued.event_time_ns,
        issuer_tag="feat001.feature_result.v1",
        seal_reference=issued.observation_hash,
    )


def evidence_from_payload(
    *, source: str, payload: object, source_event_ns: int, as_of_ns: int
) -> EvidenceRefV1:
    """Create deterministic evidence for kernels without a public issuance registry."""
    digest = hashlib.sha256(canonical_json(payload)).hexdigest()
    return EvidenceRefV1(
        source=source,
        record_digest=digest,
        as_of_ns=as_of_ns,
        source_event_ns=source_event_ns,
    )


class _NormalizedMarketEvent(Protocol):
    @property
    def provider(self) -> str: ...

    @property
    def dataset(self) -> str: ...

    @property
    def venue(self) -> str: ...

    @property
    def event_time_ns(self) -> int: ...

    @property
    def source_time_ns(self) -> int | None: ...

    @property
    def received_time_ns(self) -> int: ...

    @property
    def native_sequence(self) -> int | None: ...

    @property
    def provider_session_id(self) -> str | None: ...

    @property
    def source_record_key(self) -> str | None: ...

    @property
    def source_payload_sha256(self) -> str: ...


def evidence_from_normalized_event(value: _NormalizedMarketEvent) -> EvidenceRefV1:
    """Carry MD's source digest, sequence and source time without re-deriving identity."""
    source_time = value.source_time_ns if value.source_time_ns is not None else value.event_time_ns
    return EvidenceRefV1(
        source=f"market-data:{value.provider}:{value.dataset}:{value.venue}",
        record_digest=value.source_payload_sha256,
        as_of_ns=value.received_time_ns,
        source_event_ns=source_time,
        source_record_key=value.source_record_key,
        native_sequence=value.native_sequence,
        provider_session_id=value.provider_session_id,
    )


class _FactorOutcomeV1(FusionModelV1):
    factor_id: str
    family: FactorFamily
    instrument: str
    venue: str
    as_of_ns: int = Field(ge=0)
    source_event_ns: int = Field(ge=0)
    freshness: Freshness
    unknown_freshness_allowed: bool = False
    freshness_policy_version: str = "default/1"
    freshness_policy: FactorFreshnessPolicyV1 | None = None
    method: str
    method_version: str
    evidence_refs: tuple[EvidenceRefV1, ...]

    @field_validator(
        "factor_id", "instrument", "venue", "method", "method_version", "freshness_policy_version"
    )
    @classmethod
    def _ids(cls, value: str) -> str:
        return _identifier(value)

    @field_validator("as_of_ns", "source_event_ns", mode="before")
    @classmethod
    def _times(cls, value: object) -> object:
        if type(value) is not int or value < 0:
            raise ValueError("INVALID_INTEL_TIME")
        return value

    @model_validator(mode="after")
    def _chronology(self) -> _FactorOutcomeV1:
        if self.source_event_ns > self.as_of_ns:
            raise ValueError("FUTURE_EVIDENCE")
        if any(
            ref.as_of_ns > self.as_of_ns or ref.source_event_ns > self.as_of_ns
            for ref in self.evidence_refs
        ):
            raise ValueError("FUTURE_EVIDENCE")
        if type(self.unknown_freshness_allowed) is not bool:
            raise ValueError("INVALID_INTEL_INPUT")
        if self.freshness_policy is not None and (
            type(self.freshness_policy) is not FactorFreshnessPolicyV1
            or self.freshness_policy.factor_id != self.factor_id
            or self.freshness_policy.policy_version != self.freshness_policy_version
        ):
            raise ValueError("FACTOR_FRESHNESS_POLICY_MISMATCH")
        if self.unknown_freshness_allowed and self.freshness != "unknown":
            raise ValueError("UNKNOWN_FRESHNESS_POLICY_MISMATCH")
        if self.unknown_freshness_allowed and (
            self.freshness_policy is None or not self.freshness_policy.allow_unknown_freshness
        ):
            raise ValueError("UNKNOWN_FRESHNESS_REQUIRES_POLICY")
        if (
            self.freshness == "unknown"
            and not self.unknown_freshness_allowed
            and isinstance(self, FactorScoreV1)
        ):
            raise ValueError("UNKNOWN_FRESHNESS_REQUIRES_POLICY")
        return self


class FactorScoreV1(_FactorOutcomeV1):
    """A directional normalized factor observation, not a calibrated probability."""

    direction: Direction
    strength: str
    reliability: str

    @field_validator("strength", "reliability")
    @classmethod
    def _unit_interval(cls, value: str) -> str:
        from leviathan_core.numeric import canonical_str, parse_decimal

        number = parse_decimal(value, field="factor_score")
        if not 0 <= number <= 1:
            raise ValueError("FACTOR_SCORE_OUT_OF_BOUNDS")
        return canonical_str(number)

    @model_validator(mode="after")
    def _scored_evidence(self) -> FactorScoreV1:
        if not self.evidence_refs:
            raise ValueError("SCORE_REQUIRES_EVIDENCE")
        if self.freshness == "stale":
            raise ValueError("NONFRESH_FACTOR_MUST_ABSTAIN")
        return self


class FactorAbstentionV1(_FactorOutcomeV1):
    """Typed fail-closed outcome for missing, stale, unknown or insufficient data."""

    reason: AbstentionReason


FactorOutcomeV1 = FactorScoreV1 | FactorAbstentionV1


def to_layer_observation(value: FactorScoreV1) -> LayerObservationV1:
    """Project a factor into the existing fusion observation contract."""
    if type(value) is not FactorScoreV1:
        raise ValueError("INVALID_FACTOR_SCORE")
    evidence = value.evidence_refs[0]
    return LayerObservationV1(
        layer=value.family,
        source=evidence.source,
        source_version=value.method_version,
        event_ns=value.source_event_ns,
        available_ns=evidence.as_of_ns,
        semantic_digest=evidence.record_digest,
        score=value.strength,
        confidence=value.reliability,
    )


def unix_ns(value: datetime) -> int:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("INVALID_INTEL_TIME")
    delta = value.astimezone(UTC) - datetime(1970, 1, 1, tzinfo=UTC)
    return ((delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds) * 1000
