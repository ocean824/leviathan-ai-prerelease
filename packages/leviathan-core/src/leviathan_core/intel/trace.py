"""Deterministic immutable explanation trace for the INTEL pipeline."""

from __future__ import annotations

import hashlib
from typing import Literal

from pydantic import Field, field_validator, model_validator

from leviathan_core.decision_fusion.models import FusionModelV1
from leviathan_core.numeric import canonical_json

from .models import EvidenceRefV1, FactorOutcomeV1


class TraceStageRefV1(FusionModelV1):
    stage: Literal["fusion", "calibration", "portfolio", "risk"]
    record_id: str
    digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("record_id")
    @classmethod
    def _record_id(cls, value: str) -> str:
        if not value or value != value.strip() or len(value) > 128:
            raise ValueError("INVALID_TRACE_REF")
        return value


class TraceExclusionV1(FusionModelV1):
    evidence_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    reason: Literal["STALE", "UNKNOWN_FRESHNESS", "MISSING", "LOOKAHEAD", "INVALID", "POLICY"]


class TraceValidationError(ValueError):
    """Content-free failure for invalid deterministic trace composition."""

    _CODES = frozenset({"DUPLICATE_FACTOR_ID", "CONFLICTING_TRACE_REF"})

    def __init__(self, code: str = "DUPLICATE_FACTOR_ID") -> None:
        if code not in self._CODES:
            code = "INVALID_TRACE"
        self.code = code
        super().__init__(self.code)


def _ref_sort_key(ref: EvidenceRefV1) -> bytes:
    """Total ordering over every serialized field, not a partial identity key."""
    return canonical_json(ref.model_dump(mode="json"))


def _sort_refs(refs: tuple[EvidenceRefV1, ...]) -> tuple[EvidenceRefV1, ...]:
    ordered = tuple(sorted(refs, key=_ref_sort_key))
    by_identity: dict[tuple[str, str], bytes] = {}
    for ref in ordered:
        identity = (ref.source, ref.record_digest)
        serialized = _ref_sort_key(ref)
        prior = by_identity.setdefault(identity, serialized)
        if prior != serialized:
            raise TraceValidationError("CONFLICTING_TRACE_REF")
    return ordered


class IntelExplanationTraceV1(FusionModelV1):
    """Evidence-to-decision lineage; downstream stage refs remain explicit placeholders."""

    decision_as_of_ns: int = Field(ge=0)
    evidence_refs: tuple[EvidenceRefV1, ...]
    normalized_event_refs: tuple[EvidenceRefV1, ...]
    factor_outcomes: tuple[FactorOutcomeV1, ...]
    fusion_ref: TraceStageRefV1 | None = None
    calibration_ref: TraceStageRefV1 | None = None
    portfolio_ref: TraceStageRefV1 | None = None
    risk_ref: TraceStageRefV1 | None = None
    exclusions: tuple[TraceExclusionV1, ...] = ()

    @field_validator("evidence_refs", "normalized_event_refs")
    @classmethod
    def _canonicalize_refs(
        cls, value: tuple[EvidenceRefV1, ...]
    ) -> tuple[EvidenceRefV1, ...]:
        return _sort_refs(value)

    @field_validator("decision_as_of_ns", mode="before")
    @classmethod
    def _time(cls, value: object) -> object:
        if type(value) is not int or value < 0:
            raise ValueError("INVALID_TRACE_TIME")
        return value

    @model_validator(mode="after")
    def _point_in_time(self) -> IntelExplanationTraceV1:
        all_refs = self.evidence_refs + self.normalized_event_refs
        if any(
            ref.as_of_ns > self.decision_as_of_ns or ref.source_event_ns > self.decision_as_of_ns
            for ref in all_refs
        ):
            raise ValueError("FUTURE_EVIDENCE")
        if any(outcome.as_of_ns > self.decision_as_of_ns for outcome in self.factor_outcomes):
            raise ValueError("FUTURE_FACTOR_OUTCOME")
        factor_ids = tuple(outcome.factor_id for outcome in self.factor_outcomes)
        if len(factor_ids) != len(set(factor_ids)):
            raise ValueError("DUPLICATE_FACTOR_ID")
        return self

    @property
    def trace_sha256(self) -> str:
        """Stable hash over the complete trace excluding no mutable external state."""
        return hashlib.sha256(canonical_json(self.model_dump(mode="json"))).hexdigest()


def build_trace(
    *,
    decision_as_of_ns: int,
    evidence_refs: tuple[EvidenceRefV1, ...],
    normalized_event_refs: tuple[EvidenceRefV1, ...],
    factor_outcomes: tuple[FactorOutcomeV1, ...],
    fusion_ref: TraceStageRefV1 | None = None,
    calibration_ref: TraceStageRefV1 | None = None,
    portfolio_ref: TraceStageRefV1 | None = None,
    risk_ref: TraceStageRefV1 | None = None,
    exclusions: tuple[TraceExclusionV1, ...] = (),
) -> IntelExplanationTraceV1:
    """Canonicalize unordered lineage collections before building a replayable trace."""
    factor_ids = tuple(outcome.factor_id for outcome in factor_outcomes)
    if len(factor_ids) != len(set(factor_ids)):
        raise TraceValidationError()
    return IntelExplanationTraceV1(
        decision_as_of_ns=decision_as_of_ns,
        evidence_refs=_sort_refs(evidence_refs),
        normalized_event_refs=_sort_refs(normalized_event_refs),
        factor_outcomes=tuple(
            sorted(
                factor_outcomes,
                key=lambda value: canonical_json(value.model_dump(mode="json")),
            )
        ),
        fusion_ref=fusion_ref,
        calibration_ref=calibration_ref,
        portfolio_ref=portfolio_ref,
        risk_ref=risk_ref,
        exclusions=tuple(sorted(exclusions, key=lambda item: (item.evidence_digest, item.reason))),
    )
