"""Redacted C-101 risk evidence exports with closed-field input projections.

C-101 records accepted here are typed but not SEAL-issued. Their provenance is
therefore `TYPED_UNSEALED`. This module's seal certifies only kernel production,
not source-store authenticity. Each export contains one decision; its two
projection digests commit only to the closed fields represented in the record.
Source free-text differences intentionally leave those projections unchanged.
There is no upstream C-101 chain binding in this slice. The module is read-only
and performs no persistence or policy mutation.
"""

from __future__ import annotations

import json
import math
import re
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from typing import Literal, NoReturn, TypeVar, cast

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from leviathan_core.numeric import canonical_json
from leviathan_core.pipeline import PipelineResult
from leviathan_core.reporting.risk_evidence_chain import (
    RiskAuditChainProvenanceV1,
    RiskAuditChainVerificationV1,
    RiskAuditDecisionBindingV1,
    RiskAuditDecisionV1,
    RiskAuditTerminalActionV1,
    RiskEvidenceChainError,
    require_risk_audit_chain_verification,
)
from leviathan_core.risk.halt_reasons import is_known_halt_reason
from leviathan_core.schemas import (
    GateFinding,
    RiskAction,
    RiskVerdict,
    TradeJournalRecord,
    TradeOutcome,
)
from leviathan_core.seal import Issuer, SealedModel, SealError, require

_SCHEMA: Literal["risk.evidence.export.v1"] = "risk.evidence.export.v1"
_CHAIN_SCHEMA: Literal["risk.evidence.export.v2"] = "risk.evidence.export.v2"
_GENESIS_HASH = "0" * 64
_MAX_METADATA_NODES = 4096
_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_DECISION_ID = re.compile(r"dec_[0-9a-f]{12}\Z", re.ASCII)
_EXPORT_ISSUER = Issuer("risk.evidence.export.v1")
T = TypeVar("T", bound=BaseModel)


class RiskEvidenceErrorCodeV1(StrEnum):
    """Closed failure codes for validation, chain and seal errors."""

    INVALID_INPUT = "INVALID_INPUT"
    INCOMPLETE_EVIDENCE = "INCOMPLETE_EVIDENCE"
    POLICY_DIGEST_INVALID = "POLICY_DIGEST_INVALID"
    HALT_REASON_INVALID = "HALT_REASON_INVALID"
    UNVERIFIED_SEAL = "UNVERIFIED_SEAL"
    CHAIN_INVALID = "CHAIN_INVALID"


class RiskEvidenceExportError(ValueError):
    """Content-free export failure carrying only a closed code."""

    __slots__ = ("code",)

    def __init__(self, code: RiskEvidenceErrorCodeV1) -> None:
        self.code = code.value
        super().__init__(code.value)

    def __str__(self) -> str:
        return self.code


class RiskEvidenceProvenanceV1(StrEnum):
    """Provenance of the typed C-101 source records."""

    TYPED_UNSEALED = "TYPED_UNSEALED"


_CHAIN_PROVENANCE = RiskAuditChainProvenanceV1.CHAIN_VERIFIED_TO_SUPPLIED_HEAD_CORRELATION_ONLY


class RiskEvidencePolicyDigestSourceV1(StrEnum):
    """Authority level of a policy digest copied from the route view."""

    READ_VIEW_UNBOUND = "READ_VIEW_UNBOUND"
    READ_VIEW_CROSS_CHECKED = "READ_VIEW_CROSS_CHECKED"


class RiskEvidenceProjectionSourceV1(StrEnum):
    """Closed typed C-101 projections committed by the record."""

    RISK_VERDICT = "RISK_VERDICT"
    TRADE_JOURNAL = "TRADE_JOURNAL"


class RiskEvidenceLocalHaltCodeV1(StrEnum):
    """Export-local closed code for a global kill without a source reason."""

    GLOBAL_KILL_UNSPECIFIED = "GLOBAL_KILL_UNSPECIFIED"


class RiskEvidenceProjectionDigestV1(SealedModel):
    """Digest of a deterministic, closed-field projection of one typed input."""

    model_config = ConfigDict(strict=True, extra="forbid", revalidate_instances="always")

    source: RiskEvidenceProjectionSourceV1
    digest: str

    @field_validator("digest")
    @classmethod
    def _valid_digest(cls, value: str) -> str:
        if type(value) is not str or _SHA256.fullmatch(value) is None:
            raise ValueError("invalid")
        return value


class RiskEvidenceRecordV1(SealedModel):
    """Content-minimized, kernel-issued evidence row."""

    model_config = ConfigDict(strict=True, extra="forbid", revalidate_instances="always")

    schema_version: Literal[1] = 1
    sequence: int = Field(strict=True, ge=1)
    decision_ref: str
    outcome: RiskAction
    journal_outcome: TradeOutcome
    policy_digest: str
    policy_digest_source: RiskEvidencePolicyDigestSourceV1
    risk_findings: tuple[GateFinding, ...]
    halt_state: bool = Field(strict=True)
    halt_reason_codes: tuple[str, ...]
    setup_at_utc: datetime
    provenance: RiskEvidenceProvenanceV1
    projection_digests: tuple[RiskEvidenceProjectionDigestV1, ...]
    previous_hash: str
    record_hash: str

    @field_validator("decision_ref")
    @classmethod
    def _valid_decision_reference(cls, value: str) -> str:
        if type(value) is not str or _DECISION_ID.fullmatch(value) is None:
            raise ValueError("invalid")
        return value

    @field_validator("policy_digest", "previous_hash", "record_hash")
    @classmethod
    def _valid_digest(cls, value: str) -> str:
        if type(value) is not str or _SHA256.fullmatch(value) is None:
            raise ValueError("invalid")
        return value

    @field_validator("halt_reason_codes")
    @classmethod
    def _valid_halt_codes(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if type(value) is not tuple or any(
            type(code) is not str
            or (
                not is_known_halt_reason(code)
                and code != RiskEvidenceLocalHaltCodeV1.GLOBAL_KILL_UNSPECIFIED.value
            )
            for code in value
        ):
            raise ValueError("invalid")
        if value != tuple(sorted(set(value))):
            raise ValueError("invalid")
        return value

    @field_validator("setup_at_utc")
    @classmethod
    def _utc_timestamp(cls, value: datetime) -> datetime:
        if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("invalid")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def _consistent_halt(self) -> RiskEvidenceRecordV1:
        expected_halt = bool(self.halt_reason_codes) or (
            self.outcome is RiskAction.HALT_ALL_TRADING
        )
        if self.halt_state != expected_halt:
            raise ValueError("invalid")
        if self.halt_state and not self.halt_reason_codes:
            raise ValueError("invalid")
        if RiskEvidenceLocalHaltCodeV1.GLOBAL_KILL_UNSPECIFIED.value in self.halt_reason_codes and (
            self.outcome is not RiskAction.HALT_ALL_TRADING
            or self.halt_reason_codes
            != (RiskEvidenceLocalHaltCodeV1.GLOBAL_KILL_UNSPECIFIED.value,)
        ):
            raise ValueError("invalid")
        if self.sequence != 1 or self.previous_hash != _GENESIS_HASH:
            raise ValueError("invalid")
        if self.provenance is not RiskEvidenceProvenanceV1.TYPED_UNSEALED:
            raise ValueError("invalid")
        if tuple(item.source for item in self.projection_digests) != tuple(
            RiskEvidenceProjectionSourceV1
        ):
            raise ValueError("invalid")
        if self.policy_digest_source not in tuple(RiskEvidencePolicyDigestSourceV1):
            raise ValueError("invalid")
        return self


class RiskEvidenceExportV1(SealedModel):
    """Kernel-issued redacted export; the record source remains TYPED_UNSEALED."""

    model_config = ConfigDict(strict=True, extra="forbid", revalidate_instances="always")

    schema_version: Literal["risk.evidence.export.v1", "risk.evidence.export.v2"] = _SCHEMA
    complete: Literal[True] = True
    provenance: RiskEvidenceProvenanceV1 | RiskAuditChainProvenanceV1 = (
        RiskEvidenceProvenanceV1.TYPED_UNSEALED
    )
    records: tuple[RiskEvidenceRecordV1, ...]
    head_hash: str
    audit_chain_head_digest: str | None = None
    audit_chain_event_count: int | None = Field(default=None, strict=True, ge=1)
    audit_chain_terminal_event_id: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    audit_chain_terminal_action: RiskAuditTerminalActionV1 | None = None
    audit_chain_terminal_decision: RiskAuditDecisionV1 | None = None
    audit_chain_decision_binding: RiskAuditDecisionBindingV1 | None = None
    audit_chain_projection_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @field_validator("head_hash")
    @classmethod
    def _valid_head(cls, value: str) -> str:
        if type(value) is not str or _SHA256.fullmatch(value) is None:
            raise ValueError("invalid")
        return value

    @field_validator("audit_chain_head_digest")
    @classmethod
    def _valid_audit_chain_head(cls, value: str | None) -> str | None:
        if value is not None and (type(value) is not str or _SHA256.fullmatch(value) is None):
            raise ValueError("invalid")
        return value

    @model_validator(mode="after")
    def _one_record_and_head(self) -> RiskEvidenceExportV1:
        if type(self.records) is not tuple or len(self.records) != 1:
            raise ValueError("invalid")
        if type(self.records[0]) is not RiskEvidenceRecordV1:
            raise ValueError("invalid")
        if self.head_hash != self.records[0].record_hash:
            raise ValueError("invalid")
        if self.records[0].provenance is not RiskEvidenceProvenanceV1.TYPED_UNSEALED:
            raise ValueError("invalid")
        chain_fields = (
            self.audit_chain_head_digest,
            self.audit_chain_event_count,
            self.audit_chain_terminal_event_id,
            self.audit_chain_terminal_action,
            self.audit_chain_terminal_decision,
            self.audit_chain_decision_binding,
            self.audit_chain_projection_digest,
        )
        if self.provenance is RiskEvidenceProvenanceV1.TYPED_UNSEALED:
            if self.schema_version != _SCHEMA or any(item is not None for item in chain_fields):
                raise ValueError("invalid")
        elif self.provenance is _CHAIN_PROVENANCE:
            if (
                self.schema_version != _CHAIN_SCHEMA
                or any(item is None for item in chain_fields)
                or self.audit_chain_decision_binding
                is not RiskAuditDecisionBindingV1.CORRELATION_ID_STRING_ONLY_NOT_C101_AUTHENTICATED
                or self.audit_chain_projection_digest
                != _audit_chain_projection_digest(
                    decision_ref=self.records[0].decision_ref,
                    record_hash=self.records[0].record_hash,
                    head_digest=cast(str, self.audit_chain_head_digest),
                    event_count=cast(int, self.audit_chain_event_count),
                    terminal_event_id=cast(str, self.audit_chain_terminal_event_id),
                    terminal_action=cast(
                        RiskAuditTerminalActionV1, self.audit_chain_terminal_action
                    ),
                    terminal_decision=cast(RiskAuditDecisionV1, self.audit_chain_terminal_decision),
                    decision_binding=cast(
                        RiskAuditDecisionBindingV1, self.audit_chain_decision_binding
                    ),
                )
            ):
                raise ValueError("invalid")
        else:
            raise ValueError("invalid")
        return self


def _record_payload(
    *,
    sequence: int,
    decision_ref: str,
    outcome: RiskAction,
    journal_outcome: TradeOutcome,
    policy_digest: str,
    policy_digest_source: RiskEvidencePolicyDigestSourceV1,
    risk_findings: tuple[GateFinding, ...],
    halt_state: bool,
    halt_reason_codes: tuple[str, ...],
    setup_at_utc: datetime,
    provenance: RiskEvidenceProvenanceV1,
    projection_digests: tuple[RiskEvidenceProjectionDigestV1, ...],
    previous_hash: str,
) -> dict[str, object]:
    return {
        "schema": "risk.evidence.record.v1",
        "sequence": sequence,
        "decision_ref": decision_ref,
        "outcome": outcome.value,
        "journal_outcome": journal_outcome.value,
        "policy_digest": policy_digest,
        "policy_digest_source": policy_digest_source.value,
        "risk_findings": tuple(item.value for item in risk_findings),
        "halt_state": halt_state,
        "halt_reason_codes": halt_reason_codes,
        "setup_at_utc": setup_at_utc.astimezone(UTC).isoformat(),
        "provenance": provenance.value,
        "projection_digests": tuple(
            {"source": item.source.value, "digest": item.digest} for item in projection_digests
        ),
        "previous_hash": previous_hash,
    }


def _record_digest(record: RiskEvidenceRecordV1) -> str:
    payload = _record_payload(
        sequence=record.sequence,
        decision_ref=record.decision_ref,
        outcome=record.outcome,
        journal_outcome=record.journal_outcome,
        policy_digest=record.policy_digest,
        policy_digest_source=record.policy_digest_source,
        risk_findings=record.risk_findings,
        halt_state=record.halt_state,
        halt_reason_codes=record.halt_reason_codes,
        setup_at_utc=record.setup_at_utc,
        provenance=record.provenance,
        projection_digests=record.projection_digests,
        previous_hash=record.previous_hash,
    )
    return sha256(b"risk.evidence.record.v1\0" + canonical_json(payload)).hexdigest()


def _raise(code: RiskEvidenceErrorCodeV1) -> NoReturn:
    raise RiskEvidenceExportError(code)


def _strict_revalidate(model_type: type[T], value: object) -> T:
    if type(value) is not model_type:
        _raise(RiskEvidenceErrorCodeV1.INVALID_INPUT)
    try:
        payload = BaseModel.model_dump(
            cast(BaseModel, value), mode="python", round_trip=True, warnings=False
        )
        return model_type.model_validate(payload, strict=True)
    except Exception:
        _raise(RiskEvidenceErrorCodeV1.INVALID_INPUT)


def _strict_json_model(model_type: type[T], value: object) -> T:
    if type(value) is not dict or any(type(key) is not str for key in value):
        _raise(RiskEvidenceErrorCodeV1.INVALID_INPUT)
    try:
        raw = json.dumps(
            cast(dict[str, object], value), sort_keys=True, separators=(",", ":"), allow_nan=False
        )
        return model_type.model_validate_json(raw, strict=True)
    except Exception:
        _raise(RiskEvidenceErrorCodeV1.INVALID_INPUT)


def _metadata(value: object) -> dict[str, object] | None:
    if value is None:
        return None
    if type(value) is not dict:
        _raise(RiskEvidenceErrorCodeV1.INVALID_INPUT)
    result = cast(dict[str, object], value)
    pending: list[object] = [result]
    visited = 0
    while pending:
        item = pending.pop()
        visited += 1
        if visited > _MAX_METADATA_NODES:
            _raise(RiskEvidenceErrorCodeV1.INVALID_INPUT)
        if type(item) is dict:
            nested = cast(dict[object, object], item)
            if any(type(key) is not str for key in nested):
                _raise(RiskEvidenceErrorCodeV1.INVALID_INPUT)
            pending.extend(nested.values())
        elif type(item) is list:
            pending.extend(cast(list[object], item))
        elif type(item) is float:
            if not math.isfinite(item):
                _raise(RiskEvidenceErrorCodeV1.INVALID_INPUT)
        elif type(item) not in (str, bool, int, type(None)):
            _raise(RiskEvidenceErrorCodeV1.INVALID_INPUT)
    return result


def _valid_policy_digest(value: object) -> bool:
    return type(value) is str and _SHA256.fullmatch(value) is not None and value != _GENESIS_HASH


def _read_view(
    view: object,
    *,
    pipeline: PipelineResult,
    verdict: RiskVerdict,
    journal: TradeJournalRecord,
) -> tuple[str, RiskEvidencePolicyDigestSourceV1]:
    keys = {
        "decision_id",
        "status",
        "stage",
        "final",
        "assessment",
        "authorization",
        "paper_draft",
        "policy_digest",
        "outcome",
        "final_verdict",
        "journal_record",
    }
    if type(view) is not dict or set(view) != keys:
        _raise(RiskEvidenceErrorCodeV1.INVALID_INPUT)
    checked_view = cast(dict[str, object], view)
    if (
        type(checked_view["decision_id"]) is not str
        or checked_view["decision_id"] != pipeline.decision.decision_id
    ):
        _raise(RiskEvidenceErrorCodeV1.INCOMPLETE_EVIDENCE)
    if type(checked_view["status"]) is not str or type(checked_view["stage"]) is not str:
        _raise(RiskEvidenceErrorCodeV1.INVALID_INPUT)
    if type(checked_view["final"]) is not bool or checked_view["final"] is not True:
        _raise(RiskEvidenceErrorCodeV1.INCOMPLETE_EVIDENCE)
    expected_status = "blocked" if journal.outcome is TradeOutcome.BLOCKED else "completed"
    if checked_view["status"] != expected_status or checked_view["stage"] != expected_status:
        _raise(RiskEvidenceErrorCodeV1.INCOMPLETE_EVIDENCE)
    authorization = _metadata(checked_view["authorization"])
    paper_draft = _metadata(checked_view["paper_draft"])

    assessment = _strict_json_model(RiskVerdict, checked_view["assessment"])
    final_verdict = _strict_json_model(RiskVerdict, checked_view["final_verdict"])
    stored_journal = _strict_json_model(TradeJournalRecord, checked_view["journal_record"])
    if assessment != pipeline.verdict or final_verdict != verdict or stored_journal != journal:
        _raise(RiskEvidenceErrorCodeV1.INCOMPLETE_EVIDENCE)
    outcome = checked_view["outcome"]
    if type(outcome) is not dict or set(outcome) != {"kind", "journal_outcome"}:
        _raise(RiskEvidenceErrorCodeV1.INVALID_INPUT)
    checked_outcome = cast(dict[str, object], outcome)
    expected_kind = "pre_sim_block" if journal.outcome is TradeOutcome.BLOCKED else "paper_sim"
    if (
        checked_outcome["kind"] != expected_kind
        or checked_outcome["journal_outcome"] != journal.outcome.value
    ):
        _raise(RiskEvidenceErrorCodeV1.INCOMPLETE_EVIDENCE)

    policy_digest = checked_view["policy_digest"]
    if not _valid_policy_digest(policy_digest):
        _raise(RiskEvidenceErrorCodeV1.POLICY_DIGEST_INVALID)
    checked = cast(str, policy_digest)
    cross_checked = False
    for source in (authorization, paper_draft):
        if source is not None and "policy_digest" in source:
            source_digest = source["policy_digest"]
            if not _valid_policy_digest(source_digest) or source_digest != checked:
                _raise(RiskEvidenceErrorCodeV1.POLICY_DIGEST_INVALID)
            cross_checked = True
    source_code = (
        RiskEvidencePolicyDigestSourceV1.READ_VIEW_CROSS_CHECKED
        if cross_checked
        else RiskEvidencePolicyDigestSourceV1.READ_VIEW_UNBOUND
    )
    return checked, source_code


def _projection_digest(
    source: RiskEvidenceProjectionSourceV1,
    projection: dict[str, object],
) -> RiskEvidenceProjectionDigestV1:
    return RiskEvidenceProjectionDigestV1(
        source=source,
        digest=_projection_hash(source, projection),
    )


def _projection_hash(
    source: RiskEvidenceProjectionSourceV1,
    projection: dict[str, object],
) -> str:
    raw = canonical_json(
        {"schema": f"risk.evidence.{source.value.lower()}.projection.v1", **projection}
    )
    return sha256(raw).hexdigest()


def _audit_chain_projection_digest(
    *,
    decision_ref: str,
    record_hash: str,
    head_digest: str,
    event_count: int,
    terminal_event_id: str,
    terminal_action: RiskAuditTerminalActionV1,
    terminal_decision: RiskAuditDecisionV1,
    decision_binding: RiskAuditDecisionBindingV1,
) -> str:
    """Hash only the closed verifier metadata retained in the export."""
    payload = {
        "schema": "risk.evidence.audit-chain.projection.v2",
        "decision_ref": decision_ref,
        "record_hash": record_hash,
        "head_digest": head_digest,
        "event_count": event_count,
        "terminal_event_id": terminal_event_id,
        "terminal_action": terminal_action.value,
        "terminal_decision": terminal_decision.value,
        "decision_binding": decision_binding.value,
        "provenance": _CHAIN_PROVENANCE.value,
    }
    return sha256(canonical_json(payload)).hexdigest()


def _validate_chain(value: RiskEvidenceExportV1) -> None:
    if value.complete is not True or type(value.records) is not tuple or len(value.records) != 1:
        _raise(RiskEvidenceErrorCodeV1.CHAIN_INVALID)
    record = value.records[0]
    if type(record) is not RiskEvidenceRecordV1:
        _raise(RiskEvidenceErrorCodeV1.CHAIN_INVALID)
    if (
        record.sequence != 1
        or record.previous_hash != _GENESIS_HASH
        or record.record_hash != _record_digest(record)
        or value.head_hash != record.record_hash
    ):
        _raise(RiskEvidenceErrorCodeV1.CHAIN_INVALID)
    expected_projection_digests = (
        _projection_hash(
            RiskEvidenceProjectionSourceV1.RISK_VERDICT,
            {
                "decision_ref": record.decision_ref,
                "outcome": record.outcome.value,
                "risk_findings": tuple(item.value for item in record.risk_findings),
                "halt_state": record.halt_state,
                "halt_reason_codes": record.halt_reason_codes,
            },
        ),
        _projection_hash(
            RiskEvidenceProjectionSourceV1.TRADE_JOURNAL,
            {
                "decision_ref": record.decision_ref,
                "journal_outcome": record.journal_outcome.value,
            },
        ),
    )
    if tuple(item.digest for item in record.projection_digests) != expected_projection_digests:
        _raise(RiskEvidenceErrorCodeV1.CHAIN_INVALID)
    if value.provenance is _CHAIN_PROVENANCE:
        expected_audit_chain_projection = _audit_chain_projection_digest(
            decision_ref=record.decision_ref,
            record_hash=record.record_hash,
            head_digest=cast(str, value.audit_chain_head_digest),
            event_count=cast(int, value.audit_chain_event_count),
            terminal_event_id=cast(str, value.audit_chain_terminal_event_id),
            terminal_action=cast(RiskAuditTerminalActionV1, value.audit_chain_terminal_action),
            terminal_decision=cast(RiskAuditDecisionV1, value.audit_chain_terminal_decision),
            decision_binding=cast(RiskAuditDecisionBindingV1, value.audit_chain_decision_binding),
        )
        if value.audit_chain_projection_digest != expected_audit_chain_projection:
            _raise(RiskEvidenceErrorCodeV1.CHAIN_INVALID)


def require_risk_evidence_export(value: object) -> RiskEvidenceExportV1:
    """Require a kernel-issued result and recheck its seal and hash chain."""
    if type(value) is not RiskEvidenceExportV1:
        _raise(RiskEvidenceErrorCodeV1.UNVERIFIED_SEAL)
    try:
        require(value, _EXPORT_ISSUER.tag)
    except SealError as error:
        _raise(
            RiskEvidenceErrorCodeV1.UNVERIFIED_SEAL
            if error.code == "SEAL_NOT_ISSUED"
            else RiskEvidenceErrorCodeV1.CHAIN_INVALID
        )
    checked = value
    _validate_chain(checked)
    return checked


def build_risk_evidence_export(
    pipeline_result: PipelineResult,
    verdict: RiskVerdict,
    journal: TradeJournalRecord,
    read_view: dict[str, object],
    *,
    chain_verification: RiskAuditChainVerificationV1 | None = None,
    expected_chain_head: str | None = None,
) -> RiskEvidenceExportV1:
    """Build one redacted export after checking all typed C-101 links.

    The C-101 input models and `read_view` are not SEAL-issued. Their record
    provenance remains `TYPED_UNSEALED`; this kernel's seal means only that it
    produced the returned export, not that those inputs were authentic. When
    an audit-chain verification is supplied, it is required through the
    verifier's typed `require_*`, and its decision and head must match the
    export's decision and caller-supplied expected head. Matching that head is
    not a freshness check and does not prove it is the live store head. The
    chain claim proves correlation-string equality only, not an issued C-101
    decision ID. The retained closed verifier metadata, including this export's
    record hash, is covered by an audit-chain projection digest; raw audit rows
    are never included.
    """
    if (chain_verification is None) != (expected_chain_head is None):
        _raise(RiskEvidenceErrorCodeV1.CHAIN_INVALID)
    checked_chain: RiskAuditChainVerificationV1 | None = None
    if chain_verification is not None:
        try:
            checked_chain = require_risk_audit_chain_verification(chain_verification)
        except (RiskEvidenceChainError, TypeError, ValueError):
            _raise(RiskEvidenceErrorCodeV1.CHAIN_INVALID)
        if (
            type(expected_chain_head) is not str
            or _SHA256.fullmatch(expected_chain_head) is None
            or checked_chain.head_digest != expected_chain_head
            or checked_chain.provenance
            is not RiskAuditChainProvenanceV1.CHAIN_VERIFIED_TO_SUPPLIED_HEAD_CORRELATION_ONLY
            or checked_chain.decision_binding
            is not RiskAuditDecisionBindingV1.CORRELATION_ID_STRING_ONLY_NOT_C101_AUTHENTICATED
        ):
            _raise(RiskEvidenceErrorCodeV1.CHAIN_INVALID)
    pipeline = _strict_revalidate(PipelineResult, pipeline_result)
    final_verdict = _strict_revalidate(RiskVerdict, verdict)
    final_journal = _strict_revalidate(TradeJournalRecord, journal)

    if (
        pipeline.final is not True
        or pipeline.status != "completed"
        or pipeline.audit_sink_failure is not False
        or pipeline.failure_reason is not None
        or pipeline.final_verdict is None
        or pipeline.journal_record is None
        or pipeline.final_verdict != final_verdict
        or pipeline.journal_record != final_journal
        or pipeline.decision.decision_id != final_verdict.decision_id
        or pipeline.decision.setup_id != pipeline.setup.setup_id
        or final_journal.decision_id != final_verdict.decision_id
        or final_journal.setup_id != pipeline.setup.setup_id
    ):
        _raise(RiskEvidenceErrorCodeV1.INCOMPLETE_EVIDENCE)

    if final_journal.outcome is TradeOutcome.BLOCKED:
        if (
            pipeline.intent is not None
            or final_journal.entry is not None
            or final_journal.exit is not None
            or final_journal.mae is not None
            or final_journal.mfe is not None
        ):
            _raise(RiskEvidenceErrorCodeV1.INCOMPLETE_EVIDENCE)
    elif pipeline.intent is None or final_journal.entry is None or final_journal.exit is None:
        _raise(RiskEvidenceErrorCodeV1.INCOMPLETE_EVIDENCE)

    policy_digest, policy_digest_source = _read_view(
        read_view, pipeline=pipeline, verdict=final_verdict, journal=final_journal
    )
    at = pipeline.setup.timestamp
    if type(at) is not datetime or at.tzinfo is None or at.utcoffset() is None:
        _raise(RiskEvidenceErrorCodeV1.INCOMPLETE_EVIDENCE)
    at = at.astimezone(UTC)

    halt_reasons = final_verdict.halts_engaged
    if type(halt_reasons) is not tuple or any(
        type(reason) is not str or not is_known_halt_reason(reason) for reason in halt_reasons
    ):
        _raise(RiskEvidenceErrorCodeV1.HALT_REASON_INVALID)
    halt_codes = tuple(sorted(set(halt_reasons)))
    if (
        final_verdict.action is RiskAction.HALT_ALL_TRADING
        and not halt_codes
        and (
            GateFinding.GLOBAL_KILL in final_verdict.findings
            or GateFinding.GLOBAL_KILL in pipeline.findings
        )
    ):
        halt_codes = (RiskEvidenceLocalHaltCodeV1.GLOBAL_KILL_UNSPECIFIED.value,)
    halted = bool(halt_codes) or final_verdict.action is RiskAction.HALT_ALL_TRADING
    if halted and not halt_codes:
        _raise(RiskEvidenceErrorCodeV1.HALT_REASON_INVALID)
    decision_ref = pipeline.decision.decision_id
    if type(decision_ref) is not str or _DECISION_ID.fullmatch(decision_ref) is None:
        _raise(RiskEvidenceErrorCodeV1.INVALID_INPUT)
    if checked_chain is not None and checked_chain.decision_ref != decision_ref:
        _raise(RiskEvidenceErrorCodeV1.CHAIN_INVALID)

    risk_findings = final_verdict.findings
    if type(risk_findings) is not tuple or any(
        type(item) is not GateFinding for item in risk_findings
    ):
        _raise(RiskEvidenceErrorCodeV1.INVALID_INPUT)
    projection_digests = (
        _projection_digest(
            RiskEvidenceProjectionSourceV1.RISK_VERDICT,
            {
                "decision_ref": decision_ref,
                "outcome": final_verdict.action.value,
                "risk_findings": tuple(item.value for item in risk_findings),
                "halt_state": halted,
                "halt_reason_codes": halt_codes,
            },
        ),
        _projection_digest(
            RiskEvidenceProjectionSourceV1.TRADE_JOURNAL,
            {
                "decision_ref": decision_ref,
                "journal_outcome": final_journal.outcome.value,
            },
        ),
    )
    record_hash = sha256(
        b"risk.evidence.record.v1\0"
        + canonical_json(
            _record_payload(
                sequence=1,
                decision_ref=decision_ref,
                outcome=final_verdict.action,
                journal_outcome=final_journal.outcome,
                policy_digest=policy_digest,
                policy_digest_source=policy_digest_source,
                risk_findings=risk_findings,
                halt_state=halted,
                halt_reason_codes=halt_codes,
                setup_at_utc=at,
                provenance=RiskEvidenceProvenanceV1.TYPED_UNSEALED,
                projection_digests=projection_digests,
                previous_hash=_GENESIS_HASH,
            )
        )
    ).hexdigest()
    provenance: RiskEvidenceProvenanceV1 | RiskAuditChainProvenanceV1 = (
        RiskEvidenceProvenanceV1.TYPED_UNSEALED
    )
    schema_version: Literal["risk.evidence.export.v1", "risk.evidence.export.v2"] = _SCHEMA
    if checked_chain is not None:
        provenance = _CHAIN_PROVENANCE
        schema_version = _CHAIN_SCHEMA
    try:
        record = RiskEvidenceRecordV1(
            schema_version=1,
            sequence=1,
            decision_ref=decision_ref,
            outcome=final_verdict.action,
            journal_outcome=final_journal.outcome,
            policy_digest=policy_digest,
            policy_digest_source=policy_digest_source,
            risk_findings=risk_findings,
            halt_state=halted,
            halt_reason_codes=halt_codes,
            setup_at_utc=at,
            provenance=RiskEvidenceProvenanceV1.TYPED_UNSEALED,
            projection_digests=projection_digests,
            previous_hash=_GENESIS_HASH,
            record_hash=record_hash,
        )
        if checked_chain is None:
            candidate = RiskEvidenceExportV1(
                schema_version=schema_version,
                complete=True,
                provenance=provenance,
                records=(record,),
                head_hash=record_hash,
            )
        else:
            candidate = RiskEvidenceExportV1(
                schema_version=schema_version,
                complete=True,
                provenance=provenance,
                records=(record,),
                head_hash=record_hash,
                audit_chain_head_digest=checked_chain.head_digest,
                audit_chain_event_count=checked_chain.event_count,
                audit_chain_terminal_event_id=checked_chain.terminal_event_id,
                audit_chain_terminal_action=checked_chain.terminal_action,
                audit_chain_terminal_decision=checked_chain.terminal_decision,
                audit_chain_decision_binding=checked_chain.decision_binding,
                audit_chain_projection_digest=_audit_chain_projection_digest(
                    decision_ref=decision_ref,
                    record_hash=record_hash,
                    head_digest=checked_chain.head_digest,
                    event_count=checked_chain.event_count,
                    terminal_event_id=checked_chain.terminal_event_id,
                    terminal_action=checked_chain.terminal_action,
                    terminal_decision=checked_chain.terminal_decision,
                    decision_binding=checked_chain.decision_binding,
                ),
            )
        _validate_chain_before_seal = _record_digest(record) == record_hash
        if not _validate_chain_before_seal:
            _raise(RiskEvidenceErrorCodeV1.CHAIN_INVALID)
        export = _EXPORT_ISSUER.issue(candidate)
        return require_risk_evidence_export(export)
    except RiskEvidenceExportError:
        raise
    except SealError as error:
        _raise(
            RiskEvidenceErrorCodeV1.CHAIN_INVALID
            if error.code == "SEAL_TAMPERED"
            else RiskEvidenceErrorCodeV1.UNVERIFIED_SEAL
        )
    except Exception:
        _raise(RiskEvidenceErrorCodeV1.INVALID_INPUT)


def serialize_risk_evidence_export(value: object) -> bytes:
    """Return deterministic JSON only after rechecking the issued result."""
    export = require_risk_evidence_export(value)
    record = export.records[0]
    payload = _record_payload(
        sequence=record.sequence,
        decision_ref=record.decision_ref,
        outcome=record.outcome,
        journal_outcome=record.journal_outcome,
        policy_digest=record.policy_digest,
        policy_digest_source=record.policy_digest_source,
        risk_findings=record.risk_findings,
        halt_state=record.halt_state,
        halt_reason_codes=record.halt_reason_codes,
        setup_at_utc=record.setup_at_utc,
        provenance=record.provenance,
        projection_digests=record.projection_digests,
        previous_hash=record.previous_hash,
    )
    payload["record_hash"] = record.record_hash
    serialized: dict[str, object] = {
        "schema": export.schema_version,
        "complete": True,
        "provenance": export.provenance.value,
        "records": (payload,),
        "head_hash": export.head_hash,
    }
    if export.provenance is _CHAIN_PROVENANCE:
        serialized.update(
            {
                "audit_chain_head_digest": export.audit_chain_head_digest,
                "audit_chain_event_count": export.audit_chain_event_count,
                "audit_chain_terminal_event_id": export.audit_chain_terminal_event_id,
                "audit_chain_terminal_action": cast(
                    RiskAuditTerminalActionV1, export.audit_chain_terminal_action
                ).value,
                "audit_chain_terminal_decision": cast(
                    RiskAuditDecisionV1, export.audit_chain_terminal_decision
                ).value,
                "audit_chain_decision_binding": cast(
                    RiskAuditDecisionBindingV1, export.audit_chain_decision_binding
                ).value,
                "audit_chain_projection_digest": export.audit_chain_projection_digest,
            }
        )
    return canonical_json(serialized)


__all__ = [
    "RiskEvidenceErrorCodeV1",
    "RiskEvidenceExportError",
    "RiskEvidenceExportV1",
    "RiskEvidenceLocalHaltCodeV1",
    "RiskEvidencePolicyDigestSourceV1",
    "RiskEvidenceProjectionDigestV1",
    "RiskEvidenceProjectionSourceV1",
    "RiskEvidenceProvenanceV1",
    "RiskEvidenceRecordV1",
    "build_risk_evidence_export",
    "require_risk_evidence_export",
    "serialize_risk_evidence_export",
]
