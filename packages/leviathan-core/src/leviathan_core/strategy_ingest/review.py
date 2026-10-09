"""Explicit human review of a hash-pinned extraction packet."""

from __future__ import annotations

from typing import NoReturn, Protocol, SupportsIndex
from weakref import ReferenceType, finalize, ref

from leviathan_core.seal import Issuer, SealError, require

from .lineage import _assert_acyclic, _conflicts_for, _edges_for, packet_payload
from .models import (
    ClaimDecisionV1,
    ExtractedEvidenceV1,
    ReviewedStrategySpecV1,
    ReviewerActionV1,
    ReviewPacketV1,
    ReviewResultV1,
    StrategyIngestError,
    _issue_packet,
    _packet_is_issued,
    digest,
)

_TOKEN_SEAL = object()
_reviewed_spec_issuer = Issuer("strat001.reviewed_spec.v1")


class VerifiedLicenseV1:
    """Opaque, immutable result issued by a trusted license-review adapter."""

    __slots__ = ("__weakref__", "action_id", "license_reference_id", "reviewer_id", "source_sha256")
    source_sha256: str
    license_reference_id: str
    action_id: str
    reviewer_id: str

    def __init__(
        self,
        source_sha256: str,
        license_reference_id: str,
        action_id: str,
        reviewer_id: str,
        *,
        _seal: object | None = None,
    ) -> None:
        if _registered_token_entry(self) is not None:
            raise StrategyIngestError("LICENSE_TOKEN_IMMUTABLE")
        if type(self) is not VerifiedLicenseV1 or _seal is not _TOKEN_SEAL:
            raise StrategyIngestError("LICENSE_TOKEN_UNTRUSTED")
        object.__setattr__(self, "source_sha256", source_sha256)
        object.__setattr__(self, "license_reference_id", license_reference_id)
        object.__setattr__(self, "action_id", action_id)
        object.__setattr__(self, "reviewer_id", reviewer_id)
        _register_token(self)

    def __setattr__(self, name: str, value: object) -> None:
        raise StrategyIngestError("LICENSE_TOKEN_IMMUTABLE")

    def __delattr__(self, name: str) -> None:
        raise StrategyIngestError("LICENSE_TOKEN_IMMUTABLE")

    def __copy__(self) -> None:
        raise StrategyIngestError("LICENSE_TOKEN_NOT_COPYABLE")

    def __deepcopy__(self, memo: object) -> None:
        raise StrategyIngestError("LICENSE_TOKEN_NOT_COPYABLE")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise StrategyIngestError("LICENSE_TOKEN_NOT_SERIALIZABLE")

    def __repr__(self) -> str:
        return "VerifiedLicenseV1(<opaque>)"


def require_reviewed_spec(spec: ReviewedStrategySpecV1) -> ReviewedStrategySpecV1:
    """Require identity- and content-bound issuance by the STRAT-001 review flow."""
    if type(spec) is not ReviewedStrategySpecV1:
        raise StrategyIngestError("REVIEWED_SPEC_NOT_ISSUED")
    try:
        return require(spec, _reviewed_spec_issuer.tag)
    except SealError:
        raise StrategyIngestError("REVIEWED_SPEC_NOT_ISSUED") from None


_ISSUED_TOKENS: dict[int, tuple[ReferenceType[VerifiedLicenseV1], str]] = {}


def _token_binding_digest(token: VerifiedLicenseV1) -> str:
    return digest(
        {
            "source_sha256": token.source_sha256,
            "license_reference_id": token.license_reference_id,
            "action_id": token.action_id,
            "reviewer_id": token.reviewer_id,
        }
    )


def _registered_token_entry(
    token: VerifiedLicenseV1,
) -> tuple[ReferenceType[VerifiedLicenseV1], str] | None:
    entry = _ISSUED_TOKENS.get(id(token))
    return entry if entry is not None and entry[0]() is token else None


def _forget_token(identity: int, token_ref: ReferenceType[VerifiedLicenseV1]) -> None:
    entry = _ISSUED_TOKENS.get(identity)
    if entry is not None and entry[0] is token_ref:
        del _ISSUED_TOKENS[identity]


def _register_token(token: VerifiedLicenseV1) -> None:
    identity = id(token)
    token_ref = ref(token)
    _ISSUED_TOKENS[identity] = (token_ref, _token_binding_digest(token))
    finalize(token, _forget_token, identity, token_ref)


def _issue_verified_license(
    *, source_sha256: str, license_reference_id: str, action_id: str, reviewer_id: str
) -> VerifiedLicenseV1:
    """Trusted adapters (or isolated test fakes) issue this after external verification."""
    return VerifiedLicenseV1(
        source_sha256=source_sha256,
        license_reference_id=license_reference_id,
        action_id=action_id,
        reviewer_id=reviewer_id,
        _seal=_TOKEN_SEAL,
    )


class LicenseReviewPort(Protocol):
    """Adapter must authenticate the human attestation and its license record."""

    def verify_license(
        self,
        *,
        source_sha256: str,
        license_reference_id: str,
        reviewer_action: ReviewerActionV1,
    ) -> VerifiedLicenseV1: ...


def _validate_decisions(
    packet: ReviewPacketV1, action: ReviewerActionV1
) -> tuple[tuple[ExtractedEvidenceV1, ...], tuple[ExtractedEvidenceV1, ...]]:
    ids = {item.evidence_id for item in packet.evidence}
    decisions: dict[str, ClaimDecisionV1] = {item.evidence_id: item for item in action.decisions}
    if len(decisions) != len(action.decisions) or set(decisions) != ids:
        raise StrategyIngestError("incomplete_review")
    conflicted = {evidence_id for group in packet.conflicts for evidence_id in group.candidate_ids}
    for decision in action.decisions:
        if decision.evidence_id in conflicted:
            if decision.decision != "reject" or decision.reason_code != "conflict":
                raise StrategyIngestError("unresolved_conflict")
        elif (decision.decision == "accept" and decision.reason_code != "supported") or (
            decision.decision == "reject" and decision.reason_code == "supported"
        ):
            raise StrategyIngestError("invalid_review_reason")
    accepted = tuple(
        item for item in packet.evidence if decisions[item.evidence_id].decision == "accept"
    )
    rejected = tuple(
        item for item in packet.evidence if decisions[item.evidence_id].decision == "reject"
    )
    return accepted, rejected


def _prefix_digest(packet: ReviewPacketV1, count: int) -> str:
    payload = packet_payload(packet)
    payload["status"] = "QUARANTINED" if count == 0 else "REVIEWED"
    payload["reviewer_actions"] = [
        item.model_dump(mode="json") for item in packet.reviewer_actions[:count]
    ]
    return digest(payload)


def _validate_packet(packet: ReviewPacketV1) -> None:
    if not _packet_is_issued(packet):
        raise StrategyIngestError("PACKET_NOT_REGISTERED")
    try:
        ReviewPacketV1(**packet.model_dump())
    except Exception:
        raise StrategyIngestError("INVALID_PACKET_RECORD") from None
    if digest(packet_payload(packet)) != packet.packet_sha256:
        raise StrategyIngestError("packet_checksum_mismatch")
    expected_status = "QUARANTINED" if not packet.reviewer_actions else "REVIEWED"
    if packet.status != expected_status or (
        not packet.evidence and packet.source.license_status != "prohibited"
    ):
        raise StrategyIngestError("invalid_packet_state")
    _assert_acyclic(packet.evidence)
    ids = {item.evidence_id for item in packet.evidence}
    if len(ids) != len(packet.evidence):
        raise StrategyIngestError("duplicate_evidence_id")
    if packet.lineage_edges != _edges_for(packet.source.source_id, packet.evidence):
        raise StrategyIngestError("invalid_lineage_edges")
    if packet.conflicts != _conflicts_for(packet.evidence):
        raise StrategyIngestError("invalid_conflict_record")
    for item in packet.evidence:
        if (
            item.source_sha256 != packet.source.byte_sha256
            or item.span.byte_end > packet.source.byte_length
        ):
            raise StrategyIngestError("unresolvable_source_span")
    prior_ids: set[str] = set()
    prior_time = packet.source.review_asof_ns
    for position, prior in enumerate(packet.reviewer_actions):
        if prior.action_id in prior_ids or prior.packet_sha256 != _prefix_digest(packet, position):
            raise StrategyIngestError("review_history_invalid")
        if prior.reviewed_at_ns < prior_time:
            raise StrategyIngestError("review_history_invalid")
        _validate_decisions(packet, prior)
        prior_ids.add(prior.action_id)
        prior_time = prior.reviewed_at_ns


def _verify_license(
    packet: ReviewPacketV1, action: ReviewerActionV1, verifier: LicenseReviewPort
) -> None:
    try:
        token = verifier.verify_license(
            source_sha256=packet.source.byte_sha256,
            license_reference_id=packet.source.license_reference_id,
            reviewer_action=action,
        )
    except Exception:
        raise StrategyIngestError("LICENSE_VERIFICATION_FAILED") from None
    if type(token) is not VerifiedLicenseV1:
        raise StrategyIngestError("LICENSE_VERIFICATION_FAILED")
    entry = _registered_token_entry(token)
    try:
        actual_digest = _token_binding_digest(token)
    except Exception:
        raise StrategyIngestError("LICENSE_VERIFICATION_FAILED") from None
    expected_digest = digest(
        {
            "source_sha256": packet.source.byte_sha256,
            "license_reference_id": packet.source.license_reference_id,
            "action_id": action.action_id,
            "reviewer_id": action.reviewer_id,
        }
    )
    if entry is None or actual_digest != entry[1] or actual_digest != expected_digest:
        raise StrategyIngestError("LICENSE_VERIFICATION_FAILED")


def accept_extraction(
    packet: ReviewPacketV1,
    action: ReviewerActionV1,
    *,
    license_verifier: LicenseReviewPort,
) -> ReviewResultV1:
    """Append a complete human decision, producing a new packet and optional review-only spec."""
    if type(packet) is not ReviewPacketV1:
        raise StrategyIngestError("INVALID_PACKET_TYPE")
    if type(action) is not ReviewerActionV1:
        raise StrategyIngestError("INVALID_ACTION_TYPE")
    if license_verifier is None:
        raise StrategyIngestError("LICENSE_VERIFIER_REQUIRED")
    _validate_packet(packet)
    try:
        action = ReviewerActionV1(**action.model_dump())
    except Exception:
        raise StrategyIngestError("INVALID_ACTION_RECORD") from None
    if packet.source.license_status != "reuse_permitted":
        raise StrategyIngestError("LICENSE_NOT_REUSABLE")
    if action.packet_sha256 != packet.packet_sha256:
        raise StrategyIngestError("review_packet_mismatch")
    if any(prior.action_id == action.action_id for prior in packet.reviewer_actions):
        raise StrategyIngestError("review_action_replayed")
    previous_time = (
        packet.reviewer_actions[-1].reviewed_at_ns
        if packet.reviewer_actions
        else packet.source.review_asof_ns
    )
    if action.reviewed_at_ns < previous_time:
        raise StrategyIngestError("review_time_invalid")
    accepted, rejected = _validate_decisions(packet, action)
    _verify_license(packet, action, license_verifier)
    history = (*packet.reviewer_actions, action)
    unpinned_packet = ReviewPacketV1(
        schema_version="1",
        status="REVIEWED",
        source=packet.source,
        evidence=packet.evidence,
        lineage_edges=packet.lineage_edges,
        conflicts=packet.conflicts,
        reviewer_actions=history,
        packet_sha256="",
    )
    new_packet = _issue_packet(
        ReviewPacketV1(
            schema_version="1",
            status="REVIEWED",
            source=packet.source,
            evidence=packet.evidence,
            lineage_edges=packet.lineage_edges,
            conflicts=packet.conflicts,
            reviewer_actions=history,
            packet_sha256=digest(packet_payload(unpinned_packet)),
        )
    )
    spec: ReviewedStrategySpecV1 | None = None
    has_strategy_logic = any(
        item.claim_kind in {"entry_condition", "exit_condition"} for item in accepted
    )
    if has_strategy_logic and not packet.conflicts:
        unpinned_spec = ReviewedStrategySpecV1(
            schema_version="1",
            spec_kind="review_only",
            promotion_status="BLOCKED_UNVERIFIED_SOURCE",
            source=packet.source,
            packet_sha256=new_packet.packet_sha256,
            accepted_claims=accepted,
            rejected_claims=rejected,
            lineage_edges=packet.lineage_edges,
            conflicts=packet.conflicts,
            reviewer_actions=history,
            spec_sha256="",
        )
        spec = ReviewedStrategySpecV1(
            schema_version="1",
            spec_kind="review_only",
            promotion_status="BLOCKED_UNVERIFIED_SOURCE",
            source=packet.source,
            packet_sha256=new_packet.packet_sha256,
            accepted_claims=accepted,
            rejected_claims=rejected,
            lineage_edges=packet.lineage_edges,
            conflicts=packet.conflicts,
            reviewer_actions=history,
            spec_sha256=digest(unpinned_spec.model_dump(mode="json", exclude={"spec_sha256"})),
        )
    result = ReviewResultV1(schema_version="1", packet=new_packet, spec=spec)
    if result.spec is not None:
        # ReviewResultV1 performs strict revalidation of its nested spec. Issue the
        # exact stored instance so callers receive this identity, not its precursor.
        _reviewed_spec_issuer.issue(result.spec)
    _issue_packet(result.packet)
    return result
