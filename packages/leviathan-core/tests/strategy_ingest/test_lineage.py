"""Focused unit checks for the pure STRAT-001 review kernel."""

from __future__ import annotations

import gc
import hashlib
import json
import pickle
from copy import copy
from decimal import Decimal
from weakref import ref

import pytest
from pydantic import BaseModel, PydanticDeprecatedSince20

from leviathan_core.strategy_ingest import (
    ClaimDecisionV1,
    ExtractedEvidenceV1,
    ReviewerActionV1,
    SafeScanReceiptV1,
    SourceManifestV1,
    SourceSpanV1,
    StrategyIngestError,
    VerifiedLicenseV1,
    accept_extraction,
    register_source,
)
from leviathan_core.strategy_ingest.review import _ISSUED_TOKENS, _issue_verified_license


class _FakeLicenseVerifier:
    def verify_license(
        self, *, source_sha256: str, license_reference_id: str, reviewer_action: ReviewerActionV1
    ) -> object:
        return _issue_verified_license(
            source_sha256=source_sha256,
            license_reference_id=license_reference_id,
            action_id=reviewer_action.action_id,
            reviewer_id=reviewer_action.reviewer_id,
        )


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _manifest(
    raw: bytes = b"Enter when price crosses average.", **changes: object
) -> SourceManifestV1:
    values: dict[str, object] = {
        "schema_version": "1",
        "source_id": "source.1",
        "source_uri": "file:///fixture.md",
        "source_locator": "fixture.md",
        "source_bytes": raw,
        "byte_sha256": _sha(raw),
        "media_type": "text/markdown",
        "license_status": "reuse_permitted",
        "license_reference_id": "license.review.1",
        "collection_method": "provided_upload",
        "entitlement_status": "authorized",
        "entitlement_provenance_status": "CALLER_DECLARED",
        "drm_status": "clear",
        "safe_scan": SafeScanReceiptV1(
            schema_version="1",
            provenance_status="CALLER_DECLARED",
            scanned_sha256=_sha(raw),
            verdict="clean",
            scanner_name="fixture-scanner",
            scanner_version="1",
            scanned_at_ns=2,
        ),
        "parser_version": "fixture.1",
        "transcriber_version": None,
        "acquired_ns": 1,
        "available_ns": 2,
        "review_asof_ns": 3,
    }
    values.update(changes)
    return SourceManifestV1.model_validate(values)


def _evidence(
    manifest: SourceManifestV1,
    *,
    evidence_id: str = "claim.1",
    claim_text: str = "Cross above average",
) -> ExtractedEvidenceV1:
    return ExtractedEvidenceV1(
        schema_version="1",
        evidence_id=evidence_id,
        claim_key="entry.1",
        claim_kind="entry_condition",
        claim_text=claim_text,
        confidence=Decimal("0.80"),
        source_sha256=manifest.byte_sha256,
        span=SourceSpanV1(
            schema_version="1",
            byte_start=0,
            byte_end=len(manifest.source_bytes),
            span_sha256=_sha(manifest.source_bytes),
            page_start=None,
            page_end=None,
            time_start_ms=None,
            time_end_ms=None,
        ),
        derived_from=(),
        text_ref="text.1",
        chunk_ref="chunk.1",
        embedding_ref="embedding.1",
        tags=("mean_reversion",),
    )


def _action(packet_sha256: str, *decisions: ClaimDecisionV1) -> ReviewerActionV1:
    return ReviewerActionV1(
        schema_version="1",
        action_id="review.1",
        packet_sha256=packet_sha256,
        reviewer_id="researcher.1",
        reviewed_at_ns=4,
        decisions=tuple(decisions),
    )


def _decision(evidence_id: str, decision: str, reason_code: str) -> ClaimDecisionV1:
    return ClaimDecisionV1.model_validate(
        {
            "schema_version": "1",
            "evidence_id": evidence_id,
            "decision": decision,
            "reason_code": reason_code,
        }
    )


def test_reviewed_spec_is_hash_pinned_and_review_only() -> None:
    manifest = _manifest()
    packet = register_source(manifest, [_evidence(manifest)])
    result = accept_extraction(
        packet,
        _action(packet.packet_sha256, _decision("claim.1", "accept", "supported")),
        license_verifier=_FakeLicenseVerifier(),
    )
    spec = result.spec
    assert spec is not None
    assert packet.status == "QUARANTINED"
    assert packet.reviewer_actions == ()
    assert result.packet.status == "REVIEWED"
    assert len(result.packet.reviewer_actions) == 1
    assert spec.spec_kind == "review_only"
    assert spec.promotion_status == "BLOCKED_UNVERIFIED_SOURCE"
    assert spec.source.safe_scan.provenance_status == "CALLER_DECLARED"
    assert spec.source.entitlement_provenance_status == "CALLER_DECLARED"
    assert len(spec.accepted_claims) == 1
    assert spec.accepted_claims[0].span.span_sha256 == _sha(manifest.source_bytes)
    assert spec.source.byte_sha256 == manifest.byte_sha256
    assert spec.spec_sha256 and packet.packet_sha256
    assert "source_bytes" not in spec.model_dump()
    assert packet.evidence[0].model_dump(mode="json")["confidence"] == "0.8"
    with pytest.raises(StrategyIngestError, match="SEALED_RECORD_MUTATION_DENIED"):
        packet.evidence[0].tags = ("changed",)


@pytest.mark.parametrize(
    ("change", "code"),
    [
        ({"byte_sha256": "0" * 64}, "source_checksum_mismatch"),
        ({"entitlement_status": "unknown"}, "source_entitlement_unapproved"),
        ({"drm_status": "protected"}, "drm_not_clear"),
        (
            {"media_type": "application/octet-stream", "source_locator": "fixture.ex5"},
            "unsupported_media",
        ),
    ],
)
def test_registration_fails_closed(change: dict[str, object], code: str) -> None:
    manifest = _manifest(**change)
    with pytest.raises(StrategyIngestError) as error:
        register_source(manifest, [_evidence(manifest)])
    assert error.value.code == code


def test_span_must_match_source_bytes() -> None:
    manifest = _manifest()
    claim = _evidence(manifest)
    bad_span = SourceSpanV1(**{**claim.span.model_dump(), "span_sha256": "0" * 64})
    with pytest.raises(StrategyIngestError, match="span_checksum_mismatch"):
        register_source(manifest, [ExtractedEvidenceV1(**{**claim.model_dump(), "span": bad_span})])


def test_conflict_keeps_both_candidates_and_requires_explicit_rejection() -> None:
    manifest = _manifest()
    packet = register_source(
        manifest,
        [
            _evidence(manifest),
            _evidence(manifest, evidence_id="claim.2", claim_text="Cross below average"),
        ],
    )
    assert len(packet.conflicts) == 1
    assert packet.conflicts[0].candidate_ids == ("claim.1", "claim.2")
    with pytest.raises(StrategyIngestError, match="unresolved_conflict"):
        accept_extraction(
            packet,
            _action(
                packet.packet_sha256,
                _decision("claim.1", "accept", "supported"),
                _decision("claim.2", "reject", "conflict"),
            ),
            license_verifier=_FakeLicenseVerifier(),
        )
    result = accept_extraction(
        packet,
        _action(
            packet.packet_sha256,
            _decision("claim.1", "reject", "conflict"),
            _decision("claim.2", "reject", "conflict"),
        ),
        license_verifier=_FakeLicenseVerifier(),
    )
    assert result.spec is None
    assert len(result.packet.reviewer_actions) == 1
    assert result.packet.conflicts[0].status == "unresolved"


def test_review_must_cover_every_claim() -> None:
    manifest = _manifest()
    packet = register_source(manifest, [_evidence(manifest)])
    with pytest.raises(StrategyIngestError, match="incomplete_review"):
        accept_extraction(
            packet, _action(packet.packet_sha256), license_verifier=_FakeLicenseVerifier()
        )


def test_source_correction_changes_packet_digest() -> None:
    original = _manifest()
    corrected = _manifest(b"Enter when price crosses average!")
    first = register_source(original, [_evidence(original)])
    second = register_source(corrected, [_evidence(corrected)])
    assert first.packet_sha256 != second.packet_sha256


def test_secret_like_source_is_rejected_without_echo() -> None:
    raw = b"api_key=synthetic_secret_value_123"
    manifest = _manifest(raw)
    with pytest.raises(StrategyIngestError) as error:
        register_source(manifest, [_evidence(manifest)])
    assert error.value.code == "secret_like_source"
    assert "synthetic_secret" not in str(error.value)


@pytest.mark.parametrize("license_status", ["unreviewed", "reference_only"])
def test_unverified_rights_remain_quarantined(license_status: str) -> None:
    manifest = _manifest(license_status=license_status)
    packet = register_source(manifest, [_evidence(manifest)])
    assert packet.status == "QUARANTINED"
    assert packet.source.byte_sha256 == manifest.byte_sha256
    with pytest.raises(StrategyIngestError, match="LICENSE_NOT_REUSABLE"):
        accept_extraction(
            packet,
            _action(packet.packet_sha256, _decision("claim.1", "accept", "supported")),
            license_verifier=_FakeLicenseVerifier(),
        )


def test_prohibited_source_keeps_only_hash_and_license_finding() -> None:
    manifest = _manifest(license_status="prohibited")
    packet = register_source(manifest, [])
    assert packet.evidence == ()
    assert packet.source.license_reference_id == "license.review.1"
    with pytest.raises(StrategyIngestError, match="prohibited_source_claims_forbidden"):
        register_source(manifest, [_evidence(manifest)])
    with pytest.raises(StrategyIngestError, match="LICENSE_NOT_REUSABLE"):
        accept_extraction(
            packet, _action(packet.packet_sha256), license_verifier=_FakeLicenseVerifier()
        )


def test_set_parameters_cannot_prove_hidden_entry_logic() -> None:
    raw = b"RiskPercent=2\n"
    manifest = _manifest(raw, media_type="text/x-mt5-set", source_locator="kinno.set")
    claim = _evidence(manifest)
    with pytest.raises(StrategyIngestError, match="parameter_file_cannot_prove_logic"):
        register_source(manifest, [claim])
    parameter_claim = ExtractedEvidenceV1(**{**claim.model_dump(), "claim_kind": "parameter"})
    packet = register_source(manifest, [parameter_claim])
    assert packet.evidence[0].claim_kind == "parameter"


def test_verified_license_token_is_opaque_and_not_copyable() -> None:
    token = _issue_verified_license(
        source_sha256="0" * 64,
        license_reference_id="license.review.1",
        action_id="review.1",
        reviewer_id="researcher.1",
    )
    with pytest.raises(StrategyIngestError, match="LICENSE_TOKEN_NOT_COPYABLE"):
        copy(token)
    with pytest.raises(StrategyIngestError, match="LICENSE_TOKEN_NOT_SERIALIZABLE"):
        pickle.dumps(token)
    with pytest.raises(TypeError):
        json.dumps(token)
    with pytest.raises(StrategyIngestError, match="LICENSE_TOKEN_IMMUTABLE"):
        token.__init__("0" * 64, "license.review.1", "review.1", "researcher.1")


def test_public_records_reject_mutation_copy_and_unsafe_construction() -> None:
    manifest = _manifest()
    claim = _evidence(manifest)
    for record in (manifest.safe_scan, claim.span, claim):
        with pytest.raises(StrategyIngestError, match="SEALED_RECORD_COPY_DENIED"):
            record.model_copy()
        with pytest.raises(StrategyIngestError, match="SEALED_RECORD_COPY_DENIED"):
            record.copy()
        with pytest.raises(StrategyIngestError, match="SEALED_RECORD_COPY_DENIED"):
            copy(record)
        with pytest.raises(StrategyIngestError, match="SEALED_RECORD_SERIALIZATION_DENIED"):
            pickle.dumps(record)
        with pytest.raises(StrategyIngestError, match="SEALED_RECORD_MUTATION_DENIED"):
            del record.schema_version
        with pytest.raises(StrategyIngestError, match="SEALED_RECORD_CONSTRUCTION_DENIED"):
            type(record).model_construct(schema_version="1")


def test_invalid_record_error_has_no_supplied_input() -> None:
    secret = "synthetic_secret_value_123"
    values = _evidence(_manifest()).span.model_dump()
    values["span_sha256"] = secret
    for build in (
        lambda: SourceSpanV1(**values),
        lambda: SourceSpanV1.model_validate(values),
    ):
        with pytest.raises(StrategyIngestError) as error:
            build()
        assert secret not in str(error.value)
        assert secret not in repr(error.value.errors())
    with pytest.raises(StrategyIngestError) as error:
        SourceSpanV1(**{**_evidence(_manifest()).span.model_dump(), secret: "hidden"})
    assert secret not in repr(error.value.errors())


@pytest.mark.parametrize("confidence", [True, 0.1, Decimal("0." + "1" * 35)])
def test_confidence_requires_bounded_exact_decimal(confidence: object) -> None:
    values = _evidence(_manifest()).model_dump()
    values["confidence"] = confidence
    with pytest.raises(StrategyIngestError, match="INVALID_RECORD"):
        ExtractedEvidenceV1(**values)


def test_license_token_seal_cannot_be_stolen_or_mutated() -> None:
    token = _issue_verified_license(
        source_sha256="0" * 64,
        license_reference_id="license.review.1",
        action_id="review.1",
        reviewer_id="reviewer.1",
    )
    assert not hasattr(token, "_seal")
    with pytest.raises(StrategyIngestError, match="LICENSE_TOKEN_UNTRUSTED"):
        type(token)("0" * 64, "license.review.1", "review.1", "reviewer.1")
    with pytest.raises(StrategyIngestError, match="LICENSE_TOKEN_IMMUTABLE"):
        del token.source_sha256


def test_equal_hash_unissued_license_subclass_cannot_borrow_issuance() -> None:
    manifest = _manifest()
    packet = register_source(manifest, [_evidence(manifest)])
    action = _action(packet.packet_sha256, _decision("claim.1", "accept", "supported"))
    issued = _issue_verified_license(
        source_sha256=packet.source.byte_sha256,
        license_reference_id=packet.source.license_reference_id,
        action_id=action.action_id,
        reviewer_id=action.reviewer_id,
    )

    class EqualLicense(VerifiedLicenseV1):
        def __hash__(self) -> int:
            return hash(issued)

        def __eq__(self, other: object) -> bool:
            return True

    forged = object.__new__(EqualLicense)
    for field in ("source_sha256", "license_reference_id", "action_id", "reviewer_id"):
        object.__setattr__(forged, field, getattr(issued, field))

    class ForgedVerifier:
        def verify_license(self, **kwargs: object) -> VerifiedLicenseV1:
            return forged

    assert forged is not issued and forged == issued
    with pytest.raises(StrategyIngestError, match="LICENSE_VERIFICATION_FAILED"):
        accept_extraction(packet, action, license_verifier=ForgedVerifier())


def test_issued_license_field_tampering_fails_binding_digest() -> None:
    manifest = _manifest()
    packet = register_source(manifest, [_evidence(manifest)])
    action = _action(packet.packet_sha256, _decision("claim.1", "accept", "supported"))

    class TamperingVerifier:
        def verify_license(self, **kwargs: object) -> VerifiedLicenseV1:
            token = _issue_verified_license(
                source_sha256=packet.source.byte_sha256,
                license_reference_id=packet.source.license_reference_id,
                action_id=action.action_id,
                reviewer_id=action.reviewer_id,
            )
            object.__setattr__(token, "source_sha256", "0" * 64)
            return token

    with pytest.raises(StrategyIngestError, match="LICENSE_VERIFICATION_FAILED"):
        accept_extraction(packet, action, license_verifier=TamperingVerifier())


def test_license_issuance_entry_is_removed_after_collection() -> None:
    token = _issue_verified_license(
        source_sha256="0" * 64,
        license_reference_id="license.review.1",
        action_id="review.1",
        reviewer_id="researcher.1",
    )
    token_id = id(token)
    token_ref = ref(token)
    assert token_id in _ISSUED_TOKENS
    del token
    gc.collect()
    assert token_ref() is None
    assert token_id not in _ISSUED_TOKENS


def test_review_rejects_packet_that_bypassed_source_registration() -> None:
    manifest = _manifest()
    issued = register_source(manifest, [_evidence(manifest)])
    forged = type(issued)(**issued.model_dump())
    assert forged.packet_sha256 == issued.packet_sha256
    with pytest.raises(StrategyIngestError, match="PACKET_NOT_REGISTERED"):
        accept_extraction(
            forged,
            _action(forged.packet_sha256, _decision("claim.1", "accept", "supported")),
            license_verifier=_FakeLicenseVerifier(),
        )


def test_deprecated_copy_and_reinit_cannot_bypass_claim_type() -> None:
    manifest = _manifest()
    claim = _evidence(manifest)
    with pytest.raises(StrategyIngestError, match="SEALED_RECORD_COPY_DENIED"):
        claim.copy(update={"claim_kind": "direct_order"})
    with pytest.raises(StrategyIngestError, match="SEALED_RECORD_REINIT_DENIED"):
        claim.__init__(**{**claim.model_dump(), "claim_kind": "direct_order"})
    before = claim.model_dump()
    with pytest.raises(StrategyIngestError, match="SEALED_RECORD_REINIT_DENIED"):
        BaseModel.__init__(claim, **{**before, "claim_kind": "direct_order"})
    with pytest.raises(StrategyIngestError, match="SEALED_RECORD_REINIT_DENIED"):
        BaseModel.__setstate__(claim, {"__dict__": {**before, "claim_kind": "direct_order"}})
    assert claim.model_dump() == before
    assert ExtractedEvidenceV1.model_validate(claim) is not claim
    assert claim.claim_kind == "entry_condition"
    with pytest.warns(PydanticDeprecatedSince20):
        forged = BaseModel.copy(claim, update={"claim_kind": "direct_order"})
    with pytest.raises(StrategyIngestError, match="INVALID_EVIDENCE_RECORD"):
        register_source(manifest, [forged])


def test_caller_declared_scan_and_entitlement_cannot_be_forged_verified() -> None:
    manifest = _manifest()
    with pytest.warns(PydanticDeprecatedSince20):
        forged_scan = BaseModel.copy(manifest.safe_scan, update={"provenance_status": "VERIFIED"})
    with pytest.warns(PydanticDeprecatedSince20):
        forged_manifest = BaseModel.copy(manifest, update={"safe_scan": forged_scan})
    with pytest.raises(StrategyIngestError, match="INVALID_MANIFEST_RECORD"):
        register_source(forged_manifest, [_evidence(manifest)])
    with pytest.warns(PydanticDeprecatedSince20):
        forged_entitlement = BaseModel.copy(
            manifest, update={"entitlement_provenance_status": "VERIFIED"}
        )
    with pytest.raises(StrategyIngestError, match="INVALID_MANIFEST_RECORD"):
        register_source(forged_entitlement, [_evidence(manifest)])


def test_public_boundaries_reject_wrong_types_without_echo() -> None:
    manifest = _manifest()
    claim = _evidence(manifest)
    with pytest.raises(StrategyIngestError, match="INVALID_MANIFEST_TYPE"):
        register_source(None, [claim])  # type: ignore[arg-type]
    with pytest.raises(StrategyIngestError, match="INVALID_EVIDENCE_INPUT"):
        register_source(manifest, None)  # type: ignore[arg-type]
    packet = register_source(manifest, [claim])
    action = _action(packet.packet_sha256, _decision("claim.1", "accept", "supported"))
    with pytest.raises(StrategyIngestError, match="INVALID_PACKET_TYPE"):
        accept_extraction(None, action, license_verifier=_FakeLicenseVerifier())  # type: ignore[arg-type]
    with pytest.raises(StrategyIngestError, match="INVALID_ACTION_TYPE"):
        accept_extraction(packet, None, license_verifier=_FakeLicenseVerifier())  # type: ignore[arg-type]


@pytest.mark.parametrize("source_uri", ["https:bad", "https:///bad", "https://:80/path"])
def test_https_uri_requires_host(source_uri: str) -> None:
    with pytest.raises(StrategyIngestError, match="INVALID_RECORD"):
        _manifest(source_uri=source_uri)


def test_review_history_appends_without_mutating_prior_packet() -> None:
    manifest = _manifest()
    initial = register_source(manifest, [_evidence(manifest)])
    first = accept_extraction(
        initial,
        _action(initial.packet_sha256, _decision("claim.1", "accept", "supported")),
        license_verifier=_FakeLicenseVerifier(),
    )
    before = first.packet.model_dump()
    with pytest.raises(StrategyIngestError, match="SEALED_RECORD_REINIT_DENIED"):
        BaseModel.__init__(first.packet, **{**before, "status": "QUARANTINED"})
    assert first.packet.model_dump() == before
    revalidated = type(first.packet).model_validate(first.packet)
    assert revalidated is not first.packet
    second_action = ReviewerActionV1(
        schema_version="1",
        action_id="review.2",
        packet_sha256=first.packet.packet_sha256,
        reviewer_id="researcher.2",
        reviewed_at_ns=5,
        decisions=(_decision("claim.1", "reject", "unsupported"),),
    )
    second = accept_extraction(first.packet, second_action, license_verifier=_FakeLicenseVerifier())
    assert initial.reviewer_actions == ()
    assert first.packet.reviewer_actions[0].action_id == "review.1"
    assert [item.action_id for item in second.packet.reviewer_actions] == ["review.1", "review.2"]
    assert second.packet.packet_sha256 != first.packet.packet_sha256
    assert first.spec is not None
    assert first.spec.packet_sha256 == first.packet.packet_sha256
    assert second.spec is None
    with pytest.raises(StrategyIngestError, match="SEALED_RECORD_COPY_DENIED"):
        first.packet.model_copy(update={"reviewer_actions": ()})
    with pytest.raises(StrategyIngestError, match="SEALED_RECORD_COPY_DENIED"):
        copy(first.packet)
    with pytest.raises(StrategyIngestError, match="SEALED_RECORD_SERIALIZATION_DENIED"):
        pickle.dumps(first.packet)
