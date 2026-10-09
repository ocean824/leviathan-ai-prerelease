"""Independent adversarial acceptance tests for STRAT-001 lineage and review."""

from __future__ import annotations

import copy
import hashlib
import json
import pickle
from decimal import Decimal
from pathlib import Path

import pytest
from pydantic import BaseModel

from leviathan_core.strategy_ingest import (
    ClaimDecisionV1,
    ExtractedEvidenceV1,
    LicenseReviewPort,
    ReviewerActionV1,
    ReviewPacketV1,
    SafeScanReceiptV1,
    SourceManifestV1,
    SourceSpanV1,
    StrategyIngestError,
    VerifiedLicenseV1,
    accept_extraction,
    register_source,
)
from leviathan_core.strategy_ingest.review import _issue_verified_license

FIXTURES = Path(__file__).parent / "fixtures" / "lineage"


def sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def manifest(
    raw: bytes,
    *,
    source_id: str = "sourceA",
    locator: str = "strategy.txt",
    media_type: str = "text/plain",
    license_status: str = "reuse_permitted",
    entitlement_status: str = "authorized",
    drm_status: str = "clear",
    verdict: str = "clean",
    byte_sha256: str | None = None,
    scan_sha256: str | None = None,
    transcriber_version: str | None = None,
    acquired_ns: int = 1,
    available_ns: int = 2,
    review_asof_ns: int = 3,
) -> SourceManifestV1:
    expected_hash = sha(raw)
    receipt = SafeScanReceiptV1(
        schema_version="1",
        provenance_status="CALLER_DECLARED",
        scanned_sha256=scan_sha256 or expected_hash,
        verdict=verdict,
        scanner_name="fixture-av",
        scanner_version="1.0",
        scanned_at_ns=2,
    )
    return SourceManifestV1(
        schema_version="1",
        source_id=source_id,
        source_uri=f"file:///fixtures/{locator}",
        source_locator=locator,
        source_bytes=raw,
        byte_sha256=byte_sha256 or expected_hash,
        media_type=media_type,
        license_status=license_status,
        license_reference_id="license-record-001",
        collection_method="provided_upload",
        entitlement_status=entitlement_status,
        entitlement_provenance_status="CALLER_DECLARED",
        drm_status=drm_status,
        safe_scan=receipt,
        parser_version="plain-v1",
        transcriber_version=transcriber_version,
        acquired_ns=acquired_ns,
        available_ns=available_ns,
        review_asof_ns=review_asof_ns,
    )


def evidence(
    raw: bytes,
    *,
    evidence_id: str,
    claim_key: str,
    claim_kind: str,
    claim_text: str,
    derived_from: tuple[str, ...] = (),
) -> ExtractedEvidenceV1:
    start = raw.index(claim_text.encode("utf-8"))
    end = start + len(claim_text.encode("utf-8"))
    return ExtractedEvidenceV1(
        schema_version="1",
        evidence_id=evidence_id,
        claim_key=claim_key,
        claim_kind=claim_kind,
        claim_text=claim_text,
        confidence=Decimal("0.9"),
        source_sha256=sha(raw),
        span=SourceSpanV1(
            schema_version="1",
            byte_start=start,
            byte_end=end,
            span_sha256=sha(raw[start:end]),
            page_start=None,
            page_end=None,
            time_start_ms=None,
            time_end_ms=None,
        ),
        derived_from=derived_from,
        text_ref=None,
        chunk_ref=None,
        embedding_ref=None,
        tags=(),
    )


def packet_for(
    raw: bytes,
    claims: tuple[ExtractedEvidenceV1, ...] | None = None,
    **manifest_options: object,
) -> ReviewPacketV1:
    if claims is None:
        claims = (
            evidence(
                raw,
                evidence_id="claimA",
                claim_key="entry-rule",
                claim_kind="entry_condition",
                claim_text="Enter when the short average crosses above the long average.",
            ),
        )
    return register_source(manifest(raw, **manifest_options), claims)


def action_for(
    packet: ReviewPacketV1,
    *,
    action_id: str = "reviewA",
    reviewer_id: str = "reviewerA",
    conflicts_rejected: bool = True,
) -> ReviewerActionV1:
    conflict_ids = {
        candidate for conflict in packet.conflicts for candidate in conflict.candidate_ids
    }
    decisions = []
    for claim in packet.evidence:
        if claim.evidence_id in conflict_ids and conflicts_rejected:
            decision, reason = "reject", "conflict"
        elif claim.claim_kind in {
            "research_failure",
            "latency_loss",
            "unsafe_execution",
            "proxy_method",
            "unknown_logic",
            "naive_local_time",
        }:
            decision, reason = "reject", "unsupported"
        else:
            decision, reason = "accept", "supported"
        decisions.append(
            ClaimDecisionV1(
                schema_version="1",
                evidence_id=claim.evidence_id,
                decision=decision,
                reason_code=reason,
            )
        )
    return ReviewerActionV1(
        schema_version="1",
        action_id=action_id,
        packet_sha256=packet.packet_sha256,
        reviewer_id=reviewer_id,
        reviewed_at_ns=packet.source.review_asof_ns,
        decisions=tuple(decisions),
    )


class FakeLicenseVerifier:
    """A test-only verifier; no license provider or external service is called."""

    def verify_license(
        self,
        *,
        source_sha256: str,
        license_reference_id: str,
        reviewer_action: ReviewerActionV1,
    ) -> VerifiedLicenseV1:
        return _issue_verified_license(
            source_sha256=source_sha256,
            license_reference_id=license_reference_id,
            action_id=reviewer_action.action_id,
            reviewer_id=reviewer_action.reviewer_id,
        )


VERIFIER: LicenseReviewPort = FakeLicenseVerifier()


def test_registration_pins_source_and_each_claim_to_exact_bytes() -> None:
    raw = (FIXTURES / "clean-strategy.txt").read_bytes()
    packet = packet_for(raw)

    assert packet.source.byte_sha256 == sha(raw)
    assert packet.source.byte_length == len(raw)
    for claim in packet.evidence:
        span = claim.span
        assert sha(raw[span.byte_start : span.byte_end]) == span.span_sha256
        assert claim.source_sha256 == packet.source.byte_sha256
        assert any(
            edge.parent_id == packet.source.source_id
            and edge.child_id == claim.evidence_id
            and edge.relation == "extracted_from"
            for edge in packet.lineage_edges
        )
    assert packet.packet_sha256


@pytest.mark.parametrize(
    ("options", "expected_code"),
    [
        ({"byte_sha256": "0" * 64}, "source_checksum_mismatch"),
        ({"scan_sha256": "b" * 64}, "scan_checksum_mismatch"),
        ({"verdict": "not_scanned"}, "scan_not_clean"),
        ({"entitlement_status": "unknown"}, "source_entitlement_unapproved"),
        ({"drm_status": "protected"}, "drm_not_clear"),
        ({"media_type": "application/octet-stream", "locator": "opaque.ex5"}, "unsupported_media"),
    ],
)
def test_untrusted_or_unproven_source_fails_closed(
    options: dict[str, object], expected_code: str
) -> None:
    raw = b"Enter when the short average crosses above the long average."
    claim = evidence(
        raw,
        evidence_id="claimA",
        claim_key="entry-rule",
        claim_kind="entry_condition",
        claim_text=raw.decode("utf-8"),
    )

    with pytest.raises(StrategyIngestError) as caught:
        register_source(manifest(raw, **options), (claim,))

    assert caught.value.code == expected_code
    assert str(caught.value) == expected_code


@pytest.mark.parametrize("license_status", ["unreviewed", "reference_only", "prohibited"])
def test_unverified_or_reference_only_license_stays_quarantined_and_cannot_review(
    license_status: str,
) -> None:
    raw = b"Enter when the short average crosses above the long average."
    claim = evidence(
        raw,
        evidence_id="claimA",
        claim_key="entry-rule",
        claim_kind="entry_condition",
        claim_text=raw.decode("utf-8"),
    )
    claims = () if license_status == "prohibited" else (claim,)
    packet = packet_for(raw, claims, license_status=license_status)

    assert packet.status == "QUARANTINED"
    assert packet.evidence == claims
    with pytest.raises(StrategyIngestError) as caught:
        accept_extraction(packet, action_for(packet), license_verifier=VERIFIER)
    assert caught.value.code == "LICENSE_NOT_REUSABLE"


def test_caller_declared_scan_and_entitlement_do_not_clear_quarantine() -> None:
    raw = b"Enter when the short average crosses above the long average."
    packet = packet_for(raw, license_status="unreviewed")

    assert packet.source.safe_scan.verdict == "clean"
    assert packet.source.entitlement_status == "authorized"
    assert packet.source.safe_scan.provenance_status == "CALLER_DECLARED"
    assert packet.source.entitlement_provenance_status == "CALLER_DECLARED"
    assert packet.status == "QUARANTINED"
    with pytest.raises(StrategyIngestError) as caught:
        accept_extraction(packet, action_for(packet), license_verifier=VERIFIER)
    assert caught.value.code == "LICENSE_NOT_REUSABLE"


def test_empty_source_bytes_fail_closed() -> None:
    raw = b""
    with pytest.raises(StrategyIngestError) as caught:
        register_source(manifest(raw), ())
    assert caught.value.code == "missing_source_bytes"


def test_wrong_type_public_api_inputs_raise_typed_errors() -> None:
    raw = b"Enter when the short average crosses above the long average."
    packet = packet_for(raw)
    action = action_for(packet)
    calls = (
        (lambda: register_source(None, ()), "INVALID_MANIFEST_TYPE"),
        (lambda: register_source(manifest(raw), None), "INVALID_EVIDENCE_INPUT"),
        (lambda: register_source(manifest(raw), (None,)), "INVALID_EVIDENCE_RECORD"),
        (lambda: accept_extraction(None, action, license_verifier=VERIFIER), "INVALID_PACKET_TYPE"),
        (lambda: accept_extraction(packet, None, license_verifier=VERIFIER), "INVALID_ACTION_TYPE"),
    )

    for call, expected_code in calls:
        with pytest.raises(StrategyIngestError) as caught:
            call()
        assert caught.value.code == expected_code
        assert "None" not in str(caught.value)


def test_https_source_uri_requires_a_host() -> None:
    raw = b"Enter when the short average crosses above the long average."
    payload = manifest(raw).model_dump()
    payload["source_uri"] = "https:bad"

    with pytest.raises(StrategyIngestError) as caught:
        SourceManifestV1.model_validate(payload)

    assert caught.value.code
    assert "https:bad" not in str(caught.value)


def test_claim_span_outside_or_not_matching_source_is_rejected() -> None:
    raw = b"Entry only when the signal crosses upward."
    claim = evidence(
        raw,
        evidence_id="claimA",
        claim_key="entry-rule",
        claim_kind="entry_condition",
        claim_text=raw.decode("utf-8"),
    )
    span_fields = claim.span.model_dump()
    outside_span = SourceSpanV1(**{**span_fields, "byte_end": len(raw) + 1})
    wrong_digest_span = SourceSpanV1(**{**span_fields, "span_sha256": "b" * 64})
    outside_payload = claim.model_dump()
    outside_payload["span"] = outside_span
    wrong_digest_payload = claim.model_dump()
    wrong_digest_payload["span"] = wrong_digest_span
    outside = ExtractedEvidenceV1.model_validate(outside_payload)
    wrong_digest = ExtractedEvidenceV1.model_validate(wrong_digest_payload)

    for bad_claim, code in (
        (outside, "span_out_of_bounds"),
        (wrong_digest, "span_checksum_mismatch"),
    ):
        with pytest.raises(StrategyIngestError) as caught:
            register_source(manifest(raw), (bad_claim,))
        assert caught.value.code == code


def test_cited_derivation_is_acyclic_and_missing_parents_are_rejected() -> None:
    raw = b"Entry condition A. Derived risk rule B."
    first = evidence(
        raw,
        evidence_id="claimA",
        claim_key="entry-rule",
        claim_kind="entry_condition",
        claim_text="Entry condition A.",
    )
    second = evidence(
        raw,
        evidence_id="claimB",
        claim_key="risk-rule",
        claim_kind="risk_rule",
        claim_text="Derived risk rule B.",
        derived_from=("claimA",),
    )
    packet = packet_for(raw, (second, first))

    assert any(
        edge.parent_id == "claimA" and edge.child_id == "claimB" and edge.relation == "derived_from"
        for edge in packet.lineage_edges
    )
    missing_parent_payload = second.model_dump()
    missing_parent_payload["span"] = second.span
    missing_parent_payload["derived_from"] = ("unknown",)
    missing_parent = ExtractedEvidenceV1.model_validate(missing_parent_payload)
    with pytest.raises(StrategyIngestError) as caught:
        register_source(manifest(raw), (first, missing_parent))
    assert caught.value.code == "missing_lineage_parent"

    cycle_payload = first.model_dump()
    cycle_payload["span"] = first.span
    cycle_payload["derived_from"] = ("claimB",)
    cycle_first = ExtractedEvidenceV1.model_validate(cycle_payload)
    with pytest.raises(StrategyIngestError) as cycle_error:
        register_source(manifest(raw), (cycle_first, second))
    assert cycle_error.value.code == "lineage_cycle"


def test_source_correction_gets_a_new_content_address_without_rewriting_old_packet() -> None:
    first_raw = b"Entry only when the signal crosses upward."
    corrected_raw = b"Entry only when the signal crosses upward; require volume."
    first = packet_for(
        first_raw,
        (
            evidence(
                first_raw,
                evidence_id="claimA",
                claim_key="entry-rule",
                claim_kind="entry_condition",
                claim_text=first_raw.decode(),
            ),
        ),
    )
    corrected = packet_for(
        corrected_raw,
        (
            evidence(
                corrected_raw,
                evidence_id="claimA",
                claim_key="entry-rule",
                claim_kind="entry_condition",
                claim_text=corrected_raw.decode(),
            ),
        ),
    )

    assert first.source.source_id == corrected.source.source_id
    assert first.source.byte_sha256 != corrected.source.byte_sha256
    assert first.packet_sha256 != corrected.packet_sha256
    assert first.source.byte_sha256 == sha(first_raw)


def test_conflicting_mtr_variants_are_preserved_and_cannot_be_accepted_as_one_rule() -> None:
    raw = (FIXTURES / "mtr-conflicting-variants.txt").read_bytes()
    candidates = (
        evidence(
            raw,
            evidence_id="gridA",
            claim_key="grid-mode",
            claim_kind="parameter",
            claim_text="Grid mode A uses fixed spacing.",
        ),
        evidence(
            raw,
            evidence_id="gridB",
            claim_key="grid-mode",
            claim_kind="parameter",
            claim_text="Grid mode B scales spacing by volatility.",
        ),
        evidence(
            raw,
            evidence_id="oos",
            claim_key="oos-result",
            claim_kind="research_failure",
            claim_text="Out-of-sample lane failed.",
        ),
        evidence(
            raw,
            evidence_id="latency",
            claim_key="latency-result",
            claim_kind="latency_loss",
            claim_text="Latency-sensitive run loses at 250 ms.",
        ),
    )
    packet = packet_for(raw, candidates)
    action = action_for(packet)
    result = accept_extraction(packet, action, license_verifier=VERIFIER)

    assert len(packet.conflicts) == 1
    assert set(packet.conflicts[0].candidate_ids) == {"gridA", "gridB"}
    assert result.packet.status == "REVIEWED"
    assert result.packet.reviewer_actions == (action,)
    assert result.packet.conflicts == packet.conflicts
    assert result.spec is None

    reference_packet = register_source(manifest(raw, license_status="reference_only"), candidates)
    assert reference_packet.conflicts == packet.conflicts
    with pytest.raises(StrategyIngestError) as rights_error:
        accept_extraction(reference_packet, action_for(reference_packet), license_verifier=VERIFIER)
    assert rights_error.value.code == "LICENSE_NOT_REUSABLE"


def test_parameter_only_kinnobot_fixture_does_not_invent_entry_or_exit_logic() -> None:
    raw = (FIXTURES / "parameter-only-description.txt").read_bytes()
    text = "Synthetic preset exposes period=20 and threshold=1.5 only."
    packet = packet_for(
        raw,
        (
            evidence(
                raw,
                evidence_id="params",
                claim_key="parameters",
                claim_kind="parameter",
                claim_text=text,
            ),
        ),
        media_type="text/x-mt5-set",
        locator="kinnobot.set",
    )
    result = accept_extraction(packet, action_for(packet), license_verifier=VERIFIER)

    assert result.packet.status == "REVIEWED"
    assert result.spec is None


def test_hostile_hftcode_like_source_is_treated_as_bytes_and_never_executed(tmp_path: Path) -> None:
    marker = tmp_path / "executed.txt"
    raw = (
        (FIXTURES / "unsafe-startup-close.py")
        .read_bytes()
        .replace(b"MARKER_PATH", str(marker).encode("utf-8"))
    )
    claim_text = "Synthetic stand-in for unsafe startup and a failed local close reset."
    packet = packet_for(
        raw,
        (
            evidence(
                raw,
                evidence_id="hazard",
                claim_key="execution-hazard",
                claim_kind="unsafe_execution",
                claim_text=claim_text,
            ),
        ),
        media_type="text/x-python",
        locator="unsafe-startup-close.py",
    )

    assert packet.source.byte_sha256 == sha(raw)
    assert not marker.exists()


def test_unverified_bitcoin_course_rights_and_proxy_labels_do_not_pass() -> None:
    raw = (FIXTURES / "bitcoin-course-proxy-labels.txt").read_bytes()
    proxy_claim = evidence(
        raw,
        evidence_id="proxy",
        claim_key="method-label",
        claim_kind="proxy_method",
        claim_text="Synthetic labels HMM, order-book, and pairs are unverified proxies.",
    )

    packet = register_source(manifest(raw, license_status="unreviewed"), (proxy_claim,))
    assert packet.status == "QUARANTINED"
    assert packet.evidence == (proxy_claim,)
    with pytest.raises(StrategyIngestError) as caught:
        accept_extraction(packet, action_for(packet), license_verifier=VERIFIER)
    assert caught.value.code == "LICENSE_NOT_REUSABLE"


@pytest.mark.parametrize("naive_time", ["2024-11-03T01:30:00", "2024-11-03 01:30:00"])
def test_naive_eastern_wall_clock_cannot_be_used_as_utc_nanoseconds(naive_time: str) -> None:
    raw = b"Entry condition."
    options = {
        "schema_version": "1",
        "source_id": "sourceA",
        "source_uri": "file:///fixtures/strategy.txt",
        "source_locator": "strategy.txt",
        "source_bytes": raw,
        "byte_sha256": sha(raw),
        "media_type": "text/plain",
        "license_status": "reuse_permitted",
        "license_reference_id": "license-record-001",
        "collection_method": "provided_upload",
        "entitlement_status": "authorized",
        "entitlement_provenance_status": "CALLER_DECLARED",
        "drm_status": "clear",
        "safe_scan": SafeScanReceiptV1(
            schema_version="1",
            provenance_status="CALLER_DECLARED",
            scanned_sha256=sha(raw),
            verdict="clean",
            scanner_name="fixture-av",
            scanner_version="1.0",
            scanned_at_ns=2,
        ),
        "parser_version": "plain-v1",
        "transcriber_version": None,
        "acquired_ns": naive_time,
        "available_ns": 2,
        "review_asof_ns": 3,
    }

    with pytest.raises(StrategyIngestError) as caught:
        SourceManifestV1(**options)
    _assert_content_free_record_error(caught.value, naive_time)


def test_future_available_source_cannot_be_reviewed_as_of_an_earlier_time() -> None:
    raw = b"Enter when the short average crosses above the long average."
    with pytest.raises(StrategyIngestError) as caught:
        manifest(raw, available_ns=4, review_asof_ns=3)
    _assert_content_free_record_error(caught.value, "4")


def _assert_content_free_record_error(error: StrategyIngestError, canary: str) -> None:
    assert error.code == "INVALID_RECORD"
    assert canary not in str(error)
    assert canary not in repr(error.args)
    assert canary not in json.dumps(error.errors(), sort_keys=True)


def test_lesson_11_validation_errors_never_echo_input() -> None:
    canary = "SECRET-CANARY-DO-NOT-ECHO"
    payload = SourceSpanV1(
        schema_version="1",
        byte_start=0,
        byte_end=1,
        span_sha256="a" * 64,
        page_start=None,
        page_end=None,
        time_start_ms=None,
        time_end_ms=None,
    ).model_dump()
    payload["span_sha256"] = canary

    for construct in (
        lambda: SourceSpanV1(**payload),
        lambda: SourceSpanV1.model_validate(payload),
        lambda: SourceSpanV1.model_validate_json(json.dumps(payload)),
        lambda: SourceSpanV1.model_validate_strings(payload),
    ):
        with pytest.raises(StrategyIngestError) as caught:
            construct()
        _assert_content_free_record_error(caught.value, canary)
        assert caught.value.location == ("span_sha256",)


def test_lesson_14_17_public_records_reject_mutation_and_bypass_copy_paths() -> None:
    raw = b"Enter when the short average crosses above the long average."
    manifest_record = manifest(raw)
    packet = packet_for(raw)
    action = action_for(packet)
    result = accept_extraction(packet, action, license_verifier=VERIFIER)
    assert result.spec is not None

    conflicting_raw = (FIXTURES / "mtr-conflicting-variants.txt").read_bytes()
    conflict_packet = packet_for(
        conflicting_raw,
        (
            evidence(
                conflicting_raw,
                evidence_id="gridA",
                claim_key="grid-mode",
                claim_kind="parameter",
                claim_text="Grid mode A uses fixed spacing.",
            ),
            evidence(
                conflicting_raw,
                evidence_id="gridB",
                claim_key="grid-mode",
                claim_kind="parameter",
                claim_text="Grid mode B scales spacing by volatility.",
            ),
        ),
    )
    records = (
        manifest_record,
        manifest_record.safe_scan,
        packet.source,
        packet.evidence[0],
        packet.evidence[0].span,
        packet.lineage_edges[0],
        conflict_packet.conflicts[0],
        action.decisions[0],
        action,
        result.packet,
        result.spec,
        result,
    )
    canary = "MUTATION-CANARY-DO-NOT-ECHO"

    for record in records:
        with pytest.raises(StrategyIngestError) as reinitialized:
            record.__init__(**record.model_dump())
        assert reinitialized.value.code == "SEALED_RECORD_REINIT_DENIED"
        with pytest.raises(StrategyIngestError) as base_reinitialized:
            BaseModel.__init__(record, **record.model_dump())
        assert base_reinitialized.value.code == "SEALED_RECORD_REINIT_DENIED"
        with pytest.raises(StrategyIngestError) as restored:
            record.__setstate__(record.model_dump())
        assert restored.value.code == "SEALED_RECORD_REINIT_DENIED"

        field_name = next(iter(type(record).model_fields))
        with pytest.raises(StrategyIngestError) as assigned:
            setattr(record, field_name, canary)
        assert assigned.value.code == "SEALED_RECORD_MUTATION_DENIED"
        assert canary not in str(assigned.value)
        assert canary not in repr(assigned.value.args)

        with pytest.raises(StrategyIngestError) as deleted:
            delattr(record, field_name)
        assert deleted.value.code == "SEALED_RECORD_MUTATION_DENIED"

        with pytest.raises(StrategyIngestError) as constructed:
            type(record).model_construct(**{field_name: canary})
        assert constructed.value.code == "SEALED_RECORD_CONSTRUCTION_DENIED"

        with pytest.raises(StrategyIngestError) as model_copied:
            record.model_copy(update={field_name: canary})
        assert model_copied.value.code == "SEALED_RECORD_COPY_DENIED"

        for clone in (copy.copy, copy.deepcopy):
            with pytest.raises(StrategyIngestError) as copied:
                clone(record)
            assert copied.value.code == "SEALED_RECORD_COPY_DENIED"
        with pytest.raises(StrategyIngestError) as pickled:
            pickle.dumps(record)
        assert pickled.value.code == "SEALED_RECORD_SERIALIZATION_DENIED"


def test_lesson_15_16_license_seal_is_not_stored_or_replayable_as_issuer() -> None:
    raw = b"Enter when the short average crosses above the long average."
    packet = packet_for(raw)
    action = action_for(packet)
    token = VERIFIER.verify_license(
        source_sha256=packet.source.byte_sha256,
        license_reference_id=packet.source.license_reference_id,
        reviewer_action=action,
    )

    assert "_seal" not in VerifiedLicenseV1.__slots__
    assert not hasattr(token, "_seal")
    with pytest.raises(StrategyIngestError, match="LICENSE_TOKEN_UNTRUSTED"):
        VerifiedLicenseV1(
            packet.source.byte_sha256,
            packet.source.license_reference_id,
            action.action_id,
            action.reviewer_id,
        )
    copied_seal = getattr(token, "_seal", token)
    with pytest.raises(StrategyIngestError, match="LICENSE_TOKEN_UNTRUSTED"):
        VerifiedLicenseV1(
            packet.source.byte_sha256,
            packet.source.license_reference_id,
            action.action_id,
            action.reviewer_id,
            _seal=copied_seal,
        )
    with pytest.raises(TypeError):
        VerifiedLicenseV1(
            packet.source.byte_sha256,
            packet.source.license_reference_id,
            action.action_id,
            action.reviewer_id,
            _issuer=copied_seal,  # type: ignore[call-arg]
        )
    for change in (
        lambda: setattr(token, "reviewer_id", "TOKEN-CANARY"),
        lambda: delattr(token, "reviewer_id"),
    ):
        with pytest.raises(StrategyIngestError):
            change()

    direct_packet = ReviewPacketV1(
        **{field: getattr(packet, field) for field in type(packet).model_fields}
    )
    with pytest.raises(StrategyIngestError) as unregistered:
        accept_extraction(
            direct_packet,
            action_for(direct_packet),
            license_verifier=VERIFIER,
        )
    assert unregistered.value.code == "PACKET_NOT_REGISTERED"


def test_base_model_copy_cannot_forge_claim_kind_before_or_after_review() -> None:
    raw = b"Enter when the short average crosses above the long average."
    packet = packet_for(raw)
    claim = packet.evidence[0]

    try:
        forged_claim = BaseModel.copy(claim, update={"claim_kind": "direct_order"})
    except StrategyIngestError as exc:
        assert exc.code == "SEALED_RECORD_COPY_DENIED"
    else:
        assert forged_claim.claim_kind == "direct_order"
        with pytest.raises(StrategyIngestError) as invalid_registration:
            register_source(manifest(raw), (forged_claim,))
        assert invalid_registration.value.code == "INVALID_EVIDENCE_RECORD"

    reviewed = accept_extraction(packet, action_for(packet), license_verifier=VERIFIER)
    try:
        forged_packet = BaseModel.copy(reviewed.packet, update={"status": "QUARANTINED"})
    except StrategyIngestError as exc:
        assert exc.code == "SEALED_RECORD_COPY_DENIED"
    else:
        with pytest.raises(StrategyIngestError):
            accept_extraction(
                forged_packet,
                action_for(forged_packet),
                license_verifier=VERIFIER,
            )


def test_issued_license_token_tampering_is_detected_by_the_issuer_registry() -> None:
    raw = b"Enter when the short average crosses above the long average."
    packet = packet_for(raw)
    action = action_for(packet)

    class TamperingVerifier(FakeLicenseVerifier):
        def verify_license(self, **kwargs: object) -> VerifiedLicenseV1:
            issued = super().verify_license(**kwargs)  # type: ignore[arg-type]
            object.__setattr__(issued, "reviewer_id", "changed-after-issue")
            return issued

    with pytest.raises(StrategyIngestError) as caught:
        accept_extraction(packet, action, license_verifier=TamperingVerifier())
    assert caught.value.code == "LICENSE_VERIFICATION_FAILED"


def test_lesson_18_equal_subclass_token_cannot_borrow_issuer_registration() -> None:
    raw = b"Enter when the short average crosses above the long average."
    packet = packet_for(raw)
    action = action_for(packet)
    genuine = VERIFIER.verify_license(
        source_sha256=packet.source.byte_sha256,
        license_reference_id=packet.source.license_reference_id,
        reviewer_action=action,
    )

    class EqualUnissuedToken(VerifiedLicenseV1):
        __slots__ = ("_forced_hash",)
        _forced_hash: int

        def __eq__(self, other: object) -> bool:
            return isinstance(other, VerifiedLicenseV1) and all(
                getattr(self, field) == getattr(other, field)
                for field in (
                    "source_sha256",
                    "license_reference_id",
                    "action_id",
                    "reviewer_id",
                )
            )

        def __hash__(self) -> int:
            return self._forced_hash

    forged = object.__new__(EqualUnissuedToken)
    object.__setattr__(forged, "_forced_hash", hash(genuine))
    for field in ("source_sha256", "license_reference_id", "action_id", "reviewer_id"):
        object.__setattr__(forged, field, getattr(genuine, field))

    assert forged is not genuine
    assert forged == genuine
    assert hash(forged) == hash(genuine)

    class EqualityForgeryVerifier:
        def verify_license(self, **kwargs: object) -> VerifiedLicenseV1:
            return forged

    with pytest.raises(StrategyIngestError) as caught:
        accept_extraction(packet, action, license_verifier=EqualityForgeryVerifier())

    assert caught.value.code == "LICENSE_VERIFICATION_FAILED"


def test_typed_reviewer_decisions_are_complete_immutable_and_review_only() -> None:
    raw = b"Enter when the short average crosses above the long average."
    packet = packet_for(raw)
    first_action = action_for(packet, action_id="reviewFirst")
    first_result = accept_extraction(packet, first_action, license_verifier=VERIFIER)
    next_action = action_for(first_result.packet, action_id="reviewSecond", reviewer_id="reviewerB")
    second_result = accept_extraction(first_result.packet, next_action, license_verifier=VERIFIER)

    assert packet.status == "QUARANTINED"
    assert packet.reviewer_actions == ()
    assert first_result.packet.reviewer_actions == (first_action,)
    assert second_result.packet.reviewer_actions == (first_action, next_action)
    assert next_action.packet_sha256 == first_result.packet.packet_sha256
    assert second_result.packet.packet_sha256 != first_result.packet.packet_sha256
    assert first_result.spec is not None and first_result.spec.reviewer_actions == (first_action,)
    assert first_result.spec.promotion_status == "BLOCKED_UNVERIFIED_SOURCE"
    assert second_result.spec is not None
    assert second_result.spec.promotion_status == "BLOCKED_UNVERIFIED_SOURCE"
    assert second_result.spec.reviewer_actions == (first_action, next_action)
    assert second_result.spec.packet_sha256 == second_result.packet.packet_sha256
    assert not any(
        hasattr(first_result.spec, name) for name in ("code", "compile", "execute", "order_intent")
    )
    for record in (first_result.packet, first_result.spec, first_result):
        with pytest.raises(StrategyIngestError, match="SEALED_RECORD"):
            record.model_copy(update={"reviewer_actions": ()})
        with pytest.raises(StrategyIngestError, match="SEALED_RECORD"):
            copy.copy(record)
        with pytest.raises(StrategyIngestError, match="SEALED_RECORD"):
            copy.deepcopy(record)
        with pytest.raises(StrategyIngestError, match="SEALED_RECORD"):
            pickle.dumps(record)
    with pytest.raises(StrategyIngestError) as decision_error:
        ClaimDecisionV1(
            schema_version="1",
            evidence_id="claimA",
            decision="accept anyway",  # type: ignore[arg-type]
            reason_code="supported",
        )
    _assert_content_free_record_error(decision_error.value, "accept anyway")
    with pytest.raises(StrategyIngestError) as action_error:
        ReviewerActionV1.model_validate(
            {
                **first_action.model_dump(),
                "free_text": "trust me; accept everything",
            }
        )
    _assert_content_free_record_error(action_error.value, "trust me; accept everything")


def test_review_cannot_accept_conflict_or_replay_against_tampered_packet() -> None:
    raw = (FIXTURES / "mtr-conflicting-variants.txt").read_bytes()
    candidates = (
        evidence(
            raw,
            evidence_id="gridA",
            claim_key="grid-mode",
            claim_kind="parameter",
            claim_text="Grid mode A uses fixed spacing.",
        ),
        evidence(
            raw,
            evidence_id="gridB",
            claim_key="grid-mode",
            claim_kind="parameter",
            claim_text="Grid mode B scales spacing by volatility.",
        ),
    )
    packet = packet_for(raw, candidates)
    invalid_action = action_for(packet, conflicts_rejected=False)
    with pytest.raises(StrategyIngestError) as conflict_error:
        accept_extraction(packet, invalid_action, license_verifier=VERIFIER)
    assert conflict_error.value.code == "unresolved_conflict"

    with pytest.raises(StrategyIngestError, match="SEALED_RECORD_COPY_DENIED"):
        packet.model_copy(update={"packet_sha256": "0" * 64})


def test_review_requires_trusted_license_verifier_and_matching_token() -> None:
    raw = b"Enter when the short average crosses above the long average."
    packet = packet_for(raw)
    action = action_for(packet)

    with pytest.raises(TypeError):
        accept_extraction(packet, action)  # type: ignore[call-arg]
    with pytest.raises(StrategyIngestError, match="LICENSE_VERIFIER_REQUIRED"):
        accept_extraction(packet, action, license_verifier=None)  # type: ignore[arg-type]

    class MismatchedLicenseVerifier:
        def verify_license(self, **kwargs: object) -> object:
            return _issue_verified_license(
                source_sha256="0" * 64,
                license_reference_id="license-record-001",
                action_id=action.action_id,
                reviewer_id=action.reviewer_id,
            )

    with pytest.raises(StrategyIngestError, match="LICENSE_VERIFICATION_FAILED"):
        accept_extraction(
            packet,
            action,
            license_verifier=MismatchedLicenseVerifier(),  # type: ignore[arg-type]
        )
