"""Pure source registration and source-to-claim lineage construction."""

from __future__ import annotations

import hashlib
import re
from collections import deque
from collections.abc import Sequence

from .models import (
    ClaimConflictV1,
    ExtractedEvidenceV1,
    LineageEdgeV1,
    ReviewPacketV1,
    SourceManifestV1,
    SourceRecordV1,
    StrategyIngestError,
    _issue_packet,
    digest,
)

_SUPPORTED_MEDIA = {
    "text/plain": (".txt",),
    "text/markdown": (".md",),
    "text/html": (".html", ".htm"),
    "application/pdf": (".pdf",),
    "video/mp4": (".mp4",),
    "video/x-matroska": (".mkv",),
    "audio/mpeg": (".mp3",),
    "audio/wav": (".wav",),
    "text/x-mql5": (".mq5",),
    "text/x-mql5-include": (".mqh",),
    "text/x-mt5-set": (".set",),
    "text/x-python": (".py",),
    "text/x-c++src": (".cpp", ".cc", ".cxx"),
}
_SECRET_MARKERS = re.compile(
    rb"(?i)(?:api[_-]?key|password|client[_-]?secret|access[_-]?token)\s*[:=]\s*\S+"
    rb"|authorization\s*:\s*bearer\s+\S+|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
    rb"|\bsk_(?:live|test)_[A-Za-z0-9]{8,}"
)
_CODE_MEDIA = {"text/x-mql5", "text/x-mql5-include", "text/x-python", "text/x-c++src"}


def _assert_acyclic(evidence: tuple[ExtractedEvidenceV1, ...]) -> None:
    parents = {item.evidence_id: item.derived_from for item in evidence}
    children: dict[str, list[str]] = {node: [] for node in parents}
    indegree: dict[str, int] = {}
    for node, sources in parents.items():
        indegree[node] = len(sources)
        for parent in sources:
            if parent not in parents:
                raise StrategyIngestError("missing_lineage_parent")
            children[parent].append(node)
    ready = deque(node for node, count in indegree.items() if count == 0)
    visited = 0
    while ready:
        parent = ready.popleft()
        visited += 1
        for child in children[parent]:
            indegree[child] -= 1
            if indegree[child] == 0:
                ready.append(child)
    if visited != len(parents):
        raise StrategyIngestError("lineage_cycle")


def _edges_for(
    source_id: str, evidence: tuple[ExtractedEvidenceV1, ...]
) -> tuple[LineageEdgeV1, ...]:
    return tuple(
        sorted(
            (
                LineageEdgeV1(
                    schema_version="1",
                    parent_id=parent,
                    child_id=item.evidence_id,
                    relation="derived_from" if parent != source_id else "extracted_from",
                )
                for item in evidence
                for parent in (source_id, *item.derived_from)
            ),
            key=lambda edge: (edge.parent_id, edge.child_id, edge.relation),
        )
    )


def _conflicts_for(evidence: tuple[ExtractedEvidenceV1, ...]) -> tuple[ClaimConflictV1, ...]:
    by_key: dict[str, list[ExtractedEvidenceV1]] = {}
    for item in evidence:
        by_key.setdefault(item.claim_key, []).append(item)
    return tuple(
        ClaimConflictV1(
            schema_version="1",
            claim_key=key,
            candidate_ids=tuple(item.evidence_id for item in values),
            candidate_hashes=tuple(
                digest({"kind": item.claim_kind, "text": item.claim_text}) for item in values
            ),
            status="unresolved",
        )
        for key, values in sorted(by_key.items())
        if len({(item.claim_kind, item.claim_text) for item in values}) > 1
    )


def packet_payload(packet: ReviewPacketV1) -> dict[str, object]:
    """Canonical, public packet fields used to verify its content digest."""
    return {
        "schema_version": packet.schema_version,
        "status": packet.status,
        "source": packet.source.model_dump(mode="json"),
        "evidence": [item.model_dump(mode="json") for item in packet.evidence],
        "lineage_edges": [item.model_dump(mode="json") for item in packet.lineage_edges],
        "conflicts": [item.model_dump(mode="json") for item in packet.conflicts],
        "reviewer_actions": [item.model_dump(mode="json") for item in packet.reviewer_actions],
    }


def register_source(
    manifest: SourceManifestV1, evidence: Sequence[ExtractedEvidenceV1]
) -> ReviewPacketV1:
    """Validate provided bytes and create a review packet without parsing or executing them."""
    if type(manifest) is not SourceManifestV1:
        raise StrategyIngestError("INVALID_MANIFEST_TYPE")
    try:
        manifest = SourceManifestV1(
            **{**manifest.model_dump(), "source_bytes": manifest.source_bytes}
        )
    except Exception:
        raise StrategyIngestError("INVALID_MANIFEST_RECORD") from None
    raw = manifest.source_bytes
    if not raw:
        raise StrategyIngestError("missing_source_bytes")
    if len(raw) > 2_000_000_000:
        raise StrategyIngestError("source_size_exceeded")
    if manifest.media_type not in _SUPPORTED_MEDIA or not manifest.source_locator.lower().endswith(
        _SUPPORTED_MEDIA[manifest.media_type]
    ):
        raise StrategyIngestError("unsupported_media")
    byte_sha256 = hashlib.sha256(raw).hexdigest()
    if byte_sha256 != manifest.byte_sha256:
        raise StrategyIngestError("source_checksum_mismatch")
    if manifest.safe_scan.verdict != "clean":
        raise StrategyIngestError("scan_not_clean")
    if manifest.safe_scan.scanned_sha256 != byte_sha256:
        raise StrategyIngestError("scan_checksum_mismatch")
    if not manifest.acquired_ns <= manifest.safe_scan.scanned_at_ns <= manifest.review_asof_ns:
        raise StrategyIngestError("scan_time_invalid")
    if manifest.entitlement_status != "authorized":
        raise StrategyIngestError("source_entitlement_unapproved")
    if manifest.drm_status != "clear":
        raise StrategyIngestError("drm_not_clear")
    if (
        manifest.media_type.startswith(("audio/", "video/"))
        and manifest.transcriber_version is None
    ):
        raise StrategyIngestError("transcriber_version_missing")
    if _SECRET_MARKERS.search(raw):
        raise StrategyIngestError("secret_like_source")
    if manifest.media_type.startswith("text/"):
        try:
            raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise StrategyIngestError("opaque_text_source") from exc
        if any(byte < 32 and byte not in (9, 10, 13) for byte in raw):
            raise StrategyIngestError("opaque_text_source")

    try:
        claims = tuple(evidence)
    except Exception:
        raise StrategyIngestError("INVALID_EVIDENCE_INPUT") from None
    if not claims and manifest.license_status != "prohibited":
        raise StrategyIngestError("no_evidence")
    if claims and manifest.license_status == "prohibited":
        raise StrategyIngestError("prohibited_source_claims_forbidden")
    if not all(type(item) is ExtractedEvidenceV1 for item in claims):
        raise StrategyIngestError("INVALID_EVIDENCE_RECORD")
    try:
        claims = tuple(ExtractedEvidenceV1(**item.model_dump()) for item in claims)
    except Exception:
        raise StrategyIngestError("INVALID_EVIDENCE_RECORD") from None
    ids = [item.evidence_id for item in claims]
    if len(ids) != len(set(ids)) or manifest.source_id in ids:
        raise StrategyIngestError("duplicate_evidence_id")
    for item in claims:
        if item.source_sha256 != byte_sha256:
            raise StrategyIngestError("evidence_source_mismatch")
        span = item.span
        if span.byte_end > len(raw):
            raise StrategyIngestError("span_out_of_bounds")
        if hashlib.sha256(raw[span.byte_start : span.byte_end]).hexdigest() != span.span_sha256:
            raise StrategyIngestError("span_checksum_mismatch")
        if manifest.media_type == "application/pdf" and span.page_start is None:
            raise StrategyIngestError("page_span_missing")
        if manifest.media_type.startswith(("audio/", "video/")) and span.time_start_ms is None:
            raise StrategyIngestError("time_span_missing")
        if _SECRET_MARKERS.search(item.claim_text.encode("utf-8")):
            raise StrategyIngestError("secret_like_claim")
        if (
            manifest.license_status != "reuse_permitted"
            and manifest.media_type in _CODE_MEDIA
            and item.claim_text.encode("utf-8") in raw
        ):
            raise StrategyIngestError("unlicensed_source_copy")
        if manifest.media_type == "text/x-mt5-set" and item.claim_kind not in {
            "parameter",
            "unknown_logic",
        }:
            raise StrategyIngestError("parameter_file_cannot_prove_logic")
    _assert_acyclic(claims)

    ordered = tuple(sorted(claims, key=lambda item: item.evidence_id))
    edges = _edges_for(manifest.source_id, ordered)
    conflicts = _conflicts_for(ordered)
    source = SourceRecordV1(
        **manifest.model_dump(exclude={"source_bytes"}),
        byte_length=len(raw),
    )
    unpinned = ReviewPacketV1(
        schema_version="1",
        status="QUARANTINED",
        source=source,
        evidence=ordered,
        lineage_edges=edges,
        conflicts=conflicts,
        reviewer_actions=(),
        packet_sha256="",
    )
    return _issue_packet(
        ReviewPacketV1(
            schema_version="1",
            status="QUARANTINED",
            source=source,
            evidence=ordered,
            lineage_edges=edges,
            conflicts=conflicts,
            reviewer_actions=(),
            packet_sha256=digest(packet_payload(unpinned)),
        )
    )
