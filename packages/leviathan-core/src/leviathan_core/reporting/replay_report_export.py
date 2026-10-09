"""Deterministic, bounded C-102 replay provenance report exports.

FEAT-001 lineage is exact-type revalidated but is not SEAL-issued in this
slice. Its digests are caller-attested and reported with TYPED_UNSEALED
provenance; this module never hashes feature text or claims FEAT verification.
"""

from __future__ import annotations

import csv
import io
import json
import re
from dataclasses import dataclass
from decimal import Decimal
from typing import Final, NoReturn

from leviathan_core.feature_store.models import FeatureLineageV1, FeatureResultV1
from leviathan_core.numeric import canonical_str
from leviathan_core.research.replay_job import (
    ReplayResultArtifactV1,
    VerifiedReplayArtifactsV1,
    load_verified_replay_result,
    require_verified_replay_artifacts,
)
from leviathan_core.schemas.enums import TruthStatus
from leviathan_core.schemas.risk import GateFinding
from leviathan_core.text.safe_label import contains_deny_word, is_safe_identifier

SCHEMA_VERSION: Final = "leviathan.replay-provenance-report/1"
_FEATURE_PROVENANCE: Final = "TYPED_UNSEALED"
_REPLAY_PROVENANCE: Final = "SEALED_VERIFIED"
_DECIMAL_PROVENANCE: Final = "DECIMAL_NATIVE"
_TRUTH_STATUSES: Final = frozenset(status.value for status in TruthStatus)
_RESULT_STATUSES: Final = frozenset(("completed", "blocked"))
_SHA256_RE: Final = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_ARTIFACT_NAMES: Final = (
    "diagnostics.json",
    "input.canonical.json",
    "input.sha256",
    "result.canonical.json",
    "result.sha256",
    "risk_audit.jsonl",
)
_METRIC_PATHS: Final = (
    ("journal.entry", ("journal", "entry")),
    ("journal.exit", ("journal", "exit")),
    ("journal.mae", ("journal", "mae")),
    ("journal.mfe", ("journal", "mfe")),
    ("range.opening_range_high", ("range", "opening_range_high")),
    ("range.opening_range_low", ("range", "opening_range_low")),
    ("decision.confidence", ("decision", "confidence")),
    ("session.quality", ("session", "quality")),
    ("truth.sentiment_modifier", ("truth", "sentiment_modifier")),
    ("intent.size", ("intent", "size")),
    ("intent.stop_loss", ("intent", "stop_loss")),
    ("intent.take_profit", ("intent", "take_profit")),
)
_FEATURE_FIELDS: Final = (
    "feature_name",
    "feature_version",
    "instrument_id",
    "asof_ns",
    "definition_sha256",
    "observation_sha256",
    "source_dataset",
    "source_record_key",
    "provenance",
)


class ReplayReportError(ValueError):
    """Content-free report rejection with a stable code."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class ReplayReportExportV1:
    """Immutable deterministic serialized replay provenance report."""

    json_bytes: bytes
    csv_bytes: bytes


def _reject(code: str) -> NoReturn:
    raise ReplayReportError(code)


def _valid_digest(value: object) -> bool:
    return type(value) is str and _SHA256_RE.fullmatch(value) is not None


def _safe_identifier(value: object) -> bool:
    return (
        type(value) is str
        and is_safe_identifier(value)
        and not contains_deny_word(value)
    )


def _replay_projection(verified: VerifiedReplayArtifactsV1) -> dict[str, object]:
    # The verifier binds these strings to C-102 inputs but does not apply the
    # export boundary's text policy to every scalar.
    identifier_fields = (
        verified.strategy_ref,
        verified.strategy_id,
        verified.strategy_version,
        verified.dataset_id,
        verified.dataset_version,
        verified.truth_provider,
    )
    if any(not _safe_identifier(value) for value in identifier_fields):
        _reject("INVALID_REPLAY_ARTIFACTS")
    if (
        type(verified.truth_status) is not str
        or verified.truth_status not in _TRUTH_STATUSES
        or type(verified.result_status) is not str
        or verified.result_status not in _RESULT_STATUSES
    ):
        _reject("INVALID_REPLAY_ARTIFACTS")
    digest_fields = (
        verified.input_sha256,
        verified.result_sha256,
        verified.bars_sha256,
        verified.truth_sha256,
        verified.verified_lock_sha256,
    )
    if any(not _valid_digest(value) for value in digest_fields):
        _reject("INCONSISTENT_HASHES")
    if (
        type(verified.first_bar_ns) is not int
        or type(verified.last_bar_ns) is not int
        or verified.first_bar_ns > verified.last_bar_ns
        or verified.status != "COMPLETE"
        or verified.provenance != "C102_COMPLETE_REHASHED"
    ):
        _reject("INVALID_REPLAY_ARTIFACTS")

    pairs = verified.artifact_sha256
    if type(pairs) is not tuple or len(pairs) != len(_ARTIFACT_NAMES):
        _reject("INCONSISTENT_HASHES")
    if any(
        type(pair) is not tuple
        or len(pair) != 2
        or type(pair[0]) is not str
        or not _valid_digest(pair[1])
        for pair in pairs
    ):
        _reject("INCONSISTENT_HASHES")
    names = tuple(pair[0] for pair in pairs)
    if names != tuple(sorted(names)) or len(set(names)) != len(names):
        _reject("INCONSISTENT_HASHES")
    pair_map = dict(pairs)
    if (
        set(pair_map) != set(_ARTIFACT_NAMES)
        or pair_map.get("input.canonical.json") != verified.input_sha256
        or pair_map.get("result.canonical.json") != verified.result_sha256
    ):
        _reject("INCONSISTENT_HASHES")

    return {
        "input_sha256": verified.input_sha256,
        "result_sha256": verified.result_sha256,
        "strategy_ref": verified.strategy_ref,
        "strategy_id": verified.strategy_id,
        "strategy_version": verified.strategy_version,
        "dataset_id": verified.dataset_id,
        "dataset_version": verified.dataset_version,
        "bars_sha256": verified.bars_sha256,
        "truth_provider": verified.truth_provider,
        "truth_status": verified.truth_status,
        "truth_sha256": verified.truth_sha256,
        "verified_lock_sha256": verified.verified_lock_sha256,
        "result_status": verified.result_status,
        "first_bar_ns": verified.first_bar_ns,
        "last_bar_ns": verified.last_bar_ns,
        "artifact_sha256": [{"filename": filename, "sha256": digest} for filename, digest in pairs],
    }


def _revalidate_feature(value: object) -> FeatureResultV1:
    if type(value) is not FeatureResultV1:
        _reject("INVALID_FEATURE_LINEAGE")
    try:
        payload = value.model_dump(mode="python")
        return FeatureResultV1.model_validate(payload, strict=True)
    except Exception:
        _reject("INVALID_FEATURE_LINEAGE")


def _feature_projection(
    features: tuple[FeatureResultV1, ...], verified: VerifiedReplayArtifactsV1
) -> list[dict[str, object]]:
    if type(features) is not tuple:
        _reject("INVALID_FEATURE_LINEAGE")
    projected: list[dict[str, object]] = []
    identities: set[tuple[str, str, str]] = set()
    asofs: set[int] = set()
    for candidate in features:
        feature = _revalidate_feature(candidate)
        lineage = feature.lineage
        if type(lineage) is not FeatureLineageV1:
            _reject("INVALID_FEATURE_LINEAGE")
        identity = (feature.feature_name, feature.feature_version, feature.instrument_id)
        if identity in identities:
            _reject("INVALID_FEATURE_LINEAGE")
        identities.add(identity)
        asofs.add(feature.asof_ns)

        required_text = (
            feature.feature_name,
            feature.feature_version,
            feature.instrument_id,
            lineage.source_dataset,
        )
        if any(not _safe_identifier(item) for item in required_text):
            _reject("INVALID_FEATURE_LINEAGE")
        if lineage.source_record_key is not None and not _safe_identifier(
            lineage.source_record_key
        ):
            _reject("INVALID_FEATURE_LINEAGE")
        if lineage.source_dataset != verified.dataset_id:
            _reject("INVALID_FEATURE_LINEAGE")
        if (
            feature.source_dataset != lineage.source_dataset
            or feature.source_record_key != lineage.source_record_key
            or feature.definition_hash != lineage.definition_sha256
            or feature.observation_hash != lineage.observation_sha256
        ):
            _reject("INVALID_FEATURE_LINEAGE")
        if not _valid_digest(lineage.definition_sha256):
            _reject("INVALID_FEATURE_LINEAGE")
        if lineage.observation_sha256 is not None and not _valid_digest(lineage.observation_sha256):
            _reject("INVALID_FEATURE_LINEAGE")
        if type(feature.asof_ns) is not int or not (
            verified.first_bar_ns <= feature.asof_ns <= verified.last_bar_ns
        ):
            _reject("INVALID_FEATURE_LINEAGE")

        projected.append(
            {
                "feature_name": feature.feature_name,
                "feature_version": feature.feature_version,
                "instrument_id": feature.instrument_id,
                "asof_ns": feature.asof_ns,
                "definition_sha256": lineage.definition_sha256,
                "observation_sha256": lineage.observation_sha256,
                "source_dataset": lineage.source_dataset,
                "source_record_key": lineage.source_record_key,
                "provenance": _FEATURE_PROVENANCE,
            }
        )
    if len(asofs) > 1:
        _reject("INVALID_FEATURE_LINEAGE")
    projected.sort(
        key=lambda row: (
            str(row["feature_name"]),
            str(row["feature_version"]),
            str(row["instrument_id"]),
        )
    )
    return projected


def _metric_value(value: object) -> tuple[str, str]:
    if type(value) is not Decimal or not value.is_finite():
        _reject("INVALID_REPLAY_RESULT")
    try:
        return canonical_str(value), _DECIMAL_PROVENANCE
    except (ValueError, ArithmeticError):
        _reject("INVALID_REPLAY_RESULT")


def _metrics(result: ReplayResultArtifactV1) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for name, path in _METRIC_PATHS:
        current: object = result
        missing = False
        for component in path:
            if current is None:
                missing = True
                break
            current = getattr(current, component, None)
            if current is None:
                missing = True
                break
        if missing:
            rows.append({"name": name, "present": False, "value": None, "provenance": None})
            continue
        value, provenance = _metric_value(current)
        rows.append({"name": name, "present": True, "value": value, "provenance": provenance})
    return rows


def _diagnostics(result: ReplayResultArtifactV1) -> list[str]:
    findings: set[str] = set()
    for verdict in (result.assessment, result.final_verdict):
        for finding in verdict.findings:
            if type(finding) is not GateFinding:
                _reject("INVALID_REPLAY_RESULT")
            findings.add(finding.value)
    return sorted(findings)


def _csv_bytes(report: dict[str, object]) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(("schema_version", "section", "subject", "field", "present", "value"))
    version = report["schema_version"]

    def row(section: str, subject: str, field: str, present: bool, value: object) -> None:
        rendered = "" if value is None else value
        writer.writerow(
            (version, section, subject, field, "true" if present else "false", rendered)
        )

    replay = report["replay"]
    assert isinstance(replay, dict)
    for field, value in replay.items():
        if field == "artifact_sha256":
            artifacts = value
            assert isinstance(artifacts, list)
            for artifact in artifacts:
                assert isinstance(artifact, dict)
                row("artifact", str(artifact["filename"]), "sha256", True, artifact["sha256"])
        else:
            row("replay", "replay", field, True, value)
    features = report["features"]
    assert isinstance(features, list)
    for index, feature in enumerate(features):
        assert isinstance(feature, dict)
        subject = f"feature:{index}"
        for field in _FEATURE_FIELDS:
            value = feature[field]
            row("feature", subject, field, value is not None, value)
    metrics = report["metrics"]
    assert isinstance(metrics, list)
    for metric in metrics:
        assert isinstance(metric, dict)
        row("metric", str(metric["name"]), "value", bool(metric["present"]), metric["value"])
        row(
            "metric",
            str(metric["name"]),
            "provenance",
            metric["provenance"] is not None,
            metric["provenance"],
        )
    completeness = report["completeness"]
    assert isinstance(completeness, dict)
    for field, value in completeness.items():
        row("completeness", "replay", field, True, value)
    provenance = report["provenance"]
    assert isinstance(provenance, dict)
    for field, value in provenance.items():
        row("provenance", "report", field, True, value)
    diagnostic_codes = report["diagnostic_codes"]
    assert isinstance(diagnostic_codes, list)
    for index, code in enumerate(diagnostic_codes):
        row("diagnostic", f"diagnostic:{index}", "code", True, code)
    return output.getvalue().encode("utf-8")


def export_replay_report(
    verified: object,
    feature_results: tuple[FeatureResultV1, ...] = (),
) -> ReplayReportExportV1:
    """Export deterministic JSON and CSV; FEAT digests remain caller-attested.

    C-102 metadata is consumed only through its sealed verifier and loader.
    This function does no filesystem access, digest calculation, numerical
    transformation, throughput measurement, or profitability/promotion claim.
    """
    try:
        evidence = require_verified_replay_artifacts(verified)
    except Exception:
        _reject("INVALID_REPLAY_ARTIFACTS")
    replay = _replay_projection(evidence)
    try:
        result = load_verified_replay_result(evidence)
    except Exception:
        _reject("INVALID_REPLAY_ARTIFACTS")
    if type(result) is not ReplayResultArtifactV1:
        _reject("INVALID_REPLAY_RESULT")
    if (
        result.input_sha256 != evidence.input_sha256
        or result.bars_sha256 != evidence.bars_sha256
        or result.verified_lock_sha256 != evidence.verified_lock_sha256
        or result.status != evidence.result_status
    ):
        _reject("INCONSISTENT_HASHES")
    feature_rows = _feature_projection(feature_results, evidence)
    metric_rows = _metrics(result)
    diagnostics = _diagnostics(result)
    report: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "replay": replay,
        "features": feature_rows,
        "metrics": metric_rows,
        "completeness": {
            "status": evidence.status,
            "provenance": evidence.provenance,
        },
        "diagnostic_codes": diagnostics,
        "provenance": {
            "replay": _REPLAY_PROVENANCE,
            "features": _FEATURE_PROVENANCE,
        },
    }
    try:
        json_bytes = json.dumps(
            report, ensure_ascii=True, allow_nan=False, separators=(",", ":")
        ).encode("utf-8")
        csv_bytes = _csv_bytes(report)
    except (TypeError, ValueError, UnicodeError):
        _reject("INVALID_REPLAY_RESULT")
    return ReplayReportExportV1(json_bytes=json_bytes, csv_bytes=csv_bytes)
