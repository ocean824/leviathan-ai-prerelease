"""Independent acceptance for REPLAY-REPORT-EXPORT-001 (replay provenance report).

Written from the Wave 29 contract (section 10), the coordinator's feature/metric binding and the
writer's frozen interface, not from the writer's tests. A report is deterministic bytes built only
from sealed C-102 evidence; any failure yields an error and never a partial report.
"""

from __future__ import annotations

import csv
import dataclasses
import hashlib
import io
import json
import os
import re
import shutil
import socket
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from leviathan_core.feature_store.models import FeatureLineageV1, FeatureResultV1
from leviathan_core.numeric import canonical_str
from leviathan_core.reporting import replay_report_export as exporter
from leviathan_core.reporting.replay_report_export import (
    ReplayReportError,
    ReplayReportExportV1,
    export_replay_report,
)
from leviathan_core.research.replay_job import (
    ReplayArtifacts,
    ReplayJobError,
    run_replay_job,
    verify_replay_artifacts,
)

FIXTURE_DIR = Path(__file__).parents[1] / "fixtures" / "replay_job"
FIXTURE = FIXTURE_DIR / "v1-nq.json"
RISK_LOCK = FIXTURE_DIR / "risk_lock.yaml"
RESULT_GOLDEN = FIXTURE_DIR / "v1-nq.result.canonical.golden.json"
SCHEMA = "leviathan.replay-provenance-report/1"
CANARY = "SYNTHETIC_REPORT_CANARY_DO_NOT_ECHO"
DEFINITION_SHA = "a" * 64
OBSERVATION_SHA = "b" * 64
TOP_LEVEL = [
    "schema_version", "replay", "features", "metrics", "completeness", "diagnostic_codes",
    "provenance",
]
REPLAY_FIELDS = [
    "input_sha256", "result_sha256", "strategy_ref", "strategy_id", "strategy_version",
    "dataset_id", "dataset_version", "bars_sha256", "truth_provider", "truth_status",
    "truth_sha256", "verified_lock_sha256", "result_status", "first_bar_ns", "last_bar_ns",
    "artifact_sha256",
]
FEATURE_FIELDS = [
    "feature_name", "feature_version", "instrument_id", "asof_ns", "definition_sha256",
    "observation_sha256", "source_dataset", "source_record_key", "provenance",
]
METRICS = [
    "journal.entry", "journal.exit", "journal.mae", "journal.mfe", "range.opening_range_high",
    "range.opening_range_low", "decision.confidence", "session.quality",
    "truth.sentiment_modifier", "intent.size", "intent.stop_loss", "intent.take_profit",
]
ERROR_CODES = {
    "INVALID_REPLAY_ARTIFACTS", "INCONSISTENT_HASHES", "INVALID_REPLAY_RESULT",
    "INVALID_FEATURE_LINEAGE",
}
FREE_TEXT = [
    "post_trade_notes", "paper_sim target_hit", "Sanitized deterministic fixture evidence",
    "synthetic balanced near-dated context", "consensus=0.86", "justification",
]
FORBIDDEN_CLAIMS = re.compile(
    r"throughput|profitab|pnl|sharpe|promot|eligib|live[_ -]?ready|deployable|win[_ ]?rate",
    re.IGNORECASE,
)


def _manifest(**changes: Any) -> dict[str, Any]:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    for dotted, value in changes.items():
        target = data
        *path, last = dotted.split("__")
        for key in path:
            target = target[key]
        target[last] = value
    return data


def _ns(timestamp: str) -> int:
    moment = datetime.fromisoformat(timestamp.replace("Z", "+00:00")).astimezone(UTC)
    return (moment - datetime(1970, 1, 1, tzinfo=UTC)) // timedelta(microseconds=1) * 1000


MANIFEST = _manifest()
DATASET = MANIFEST["dataset"]["dataset_id"]
FIRST_BAR_NS = _ns(MANIFEST["dataset"]["bars"][0]["timestamp"])
LAST_BAR_NS = _ns(MANIFEST["dataset"]["bars"][-1]["timestamp"])
GOLDEN = json.loads(RESULT_GOLDEN.read_text(encoding="utf-8"))


def _run(tmp_path: Path, name: str = "run", **changes: Any) -> ReplayArtifacts:
    manifest = tmp_path / f"{name}.json"
    manifest.write_text(json.dumps(_manifest(**changes)), encoding="utf-8")
    return run_replay_job(manifest, RISK_LOCK, tmp_path / name)


def _feature(
    *,
    name: str = "rsi",
    version: str = "1",
    instrument: str = "NQ",
    asof: int | None = None,
    dataset: str | None = DATASET,
    record: str | None = "rec-1",
    definition_sha: str = DEFINITION_SHA,
    observation_sha: str | None = OBSERVATION_SHA,
) -> FeatureResultV1:
    stamp = FIRST_BAR_NS + 60_000_000_000 if asof is None else asof
    return FeatureResultV1(
        found=True, feature_name=name, feature_version=version, instrument_id=instrument,
        asof_ns=stamp, value_decimal=Decimal("1.5"), quality="ok", source_dataset=dataset,
        source_record_key=record, event_time_ns=stamp, availability_ns=stamp,
        source_keys=(record,) if record else (), definition_hash=definition_sha,
        observation_hash=observation_sha,
        lineage=FeatureLineageV1(
            definition_sha256=definition_sha, observation_sha256=observation_sha,
            source_dataset=dataset, source_record_key=record,
        ),
    )


@pytest.fixture(scope="module")
def baseline(tmp_path_factory: pytest.TempPathFactory) -> ReplayArtifacts:
    return _run(tmp_path_factory.mktemp("report-baseline"))


@pytest.fixture
def verified(baseline: ReplayArtifacts) -> Any:
    return verify_replay_artifacts(baseline)


def _report(report: ReplayReportExportV1) -> dict[str, Any]:
    return json.loads(report.json_bytes)


def _expect_error(action: Any, *codes: str) -> ReplayReportError:
    with pytest.raises(ReplayReportError) as raised:
        action()
    assert raised.value.code in (set(codes) or ERROR_CODES)
    assert str(raised.value) == raised.value.code
    assert CANARY not in f"{raised.value!r} {raised.value}"
    assert raised.value.__cause__ is None or CANARY not in repr(raised.value.__cause__)
    return raised.value


def _copy_run(artifacts: ReplayArtifacts, destination: Path) -> ReplayArtifacts:
    shutil.copytree(artifacts.result_path.parent, destination)
    return dataclasses.replace(
        artifacts,
        input_path=destination / artifacts.input_path.name,
        result_path=destination / artifacts.result_path.name,
        complete_path=destination / artifacts.complete_path.name,
    )


def _junction(target: Path, link: Path) -> None:
    import _winapi  # stdlib on Windows; no administrator rights needed

    _winapi.CreateJunction(str(target), str(link))


# ------------------------------------------------------------------ bytes and schema


def test_the_export_is_a_frozen_pair_of_bytes(verified: Any) -> None:
    report = export_replay_report(verified)
    assert type(report) is ReplayReportExportV1
    assert dataclasses.is_dataclass(report)
    assert [f.name for f in dataclasses.fields(report)] == ["json_bytes", "csv_bytes"]
    assert isinstance(report.json_bytes, bytes) and isinstance(report.csv_bytes, bytes)
    with pytest.raises(dataclasses.FrozenInstanceError):
        report.json_bytes = b"{}"  # type: ignore[misc]


def test_equal_inputs_give_identical_bytes_every_time(verified: Any, tmp_path: Path) -> None:
    first = export_replay_report(verified, (_feature(),))
    second = export_replay_report(verified, (_feature(),))
    assert first == second
    assert first.json_bytes == second.json_bytes and first.csv_bytes == second.csv_bytes
    again = verify_replay_artifacts(_run(tmp_path, "again"))
    assert export_replay_report(again).json_bytes == export_replay_report(verified).json_bytes


def test_json_is_compact_utf8_with_the_frozen_schema_and_field_order(verified: Any) -> None:
    raw = export_replay_report(verified).json_bytes
    text = raw.decode("utf-8")
    assert not raw.startswith(b"\xef\xbb\xbf") and "\r" not in text and "\n" not in text
    document = json.loads(text)
    assert text == json.dumps(document, separators=(",", ":"), ensure_ascii=False)
    assert list(document) == TOP_LEVEL
    assert document["schema_version"] == SCHEMA
    assert list(document["replay"]) == REPLAY_FIELDS
    assert document["completeness"] == {
        "status": "COMPLETE", "provenance": "C102_COMPLETE_REHASHED",
    }
    assert document["provenance"] == {"replay": "SEALED_VERIFIED", "features": "TYPED_UNSEALED"}
    assert document["features"] == [] and isinstance(document["diagnostic_codes"], list)


def test_replay_identity_is_copied_from_the_verifier_and_digests_are_preserved(
    verified: Any, baseline: ReplayArtifacts,
) -> None:
    replay = _report(export_replay_report(verified))["replay"]
    for name in REPLAY_FIELDS[:-1]:
        assert replay[name] == getattr(verified, name), name
    assert replay["input_sha256"] == baseline.input_sha256
    assert replay["result_sha256"] == baseline.result_sha256
    assert replay["first_bar_ns"] == FIRST_BAR_NS and replay["last_bar_ns"] == LAST_BAR_NS
    assert [(item["filename"], item["sha256"]) for item in replay["artifact_sha256"]] == [
        tuple(pair) for pair in verified.artifact_sha256
    ]
    assert [item["filename"] for item in replay["artifact_sha256"]] == sorted(
        item["filename"] for item in replay["artifact_sha256"]
    )
    assert len(replay["artifact_sha256"]) == 6


def test_metrics_are_the_closed_whitelist_copied_without_arithmetic(verified: Any) -> None:
    metrics = _report(export_replay_report(verified))["metrics"]
    assert [item["name"] for item in metrics] == METRICS
    assert all(list(item) == ["name", "present", "value", "provenance"] for item in metrics)
    expected = {
        name: GOLDEN[name.split(".")[0]][name.split(".")[1]] for name in METRICS
    }
    for item in metrics:
        assert item["present"] is True
        assert item["value"] == expected[item["name"]], item["name"]
        assert isinstance(item["value"], str)
        assert item["provenance"] == "DECIMAL_NATIVE", item["name"]


def test_an_absent_metric_is_reported_absent_never_as_zero(tmp_path: Path) -> None:
    artifacts = _run(tmp_path, "blocked", risk__initial_halts=["operator_hold"])
    blocked = verify_replay_artifacts(artifacts)
    source = json.loads(artifacts.result_path.read_bytes())
    metrics = {item["name"]: item for item in _report(export_replay_report(blocked))["metrics"]}
    absent = []
    for name in METRICS:
        group, field = name.split(".")
        raw = (source.get(group) or {}).get(field)
        item = metrics[name]
        if raw is None:
            absent.append(name)
            assert item == {"name": name, "present": False, "value": None, "provenance": None}
        else:
            assert item["present"] is True and item["value"] == raw, name
    # A blocked route never produced an intent, so those three metrics must be absent.
    assert {"intent.size", "intent.stop_loss", "intent.take_profit"} <= set(absent)
    for name in absent:
        assert metrics[name]["value"] not in ("0", 0, "")
    rows = list(csv.reader(io.StringIO(export_replay_report(blocked).csv_bytes.decode("utf-8"))))
    for name in absent:
        row = next(row for row in rows[1:] if name in " ".join(row[1:4]))
        assert row[4] == "false" and row[5] == "", name


def test_no_free_text_or_claim_reaches_the_report(verified: Any) -> None:
    report = export_replay_report(verified, (_feature(),))
    text = report.json_bytes.decode("utf-8") + report.csv_bytes.decode("utf-8")
    for fragment in FREE_TEXT:
        assert fragment not in text, fragment
    assert not FORBIDDEN_CLAIMS.search(text)
    document = _report(report)
    assert all(re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", code) for code in document["diagnostic_codes"])
    assert document["diagnostic_codes"] == sorted(set(document["diagnostic_codes"]))


# ---------------------------------------------------------------------------- CSV


def test_csv_is_lf_utf8_with_the_frozen_header_and_agrees_with_json(verified: Any) -> None:
    report = export_replay_report(verified, (_feature(),))
    text = report.csv_bytes.decode("utf-8")
    assert "\r" not in text and not report.csv_bytes.startswith(b"\xef\xbb\xbf")
    rows = list(csv.reader(io.StringIO(text)))
    assert rows[0] == ["schema_version", "section", "subject", "field", "present", "value"]
    assert all(len(row) == 6 for row in rows) and all(row[0] == SCHEMA for row in rows[1:])
    document = _report(report)
    joined = [" ".join(row[1:4]) for row in rows[1:]]
    for name in METRICS:
        assert any(name in line for line in joined), name
    metric_rows = {
        name: next(row for row in rows[1:] if name in " ".join(row[1:4])) for name in METRICS
    }
    for item in document["metrics"]:
        row = metric_rows[item["name"]]
        assert row[4] == ("true" if item["present"] else "false")
        assert row[5] == ("" if item["value"] is None else item["value"])
    values = {row[5] for row in rows[1:]}
    for field in ("input_sha256", "result_sha256", "bars_sha256", "dataset_id"):
        assert document["replay"][field] in values, field


# ------------------------------------------------------------------ feature lineage


def test_features_are_reported_as_typed_unsealed_and_caller_attested(verified: Any) -> None:
    features = (
        _feature(name="rsi", asof=FIRST_BAR_NS + 60_000_000_000),
        _feature(name="atr", asof=FIRST_BAR_NS + 60_000_000_000, record="rec-2"),
    )
    items = _report(export_replay_report(verified, features))["features"]
    assert len(items) == 2
    assert all(list(item) == FEATURE_FIELDS for item in items)
    assert all(item["provenance"] == "TYPED_UNSEALED" for item in items)
    assert all(item["source_dataset"] == DATASET for item in items)
    # Output is stably sorted by (feature_name, feature_version, instrument_id).
    ordered = sorted(
        features, key=lambda f: (f.feature_name, f.feature_version, f.instrument_id)
    )
    assert [item["feature_name"] for item in items] == ["atr", "rsi"]
    for item, source in zip(items, ordered, strict=True):
        assert item["definition_sha256"] == source.lineage.definition_sha256 == DEFINITION_SHA
        assert item["observation_sha256"] == OBSERVATION_SHA
        assert item["feature_name"] == source.feature_name and item["asof_ns"] == source.asof_ns
        assert item["source_record_key"] == source.source_record_key


def test_the_input_order_of_features_never_changes_the_bytes(verified: Any) -> None:
    stamp = FIRST_BAR_NS + 60_000_000_000
    features = (
        _feature(name="rsi", version="2", asof=stamp),
        _feature(name="atr", asof=stamp, record="rec-2"),
        _feature(name="rsi", version="1", asof=stamp, instrument="ES", record="rec-3"),
        _feature(name="rsi", version="1", asof=stamp, instrument="NQ", record="rec-4"),
    )
    forward = export_replay_report(verified, features)
    assert export_replay_report(verified, tuple(reversed(features))) == forward
    shuffled = (features[2], features[0], features[3], features[1])
    assert export_replay_report(verified, shuffled) == forward
    keys = [
        (i["feature_name"], i["feature_version"], i["instrument_id"])
        for i in _report(forward)["features"]
    ]
    assert keys == sorted(keys)


def test_the_as_of_window_is_inclusive_at_both_bar_ends(verified: Any) -> None:
    for stamp in (FIRST_BAR_NS, LAST_BAR_NS, FIRST_BAR_NS + 1):
        report = export_replay_report(verified, (_feature(asof=stamp),))
        assert _report(report)["features"][0]["asof_ns"] == stamp


def test_a_feature_from_another_dataset_is_rejected(verified: Any) -> None:
    for dataset in ("another-dataset", DATASET + "x", DATASET.upper(), DATASET[:-1]):
        _expect_error(lambda dataset=dataset: export_replay_report(
            verified, (_feature(dataset=dataset),)), "INVALID_FEATURE_LINEAGE")


def test_a_missing_dataset_is_rejected(verified: Any) -> None:
    _expect_error(
        lambda: export_replay_report(verified, (_feature(dataset=None),)),
        "INVALID_FEATURE_LINEAGE",
    )


def test_grammar_invalid_text_is_rejected_and_never_echoed(verified: Any) -> None:
    unsafe = [
        f"bad {CANARY}", f"{CANARY}\n", f"{CANARY};x", f"../{CANARY}", f"{CANARY}\x00",
        f"é{CANARY}", "x" * 4096 + CANARY, f"{CANARY},{CANARY}", f'"{CANARY}"',
    ]
    for text in unsafe:
        for build in (
            lambda text=text: _feature(dataset=text),
            lambda text=text: _feature(name=text),
            lambda text=text: _feature(instrument=text),
            lambda text=text: _feature(record=text),
        ):
            def attempt(build=build) -> ReplayReportExportV1:
                return export_replay_report(verified, (build(),))

            try:
                _expect_error(attempt, "INVALID_FEATURE_LINEAGE")
            except pytest.fail.Exception:
                raise
            except ValueError:
                # The FEAT model itself refused the value before the exporter saw it.
                continue


def test_mixed_as_of_values_are_rejected(verified: Any) -> None:
    base = FIRST_BAR_NS + 60_000_000_000
    _expect_error(lambda: export_replay_report(
        verified, (_feature(name="rsi", asof=base), _feature(name="atr", asof=base + 1))),
        "INVALID_FEATURE_LINEAGE")


def test_an_as_of_outside_the_replay_bar_window_is_rejected_as_lookahead(verified: Any) -> None:
    for stamp in (LAST_BAR_NS + 1, LAST_BAR_NS + 10**12, FIRST_BAR_NS - 1, 0):
        _expect_error(
            lambda stamp=stamp: export_replay_report(verified, (_feature(asof=stamp),)),
            "INVALID_FEATURE_LINEAGE",
        )


def test_duplicate_feature_identity_is_rejected(verified: Any) -> None:
    _expect_error(lambda: export_replay_report(
        verified, (_feature(), _feature(observation_sha="c" * 64))), "INVALID_FEATURE_LINEAGE")
    # The same name under another version or instrument is a different identity.
    export_replay_report(verified, (_feature(), _feature(version="2")))
    export_replay_report(verified, (_feature(), _feature(instrument="ES")))


def test_feature_digests_must_be_lowercase_sha256_hex(verified: Any) -> None:
    for bad in ("A" * 64, "a" * 63, "a" * 65, "g" * 64, "", CANARY):
        for build in (
            lambda bad=bad: _feature(definition_sha=bad),
            lambda bad=bad: _feature(observation_sha=bad),
        ):
            try:
                feature = build()
            except ValueError:
                continue
            _expect_error(lambda feature=feature: export_replay_report(verified, (feature,)),
                          "INVALID_FEATURE_LINEAGE")


def test_the_exporter_never_hashes_feature_data_itself(verified: Any) -> None:
    other = _feature(definition_sha="d" * 64, observation_sha="e" * 64)
    item = _report(export_replay_report(verified, (other,)))["features"][0]
    assert (item["definition_sha256"], item["observation_sha256"]) == ("d" * 64, "e" * 64)


def test_wrong_feature_argument_types_are_rejected(verified: Any) -> None:
    good = _feature()
    for bad in (
        [good], {"feature_name": "rsi"}, "rsi", (good, None), (good.model_dump(),), (object(),), 7,
        (good, good.lineage),
    ):
        _expect_error(lambda bad=bad: export_replay_report(verified, bad),  # type: ignore[arg-type]
                      "INVALID_FEATURE_LINEAGE")


# ----------------------------------------------------- the C-102 proof and the loader


def test_only_a_sealed_verified_replay_is_accepted(
    verified: Any, baseline: ReplayArtifacts,
) -> None:
    for bad in (None, baseline, "verified", {"status": "COMPLETE"}, object(), 7, b"x"):
        _expect_error(lambda bad=bad: export_replay_report(bad), "INVALID_REPLAY_ARTIFACTS")
    forged = object.__new__(type(verified))
    for name in type(verified).model_fields:
        object.__setattr__(forged, name, getattr(verified, name))
    _expect_error(lambda: export_replay_report(forged), "INVALID_REPLAY_ARTIFACTS")
    _expect_error(lambda: export_replay_report(type(verified).model_construct()),
                  "INVALID_REPLAY_ARTIFACTS")


def test_an_altered_or_inconsistent_verified_replay_is_rejected(baseline: ReplayArtifacts) -> None:
    altered = verify_replay_artifacts(baseline)
    object.__setattr__(altered, "result_sha256", "0" * 64)
    _expect_error(lambda: export_replay_report(altered),
                  "INVALID_REPLAY_ARTIFACTS", "INCONSISTENT_HASHES")
    copied = verify_replay_artifacts(baseline).model_copy(update={"input_sha256": "1" * 64})
    _expect_error(lambda: export_replay_report(copied),
                  "INVALID_REPLAY_ARTIFACTS", "INCONSISTENT_HASHES")


def test_a_result_file_altered_after_verification_gives_no_report(
    baseline: ReplayArtifacts, tmp_path: Path,
) -> None:
    copied = _copy_run(baseline, tmp_path / "late-tamper")
    verified_copy = verify_replay_artifacts(copied)
    export_replay_report(verified_copy)
    copied.result_path.write_bytes(copied.result_path.read_bytes() + b" ")
    _expect_error(lambda: export_replay_report(verified_copy),
                  "INVALID_REPLAY_ARTIFACTS", "INCONSISTENT_HASHES")


def test_a_non_finite_or_unknown_result_is_rejected(
    baseline: ReplayArtifacts, monkeypatch: pytest.MonkeyPatch,
) -> None:
    verified_now = verify_replay_artifacts(baseline)
    real = exporter.load_verified_replay_result(verified_now)
    journal = real.journal.model_copy(update={"mae": Decimal("NaN")})
    for broken in (
        real.model_copy(update={"journal": journal}),
        real.model_copy(
            update={"journal": real.journal.model_copy(update={"mfe": Decimal("Infinity")})}
        ),
    ):
        monkeypatch.setattr(
            exporter, "load_verified_replay_result", lambda _v, broken=broken: broken
        )
        _expect_error(lambda: export_replay_report(verified_now), "INVALID_REPLAY_RESULT")
    monkeypatch.setattr(exporter, "load_verified_replay_result", lambda _v: object())
    _expect_error(lambda: export_replay_report(verified_now), "INVALID_REPLAY_RESULT")
    monkeypatch.setattr(exporter, "load_verified_replay_result", lambda _v: None)
    _expect_error(lambda: export_replay_report(verified_now), "INVALID_REPLAY_RESULT")


@pytest.mark.skipif(sys.platform != "win32", reason="directory junctions are Windows-only")
def test_a_junction_for_the_artifact_root_gives_no_report(
    baseline: ReplayArtifacts, tmp_path: Path,
) -> None:
    real = _copy_run(baseline, tmp_path / "real-run")
    link = tmp_path / "linked-run"
    _junction(real.result_path.parent, link)
    through_link = dataclasses.replace(
        real,
        input_path=link / real.input_path.name,
        result_path=link / real.result_path.name,
        complete_path=link / real.complete_path.name,
    )
    with pytest.raises(ReplayJobError) as raised:
        verify_replay_artifacts(through_link)
    assert raised.value.code == "ARTIFACT_INVALID"
    _expect_error(lambda: export_replay_report(through_link), "INVALID_REPLAY_ARTIFACTS")


@pytest.mark.skipif(sys.platform != "win32", reason="directory junctions are Windows-only")
@pytest.mark.parametrize("swap", ["same-content", "other-run"])
def test_a_junction_swapped_in_after_verification_gives_no_report(
    baseline: ReplayArtifacts, tmp_path: Path, swap: str,
) -> None:
    copied = _copy_run(baseline, tmp_path / "swapped")
    verified_copy = verify_replay_artifacts(copied)
    run_dir = copied.result_path.parent
    if swap == "same-content":
        moved = tmp_path / "swapped-moved"
        os.rename(run_dir, moved)
        _junction(moved, run_dir)
    else:
        other = _copy_run(_run(tmp_path, "other-source", seed=7), tmp_path / "other-run")
        shutil.rmtree(run_dir)
        _junction(other.result_path.parent, run_dir)
    _expect_error(lambda: export_replay_report(verified_copy), "INVALID_REPLAY_ARTIFACTS")


# --------------------------------------------------------- no partial output, no effects


def test_a_failure_never_leaves_a_partial_report_or_touches_the_run(
    baseline: ReplayArtifacts, verified: Any,
) -> None:
    run_dir = baseline.result_path.parent
    before = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(run_dir.iterdir())}
    results: list[object] = []
    for features in ((_feature(dataset="other"),), (_feature(asof=LAST_BAR_NS + 1),),
                     (_feature(), _feature())):
        try:
            results.append(export_replay_report(verified, features))
        except ReplayReportError:
            continue
    assert results == []
    export_replay_report(verified, (_feature(),))
    after = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(run_dir.iterdir())}
    assert after == before


def test_export_makes_no_network_or_process_call(
    verified: Any, monkeypatch: pytest.MonkeyPatch,
) -> None:
    def blocked(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("network or process call during export")

    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    monkeypatch.setattr(subprocess, "Popen", blocked)
    export_replay_report(verified, (_feature(),))


def test_the_replay_runner_output_bytes_are_unchanged(baseline: ReplayArtifacts) -> None:
    assert baseline.result_path.read_bytes() == RESULT_GOLDEN.read_bytes()
    assert _manifest() == MANIFEST


# ------------------------------------- every exported text scalar passes its grammar or enum

TEXT_SCALARS = (
    "strategy_ref", "strategy_id", "strategy_version", "dataset_id", "dataset_version",
    "truth_provider", "truth_status",
)
SECRET_SHAPED = (
    f"bad {CANARY}", f"{CANARY}\n", f"{CANARY};x", f"../{CANARY}", f"{CANARY}\x00",
    f"é{CANARY}", "x" * 4096 + CANARY, f"{CANARY},{CANARY}", f'"{CANARY}"',
    f"api_key={CANARY}", f"=cmd|{CANARY}", f"Bearer {CANARY}", "",
)


@pytest.fixture
def passthrough(baseline: ReplayArtifacts, monkeypatch: pytest.MonkeyPatch) -> Any:
    """Isolate the exporter's own text checks from the SEAL proof: the proof check passes any
    object through, and the loader returns the genuine result, so only the scalars differ."""
    genuine = verify_replay_artifacts(baseline)
    result = exporter.load_verified_replay_result(genuine)
    monkeypatch.setattr(exporter, "require_verified_replay_artifacts", lambda value: value)
    monkeypatch.setattr(exporter, "load_verified_replay_result", lambda _value: result)
    return genuine


def test_the_control_object_exports_under_the_isolation(passthrough: Any) -> None:
    # Without this the rejections below could be caused by the isolation itself.
    copy = passthrough.model_copy()
    assert export_replay_report(copy) == export_replay_report(passthrough)


@pytest.mark.parametrize("field", TEXT_SCALARS)
def test_a_secret_shaped_value_in_any_exported_text_scalar_rejects_the_whole_report(
    passthrough: Any, field: str,
) -> None:
    for text in SECRET_SHAPED:
        tampered = passthrough.model_copy(update={field: text})
        produced: list[ReplayReportExportV1] = []

        def attempt(tampered: Any = tampered, produced: list[Any] = produced) -> None:
            produced.append(export_replay_report(tampered))

        error = _expect_error(attempt)
        assert produced == [] and error.code in ERROR_CODES


@pytest.mark.parametrize("field", TEXT_SCALARS)
def test_a_non_string_text_scalar_rejects_the_whole_report(passthrough: Any, field: str) -> None:
    for value in (None, 7, b"x", ["a"], object()):
        tampered = passthrough.model_copy(update={field: value})
        _expect_error(lambda tampered=tampered: export_replay_report(tampered))


def test_no_exported_byte_ever_contains_a_rejected_canary(passthrough: Any) -> None:
    # A rejection yields no bytes at all, in JSON or in CSV; a pass-through control proves it.
    for field in TEXT_SCALARS:
        tampered = passthrough.model_copy(update={field: f"bad {CANARY}"})
        with pytest.raises(ReplayReportError) as raised:
            export_replay_report(tampered)
        assert CANARY not in f"{raised.value!r} {raised.value} {raised.value.__cause__!r}"
    clean = export_replay_report(passthrough)
    assert CANARY.encode() not in clean.json_bytes and CANARY.encode() not in clean.csv_bytes


REVIEW_CANARY = "api_key_secret_review_canary"


@pytest.mark.parametrize("field", ["strategy_id", "dataset_version"])
def test_the_review_canary_yields_no_report_bytes_for_either_field(
    passthrough: Any, field: str,
) -> None:
    tampered = passthrough.model_copy(update={field: REVIEW_CANARY})
    produced: list[ReplayReportExportV1] = []
    with pytest.raises(ReplayReportError) as raised:
        produced.append(export_replay_report(tampered))
    assert produced == []  # neither the JSON nor the CSV path returns bytes
    assert raised.value.code in ERROR_CODES and str(raised.value) == raised.value.code
    shown = f"{raised.value!r} {raised.value} {raised.value.__cause__!r}"
    assert REVIEW_CANARY not in shown and field not in shown
    clean = export_replay_report(passthrough)
    assert REVIEW_CANARY.encode() not in clean.json_bytes + clean.csv_bytes


DENY_WORDS = (
    "apikey", "api", "key", "secret", "token", "passwd", "password", "bearer", "auth",
    "akia", "ghp", "xox", "sk",
)


@pytest.mark.parametrize("field", TEXT_SCALARS)
def test_a_deny_word_segment_in_any_text_scalar_rejects_the_whole_report(
    passthrough: Any, field: str,
) -> None:
    for word in DENY_WORDS:
        for text in (f"{word}_{CANARY}", f"{CANARY}_{word}", f"a_{word}_b", word, word.upper()):
            tampered = passthrough.model_copy(update={field: text})
            with pytest.raises(ReplayReportError) as raised:
                export_replay_report(tampered)
            assert raised.value.code in ERROR_CODES and str(raised.value) == raised.value.code
            assert CANARY not in f"{raised.value!r} {raised.value.__cause__!r}"


def test_a_word_only_containing_a_deny_word_is_not_a_segment_match(passthrough: Any) -> None:
    # The rule is segment-level, so ordinary identifiers must not be refused as false positives.
    for text in ("monkey_business", "skate_board", "authority_x"):
        clean = passthrough.model_copy(update={"strategy_id": text})
        assert json.loads(export_replay_report(clean).json_bytes)["replay"]["strategy_id"] == text


# ------------------------------------------- Decimal-native confidence, quality and sentiment

DECIMAL_METRICS = {
    "decision.confidence": ("decision", "confidence"),
    "session.quality": ("session", "quality"),
    "truth.sentiment_modifier": ("truth", "sentiment_modifier"),
}
BEYOND_FLOAT = {
    "decision.confidence": Decimal("0.1234567890123456789012345678"),
    "session.quality": Decimal("0.9999999999999999999999"),
    "truth.sentiment_modifier": Decimal("-0.0123456789012345678901"),
}


def _with_metric(result: Any, name: str, value: object) -> Any:
    group, field = DECIMAL_METRICS[name]
    changed = getattr(result, group).model_copy(update={field: value})
    return result.model_copy(update={group: changed})


def _metric(report: ReplayReportExportV1, name: str) -> dict[str, Any]:
    return next(item for item in _report(report)["metrics"] if item["name"] == name)


@pytest.fixture
def genuine_result(baseline: ReplayArtifacts) -> Any:
    return exporter.load_verified_replay_result(verify_replay_artifacts(baseline))


def _export_with(
    monkeypatch: pytest.MonkeyPatch, baseline: ReplayArtifacts, result: object
) -> ReplayReportExportV1:
    verified_now = verify_replay_artifacts(baseline)
    monkeypatch.setattr(exporter, "load_verified_replay_result", lambda _v: result)
    return export_replay_report(verified_now)


def test_every_metric_is_decimal_native_and_no_float_provenance_is_ever_emitted(
    verified: Any,
) -> None:
    report = export_replay_report(verified, (_feature(),))
    assert all(item["provenance"] == "DECIMAL_NATIVE" for item in _report(report)["metrics"])
    assert b"FLOAT_PERSISTED" not in report.json_bytes + report.csv_bytes


@pytest.mark.parametrize("name", list(DECIMAL_METRICS))
def test_a_decimal_beyond_float_precision_is_reported_exactly(
    baseline: ReplayArtifacts, genuine_result: Any, monkeypatch: pytest.MonkeyPatch, name: str,
) -> None:
    value = BEYOND_FLOAT[name]
    assert str(float(value)) != str(value)  # a float round trip would change the digits
    report = _export_with(monkeypatch, baseline, _with_metric(genuine_result, name, value))
    item = _metric(report, name)
    assert item["present"] is True and item["provenance"] == "DECIMAL_NATIVE"
    assert item["value"] == canonical_str(value)
    rows = list(csv.reader(io.StringIO(report.csv_bytes.decode("utf-8"))))
    assert any(row[5] == item["value"] for row in rows[1:] if name in " ".join(row[1:4]))


@pytest.mark.parametrize("name", list(DECIMAL_METRICS))
@pytest.mark.parametrize("spelling", ["0.500", "5E-1", "0.5000000000", "+0.5", "00.5"])
def test_equal_decimals_in_any_spelling_give_one_canonical_string(
    baseline: ReplayArtifacts, genuine_result: Any, monkeypatch: pytest.MonkeyPatch,
    name: str, spelling: str,
) -> None:
    value = Decimal(spelling) if name != "truth.sentiment_modifier" else Decimal(spelling) / 4
    report = _export_with(monkeypatch, baseline, _with_metric(genuine_result, name, value))
    assert _metric(report, name)["value"] == canonical_str(value)
    assert _metric(report, name)["value"] == canonical_str(value.normalize())


@pytest.mark.parametrize("name", list(DECIMAL_METRICS))
@pytest.mark.parametrize("bad", [
    0.5, 1.0, 0.0, float("nan"), float("inf"), True, False, "0.5", Decimal("NaN"),
    Decimal("sNaN"), Decimal("Infinity"), Decimal("-Infinity"), 1, b"0.5", [Decimal("0.5")],
])
def test_floats_and_other_non_decimal_values_are_rejected_for_these_metrics(
    baseline: ReplayArtifacts, genuine_result: Any, monkeypatch: pytest.MonkeyPatch,
    name: str, bad: object,
) -> None:
    broken = _with_metric(genuine_result, name, bad)
    verified_now = verify_replay_artifacts(baseline)
    monkeypatch.setattr(exporter, "load_verified_replay_result", lambda _v: broken)
    _expect_error(lambda: export_replay_report(verified_now), "INVALID_REPLAY_RESULT")


def test_the_decimal_metrics_still_equal_the_persisted_result_text(
    baseline: ReplayArtifacts, verified: Any,
) -> None:
    source = json.loads(baseline.result_path.read_bytes())
    metrics = {item["name"]: item for item in _report(export_replay_report(verified))["metrics"]}
    for name, (group, field) in DECIMAL_METRICS.items():
        assert metrics[name]["value"] == source[group][field], name
        assert metrics[name]["provenance"] == "DECIMAL_NATIVE"
