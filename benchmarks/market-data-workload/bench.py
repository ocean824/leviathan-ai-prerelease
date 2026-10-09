"""Measure the local streamed parse/dedupe/FIFO/in-process ACK stage only."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import math
import os
import platform
import queue
import sys
import threading
import time
from decimal import Decimal
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from envelope import (
    MAX_ENVELOPE_BYTES,
    MAX_EVENT_COUNT,
    json_bytes,
    json_numbers_fit_precision,
    ms_to_ns,
    payload_base,
)
from validate import EVENT_TYPES, WorkloadValidationError, load_profile


class BenchmarkError(ValueError):
    def __init__(self, code: str, detail: str) -> None:
        self.code = code
        super().__init__(f"{code}: {detail}")


def _reject_nonfinite_json(_: str) -> None:
    raise ValueError("nonfinite JSON token")


def _reject_nonfinite_manifest(_: str) -> None:
    raise BenchmarkError("MANIFEST_NUMBER", "nonfinite JSON number is forbidden")


_FIELDS = {
    "event_id",
    "schema_version",
    "source",
    "venue",
    "instrument_id",
    "symbol",
    "channel",
    "event_type",
    "event_time_utc_ns",
    "exchange_time_utc_ns",
    "ingest_time_utc_ns",
    "processing_time_utc_ns",
    "sequence",
    "reconstructed",
    "flags",
    "payload",
}


def _check_record(record: Any, profile: dict[str, Any]) -> None:
    if not isinstance(record, dict) or set(record) != _FIELDS:
        raise BenchmarkError("INVALID_RECORD", "record fields differ from normalized envelope")
    for key in ("event_id", "source", "venue", "instrument_id", "symbol", "channel", "event_type"):
        if not isinstance(record[key], str) or not record[key]:
            raise BenchmarkError("INVALID_RECORD", f"{key} is not a nonempty string")
    if record["schema_version"] != "leviathan.market_event/1":
        raise BenchmarkError("INVALID_RECORD", "event schema version mismatch")
    if record["event_type"] not in EVENT_TYPES:
        raise BenchmarkError("INVALID_RECORD", "unknown event type")
    if (
        record["venue"] not in profile["traffic"]["venues"]
        or record["channel"] not in profile["traffic"]["channels"]
    ):
        raise BenchmarkError("INVALID_RECORD", "undeclared venue or channel")
    for key in (
        "event_time_utc_ns",
        "exchange_time_utc_ns",
        "ingest_time_utc_ns",
        "processing_time_utc_ns",
        "sequence",
    ):
        if type(record[key]) is not int or record[key] < 0:
            raise BenchmarkError("INVALID_RECORD", f"{key} is not a nonnegative integer")
    if record["sequence"] < 1 or type(record["reconstructed"]) is not bool:
        raise BenchmarkError("INVALID_RECORD", "invalid sequence or reconstructed flag")
    if record["processing_time_utc_ns"] < record["ingest_time_utc_ns"]:
        raise BenchmarkError("INVALID_RECORD", "processing precedes ingest")
    skew_ns = record["exchange_time_utc_ns"] - record["event_time_utc_ns"]
    if not 0 <= skew_ns <= ms_to_ns(profile["disorder"]["clock_skew_ms"]["max"]):
        raise BenchmarkError("INVALID_RECORD", "exchange clock skew exceeds declaration")
    if record["ingest_time_utc_ns"] < record["event_time_utc_ns"]:
        raise BenchmarkError("INVALID_RECORD", "ingest precedes event")
    if not isinstance(record["flags"], list) or any(
        not isinstance(flag, str) for flag in record["flags"]
    ):
        raise BenchmarkError("INVALID_RECORD", "flags must be strings")
    payload = record["payload"]
    if not isinstance(payload, dict):
        raise BenchmarkError("INVALID_PAYLOAD_TYPE", "typed payload must be an object")
    expected = payload_base(record["event_type"])
    if set(payload) not in (set(expected), set(expected) | {"padding"}):
        raise BenchmarkError("INVALID_PAYLOAD_TYPE", "payload fields differ from event schema")
    if any(type(payload[key]) is not type(sample) for key, sample in expected.items()):
        raise BenchmarkError("INVALID_PAYLOAD_TYPE", "payload field has wrong JSON type")
    if "padding" in payload and type(payload["padding"]) is not str:
        raise BenchmarkError("INVALID_PAYLOAD_TYPE", "padding must be a string")
    if len(json_bytes(payload)) > profile["traffic"]["payload_bytes"][record["event_type"]]["max"]:
        raise BenchmarkError("INVALID_PAYLOAD_TYPE", "payload exceeds the declared type maximum")


def _peak_rss_bytes() -> int | None:
    if os.name == "nt":

        class Counters(ctypes.Structure):
            _fields_ = [
                ("cb", ctypes.c_uint32),
                ("PageFaultCount", ctypes.c_uint32),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        counters = Counters()
        counters.cb = ctypes.sizeof(Counters)
        get_process = ctypes.windll.kernel32.GetCurrentProcess
        get_process.restype = ctypes.c_void_p
        get_memory = ctypes.windll.psapi.GetProcessMemoryInfo
        get_memory.argtypes = [ctypes.c_void_p, ctypes.POINTER(Counters), ctypes.c_uint32]
        if get_memory(get_process(), ctypes.byref(counters), counters.cb):
            return int(counters.PeakWorkingSetSize)
        return None
    try:
        import resource

        usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return int(usage * (1 if sys.platform == "darwin" else 1024))
    except ImportError:
        return None


def _percentile(sorted_values: list[int], fraction: float) -> int:
    return sorted_values[max(0, math.ceil(fraction * len(sorted_values)) - 1)]


def _manifest(path: Path, profile_path: Path) -> dict[str, Any]:
    try:
        data = json.loads(
            path.read_text(encoding="utf-8"),
            parse_float=Decimal,
            parse_int=int,
            parse_constant=_reject_nonfinite_manifest,
        )
    except BenchmarkError:
        raise
    except (OSError, ValueError) as exc:
        raise BenchmarkError("MANIFEST_READ", "manifest could not be read as JSON") from exc
    if not json_numbers_fit_precision(data):
        raise BenchmarkError("PRECISION_EXCEEDED", "manifest JSON number exceeds 34 digits")
    if not isinstance(data, dict) or data.get("schema_version") != "leviathan.workload.manifest/1":
        raise BenchmarkError("MANIFEST_SCHEMA", "invalid manifest version")
    if data.get("profile_sha256") != hashlib.sha256(profile_path.read_bytes()).hexdigest():
        raise BenchmarkError("PROFILE_CHECKSUM", "profile bytes differ from generator profile")
    for key in (
        "generator_sha256",
        "generated_line_count",
        "generated_unique_count",
        "duplicates_generated",
        "generated_bytes",
        "declared_gap_ranges",
        "late_event_keys",
        "late_rejected_keys",
        "eligible_unique_count",
    ):
        if key not in data:
            raise BenchmarkError("MANIFEST_SCHEMA", f"missing {key}")
    for key in (
        "generated_line_count",
        "generated_unique_count",
        "duplicates_generated",
        "generated_bytes",
        "eligible_unique_count",
    ):
        if type(data[key]) is not int or data[key] < 0:
            raise BenchmarkError("MANIFEST_SCHEMA", f"{key} must be a nonnegative integer")
    if not isinstance(data["declared_gap_ranges"], list) or not isinstance(
        data["late_rejected_keys"], list
    ):
        raise BenchmarkError("MANIFEST_SCHEMA", "invalid gap or late declaration")
    return data


def _summary(report: dict[str, Any]) -> str:
    latency = report["enqueue_to_ack_latency_ns"]
    lines = [
        "# C-103 local synthetic ingestion stage",
        "",
        "**Single-run synthetic observation. Use at least three runs and report "
        "median/min/max; PRD target verified: false.**",
        "",
        f"Pipeline: `{report['pipeline']}`; "
        f"latency boundary: `{report['latency_boundary']}`; "
        f"durability: `{report['durability']}`.",
        f"Host: {report['host']['os']} / {report['host']['cpu_model']} / "
        f"{report['host']['ram_bytes']} bytes RAM.",
        f"Input: {report['generated_line_count']} NDJSON lines, "
        f"{report['input_bytes']} bytes, SHA-256 `{report['generator_sha256']}`.",
        f"Eligible unique: {report['eligible_unique']}; ACKed: {report['unique_acked']}; "
        f"loss: {report['loss_count']} ({report['loss_rate']:.6f}).",
        f"Late rejected: {report['late_rejected']}; duplicates: {report['duplicates_seen']}; "
        f"declared gap events: {report['declared_gap_count']}; invalid: {report['invalid_seen']}.",
        f"Whole-pipeline: {report['pipeline_events_per_sec']:.1f} ACKed events/s; "
        f"steady state after warmup: {report['steady_state_events_per_sec']:.1f} ACKed "
        f"events/s; input bytes/s: {report['bytes_per_sec']:.1f}.",
        f"Enqueue-to-ACK ns: p50 {latency['p50']}, p95 {latency['p95']}, "
        f"p99 {latency['p99']}, max {latency['max']}; "
        f"queue peak {report['queue_depth_peak']}.",
        f"Peak RSS: {report['peak_rss_bytes']} bytes; benchmark cap: "
        f"{report['memory_cap_bytes']} bytes and {report['event_cap']} unique events.",
        "",
        "The file is read unpaced. The profile's rate, duration and burst fields "
        "describe the stated synthetic workload; this run measures maximum local "
        "file-fed stage throughput and does not enforce arrival pacing.",
        "",
        "## Unverified PRD gates",
        "",
    ]
    for gate in report["unverified_prd_gates"]:
        lines.append(
            f"- **{gate['name']}** ({gate['target']}): {gate['boundary']}; "
            f"missing: {gate['missing_evidence']}."
        )
    return "\n".join(lines) + "\n"


def run_benchmark(
    profile_path: str | Path,
    input_path: str | Path,
    manifest_path: str | Path,
    report_path: str | Path,
    *,
    drop_ack_keys: set[str] | None = None,
) -> dict[str, Any]:
    """Stream and verify the source, then report the exact local ACK boundary."""
    profile_path, input_path, manifest_path, report_path = map(
        Path, (profile_path, input_path, manifest_path, report_path)
    )
    profile = load_profile(profile_path)
    if profile["profile_kind"] != "synthetic":
        raise BenchmarkError("PROFILE_KIND", "local harness requires synthetic profile")
    manifest = _manifest(manifest_path, profile_path)
    declared_count = profile["traffic"]["event_count"]
    threshold_ns = ms_to_ns(profile["disorder"]["late_threshold_ms"])
    if manifest["generated_unique_count"] != declared_count:
        raise BenchmarkError("PROFILE_COUNT", "manifest unique count differs from profile")
    declared: set[tuple[str, str, str, int, int]] = set()
    for gap in manifest["declared_gap_ranges"]:
        try:
            item = (gap["venue"], gap["instrument_id"], gap["channel"], gap["start"], gap["end"])
            if type(item[3]) is not int or type(item[4]) is not int or item[3] > item[4]:
                raise ValueError("invalid range")
        except (KeyError, TypeError, ValueError) as exc:
            raise BenchmarkError("MANIFEST_SCHEMA", "invalid declared gap") from exc
        if item in declared:
            raise BenchmarkError("MANIFEST_SCHEMA", "duplicate declared gap")
        declared.add(item)
    observed: set[tuple[str, str, str, int, int]] = set()
    work_queue: queue.Queue[tuple[str, int] | None] = queue.Queue(
        maxsize=profile["delivery"]["queue_capacity"]
    )
    ack_latencies: list[int] = []
    ack_times: list[int] = []
    unique_acked = 0
    dropped = drop_ack_keys or set()

    def consume() -> None:
        nonlocal unique_acked
        while True:
            item = work_queue.get()
            if item is None:
                work_queue.task_done()
                return
            key, enqueue_ns = item
            # The consumer has read the item; this timestamp is its in-process ACK.
            ack_ns = time.perf_counter_ns()
            if key not in dropped:
                unique_acked += 1
                ack_latencies.append(ack_ns - enqueue_ns)
                ack_times.append(ack_ns)
            work_queue.task_done()

    reader_start_ns = time.perf_counter_ns()
    cpu_start_ns = time.process_time_ns()
    consumer = threading.Thread(target=consume, daemon=True)
    consumer.start()
    digest = hashlib.sha256()
    line_count = 0
    byte_count = 0
    duplicate_count = 0
    late_keys: list[str] = []
    rejected_keys: list[str] = []
    seen: set[str] = set()
    sequence_by_stream: dict[tuple[str, str, str], int] = {}
    queue_peak = 0
    invalid_seen = 0
    try:
        with input_path.open("rb") as stream:
            for raw in stream:
                line_count += 1
                byte_count += len(raw)
                digest.update(raw)
                if not raw.endswith(b"\n") or len(raw) > MAX_ENVELOPE_BYTES:
                    invalid_seen += 1
                    raise BenchmarkError("TRUNCATED_OR_OVERSIZE", f"line {line_count}")
                try:
                    record = json.loads(raw, parse_constant=_reject_nonfinite_json)
                    _check_record(record, profile)
                except BenchmarkError:
                    invalid_seen += 1
                    raise
                except (UnicodeDecodeError, ValueError) as exc:
                    invalid_seen += 1
                    raise BenchmarkError(
                        "INVALID_RECORD", f"line {line_count} is not valid JSON"
                    ) from exc
                key = record["event_id"]
                if key in seen:
                    duplicate_count += 1
                    continue
                seen.add(key)
                if len(seen) > declared_count:
                    raise BenchmarkError(
                        "PROFILE_COUNT", "input has more unique records than profile"
                    )
                stream_key = (record["venue"], record["instrument_id"], record["channel"])
                previous = sequence_by_stream.get(stream_key)
                if previous is not None:
                    expected = previous + 1
                    if record["sequence"] != expected:
                        gap = (*stream_key, expected, record["sequence"] - 1)
                        if gap not in declared or record["sequence"] <= expected:
                            raise BenchmarkError(
                                "UNEXPECTED_GAP",
                                "sequence differs from declared stream progression",
                            )
                        observed.add(gap)
                elif record["sequence"] != 1:
                    raise BenchmarkError("UNEXPECTED_GAP", "first stream sequence is not 1")
                sequence_by_stream[stream_key] = record["sequence"]
                lateness_ns = record["ingest_time_utc_ns"] - record["event_time_utc_ns"]
                if "late" in record["flags"]:
                    late_keys.append(key)
                    if (
                        profile["disorder"]["late_policy"] == "reject"
                        and lateness_ns > threshold_ns
                    ):
                        rejected_keys.append(key)
                        continue
                elif lateness_ns > threshold_ns:
                    raise BenchmarkError("INVALID_RECORD", "undeclared late event")
                # Entry is immediately before the bounded FIFO put, including any block time.
                enqueue_ns = time.perf_counter_ns()
                work_queue.put((key, enqueue_ns))
                queue_peak = max(queue_peak, work_queue.qsize())
    except OSError as exc:
        raise BenchmarkError("INPUT_READ", "input NDJSON could not be read") from exc
    finally:
        work_queue.put(None)
        work_queue.join()
        consumer.join()
    final_ack_ns = ack_times[-1] if ack_times else time.perf_counter_ns()
    if (
        digest.hexdigest() != manifest["generator_sha256"]
        or byte_count != manifest["generated_bytes"]
        or line_count != manifest["generated_line_count"]
    ):
        raise BenchmarkError(
            "CHECKSUM_MISMATCH", "NDJSON bytes, lines or size differ from manifest"
        )
    if observed != declared:
        raise BenchmarkError("DECLARED_GAP_MISMATCH", "manifest gaps not observed exactly")
    if (
        len(seen) != declared_count
        or len(seen) != manifest["generated_unique_count"]
        or duplicate_count != manifest["duplicates_generated"]
    ):
        raise BenchmarkError("COUNT_MISMATCH", "unique or duplicate count differs from manifest")
    if late_keys != manifest["late_event_keys"] or rejected_keys != manifest["late_rejected_keys"]:
        raise BenchmarkError("LATE_MISMATCH", "late identities differ from manifest")
    eligible_unique = len(seen) - len(rejected_keys)
    if eligible_unique <= 0 or eligible_unique != manifest["eligible_unique_count"]:
        raise BenchmarkError("ELIGIBLE_MISMATCH", "eligible unique count invalid or differs")
    loss_count = eligible_unique - unique_acked
    if loss_count < 0:
        raise BenchmarkError("ACK_MISMATCH", "more ACKs than eligible records")
    elapsed_seconds = max((final_ack_ns - reader_start_ns) / 1e9, 1e-9)
    warmup_end_ns = reader_start_ns + int(Decimal(str(profile["warmup_seconds"])) * 1_000_000_000)
    steady_acks = sum(moment >= warmup_end_ns for moment in ack_times)
    steady_seconds = max((final_ack_ns - warmup_end_ns) / 1e9, 0)
    ack_latencies.sort()
    latency = {
        label: _percentile(ack_latencies, fraction) if ack_latencies else None
        for label, fraction in (("p50", 0.5), ("p95", 0.95), ("p99", 0.99), ("max", 1.0))
    }
    report: dict[str, Any] = {
        "schema_version": "leviathan.workload.report/1",
        "pipeline": "local_parse_dedupe_to_in_process_ack",
        "latency_boundary": "enqueue_to_ack",
        "durability": "none",
        "dataset_class": "synthetic",
        "result_scope": "single_run_observation",
        "prd_target_verified": False,
        "profile_name": profile["name"],
        "profile_sha256": manifest["profile_sha256"],
        "generator_sha256": digest.hexdigest(),
        "generated_line_count": line_count,
        "input_bytes": byte_count,
        "declared_gap_ranges": manifest["declared_gap_ranges"],
        "late_rejected_keys": rejected_keys,
        "eligible_unique": eligible_unique,
        "unique_acked": unique_acked,
        "loss_count": loss_count,
        "loss_rate": loss_count / eligible_unique,
        "late_rejected": len(rejected_keys),
        "duplicates_seen": duplicate_count,
        "declared_gap_count": sum(gap[4] - gap[3] + 1 for gap in declared),
        "invalid_seen": invalid_seen,
        "enqueue_to_ack_latency_ns": latency,
        "pipeline_elapsed_seconds": elapsed_seconds,
        "pipeline_events_per_sec": unique_acked / elapsed_seconds,
        "steady_state_seconds": steady_seconds,
        "steady_state_events_per_sec": steady_acks / steady_seconds if steady_seconds else 0.0,
        "bytes_per_sec": byte_count / elapsed_seconds,
        "queue_depth_peak": queue_peak,
        "process_cpu_seconds": (time.process_time_ns() - cpu_start_ns) / 1e9,
        "peak_rss_bytes": _peak_rss_bytes(),
        "memory_cap_bytes": 1_610_612_736,
        "event_cap": MAX_EVENT_COUNT,
        "host": {
            "os": platform.platform(),
            "cpu_model": profile["hardware"]["cpu_model"],
            "logical_cpus": os.cpu_count(),
            "ram_bytes": profile["hardware"]["ram_bytes"],
            "python": platform.python_version(),
            "profile_hardware": profile["hardware"],
        },
        "input_delivery": "unpaced_local_file",
        "unverified_prd_gates": [
            {
                "name": "storage",
                "target": ">=200000 events/s/node and p99 write ACK <15 ms",
                "boundary": "durable store write ACK",
                "missing_evidence": (
                    "representative mix, chosen store and hardware, durability "
                    "and independent store measurements"
                ),
                "verified": False,
            },
            {
                "name": "ingestion",
                "target": ">=250000 events/s/shard, WS p99 <=15 ms, REST p99 <=100 ms",
                "boundary": "ingest to network publish",
                "missing_evidence": (
                    "provider adapter, shard, network consumers, backpressure "
                    "and independent publish measurements"
                ),
                "verified": False,
            },
            {
                "name": "replay",
                "target": ">=2000000 ticks/s/worker",
                "boundary": "strategy replay worker",
                "missing_evidence": (
                    "tick workload, replay engine and independent worker measurements"
                ),
                "verified": False,
            },
        ],
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    report_path.with_suffix(".md").write_text(_summary(report), encoding="utf-8")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True, type=Path)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        report = run_benchmark(args.profile, args.input, args.manifest, args.report)
    except (BenchmarkError, WorkloadValidationError, OSError) as exc:
        print(exc, file=sys.stderr)
        return 2
    print(
        f"ACKED {report['unique_acked']} loss={report['loss_count']} "
        f"pipeline_events_per_sec={report['pipeline_events_per_sec']:.1f}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
