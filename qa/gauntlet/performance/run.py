"""Run a bounded, local C-103 synthetic baseline and report blocked PRD gates.

This harness is intentionally not a sustained-load or representative SLO test.
It streams at most 100,000 unique synthetic events and runs child processes
sequentially with a per-process timeout.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import time
from contextlib import suppress
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
WORKLOAD_DIR = REPO / "benchmarks" / "market-data-workload"
GENERATOR = WORKLOAD_DIR / "generate.py"
BENCHMARK = WORKLOAD_DIR / "bench.py"
VALIDATOR = WORKLOAD_DIR / "validate.py"
MAX_EVENTS = 100_000
MAX_RUNS = 5
MAX_TIMEOUT_SECONDS = 120
MAX_TOTAL_RUNTIME_SECONDS = 900
REPORT_SCHEMA = "leviathan.performance-report/1"
GATE_NAMES = ("storage", "market_ingestion", "backtest")


class PerformanceError(ValueError):
    """A stable, content-free harness error."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


def _no_constant(token: str) -> None:
    raise PerformanceError("INVALID_JSON", f"non-finite JSON constant {token} is forbidden")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PerformanceError("INVALID_JSON", "duplicate object key")
        result[key] = value
    return result


def _read_json(path: Path) -> Any:
    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            parse_constant=_no_constant,
            object_pairs_hook=_unique_object,
        )
    except PerformanceError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PerformanceError("PROFILE_READ", "profile could not be read as JSON") from exc


def _remaining_timeout(deadline: float | None, requested: int) -> int:
    if deadline is None:
        return requested
    remaining = int(deadline - time.monotonic())
    if remaining < 1:
        raise PerformanceError("RUN_TIMEOUT", "overall benchmark wall-clock limit reached")
    return min(requested, remaining)


def load_profile(path: str | Path, *, deadline: float | None = None) -> tuple[dict[str, Any], Path]:
    """Load a PERF wrapper profile or a C-103 workload profile.

    Direct C-103 profiles are accepted for the contract's `--profile` form.
    The PERF wrapper permits only 3-5 repeats, at most 120 seconds per child and the
    C-103 100,000-unique-event ceiling.
    """
    profile_path = Path(path).resolve()
    raw = _read_json(profile_path)
    if not isinstance(raw, dict):
        raise PerformanceError("PROFILE_TYPE", "profile must be a JSON object")
    if raw.get("schema_version") == "leviathan.performance-profile/1":
        if set(raw) != {
            "schema_version",
            "name",
            "workload_profile",
            "repeat_count",
            "timeout_seconds",
        }:
            raise PerformanceError("PROFILE_FIELDS", "performance profile fields are invalid")
        if not isinstance(raw["name"], str) or not raw["name"] or len(raw["name"]) > 120:
            raise PerformanceError("PROFILE_VALUE", "profile name is invalid")
        if (
            not isinstance(raw["workload_profile"], str)
            or not raw["workload_profile"]
            or len(raw["workload_profile"]) > 1024
        ):
            raise PerformanceError("PROFILE_VALUE", "workload_profile must be a path")
        if type(raw["repeat_count"]) is not int or not 3 <= raw["repeat_count"] <= MAX_RUNS:
            raise PerformanceError("PROFILE_BOUND", "repeat_count must be between 3 and 5")
        if (
            type(raw["timeout_seconds"]) is not int
            or not 1 <= raw["timeout_seconds"] <= MAX_TIMEOUT_SECONDS
        ):
            raise PerformanceError("PROFILE_BOUND", "timeout_seconds must be between 1 and 120")
        workload_path = (profile_path.parent / raw["workload_profile"]).resolve()
        settings = raw
    else:
        workload_path = profile_path
        settings = {
            "schema_version": "leviathan.performance-profile/1",
            "name": "c103-local-synthetic",
            "repeat_count": 3,
            "timeout_seconds": 120,
        }
    if not workload_path.is_file():
        raise PerformanceError("PROFILE_PATH", "workload profile does not exist")
    try:
        completed = subprocess.run(
            [sys.executable, str(VALIDATOR), "--profile", str(workload_path)],
            cwd=REPO,
            capture_output=True,
            text=True,
            timeout=_remaining_timeout(deadline, MAX_TIMEOUT_SECONDS),
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise PerformanceError("PROFILE_TIMEOUT", "C-103 profile validation timed out") from exc
    if completed.returncode != 0:
        raise PerformanceError("PROFILE_INVALID", "C-103 profile validation failed")
    workload = _read_json(workload_path)
    if not isinstance(workload, dict) or workload.get("schema_version") != "leviathan.workload/1":
        raise PerformanceError("PROFILE_SCHEMA", "profile is not a C-103 workload profile")
    traffic = workload.get("traffic")
    event_count = traffic.get("event_count") if isinstance(traffic, dict) else None
    if type(event_count) is not int or not 1 <= event_count <= MAX_EVENTS:
        raise PerformanceError("PROFILE_BOUND", "event_count must be between 1 and 100000")
    if workload.get("profile_kind") != "synthetic":
        raise PerformanceError("PROFILE_KIND", "only the C-103 synthetic baseline is runnable")
    return settings, workload_path


def _run_command(
    command: list[str], timeout: int, *, cwd: Path, deadline: float | None = None
) -> None:
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=_remaining_timeout(deadline, timeout),
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise PerformanceError("RUN_TIMEOUT", "bounded benchmark child timed out") from exc
    if completed.returncode != 0:
        raise PerformanceError("RUN_FAILED", "bounded benchmark child failed")


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _host_facts() -> dict[str, Any]:
    cpu_model = platform.processor() or "unknown"
    ram_bytes: int | None = None
    process_count: int | None = None
    filesystem = "unknown"
    disk_type = "unknown"
    if os.name == "nt":
        try:
            import winreg

            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
            ) as key:
                cpu_model = str(winreg.QueryValueEx(key, "ProcessorNameString")[0]).strip()
        except OSError:
            pass
        try:

            class MemoryStatusEx(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]

            memory = MemoryStatusEx()
            memory.dwLength = ctypes.sizeof(memory)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(memory)):
                ram_bytes = int(memory.ullTotalPhys)
        except (AttributeError, OSError):
            pass
        try:
            process_ids = (ctypes.c_ulong * 8192)()
            bytes_needed = ctypes.c_ulong()
            if ctypes.windll.psapi.EnumProcesses(
                process_ids, ctypes.sizeof(process_ids), ctypes.byref(bytes_needed)
            ) and bytes_needed.value < ctypes.sizeof(process_ids):
                process_count = int(bytes_needed.value // ctypes.sizeof(ctypes.c_ulong))
        except (AttributeError, OSError):
            pass
        try:
            volume_root = str(Path(REPO.anchor))
            fs_name = ctypes.create_unicode_buffer(256)
            ok = ctypes.windll.kernel32.GetVolumeInformationW(
                ctypes.c_wchar_p(volume_root),
                None,
                0,
                None,
                None,
                None,
                fs_name,
                len(fs_name),
            )
            if ok:
                filesystem = fs_name.value
            drive_kind = ctypes.windll.kernel32.GetDriveTypeW(ctypes.c_wchar_p(volume_root))
            disk_type = {
                2: "removable drive; physical media type not measured",
                3: "fixed drive; physical media type not measured",
                4: "network drive",
                5: "optical drive",
                6: "RAM disk",
            }.get(int(drive_kind), "unknown")
        except (AttributeError, OSError):
            pass
    if ram_bytes is None and hasattr(os, "sysconf"):
        with suppress(OSError, ValueError):
            ram_bytes = int(os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES"))
    return {
        "cpu_model": cpu_model,
        "ram_bytes": ram_bytes,
        "logical_cpus": os.cpu_count(),
        "process_count": process_count,
        "disk_type": disk_type,
        "filesystem": filesystem,
    }


def _working_tree_dirty() -> bool | None:
    try:
        result = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=REPO,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return bool(result.stdout) if result.returncode == 0 else None


def _percentile_summary(reports: list[dict[str, Any]], key: str) -> dict[str, float]:
    values = [float(item[key]) for item in reports]
    return {"median": statistics.median(values), "min": min(values), "max": max(values)}


def _gate_blockers() -> dict[str, dict[str, str]]:
    return {
        "storage": {
            "status": "BLOCKED",
            "target": ">=200000 events/s/node and p99 durable write ACK <15 ms",
            "boundary": "durable store write ACK",
            "reason": (
                "No representative mix, selected durable store, durability configuration, "
                "or storage ACK measurement is available in this synthetic C-103 run."
            ),
        },
        "market_ingestion": {
            "status": "BLOCKED",
            "target": (
                ">=250000 events/s/shard; WS receive-to-publish p99 <=15 ms at "
                "200000 events/s; REST p99 <=100 ms"
            ),
            "boundary": "provider receive to network publish",
            "reason": (
                "No provider entitlement, live adapter, shard, network consumer, paced "
                "200000 events/s load, REST request path, or publish ACK measurement is available."
            ),
        },
        "backtest": {
            "status": "BLOCKED",
            "target": ">=2000000 ticks/s/worker including replay and simulator work",
            "boundary": "strategy replay worker",
            "reason": (
                "No representative tick workload or integrated replay-and-simulator "
                "worker measurement is available."
            ),
        },
    }


def run_benchmark(profile_path: str | Path, report_dir: str | Path) -> dict[str, Any]:
    """Run the C-103 generator and three sequential measurements, then write evidence."""
    started = time.monotonic()
    deadline = started + MAX_TOTAL_RUNTIME_SECONDS
    destination = Path(report_dir).resolve()
    if destination.exists() and (not destination.is_dir() or any(destination.iterdir())):
        raise PerformanceError("REPORT_EXISTS", "refusing to overwrite existing evidence")
    destination.mkdir(parents=True, exist_ok=True)
    settings, workload_path = load_profile(profile_path, deadline=deadline)
    workload_profile = _read_json(workload_path)
    workload_sha = _hash_file(workload_path)
    observations: list[dict[str, Any]] = []
    input_hash = ""
    manifest_hash = ""
    manifest: dict[str, Any] = {}
    raw_run_dir = destination / "runs"
    raw_run_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="perf001-") as scratch_name:
        scratch = Path(scratch_name)
        input_path = scratch / "synthetic.ndjson"
        manifest_path = scratch / "manifest.json"
        _run_command(
            [
                sys.executable,
                str(GENERATOR),
                "--profile",
                str(workload_path),
                "--output",
                str(input_path),
                "--manifest",
                str(manifest_path),
            ],
            settings["timeout_seconds"],
            cwd=REPO,
            deadline=deadline,
        )
        input_hash = _hash_file(input_path)
        manifest_hash = _hash_file(manifest_path)
        manifest = _read_json(manifest_path)
        for index in range(settings["repeat_count"]):
            child_report = raw_run_dir / f"c103-run-{index + 1:02}.json"
            _run_command(
                [
                    sys.executable,
                    str(BENCHMARK),
                    "--profile",
                    str(workload_path),
                    "--input",
                    str(input_path),
                    "--manifest",
                    str(manifest_path),
                    "--report",
                    str(child_report),
                ],
                settings["timeout_seconds"],
                cwd=REPO,
                deadline=deadline,
            )
            data = _read_json(child_report)
            observations.append(
                {
                    "run_index": index + 1,
                    "pipeline_events_per_sec": data["pipeline_events_per_sec"],
                    "steady_state_events_per_sec": data["steady_state_events_per_sec"],
                    "enqueue_to_ack_latency_ns": data["enqueue_to_ack_latency_ns"],
                    "eligible_unique": data["eligible_unique"],
                    "unique_acked": data["unique_acked"],
                    "loss_count": data["loss_count"],
                    "peak_rss_bytes": data["peak_rss_bytes"],
                    "process_cpu_seconds": data["process_cpu_seconds"],
                    "source_report_sha256": _hash_file(child_report),
                    "source_report_path": f"runs/{child_report.name}",
                }
            )
    first = observations[0]
    if any(item["loss_count"] != 0 for item in observations):
        raise PerformanceError(
            "MEASURED_LOSS", "synthetic C-103 run observed unacknowledged eligible events"
        )
    if any(
        (item["eligible_unique"], item["unique_acked"])
        != (first["eligible_unique"], first["unique_acked"])
        for item in observations[1:]
    ):
        raise PerformanceError(
            "MEASURED_COUNTS", "synthetic C-103 run counters differ across repeats"
        )
    latency_quantiles = {
        quantile: {
            "median": statistics.median(
                int(item["enqueue_to_ack_latency_ns"][quantile]) for item in observations
            ),
            "min": min(int(item["enqueue_to_ack_latency_ns"][quantile]) for item in observations),
            "max": max(int(item["enqueue_to_ack_latency_ns"][quantile]) for item in observations),
        }
        for quantile in ("p50", "p95", "p99", "max")
    }
    child_host = data["host"]
    measured_host = _host_facts()
    dirty = _working_tree_dirty()
    if (
        measured_host["ram_bytes"] is None
        or measured_host["logical_cpus"] is None
        or measured_host["process_count"] is None
    ):
        raise PerformanceError("HOST_FACTS", "measured RAM, CPU and process facts are required")
    hardware = workload_profile.get("hardware", {})
    report = {
        "schema_version": REPORT_SCHEMA,
        "run_name": settings["name"],
        "claim_scope": (
            "bounded local synthetic C-103 baseline; not representative and not sustained. "
            "Prior reviewer samples show same-code medians vary roughly 44k to 51k events/s "
            "across sessions; between-session deltas under about 20% are not significant."
        ),
        "profile": {
            "schema_version": "leviathan.workload/1",
            "profile_sha256": workload_sha,
            "name": workload_profile["name"],
            "seed": workload_profile["seed"],
            "event_count_cap": MAX_EVENTS,
            "event_count": workload_profile["traffic"]["event_count"],
            "repeat_count": len(observations),
        },
        "workload": {
            "run_duration_seconds": workload_profile["run_duration_seconds"],
            "warmup_seconds": workload_profile["warmup_seconds"],
            "event_rate_per_second": workload_profile["traffic"]["event_rate_per_second"],
            "event_rate_kind": "declared_nominal",
            "paced": False,
            "traffic_mix": workload_profile["traffic"]["mix"],
            "payload_bytes": workload_profile["traffic"]["payload_bytes"],
            "instrument_count": workload_profile["traffic"]["instruments"],
            "venue_count": len(workload_profile["traffic"]["venues"]),
            "channel_count": len(workload_profile["traffic"]["channels"]),
            "producer_count": workload_profile["traffic"]["producers"],
            "consumer_count": workload_profile["traffic"]["consumers"],
            "shard_count": workload_profile["traffic"]["shards"],
            "storage_node_count": None,
            "backtest_worker_count": None,
        },
        "measurement": {
            "pipeline": "local_parse_dedupe_to_in_process_ack",
            "latency_boundary": "enqueue_to_ack",
            "ack_semantics": (
                "consumer dequeued the eligible event from the bounded in-process FIFO"
            ),
            "durability": "none",
            "dataset_class": "synthetic",
            "prd_target_verified": False,
            "generator_sha256": manifest["generator_sha256"],
            "input_sha256": input_hash,
            "manifest_sha256": manifest_hash,
            "eligible_unique": first["eligible_unique"],
            "unique_acked": first["unique_acked"],
            "loss_count": 0,
            "pipeline_events_per_sec": _percentile_summary(observations, "pipeline_events_per_sec"),
            "steady_state_events_per_sec": _percentile_summary(
                observations, "steady_state_events_per_sec"
            ),
            "enqueue_to_ack_latency_ns": latency_quantiles,
        },
        "host": {
            "os": child_host.get("os", platform.platform()),
            "cpu_model": measured_host["cpu_model"],
            "logical_cpus": measured_host["logical_cpus"],
            "ram_bytes": measured_host["ram_bytes"],
            "disk_type": measured_host["disk_type"],
            "filesystem": measured_host["filesystem"],
            "power_policy": hardware.get("power_policy", "not measured"),
            "thermal_throttling": "not measured",
            "host_load": "not controlled or sampled; see run-to-run min/median/max variance",
            "runtime": child_host.get("python", sys.version.split()[0]),
            "commit": _git_commit(),
            "working_tree_dirty": dirty,
            "process_count": measured_host["process_count"],
            "declared_hardware": hardware,
            "host_facts_source": (
                "CPU model from Windows processor registry; RAM from GlobalMemoryStatusEx; "
                "filesystem and drive class from Windows volume APIs; process count from "
                "EnumProcesses; dirty state from git status --porcelain. Physical disk media "
                "type, power policy, thermal state and host load are not measured."
            ),
        },
        "resource_bounds": {
            "max_unique_events": MAX_EVENTS,
            "max_child_timeout_seconds": settings["timeout_seconds"],
            "max_total_runtime_seconds": MAX_TOTAL_RUNTIME_SECONDS,
            "elapsed_runtime_seconds": time.monotonic() - started,
            "children_sequential": True,
            "peak_rss_bytes_max": max(int(item["peak_rss_bytes"]) for item in observations),
            "process_cpu_seconds_per_run": _percentile_summary(observations, "process_cpu_seconds"),
        },
        "observations": observations,
        "verdicts": _gate_blockers(),
        "additional_gates": {
            "storage_reads": {
                "status": "BLOCKED",
                "target": "online cached p99 <5 ms; hot p99 <50 ms; errors <0.01% at 2x target QPS",
                "reason": (
                    "No integrated representative online storage query workload or "
                    "2x-target-QPS run."
                ),
            },
            "snapshot": {
                "status": "BLOCKED",
                "target": "10,000,000 keys in <30 s",
                "reason": (
                    "No 10-million-key snapshot/restart workload or integrated "
                    "snapshot measurement."
                ),
            },
            "observability": {
                "status": "BLOCKED",
                "target": "overhead <=2% CPU and <=50 MB buffers",
                "reason": "No baseline-versus-instrumented CPU and buffer measurement.",
            },
            "update_check": {
                "status": "BLOCKED",
                "target": "p99 <2 s at 10,000 RPS",
                "reason": "No integrated update-check endpoint or 10000-RPS run.",
            },
        },
    }
    out_json = destination / "performance-report.json"
    out_md = destination / "performance-report.md"
    out_json.write_text(
        json.dumps(report, sort_keys=True, indent=2, allow_nan=False) + "\n", encoding="utf-8"
    )
    out_md.write_text(_summary(report), encoding="utf-8")
    return report


def _git_commit() -> str | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=REPO,
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout.strip() if result.returncode == 0 else None


def _summary(report: dict[str, Any]) -> str:
    measurement = report["measurement"]
    lines = [
        "# PERF-001 local synthetic benchmark",
        "",
        f"Scope: {report['claim_scope']}",
        (
            f"Pipeline: `{measurement['pipeline']}`; latency: "
            f"`{measurement['latency_boundary']}`; durability: `{measurement['durability']}`."
        ),
        (
            f"Input SHA-256: `{measurement['input_sha256']}`; generated events: "
            f"{report['profile']['event_count']}; runs: {report['profile']['repeat_count']}."
        ),
        (
            f"Declared nominal input rate: {report['workload']['event_rate_per_second']} events/s; "
            f"paced: {report['workload']['paced']}."
        ),
        (
            "Throughput events/s median/min/max: "
            f"{measurement['pipeline_events_per_sec']['median']:.1f} / "
            f"{measurement['pipeline_events_per_sec']['min']:.1f} / "
            f"{measurement['pipeline_events_per_sec']['max']:.1f}."
        ),
        (
            "ACK latency p99 ns median/min/max: "
            f"{measurement['enqueue_to_ack_latency_ns']['p99']['median']} / "
            f"{measurement['enqueue_to_ack_latency_ns']['p99']['min']} / "
            f"{measurement['enqueue_to_ack_latency_ns']['p99']['max']}."
        ),
        (
            f"Peak RSS maximum: {report['resource_bounds']['peak_rss_bytes_max']} bytes; "
            f"cap: {MAX_EVENTS} unique events; benchmark children ran sequentially."
        ),
        (
            f"Measured host: {report['host']['cpu_model']}; "
            f"RAM {report['host']['ram_bytes']} bytes; OS {report['host']['os']}; "
            f"working tree dirty: {report['host']['working_tree_dirty']}."
        ),
        (
            f"Overall runtime cap: {report['resource_bounds']['max_total_runtime_seconds']} s; "
            "observed benchmark elapsed: "
            f"{report['resource_bounds']['elapsed_runtime_seconds']:.2f} s."
        ),
        (
            "Host load was not controlled or sampled; thermal throttling and power policy "
            "were not measured. See raw per-run reports and variance above."
        ),
        (
            "Prior reviewer samples show same-code medians vary roughly 44k to 51k events/s "
            "across sessions; between-session deltas under about 20% are not significant."
        ),
        "",
        "No result in this synthetic local stage verifies a PRD target.",
        "",
        "## Gate verdicts",
        "",
    ]
    lines.extend(
        f"- **{name}: {gate['status']}** — {gate['reason']}"
        for name, gate in report["verdicts"].items()
    )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path, help="output evidence directory")
    args = parser.parse_args(argv)
    try:
        report = run_benchmark(args.profile, args.report)
    except PerformanceError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(f"WROTE {args.report} runs={report['profile']['repeat_count']} verdicts=BLOCKED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
