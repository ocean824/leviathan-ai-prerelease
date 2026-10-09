"""Generate deterministic, streamed C-103 normalized market data NDJSON."""

from __future__ import annotations

import argparse
import hashlib
import os
import random
import sys
from decimal import Decimal
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from envelope import BASE_NS, envelope_fits, json_bytes, ms_to_ns, sized_payload
from validate import EVENT_TYPES, WorkloadValidationError, load_profile


def _sample_bucket(
    rng: random.Random, shape: dict[str, int | float | Decimal]
) -> int | float | Decimal:
    draw = rng.random()
    if draw < 0.5:
        return shape["p50"]
    if draw < 0.99:
        return shape["p99"]
    return shape["max"]


def _chosen(index: int, ratio: int | float | Decimal) -> bool:
    exact_ratio = Decimal(str(ratio))
    return int((index + 1) * exact_ratio + Decimal("1e-9")) > int(
        index * exact_ratio + Decimal("1e-9")
    )


def generate_dataset(
    profile_path: str | Path, output_path: str | Path, manifest_path: str | Path
) -> dict[str, Any]:
    """Write NDJSON and its byte-level manifest; return the manifest."""
    profile_path = Path(profile_path)
    output_path = Path(output_path)
    manifest_path = Path(manifest_path)
    if output_path.resolve() == manifest_path.resolve():
        raise WorkloadValidationError("OUTPUT_PATH", "data and manifest paths must differ")
    profile = load_profile(profile_path)
    if profile["profile_kind"] != "synthetic":
        raise WorkloadValidationError(
            "NONACCEPTANCE_PROFILE", "generator requires synthetic profile"
        )
    traffic = profile["traffic"]
    disorder = profile["disorder"]
    # Tiny fixtures must revisit a stream to exercise sequence-gap behavior.
    # A short fixture samples a subset of the declared instrument universe.
    active_instruments = min(
        traffic["instruments"],
        max(1, traffic["event_count"] // (2 * len(traffic["venues"]) * len(traffic["channels"]))),
    )
    rng = random.Random(profile["seed"])
    cumulative: list[tuple[str, Decimal]] = []
    total = Decimal(0)
    for event_type in EVENT_TYPES:
        total += Decimal(str(traffic["mix"][event_type]))
        cumulative.append((event_type, total))
    sequences: dict[tuple[str, str, str], int] = {}
    gaps: list[dict[str, Any]] = []
    late_keys: list[str] = []
    rejected_keys: list[str] = []
    digest = hashlib.sha256()
    byte_count = 0
    line_count = 0
    duplicate_count = 0
    output_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = output_path.with_name(output_path.name + ".tmp")
    try:
        with temp_path.open("wb") as stream:
            for index in range(traffic["event_count"]):
                instrument_id = f"SIM-{index % active_instruments:04d}"
                venue = traffic["venues"][(index // active_instruments) % len(traffic["venues"])]
                channel = traffic["channels"][
                    (index // (active_instruments * len(traffic["venues"])))
                    % len(traffic["channels"])
                ]
                stream_key = (venue, instrument_id, channel)
                previous = sequences.get(stream_key, 0)
                sequence = previous + 1
                if previous and _chosen(index, disorder["gap_ratio"]):
                    start = sequence
                    sequence += disorder["gap_size"]
                    gaps.append(
                        {
                            "venue": venue,
                            "instrument_id": instrument_id,
                            "channel": channel,
                            "start": start,
                            "end": sequence - 1,
                        }
                    )
                sequences[stream_key] = sequence
                draw = rng.random()
                event_type = next(
                    (kind for kind, limit in cumulative if Decimal.from_float(draw) < limit),
                    EVENT_TYPES[-1],
                )
                payload = sized_payload(
                    event_type, int(_sample_bucket(rng, traffic["payload_bytes"][event_type]))
                )
                event_id = f"{profile['seed']}:{index}"
                ingest_ns = BASE_NS + index * 1_000
                late = _chosen(index, disorder["late_ratio"])
                lateness_ns = ms_to_ns(_sample_bucket(rng, disorder["lateness_ms"])) if late else 0
                if late:
                    late_keys.append(event_id)
                    if disorder["late_policy"] == "reject" and lateness_ns > ms_to_ns(
                        disorder["late_threshold_ms"]
                    ):
                        rejected_keys.append(event_id)
                event_ns = ingest_ns - lateness_ns
                skew_ns = ms_to_ns(_sample_bucket(rng, disorder["clock_skew_ms"]))
                record = {
                    "event_id": event_id,
                    "schema_version": "leviathan.market_event/1",
                    "source": "C103_SYNTH",
                    "venue": venue,
                    "instrument_id": instrument_id,
                    "symbol": instrument_id,
                    "channel": channel,
                    "event_type": event_type,
                    "event_time_utc_ns": event_ns,
                    "exchange_time_utc_ns": event_ns + skew_ns,
                    "ingest_time_utc_ns": ingest_ns,
                    "processing_time_utc_ns": ingest_ns + 1_000,
                    "sequence": sequence,
                    "reconstructed": False,
                    "flags": ["synthetic"] + (["late"] if late else []),
                    "payload": payload,
                }
                encoded = json_bytes(record) + b"\n"
                if not envelope_fits(len(encoded)):
                    raise WorkloadValidationError("EVENT_SIZE", f"event {event_id} exceeds 64 KiB")
                for _ in range(2 if _chosen(index, disorder["duplicate_ratio"]) else 1):
                    stream.write(encoded)
                    digest.update(encoded)
                    byte_count += len(encoded)
                    line_count += 1
                if _chosen(index, disorder["duplicate_ratio"]):
                    duplicate_count += 1
        os.replace(temp_path, output_path)
    finally:
        temp_path.unlink(missing_ok=True)
    manifest: dict[str, Any] = {
        "schema_version": "leviathan.workload.manifest/1",
        "profile_sha256": hashlib.sha256(profile_path.read_bytes()).hexdigest(),
        "generator_sha256": digest.hexdigest(),
        "generated_bytes": byte_count,
        "generated_line_count": line_count,
        "generated_unique_count": traffic["event_count"],
        "duplicates_generated": duplicate_count,
        "declared_gap_ranges": gaps,
        "late_event_keys": late_keys,
        "late_rejected_keys": rejected_keys,
        "eligible_unique_count": traffic["event_count"] - len(rejected_keys),
    }
    manifest_path.write_bytes(json_bytes(manifest) + b"\n")
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        manifest = generate_dataset(args.profile, args.output, args.manifest)
    except (WorkloadValidationError, OSError) as exc:
        print(exc, file=sys.stderr)
        return 2
    print(
        f"GENERATED {manifest['generated_line_count']} lines sha256={manifest['generator_sha256']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
