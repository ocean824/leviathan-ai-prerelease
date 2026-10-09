"""Deterministic offline smoke over synthetic JSONL; no provider transport."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from leviathan_market_data.ingress import IngestReceipt, IngestStatus, NormalizedIngress, SinkAck
from leviathan_market_data.normalization import Normalizer, VendorRecord
from leviathan_market_data.schema import NormalizedMarketEventV1
from leviathan_market_data.symbology import InstrumentMapping, MappingRegistry


class _MemorySink:
    def __init__(self) -> None:
        self.events: list[NormalizedMarketEventV1] = []

    def accept(self, event: NormalizedMarketEventV1) -> SinkAck:
        self.events.append(event)
        return SinkAck(accepted=True)


def run_fixture(path: Path) -> dict[str, object]:
    lines = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
             if line.strip()]
    registry = MappingRegistry()
    for item in lines:
        if "mapping" in item:
            registry.register(InstrumentMapping(**item["mapping"]))
    sink = _MemorySink()
    ingress = NormalizedIngress(Normalizer(registry), sink)
    receipts: list[IngestReceipt] = []
    for item in lines:
        if "record" not in item:
            continue
        result = ingress.ingest(VendorRecord(**item["record"]))
        receipts.append(result)
        receipts.extend(result.drained_receipts)
    receipts.extend(ingress.flush())
    terminals = [receipt for receipt in receipts if receipt.status != IngestStatus.BUFFERED]
    checksum_input = json.dumps(
        [
            {
                "idempotency_key": event.idempotency_key,
                "event_type": event.event_type,
                "event_time_ns": event.event_time_ns,
                "source_time_ns": event.source_time_ns,
                "exchange_time_ns": event.exchange_time_ns,
                "mapping_version": event.mapping_version,
                "payload": event.payload.model_dump(mode="json"),
            }
            for event in sink.events
        ],
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return {
        "event_count": sum("record" in item for item in lines),
        "accepted": sum(r.status == IngestStatus.ACCEPTED for r in terminals),
        "duplicate": sum(r.status == IngestStatus.DUPLICATE for r in terminals),
        "quarantined": sum(r.status == IngestStatus.QUARANTINED for r in terminals),
        "backpressure": sum(r.status == IngestStatus.BACKPRESSURE for r in terminals),
        "semantic_checksum": hashlib.sha256(checksum_input).hexdigest(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(run_fixture(args.fixture), sort_keys=True))


if __name__ == "__main__":
    main()
