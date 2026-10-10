"""Cycle 2: verified template export/import to a second tree and replay-only sidecar call."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from leviathan_market_data.public_sources.api_anything_templates import (
    export_pinned_template,
    import_pinned_template,
)

import c1_harness as C


def test_cross_tree_export_import_then_replay_only_call_succeeds(
    collector: Path, tmp_path: Path
) -> None:
    source = C.make_variant(collector, f"transfer-source-{tmp_path.name}", vendor="real", challenge="real")
    source_data = tmp_path / "source-data"
    source_data.mkdir()
    entry = C.write_pin(source, "cnn.fear_greed")

    bundle = tmp_path / "template.bundle.json"
    source_registry = source / "templates" / "PINNED.json"
    export_pinned_template(
        "cnn.fear_greed",
        data_dir=source_data,
        registry_path=source_registry,
        destination=bundle,
    )

    destination = C.make_variant(collector, f"transfer-destination-{tmp_path.name}", vendor="real", challenge="real")
    destination_registry = destination / "templates" / "PINNED.json"
    destination_registry.write_bytes(source_registry.read_bytes())
    fixture_rel = entry["fixture_path"]
    (destination / "templates" / fixture_rel).parent.mkdir(parents=True, exist_ok=True)
    (destination / "templates" / fixture_rel).write_bytes(
        (source / "templates" / fixture_rel).read_bytes()
    )
    registry_sha = hashlib.sha256(destination_registry.read_bytes()).hexdigest()
    (destination / "dist" / "pin-hash.js").write_text(
        f'export const PIN_REGISTRY_SHA256 = "{registry_sha}";\n', encoding="utf-8"
    )

    imported_sha = import_pinned_template(
        bundle,
        registry_path=destination_registry,
        data_dir=tmp_path / "destination-data",
    )
    assert imported_sha == entry["sha256"]
    assert (destination / "templates" / entry["template_path"]).is_file()

    data_dir = tmp_path / "replay-data"
    data_dir.mkdir()
    world = C.default_world("cnn.fear_greed")
    sidecar = C.Sidecar1(
        destination,
        data_dir,
        world=world,
        extra_env={"LEVIATHAN_REPLAY_ONLY": "1"},
    )
    try:
        reply, notes = sidecar.call("cnn.fear_greed")
    finally:
        sidecar.close()
    assert notes == []
    assert reply["status"] == "OK", reply
    assert reply["template_sha256"] == entry["sha256"]
