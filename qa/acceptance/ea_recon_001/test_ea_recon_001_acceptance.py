from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import shutil
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from leviathan_core.strategy_ingest.presets.golden_goose_klp_presets import (
    EA_RECON_PRESET_REGISTRY_V1,
    SEED_MANIFEST_SHA256,
    import_ea_seed_preset,
)
from leviathan_core.strategy_ingest.presets.mt_set_import import (
    MtSetImportError,
    validated_hosting_material,
)

_REPO = Path(__file__).resolve().parents[3]
_SOURCE = _REPO / "packages/leviathan-core/src/leviathan_core/strategy_ingest/presets"
_DEFAULT_SEED_ROOT = Path(
    r"C:\Users\XYRASYSTEMS\TRAYCER MASTER TEMPLATE\XYRA-MASTER\projects"
    r"\XYRASYSTEMS\LEVIATHAN AI\inputs\strategy-seeds"
)
_SECRET = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"


def _seed_root() -> Path:
    return Path(os.environ.get("LEVIATHAN_STRATEGY_SEEDS", _DEFAULT_SEED_ROOT))


def _manifest() -> tuple[Path, dict[str, Any]]:
    manifest_path = _seed_root() / "manifest.json"
    if not manifest_path.is_file():
        pytest.skip(
            "external strategy seed manifest is absent; GitHub CI skips read-only source checks"
        )
    raw = manifest_path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    assert digest == SEED_MANIFEST_SHA256
    return manifest_path, json.loads(raw)


def _manifest_rows(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {row["sha256"]: row for row in manifest["entries"] if isinstance(row.get("sha256"), str)}


def _source_cells(raw: bytes) -> dict[str, str]:
    cells: dict[str, str] = {}
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        text = raw.decode("utf-16")
    elif raw.startswith(b"\xef\xbb\xbf"):
        text = raw.decode("utf-8-sig")
    else:
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            encoding = "utf-16-le" if raw[1::2].count(0) > len(raw) // 6 else "utf-16-be"
            text = raw.decode(encoding)
    for original_line in text.splitlines():
        line = original_line.strip()
        if not line or line.startswith(";") or "=" not in line:
            continue
        name, cell = line.split("=", 1)
        name = name.strip()
        if re.fullmatch(r"hint\d+", name, re.IGNORECASE):
            continue
        cells[name] = cell.strip().split("||", 1)[0].strip()
    return cells


def _roundtrip_contract(module: ModuleType, preset_id: str, raw: bytes) -> None:
    imported = module.import_ea_seed_preset(preset_id, raw)
    material = sys.modules[f"{module.__name__}.mt_set_import"].validated_hosting_material(
        imported.parsed_set, sovereign_risk_overrides={}
    )
    assert material.original_set_bytes == raw
    assert material.original_sha256 == hashlib.sha256(raw).hexdigest()
    assert dict(material.effective_values) == dict(imported.parsed_set.values)
    reimported = module.import_ea_seed_preset(preset_id, material.original_set_bytes)
    assert tuple(reimported.parsed_set.parameters) == tuple(imported.parsed_set.parameters)
    assert dict(reimported.parsed_set.values) == dict(imported.parsed_set.values)


def test_external_golden_goose_and_klp_sources_round_trip_without_loss() -> None:
    manifest_path, manifest = _manifest()
    rows_by_hash = _manifest_rows(manifest)
    assert manifest_path.stat().st_size > 0
    assert len(EA_RECON_PRESET_REGISTRY_V1) == 16
    for preset_id, entry in EA_RECON_PRESET_REGISTRY_V1.items():
        record = rows_by_hash.get(entry.source_sha256)
        assert record is not None, f"manifest has no exact source row for {preset_id}"
        assert record["ext"].casefold() == ".set"
        assert record["crack_labelled"] is entry.crack_labelled
        source_path = _seed_root() / record["library_path"]
        if not source_path.is_file():
            pytest.skip(f"external .set seed is absent for {preset_id}: {source_path}")
        raw = source_path.read_bytes()
        assert hashlib.sha256(raw).hexdigest() == entry.source_sha256
        assert record["sha256"] == entry.source_sha256

        imported = import_ea_seed_preset(preset_id, raw)
        assert imported.source_manifest_sha256 == SEED_MANIFEST_SHA256
        assert imported.source_sha256 == entry.source_sha256
        assert imported.crack_labelled is record["crack_labelled"]
        assert imported.parsed_set.original_set_bytes == raw
        assert imported.parsed_set.original_sha256 == entry.source_sha256

        source_fields = _source_cells(raw)
        parameters = imported.parsed_set.parameters
        assert set(parameters) == set(source_fields)
        assert tuple(mapping.source_name for mapping in imported.field_mappings) == tuple(
            sorted(parameters, key=str.casefold)
        )
        for field_name, source_value in source_fields.items():
            assert parameters[field_name].raw_value == source_value

        hosting = validated_hosting_material(imported.parsed_set, sovereign_risk_overrides={})
        assert hosting.original_set_bytes == raw
        assert hosting.original_sha256 == entry.source_sha256
        assert dict(hosting.effective_values) == dict(imported.parsed_set.values)
        round_trip = import_ea_seed_preset(preset_id, hosting.original_set_bytes)
        assert tuple(round_trip.parsed_set.parameters) == tuple(parameters)
        assert dict(round_trip.parsed_set.values) == dict(imported.parsed_set.values)


def test_registry_covers_manifest_families_and_crack_flags() -> None:
    _, manifest = _manifest()
    rows_by_hash = _manifest_rows(manifest)
    assert {entry.family_id for entry in EA_RECON_PRESET_REGISTRY_V1.values()} == {
        "GOLDEN_GOOSE",
        "KLP",
    }
    assert sum(e.family_id == "GOLDEN_GOOSE" for e in EA_RECON_PRESET_REGISTRY_V1.values()) == 13
    assert sum(e.family_id == "KLP" for e in EA_RECON_PRESET_REGISTRY_V1.values()) == 3
    for preset_id, entry in EA_RECON_PRESET_REGISTRY_V1.items():
        manifest_row = rows_by_hash.get(entry.source_sha256)
        assert manifest_row is not None, f"missing manifest family entry: {preset_id}"
        assert manifest_row["ext"].casefold() == ".set"
        assert manifest_row["crack_labelled"] is entry.crack_labelled


def test_appledouble_and_secret_material_are_rejected_without_partial_import(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with pytest.raises(MtSetImportError) as sidecar:
        import_ea_seed_preset("._gg-1k-harvest-goal-mt4", b"Lots=0.1\n")
    assert sidecar.value.code == "UNKNOWN_SEED_PRESET"

    with pytest.raises(MtSetImportError) as secret_name:
        import_ea_seed_preset(
            "gg-1k-harvest-goal-mt4",
            f"startingLot=0.1\napiKey={_SECRET}\n".encode(),
        )
    assert secret_name.value.code == "SECRET_FIELD_QUARANTINED"
    assert str(secret_name.value) == "SECRET_FIELD_QUARANTINED"
    assert _SECRET not in repr(secret_name.value)
    assert _SECRET not in repr(vars(secret_name.value))

    with pytest.raises(MtSetImportError) as secret_value:
        import_ea_seed_preset(
            "gg-1k-harvest-goal-mt4",
            f"startingLot=0.1\nEA_Name={_SECRET}\n".encode(),
        )
    assert secret_value.value.code == "SECRET_VALUE_QUARANTINED"
    assert str(secret_value.value) == "SECRET_VALUE_QUARANTINED"
    assert _SECRET not in repr(secret_value.value)
    assert _SECRET not in repr(vars(secret_value.value))
    assert not hasattr(secret_value.value, "partial_result")
    assert _SECRET not in caplog.text


def test_repository_contains_no_seed_payloads_or_compiled_ea_binaries() -> None:
    seed_dir = _REPO / "inputs/strategy-seeds"
    assert not seed_dir.exists() or not any(path.is_file() for path in seed_dir.rglob("*"))
    for _current, _dirs, files in os.walk(_REPO):
        assert not [name for name in files if Path(name).suffix.casefold() in {".ex4", ".ex5"}]


def _load_scratch_adapter(tmp_path: Path, mutation: str) -> ModuleType:
    package_dir = tmp_path / "scratchpkg"
    package_dir.mkdir()
    shutil.copy2(_SOURCE / "golden_goose_klp_presets.py", package_dir)
    shutil.copy2(_SOURCE / "mt_set_import.py", package_dir)
    adapter_path = package_dir / "golden_goose_klp_presets.py"
    importer_path = package_dir / "mt_set_import.py"
    adapter_text = adapter_path.read_text(encoding="utf-8")
    importer_text = importer_path.read_text(encoding="utf-8")

    if mutation == "quarantine_bypass":
        assert "    _quarantine_secret_fields(raw_set)\n" in adapter_text
        adapter_text = adapter_text.replace(
            "    _quarantine_secret_fields(raw_set)\n", "    pass\n", 1
        )
    elif mutation == "digest_unchecked":
        anchor = "    if digest not in {entry.source_sha256, entry.fixture_sha256}:\n"
        assert anchor in adapter_text
        adapter_text = adapter_text.replace(anchor, "    if False:\n", 1)
    elif mutation == "secret_preserved":
        anchor = '            raise MtSetImportError("SECRET_VALUE_QUARANTINED")\n'
        assert anchor in adapter_text
        adapter_text = adapter_text.replace(
            anchor,
            '            raise MtSetImportError(f"SECRET_VALUE_QUARANTINED:{value}")\n',
            1,
        )
    elif mutation == "value_dropped":
        anchor = (
            "    effective = {name: parameter.value "
            "for name, parameter in preset.parameters.items()}\n"
        )
        assert anchor in importer_text
        importer_text = importer_text.replace(anchor, "    effective = {}\n", 1)
    else:
        raise AssertionError(f"unknown scratch mutation: {mutation}")

    adapter_path.write_text(adapter_text, encoding="utf-8")
    importer_path.write_text(importer_text, encoding="utf-8")
    package_name = f"ea_recon_scratch_{mutation}_{id(tmp_path)}"
    spec = importlib.util.spec_from_file_location(
        package_name,
        adapter_path,
        submodule_search_locations=[str(package_dir)],
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[package_name] = module
    spec.loader.exec_module(module)
    return module


def _probe_scratch_mutation(module: ModuleType, mutation: str) -> None:
    preset_id = "gg-1k-harvest-goal-mt4"
    entry = module.EA_RECON_PRESET_REGISTRY_V1[preset_id]
    fixture_path = (
        _REPO
        / "packages/leviathan-core/tests/strategy_ingest/fixtures/ea_recon001"
        / entry.fixture_name
    )
    raw = fixture_path.read_bytes()

    if mutation == "value_dropped":
        parsed = module.import_ea_seed_preset(preset_id, raw).parsed_set
        hosted = sys.modules[f"{module.__name__}.mt_set_import"].validated_hosting_material(
            parsed, sovereign_risk_overrides={}
        )
        assert dict(hosted.effective_values) == dict(parsed.values)
    elif mutation in {"quarantine_bypass", "secret_preserved"}:
        try:
            module.import_ea_seed_preset(preset_id, f"EA_Name={_SECRET}\n".encode())
        except module.MtSetImportError as exc:
            assert exc.code == "SECRET_VALUE_QUARANTINED"
            assert _SECRET not in str(exc)
            assert _SECRET not in repr(exc)
        else:
            raise AssertionError("secret-bearing preset was accepted")
    elif mutation == "digest_unchecked":
        changed = raw.replace(b"LicenceType=0", b"LicenceType=1", 1)
        assert changed != raw
        try:
            module.import_ea_seed_preset(preset_id, changed)
        except module.MtSetImportError as exc:
            assert exc.code == "SOURCE_HASH_MISMATCH"
        else:
            raise AssertionError("modified source bytes were accepted")


@pytest.mark.parametrize(
    "mutation",
    ["value_dropped", "quarantine_bypass", "digest_unchecked", "secret_preserved"],
)
def test_scratch_mutants_are_killed(tmp_path: Path, mutation: str) -> None:
    module = _load_scratch_adapter(tmp_path, mutation)
    with pytest.raises(AssertionError):
        _probe_scratch_mutation(module, mutation)
