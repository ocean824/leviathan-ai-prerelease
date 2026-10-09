from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from leviathan_core.strategy_ingest.presets.golden_goose_klp_presets import (
    EA_RECON_PRESET_REGISTRY_V1,
    GOLDEN_GOOSE_KLP_PARAMETER_SCHEMA_V1,
    import_ea_seed_preset,
)
from leviathan_core.strategy_ingest.presets.mt_set_import import MtSetImportError

_FIXTURES = Path(__file__).parent / "fixtures" / "ea_recon001"


def test_all_registered_golden_goose_and_klp_parameter_fixtures_round_trip() -> None:
    assert len(EA_RECON_PRESET_REGISTRY_V1) == 16
    assert len(GOLDEN_GOOSE_KLP_PARAMETER_SCHEMA_V1) == 176

    family_counts = {"GOLDEN_GOOSE": 0, "KLP": 0}
    for preset_id, entry in EA_RECON_PRESET_REGISTRY_V1.items():
        raw = (_FIXTURES / entry.fixture_name).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == entry.fixture_sha256
        assert b"hint" not in raw.lower()

        imported = import_ea_seed_preset(preset_id, raw)
        repeated = import_ea_seed_preset(preset_id, raw)
        family_counts[entry.family_id] += 1

        assert imported.schema_version == "1"
        assert imported.family_id == entry.family_id
        assert imported.preset_role == entry.preset_role
        assert imported.preset_version == entry.preset_version
        assert imported.source_sha256 == entry.source_sha256
        assert imported.source_manifest_sha256
        assert imported.crack_labelled is entry.crack_labelled
        assert imported.license_attestation_ref == entry.license_attestation_ref
        assert imported.parsed_set.original_sha256 == entry.fixture_sha256
        assert imported.parsed_set.original_set_bytes == raw
        assert imported.parsed_set.source_family == "TITAN_X"
        assert imported.parsed_set.instrument_mapping.instrument_id == "UNBOUND"
        assert imported.parsed_set.timezone_mapping.iana_timezone is None
        assert tuple(binding.source_name for binding in imported.field_mappings) == tuple(
            sorted(imported.parsed_set.parameters, key=str.casefold)
        )
        assert imported.source_sha256 == repeated.source_sha256
        assert imported.parsed_set.values == repeated.parsed_set.values

    assert family_counts == {"GOLDEN_GOOSE": 13, "KLP": 3}


@pytest.mark.parametrize(
    "secret_field",
    ["apiKey", "client_secret", "password", "privateKey", "access_token"],
)
def test_secret_bearing_fields_are_quarantined_without_echoing_values(
    secret_field: str,
) -> None:
    canary = "SECRET_CANARY_VALUE_7a49"
    with pytest.raises(MtSetImportError) as error:
        import_ea_seed_preset("gg-1k-harvest-goal-mt4", f"{secret_field}={canary}\n".encode())
    assert error.value.code == "SECRET_FIELD_QUARANTINED"
    assert str(error.value) == "SECRET_FIELD_QUARANTINED"
    assert canary not in str(error.value)


def test_secret_value_patterns_are_quarantined_without_echoing_values() -> None:
    canary = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
    with pytest.raises(MtSetImportError) as error:
        import_ea_seed_preset("gg-1k-harvest-goal-mt4", f"EA_Name={canary}\n".encode())
    assert error.value.code == "SECRET_VALUE_QUARANTINED"
    assert canary not in str(error.value)


def test_unregistered_sidecars_and_modified_source_bytes_are_rejected() -> None:
    with pytest.raises(MtSetImportError) as unknown:
        import_ea_seed_preset("._gg-1k-harvest-goal-mt4", b"Lots=0.1\n")
    assert unknown.value.code == "UNKNOWN_SEED_PRESET"

    entry = EA_RECON_PRESET_REGISTRY_V1["gg-1k-harvest-goal-mt4"]
    raw = (_FIXTURES / entry.fixture_name).read_bytes() + b"Lots=0.2\n"
    with pytest.raises(MtSetImportError) as changed:
        import_ea_seed_preset(entry.preset_id, raw)
    assert changed.value.code == "SOURCE_HASH_MISMATCH"


def test_preset_registry_cannot_be_mutated() -> None:
    with pytest.raises(TypeError):
        EA_RECON_PRESET_REGISTRY_V1["attacker-preset"] = next(
            iter(EA_RECON_PRESET_REGISTRY_V1.values())
        )  # type: ignore[index]
