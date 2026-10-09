"""Synthetic, offline tests for the DEP-001 preflight contract."""

from __future__ import annotations

import copy
import hashlib
import json
import pickle
import sys
from dataclasses import replace
from datetime import date
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from infra.cloud.validate_resource_intent import (  # noqa: E402
    ResourceIntentRegistries,
    load_manifest,
    main,
)
from infra.cloud.validate_resource_intent import (  # noqa: E402
    validate_resource_intent as _validate_resource_intent,
)

EXAMPLE = ROOT / "infra/cloud/resource_intent.example.yaml"
TODAY = date(2026, 9, 30)
MAP_BYTES = (
    b"requirements:\n"
    b"  - id: LEV-REQ-001\n"
    b"  - id: LEV-REQ-006\n"
    b"  - id: LEV-REQ-009\n"
)
OWNERS = ["data-team", "platform-team", "release-manager"]
PRICES = ["https://developers.cloudflare.com/plans/"]


def _snapshot(values: list[str]) -> str:
    canonical = json.dumps(sorted(values), ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


REGISTRY_JSON = json.dumps(
    {
        "schema_version": 1,
        "owners": OWNERS,
        "owner_snapshot_id": _snapshot(OWNERS),
        "price_sources": PRICES,
        "price_source_snapshot_id": _snapshot(PRICES),
        "requirements_map_sha256": hashlib.sha256(MAP_BYTES).hexdigest(),
    },
    sort_keys=True,
    separators=(",", ":"),
).encode("utf-8")
REGISTRIES = ResourceIntentRegistries(REGISTRY_JSON, MAP_BYTES)


def validate_resource_intent(manifest: object, *, today: date, previous: object | None = None):
    return _validate_resource_intent(
        manifest, today=today, previous=previous, registries=REGISTRIES
    )


@pytest.fixture
def ready() -> dict:
    plan = load_manifest(EXAMPLE)
    assert isinstance(plan, dict)
    for env in plan["environments"].values():
        for resource in env["resources"]:
            resource["cost"] = {
                "currency": "USD",
                "monthly_cap": "12.50",
                "price_source": "https://developers.cloudflare.com/plans/",
                "retrieved_on": "2026-09-30",
            }
    return plan


def test_example_is_a_blocked_intent() -> None:
    result = validate_resource_intent(load_manifest(EXAMPLE), today=TODAY)
    assert result.exit_code == 2
    assert "PRICE_EVIDENCE_MISSING" in result.report
    assert "COST_CAP_PLACEHOLDER" in result.report


def test_valid_plan_redacted_deterministic_diff(ready: dict) -> None:
    first = validate_resource_intent(ready, today=TODAY)
    second = validate_resource_intent(copy.deepcopy(ready), today=TODAY)
    assert first == second
    assert first.exit_code == 0
    assert f"registries_sha256 {hashlib.sha256(REGISTRY_JSON).hexdigest()}" in first.report
    assert f"owner_snapshot_id {_snapshot(OWNERS)}" in first.report
    assert f"price_source_snapshot_id {_snapshot(PRICES)}" in first.report
    assert f"requirements_map_sha256 {hashlib.sha256(MAP_BYTES).hexdigest()}" in first.report
    assert first.report.count("+ ") == 8
    assert "development USD 50.00" in first.report
    assert "live USD 25.00" in first.report
    assert "staging USD 25.00" in first.report
    assert "vault://" not in first.report
    assert "leviathan-licensing" not in first.report
    assert "https://" not in first.report
    assert "(no changes)" in validate_resource_intent(
        ready, today=TODAY, previous=copy.deepcopy(ready)
    ).report


@pytest.mark.parametrize(
    ("case", "code", "exit_code"),
    [
        ("vendor", "VENDOR_KIND_INVALID", 1),
        ("scope", "SCOPE_OR_VERSION_INVALID", 1),
        ("literal_secret", "SECRET_OR_UNSAFE_FIELD", 1),
        ("requirement", "REQUIREMENT_MISSING", 2),
        ("price_source", "PRICE_EVIDENCE_MISSING", 2),
        ("stale_price", "PRICE_EVIDENCE_STALE", 2),
        ("retention_days", "RETENTION_POLICY_BLOCKED", 2),
        ("delete_on_destroy", "RETENTION_POLICY_BLOCKED", 2),
        ("staging_live_alias", "CREDENTIAL_SCOPE_INVALID", 1),
        ("live_dev_alias", "CREDENTIAL_SCOPE_INVALID", 1),
        ("zero_cap", "COST_CAP_PLACEHOLDER", 2),
    ],
)
def test_fail_closed(ready: dict, case: str, code: str, exit_code: int) -> None:
    development = ready["environments"]["development"]["resources"]
    live = ready["environments"]["live"]["resources"]
    staging = ready["environments"]["staging"]["resources"]
    if case == "vendor":
        live[0]["provider"] = "aws"
    elif case == "scope":
        ready["project"] = "factory-admin"
    elif case == "literal_secret":
        development[0]["password"] = "example"
    elif case == "requirement":
        development[0]["requirements"] = []
    elif case == "price_source":
        del development[0]["cost"]["price_source"]
    elif case == "stale_price":
        development[0]["cost"]["retrieved_on"] = "2026-08-30"
    elif case == "retention_days":
        development[3]["retention"]["days"] = 365
    elif case == "delete_on_destroy":
        development[3]["retention"]["delete_on_destroy"] = True
    elif case == "staging_live_alias":
        staging[0]["credential_aliases"] = ["vault://leviathan-ai/live/neon/NEON_DATABASE_URL"]
    elif case == "live_dev_alias":
        live[0]["credential_aliases"] = [
            "vault://leviathan-ai/development/neon/NEON_DATABASE_URL"
        ]
    elif case == "zero_cap":
        development[0]["cost"]["monthly_cap"] = "0.00"
    result = validate_resource_intent(ready, today=TODAY)
    assert result.exit_code == exit_code
    assert code in result.report


def test_literal_token_value_never_echoed(ready: dict) -> None:
    marker = "sk_abcdefghijklmnopqrstuvwxyz123456"
    ready["environments"]["development"]["resources"][0]["owner"] = marker
    result = validate_resource_intent(ready, today=TODAY)
    assert result.exit_code == 1
    assert marker not in result.report


def test_bool_integer_is_rejected(ready: dict) -> None:
    ready["environments"]["development"]["resources"][3]["retention"]["days"] = True
    result = validate_resource_intent(ready, today=TODAY)
    assert result.exit_code == 1
    assert "RETENTION_INVALID" in result.report


def test_text_boolean_is_rejected(ready: dict) -> None:
    ready["environments"]["development"]["resources"][0]["minimum_tier"] = "true"
    result = validate_resource_intent(ready, today=TODAY)
    assert result.exit_code == 1
    assert "MINIMUM_TIER_INVALID" in result.report


def test_price_age_boundary(ready: dict) -> None:
    for env in ready["environments"].values():
        for resource in env["resources"]:
            resource["cost"]["retrieved_on"] = "2026-08-31"
    assert validate_resource_intent(ready, today=TODAY).exit_code == 0
    ready["environments"]["live"]["resources"][0]["cost"]["retrieved_on"] = "2026-08-30"
    assert validate_resource_intent(ready, today=TODAY).exit_code == 2


def test_historical_cli_date_cannot_report_current_readiness(
    ready: dict, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    historical = date(2026, 8, 20)
    for env in ready["environments"].values():
        for resource in env["resources"]:
            resource["cost"]["retrieved_on"] = "2026-08-15"
    history_result = validate_resource_intent(ready, today=historical)
    assert history_result.exit_code == 0
    assert f"evaluation_date {historical.isoformat()}" in history_result.report

    manifest_file = tmp_path / "manifest.yaml"
    registry_file = tmp_path / "registries.json"
    map_file = tmp_path / "requirements.yaml"
    manifest_file.write_text(yaml.safe_dump(ready), encoding="utf-8")
    registry_file.write_bytes(REGISTRY_JSON)
    map_file.write_bytes(MAP_BYTES)
    assert main([
        str(manifest_file), "--registries", str(registry_file),
        "--requirements-map", str(map_file), "--historical", "--today", historical.isoformat(),
    ]) == 2
    output = capsys.readouterr().out
    assert f"evaluation_date {historical.isoformat()}" in output
    assert "HISTORICAL" in output
    assert "HISTORICAL_EVALUATION" in output
    assert "BLOCKERS\n(none)" not in output

    assert main([
        str(manifest_file), "--registries", str(registry_file),
        "--requirements-map", str(map_file), "--today", historical.isoformat(),
    ]) == 1
    no_flag_output = capsys.readouterr().out
    assert "TODAY_OVERRIDE_REQUIRES_HISTORICAL" in no_flag_output
    assert "evaluation_date " in no_flag_output


def test_historical_early_errors_keep_the_mode_label(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    malformed = tmp_path / "malformed.yaml"
    malformed.write_text("schema_version: [\n", encoding="utf-8")
    args = [str(malformed), "--historical", "--today", "2026-08-20"]
    assert main(args) == 1
    malformed_output = capsys.readouterr().out
    assert "evaluation_date 2026-08-20\nHISTORICAL\nINVALID" in malformed_output
    assert "DOCUMENT_OR_DATE_INVALID" in malformed_output

    bad_registry = tmp_path / "registries.json"
    requirements = tmp_path / "requirements.yaml"
    bad_registry.write_text("{", encoding="utf-8")
    requirements.write_bytes(MAP_BYTES)
    assert main([
        str(EXAMPLE), "--historical", "--today", "2026-08-20",
        "--registries", str(bad_registry), "--requirements-map", str(requirements),
    ]) == 2
    registry_output = capsys.readouterr().out
    assert "evaluation_date 2026-08-20\nHISTORICAL\nBLOCKERS" in registry_output
    assert "REGISTRY_INVALID" in registry_output


def test_proposed_change_is_diff_without_values(ready: dict) -> None:
    prior = copy.deepcopy(ready)
    ready["environments"]["live"]["resources"][0]["cost"]["monthly_cap"] = "18.00"
    result = validate_resource_intent(ready, today=TODAY, previous=prior)
    assert result.exit_code == 0
    assert result.report.count("~ ") == 1
    assert "18.00" not in result.report.split("DECLARED MONTHLY CAPS")[0]


def test_yaml_duplicate_keys_rejected(tmp_path: Path) -> None:
    document = tmp_path / "duplicate.yaml"
    document.write_text("schema_version: 1\nschema_version: 1\n", encoding="utf-8")
    with pytest.raises(ValueError, match="INVALID_DOCUMENT"):
        load_manifest(document)


def test_recursive_object_fails_closed(ready: dict) -> None:
    cost = ready["environments"]["development"]["resources"][0]["cost"]
    cost["cycle"] = cost
    result = validate_resource_intent(ready, today=TODAY)
    assert result.exit_code == 1


def test_result_freeze_semantics(ready: dict) -> None:
    result = validate_resource_intent(ready, today=TODAY)
    with pytest.raises(TypeError):
        copy.copy(result)
    with pytest.raises(TypeError):
        copy.deepcopy(result)
    with pytest.raises(TypeError):
        pickle.dumps(result)
    with pytest.raises(TypeError):
        replace(result, exit_code=True)


def test_result_assignment_and_deletion_do_not_echo(ready: dict) -> None:
    result = validate_resource_intent(ready, today=TODAY)
    marker = "SYNTHETIC_CANARY_VALUE"
    with pytest.raises(Exception) as assignment:
        result.report = marker
    assert marker not in str(assignment.value)
    with pytest.raises(Exception) as deletion:
        del result.report
    assert marker not in str(deletion.value)


def test_registry_missing_blocks_otherwise_ready_plan(ready: dict) -> None:
    result = _validate_resource_intent(ready, today=TODAY)
    assert result.exit_code == 2
    assert "REGISTRY_MISSING" in result.blockers


def test_registry_membership_blocks_unreviewed_values(ready: dict) -> None:
    resource = ready["environments"]["development"]["resources"][1]
    resource["owner"] = "ghp_SYNTHETIC_NOT_REAL_0123456789ABCDEF"
    resource["cost"]["price_source"] = (
        "https://example.com/pricing/ghp_SYNTHETIC_NOT_REAL_0123456789ABCDEF"
    )
    resource["requirements"] = ["LEV-REQ-999"]
    result = validate_resource_intent(ready, today=TODAY)
    assert result.exit_code == 2
    assert any("OWNER_UNAPPROVED" in code for code in result.blockers)
    assert any("PRICE_SOURCE_UNAPPROVED" in code for code in result.blockers)
    assert any("REQUIREMENT_UNMAPPED" in code for code in result.blockers)
    assert "SYNTHETIC_NOT_REAL" not in result.report


@pytest.mark.parametrize("field", ["purpose", "region", "jurisdiction", "tier"])
def test_closed_metadata_rejects_opaque_values(ready: dict, field: str) -> None:
    marker = "opaque-9f84c04f1f4c4b37"
    ready["environments"]["development"]["resources"][0][field] = marker
    result = validate_resource_intent(ready, today=TODAY)
    assert result.exit_code == 1
    assert any(code.endswith("RESOURCE_METADATA_INVALID") for code in result.errors)
    assert marker not in result.report


def test_invalid_port_has_safe_cli_error(
    ready: dict, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    marker = "SYNTHETIC_SECRET_ONLY"
    ready["environments"]["development"]["resources"][0]["cost"]["price_source"] = (
        f"https://example.com:{marker}/pricing"
    )
    manifest_file = tmp_path / "manifest.yaml"
    registry_file = tmp_path / "registries.json"
    map_file = tmp_path / "requirements.yaml"
    manifest_file.write_text(yaml.safe_dump(ready), encoding="utf-8")
    registry_file.write_bytes(REGISTRY_JSON)
    map_file.write_bytes(MAP_BYTES)
    assert main([
        str(manifest_file), "--registries", str(registry_file),
        "--requirements-map", str(map_file), "--historical", "--today", TODAY.isoformat(),
    ]) == 1
    output = capsys.readouterr()
    assert "PRICE_SOURCE_INVALID" in output.out
    assert not output.err
    assert marker not in output.out


def test_registry_snapshot_hash_mismatch_is_safe() -> None:
    with pytest.raises(ValueError, match="REGISTRY_INVALID"):
        ResourceIntentRegistries(REGISTRY_JSON, MAP_BYTES + b"# tampered\n")
    with pytest.raises(TypeError):
        copy.copy(REGISTRIES)
    with pytest.raises(TypeError):
        copy.deepcopy(REGISTRIES)
    with pytest.raises(TypeError):
        pickle.dumps(REGISTRIES)
