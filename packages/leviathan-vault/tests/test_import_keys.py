from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from leviathan_vault import import_keys, transaction

SYNTHETIC = """========================
LIVE MARKET DATA
========================
DATABENTO: development plan
https://data.example.test/v1
KEY: Zq8pY4rT9mL2vN6x | SECRET: H7cW3jK8pR2mQ5tV

FRED: free plan
KEY: P9vT2xL6mQ8rJ4kY

MACRO MIRROR: plan
Same FRED key

WEB PORTAL: account
Login: synthetic-user@example.test
Password: R5mL8pV2kQ9jT4xN

NOT PURCHASED: web form only
No key. Base https://none.example.test

IBKR: broker
B7qW9mP3vT8xL2rK

KALSHI: authenticated
Header: M3xQ7pL9vT2rK8jW

COPERNICUS: account
SECRET: V8jL2qP9mT4xR7kW
"""
VALUES = [
    "Zq8pY4rT9mL2vN6x", "H7cW3jK8pR2mQ5tV",
    "P9vT2xL6mQ8rJ4kY", "R5mL8pV2kQ9jT4xN",
    "B7qW9mP3vT8xL2rK", "M3xQ7pL9vT2rK8jW",
    "V8jL2qP9mT4xR7kW",
]


def _registry(root: Path) -> Path:
    path = root / "registries" / "SECRET_REGISTRY.yaml"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"schema_version": "1.0.0", "entries": [{
        "name": "EXISTING_SECRET", "scope": "factory-admin", "environment": "administration",
        "store_reference": "dpapi-current-user://factory-admin--administration--EXISTING_SECRET.dpapi",
        "inherit_to_projects": False, "purpose": "unchanged metadata",
    }]}), encoding="utf-8")
    return path


def _bindings(root: Path) -> Path:
    path = root / "SECRET_BINDINGS.yaml"
    path.write_text(json.dumps({"schema_version": "1.0.0", "bindings": [{
        "provider": "unrelated", "name": "UNRELATED_API_KEY", "scope": "leviathan-ai",
        "environment": "development", "state": "pending_import", "custom": "preserve",
    }], "aliases": []}), encoding="utf-8")
    return path


def _assert_redacted(output: str) -> None:
    for value in VALUES:
        for start in range(len(value) - 5):
            assert value[start:start + 6] not in output


def test_parser_constructs_and_no_urls_or_logins() -> None:
    plan = import_keys.parse_key_text(SYNTHETIC)
    assert {(item.name, item.environment) for item in plan.credentials} == {
        ("DATABENTO_API_KEY", "development"), ("DATABENTO_SECRET", "development"),
        ("FRED_API_KEY", "development"), ("IBKR_CREDENTIAL", "live"),
        ("KALSHI_API_KEY", "live"), ("COPERNICUS_SECRET", "development"),
    }
    assert [(item.provider, item.target_name) for item in plan.aliases] == [
        ("MACRO_MIRROR", "FRED_API_KEY")
    ]
    assert plan.interactive_login_skipped == ("WEB_PORTAL",)
    assert plan.requires_key == ("NOT_PURCHASED",)
    assert not any("https" in item.value for item in plan.credentials)
    _assert_redacted(repr(plan))


def test_dry_run_idempotency_backup_and_semantic_preservation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = _registry(tmp_path)
    bindings = _bindings(tmp_path)
    original = json.loads(registry.read_text(encoding="utf-8"))
    original_bindings = json.loads(bindings.read_text(encoding="utf-8"))
    plan = import_keys.parse_key_text(SYNTHETIC)
    calls: list[tuple[str, bool]] = []
    monkeypatch.setattr(import_keys, "_broker_write", lambda root, item, scope, replace:
                        calls.append((item.name, replace)))
    dry = import_keys.import_plan(
        tmp_path, plan, "leviathan-ai", dry_run=True, bindings=bindings
    )
    assert dry.imported == 0 and dry.would_import == 6 and dry.dry_run
    assert json.loads(registry.read_text(encoding="utf-8")) == original
    assert json.loads(bindings.read_text(encoding="utf-8")) == original_bindings
    assert not (tmp_path / ".local").exists()
    assert not calls
    result = import_keys.import_plan(tmp_path, plan, "leviathan-ai", bindings=bindings)
    assert result.imported == 6 and len(calls) == 6
    saved = json.loads(registry.read_text(encoding="utf-8"))
    assert saved["entries"][0] == original["entries"][0]
    assert len(saved["entries"]) == 7
    for entry in saved["entries"][1:]:
        assert set(entry) == {
            "store_reference", "scope", "environment", "purpose", "owner", "name",
            "classification", "inherit_to_projects", "provider", "rotation", "validation",
        }
        assert entry["inherit_to_projects"] is False
        assert entry["validation"]["provider_authentication"] == "NOT_TESTED"
    backups = list((tmp_path / ".local" / "registry-backups").glob("*.yaml"))
    assert len(backups) == 1
    assert json.loads(backups[0].read_text(encoding="utf-8")) == original
    assert import_keys.import_plan(
        tmp_path, plan, "leviathan-ai", bindings=bindings
    ).skipped_existing == 6
    assert len(calls) == 6
    assert import_keys.import_plan(
        tmp_path, plan, "leviathan-ai", bindings=bindings, replace=True
    ).imported == 6
    assert calls[-6:] == [(item.name, True) for item in plan.credentials]
    saved_bindings = json.loads(bindings.read_text(encoding="utf-8"))
    assert saved_bindings["bindings"][0] == original_bindings["bindings"][0]
    assert saved_bindings["aliases"] == [{
        "provider": "macro-mirror", "name": "MACRO_MIRROR_API_KEY",
        "scope": "leviathan-ai", "environment": "development",
        "target": {"provider": "fred", "name": "FRED_API_KEY",
                   "scope": "leviathan-ai", "environment": "development"},
    }]
    assert saved_bindings["bindings"][-1]["name"] == "COPERNICUS_SECRET"
    _assert_redacted(registry.read_text(encoding="utf-8"))
    _assert_redacted(backups[0].read_text(encoding="utf-8"))
    _assert_redacted(bindings.read_text(encoding="utf-8"))


def test_alias_destination_and_invalid_alias_preflight(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = _registry(tmp_path)
    original = registry.read_bytes()
    plan = import_keys.parse_key_text(SYNTHETIC)
    calls: list[str] = []
    monkeypatch.setattr(import_keys, "_broker_write", lambda *args: calls.append("called"))
    with pytest.raises(import_keys.ImportErrorCode, match=r"^IMPORT_BINDINGS_REQUIRED$"):
        import_keys.import_plan(tmp_path, plan, "leviathan-ai")
    assert registry.read_bytes() == original and not calls
    dry = import_keys.import_plan(tmp_path, plan, "leviathan-ai", dry_run=True)
    assert dry.bindings_required and dry.imported == 0 and dry.would_import == 6
    assert "FRED_API_KEY" in dry.unresolved_mappings
    assert not (tmp_path / ".local").exists()
    with pytest.raises(import_keys.ImportErrorCode, match=r"^IMPORT_BINDINGS_FAILED$"):
        import_keys.import_plan(
            tmp_path, plan, "leviathan-ai", bindings=tmp_path / "absent.yaml"
        )
    assert registry.read_bytes() == original and not calls
    bindings = _bindings(tmp_path)
    unresolved = json.loads(bindings.read_text(encoding="utf-8"))
    unresolved["bindings"].append({
        "provider": "fred", "name": "FRED_API_KEY", "scope": "leviathan-ai",
        "environment": "development", "state": "pending_import",
    })
    bindings.write_text(json.dumps(unresolved), encoding="utf-8")
    orphan = import_keys.ImportPlan((), (
        import_keys.ManifestAlias("MACRO_MIRROR", "FRED", "FRED_API_KEY", "development"),
    ), (), ())
    with pytest.raises(import_keys.ImportErrorCode, match=r"^IMPORT_BINDINGS_FAILED$"):
        import_keys.import_plan(tmp_path, orphan, "leviathan-ai", bindings=bindings)
    bindings = _bindings(tmp_path)
    bad = import_keys.ImportPlan((), (
        import_keys.ManifestAlias("ALIAS_ONE", "UNKNOWN", "UNKNOWN_API_KEY", "development"),
    ), (), ())
    with pytest.raises(import_keys.ImportErrorCode, match=r"^IMPORT_BINDINGS_FAILED$"):
        import_keys.import_plan(tmp_path, bad, "leviathan-ai", bindings=bindings)
    assert registry.read_bytes() == original and not calls
    cycle = import_keys.ImportPlan((), (
        import_keys.ManifestAlias("ALIAS_ONE", "ALIAS_TWO", "ALIAS_TWO_API_KEY", "development"),
        import_keys.ManifestAlias("ALIAS_TWO", "ALIAS_ONE", "ALIAS_ONE_API_KEY", "development"),
    ), (), ())
    with pytest.raises(import_keys.ImportErrorCode, match=r"^IMPORT_BINDINGS_FAILED$"):
        import_keys.import_plan(tmp_path, cycle, "leviathan-ai", bindings=bindings)
    assert registry.read_bytes() == original and not calls


def test_credential_without_alias_requires_bindings_before_mutation(
    tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    registry = _registry(tmp_path)
    original = registry.read_bytes()
    source = tmp_path / "synthetic.txt"
    source.write_text("FRED: synthetic\nKEY: P9vT2xL6mQ8rJ4kY\n", encoding="utf-8")
    args = ["--source", str(source), "--scope", "leviathan-ai",
            "--factory-root", str(tmp_path)]
    assert import_keys.main(args) == 2
    assert capsys.readouterr().err.strip() == "IMPORT_BINDINGS_REQUIRED"
    assert registry.read_bytes() == original
    assert not (tmp_path / ".local").exists()
    assert import_keys.main([*args, "--dry-run"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["dry_run"] and result["bindings_required"]
    assert result["imported"] == 0 and result["would_import"] == 1
    assert result["unresolved_mappings"] == ["FRED_API_KEY"]
    assert registry.read_bytes() == original
    assert not (tmp_path / ".local").exists()
    _assert_redacted(json.dumps(result))

    malformed = tmp_path / "malformed-bindings.yaml"
    malformed.write_text("{invalid", encoding="utf-8")
    assert import_keys.main([*args, "--bindings", str(malformed)]) == 2
    assert capsys.readouterr().err.strip() == "IMPORT_BINDINGS_FAILED"
    assert malformed.read_text(encoding="utf-8") == "{invalid"
    assert registry.read_bytes() == original


def test_bindings_junction_denied_before_import(tmp_path: Path) -> None:
    if os.name != "nt":
        pytest.skip("Windows reparse-point policy")
    registry = _registry(tmp_path / "factory")
    original = registry.read_bytes()
    outside = tmp_path / "outside-bindings"
    outside.mkdir()
    _bindings(outside)
    junction = tmp_path / "linked-bindings"
    result = subprocess.run(["cmd", "/c", "mklink", "/J", str(junction), str(outside)],
                            capture_output=True, text=True, check=False)
    if result.returncode:
        pytest.skip("Windows host cannot create disposable junction")
    plan = import_keys.ImportPlan((
        import_keys.ParsedCredential("FRED", "FRED_API_KEY", "development", VALUES[2]),
    ), (), (), ())
    with pytest.raises(transaction.TransactionError, match=r"^IMPORT_PATH_DENIED$"):
        import_keys.import_plan(tmp_path / "factory", plan, "leviathan-ai",
                                bindings=junction / "SECRET_BINDINGS.yaml")
    assert registry.read_bytes() == original
    assert not (tmp_path / "factory" / ".local").exists()


def test_canonical_provider_mapping_and_explicit_environment() -> None:
    plan = import_keys.parse_key_text(
        "POLYGON: stocks\nKEY: Q8mT2pL7rV4xK9jN\n\n"
        "KALSHI MARKET DATA: public feed\nKEY: W2pN8tR4mL9xJ7vQ\n\n"
        "KALSHI: authenticated\nHeader: B7qW9mP3vT8xL2rK\n"
    )
    assert {(item.name, item.environment) for item in plan.credentials} == {
        ("MASSIVE_API_KEY", "development"),
        ("KALSHI_MARKET_DATA_API_KEY", "development"),
        ("KALSHI_API_KEY", "live"),
    }
    with pytest.raises(import_keys.ImportErrorCode, match=r"^IMPORT_FORMAT_DENIED$"):
        import_keys.parse_key_text("KALSHI FEED: ambiguous\nKEY: P9vT2xL6mQ8rJ4kY\n")
    with pytest.raises(import_keys.ImportErrorCode, match=r"^IMPORT_FORMAT_DENIED$"):
        import_keys.parse_key_text("UNKNOWN SERVICE: plan\nKEY: P9vT2xL6mQ8rJ4kY\n")


def test_required_binding_matches_touched_provider_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _registry(tmp_path)
    bindings = _bindings(tmp_path)
    document = json.loads(bindings.read_text(encoding="utf-8"))
    document["bindings"].extend([
        {"provider": "massive", "name": "MASSIVE_API_KEY", "scope": "leviathan-ai",
         "environment": "development", "state": "pending_import"},
        {"provider": "fred", "name": "FRED_API_KEY", "scope": "leviathan-ai",
         "environment": "development", "state": "pending_import"},
        {"provider": "cloudflare", "name": "CLOUDFLARE_API_TOKEN",
         "scope": "leviathan-ai", "environment": "development",
         "state": "pending_dep_provisioning"},
    ])
    bindings.write_text(json.dumps(document), encoding="utf-8")
    polygon = import_keys.parse_key_text("POLYGON: stocks\nKEY: Q8mT2pL7rV4xK9jN\n")
    dry = import_keys.import_plan(tmp_path, polygon, "leviathan-ai",
                                 bindings=bindings, dry_run=True)
    assert dry.imported == 0 and dry.would_import == 1
    assert json.loads(bindings.read_text(encoding="utf-8")) == document
    monkeypatch.setattr(import_keys, "_broker_write", lambda *args: None)
    import_keys.import_plan(tmp_path, polygon, "leviathan-ai", bindings=bindings)
    saved = json.loads(bindings.read_text(encoding="utf-8"))
    assert saved["bindings"][1]["state"] == "locally_stored"
    assert saved["bindings"][2:] == document["bindings"][2:]
    wrong_field = import_keys.ImportPlan((
        import_keys.ParsedCredential("MASSIVE", "MASSIVE_SECRET", "development",
                                     "P9vT2xL6mQ8rJ4kY"),
    ), (), (), ())
    fresh = tmp_path / "fresh-bindings.yaml"
    fresh.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(import_keys.ImportErrorCode, match=r"^IMPORT_BINDINGS_FAILED$"):
        import_keys.import_plan(tmp_path, wrong_field, "leviathan-ai",
                                bindings=fresh, dry_run=True)
    wrong_environment = import_keys.ImportPlan((
        import_keys.ParsedCredential("KALSHI", "KALSHI_API_KEY", "development",
                                     "P9vT2xL6mQ8rJ4kY"),
    ), (), (), ())
    with pytest.raises(import_keys.ImportErrorCode, match=r"^IMPORT_FORMAT_DENIED$"):
        import_keys.import_plan(tmp_path, wrong_environment, "leviathan-ai", dry_run=True)
    wrong_classification = import_keys.ImportPlan((
        import_keys.ParsedCredential("MASSIVE", "MASSIVE_API_KEY", "development",
                                     "P9vT2xL6mQ8rJ4kY", "public-configuration"),
    ), (), (), ())
    with pytest.raises(import_keys.ImportErrorCode, match=r"^IMPORT_FORMAT_DENIED$"):
        import_keys.import_plan(tmp_path, wrong_classification, "leviathan-ai", dry_run=True)


def test_existing_alias_edges_and_duplicate_registry_targets(tmp_path: Path) -> None:
    registry = _registry(tmp_path)
    bindings = _bindings(tmp_path)
    base = json.loads(bindings.read_text(encoding="utf-8"))
    base["bindings"].append({
        "provider": "fred", "name": "FRED_API_KEY", "scope": "leviathan-ai",
        "environment": "live", "state": "locally_stored",
    })
    base["aliases"].append({
        "provider": "macro-mirror", "name": "MACRO_MIRROR_API_KEY",
        "scope": "leviathan-ai", "environment": "development",
        "target": {"provider": "fred", "name": "FRED_API_KEY",
                   "scope": "leviathan-ai", "environment": "live"},
    })
    bindings.write_text(json.dumps(base), encoding="utf-8")
    with pytest.raises(import_keys.ImportErrorCode, match=r"^IMPORT_BINDINGS_FAILED$"):
        import_keys.import_plan(tmp_path, import_keys.ImportPlan((), (), (), ()),
                                "leviathan-ai", bindings=bindings, dry_run=True)
    base["aliases"][0]["target"] = {
        "provider": "fred", "name": "FRED_API_KEY", "scope": "factory-admin",
        "environment": "administration",
    }
    bindings.write_text(json.dumps(base), encoding="utf-8")
    with pytest.raises(import_keys.ImportErrorCode, match=r"^IMPORT_BINDINGS_FAILED$"):
        import_keys.import_plan(tmp_path, import_keys.ImportPlan((), (), (), ()),
                                "leviathan-ai", bindings=bindings, dry_run=True)
    base["bindings"][1]["environment"] = "development"
    base["aliases"][0]["target"] = {
        "provider": "fred", "name": "FRED_API_KEY", "scope": "leviathan-ai",
        "environment": "development",
    }
    bindings.write_text(json.dumps(base), encoding="utf-8")
    registry_data = json.loads(registry.read_text(encoding="utf-8"))
    duplicated = {"name": "FRED_API_KEY", "scope": "leviathan-ai",
                  "environment": "development", "inherit_to_projects": False}
    registry_data["entries"].extend([duplicated, duplicated.copy()])
    registry.write_text(json.dumps(registry_data), encoding="utf-8")
    with pytest.raises(import_keys.ImportErrorCode, match=r"^IMPORT_REGISTRY_FAILED$"):
        import_keys.import_plan(tmp_path, import_keys.ImportPlan((), (), (), ()),
                                "leviathan-ai", bindings=bindings, dry_run=True)


@pytest.mark.parametrize("source,target,environment", [
    ("KALSHI MARKET DATA", "KALSHI", "live"),
    ("KALSHI", "KALSHI MARKET DATA", "development"),
])
def test_alias_only_known_source_environment_mismatch_denied_before_write(
    tmp_path: Path, source: str, target: str, environment: str,
) -> None:
    registry = _registry(tmp_path)
    bindings = _bindings(tmp_path)
    target_name = f"{import_keys._slug(target)}_API_KEY"
    metadata = json.loads(registry.read_text(encoding="utf-8"))
    metadata["entries"].append({
        "name": target_name, "scope": "leviathan-ai", "environment": environment,
        "inherit_to_projects": False,
        "store_reference": import_keys.store_reference(
            target_name, "leviathan-ai", environment),
    })
    registry.write_text(json.dumps(metadata), encoding="utf-8")
    document = json.loads(bindings.read_text(encoding="utf-8"))
    document["bindings"].append({
        "provider": import_keys._slug(target).lower().replace("_", "-"),
        "name": target_name, "scope": "leviathan-ai", "environment": environment,
        "state": "locally_stored",
    })
    bindings.write_text(json.dumps(document), encoding="utf-8")
    before_registry, before_bindings = registry.read_bytes(), bindings.read_bytes()
    source_text = f"{source}: alias only\nSame {target} key\n"
    with pytest.raises(import_keys.ImportErrorCode, match=r"^IMPORT_FORMAT_DENIED$"):
        plan = import_keys.parse_key_text(source_text)
        import_keys.import_plan(tmp_path, plan, "leviathan-ai", bindings=bindings)
    assert registry.read_bytes() == before_registry
    assert bindings.read_bytes() == before_bindings
    assert not (tmp_path / ".local").exists()


@pytest.mark.parametrize("invalid", ["inherited", "reference"])
def test_alias_target_must_satisfy_vault_metadata_policy(
    tmp_path: Path, invalid: str,
) -> None:
    registry = _registry(tmp_path)
    bindings = _bindings(tmp_path)
    document = json.loads(registry.read_text(encoding="utf-8"))
    target = {
        "name": "FRED_API_KEY", "scope": "leviathan-ai", "environment": "development",
        "inherit_to_projects": False,
        "store_reference": import_keys.store_reference(
            "FRED_API_KEY", "leviathan-ai", "development"),
    }
    if invalid == "inherited":
        target["inherit_to_projects"] = True
    else:
        target["store_reference"] = "dpapi-current-user://wrong.dpapi"
    document["entries"].append(target)
    registry.write_text(json.dumps(document), encoding="utf-8")
    manifest = json.loads(bindings.read_text(encoding="utf-8"))
    manifest["bindings"].append({
        "provider": "fred", "name": "FRED_API_KEY", "scope": "leviathan-ai",
        "environment": "development", "state": "locally_stored",
    })
    bindings.write_text(json.dumps(manifest), encoding="utf-8")
    before_registry, before_bindings = registry.read_bytes(), bindings.read_bytes()
    plan = import_keys.parse_key_text("MACRO MIRROR: alias\nSame FRED key\n")
    with pytest.raises(import_keys.ImportErrorCode, match=r"^IMPORT_BINDINGS_FAILED$"):
        import_keys.import_plan(tmp_path, plan, "leviathan-ai", bindings=bindings)
    assert registry.read_bytes() == before_registry
    assert bindings.read_bytes() == before_bindings
    assert not list((tmp_path / ".local").rglob("*.dpapi"))


def test_cli_alias_persistence_and_redacted_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    _registry(tmp_path)
    bindings = _bindings(tmp_path)
    source = tmp_path / "keys.txt"
    source.write_text(SYNTHETIC, encoding="utf-8")
    monkeypatch.setattr(import_keys, "_broker_write", lambda *args: None)
    args = ["--source", str(source), "--scope", "leviathan-ai",
            "--factory-root", str(tmp_path), "--bindings", str(bindings)]
    assert import_keys.main(args) == 0
    first = capsys.readouterr()
    _assert_redacted(first.out + first.err)
    assert json.loads(first.out)["aliases"] == 1
    assert import_keys.main(args) == 0
    second = capsys.readouterr()
    _assert_redacted(second.out + second.err)
    assert json.loads(second.out)["skipped_existing"] == 6
    assert len(json.loads(bindings.read_text(encoding="utf-8"))["aliases"]) == 1


def test_broker_failure_rolls_back_entry_and_never_echoes_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    registry = _registry(tmp_path)
    bindings = _bindings(tmp_path)
    original = json.loads(registry.read_text(encoding="utf-8"))
    item = import_keys.ParsedCredential("FRED", "FRED_API_KEY", "development", VALUES[2])
    monkeypatch.setattr(import_keys.shutil, "which", lambda name: "powershell.exe")
    real_run = subprocess.run

    def broker_failure(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        if args and isinstance(args[0], list) and args[0][-1] == import_keys._BROKER_SCRIPT:
            return subprocess.CompletedProcess(
                args, 1, stdout=VALUES[2], stderr=VALUES[2]
            )
        return real_run(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(import_keys.subprocess, "run", broker_failure)
    with pytest.raises(import_keys.ImportErrorCode, match=r"^SECRET_WRITE_FAILED$"):
        import_keys.import_plan(
            tmp_path, import_keys.ImportPlan((item,), (), (), ()), "leviathan-ai",
            bindings=bindings,
        )
    assert json.loads(registry.read_text(encoding="utf-8")) == original
    _assert_redacted(capsys.readouterr().out + capsys.readouterr().err)


def test_malformed_fixture_redaction(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    source = tmp_path / "synthetic.txt"
    source.write_text("FRED: plan\nKEY: P9vT2xL6mQ8rJ4kY\nKEY: P9vT2xL6mQ8rJ4kY\n",
                      encoding="utf-8")
    assert import_keys.main(["--source", str(source), "--scope", "leviathan-ai",
                             "--factory-root", str(tmp_path), "--dry-run"]) == 2
    output = capsys.readouterr()
    _assert_redacted(output.out + output.err)
