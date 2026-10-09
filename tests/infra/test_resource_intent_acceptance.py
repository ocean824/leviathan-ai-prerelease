"""Independent adversarial acceptance for DEP-001 resource intent preflight."""

from __future__ import annotations

import copy
import hashlib
import json
import socket
import sys
from datetime import date
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from infra.cloud.validate_resource_intent import (
    ResourceIntentRegistries,
    load_registries,
    main,
    validate_resource_intent,
)

TODAY = date(2026, 9, 30)
SECRET = "sk_live_acceptance_secret_value_12345"
APPROVED_OWNERS = ("platform-team", "release-manager")
APPROVED_PRICE_SOURCES = ("https://example.com/pricing",)
REQUIREMENTS_MAP = (
    b"requirements:\n"
    b"  - id: LEV-REQ-001\n"
    b"  - id: LEV-REQ-006\n"
    b"  - id: LEV-REQ-009\n"
)


def _registry_bytes(
    *,
    owners: tuple[str, ...] = APPROVED_OWNERS,
    price_sources: tuple[str, ...] = APPROVED_PRICE_SOURCES,
    requirements_map: bytes = REQUIREMENTS_MAP,
) -> bytes:
    def digest(values: tuple[str, ...]) -> str:
        canonical = json.dumps(
            sorted(values), ensure_ascii=True, separators=(",", ":")
        ).encode("ascii")
        return hashlib.sha256(canonical).hexdigest()

    document = {
        "schema_version": 1,
        "owners": list(owners),
        "owner_snapshot_id": digest(owners),
        "price_sources": list(price_sources),
        "price_source_snapshot_id": digest(price_sources),
        "requirements_map_sha256": hashlib.sha256(requirements_map).hexdigest(),
    }
    return json.dumps(document, ensure_ascii=True, separators=(",", ":")).encode("ascii")


def _registries(
    *,
    owners: tuple[str, ...] = APPROVED_OWNERS,
    price_sources: tuple[str, ...] = APPROVED_PRICE_SOURCES,
    requirements_map: bytes = REQUIREMENTS_MAP,
) -> ResourceIntentRegistries:
    return ResourceIntentRegistries(
        _registry_bytes(
            owners=owners,
            price_sources=price_sources,
            requirements_map=requirements_map,
        ),
        requirements_map,
    )


def _validate(manifest: object):
    return validate_resource_intent(manifest, today=TODAY, registries=_registries())


def _resource(
    env: str, provider: str, kind: str, name: str, alias_provider: str
) -> dict[str, object]:
    body: dict[str, object] = {
        "provider": provider,
        "kind": kind,
        "name": name,
        "purpose": "licensing",
        "requirements": ["LEV-REQ-001" if kind == "worker" else "LEV-REQ-009"],
        "owner": "platform-team",
        "approver": "release-manager",
        "region": "us-central",
        "jurisdiction": "US",
        "data_classification": "confidential",
        "tier": "minimum",
        "minimum_tier": True,
        "cost": {
            "currency": "USD",
            "monthly_cap": "10.00",
            "price_source": "https://example.com/pricing",
            "retrieved_on": TODAY.isoformat(),
        },
        "credential_aliases": [
            "vault://leviathan-ai/"
            f"{'live' if env == 'live' else 'development'}/{alias_provider}/"
            f"{name.upper().replace('-', '_')}"
        ],
    }
    if provider == "neon":
        body["neon"] = {
            "project": f"project-{env}",
            "branch": f"branch-{env}",
            "role": "licensing-reader",
        }
    else:
        body["binding"] = f"binding-{name}"
    return body


def _manifest() -> dict[str, object]:
    environments: dict[str, object] = {}
    for env in ("development", "staging", "live"):
        environments[env] = {
            "identity": f"leviathan-{env}",
            "resources": [
                _resource(env, "cloudflare", "worker", f"licensing-worker-{env}", "cloudflare"),
                _resource(env, "neon", "database", f"licensing-db-{env}", "neon"),
            ],
        }
    return {"schema_version": 1, "project": "leviathan-ai", "environments": environments}


def _resource_at(manifest: dict[str, object], env: str, index: int = 0) -> dict[str, object]:
    environments = manifest["environments"]
    assert isinstance(environments, dict)
    environment = environments[env]
    assert isinstance(environment, dict)
    resources = environment["resources"]
    assert isinstance(resources, list)
    resource = resources[index]
    assert isinstance(resource, dict)
    return resource


def test_valid_three_env_manifest_and_staging_alias_scope() -> None:
    manifest = _manifest()
    result = _validate(manifest)

    assert result.exit_code == 0
    assert result.errors == ()
    assert result.blockers == ()
    assert "staging cloudflare" not in result.report  # report uses opaque resource identifiers
    staging_alias = _resource_at(manifest, "staging")["credential_aliases"]
    assert staging_alias == ["vault://leviathan-ai/development/cloudflare/LICENSING_WORKER_STAGING"]


def test_each_environment_requires_licensing_worker_and_neon_intent() -> None:
    for env, kind in (("development", "worker"), ("staging", "database"), ("live", "worker")):
        manifest = _manifest()
        environments = manifest["environments"]
        assert isinstance(environments, dict)
        environment = environments[env]
        assert isinstance(environment, dict)
        resources = environment["resources"]
        assert isinstance(resources, list)
        environment["resources"] = [resource for resource in resources if resource["kind"] != kind]

        result = _validate(manifest)

        assert result.exit_code == 2
        expected = f"{env}: LICENSING_{kind.upper()}_MISSING"
        assert expected in result.blockers


def test_missing_or_stale_price_evidence_is_a_blocker_not_a_pass() -> None:
    missing = _manifest()
    _resource_at(missing, "development")["cost"] = {
        "currency": "USD",
        "monthly_cap": "10.00",
    }
    missing_result = _validate(missing)
    assert missing_result.exit_code == 2
    assert any(code.endswith("PRICE_EVIDENCE_MISSING") for code in missing_result.blockers)

    stale = _manifest()
    _resource_at(stale, "development")["cost"]["retrieved_on"] = "2026-08-30"
    stale_result = _validate(stale)
    assert stale_result.exit_code == 2
    assert any(code.endswith("PRICE_EVIDENCE_STALE") for code in stale_result.blockers)


def test_missing_registry_and_nonmember_owner_or_price_source_are_blockers() -> None:
    manifest = _manifest()
    missing = validate_resource_intent(manifest, today=TODAY)
    assert missing.exit_code == 2
    assert "REGISTRY_MISSING" in missing.blockers

    unapproved_owner = _manifest()
    owner_value = "opaque-owner-7f6c9d20a34e4b37"
    _resource_at(unapproved_owner, "development")["owner"] = owner_value
    owner_result = validate_resource_intent(
        unapproved_owner, today=TODAY, registries=_registries()
    )
    assert owner_result.exit_code == 2
    assert any(code.endswith("OWNER_UNAPPROVED") for code in owner_result.blockers)
    assert owner_result.errors == ()
    assert owner_value not in owner_result.report

    unapproved_price = _manifest()
    price_url = "https://example.com/catalog/opaque-ref-9f84c04f1f4c4b37/pricing"
    _resource_at(unapproved_price, "development")["cost"]["price_source"] = price_url
    price_result = validate_resource_intent(
        unapproved_price, today=TODAY, registries=_registries()
    )
    assert price_result.exit_code == 2
    assert any(code.endswith("PRICE_SOURCE_UNAPPROVED") for code in price_result.blockers)
    assert price_url not in price_result.report


@pytest.mark.parametrize(
    "digest_field",
    ["owner_snapshot_id", "price_source_snapshot_id", "requirements_map_sha256"],
)
def test_registry_snapshot_hash_mismatch_is_rejected_safely(
    tmp_path: Path, digest_field: str
) -> None:
    registry_document = json.loads(_registry_bytes())
    registry_document[digest_field] = "f" * 64
    registry_path = tmp_path / "registries.json"
    requirements_path = tmp_path / "requirements.yaml"
    registry_path.write_text(json.dumps(registry_document), encoding="utf-8")
    requirements_path.write_bytes(REQUIREMENTS_MAP)

    with pytest.raises(ValueError, match="REGISTRY_INVALID"):
        load_registries(registry_path, requirements_path)


def test_credential_like_owner_is_rejected_by_membership_not_value_pattern() -> None:
    manifest = _manifest()
    opaque_owner = "svc-owner-4d18a9b7c2035f6e"
    _resource_at(manifest, "development")["owner"] = opaque_owner

    result = validate_resource_intent(manifest, today=TODAY, registries=_registries())

    assert result.exit_code == 2
    assert result.errors == ()
    assert any(code.endswith("OWNER_UNAPPROVED") for code in result.blockers)
    assert opaque_owner not in result.report


def test_https_price_path_requires_exact_approved_registry_entry() -> None:
    url = "https://example.com/catalog/opaque-ref-9f84c04f1f4c4b37/pricing"
    unapproved = _manifest()
    _resource_at(unapproved, "development")["cost"]["price_source"] = url
    blocked = validate_resource_intent(unapproved, today=TODAY, registries=_registries())
    assert blocked.exit_code == 2
    assert any(code.endswith("PRICE_SOURCE_UNAPPROVED") for code in blocked.blockers)

    approved = validate_resource_intent(
        unapproved,
        today=TODAY,
        registries=_registries(price_sources=(*APPROVED_PRICE_SOURCES, url)),
    )
    assert approved.exit_code == 0
    assert approved.blockers == ()


def test_malformed_price_port_is_safe_cli_error_without_traceback_or_token(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    manifest = _manifest()
    token = "SYNTHETIC_SECRET_ONLY"
    _resource_at(manifest, "development")["cost"]["price_source"] = (
        f"https://example.com:{token}/pricing"
    )
    manifest_path = tmp_path / "manifest.yaml"
    registry_path = tmp_path / "registries.json"
    requirements_path = tmp_path / "requirements.yaml"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    registry_path.write_bytes(_registry_bytes())
    requirements_path.write_bytes(REQUIREMENTS_MAP)

    exit_code = main(
        [
            str(manifest_path),
            "--registries",
            str(registry_path),
            "--requirements-map",
            str(requirements_path),
            "--today",
            TODAY.isoformat(),
            "--historical",
        ]
    )
    output = capsys.readouterr().out

    assert exit_code == 1
    assert "PRICE_SOURCE_INVALID" in output
    assert token not in output
    assert "Traceback" not in output


def test_historical_today_requires_flag_and_never_returns_ready_exit_code(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    manifest = _manifest()
    environments = manifest["environments"]
    assert isinstance(environments, dict)
    for environment in environments.values():
        assert isinstance(environment, dict)
        resources = environment["resources"]
        assert isinstance(resources, list)
        for resource in resources:
            resource["cost"]["retrieved_on"] = "2019-12-20"

    manifest_path = tmp_path / "historical-manifest.yaml"
    registry_path = tmp_path / "registries.json"
    requirements_path = tmp_path / "requirements.yaml"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    registry_path.write_bytes(_registry_bytes())
    requirements_path.write_bytes(REQUIREMENTS_MAP)
    args = [
        str(manifest_path),
        "--registries",
        str(registry_path),
        "--requirements-map",
        str(requirements_path),
        "--today",
        "2020-01-01",
    ]

    missing_flag_exit = main(args)
    missing_flag_output = capsys.readouterr().out
    assert missing_flag_exit != 0
    assert "HISTORICAL" in missing_flag_output

    historical_exit = main([*args, "--historical"])
    historical_output = capsys.readouterr().out
    assert historical_exit != 0
    assert "HISTORICAL" in historical_output


def test_syntax_valid_requirement_absent_from_snapshot_is_a_blocker() -> None:
    manifest = _manifest()
    _resource_at(manifest, "development")["requirements"] = ["LEV-REQ-999"]

    result = validate_resource_intent(manifest, today=TODAY, registries=_registries())

    assert result.exit_code == 2
    assert any(code.endswith("REQUIREMENT_UNMAPPED") for code in result.blockers)
    assert not any(code.endswith("REQUIREMENT_INVALID") for code in result.errors)


def test_price_evidence_age_boundary_is_inclusive_at_thirty_days() -> None:
    at_boundary = _manifest()
    _resource_at(at_boundary, "development")["cost"]["retrieved_on"] = "2026-08-31"
    boundary_result = _validate(at_boundary)
    assert boundary_result.exit_code == 0

    future = _manifest()
    _resource_at(future, "development")["cost"]["retrieved_on"] = "2026-10-01"
    future_result = _validate(future)
    assert future_result.exit_code == 2
    assert any(code.endswith("PRICE_EVIDENCE_STALE") for code in future_result.blockers)


def test_only_neon_and_cloudflare_resource_kinds_are_accepted() -> None:
    manifest = _manifest()
    resource = _resource_at(manifest, "development")
    resource["provider"] = "aws"
    resource["kind"] = "database"

    result = _validate(manifest)

    assert result.exit_code == 1
    assert any("VENDOR_KIND_INVALID" in code for code in result.errors)


def test_factory_admin_and_literal_secret_are_rejected_and_redacted() -> None:
    manifest = _manifest()
    _resource_at(manifest, "development")["credential_aliases"] = [
        "vault://factory-admin/cloudflare/TOKEN"
    ]
    _resource_at(manifest, "live", 1)["purpose"] = SECRET

    result = _validate(manifest)

    assert result.exit_code == 1
    assert result.errors
    rendered = "\n".join((result.report, *result.errors, *result.blockers))
    assert SECRET not in rendered
    assert "factory-admin" not in rendered


def test_live_alias_is_forbidden_outside_live_and_cross_environment_alias_reuse_is_invalid() -> (
    None
):
    wrong_scope = _manifest()
    _resource_at(wrong_scope, "development")["credential_aliases"] = [
        "vault://leviathan-ai/live/cloudflare/DEV_TOKEN"
    ]
    wrong_scope_result = _validate(wrong_scope)
    assert wrong_scope_result.exit_code == 1
    assert any("CREDENTIAL_SCOPE_INVALID" in code for code in wrong_scope_result.errors)

    reused = _manifest()
    _resource_at(reused, "staging")["credential_aliases"] = _resource_at(reused, "development")[
        "credential_aliases"
    ]
    reused_result = _validate(reused)
    assert reused_result.exit_code == 1
    assert any("CREDENTIAL" in code for code in reused_result.errors)


def test_destructive_r2_retention_is_not_ready() -> None:
    manifest = _manifest()
    r2 = _resource("development", "cloudflare", "r2", "archive-dev", "cloudflare-r2")
    r2["purpose"] = "cold_archive"
    r2["retention"] = {
        "days": 2557,
        "lock_intent": "required",
        "legal_hold": True,
        "delete_on_destroy": True,
    }
    environment = manifest["environments"]["development"]
    environment["resources"].append(r2)

    result = _validate(manifest)

    assert result.exit_code == 2
    assert any("RETENTION_POLICY_BLOCKED" in code for code in result.blockers)


def test_report_is_deterministic_redacted_and_has_the_declared_exit_code() -> None:
    manifest = _manifest()
    first = _validate(manifest)
    second = _validate(copy.deepcopy(manifest))

    assert first.exit_code == second.exit_code == 0
    assert first.report == second.report
    assert SECRET not in first.report


def test_validation_does_not_attempt_network_access(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden_connect(*args: object, **kwargs: object) -> None:
        raise AssertionError("resource preflight attempted a network connection")

    monkeypatch.setattr(socket.socket, "connect", forbidden_connect)
    result = _validate(_manifest())
    assert result.exit_code == 0
