"""Independent black-box acceptance for the composed licensing Worker."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import uuid
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
FIXTURES = PACKAGE / "tests" / "fixtures" / "compose"
PROBE_TEMPLATE = FIXTURES / "worker_compose_probe.template.ts.txt"
EXPECTED_VITEST_CASES = 14


def _run_vitest_probe() -> str:
    node = shutil.which("node")
    assert node is not None, "Node is required to execute the pinned Worker acceptance probe"
    package_json = json.loads((PACKAGE / "package.json").read_text(encoding="utf-8"))
    assert package_json["devDependencies"]["vitest"] == "4.1.11"
    assert (PACKAGE / "node_modules" / "vitest" / "vitest.mjs").is_file()
    assert PROBE_TEMPLATE.is_file()

    generated_dir = PACKAGE / f"compose_acceptance_{uuid.uuid4().hex}"
    generated_dir.mkdir()
    generated = generated_dir / "worker_compose_acceptance.generated.test.ts"
    generated.write_text(PROBE_TEMPLATE.read_text(encoding="utf-8"), encoding="utf-8")
    config = generated_dir / "vitest.acceptance.config.ts"
    include = json.dumps(generated.relative_to(PACKAGE).as_posix())
    config.write_text(
        f'import {{ defineConfig }} from "vitest/config";\n'
        f"export default defineConfig({{ root: {json.dumps(str(PACKAGE))}, "
        f'test: {{ include: [{include}], environment: "node" }} }});\n',
        encoding="utf-8",
    )
    try:
        result = subprocess.run(
            [node, "node_modules/vitest/vitest.mjs", "run", "--config", str(config)],
            cwd=PACKAGE,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=300,
            check=False,
        )
    finally:
        shutil.rmtree(generated_dir, ignore_errors=True)

    output = f"{result.stdout}\n{result.stderr}"
    assert result.returncode == 0, output
    summary = re.search(r"Tests\s+(\d+) passed(?:\s+\((\d+)\))?", output)
    assert summary is not None, output
    passed = int(summary.group(1))
    total = int(summary.group(2) or summary.group(1))
    assert EXPECTED_VITEST_CASES > 0, "Set the frozen acceptance probe case count before release"
    assert (passed, total) == (EXPECTED_VITEST_CASES, EXPECTED_VITEST_CASES), output
    return output


def test_composed_worker_acceptance_probe() -> None:
    """Run frozen black-box route, adapter, crypto and configuration probes."""
    _run_vitest_probe()


def test_licensing_source_contains_no_trial_token() -> None:
    """Enforce the accepted source-only no-trial requirement with ripgrep."""
    rg = shutil.which("rg")
    assert rg is not None, "ripgrep is required for the source no-trial gate"
    source = PACKAGE / "src"
    result = subprocess.run(
        [rg, "-i", "trial", str(source)],
        cwd=PACKAGE,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=False,
    )
    assert result.returncode == 1 and not result.stdout.strip(), result.stdout + result.stderr


def test_migration_003_materializes_all_six_immutable_system_roles_and_seat_audit_schema() -> None:
    migration = (PACKAGE / "migrations" / "003_signup_admin.sql").read_text(encoding="utf-8")
    lowered = migration.lower()
    for role_id in ("owner", "admin", "billing", "auditor", "readonly", "service"):
        assert re.search(rf"\('{role_id}',\s*null,\s*true,", lowered), role_id
    assert "create table if not exists licensing_seats" in lowered
    for column in (
        "org_id text not null",
        "subscription_id text not null",
        "seat_id text not null",
        "user_id text not null",
        "role_id text not null",
        "status text not null",
        "version bigint not null",
        "assigned_at_utc_ns bigint not null",
        "updated_at_utc_ns bigint not null",
        "audit_event_id text not null",
    ):
        assert column in lowered, column
    assert "create table if not exists licensing_admin_audit" in lowered
    for column in (
        "audit_event_id text primary key",
        "actor_user_id text not null",
        "target_id text not null",
        "action text not null",
        "before_role_id text",
        "after_role_id text not null",
        "before_status text",
        "after_status text not null",
        "occurred_at_utc_ns bigint not null",
    ):
        assert column in lowered, column
    assert "create trigger licensing_roles_system_seed_immutable" in lowered
    assert "before update or delete on licensing_roles" in lowered
    assert "old.immutable=true and old.org_id is null" in lowered
    assert "create trigger licensing_admin_audit_append_only" in lowered
    assert "before update or delete on licensing_admin_audit" in lowered
    assert "create or replace function licensing_reject_append_only_mutation" in lowered


def test_migrations_001_and_002_remain_byte_identical() -> None:
    expected = {
        "001_subscription.sql": "59A63754BE44670496DFC48178404B332F7CC97DD890D42417265BB19703313C",
        "002_no_trial.sql": "5960EDA55E63D0A75D2CA5394C89CE855EF4B69D34AD78428F0D52DF413A7EE6",
    }
    for name, sha256 in expected.items():
        actual = hashlib.sha256((PACKAGE / "migrations" / name).read_bytes()).hexdigest().upper()
        assert actual == sha256, f"{name} changed: {actual}"


def test_migration_runner_cli_never_emits_database_url() -> None:
    source = (PACKAGE / "scripts" / "apply_migrations.mjs").read_text(encoding="utf-8")
    assert "process.env.DATABASE_URL" in source
    assert 'process.stdout.write("Migrations applied.\\n")' in source
    assert 'process.stderr.write("Migration failed.\\n")' in source
    assert "console.log(connectionString" not in source
    assert "process.stdout.write(connectionString" not in source
