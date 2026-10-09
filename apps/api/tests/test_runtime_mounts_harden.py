from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import FastAPI, Request
from fastapi.responses import Response

from leviathan_api.deployment_config import (
    LEDGER_INTEGRITY_SERVICE_ID,
    PROJECT_ID,
    DeploymentConfigCode,
    DeploymentConfigError,
    DeploymentDiagnosticCode,
    load_deployment_config,
)
from leviathan_api.main import runtime_mount_gate
from leviathan_api.runtime_mounts import RuntimeMountStatusV1, _startup_reason_code
from leviathan_core.deployment_secret_refs import (
    issue_allowed_secret_bindings,
    issue_provider_alias_map,
)

_REFERENCE = "vault://leviathan-ai/development/synthetic-provider/LEDGER_INTEGRITY_KEY"


@pytest.mark.parametrize(
    "status",
    [
        None,
        object(),
        RuntimeMountStatusV1("SECRET_CANARY", None),
        RuntimeMountStatusV1(None, "SECRET_CANARY"),
    ],
)
@pytest.mark.asyncio
async def test_runtime_gate_fails_closed_for_missing_or_corrupt_status(status: object) -> None:
    app = FastAPI()
    app.state.runtime_mount_status = status
    request = Request(
        {
            "type": "http",
            "app": app,
            "method": "GET",
            "path": "/v1/omega/tasks",
            "headers": [],
            "query_string": b"",
        }
    )

    async def next_response(_request: Request) -> Response:
        return Response("unexpected")

    response = await runtime_mount_gate(request, next_response)
    assert response.status_code == 503
    assert response.headers["cache-control"] == "no-store"
    assert b"RUNTIME_NOT_CONFIGURED" in response.body
    assert b"SECRET_CANARY" not in response.body


def test_runtime_reason_for_unresolvable_vault_key_is_closed_code() -> None:
    assert _startup_reason_code(ValueError("KEY_REF_UNRESOLVABLE")) == "KEY_UNRESOLVABLE"


def test_config_rejects_equal_store_paths_with_path_collision_diagnostic(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "deployment.toml"
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    config_path.write_text(
        "\n".join(
            (
                "[project]",
                f'project_id = "{PROJECT_ID}"',
                'environment = "PAPER"',
                "[secrets]",
                f'ledger_integrity_key_ref = "{_REFERENCE}"',
                "[omega]",
                'due_store_path = "shared.sqlite3"',
                "max_heartbeat_age_ns = 2000000000",
                "[mcp_control]",
                'audit_store_path = "shared.sqlite3"',
            )
        ),
        encoding="utf-8",
    )
    bindings = issue_allowed_secret_bindings(
        ((LEDGER_INTEGRITY_SERVICE_ID, "development", _REFERENCE),)
    )
    aliases = issue_provider_alias_map(())

    with pytest.raises(DeploymentConfigError) as raised:
        load_deployment_config(
            config_path,
            app_data_dir=data_dir,
            allowed_bindings=bindings,
            provider_aliases=aliases,
        )
    assert raised.value.code is DeploymentConfigCode.STORE_PATH_INVALID
    assert raised.value.diagnostic_code is DeploymentDiagnosticCode.PATHS_COLLIDE
    assert str(raised.value) == "STORE_PATH_INVALID"
