"""Independent acceptance for CHAT-TOOLS mounting and trust boundaries."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
from collections import Counter
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from fastapi.testclient import TestClient

from leviathan_api.chat.tool_bridge import (
    AppRouteOutcomeV1,
    ChatToolAuditEventV1,
    ChatToolBridgeV1,
)
from leviathan_api.chat_tools_runtime import (
    CHAT_TOOL_APP_ROUTE_ALLOWLIST_V1,
    CHAT_TOOL_EFFECT_ROUTE_ALLOWLIST_V1,
    AppRoutePortAdapterV1,
)
from leviathan_api.main import create_app
from leviathan_api.wave35_mounts import Wave35MountDependenciesV1
from leviathan_core.agent_council.model_registry import ModelRegistryV1
from leviathan_core.security.principal_verifier import (
    PrincipalVerifier,
    RSAPublicKeyV1,
    TrustedIssuerV1,
    VerifiedPrincipalV1,
)

_ROOT = Path(__file__).resolve().parents[3]
_RSA = json.loads(
    (_ROOT / "packages/leviathan-core/tests/security/fixtures/sec003_synthetic_rsa.json").read_text(
        encoding="utf-8"
    )
)
_MODULUS = int(_RSA["modulus_hex"], 16)
_EXPONENT = int(_RSA["public_exponent_hex"], 16)
_PRIVATE_EXPONENT = int(_RSA["private_exponent_hex"], 16)
_ISSUER = "chat-acceptance-idp"
_AUDIENCE = "chat-acceptance-api"
_ORG = "org-chat-acceptance"
_PROJECT = "project-chat-acceptance"
_ENVIRONMENT = "paper"
_KID = "chat-acceptance-key"
_ACCOUNT = "account-chat-acceptance"
_NOW = datetime(2026, 10, 7, 18, 0, tzinfo=UTC)
_NOW_SECONDS = int(_NOW.timestamp())

_TOOL_ENDPOINTS = {
    ("/api/chat/tools/registry", "GET"),
    ("/api/chat/tools/plan", "POST"),
    ("/api/chat/tools/confirm", "POST"),
    ("/api/chat/tools/read", "POST"),
}


class _KeySet:
    def get_key(self, issuer: str, kid: str) -> RSAPublicKeyV1 | None:
        if (issuer, kid) != (_ISSUER, _KID):
            return None
        return RSAPublicKeyV1(_MODULUS, _EXPONENT)


class _Revocations:
    def is_revoked(self, _issuer: str, _jti: str) -> bool:
        return False


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _segment(value: object) -> str:
    return _b64url(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def _signature(message: bytes) -> bytes:
    digest_info = (
        bytes.fromhex("3031300d060960864801650304020105000420") + hashlib.sha256(message).digest()
    )
    width = (_MODULUS.bit_length() + 7) // 8
    encoded = b"\x00\x01" + b"\xff" * (width - len(digest_info) - 3) + b"\x00" + digest_info
    return pow(int.from_bytes(encoded, "big"), _PRIVATE_EXPONENT, _MODULUS).to_bytes(width, "big")


def _verified_principal() -> VerifiedPrincipalV1:
    header = _segment({"alg": "RS256", "kid": _KID, "typ": "JWT"})
    claims = {
        "iss": _ISSUER,
        "aud": _AUDIENCE,
        "org": _ORG,
        "sub": "synthetic-chat-operator",
        "role": "Operator",
        "scope": ["mcp:read", "mcp:write"],
        "env": _ENVIRONMENT,
        "portfolio": _ACCOUNT,
        "jti": "synthetic-chat-jti",
        "iat": _NOW_SECONDS,
        "nbf": _NOW_SECONDS,
        "exp": _NOW_SECONDS + 300,
    }
    signing_input = f"{header}.{_segment(claims)}".encode("ascii")
    token = f"{signing_input.decode('ascii')}.{_b64url(_signature(signing_input))}"
    verifier = PrincipalVerifier(
        trusted_issuer=TrustedIssuerV1(
            issuer=_ISSUER,
            audience=_AUDIENCE,
            org_id=_ORG,
            project_id=_PROJECT,
            env=_ENVIRONMENT,
        ),
        key_set=_KeySet(),
        revocations=_Revocations(),
        clock=lambda: _NOW,
    )
    return verifier.verify(token)


class _Audit:
    def __init__(self) -> None:
        self.events: list[ChatToolAuditEventV1] = []

    async def append(self, event: ChatToolAuditEventV1) -> None:
        self.events.append(event)


class _AppRoutes:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.result = AppRouteOutcomeV1(
            status_code=202,
            allowed=True,
            effect_performed=True,
            output={"synthetic": True},
        )

    async def invoke(
        self,
        _principal: VerifiedPrincipalV1,
        *,
        route_id: str,
        arguments: Mapping[str, object],
        idempotency_key: str,
    ) -> AppRouteOutcomeV1:
        del arguments, idempotency_key
        self.calls.append(route_id)
        return self.result


def _bridge() -> tuple[ChatToolBridgeV1, _Audit]:
    audit = _Audit()
    return ChatToolBridgeV1(
        mcp=None,
        audit=audit,
        now_ns=lambda: _NOW_SECONDS * 1_000_000_000,
    ), audit


def test_create_app_mounts_each_documented_chat_tools_operation_once() -> None:
    app = create_app()
    with TestClient(app):
        operations = Counter(
            (path, method.upper())
            for path, methods in app.openapi()["paths"].items()
            for method in methods
            if method.lower() in {"get", "post"}
        )
    assert set(operations) >= _TOOL_ENDPOINTS
    assert all(operations[operation] == 1 for operation in _TOOL_ENDPOINTS)


def test_missing_bridge_fails_closed_on_every_chat_tools_endpoint(tmp_path: Path) -> None:
    app = create_app(
        wave35_mount_dependencies=Wave35MountDependenciesV1(
            app_data_dir=tmp_path,
            model_registry=ModelRegistryV1(version="v1", entries=()),
        )
    )
    with TestClient(app) as client:
        responses = [
            client.get("/api/chat/tools/registry"),
            client.post("/api/chat/tools/plan", json={}),
            client.post("/api/chat/tools/confirm", json={}),
            client.post("/api/chat/tools/read", json={}),
        ]
    assert [response.status_code for response in responses] == [503] * 4
    assert [response.json() for response in responses] == [
        {"code": "CHAT_TOOLS_NOT_CONFIGURED"}
    ] * 4


def test_bridge_without_sec003_resolver_and_unsealed_principal_fail_closed(
    tmp_path: Path,
) -> None:
    bridge, _audit = _bridge()
    app_without_resolver = create_app(
        wave35_mount_dependencies=Wave35MountDependenciesV1(
            app_data_dir=tmp_path / "no-resolver",
            chat_tool_bridge=bridge,
            model_registry=ModelRegistryV1(version="v1", entries=()),
        )
    )
    with TestClient(app_without_resolver) as client:
        unavailable = [
            client.get("/api/chat/tools/registry"),
            client.post("/api/chat/tools/plan", json={}),
            client.post("/api/chat/tools/confirm", json={}),
            client.post("/api/chat/tools/read", json={}),
        ]
    assert [response.status_code for response in unavailable] == [503] * 4
    assert [response.json() for response in unavailable] == [
        {"detail": {"version": "1", "code": "AUTH_UNAVAILABLE"}}
    ] * 4

    bridge, _audit = _bridge()
    app_unsealed = create_app(
        wave35_mount_dependencies=Wave35MountDependenciesV1(
            app_data_dir=tmp_path / "unsealed",
            chat_tool_bridge=bridge,
            model_registry=ModelRegistryV1(version="v1", entries=()),
            verified_principal_resolver=lambda _request: cast(VerifiedPrincipalV1, object()),
        )
    )
    with TestClient(app_unsealed) as client:
        unauthenticated = client.get("/api/chat/tools/registry")
    assert unauthenticated.status_code == 401
    assert unauthenticated.json() == {"detail": {"version": "1", "code": "UNAUTHENTICATED"}}


def test_verified_read_registry_and_app_route_guard_preserve_only_allowed_paper_result(
    tmp_path: Path,
) -> None:
    bridge, audit = _bridge()
    principal = _verified_principal()
    app = create_app(
        wave35_mount_dependencies=Wave35MountDependenciesV1(
            app_data_dir=tmp_path / "configured",
            chat_tool_bridge=bridge,
            model_registry=ModelRegistryV1(version="v1", entries=()),
            verified_principal_resolver=lambda _request: principal,
        )
    )
    with TestClient(app) as client:
        registry = client.get("/api/chat/tools/registry")
    assert registry.status_code == 200
    assert registry.json()["version"] == "1"
    assert registry.json()["entries"]
    assert len(audit.events) == 1

    legacy_paper_effect_routes = frozenset(
        {
            "orders.create_then_submit",
            "orders.activation.activate",
            "orders.activation.revoke",
            "paper.mass_cancel.v1",
        }
    )
    assert legacy_paper_effect_routes <= CHAT_TOOL_EFFECT_ROUTE_ALLOWLIST_V1
    registry_app_routes = {
        entry.route for entry in bridge.registry.entries if entry.route_kind == "app_route"
    }
    documented_route_exemptions: frozenset[str] = frozenset()
    assert registry_app_routes <= (CHAT_TOOL_APP_ROUTE_ALLOWLIST_V1 | documented_route_exemptions)
    assert (registry_app_routes | documented_route_exemptions) >= CHAT_TOOL_APP_ROUTE_ALLOWLIST_V1
    routes = _AppRoutes()
    adapter = AppRoutePortAdapterV1(routes)
    allowed = asyncio.run(
        adapter.invoke(
            principal,
            route_id="orders.create_then_submit",
            arguments={"environment": "paper"},
            idempotency_key="synthetic-idempotency-0001",
        )
    )
    assert allowed is routes.result
    assert allowed.status_code == 202
    assert allowed.effect_performed is True
    assert routes.calls == ["orders.create_then_submit"]

    for denied_route in (
        "live-activation.enable",
        "credentials.write",
        "halt.release",
        "admin.manage",
        "licensing.change",
    ):
        denied = asyncio.run(
            adapter.invoke(
                principal,
                route_id=denied_route,
                arguments={"environment": "paper"},
                idempotency_key="synthetic-idempotency-0002",
            )
        )
        assert denied.status_code == 403
        assert denied.allowed is False
        assert denied.effect_performed is False
        assert denied.reason_codes == ("CHAT_ROUTE_DENIED",)
    paper_only = asyncio.run(
        adapter.invoke(
            principal,
            route_id="orders.create_then_submit",
            arguments={"environment": "live"},
            idempotency_key="synthetic-idempotency-0003",
        )
    )
    assert paper_only.status_code == 403
    assert paper_only.reason_codes == ("PAPER_ONLY",)

    unlisted = asyncio.run(
        adapter.invoke(
            principal,
            route_id="unlisted.route",
            arguments={"environment": "paper"},
            idempotency_key="synthetic-idempotency-unlisted",
        )
    )
    assert unlisted.status_code == 403
    assert unlisted.allowed is False
    assert unlisted.effect_performed is False
    assert unlisted.reason_codes == ("CHAT_ROUTE_DENIED",)
    assert routes.calls == ["orders.create_then_submit"]
