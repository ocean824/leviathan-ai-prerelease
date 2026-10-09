"""Production composition tests with synthetic credentials and fake transports."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpcore
import httpx
import pytest
from leviathan_store.preferences import PreferencesError, UserPreferencesV1
from pydantic import SecretStr

from leviathan_api.chat.models import (
    ChatApiShapeV1,
    ChatErrorCodeV1,
    ChatMessageV1,
    ChatRequestV1,
    ChatRoleV1,
    ChatServiceError,
)
from leviathan_api.chat.port import ProviderCallV1, ProviderHttpResponseV1
from leviathan_api.chat_compose import (
    ChatCompositionError,
    HttpxChatTransportV1,
    _PinnedNetworkBackend,
    compose_chat_service,
    load_model_catalog,
)
from leviathan_core.security.authz_models import (
    _VERIFIER_MARKER,
    PrincipalV1,
    TrustedPrincipalAdapterV1,
)
from leviathan_vault.app_credentials import InMemoryCredentialStore

_ROOT = Path(__file__).resolve().parents[3]
_CATALOG = _ROOT / "infra" / "chat" / "model-catalog-v1.json"
_NOW_NS = 1_800_000_000_000_000_000


class _Preferences:
    def __init__(self) -> None:
        self.documents: dict[tuple[str, str], UserPreferencesV1] = {}

    def get(self, user_scope: str, namespace: str) -> UserPreferencesV1 | None:
        return self.documents.get((user_scope, namespace))

    def put(
        self,
        user_scope: str,
        namespace: str,
        document: dict[str, object],
        *,
        if_match: str,
    ) -> UserPreferencesV1:
        key = (user_scope, namespace)
        current = self.documents.get(key)
        if (current is None and if_match != "*") or (
            current is not None and if_match != str(current.revision)
        ):
            raise PreferencesError("REVISION_CONFLICT", current)
        record = UserPreferencesV1(
            schema_version=1,
            user_scope=user_scope,
            namespace=namespace,
            document=dict(document),
            updated_at_ns=_NOW_NS,
            revision=1 if current is None else current.revision + 1,
        )
        self.documents[key] = record
        return record

    def delete(self, user_scope: str, namespace: str) -> None:
        self.documents.pop((user_scope, namespace), None)


class _Transport:
    def __init__(self) -> None:
        self.calls: list[ProviderCallV1] = []

    async def complete(self, call: ProviderCallV1) -> ProviderHttpResponseV1:
        self.calls.append(call)
        return ProviderHttpResponseV1(
            status_code=200,
            body=json.dumps(
                {
                    "content": [{"type": "text", "text": "synthetic answer"}],
                    "usage": {"input_tokens": 2, "output_tokens": 2},
                    "stop_reason": "end_turn",
                }
            ).encode(),
        )

    def stream(self, _call: ProviderCallV1) -> AsyncIterator[bytes]:
        async def no_stream() -> AsyncIterator[bytes]:
            if False:
                yield b""
            raise AssertionError("stream not expected in this test")

        return no_stream()


def _principal():
    claims = PrincipalV1(
        principal_id="chat.operator",
        project_id="leviathan-ai",
        roles=("operator",),
        env="development",
    )
    return TrustedPrincipalAdapterV1.from_verified_claims(claims, verifier_marker=_VERIFIER_MARKER)


def _credentials() -> InMemoryCredentialStore:
    store = InMemoryCredentialStore()
    store.put_profile(
        "ANTHROPIC",
        "PAPER",
        "default",
        {"api_key": SecretStr("synthetic-provider-key")},
    )
    return store


def test_shipped_catalog_has_requested_models_and_compatible_template() -> None:
    registry = load_model_catalog(_CATALOG, None)
    aliases = {entry.alias for entry in registry.entries}
    assert {
        "claude-fable-5-1",
        "claude-opus-5-5",
        "claude-sonnet-5-5",
        "claude-haiku-4-5-20251001",
        "gpt-6-astra",
        "gpt-6-1-sol",
        "gpt-6-luna",
        "compatible-user-model",
    } <= aliases
    compatible = next(item for item in registry.entries if item.alias == "compatible-user-model")
    assert compatible.credential_name == "OPENAI_COMPATIBLE_API_KEY"
    assert not compatible.approved and not compatible.available


def test_user_catalog_entry_replaces_matching_shipped_model(tmp_path: Path) -> None:
    default = json.loads(_CATALOG.read_text(encoding="utf-8"))
    override = next(
        entry for entry in default["entries"] if entry["alias"] == "claude-haiku-4-5-20251001"
    )
    override = dict(override)
    override["model_id"] = "claude-haiku-user-approved"
    user_path = tmp_path / "model-registry-v1.json"
    user_path.write_text(json.dumps({"version": "v1", "entries": [override]}), encoding="utf-8")

    registry = load_model_catalog(_CATALOG, user_path)
    matches = [entry for entry in registry.entries if entry.alias == override["alias"]]
    assert len(matches) == 1
    assert matches[0].model_id == "claude-haiku-user-approved"
    assert len(registry.entries) == len(default["entries"])


def test_invalid_catalog_fails_with_content_free_error(tmp_path: Path) -> None:
    invalid = tmp_path / "invalid.json"
    invalid.write_text('{"provider_key":"do-not-echo","entries":[]}', encoding="utf-8")
    with pytest.raises(ChatCompositionError) as caught:
        load_model_catalog(invalid, None)
    assert str(caught.value) == "MODEL_CATALOG_INVALID"
    assert "do-not-echo" not in repr(caught.value)


def test_models_bind_only_for_matching_credential_environment_and_profile(tmp_path: Path) -> None:
    store = _credentials()
    transport = _Transport()
    composed = compose_chat_service(
        app_data_dir=tmp_path,
        credential_store=store,
        profile_id="default",
        environment="PAPER",
        preferences_store=None,
        transport=transport,
        clock_ns=lambda: _NOW_NS,
        catalog_path=_CATALOG,
    )
    assert composed.bound_models == (
        "claude-fable-5-1",
        "claude-haiku-4-5-20251001",
        "claude-opus-5-5",
        "claude-sonnet-5-5",
    )
    assert not transport.calls

    wrong_profile = compose_chat_service(
        app_data_dir=tmp_path / "wrong-profile",
        credential_store=store,
        profile_id="another-profile",
        environment="PAPER",
        preferences_store=None,
        transport=transport,
        clock_ns=lambda: _NOW_NS,
        catalog_path=_CATALOG,
    )
    assert wrong_profile.bound_models == ()


def test_compatible_model_uses_injected_resolver_without_dns(tmp_path: Path) -> None:
    store = InMemoryCredentialStore()
    store.put_profile(
        "OPENAI_COMPATIBLE",
        "PAPER",
        "default",
        {
            "api_key": SecretStr("synthetic-compatible-key"),
            "base_url": "https://models.example.test",
            "display_label": "Synthetic compatible",
        },
    )
    defaults = json.loads(_CATALOG.read_text(encoding="utf-8"))
    template = next(
        item for item in defaults["entries"] if item["entry_id"] == "compatible.user-model-template"
    )
    user_entry = dict(template)
    user_entry.update(
        {
            "model_id": "synthetic-compatible-model",
            "registry_version": "v2",
            "approved": True,
            "available": True,
            "input_cost_per_million_tokens_usd": "1.00",
            "output_cost_per_million_tokens_usd": "2.00",
        }
    )
    user_registry = tmp_path / "chat" / "model-registry-v1.json"
    user_registry.parent.mkdir(parents=True)
    user_registry.write_text(
        json.dumps({"version": "v2", "entries": [user_entry]}), encoding="utf-8"
    )
    resolved: list[tuple[str, int]] = []

    def address_resolver(host: str, port: int) -> tuple[str, ...]:
        resolved.append((host, port))
        return ("8.8.8.8",)

    composed = compose_chat_service(
        app_data_dir=tmp_path,
        credential_store=store,
        profile_id="default",
        environment="PAPER",
        preferences_store=None,
        transport=_Transport(),
        clock_ns=lambda: _NOW_NS,
        catalog_path=_CATALOG,
        address_resolver=address_resolver,
    )
    assert composed.bound_models == ("compatible-user-model",)
    assert resolved == [("models.example.test", 443)]


@pytest.mark.parametrize("address", ["127.0.0.1", "10.0.0.2", "169.254.1.1"])
def test_compatible_public_host_rejects_non_global_pins(tmp_path: Path, address: str) -> None:
    store = InMemoryCredentialStore()
    store.put_profile(
        "OPENAI_COMPATIBLE",
        "PAPER",
        "default",
        {
            "api_key": SecretStr("synthetic-compatible-key"),
            "base_url": "https://models.example.test",
            "display_label": "Synthetic compatible",
        },
    )
    defaults = json.loads(_CATALOG.read_text(encoding="utf-8"))
    template = next(
        item for item in defaults["entries"] if item["entry_id"] == "compatible.user-model-template"
    )
    user_entry = dict(template)
    user_entry.update({"registry_version": "v2", "approved": True, "available": True})
    user_registry = tmp_path / "chat" / "model-registry-v1.json"
    user_registry.parent.mkdir(parents=True)
    user_registry.write_text(
        json.dumps({"version": "v2", "entries": [user_entry]}), encoding="utf-8"
    )
    composed = compose_chat_service(
        app_data_dir=tmp_path,
        credential_store=store,
        profile_id="default",
        environment="PAPER",
        preferences_store=None,
        transport=_Transport(),
        clock_ns=lambda: _NOW_NS,
        catalog_path=_CATALOG,
        address_resolver=lambda _host, _port: (address,),
    )
    assert composed.bound_models == ()


def test_secret_is_resolved_at_call_time_and_never_returned(tmp_path: Path) -> None:
    store = _credentials()
    resolve_calls = 0
    resolve = store.resolve

    def counted_resolve(provider: str, environment: str, profile_id: str) -> Any:
        nonlocal resolve_calls
        resolve_calls += 1
        return resolve(provider, environment, profile_id)

    store.resolve = counted_resolve  # type: ignore[method-assign]
    preferences = _Preferences()
    preferences.put(
        "chat.operator",
        "chat.disclosure",
        {"providers": {"claude": True}},
        if_match="*",
    )
    transport = _Transport()
    composed = compose_chat_service(
        app_data_dir=tmp_path,
        credential_store=store,
        profile_id="default",
        environment="PAPER",
        preferences_store=preferences,
        transport=transport,
        clock_ns=lambda: _NOW_NS,
        catalog_path=_CATALOG,
    )
    assert resolve_calls == 0
    result = asyncio.run(
        composed.service.complete(
            _principal(),
            ChatRequestV1(
                request_id="chat-request-1",
                model_alias="claude-sonnet-5-5",
                messages=(ChatMessageV1(role=ChatRoleV1.USER, content="hello"),),
                max_output_tokens=8,
                hosted_egress_disclosed=True,
            ),
        )
    )
    assert resolve_calls == 1
    assert transport.calls[0].credential.get_secret_value() == "synthetic-provider-key"
    assert "synthetic-provider-key" not in repr(result)
    assert result.record.cost_status == "available"
    assert preferences.get("chat.operator", "chat.policy") is not None


def test_daily_cap_above_hard_max_is_rejected_not_clamped(tmp_path: Path) -> None:
    preferences = _Preferences()
    preferences.put(
        "chat.operator",
        "chat.policy",
        {"daily_cost_cap_usd": "100.01"},
        if_match="*",
    )
    preferences.put(
        "chat.operator",
        "chat.disclosure",
        {"providers": {"claude": True}},
        if_match="*",
    )
    transport = _Transport()
    composed = compose_chat_service(
        app_data_dir=tmp_path,
        credential_store=_credentials(),
        profile_id="default",
        environment="PAPER",
        preferences_store=preferences,
        transport=transport,
        clock_ns=lambda: _NOW_NS,
        catalog_path=_CATALOG,
    )
    request = ChatRequestV1(
        request_id="over-cap-configuration",
        model_alias="claude-sonnet-5-5",
        messages=(ChatMessageV1(role=ChatRoleV1.USER, content="hello"),),
        max_output_tokens=8,
        hosted_egress_disclosed=True,
    )
    with pytest.raises(ChatServiceError) as caught:
        asyncio.run(composed.service.complete(_principal(), request))
    assert caught.value.code is ChatErrorCodeV1.POLICY_DENIED
    assert transport.calls == []


def test_httpx_transport_uses_mock_transport_without_network() -> None:
    seen: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, content=b'{"synthetic":"ok"}')

    call = ProviderCallV1(
        api_shape=ChatApiShapeV1.OPENAI_RESPONSES,
        endpoint="https://api.openai.com/v1/responses",
        pinned_addresses=(),
        model_id="gpt.synthetic",
        messages=(ChatMessageV1(role=ChatRoleV1.USER, content="hello"),),
        max_output_tokens=32,
        timeout_ms=2_000,
        credential=SecretStr("synthetic-httpx-key"),
        body_json='{"model":"gpt.synthetic","input":[]}',
    )
    transport = HttpxChatTransportV1(
        http_transport=httpx.MockTransport(handler),
        connect_timeout_s=1.0,
        read_timeout_s=1.0,
    )
    response = asyncio.run(transport.complete(call))
    assert response.status_code == 200
    assert response.body == b'{"synthetic":"ok"}'
    assert len(seen) == 1
    assert seen[0].headers["authorization"] == "Bearer synthetic-httpx-key"
    assert "hello" not in seen[0].content.decode()


def test_httpx_transport_streams_sse_with_mock_transport_without_network() -> None:
    seen: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            content=b'data: {"type":"response.completed"}\n\n',
        )

    call = ProviderCallV1(
        api_shape=ChatApiShapeV1.OPENAI_RESPONSES,
        endpoint="https://api.openai.com/v1/responses",
        pinned_addresses=(),
        model_id="gpt.synthetic",
        messages=(ChatMessageV1(role=ChatRoleV1.USER, content="hello"),),
        max_output_tokens=32,
        timeout_ms=2_000,
        credential=SecretStr("synthetic-stream-key"),
        body_json='{"model":"gpt.synthetic","input":[],"stream":true}',
    )
    transport = HttpxChatTransportV1(http_transport=httpx.MockTransport(handler))

    async def collect() -> list[bytes]:
        return [chunk async for chunk in transport.stream(call)]

    chunks = asyncio.run(collect())
    assert chunks == [b'data: {"type":"response.completed"}\n\n']
    assert len(seen) == 1


def test_compatible_httpx_backend_dials_only_pinned_address() -> None:
    seen: list[tuple[str, int]] = []

    class RecordingBackend(httpcore.AsyncMockBackend):
        async def connect_tcp(
            self,
            host: str,
            port: int,
            timeout: float | None = None,
            local_address: str | None = None,
            socket_options: Any = None,
        ) -> httpcore.AsyncNetworkStream:
            seen.append((host, port))
            return await super().connect_tcp(
                host,
                port,
                timeout=timeout,
                local_address=local_address,
                socket_options=socket_options,
            )

    pinned = _PinnedNetworkBackend(
        "models.example.test", ("203.0.113.17",), delegate=RecordingBackend([b""])
    )
    stream = asyncio.run(pinned.connect_tcp("models.example.test", 443))
    asyncio.run(stream.aclose())
    assert seen == [("203.0.113.17", 443)]
    with pytest.raises(httpcore.ConnectError):
        asyncio.run(pinned.connect_tcp("other.example.test", 443))


def test_unsupported_credential_environment_is_rejected_before_binding(tmp_path: Path) -> None:
    with pytest.raises(ChatCompositionError) as caught:
        compose_chat_service(
            app_data_dir=tmp_path,
            credential_store=_credentials(),
            profile_id="default",
            environment="development",
            preferences_store=None,
            transport=_Transport(),
            clock_ns=lambda: _NOW_NS,
            catalog_path=_CATALOG,
        )
    assert str(caught.value) == "CREDENTIAL_ENVIRONMENT_INVALID"
