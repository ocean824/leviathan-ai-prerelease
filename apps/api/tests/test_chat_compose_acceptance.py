"""Independent acceptance coverage for production chat composition (CHAT-COMPOSE-001)."""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
from collections.abc import Callable
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from leviathan_store.preferences import UserPreferencesV1
from pydantic import SecretStr

from leviathan_api.chat.models import (
    ChatErrorCodeV1,
    ChatMessageV1,
    ChatRequestV1,
    ChatRoleV1,
    ChatServiceError,
)
from leviathan_api.chat.service import ChatServiceV1
from leviathan_api.chat_compose import (
    HttpxChatTransportV1,
    compose_chat_service,
    load_model_catalog,
)
from leviathan_api.routers.chat_models import create_chat_models_router
from leviathan_core.security.authz_models import (
    _VERIFIER_MARKER,
    PrincipalV1,
    TrustedPrincipalAdapterV1,
)
from leviathan_vault.app_credentials import InMemoryCredentialStore

_FIXTURES = Path(__file__).parent / "fixtures" / "chat_compose"
_CANARY_KEY = "synthetic-chat-key-canary-DO-NOT-USE"
_BODY_CANARY = "synthetic-private-prompt-canary"
_OK_CHAT_COMPLETIONS = json.dumps(
    {
        "choices": [{"message": {"content": "synthetic answer"}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 2, "completion_tokens": 2},
    },
    separators=(",", ":"),
).encode("utf-8")
_OK_OPENAI_RESPONSES = json.dumps(
    {
        "status": "completed",
        "output": [
            {
                "type": "message",
                "content": [{"type": "output_text", "text": "synthetic answer"}],
            }
        ],
        "usage": {"input_tokens": 2, "output_tokens": 2},
    },
    separators=(",", ":"),
).encode("utf-8")


class _Preferences:
    """Small persistent-port stand-in: documents survive composition recreation."""

    def __init__(self, documents: dict[tuple[str, str], dict[str, object]]) -> None:
        self.documents = documents
        self.revisions = {key: 1 for key in documents}
        self.reads: list[tuple[str, str]] = []
        self.writes: list[tuple[str, str, dict[str, object]]] = []

    def get(self, user_scope: str, namespace: str) -> UserPreferencesV1 | None:
        self.reads.append((user_scope, namespace))
        document = self.documents.get((user_scope, namespace))
        if document is None:
            return None
        return UserPreferencesV1(
            schema_version=1,
            user_scope=user_scope,
            namespace=namespace,
            document=document,
            updated_at_ns=1,
            revision=self.revisions[(user_scope, namespace)],
        )

    def put(
        self,
        user_scope: str,
        namespace: str,
        document: dict[str, object],
        *,
        if_match: str,
    ) -> UserPreferencesV1:
        self.documents[(user_scope, namespace)] = document
        self.revisions[(user_scope, namespace)] = self.revisions.get((user_scope, namespace), 0) + 1
        self.writes.append((user_scope, namespace, document))
        return UserPreferencesV1(
            schema_version=1,
            user_scope=user_scope,
            namespace=namespace,
            document=document,
            updated_at_ns=2,
            revision=self.revisions[(user_scope, namespace)],
        )

    def delete(self, user_scope: str, namespace: str) -> None:
        self.documents.pop((user_scope, namespace), None)


class _HttpProbe:
    def __init__(
        self,
        *,
        response_body: bytes | None = None,
        status_code: int = 200,
    ) -> None:
        self.requests: list[httpx.Request] = []
        self.response_body = response_body
        self.status_code = status_code

    async def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        body = self.response_body
        if body is None:
            body = (
                _OK_OPENAI_RESPONSES
                if request.url.path.endswith("/responses")
                else _OK_CHAT_COMPLETIONS
            )
        return httpx.Response(self.status_code, content=body)


def _principal(principal_id: str = "operator.chat"):
    claims = PrincipalV1(
        principal_id=principal_id,
        project_id="leviathan-ai",
        roles=("operator",),
        env="development",
    )
    return TrustedPrincipalAdapterV1.from_verified_claims(claims, verifier_marker=_VERIFIER_MARKER)


def _preferences(
    *, cap: str = "5.00", gpt_disclosed: bool = True, ollama_disclosed: bool = True
) -> _Preferences:
    return _Preferences(
        {
            ("operator.chat", "chat.policy"): {
                "daily_cost_cap_usd": cap,
                "utc_day": "1970-01-01",
                "daily_reserved_cost_usd": "0.00",
            },
            (
                "operator.chat",
                "chat.disclosure",
            ): {"providers": {"gpt": gpt_disclosed, "ollama": ollama_disclosed}},
        }
    )


def _credential_store(*, openai: bool = True, compatible_url: str | None = None):
    store = InMemoryCredentialStore()
    if openai:
        store.put_profile("OPENAI", "PAPER", "default", {"api_key": SecretStr(_CANARY_KEY)})
    if compatible_url is not None:
        store.put_profile(
            "OPENAI_COMPATIBLE",
            "PAPER",
            "default",
            {
                "api_key": SecretStr(_CANARY_KEY),
                "base_url": compatible_url,
                "display_label": "Synthetic local model",
            },
        )
    return store


def _prepare_app_data(root: Path) -> None:
    registry_path = root / "chat" / "model-registry-v1.json"
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(_FIXTURES / "user-model-registry.json", registry_path)


def _compose(
    root: Path,
    *,
    credential_store: InMemoryCredentialStore,
    preferences_store: _Preferences | None = None,
    transport: object | None = None,
    clock_ns: Callable[[], int] = lambda: 10_000_000_000,
    address_resolver: Callable[[str, int], tuple[str, ...]] | None = None,
):
    _prepare_app_data(root)

    def forbid_system_resolution(_host: str, _port: int) -> tuple[str, ...]:
        raise AssertionError("acceptance tests must not perform DNS or network I/O")

    return compose_chat_service(
        app_data_dir=root,
        credential_store=credential_store,
        profile_id="default",
        environment="PAPER",
        preferences_store=preferences_store or _preferences(),
        transport=transport,
        clock_ns=clock_ns,
        catalog_path=_FIXTURES / "default-model-catalog.json",
        address_resolver=address_resolver or forbid_system_resolution,
    )


def _request(*, alias: str = "assistant.default") -> ChatRequestV1:
    return ChatRequestV1(
        request_id="chat.compose.acceptance",
        model_alias=alias,
        messages=(ChatMessageV1(role=ChatRoleV1.USER, content=_BODY_CANARY),),
        max_output_tokens=256,
        stream=False,
        hosted_egress_disclosed=True,
    )


def _api(service: ChatServiceV1, principal_id: str = "operator.chat") -> TestClient:
    app = FastAPI()
    trusted = _principal(principal_id)

    @app.middleware("http")
    async def bind_test_principal(request: Request, call_next):  # type: ignore[no-untyped-def]
        request.state.trusted_principal = trusted
        return await call_next(request)

    app.include_router(create_chat_models_router(service), prefix="/api")
    return TestClient(app)


def test_default_and_user_catalogs_merge_as_validated_registry(tmp_path: Path) -> None:
    user_path = tmp_path / "user-model-registry.json"
    shutil.copyfile(_FIXTURES / "user-model-registry.json", user_path)

    registry = load_model_catalog(_FIXTURES / "default-model-catalog.json", user_path)

    assert {row.alias for row in registry.entries} == {"assistant.default", "assistant.user"}
    assert {row.entry_id for row in registry.entries} == {
        "entry.default.chat",
        "entry.user.chat",
    }


def test_models_endpoint_lists_only_models_with_current_profile_credentials(tmp_path: Path) -> None:
    # The registry contains both the default GPT model and a user compatible model,
    # but only the OPENAI profile exists for this profile/environment pair.
    composition = _compose(
        tmp_path,
        credential_store=_credential_store(openai=True),
        preferences_store=_preferences(),
    )

    with _api(composition.service) as client:
        response = client.get("/api/chat/models")

    assert response.status_code == 200
    rows = response.json()["models"]
    assert [row["alias"] for row in rows] == ["assistant.default"]
    assert _CANARY_KEY not in response.text
    assert "assistant.user" not in response.text


def test_model_without_any_provider_credential_is_never_bound(tmp_path: Path) -> None:
    composition = _compose(
        tmp_path,
        credential_store=_credential_store(openai=False),
        preferences_store=_preferences(),
    )

    with _api(composition.service) as client:
        response = client.get("/api/chat/models")

    assert response.status_code == 200
    assert response.json() == {"models": []}


def test_successful_httpx_call_does_not_disclose_key_or_prompt_in_response_or_logs(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    probe = _HttpProbe()
    transport = HttpxChatTransportV1(http_transport=httpx.MockTransport(probe))
    composition = _compose(
        tmp_path,
        credential_store=_credential_store(openai=True),
        preferences_store=_preferences(),
        transport=transport,
    )

    caplog.set_level(logging.DEBUG)
    with _api(composition.service) as client:
        response = client.post(
            "/api/chat/complete",
            json={
                "request_id": "chat.compose.acceptance",
                "model_alias": "assistant.default",
                "messages": [{"role": "user", "content": _BODY_CANARY}],
                "max_output_tokens": 256,
                "stream": False,
                "hosted_egress_disclosed": True,
            },
        )

    assert response.status_code == 200
    assert len(probe.requests) == 1
    # Credential disclosure is restricted to the outbound authorization header.
    assert probe.requests[0].headers.get("authorization") == f"Bearer {_CANARY_KEY}"
    timeout = probe.requests[0].extensions.get("timeout")
    assert isinstance(timeout, dict)
    assert all(
        isinstance(timeout.get(name), (int, float)) and 0 < timeout[name] <= 30.0
        for name in ("connect", "read", "write", "pool")
    )
    assert _CANARY_KEY not in response.text
    assert _BODY_CANARY not in caplog.text
    assert _CANARY_KEY not in caplog.text


def test_provider_response_size_is_bounded_before_model_parsing(tmp_path: Path) -> None:
    probe = _HttpProbe(response_body=b"{" + (b"x" * 2_100_000) + b"}")
    transport = HttpxChatTransportV1(http_transport=httpx.MockTransport(probe))
    composition = _compose(
        tmp_path,
        credential_store=_credential_store(openai=True),
        preferences_store=_preferences(),
        transport=transport,
    )

    with pytest.raises(ChatServiceError) as error:
        asyncio.run(composition.service.complete(_principal(), _request()))

    assert error.value.code is ChatErrorCodeV1.PROVIDER_INVALID_RESPONSE
    assert len(probe.requests) == 1


def test_provider_error_body_cannot_echo_credential_into_response_or_logs(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    provider_body = f"upstream rejected key {_CANARY_KEY}".encode()
    probe = _HttpProbe(response_body=provider_body, status_code=500)
    transport = HttpxChatTransportV1(http_transport=httpx.MockTransport(probe))
    composition = _compose(
        tmp_path,
        credential_store=_credential_store(openai=True),
        preferences_store=_preferences(),
        transport=transport,
    )
    caplog.set_level(logging.DEBUG)

    with _api(composition.service) as client:
        response = client.post(
            "/api/chat/complete",
            json={
                "request_id": "chat.compose.acceptance",
                "model_alias": "assistant.default",
                "messages": [{"role": "user", "content": _BODY_CANARY}],
                "max_output_tokens": 256,
                "stream": False,
                "hosted_egress_disclosed": True,
            },
        )

    assert response.status_code == 503
    assert _CANARY_KEY not in response.text
    assert _CANARY_KEY not in caplog.text
    assert _BODY_CANARY not in caplog.text
    assert provider_body.decode("utf-8") not in response.text


def test_http_non_loopback_openai_compatible_profile_is_rejected(tmp_path: Path) -> None:
    # Simulate corrupt credential metadata that bypassed the normal CONN-001
    # writer. Composition must fail closed even when the store's input check is
    # not the guard that catches this read.
    store = _credential_store(openai=True, compatible_url="https://1.1.1.1")
    original_status = store.status_all()
    profile = next(row for row in original_status if row.provider == "OPENAI_COMPATIBLE")
    object.__setattr__(profile, "base_url", "http://models.example.invalid")
    original_resolve = store.resolve
    resolved = original_resolve("OPENAI_COMPATIBLE", "PAPER", "default")
    object.__setattr__(resolved, "_profile", profile)
    store.status_all = lambda: tuple(  # type: ignore[method-assign]
        profile if row.provider == "OPENAI_COMPATIBLE" else row for row in original_status
    )
    store.resolve = lambda provider, environment, profile_id: (  # type: ignore[method-assign]
        resolved
        if provider == "OPENAI_COMPATIBLE"
        else original_resolve(provider, environment, profile_id)
    )

    composition = _compose(
        tmp_path,
        credential_store=store,
        preferences_store=_preferences(),
        address_resolver=lambda _host, _port: ("1.1.1.1",),
    )
    with _api(composition.service) as client:
        response = client.get("/api/chat/models")

    assert response.status_code == 200
    assert [row["alias"] for row in response.json()["models"]] == ["assistant.default"]


@pytest.mark.parametrize(
    "base_url",
    ("http://127.0.0.1:11434", "https://models.example.invalid"),
    ids=("loopback-http", "public-https"),
)
def test_safe_compatible_profiles_can_be_bound_without_opening_a_socket(
    tmp_path: Path, base_url: str
) -> None:
    probe = _HttpProbe()
    resolutions: list[tuple[str, int]] = []

    def resolve_fixed_public_address(host: str, port: int) -> tuple[str, ...]:
        resolutions.append((host, port))
        return ("1.1.1.1",)

    transport = HttpxChatTransportV1(http_transport=httpx.MockTransport(probe))
    composition = _compose(
        tmp_path,
        credential_store=_credential_store(openai=False, compatible_url=base_url),
        preferences_store=_preferences(),
        transport=transport,
        address_resolver=resolve_fixed_public_address,
    )

    with _api(composition.service) as client:
        response = client.get("/api/chat/models")

    assert response.status_code == 200
    assert [row["alias"] for row in response.json()["models"]] == ["assistant.user"]
    if base_url.startswith("https://"):
        assert resolutions == [("models.example.invalid", 443)]
    else:
        assert resolutions == []


def test_hosted_egress_disclosure_is_read_from_persisted_user_preferences(
    tmp_path: Path,
) -> None:
    probe = _HttpProbe()
    transport = HttpxChatTransportV1(http_transport=httpx.MockTransport(probe))
    preferences = _preferences(gpt_disclosed=False)
    store = _credential_store(openai=True)
    first = _compose(
        tmp_path,
        credential_store=store,
        preferences_store=preferences,
        transport=transport,
    )

    with pytest.raises(ChatServiceError) as error:
        asyncio.run(first.service.complete(_principal(), _request()))
    assert error.value.code is ChatErrorCodeV1.DISCLOSURE_REQUIRED
    assert probe.requests == []

    # Simulate the user acknowledging the hosted-egress notice through the
    # persistent preferences port, then restart composition over the same data.
    preferences.documents[("operator.chat", "chat.disclosure")] = {
        "providers": {"gpt": True, "ollama": True}
    }
    restarted = _compose(
        tmp_path,
        credential_store=store,
        preferences_store=preferences,
        transport=transport,
    )
    asyncio.run(restarted.service.complete(_principal(), _request()))

    assert len(probe.requests) == 1
    assert ("operator.chat", "chat.disclosure") in preferences.reads


def test_daily_user_cost_cap_denies_before_http_transport_and_is_user_scoped(
    tmp_path: Path,
) -> None:
    probe = _HttpProbe()
    transport = HttpxChatTransportV1(http_transport=httpx.MockTransport(probe))
    preferences = _preferences(cap="0.000001")
    composition = _compose(
        tmp_path,
        credential_store=_credential_store(openai=True),
        preferences_store=preferences,
        transport=transport,
    )

    with pytest.raises(ChatServiceError) as error:
        asyncio.run(composition.service.complete(_principal(), _request()))

    assert error.value.code is ChatErrorCodeV1.POLICY_DENIED
    assert probe.requests == []
    assert ("operator.chat", "chat.policy") in preferences.reads
    assert (
        preferences.documents[("operator.chat", "chat.policy")]["daily_reserved_cost_usd"] == "0.00"
    )

    # The same composed service applies a separate cap to each principal.
    preferences.documents[("operator.other", "chat.policy")] = {
        "daily_cost_cap_usd": "5.00",
        "utc_day": "1970-01-01",
        "daily_reserved_cost_usd": "0.00",
    }
    preferences.revisions[("operator.other", "chat.policy")] = 1
    preferences.documents[("operator.other", "chat.disclosure")] = {
        "providers": {"gpt": True, "ollama": True}
    }
    preferences.revisions[("operator.other", "chat.disclosure")] = 1
    asyncio.run(composition.service.complete(_principal("operator.other"), _request()))
    assert len(probe.requests) == 1
    assert ("operator.other", "chat.policy") in preferences.reads
    assert any(
        scope == "operator.other" and namespace == "chat.policy"
        for scope, namespace, _ in preferences.writes
    )
    policy_doc = preferences.documents[("operator.other", "chat.policy")]
    assert policy_doc["utc_day"] == "1970-01-01"
    assert policy_doc["daily_reserved_cost_usd"] != "0.00"


def test_daily_cost_cap_above_operator_max_is_denied_without_clamping(tmp_path: Path) -> None:
    probe = _HttpProbe()
    transport = HttpxChatTransportV1(http_transport=httpx.MockTransport(probe))
    preferences = _preferences(cap="100.01")
    composition = _compose(
        tmp_path,
        credential_store=_credential_store(openai=True),
        preferences_store=preferences,
        transport=transport,
    )

    with pytest.raises(ChatServiceError) as error:
        asyncio.run(composition.service.complete(_principal(), _request()))

    assert error.value.code is ChatErrorCodeV1.POLICY_DENIED
    assert probe.requests == []
    policy_doc = preferences.documents[("operator.chat", "chat.policy")]
    assert policy_doc["daily_cost_cap_usd"] == "100.01"
    assert policy_doc["daily_reserved_cost_usd"] == "0.00"


def test_daily_reservation_rolls_over_only_at_utc_day_boundary(tmp_path: Path) -> None:
    probe = _HttpProbe()
    transport = HttpxChatTransportV1(http_transport=httpx.MockTransport(probe))
    preferences = _preferences(cap="0.01")
    preferences.documents[("operator.chat", "chat.policy")]["daily_reserved_cost_usd"] = "0.01"
    next_utc_day_ns = 86_410_000_000_000
    composition = _compose(
        tmp_path,
        credential_store=_credential_store(openai=True),
        preferences_store=preferences,
        transport=transport,
        clock_ns=lambda: next_utc_day_ns,
    )

    asyncio.run(composition.service.complete(_principal(), _request()))

    assert len(probe.requests) == 1
    policy_doc = preferences.documents[("operator.chat", "chat.policy")]
    assert policy_doc["utc_day"] == "1970-01-02"
    assert policy_doc["daily_reserved_cost_usd"] != "0.01"
