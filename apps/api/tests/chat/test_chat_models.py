"""Synthetic unit coverage for the CHAT-001 provider boundary."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Awaitable, Callable
from decimal import Decimal

import pytest
from fastapi import FastAPI, Request, Response
from fastapi.testclient import TestClient
from pydantic import ValidationError

from leviathan_api.chat.models import (
    ChatApiShapeV1,
    ChatErrorCodeV1,
    ChatMessageV1,
    ChatRequestV1,
    ChatRoleV1,
    ChatServiceError,
    ChatUsageV1,
)
from leviathan_api.chat.port import (
    ChatDisclosurePort,
    ChatModelBindingV1,
    ChatPolicyDecisionV1,
    ChatPolicyPort,
    ChatPriceScheduleV1,
    ChatPriceV1,
    ChatTransportPort,
    ProviderCallV1,
    ProviderHttpResponseV1,
    TrustedCompatibleEndpointV1,
)
from leviathan_api.chat.providers import (
    build_provider_call,
    normalize_provider_response,
    normalize_provider_stream,
)
from leviathan_api.chat.service import ChatServiceV1
from leviathan_api.routers.chat_models import create_chat_models_router
from leviathan_core.agent_council.model_registry import (
    ModelCapabilityV1,
    ModelRegistryEntryV1,
    ModelRegistryV1,
    Provider,
)
from leviathan_core.security.authz_models import (
    _VERIFIER_MARKER,
    PrincipalV1,
    TrustedPrincipalAdapterV1,
    TrustedPrincipalV1,
)


def _principal() -> TrustedPrincipalV1:
    claims = PrincipalV1(
        principal_id="operator.1",
        project_id="leviathan-ai",
        roles=("operator",),
        env="development",
        venue=None,
        portfolio=None,
        strategy=None,
    )
    return TrustedPrincipalAdapterV1.from_verified_claims(claims, verifier_marker=_VERIFIER_MARKER)


def _model(
    *,
    provider: Provider = "gpt",
    approved: bool = True,
    available: bool = True,
    alias: str = "assistant.fast",
    entry_id: str = "entry.fast",
    input_cost: Decimal = Decimal("0"),
    output_cost: Decimal = Decimal("0"),
) -> ModelRegistryEntryV1:
    return ModelRegistryEntryV1(
        entry_id=entry_id,
        alias=alias,
        provider=provider,
        model_id=f"{provider}.model.synthetic",
        model_version="v1",
        registry_version="v1",
        capability=ModelCapabilityV1(
            modalities=("text",),
            tools=(),
            output_schemas=(),
            structured_output=False,
            max_context_tokens=16_384,
            max_output_tokens=8_192,
            quality_class="standard",
            privacy_class="internal",
        ),
        supported_regions=("local",),
        approved=approved,
        available=available,
        available_from_ns=1,
        available_until_ns=2**63 - 1,
        credential_name="MODEL_KEY",
        input_cost_per_million_tokens_usd=input_cost,
        output_cost_per_million_tokens_usd=output_cost,
        cost_class="low",
        latency_class="low",
        latency_reservation_ns=1_000_000_000,
    )


class FakePolicy(ChatPolicyPort):
    def __init__(
        self, *, allowed: bool = True, remaining_tokens: int = 100_000, remaining_cost: str = "1"
    ) -> None:
        self.allowed = allowed
        self.remaining_tokens = remaining_tokens
        self.remaining_cost = remaining_cost
        self.calls = 0

    def authorize(
        self,
        principal: TrustedPrincipalV1,
        request: ChatRequestV1,
        model: ModelRegistryEntryV1,
    ) -> ChatPolicyDecisionV1:
        self.calls += 1
        return ChatPolicyDecisionV1(
            allowed=self.allowed,
            code="ALLOW" if self.allowed else "DENY",
            policy_version="policy.v1",
            remaining_cost_usd=Decimal(self.remaining_cost),
            max_output_tokens=8_192,
            remaining_tokens=self.remaining_tokens,
        )


class FakeDisclosure(ChatDisclosurePort):
    def __init__(self, acknowledged: bool = True) -> None:
        self.value = acknowledged
        self.calls: list[str] = []

    def acknowledged(self, principal: TrustedPrincipalV1, provider: str) -> bool:
        self.calls.append(provider)
        return self.value


class FakeTransport(ChatTransportPort):
    def __init__(
        self,
        *,
        text: str = "synthetic answer",
        fail: Exception | None = None,
        api_shape: ChatApiShapeV1 = ChatApiShapeV1.OPENAI_CHAT_COMPLETIONS,
        stream_text: tuple[str, ...] = ("hello ", "world"),
    ) -> None:
        self.text = text
        self.fail = fail
        self.api_shape = api_shape
        self.stream_text = stream_text
        self.calls: list[ProviderCallV1] = []
        self.stream_calls: list[ProviderCallV1] = []
        self.cancelled = False

    async def complete(self, call: ProviderCallV1) -> ProviderHttpResponseV1:
        self.calls.append(call)
        if self.fail is not None:
            raise self.fail
        body = {
            "choices": [
                {
                    "message": {"content": self.text, "tool_calls": []},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 5, "completion_tokens": 3},
        }
        return ProviderHttpResponseV1(status_code=200, body=json.dumps(body).encode())

    async def stream(self, call: ProviderCallV1) -> AsyncIterator[bytes]:
        self.stream_calls.append(call)
        try:
            frames = [
                {"choices": [{"delta": {"content": text}, "finish_reason": None}]}
                for text in self.stream_text
            ]
            frames.append(
                {
                    "choices": [{"delta": {}, "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 5, "completion_tokens": 2},
                }
            )
            for frame in frames:
                yield f"data: {json.dumps(frame)}\n\n".encode()
            yield b"data: [DONE]\n\n"
        finally:
            self.cancelled = True


def _request(
    *, stream: bool = False, disclosure: bool = True, alias: str = "assistant.fast"
) -> ChatRequestV1:
    return ChatRequestV1(
        request_id="request.1",
        model_alias=alias,
        messages=(
            ChatMessageV1(role=ChatRoleV1.SYSTEM, content="be concise"),
            ChatMessageV1(role=ChatRoleV1.USER, content="hello"),
        ),
        max_output_tokens=32,
        stream=stream,
        hosted_egress_disclosed=disclosure,
    )


def _service(
    *,
    model: ModelRegistryEntryV1 | None = None,
    shape: ChatApiShapeV1 = ChatApiShapeV1.OPENAI_CHAT_COMPLETIONS,
    policy: FakePolicy | None = None,
    disclosure: FakeDisclosure | None = None,
    transport: FakeTransport | None = None,
    secret: str = "synthetic-provider-key-canary",
    resolver: Callable[[str], str | None] | None = None,
    price_schedule: ChatPriceScheduleV1 | None = None,
    endpoints: tuple[TrustedCompatibleEndpointV1, ...] = (),
) -> ChatServiceV1:
    entry = model or _model()
    binding = ChatModelBindingV1(
        entry_id=entry.entry_id,
        api_shape=shape,
        endpoint_id="local.endpoint" if shape is ChatApiShapeV1.OPENAI_COMPATIBLE else None,
        timeout_ms=2_000,
    )
    return ChatServiceV1(
        registry=ModelRegistryV1(version="v1", entries=(entry,)),
        bindings=(binding,),
        policy=policy or FakePolicy(),
        resolve_secret=resolver or (lambda name: secret),
        transport=transport or FakeTransport(),
        disclosure=disclosure or FakeDisclosure(),
        endpoints=endpoints,
        price_schedule=price_schedule,
        clock_ns=lambda: 10_000_000_000,
    )


@pytest.mark.parametrize(
    ("provider", "shape", "expected_endpoint", "body_key"),
    [
        (
            "claude",
            ChatApiShapeV1.ANTHROPIC_MESSAGES,
            "https://api.anthropic.com/v1/messages",
            "max_tokens",
        ),
        (
            "gpt",
            ChatApiShapeV1.OPENAI_CHAT_COMPLETIONS,
            "https://api.openai.com/v1/chat/completions",
            "messages",
        ),
        ("gpt", ChatApiShapeV1.OPENAI_RESPONSES, "https://api.openai.com/v1/responses", "input"),
    ],
)
def test_provider_shapes_are_translated_from_registry_only(
    provider: Provider, shape: ChatApiShapeV1, expected_endpoint: str, body_key: str
) -> None:
    model = _model(provider=provider)
    call = build_provider_call(
        _request(),
        model,
        ChatModelBindingV1(entry_id=model.entry_id, api_shape=shape, timeout_ms=2_000),
        endpoints={},
        credential="canary-secret-value",
    )
    payload = json.loads(call.body_json)
    assert call.endpoint == expected_endpoint
    assert payload["model"] == model.model_id
    assert body_key in payload
    assert "canary-secret-value" not in repr(call)
    assert "canary-secret-value" not in call.body_json


def test_compatible_endpoint_requires_trusted_explicit_pinned_config() -> None:
    with pytest.raises(ValueError):
        TrustedCompatibleEndpointV1(
            endpoint_id="unsafe.endpoint",
            base_url="https://example.test",
            pinned_addresses=("127.0.0.1",),
        )
    endpoint = TrustedCompatibleEndpointV1(
        endpoint_id="local.endpoint",
        base_url="http://127.0.0.1:11434",
        pinned_addresses=("127.0.0.1",),
        allow_private_network=True,
        local_endpoint=True,
    )
    model = _model(provider="ollama")
    call = build_provider_call(
        _request(),
        model,
        ChatModelBindingV1(
            entry_id=model.entry_id,
            api_shape=ChatApiShapeV1.OPENAI_COMPATIBLE,
            endpoint_id=endpoint.endpoint_id,
            timeout_ms=1_000,
        ),
        endpoints={endpoint.endpoint_id: endpoint},
        credential="local-canary",
    )
    assert call.endpoint == "http://127.0.0.1:11434/v1/chat/completions"
    assert call.pinned_addresses == ("127.0.0.1",)


@pytest.mark.asyncio
async def test_complete_normalizes_usage_cost_and_hides_secret_from_surfaces() -> None:
    transport = FakeTransport()
    schedule = ChatPriceScheduleV1(
        version="prices.v1",
        prices=(
            ChatPriceV1(
                model_alias="assistant.fast",
                input_usd_per_million_tokens=Decimal("1"),
                output_usd_per_million_tokens=Decimal("2"),
            ),
        ),
    )
    service = _service(transport=transport, price_schedule=schedule)
    result = await service.complete(_principal(), _request())
    assert [event.event for event in result.events] == [
        "start",
        "text_delta",
        "usage",
        "finish",
        "record",
    ]
    assert result.record.usage == ChatUsageV1(input_tokens=5, output_tokens=3)
    assert result.record.cost_status == "available"
    assert result.record.cost_usd == "0.000011"
    assert result.record.hosted_egress_disclosed is True
    surfaces = repr(result) + result.model_dump_json() + repr(transport.calls[0])
    assert "synthetic-provider-key-canary" not in surfaces


@pytest.mark.asyncio
async def test_policy_budget_disclosure_and_model_denials_happen_before_secret_or_network() -> None:
    calls: list[str] = []
    transport = FakeTransport()
    policy = FakePolicy(allowed=False)

    def tracked_resolver(name: str) -> str:
        calls.append(name)
        return "key"

    service = _service(policy=policy, transport=transport, resolver=tracked_resolver)
    with pytest.raises(ChatServiceError) as denied:
        await service.complete(_principal(), _request())
    assert denied.value.code is ChatErrorCodeV1.POLICY_DENIED
    assert calls == [] and transport.calls == []

    small_budget = FakePolicy(allowed=True, remaining_tokens=10)
    service = _service(policy=small_budget, transport=transport, resolver=tracked_resolver)
    with pytest.raises(ChatServiceError) as exhausted:
        await service.complete(_principal(), _request())
    assert exhausted.value.code is ChatErrorCodeV1.BUDGET_EXCEEDED
    assert transport.calls == []

    cost_budget = FakePolicy(allowed=True, remaining_cost="0.000001")
    priced_model = _model(input_cost=Decimal("1"), output_cost=Decimal("1"))
    secret_calls: list[str] = []
    service = _service(
        model=priced_model,
        policy=cost_budget,
        transport=transport,
        resolver=lambda name: secret_calls.append(name) or "key",
    )
    with pytest.raises(ChatServiceError) as cost_exhausted:
        await service.complete(_principal(), _request())
    assert cost_exhausted.value.code is ChatErrorCodeV1.BUDGET_EXCEEDED
    assert secret_calls == []
    assert transport.calls == []

    unacknowledged = FakeDisclosure(False)
    service = _service(disclosure=unacknowledged, transport=transport)
    with pytest.raises(ChatServiceError) as disclosure_error:
        await service.complete(_principal(), _request(disclosure=False))
    assert disclosure_error.value.code is ChatErrorCodeV1.DISCLOSURE_REQUIRED
    assert transport.calls == []

    service = _service(model=_model(approved=False), transport=transport)
    with pytest.raises(ChatServiceError) as unapproved:
        await service.complete(_principal(), _request())
    assert unapproved.value.code is ChatErrorCodeV1.MODEL_NOT_ALLOWED
    assert transport.calls == []


@pytest.mark.asyncio
async def test_missing_or_rotated_credentials_are_resolved_per_request() -> None:
    keys = [None, "rotated-synthetic-key"]
    seen: list[str] = []
    transport = FakeTransport()
    service = _service(transport=transport)

    def rotating_resolver(name: str) -> str | None:
        seen.append(name)
        return keys.pop(0)

    service = _service(transport=transport, resolver=rotating_resolver)
    with pytest.raises(ChatServiceError) as missing:
        await service.complete(_principal(), _request())
    assert missing.value.code is ChatErrorCodeV1.CREDENTIAL_UNAVAILABLE
    assert transport.calls == []
    result = await service.complete(_principal(), _request())
    assert seen == ["openai_api_key", "openai_api_key"]
    assert len(transport.calls) == 1
    assert result.record.request_id == "request.1"


@pytest.mark.asyncio
async def test_stream_order_usage_record_and_disconnect_cancellation() -> None:
    transport = FakeTransport()
    service = _service(transport=transport)
    events = [event async for event in service.stream(_principal(), _request(stream=True))]
    assert [event.event for event in events] == [
        "start",
        "text_delta",
        "text_delta",
        "usage",
        "finish",
        "record",
    ]
    assert events[1].text_delta == "hello "
    assert events[-1].record is not None
    assert transport.cancelled is True


@pytest.mark.asyncio
async def test_provider_credential_is_redacted_across_stream_frame_boundaries() -> None:
    canary = "synthetic-provider-key-canary"
    transport = FakeTransport(stream_text=("before synthetic-provider-", "key-canary after"))
    service = _service(transport=transport, secret=canary)
    events = [event async for event in service.stream(_principal(), _request(stream=True))]
    serialized = "".join(event.model_dump_json() for event in events)
    assert canary not in serialized
    assert "[REDACTED]" in serialized


@pytest.mark.asyncio
async def test_transport_failures_are_fixed_and_provider_text_is_not_echoed() -> None:
    secretish = "provider response contained synthetic-canary"
    service = _service(transport=FakeTransport(fail=RuntimeError(secretish)))
    with pytest.raises(ChatServiceError) as error:
        await service.complete(_principal(), _request())
    assert error.value.code is ChatErrorCodeV1.PROVIDER_UNAVAILABLE
    assert secretish not in str(error.value)
    assert secretish not in repr(error.value)


def test_unknown_price_is_explicitly_unavailable() -> None:
    # The same output is not assigned a fabricated dollar amount without an approved schedule.
    async def run() -> None:
        result = await _service().complete(_principal(), _request())
        assert result.record.cost_status == "unavailable"
        assert result.record.cost_usd is None

        asyncio.run(run())


@pytest.mark.parametrize(
    ("shape", "payload", "expected_text", "input_field", "output_field"),
    [
        (
            ChatApiShapeV1.ANTHROPIC_MESSAGES,
            {
                "content": [{"type": "text", "text": "hello"}],
                "usage": {"input_tokens": 3, "output_tokens": 2},
                "stop_reason": "end_turn",
            },
            "hello",
            "input_tokens",
            "output_tokens",
        ),
        (
            ChatApiShapeV1.OPENAI_CHAT_COMPLETIONS,
            {
                "choices": [
                    {"message": {"content": "hello", "tool_calls": []}, "finish_reason": "stop"}
                ],
                "usage": {"prompt_tokens": 3, "completion_tokens": 2},
            },
            "hello",
            "prompt_tokens",
            "completion_tokens",
        ),
        (
            ChatApiShapeV1.OPENAI_RESPONSES,
            {
                "status": "completed",
                "output": [
                    {"type": "message", "content": [{"type": "output_text", "text": "hello"}]}
                ],
                "usage": {"input_tokens": 3, "output_tokens": 2},
            },
            "hello",
            "input_tokens",
            "output_tokens",
        ),
    ],
)
def test_provider_response_shapes_normalize_to_neutral_reply(
    shape: ChatApiShapeV1,
    payload: dict[str, object],
    expected_text: str,
    input_field: str,
    output_field: str,
) -> None:
    response = ProviderHttpResponseV1(status_code=200, body=json.dumps(payload).encode())
    reply = normalize_provider_response(shape, response)
    assert reply.text == expected_text
    assert reply.usage.input_tokens == payload["usage"][input_field]  # type: ignore[index]
    assert reply.usage.output_tokens == payload["usage"][output_field]  # type: ignore[index]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("shape", "frames", "expected"),
    [
        (
            ChatApiShapeV1.ANTHROPIC_MESSAGES,
            (
                {"type": "message_start", "message": {"usage": {"input_tokens": 2}}},
                {
                    "type": "content_block_delta",
                    "delta": {"type": "text_delta", "text": "hi"},
                },
                {
                    "type": "message_delta",
                    "delta": {"stop_reason": "end_turn"},
                    "usage": {"output_tokens": 1},
                },
            ),
            "hi",
        ),
        (
            ChatApiShapeV1.OPENAI_CHAT_COMPLETIONS,
            (
                {"choices": [{"delta": {"content": "hi"}, "finish_reason": None}]},
                {
                    "choices": [{"delta": {}, "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 2, "completion_tokens": 1},
                },
            ),
            "hi",
        ),
        (
            ChatApiShapeV1.OPENAI_RESPONSES,
            (
                {"type": "response.output_text.delta", "delta": "hi"},
                {
                    "type": "response.completed",
                    "response": {
                        "status": "completed",
                        "usage": {"input_tokens": 2, "output_tokens": 1},
                    },
                },
            ),
            "hi",
        ),
    ],
)
async def test_vendor_sse_shapes_normalize(
    shape: ChatApiShapeV1, frames: tuple[dict[str, object], ...], expected: str
) -> None:
    async def source() -> AsyncIterator[bytes]:
        for frame in frames:
            yield f"data: {json.dumps(frame)}\n\n".encode()

    chunks = [item async for item in normalize_provider_stream(shape, source())]
    assert "".join(item.text_delta or "" for item in chunks) == expected
    usage = next(item.usage for item in chunks if item.usage is not None)
    assert usage == ChatUsageV1(input_tokens=2, output_tokens=1)
    assert chunks[-1].finish_reason == "stop"


@pytest.mark.asyncio
async def test_streamed_openai_tool_proposal_is_bounded_and_non_executable() -> None:
    frames: tuple[dict[str, object], ...] = (
        {
            "choices": [
                {
                    "delta": {
                        "tool_calls": [
                            {"index": 0, "function": {"name": "tool.lookup", "arguments": '{"q":'}}
                        ]
                    },
                    "finish_reason": None,
                }
            ]
        },
        {
            "choices": [
                {
                    "delta": {"tool_calls": [{"index": 0, "function": {"arguments": '"x"}'}}]},
                    "finish_reason": None,
                }
            ]
        },
        {
            "choices": [{"delta": {}, "finish_reason": "tool_calls"}],
            "usage": {"prompt_tokens": 2, "completion_tokens": 1},
        },
    )

    async def source() -> AsyncIterator[bytes]:
        for frame in frames:
            yield f"data: {json.dumps(frame)}\n\n".encode()

    chunks = [
        item
        async for item in normalize_provider_stream(
            ChatApiShapeV1.OPENAI_CHAT_COMPLETIONS, source()
        )
    ]
    proposal = next(item.tool_proposal for item in chunks if item.tool_proposal is not None)
    assert proposal.name == "tool.lookup"
    assert json.loads(proposal.arguments_json) == {"q": "x"}
    assert chunks[-1].finish_reason == "tool_calls"


def test_router_auth_no_store_and_fixed_provider_error() -> None:
    transport = FakeTransport(fail=RuntimeError("private provider detail"))
    app = FastAPI()
    app.include_router(create_chat_models_router(_service(transport=transport)))

    @app.middleware("http")
    async def synthetic_auth(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        request.state.trusted_principal = _principal()
        return await call_next(request)

    with TestClient(app) as client:
        response = client.post(
            "/chat/complete",
            json={
                "request_id": "request.1",
                "model_alias": "assistant.fast",
                "messages": [{"role": "user", "content": "hello"}],
                "max_output_tokens": 16,
                "stream": False,
                "hosted_egress_disclosed": True,
            },
        )
        assert response.status_code == 503
        assert response.json() == {"code": "PROVIDER_UNAVAILABLE"}
        assert response.headers["cache-control"] == "no-store"
        assert "private provider detail" not in response.text
        method_mismatch = client.get("/chat/complete")
        assert method_mismatch.status_code == 405
        assert method_mismatch.headers["cache-control"] == "no-store"
        unknown = client.get("/chat/not-a-route")
        assert unknown.status_code == 404
        assert unknown.headers["cache-control"] == "no-store"

    app2 = FastAPI()
    app2.include_router(create_chat_models_router(_service()))
    with TestClient(app2) as client:
        missing = client.get("/chat/models")
        assert missing.status_code == 401
        assert missing.json() == {"code": "AUTH_REQUIRED"}
        assert missing.headers["cache-control"] == "no-store"


@pytest.mark.parametrize(
    "bad",
    [
        {
            "request_id": "request.1",
            "model_alias": "assistant.fast",
            "messages": [],
            "max_output_tokens": 1,
        },
        {
            "request_id": "request.1",
            "model_alias": "assistant.fast",
            "messages": [{"role": "system", "content": "x"}, {"role": "user", "content": "x"}],
            "max_output_tokens": True,
        },
    ],
)
def test_request_models_reject_invalid_shape(bad: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        ChatRequestV1.model_validate(bad)
