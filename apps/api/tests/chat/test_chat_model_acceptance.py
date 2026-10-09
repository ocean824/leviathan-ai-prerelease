"""Independent acceptance tests for the bounded CHAT-001 model service."""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from decimal import Decimal

import pytest
from fastapi import FastAPI, Request, Response
from fastapi.testclient import TestClient

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
    ProviderCallV1,
    ProviderHttpResponseV1,
    ProviderTransportError,
    TrustedCompatibleEndpointV1,
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

CANARY_SECRET = "CHAT001_CANARY_DO_NOT_DISCLOSE_83d9f57b"
CANARY_PROVIDER_TEXT = "private provider diagnostic CHAT001_CANARY_DO_NOT_DISCLOSE_83d9f57b"
NORMAL_BODY: dict[ChatApiShapeV1, dict[str, object]] = {
    ChatApiShapeV1.ANTHROPIC_MESSAGES: {
        "content": [{"type": "text", "text": "synthetic answer"}],
        "usage": {"input_tokens": 3, "output_tokens": 2},
        "stop_reason": "end_turn",
    },
    ChatApiShapeV1.OPENAI_CHAT_COMPLETIONS: {
        "choices": [
            {"message": {"content": "synthetic answer", "tool_calls": []}, "finish_reason": "stop"}
        ],
        "usage": {"prompt_tokens": 3, "completion_tokens": 2},
    },
    ChatApiShapeV1.OPENAI_RESPONSES: {
        "status": "completed",
        "output": [
            {"type": "message", "content": [{"type": "output_text", "text": "synthetic answer"}]}
        ],
        "usage": {"input_tokens": 3, "output_tokens": 2},
    },
    ChatApiShapeV1.OPENAI_COMPATIBLE: {
        "choices": [
            {"message": {"content": "synthetic answer", "tool_calls": []}, "finish_reason": "stop"}
        ],
        "usage": {"prompt_tokens": 3, "completion_tokens": 2},
    },
}


def _principal() -> TrustedPrincipalV1:
    claims = PrincipalV1(
        principal_id="operator.chat",
        project_id="leviathan-ai",
        roles=("operator",),
        env="development",
    )
    return TrustedPrincipalAdapterV1.from_verified_claims(claims, verifier_marker=_VERIFIER_MARKER)


def _model(
    *,
    provider: Provider = "gpt",
    alias: str = "assistant.chat",
    entry_id: str = "entry.chat",
    approved: bool = True,
) -> ModelRegistryEntryV1:
    return ModelRegistryEntryV1(
        entry_id=entry_id,
        alias=alias,
        provider=provider,
        model_id=f"{provider}.synthetic.v1",
        model_version="v1",
        registry_version="v1",
        capability=ModelCapabilityV1(
            modalities=("text",),
            structured_output=False,
            max_context_tokens=16_384,
            max_output_tokens=8_192,
            quality_class="standard",
            privacy_class="internal",
        ),
        supported_regions=("local",),
        approved=approved,
        available=True,
        available_from_ns=1,
        available_until_ns=2**63 - 1,
        credential_name="SYNTHETIC_MODEL_KEY",
        input_cost_per_million_tokens_usd=Decimal("0"),
        output_cost_per_million_tokens_usd=Decimal("0"),
        cost_class="low",
        latency_class="low",
        latency_reservation_ns=1_000_000_000,
    )


class _Policy(ChatPolicyPort):
    def __init__(
        self,
        *,
        allowed: bool = True,
        remaining_tokens: int = 50_000,
        remaining_cost: Decimal = Decimal("1"),
        max_output_tokens: int = 8_192,
    ) -> None:
        self.allowed = allowed
        self.remaining_tokens = remaining_tokens
        self.remaining_cost = remaining_cost
        self.max_output_tokens = max_output_tokens
        self.calls = 0

    def authorize(
        self,
        principal: TrustedPrincipalV1,
        request: ChatRequestV1,
        model: ModelRegistryEntryV1,
    ) -> ChatPolicyDecisionV1:
        del principal, request, model
        self.calls += 1
        return ChatPolicyDecisionV1(
            allowed=self.allowed,
            code="ALLOW" if self.allowed else "DENY",
            policy_version="policy.acceptance.v1",
            remaining_cost_usd=self.remaining_cost,
            max_output_tokens=self.max_output_tokens,
            remaining_tokens=self.remaining_tokens,
        )


class _Disclosure(ChatDisclosurePort):
    def __init__(self, acknowledged: bool = True) -> None:
        self.value = acknowledged
        self.calls: list[str] = []

    def acknowledged(self, principal: TrustedPrincipalV1, provider: str) -> bool:
        del principal
        self.calls.append(provider)
        return self.value


class _Transport:
    def __init__(
        self,
        *,
        status_code: int = 200,
        body: bytes | None = None,
        stream_chunks: tuple[bytes, ...] = (),
        complete_error: Exception | None = None,
        stream_error: Exception | None = None,
    ) -> None:
        self.status_code = status_code
        self.body = (
            body
            if body is not None
            else _json_bytes(NORMAL_BODY[ChatApiShapeV1.OPENAI_CHAT_COMPLETIONS])
        )
        self.stream_chunks = stream_chunks
        self.complete_error = complete_error
        self.stream_error = stream_error
        self.calls: list[ProviderCallV1] = []
        self.stream_calls: list[ProviderCallV1] = []
        self.stream_started = asyncio.Event()
        self.stream_closed = asyncio.Event()

    async def complete(self, call: ProviderCallV1) -> ProviderHttpResponseV1:
        self.calls.append(call)
        if self.complete_error is not None:
            raise self.complete_error
        return ProviderHttpResponseV1(status_code=self.status_code, body=self.body)

    async def stream(self, call: ProviderCallV1) -> AsyncIterator[bytes]:
        self.stream_calls.append(call)
        self.stream_started.set()
        try:
            for chunk in self.stream_chunks:
                yield chunk
            if self.stream_error is not None:
                raise self.stream_error
        finally:
            self.stream_closed.set()


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sse(value: object) -> bytes:
    return b"data: " + _json_bytes(value) + b"\n\n"


def _request(
    *,
    alias: str = "assistant.chat",
    stream: bool = False,
    disclosure: bool = True,
) -> ChatRequestV1:
    return ChatRequestV1(
        request_id="request.acceptance",
        model_alias=alias,
        messages=(
            ChatMessageV1(role=ChatRoleV1.SYSTEM, content="answer concisely"),
            ChatMessageV1(role=ChatRoleV1.USER, content="synthetic question"),
        ),
        max_output_tokens=32,
        stream=stream,
        hosted_egress_disclosed=disclosure,
    )


def _service(
    *,
    shape: ChatApiShapeV1 = ChatApiShapeV1.OPENAI_CHAT_COMPLETIONS,
    model: ModelRegistryEntryV1 | None = None,
    policy: _Policy | None = None,
    disclosure: _Disclosure | None = None,
    transport: _Transport | None = None,
    resolve_secret: Callable[[str], str | None] | None = None,
    endpoints: tuple[TrustedCompatibleEndpointV1, ...] = (),
    price_schedule: ChatPriceScheduleV1 | None = None,
    max_requests_per_minute: int = 30,
    max_stream_ms: int = 300_000,
) -> tuple[ChatServiceV1, _Policy, _Transport, list[str]]:
    selected_model = model or _model()
    endpoint_id = "endpoint.local" if shape is ChatApiShapeV1.OPENAI_COMPATIBLE else None
    binding = ChatModelBindingV1(
        entry_id=selected_model.entry_id,
        api_shape=shape,
        endpoint_id=endpoint_id,
        timeout_ms=250,
        max_retries=0,
    )
    active_policy = policy or _Policy()
    active_transport = transport or _Transport(body=_json_bytes(NORMAL_BODY[shape]))
    names: list[str] = []

    def secret_resolver(name: str) -> str | None:
        names.append(name)
        if resolve_secret is not None:
            return resolve_secret(name)
        return CANARY_SECRET

    service = ChatServiceV1(
        registry=ModelRegistryV1(version="v1", entries=(selected_model,)),
        bindings=(binding,),
        policy=active_policy,
        resolve_secret=secret_resolver,
        transport=active_transport,
        disclosure=disclosure or _Disclosure(),
        endpoints=endpoints,
        price_schedule=price_schedule,
        clock_ns=lambda: 10_000_000_000,
        max_requests_per_minute=max_requests_per_minute,
        max_stream_ms=max_stream_ms,
    )
    return service, active_policy, active_transport, names


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("shape", "provider", "expected_endpoint", "request_key"),
    [
        (
            ChatApiShapeV1.ANTHROPIC_MESSAGES,
            "claude",
            "https://api.anthropic.com/v1/messages",
            "max_tokens",
        ),
        (
            ChatApiShapeV1.OPENAI_CHAT_COMPLETIONS,
            "gpt",
            "https://api.openai.com/v1/chat/completions",
            "messages",
        ),
        (
            ChatApiShapeV1.OPENAI_RESPONSES,
            "gpt",
            "https://api.openai.com/v1/responses",
            "input",
        ),
    ],
)
async def test_hosted_provider_shapes_normalize_requests_and_usage(
    shape: ChatApiShapeV1,
    provider: Provider,
    expected_endpoint: str,
    request_key: str,
) -> None:
    transport = _Transport(body=_json_bytes(NORMAL_BODY[shape]))
    service, _, _, resolved = _service(
        shape=shape, model=_model(provider=provider), transport=transport
    )
    result = await service.complete(_principal(), _request())

    call = transport.calls[0]
    payload = json.loads(call.body_json)
    assert call.api_shape is shape
    assert call.endpoint == expected_endpoint
    assert payload[request_key]
    expected_model = "claude.synthetic.v1" if provider == "claude" else "gpt.synthetic.v1"
    assert payload["model"] == expected_model
    assert call.follow_redirects is False
    assert result.events[2].usage == ChatUsageV1(input_tokens=3, output_tokens=2)
    assert result.record.usage == ChatUsageV1(input_tokens=3, output_tokens=2)
    assert resolved == ["anthropic_api_key" if provider == "claude" else "openai_api_key"]
    assert CANARY_SECRET not in repr(call)
    assert CANARY_SECRET not in call.body_json


@pytest.mark.asyncio
async def test_compatible_shape_uses_only_trusted_pinned_endpoint() -> None:
    endpoint = TrustedCompatibleEndpointV1(
        endpoint_id="endpoint.local",
        base_url="http://127.0.0.1:11434",
        pinned_addresses=("127.0.0.1",),
        allow_private_network=True,
        local_endpoint=True,
    )
    transport = _Transport(body=_json_bytes(NORMAL_BODY[ChatApiShapeV1.OPENAI_COMPATIBLE]))
    service, _, _, resolved = _service(
        shape=ChatApiShapeV1.OPENAI_COMPATIBLE,
        model=_model(provider="ollama"),
        endpoints=(endpoint,),
        transport=transport,
    )
    result = await service.complete(_principal(), _request())

    call = transport.calls[0]
    assert call.api_shape is ChatApiShapeV1.OPENAI_COMPATIBLE
    assert call.endpoint == "http://127.0.0.1:11434/v1/chat/completions"
    assert call.pinned_addresses == ("127.0.0.1",)
    assert call.follow_redirects is False
    assert result.record.usage == ChatUsageV1(input_tokens=3, output_tokens=2)
    assert resolved == ["openai_compatible_api_key"]


@pytest.mark.parametrize(
    "endpoint_values",
    [
        {"base_url": "http://example.test", "pinned_addresses": ("8.8.8.8",)},
        {"base_url": "https://example.test", "pinned_addresses": ("127.0.0.1",)},
        {"base_url": "https://user:pass@example.test", "pinned_addresses": ("8.8.8.8",)},
        {"base_url": "https://example.test/redirect", "pinned_addresses": ("8.8.8.8",)},
        {
            "base_url": "https://example.test/?next=http://127.0.0.1",
            "pinned_addresses": ("8.8.8.8",),
        },
        {"base_url": "https://10.0.0.8", "pinned_addresses": ("10.0.0.8",)},
        {"base_url": "https://example.test", "pinned_addresses": ("10.0.0.8",)},
    ],
)
def test_compatible_endpoint_rejects_private_public_redirect_and_userinfo_routes(
    endpoint_values: dict[str, object],
) -> None:
    with pytest.raises(ValueError):
        TrustedCompatibleEndpointV1(
            endpoint_id="endpoint.bad",
            allow_private_network=False,
            local_endpoint=False,
            **endpoint_values,
        )


@pytest.mark.asyncio
async def test_stream_sse_event_order_and_completed_record() -> None:
    frames = (
        _sse({"choices": [{"delta": {"content": "hello "}, "finish_reason": None}]}),
        _sse({"choices": [{"delta": {"content": "world"}, "finish_reason": None}]}),
        _sse(
            {
                "choices": [{"delta": {}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 3, "completion_tokens": 2},
            }
        ),
    )
    transport = _Transport(stream_chunks=frames)
    service, _, _, _ = _service(transport=transport)
    events = [event async for event in service.stream(_principal(), _request(stream=True))]
    assert [event.event for event in events] == [
        "start",
        "text_delta",
        "text_delta",
        "usage",
        "finish",
        "record",
    ]
    assert [event.text_delta for event in events if event.event == "text_delta"] == [
        "hello ",
        "world",
    ]
    assert events[-1].record is not None
    assert transport.stream_closed.is_set()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("shape", "provider", "frames"),
    [
        (
            ChatApiShapeV1.ANTHROPIC_MESSAGES,
            "claude",
            (
                _sse({"type": "message_start", "message": {"usage": {"input_tokens": 3}}}),
                _sse(
                    {
                        "type": "content_block_delta",
                        "delta": {"type": "text_delta", "text": "anthropic"},
                    }
                ),
                _sse(
                    {
                        "type": "message_delta",
                        "delta": {"stop_reason": "end_turn"},
                        "usage": {"output_tokens": 2},
                    }
                ),
            ),
        ),
        (
            ChatApiShapeV1.OPENAI_RESPONSES,
            "gpt",
            (
                _sse({"type": "response.output_text.delta", "delta": "responses"}),
                _sse(
                    {
                        "type": "response.completed",
                        "response": {
                            "status": "completed",
                            "usage": {"input_tokens": 3, "output_tokens": 2},
                        },
                    }
                ),
            ),
        ),
    ],
)
async def test_anthropic_and_responses_stream_shapes_normalize_usage(
    shape: ChatApiShapeV1,
    provider: Provider,
    frames: tuple[bytes, ...],
) -> None:
    transport = _Transport(stream_chunks=frames)
    service, _, _, _ = _service(shape=shape, model=_model(provider=provider), transport=transport)
    events = [event async for event in service.stream(_principal(), _request(stream=True))]
    assert events[0].event == "start"
    assert events[-2].event == "finish"
    assert events[-1].event == "record"
    usage = next(event.usage for event in events if event.event == "usage")
    assert usage == ChatUsageV1(input_tokens=3, output_tokens=2)


@pytest.mark.asyncio
async def test_secret_canary_split_across_stream_frames_is_redacted() -> None:
    split = len(CANARY_SECRET) // 2
    transport = _Transport(
        stream_chunks=(
            _sse(
                {"choices": [{"delta": {"content": CANARY_SECRET[:split]}, "finish_reason": None}]}
            ),
            _sse(
                {"choices": [{"delta": {"content": CANARY_SECRET[split:]}, "finish_reason": None}]}
            ),
            _sse(
                {
                    "choices": [{"delta": {}, "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 3, "completion_tokens": 2},
                }
            ),
        )
    )
    service, _, _, _ = _service(transport=transport)
    events = [event async for event in service.stream(_principal(), _request(stream=True))]
    serialized = repr(events) + json.dumps([item.model_dump(mode="json") for item in events])
    assert CANARY_SECRET not in serialized
    assert "[REDACTED]" in serialized


@pytest.mark.asyncio
async def test_stream_cancellation_closes_provider_iterator() -> None:
    transport = _Transport(
        stream_chunks=(_sse({"choices": [{"delta": {"content": "first"}, "finish_reason": None}]}),)
    )
    gate = asyncio.Event()

    async def blocked_stream(call: ProviderCallV1) -> AsyncIterator[bytes]:
        transport.stream_calls.append(call)
        transport.stream_started.set()
        try:
            yield transport.stream_chunks[0]
            await gate.wait()
        finally:
            transport.stream_closed.set()

    transport.stream = blocked_stream  # type: ignore[method-assign]
    service, _, _, _ = _service(transport=transport)

    async def consume() -> None:
        async for _event in service.stream(_principal(), _request(stream=True)):
            pass

    task = asyncio.create_task(consume())
    await asyncio.wait_for(transport.stream_started.wait(), timeout=1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert transport.stream_closed.is_set()


@pytest.mark.asyncio
async def test_stream_disconnect_is_content_free_and_has_no_success_marker() -> None:
    frame = _sse({"choices": [{"delta": {"content": "partial"}, "finish_reason": None}]})
    transport = _Transport(stream_chunks=(frame,), stream_error=RuntimeError(CANARY_PROVIDER_TEXT))
    service, _, _, _ = _service(transport=transport)
    events = [event async for event in service.stream(_principal(), _request(stream=True))]
    assert [event.event for event in events] == ["start", "text_delta", "error"]
    assert events[-1].error_code is ChatErrorCodeV1.PROVIDER_UNAVAILABLE
    assert CANARY_SECRET not in repr(events)
    assert CANARY_PROVIDER_TEXT not in repr(events)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"not-json",
        b'{"choices":[]}',
        _json_bytes(
            {
                "choices": [{"message": {"content": ""}, "finish_reason": "unknown"}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1},
            }
        ),
    ],
)
async def test_empty_malformed_and_invalid_provider_outputs_fail_closed(body: bytes) -> None:
    transport = _Transport(body=body)
    service, _, _, _ = _service(transport=transport)
    with pytest.raises(ChatServiceError) as error:
        await service.complete(_principal(), _request())
    assert error.value.code is ChatErrorCodeV1.PROVIDER_INVALID_RESPONSE
    assert len(transport.calls) == 1


@pytest.mark.asyncio
async def test_oversize_normalized_output_is_rejected_without_echo() -> None:
    body = _json_bytes(
        {
            "choices": [
                {
                    "message": {"content": "x" * 1_000_001, "tool_calls": []},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 3, "completion_tokens": 2},
        }
    )
    transport = _Transport(body=body)
    service, _, _, _ = _service(transport=transport)
    with pytest.raises(ChatServiceError) as error:
        await service.complete(_principal(), _request())
    assert error.value.code is ChatErrorCodeV1.PROVIDER_INVALID_RESPONSE
    assert "x" * 128 not in str(error.value)


@pytest.mark.asyncio
async def test_provider_status_and_timeout_are_fixed_errors() -> None:
    throttled = _Transport(status_code=429, body=CANARY_PROVIDER_TEXT.encode())
    service, _, _, _ = _service(transport=throttled)
    with pytest.raises(ChatServiceError) as rate_error:
        await service.complete(_principal(), _request())
    assert rate_error.value.code is ChatErrorCodeV1.PROVIDER_RATE_LIMITED
    assert CANARY_PROVIDER_TEXT not in str(rate_error.value)

    slow = _Transport()

    async def delayed(call: ProviderCallV1) -> ProviderHttpResponseV1:
        slow.calls.append(call)
        await asyncio.sleep(0.5)
        return ProviderHttpResponseV1(
            status_code=200,
            body=_json_bytes(NORMAL_BODY[ChatApiShapeV1.OPENAI_CHAT_COMPLETIONS]),
        )

    slow.complete = delayed  # type: ignore[method-assign]
    service, _, _, _ = _service(transport=slow)
    with pytest.raises(ChatServiceError) as timeout_error:
        await service.complete(_principal(), _request())
    assert timeout_error.value.code is ChatErrorCodeV1.PROVIDER_TIMEOUT

    redirect = _Transport(status_code=302, body=b"location: http://127.0.0.1/private")
    service, _, _, _ = _service(transport=redirect)
    with pytest.raises(ChatServiceError) as redirect_error:
        await service.complete(_principal(), _request())
    assert redirect_error.value.code is ChatErrorCodeV1.PROVIDER_UNAVAILABLE
    assert len(redirect.calls) == 1
    assert redirect.calls[0].follow_redirects is False


@pytest.mark.asyncio
async def test_local_rate_limit_is_enforced_without_a_retry() -> None:
    transport = _Transport()
    service, _, _, _ = _service(transport=transport, max_requests_per_minute=1)
    await service.complete(_principal(), _request())
    with pytest.raises(ChatServiceError) as error:
        await service.complete(_principal(), _request())
    assert error.value.code is ChatErrorCodeV1.RATE_LIMITED
    assert len(transport.calls) == 1


@pytest.mark.asyncio
async def test_unknown_price_is_unavailable_and_usage_is_exact() -> None:
    service, _, _, _ = _service()
    result = await service.complete(_principal(), _request())
    assert result.record.usage == ChatUsageV1(input_tokens=3, output_tokens=2)
    assert result.record.cost_status == "unavailable"
    assert result.record.cost_usd is None

    schedule = ChatPriceScheduleV1(
        version="price.v1",
        prices=(
            ChatPriceV1(
                model_alias="assistant.chat",
                input_usd_per_million_tokens=Decimal("1.25"),
                output_usd_per_million_tokens=Decimal("2.5"),
            ),
        ),
    )
    priced, _, _, _ = _service(price_schedule=schedule)
    priced_result = await priced.complete(_principal(), _request())
    assert priced_result.record.cost_status == "available"
    assert priced_result.record.cost_usd == "0.00000875"


@pytest.mark.asyncio
async def test_policy_model_credential_and_budget_denials_happen_before_network() -> None:
    transport = _Transport()
    denied, policy, _, resolved = _service(policy=_Policy(allowed=False), transport=transport)
    with pytest.raises(ChatServiceError) as policy_error:
        await denied.complete(_principal(), _request())
    assert policy_error.value.code is ChatErrorCodeV1.POLICY_DENIED
    assert policy.calls == 1 and resolved == [] and transport.calls == []

    unknown_model, _, _, unknown_resolutions = _service(transport=transport)
    with pytest.raises(ChatServiceError) as unknown_error:
        await unknown_model.complete(_principal(), _request(alias="model.not-allowlisted"))
    assert unknown_error.value.code is ChatErrorCodeV1.MODEL_NOT_ALLOWED
    assert unknown_resolutions == [] and transport.calls == []

    unapproved, _, _, unapproved_resolutions = _service(
        model=_model(approved=False), transport=transport
    )
    with pytest.raises(ChatServiceError) as model_error:
        await unapproved.complete(_principal(), _request())
    assert model_error.value.code is ChatErrorCodeV1.MODEL_NOT_ALLOWED
    assert unapproved_resolutions == [] and transport.calls == []

    missing, _, _, missing_resolutions = _service(
        transport=transport, resolve_secret=lambda _name: None
    )
    with pytest.raises(ChatServiceError) as credential_error:
        await missing.complete(_principal(), _request())
    assert credential_error.value.code is ChatErrorCodeV1.CREDENTIAL_UNAVAILABLE
    assert missing_resolutions == ["openai_api_key"] and transport.calls == []

    undisclosed, _, _, undisclosed_resolutions = _service(
        disclosure=_Disclosure(acknowledged=False), transport=transport
    )
    with pytest.raises(ChatServiceError) as disclosure_error:
        await undisclosed.complete(_principal(), _request())
    assert disclosure_error.value.code is ChatErrorCodeV1.DISCLOSURE_REQUIRED
    assert undisclosed_resolutions == [] and transport.calls == []

    too_few_tokens, _, _, budget_resolutions = _service(
        policy=_Policy(remaining_tokens=20), transport=transport
    )
    with pytest.raises(ChatServiceError) as budget_error:
        await too_few_tokens.complete(_principal(), _request())
    assert budget_error.value.code is ChatErrorCodeV1.BUDGET_EXCEEDED
    assert budget_resolutions == [] and transport.calls == []

    too_little_cost, _, _, cost_resolutions = _service(
        policy=_Policy(remaining_cost=Decimal("0")),
        price_schedule=ChatPriceScheduleV1(
            version="price.v1",
            prices=(
                ChatPriceV1(
                    model_alias="assistant.chat",
                    input_usd_per_million_tokens=Decimal("100"),
                    output_usd_per_million_tokens=Decimal("100"),
                ),
            ),
        ),
        transport=transport,
    )
    with pytest.raises(ChatServiceError) as cost_error:
        await too_little_cost.complete(_principal(), _request())
    assert cost_error.value.code is ChatErrorCodeV1.BUDGET_EXCEEDED
    assert cost_resolutions == [] and transport.calls == []


@pytest.mark.asyncio
async def test_no_quality_lowering_or_retry_fallback() -> None:
    advanced = _model(alias="assistant.advanced", entry_id="entry.advanced")
    basic = _model(alias="assistant.basic", entry_id="entry.basic")
    transport = _Transport(complete_error=ProviderTransportError("PROVIDER_UNAVAILABLE"))
    service = ChatServiceV1(
        registry=ModelRegistryV1(version="v1", entries=(advanced, basic)),
        bindings=(
            ChatModelBindingV1(
                entry_id=advanced.entry_id,
                api_shape=ChatApiShapeV1.OPENAI_CHAT_COMPLETIONS,
                timeout_ms=250,
                max_retries=0,
            ),
            ChatModelBindingV1(
                entry_id=basic.entry_id,
                api_shape=ChatApiShapeV1.OPENAI_CHAT_COMPLETIONS,
                timeout_ms=250,
                max_retries=0,
            ),
        ),
        policy=_Policy(),
        resolve_secret=lambda _name: CANARY_SECRET,
        transport=transport,
        disclosure=_Disclosure(),
        clock_ns=lambda: 10_000_000_000,
    )
    with pytest.raises(ChatServiceError) as error:
        await service.complete(_principal(), _request(alias=advanced.alias))
    assert error.value.code is ChatErrorCodeV1.PROVIDER_UNAVAILABLE
    assert len(transport.calls) == 1
    assert transport.calls[0].model_id == advanced.model_id


@pytest.mark.asyncio
async def test_credential_rotation_and_revocation_are_resolved_per_request() -> None:
    secret_values: list[str | None] = ["rotation-key-A", "rotation-key-B", None]
    transport = _Transport()
    service, _, _, resolved = _service(
        transport=transport,
        resolve_secret=lambda name: (
            secret_values.pop(0) if name == "openai_api_key" else "wrong-name"
        ),
    )
    first = await service.complete(_principal(), _request())
    second = await service.complete(_principal(), _request())
    with pytest.raises(ChatServiceError) as revoked:
        await service.complete(_principal(), _request())
    assert revoked.value.code is ChatErrorCodeV1.CREDENTIAL_UNAVAILABLE
    assert resolved == ["openai_api_key"] * 3
    assert [call.credential.get_secret_value() for call in transport.calls] == [
        "rotation-key-A",
        "rotation-key-B",
    ]
    public = repr(first) + repr(second) + first.model_dump_json() + second.model_dump_json()
    assert "rotation-key-A" not in public and "rotation-key-B" not in public


@pytest.mark.asyncio
async def test_secret_canary_is_absent_from_results_errors_logs_and_audit_record(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    body = {
        "choices": [
            {
                "message": {
                    "content": f"answer includes {CANARY_SECRET}",
                    "tool_calls": [
                        {
                            "function": {
                                "name": "tool.lookup",
                                "arguments": json.dumps({"value": CANARY_SECRET}),
                            }
                        }
                    ],
                },
                "finish_reason": "tool_calls",
            }
        ],
        "usage": {"prompt_tokens": 3, "completion_tokens": 2},
    }
    transport = _Transport(body=_json_bytes(body))
    service, _, _, _ = _service(transport=transport)
    result = await service.complete(_principal(), _request())
    public_text = repr(result) + result.model_dump_json() + repr(result.record)
    assert CANARY_SECRET not in public_text
    assert CANARY_SECRET not in caplog.text
    assert CANARY_SECRET not in result.record.model_dump_json()

    failing, _, _, _ = _service(
        transport=_Transport(complete_error=RuntimeError(CANARY_PROVIDER_TEXT))
    )
    with pytest.raises(ChatServiceError) as error:
        await failing.complete(_principal(), _request())
    assert CANARY_SECRET not in str(error.value) + repr(error.value)
    assert CANARY_PROVIDER_TEXT not in caplog.text


def test_router_rejects_missing_and_forged_principals_uniformly_and_sets_no_store() -> None:
    service, _, transport, _ = _service()
    app = FastAPI()
    app.include_router(create_chat_models_router(service))

    @app.middleware("http")
    async def inject_forged(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        if request.headers.get("x-principal-mode") == "forged":
            request.state.trusted_principal = object()
        return await call_next(request)

    with TestClient(app) as client:
        missing = client.get("/chat/models")
        forged = client.get("/chat/models", headers={"x-principal-mode": "forged"})
        request_body = {
            "request_id": "request.unauthenticated",
            "model_alias": "assistant.chat",
            "messages": [{"role": "user", "content": "synthetic"}],
            "max_output_tokens": 16,
            "hosted_egress_disclosed": True,
        }
        missing_post = client.post("/chat/complete", json=request_body)
        forged_post = client.post(
            "/chat/complete",
            json=request_body,
            headers={"x-principal-mode": "forged"},
        )
    assert missing.status_code == forged.status_code == 401
    assert missing.json() == forged.json() == {"code": "AUTH_REQUIRED"}
    assert missing.headers["cache-control"] == forged.headers["cache-control"] == "no-store"
    assert missing_post.status_code == forged_post.status_code == 401
    assert missing_post.json() == forged_post.json() == {"code": "AUTH_REQUIRED"}
    assert (
        missing_post.headers["cache-control"] == forged_post.headers["cache-control"] == "no-store"
    )
    assert transport.calls == []


def test_router_accepts_only_issued_principal_and_keeps_response_no_store() -> None:
    service, _, transport, _ = _service()
    app = FastAPI()
    app.include_router(create_chat_models_router(service))

    @app.middleware("http")
    async def inject_verified(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        request.state.trusted_principal = _principal()
        return await call_next(request)

    with TestClient(app) as client:
        response = client.post(
            "/chat/complete",
            json={
                "request_id": "request.router",
                "model_alias": "assistant.chat",
                "messages": [{"role": "user", "content": "synthetic route probe"}],
                "max_output_tokens": 16,
                "hosted_egress_disclosed": True,
            },
        )
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.json()["record"]["usage"] == {"input_tokens": 3, "output_tokens": 2}
    assert len(transport.calls) == 1


def test_compatible_endpoint_input_is_not_caller_controlled_and_redirect_is_not_followed() -> None:
    # Public internet destinations are accepted only as explicit trusted config with public pins.
    endpoint = TrustedCompatibleEndpointV1(
        endpoint_id="endpoint.public",
        base_url="https://compatible.example",
        pinned_addresses=("8.8.8.8",),
        allow_private_network=False,
        local_endpoint=False,
    )
    with pytest.raises(ValueError):
        TrustedCompatibleEndpointV1(
            endpoint_id="endpoint.redirect",
            base_url="https://compatible.example/redirect?to=http://127.0.0.1",
            pinned_addresses=("8.8.8.8",),
        )
    assert endpoint.endpoint_id == "endpoint.public"
