"""Fail-closed, provider-neutral chat orchestration over injected trust and transport ports."""

from __future__ import annotations

import asyncio
import time
from collections import deque
from collections.abc import AsyncIterator, Callable
from decimal import Decimal
from threading import Lock
from typing import Literal, cast

from leviathan_core.agent_council.model_registry import ModelRegistryEntryV1, ModelRegistryV1
from leviathan_core.security.authz_models import TrustedPrincipalV1, require_trusted_principal

from .models import (
    MAX_OUTPUT_TOKENS,
    ChatApiShapeV1,
    ChatErrorCodeV1,
    ChatMessageV1,
    ChatModelPublicV1,
    ChatRequestRecordV1,
    ChatRequestV1,
    ChatResultV1,
    ChatRoleV1,
    ChatServiceError,
    ChatStreamEventV1,
    ChatToolProposalV1,
    ChatUsageV1,
)
from .port import (
    ChatDisclosurePort,
    ChatModelBindingV1,
    ChatPolicyDecisionV1,
    ChatPolicyPort,
    ChatPriceScheduleV1,
    ChatSecretResolver,
    ChatTransportPort,
    ProviderCallV1,
    ProviderChunkV1,
    ProviderReplyV1,
    ProviderTransportError,
    TrustedCompatibleEndpointV1,
)
from .providers import build_provider_call, normalize_provider_response, normalize_provider_stream

_HOSTED_SHAPES = frozenset(
    {
        ChatApiShapeV1.ANTHROPIC_MESSAGES,
        ChatApiShapeV1.OPENAI_CHAT_COMPLETIONS,
        ChatApiShapeV1.OPENAI_RESPONSES,
    }
)
_SECRET_NAME = {
    ChatApiShapeV1.ANTHROPIC_MESSAGES: "anthropic_api_key",
    ChatApiShapeV1.OPENAI_CHAT_COMPLETIONS: "openai_api_key",
    ChatApiShapeV1.OPENAI_RESPONSES: "openai_api_key",
    ChatApiShapeV1.OPENAI_COMPATIBLE: "openai_compatible_api_key",
}
_RATE_WINDOW_NS = 60_000_000_000
_MAX_PROVIDER_OUTPUT_BYTES = 1_000_000


class ChatServiceV1:
    """Run bounded chat requests; no SDK, environment lookup, or ambient network client."""

    def __init__(
        self,
        *,
        registry: ModelRegistryV1,
        bindings: tuple[ChatModelBindingV1, ...],
        policy: ChatPolicyPort,
        resolve_secret: ChatSecretResolver,
        transport: ChatTransportPort,
        disclosure: ChatDisclosurePort,
        endpoints: tuple[TrustedCompatibleEndpointV1, ...] = (),
        price_schedule: ChatPriceScheduleV1 | None = None,
        clock_ns: Callable[[], int] = time.monotonic_ns,
        max_requests_per_minute: int = 30,
        max_stream_ms: int = 300_000,
    ) -> None:
        if type(registry) is not ModelRegistryV1 or type(bindings) is not tuple:
            raise TypeError("CHAT_CONFIGURATION_INVALID")
        if any(type(item) is not ChatModelBindingV1 for item in bindings):
            raise TypeError("CHAT_CONFIGURATION_INVALID")
        if any(type(item) is not TrustedCompatibleEndpointV1 for item in endpoints):
            raise TypeError("CHAT_CONFIGURATION_INVALID")
        if type(max_requests_per_minute) is not int or not 1 <= max_requests_per_minute <= 1_000:
            raise TypeError("CHAT_CONFIGURATION_INVALID")
        if type(max_stream_ms) is not int or not 100 <= max_stream_ms <= 300_000:
            raise TypeError("CHAT_CONFIGURATION_INVALID")
        if not callable(resolve_secret) or not callable(clock_ns):
            raise TypeError("CHAT_CONFIGURATION_INVALID")
        if not callable(getattr(policy, "authorize", None)) or not callable(
            getattr(disclosure, "acknowledged", None)
        ):
            raise TypeError("CHAT_CONFIGURATION_INVALID")
        if not callable(getattr(transport, "complete", None)) or not callable(
            getattr(transport, "stream", None)
        ):
            raise TypeError("CHAT_CONFIGURATION_INVALID")
        binding_ids = tuple(item.entry_id for item in bindings)
        endpoint_ids = tuple(item.endpoint_id for item in endpoints)
        if len(set(binding_ids)) != len(binding_ids) or len(set(endpoint_ids)) != len(endpoint_ids):
            raise TypeError("CHAT_CONFIGURATION_INVALID")
        known_entries = {entry.entry_id: entry for entry in registry.entries}
        if any(entry_id not in known_entries for entry_id in binding_ids):
            raise TypeError("CHAT_CONFIGURATION_INVALID")
        for binding in bindings:
            if (
                binding.api_shape is ChatApiShapeV1.OPENAI_COMPATIBLE
                and binding.endpoint_id not in endpoint_ids
            ):
                raise TypeError("CHAT_CONFIGURATION_INVALID")
        if price_schedule is not None and type(price_schedule) is not ChatPriceScheduleV1:
            raise TypeError("CHAT_CONFIGURATION_INVALID")
        self._registry = registry
        self._bindings = {item.entry_id: item for item in bindings}
        self._policy = policy
        self._resolve_secret = resolve_secret
        self._transport = transport
        self._disclosure = disclosure
        self._endpoints = {item.endpoint_id: item for item in endpoints}
        self._price_schedule = price_schedule
        self._clock_ns = clock_ns
        self._max_requests_per_minute = max_requests_per_minute
        self._max_stream_ns = max_stream_ms * 1_000_000
        self._rate_lock = Lock()
        self._rate_events: dict[str, deque[int]] = {}

    def list_models(self, principal: TrustedPrincipalV1) -> tuple[ChatModelPublicV1, ...]:
        try:
            verified = require_trusted_principal(principal)
        except Exception:
            raise ChatServiceError(ChatErrorCodeV1.AUTH_REQUIRED) from None
        rows: list[ChatModelPublicV1] = []
        now_ns = self._wall_clock()
        for entry in self._registry.entries:
            if (
                not entry.approved
                or not entry.available
                or not entry.available_from_ns <= now_ns < entry.available_until_ns
            ):
                continue
            binding = self._bindings.get(entry.entry_id)
            if binding is None:
                continue
            try:
                decision = self._policy.authorize(verified, _model_list_probe(entry.alias), entry)
            except Exception:
                continue
            if type(decision) is not ChatPolicyDecisionV1 or not decision.allowed:
                continue
            rows.append(
                ChatModelPublicV1(
                    alias=entry.alias,
                    provider=entry.provider,
                    model_version=entry.model_version,
                    registry_version=self._registry.version,
                    modalities=entry.capability.modalities,
                    max_context_tokens=entry.capability.max_context_tokens,
                    max_output_tokens=min(entry.capability.max_output_tokens, MAX_OUTPUT_TOKENS),
                )
            )
        return tuple(sorted(rows, key=lambda row: row.alias))

    async def complete(self, principal: TrustedPrincipalV1, request: ChatRequestV1) -> ChatResultV1:
        prepared = self._preflight(principal, request, stream_expected=False)
        start_ns = self._clock()
        try:
            response = await asyncio.wait_for(
                self._transport.complete(prepared[4]),
                timeout=prepared[4].timeout_ms / 1000,
            )
        except TimeoutError:
            raise ChatServiceError(ChatErrorCodeV1.PROVIDER_TIMEOUT) from None
        except ProviderTransportError as exc:
            raise ChatServiceError(ChatErrorCodeV1(exc.code)) from None
        except ChatServiceError:
            raise
        except Exception:
            raise ChatServiceError(ChatErrorCodeV1.PROVIDER_UNAVAILABLE) from None
        model, binding, policy, _, _ = prepared
        reply = normalize_provider_response(binding.api_shape, response)
        secret = prepared[4].credential.get_secret_value()
        reply = _redact_reply(reply, secret)
        self._validate_reply(reply, request, model)
        record = self._record(request, model, binding, policy, reply.usage, start_ns)
        events: list[ChatStreamEventV1] = [
            ChatStreamEventV1(event="start", request_id=request.request_id)
        ]
        if reply.text:
            events.append(
                ChatStreamEventV1(
                    event="text_delta", request_id=request.request_id, text_delta=reply.text
                )
            )
        events.append(
            ChatStreamEventV1(event="usage", request_id=request.request_id, usage=reply.usage)
        )
        events.extend(
            ChatStreamEventV1(
                event="tool_proposal", request_id=request.request_id, tool_proposal=item
            )
            for item in reply.tool_proposals
        )
        events.extend(
            (
                ChatStreamEventV1(
                    event="finish",
                    request_id=request.request_id,
                    finish_reason=_finish_reason(reply.finish_reason),
                ),
                ChatStreamEventV1(event="record", request_id=request.request_id, record=record),
            )
        )
        return ChatResultV1(events=tuple(events), record=record)

    async def stream(
        self, principal: TrustedPrincipalV1, request: ChatRequestV1
    ) -> AsyncIterator[ChatStreamEventV1]:
        try:
            prepared = self._preflight(principal, request, stream_expected=True)
        except ChatServiceError as exc:
            request_id = request.request_id if type(request) is ChatRequestV1 else "invalid-request"
            yield ChatStreamEventV1(event="error", request_id=request_id, error_code=exc.code)
            return
        model, binding, policy, _reserved_tokens, call = prepared
        start_ns = self._clock()
        yield ChatStreamEventV1(event="start", request_id=request.request_id)
        usage: ChatUsageV1 | None = None
        finished: str | None = None
        output_bytes = 0
        deadline_ns = start_ns + min(self._max_stream_ns, call.timeout_ms * 1_000_000)
        try:
            iterator = normalize_provider_stream(
                binding.api_shape, self._transport.stream(call)
            ).__aiter__()
            secret_filter = _SecretStreamFilter(call.credential.get_secret_value())
            while True:
                remaining_ns = deadline_ns - self._clock()
                if remaining_ns <= 0:
                    raise TimeoutError
                try:
                    chunk = await asyncio.wait_for(
                        iterator.__anext__(), timeout=remaining_ns / 1_000_000_000
                    )
                except StopAsyncIteration:
                    break
                if type(chunk) is not ProviderChunkV1:
                    raise ChatServiceError(ChatErrorCodeV1.PROVIDER_INVALID_RESPONSE)
                if chunk.kind == "text_delta" and chunk.text_delta is not None:
                    output_bytes += len(chunk.text_delta.encode("utf-8"))
                    if output_bytes > _MAX_PROVIDER_OUTPUT_BYTES:
                        raise ChatServiceError(ChatErrorCodeV1.PROVIDER_INVALID_RESPONSE)
                    safe_delta = secret_filter.push(chunk.text_delta)
                    if not safe_delta:
                        continue
                    yield ChatStreamEventV1(
                        event="text_delta",
                        request_id=request.request_id,
                        text_delta=safe_delta,
                    )
                elif chunk.kind == "usage" and chunk.usage is not None:
                    usage = chunk.usage
                    yield ChatStreamEventV1(
                        event="usage", request_id=request.request_id, usage=usage
                    )
                elif chunk.kind == "tool_proposal" and chunk.tool_proposal is not None:
                    yield ChatStreamEventV1(
                        event="tool_proposal",
                        request_id=request.request_id,
                        tool_proposal=_redact_tool(
                            chunk.tool_proposal, call.credential.get_secret_value()
                        ),
                    )
                elif chunk.kind == "finish" and chunk.finish_reason is not None:
                    finished = chunk.finish_reason
            if usage is None or finished is None:
                raise ChatServiceError(ChatErrorCodeV1.PROVIDER_INVALID_RESPONSE)
            final_delta = secret_filter.finish()
            if final_delta:
                yield ChatStreamEventV1(
                    event="text_delta", request_id=request.request_id, text_delta=final_delta
                )
            self._validate_usage(usage, request, model)
            record = self._record(request, model, binding, policy, usage, start_ns)
            yield ChatStreamEventV1(
                event="finish",
                request_id=request.request_id,
                finish_reason=_finish_reason(finished),
            )
            yield ChatStreamEventV1(event="record", request_id=request.request_id, record=record)
        except TimeoutError:
            yield ChatStreamEventV1(
                event="error",
                request_id=request.request_id,
                error_code=ChatErrorCodeV1.PROVIDER_TIMEOUT,
            )
            return
        except ProviderTransportError as exc:
            yield ChatStreamEventV1(
                event="error", request_id=request.request_id, error_code=ChatErrorCodeV1(exc.code)
            )
            return
        except asyncio.CancelledError:
            raise
        except ChatServiceError as exc:
            yield ChatStreamEventV1(
                event="error", request_id=request.request_id, error_code=exc.code
            )
            return
        except Exception:
            yield ChatStreamEventV1(
                event="error",
                request_id=request.request_id,
                error_code=ChatErrorCodeV1.PROVIDER_UNAVAILABLE,
            )
            return

    def _preflight(
        self,
        principal: TrustedPrincipalV1,
        request: ChatRequestV1,
        *,
        stream_expected: bool,
    ) -> tuple[ModelRegistryEntryV1, ChatModelBindingV1, ChatPolicyDecisionV1, int, ProviderCallV1]:
        if type(request) is not ChatRequestV1:
            raise ChatServiceError(ChatErrorCodeV1.REQUEST_INVALID)
        if request.stream is not stream_expected:
            raise ChatServiceError(ChatErrorCodeV1.REQUEST_INVALID)
        try:
            verified = require_trusted_principal(principal)
        except Exception:
            raise ChatServiceError(ChatErrorCodeV1.AUTH_REQUIRED) from None
        model = next(
            (entry for entry in self._registry.entries if entry.alias == request.model_alias), None
        )
        if model is None or not model.approved or not model.available:
            raise ChatServiceError(ChatErrorCodeV1.MODEL_NOT_ALLOWED)
        binding = self._bindings.get(model.entry_id)
        if binding is None:
            raise ChatServiceError(ChatErrorCodeV1.MODEL_NOT_ALLOWED)
        now_ns = self._wall_clock()
        if not model.available_from_ns <= now_ns < model.available_until_ns:
            raise ChatServiceError(ChatErrorCodeV1.MODEL_NOT_ALLOWED)
        try:
            decision = self._policy.authorize(verified, request, model)
        except Exception:
            raise ChatServiceError(ChatErrorCodeV1.POLICY_DENIED) from None
        if type(decision) is not ChatPolicyDecisionV1 or not decision.allowed:
            raise ChatServiceError(ChatErrorCodeV1.POLICY_DENIED)
        # No provider-specific tokenizer is imported here. UTF-8 bytes are a
        # conservative token upper bound for byte-level tokenizers; this may
        # reject some otherwise-valid long prompts, but never under-reserves.
        input_tokens = sum(len(message.content.encode("utf-8")) for message in request.messages)
        reserved_tokens = input_tokens + request.max_output_tokens
        if (
            request.max_output_tokens > decision.max_output_tokens
            or reserved_tokens > decision.remaining_tokens
            or reserved_tokens > model.capability.max_context_tokens
        ):
            raise ChatServiceError(ChatErrorCodeV1.BUDGET_EXCEEDED)
        self._record_local_reservation(verified.principal_id, reserved_tokens)
        scheduled_price = self._price_for(model.alias)
        input_rate = model.input_cost_per_million_tokens_usd
        output_rate = model.output_cost_per_million_tokens_usd
        if scheduled_price is not None:
            input_rate = max(input_rate, scheduled_price[0])
            output_rate = max(output_rate, scheduled_price[1])
        projected_cost = (
            Decimal(input_tokens) * input_rate + Decimal(request.max_output_tokens) * output_rate
        ) / Decimal(1_000_000)
        if projected_cost > decision.remaining_cost_usd:
            raise ChatServiceError(ChatErrorCodeV1.BUDGET_EXCEEDED)
        if binding.api_shape in _HOSTED_SHAPES:
            try:
                accepted = self._disclosure.acknowledged(verified, model.provider)
            except Exception:
                accepted = False
            if not request.hosted_egress_disclosed or accepted is not True:
                raise ChatServiceError(ChatErrorCodeV1.DISCLOSURE_REQUIRED)
        secret_name = _SECRET_NAME[binding.api_shape]
        try:
            credential = self._resolve_secret(secret_name)
        except Exception:
            credential = None
        if type(credential) is not str or not credential or len(credential) > 4_096:
            raise ChatServiceError(ChatErrorCodeV1.CREDENTIAL_UNAVAILABLE)
        try:
            call = build_provider_call(
                request,
                model,
                binding,
                endpoints=self._endpoints,
                credential=credential,
            )
        except ChatServiceError:
            raise
        except Exception:
            raise ChatServiceError(ChatErrorCodeV1.ENDPOINT_UNSAFE) from None
        return model, binding, decision, reserved_tokens, call

    def _record_local_reservation(self, principal_id: str, tokens: int) -> None:
        # Policy remains the authoritative cross-process budget gate. This local
        # request-rate bound protects this process from unbounded in-flight work.
        now = self._clock()
        with self._rate_lock:
            if principal_id not in self._rate_events and len(self._rate_events) >= 10_000:
                raise ChatServiceError(ChatErrorCodeV1.RATE_LIMITED)
            events = self._rate_events.setdefault(principal_id, deque())
            while events and now - events[0] >= _RATE_WINDOW_NS:
                events.popleft()
            if len(events) >= self._max_requests_per_minute:
                raise ChatServiceError(ChatErrorCodeV1.RATE_LIMITED)
            events.append(now)

    def _validate_reply(
        self, reply: ProviderReplyV1, request: ChatRequestV1, model: ModelRegistryEntryV1
    ) -> None:
        if len(reply.text.encode("utf-8")) > 1_000_000 or len(reply.tool_proposals) > 64:
            raise ChatServiceError(ChatErrorCodeV1.PROVIDER_INVALID_RESPONSE)
        self._validate_usage(reply.usage, request, model)

    @staticmethod
    def _validate_usage(
        usage: ChatUsageV1, request: ChatRequestV1, model: ModelRegistryEntryV1
    ) -> None:
        if (
            type(usage) is not ChatUsageV1
            or usage.input_tokens > model.capability.max_context_tokens
            or usage.output_tokens > request.max_output_tokens
        ):
            raise ChatServiceError(ChatErrorCodeV1.PROVIDER_INVALID_RESPONSE)

    def _price_for(self, alias: str) -> tuple[Decimal, Decimal] | None:
        if self._price_schedule is None:
            return None
        price = next((row for row in self._price_schedule.prices if row.model_alias == alias), None)
        if price is None:
            return None
        return price.input_usd_per_million_tokens, price.output_usd_per_million_tokens

    def _record(
        self,
        request: ChatRequestV1,
        model: ModelRegistryEntryV1,
        binding: ChatModelBindingV1,
        policy: ChatPolicyDecisionV1,
        usage: ChatUsageV1,
        started_ns: int,
    ) -> ChatRequestRecordV1:
        elapsed = max(0, self._clock() - started_ns)
        price = self._price_for(model.alias)
        if price is None:
            cost_status: Literal["available", "unavailable"] = "unavailable"
            cost = None
        else:
            value = (
                Decimal(usage.input_tokens) * price[0] + Decimal(usage.output_tokens) * price[1]
            ) / Decimal(1_000_000)
            cost_status = "available"
            cost = format(value, "f")
        return ChatRequestRecordV1(
            request_id=request.request_id,
            model_alias=request.model_alias,
            api_shape=binding.api_shape,
            registry_version=self._registry.version,
            policy_version=policy.policy_version,
            elapsed_ns=min(elapsed, 2**63 - 1),
            usage=usage,
            cost_status=cost_status,
            cost_usd=cost,
            hosted_egress_disclosed=request.hosted_egress_disclosed,
        )

    def _clock(self) -> int:
        try:
            result = self._clock_ns()
        except Exception:
            raise ChatServiceError(ChatErrorCodeV1.PROVIDER_UNAVAILABLE) from None
        if type(result) is not int or result < 0:
            raise ChatServiceError(ChatErrorCodeV1.PROVIDER_UNAVAILABLE)
        return result

    @staticmethod
    def _wall_clock() -> int:
        return time.time_ns()


def _finish_reason(value: str) -> Literal["stop", "length", "tool_calls"]:
    if value not in {"stop", "length", "tool_calls"}:
        raise ChatServiceError(ChatErrorCodeV1.PROVIDER_INVALID_RESPONSE)
    return cast(Literal["stop", "length", "tool_calls"], value)


class _SecretStreamFilter:
    """Redact an exact credential even when provider text splits it across frames."""

    def __init__(self, secret: str) -> None:
        self._secret = secret
        self._pending = ""

    def push(self, value: str) -> str:
        text = (self._pending + value).replace(self._secret, "[REDACTED]")
        held = min(max(len(self._secret) - 1, 0), len(text))
        while held and not text.endswith(self._secret[:held]):
            held -= 1
        if held == 0:
            self._pending = ""
            return text
        safe, self._pending = text[:-held], text[-held:]
        return safe

    def finish(self) -> str:
        value, self._pending = self._pending, ""
        if value and self._secret.startswith(value):
            return "[REDACTED]"
        return value.replace(self._secret, "[REDACTED]")


def _redact_tool(tool: object, secret: str) -> ChatToolProposalV1:
    if type(tool) is not ChatToolProposalV1:
        raise ChatServiceError(ChatErrorCodeV1.PROVIDER_INVALID_RESPONSE)
    proposal = tool
    arguments_json = (
        "{}" if secret and secret in proposal.arguments_json else proposal.arguments_json
    )
    return proposal.model_copy(update={"arguments_json": arguments_json})


def _redact_reply(reply: ProviderReplyV1, secret: str) -> ProviderReplyV1:
    if type(reply) is not ProviderReplyV1:
        raise ChatServiceError(ChatErrorCodeV1.PROVIDER_INVALID_RESPONSE)
    return reply.model_copy(
        update={
            "text": reply.text.replace(secret, "[REDACTED]"),
            "tool_proposals": tuple(_redact_tool(tool, secret) for tool in reply.tool_proposals),
        }
    )


def _model_list_probe(alias: str) -> ChatRequestV1:
    """Internal metadata-only policy probe; never sent to a provider."""
    return ChatRequestV1(
        request_id="model-list",
        model_alias=alias,
        messages=(ChatMessageV1(role=ChatRoleV1.USER, content="model-list-policy-probe"),),
        max_output_tokens=1,
    )


__all__ = ["ChatServiceV1"]
