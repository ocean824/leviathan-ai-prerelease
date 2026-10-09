"""Provider-specific request translation for injected CHAT-001 transports."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Mapping

from pydantic import SecretStr

from leviathan_core.agent_council.model_registry import ModelRegistryEntryV1

from .models import (
    ChatApiShapeV1,
    ChatErrorCodeV1,
    ChatMessageV1,
    ChatRequestV1,
    ChatServiceError,
    ChatToolProposalV1,
    ChatUsageV1,
)
from .port import (
    ChatModelBindingV1,
    ProviderCallV1,
    ProviderChunkV1,
    ProviderHttpResponseV1,
    ProviderReplyV1,
    TrustedCompatibleEndpointV1,
)

_HOSTED_ENDPOINTS = {
    ChatApiShapeV1.ANTHROPIC_MESSAGES: "https://api.anthropic.com/v1/messages",
    ChatApiShapeV1.OPENAI_CHAT_COMPLETIONS: "https://api.openai.com/v1/chat/completions",
    ChatApiShapeV1.OPENAI_RESPONSES: "https://api.openai.com/v1/responses",
}


def _system_and_messages(
    messages: tuple[ChatMessageV1, ...],
) -> tuple[str | None, list[dict[str, str]]]:
    system_parts = [message.content for message in messages if message.role.value == "system"]
    converted = [
        {"role": message.role.value, "content": message.content}
        for message in messages
        if message.role.value != "system"
    ]
    return ("\n\n".join(system_parts) if system_parts else None), converted


def build_provider_call(
    request: ChatRequestV1,
    model: ModelRegistryEntryV1,
    binding: ChatModelBindingV1,
    *,
    endpoints: Mapping[str, TrustedCompatibleEndpointV1],
    credential: str,
) -> ProviderCallV1:
    """Translate only approved registry data and bounded input into an API-shaped call."""
    if type(request) is not ChatRequestV1 or type(model) is not ModelRegistryEntryV1:
        raise ChatServiceError(ChatErrorCodeV1.MODEL_NOT_ALLOWED)
    if type(binding) is not ChatModelBindingV1:
        raise ChatServiceError(ChatErrorCodeV1.MODEL_NOT_ALLOWED)
    expected_shapes = {
        "claude": {ChatApiShapeV1.ANTHROPIC_MESSAGES},
        "gpt": {
            ChatApiShapeV1.OPENAI_CHAT_COMPLETIONS,
            ChatApiShapeV1.OPENAI_RESPONSES,
            ChatApiShapeV1.OPENAI_COMPATIBLE,
        },
        "ollama": {ChatApiShapeV1.OPENAI_COMPATIBLE},
    }
    if binding.entry_id != model.entry_id or binding.api_shape not in expected_shapes.get(
        model.provider, set()
    ):
        raise ChatServiceError(ChatErrorCodeV1.MODEL_NOT_ALLOWED)
    if type(credential) is not str or not credential or len(credential) > 4_096:
        raise ChatServiceError(ChatErrorCodeV1.CREDENTIAL_UNAVAILABLE)

    endpoint = _HOSTED_ENDPOINTS.get(binding.api_shape)
    pinned_addresses: tuple[str, ...] = ()
    if binding.api_shape is ChatApiShapeV1.OPENAI_COMPATIBLE:
        selected = endpoints.get(binding.endpoint_id or "")
        if selected is None:
            raise ChatServiceError(ChatErrorCodeV1.ENDPOINT_UNSAFE)
        endpoint = selected.base_url.rstrip("/") + "/v1/chat/completions"
        pinned_addresses = selected.pinned_addresses
    if endpoint is None:
        raise ChatServiceError(ChatErrorCodeV1.ENDPOINT_UNSAFE)

    messages = request.messages
    system, converted = _system_and_messages(messages)
    common: dict[str, object]
    if binding.api_shape is ChatApiShapeV1.ANTHROPIC_MESSAGES:
        if not converted:
            raise ChatServiceError(ChatErrorCodeV1.REQUEST_INVALID)
        common = {
            "model": model.model_id,
            "max_tokens": request.max_output_tokens,
            "messages": converted,
            "stream": request.stream,
        }
        if system is not None:
            common["system"] = system
    elif binding.api_shape is ChatApiShapeV1.OPENAI_RESPONSES:
        common = {
            "model": model.model_id,
            "input": [
                {"role": message.role.value, "content": message.content} for message in messages
            ],
            "max_output_tokens": request.max_output_tokens,
            "stream": request.stream,
        }
    else:
        common = {
            "model": model.model_id,
            "messages": [
                {"role": message.role.value, "content": message.content} for message in messages
            ],
            "max_tokens": request.max_output_tokens,
            "stream": request.stream,
        }
    try:
        body_json = json.dumps(common, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
        call = ProviderCallV1(
            api_shape=binding.api_shape,
            endpoint=endpoint,
            pinned_addresses=pinned_addresses,
            model_id=model.model_id,
            messages=request.messages,
            max_output_tokens=request.max_output_tokens,
            timeout_ms=binding.timeout_ms,
            credential=SecretStr(credential),
            body_json=body_json,
        )
    except Exception:
        raise ChatServiceError(ChatErrorCodeV1.REQUEST_INVALID) from None
    return call


def normalize_provider_response(
    api_shape: ChatApiShapeV1, response: ProviderHttpResponseV1
) -> ProviderReplyV1:
    """Parse vendor-specific JSON into a bounded neutral result; discard raw errors."""
    if type(response) is not ProviderHttpResponseV1:
        raise ChatServiceError(ChatErrorCodeV1.PROVIDER_INVALID_RESPONSE)
    if response.status_code == 429:
        raise ChatServiceError(ChatErrorCodeV1.PROVIDER_RATE_LIMITED)
    if not 200 <= response.status_code < 300:
        raise ChatServiceError(ChatErrorCodeV1.PROVIDER_UNAVAILABLE)
    try:
        payload: object = json.loads(response.body.decode("utf-8"))
        if type(payload) is not dict:
            raise ValueError
        if api_shape is ChatApiShapeV1.ANTHROPIC_MESSAGES:
            text, tools = _anthropic_content(payload.get("content"))
            usage_data = payload.get("usage")
            if type(usage_data) is not dict:
                raise ValueError
            usage = ChatUsageV1(
                input_tokens=_required_count(usage_data, "input_tokens"),
                output_tokens=_required_count(usage_data, "output_tokens"),
            )
            finish = _normalize_finish(payload.get("stop_reason"))
        elif api_shape is ChatApiShapeV1.OPENAI_RESPONSES:
            text, tools = _responses_content(payload)
            usage_data = payload.get("usage")
            if type(usage_data) is not dict:
                raise ValueError
            usage = ChatUsageV1(
                input_tokens=_required_count(usage_data, "input_tokens"),
                output_tokens=_required_count(usage_data, "output_tokens"),
            )
            finish = _normalize_finish(payload.get("status"))
        else:
            choices = payload.get("choices")
            if type(choices) is not list or not choices or type(choices[0]) is not dict:
                raise ValueError
            message = choices[0].get("message")
            usage_data = payload.get("usage")
            if type(message) is not dict:
                raise ValueError
            content = message.get("content")
            if content is not None and type(content) is not str:
                raise ValueError
            if type(usage_data) is not dict:
                raise ValueError
            text = content if type(content) is str else ""
            tools = _openai_tools(message.get("tool_calls", []))
            usage = ChatUsageV1(
                input_tokens=_required_count(usage_data, "prompt_tokens"),
                output_tokens=_required_count(usage_data, "completion_tokens"),
            )
            finish = _normalize_finish(choices[0].get("finish_reason"))
        return ProviderReplyV1(
            text=text,
            usage=usage,
            finish_reason=finish,
            tool_proposals=tuple(tools),
        )
    except ChatServiceError:
        raise
    except Exception:
        raise ChatServiceError(ChatErrorCodeV1.PROVIDER_INVALID_RESPONSE) from None


def _anthropic_content(content: object) -> tuple[str, list[ChatToolProposalV1]]:
    if type(content) is not list:
        raise ValueError
    parts: list[str] = []
    tools: list[ChatToolProposalV1] = []
    for block in content:
        if type(block) is not dict:
            raise ValueError
        if block.get("type") == "text" and type(block.get("text")) is str:
            text = block.get("text")
            if type(text) is str:
                parts.append(text)
        elif block.get("type") == "tool_use":
            name = block.get("name")
            arguments = block.get("input")
            if type(name) is not str or type(arguments) is not dict:
                raise ValueError
            tools.append(
                ChatToolProposalV1(
                    name=name,
                    arguments_json=json.dumps(arguments, ensure_ascii=False, separators=(",", ":")),
                )
            )
    return "".join(parts), tools


def _responses_content(payload: dict[str, object]) -> tuple[str, list[ChatToolProposalV1]]:
    output = payload.get("output", [])
    if type(output) is not list:
        raise ValueError
    parts: list[str] = []
    output_text = payload.get("output_text")
    if type(output_text) is str:
        parts.append(output_text)
    tools: list[ChatToolProposalV1] = []
    for item in output:
        if type(item) is not dict:
            raise ValueError
        if item.get("type") == "message":
            if type(output_text) is str:
                continue
            content = item.get("content", [])
            if type(content) is not list:
                raise ValueError
            for block in content:
                if (
                    type(block) is dict
                    and block.get("type") == "output_text"
                    and type(block.get("text")) is str
                ):
                    text = block.get("text")
                    if type(text) is str:
                        parts.append(text)
        elif item.get("type") == "function_call":
            name = item.get("name")
            arguments = item.get("arguments")
            if type(name) is not str or type(arguments) is not str:
                raise ValueError
            tools.append(ChatToolProposalV1(name=name, arguments_json=arguments))
    return "".join(parts), tools


def _openai_tools(values: object) -> list[ChatToolProposalV1]:
    if type(values) is not list:
        raise ValueError
    output: list[ChatToolProposalV1] = []
    for item in values:
        function = item.get("function") if type(item) is dict else None
        if type(function) is not dict:
            raise ValueError
        name = function.get("name")
        arguments = function.get("arguments")
        if type(name) is not str or type(arguments) is not str:
            raise ValueError
        output.append(
            ChatToolProposalV1(
                name=name,
                arguments_json=arguments,
            )
        )
    return output


def _required_count(value: dict[str, object], key: str) -> int:
    count = value.get(key)
    if type(count) is not int or count < 0 or count > 1_000_000_000:
        raise ValueError
    return count


def _normalize_finish(value: object) -> str:
    if value in ("stop", "end_turn", "tool_use", "tool_calls", "completed"):
        return "tool_calls" if value in ("tool_use", "tool_calls") else "stop"
    if value in ("length", "max_tokens", "incomplete"):
        return "length"
    raise ChatServiceError(ChatErrorCodeV1.PROVIDER_INVALID_RESPONSE)


async def normalize_provider_stream(
    api_shape: ChatApiShapeV1, chunks: AsyncIterator[bytes]
) -> AsyncIterator[ProviderChunkV1]:
    """Parse bounded server-sent JSON frames; no vendor error/body text escapes."""
    buffer = bytearray()
    input_tokens: int | None = None
    output_tokens: int | None = None
    finish: str | None = None
    frame_count = 0
    received_bytes = 0
    tool_states: dict[str, dict[str, str]] = {}

    def consume_frame(
        frame: bytes,
    ) -> tuple[list[ProviderChunkV1], tuple[int | None, int | None], str | None] | None:
        nonlocal frame_count
        lines = [line[5:].lstrip() for line in frame.splitlines() if line.startswith(b"data:")]
        if not lines:
            return None
        frame_count += 1
        if frame_count > 10_000:
            raise ChatServiceError(ChatErrorCodeV1.PROVIDER_INVALID_RESPONSE)
        raw_data = b"\n".join(lines)
        if raw_data == b"[DONE]":
            return None
        try:
            event: object = json.loads(raw_data.decode("utf-8"))
            if type(event) is not dict:
                raise ValueError
            normalized, counts, event_finish = _stream_frame(api_shape, event, tool_states)
            return normalized, counts, event_finish
        except ChatServiceError:
            raise
        except Exception:
            raise ChatServiceError(ChatErrorCodeV1.PROVIDER_INVALID_RESPONSE) from None

    async for chunk in chunks:
        if type(chunk) is not bytes:
            raise ChatServiceError(ChatErrorCodeV1.PROVIDER_INVALID_RESPONSE)
        received_bytes += len(chunk)
        if received_bytes > 2_100_000:
            raise ChatServiceError(ChatErrorCodeV1.PROVIDER_INVALID_RESPONSE)
        buffer.extend(chunk)
        while b"\n\n" in buffer or b"\r\n\r\n" in buffer:
            delimiters = tuple(
                (position, delimiter)
                for delimiter in (b"\n\n", b"\r\n\r\n")
                if (position := buffer.find(delimiter)) >= 0
            )
            end, delimiter = min(delimiters, key=lambda item: item[0])
            frame = bytes(buffer[:end])
            del buffer[: end + len(delimiter)]
            result = consume_frame(frame)
            if result is None:
                continue
            normalized, counts, event_finish = result
            input_tokens = counts[0] if counts[0] is not None else input_tokens
            output_tokens = counts[1] if counts[1] is not None else output_tokens
            finish = event_finish or finish
            for item in normalized:
                yield item
    if buffer.strip():
        result = consume_frame(bytes(buffer))
        if result is not None:
            normalized, counts, event_finish = result
            input_tokens = counts[0] if counts[0] is not None else input_tokens
            output_tokens = counts[1] if counts[1] is not None else output_tokens
            finish = event_finish or finish
            for item in normalized:
                yield item
    if input_tokens is None or output_tokens is None or finish is None:
        raise ChatServiceError(ChatErrorCodeV1.PROVIDER_INVALID_RESPONSE)
    yield ProviderChunkV1(
        kind="usage", usage=ChatUsageV1(input_tokens=input_tokens, output_tokens=output_tokens)
    )
    yield ProviderChunkV1(kind="finish", finish_reason=finish)


def _stream_frame(
    api_shape: ChatApiShapeV1,
    event: dict[str, object],
    tool_states: dict[str, dict[str, str]],
) -> tuple[list[ProviderChunkV1], tuple[int | None, int | None], str | None]:
    output: list[ProviderChunkV1] = []
    input_count: int | None = None
    output_count: int | None = None
    finish: str | None = None
    if api_shape is ChatApiShapeV1.ANTHROPIC_MESSAGES:
        kind = event.get("type")
        if kind == "message_start":
            message = event.get("message")
            usage = message.get("usage") if type(message) is dict else None
            input_count = usage.get("input_tokens") if type(usage) is dict else None
        elif kind == "content_block_delta":
            delta = event.get("delta")
            text = delta.get("text") if type(delta) is dict else None
            if type(text) is str and text:
                output.append(ProviderChunkV1(kind="text_delta", text_delta=text))
            elif type(delta) is dict and delta.get("type") == "input_json_delta":
                index = event.get("index")
                partial = delta.get("partial_json")
                if type(index) is not int or type(partial) is not str:
                    raise ChatServiceError(ChatErrorCodeV1.PROVIDER_INVALID_RESPONSE)
                state = tool_states.setdefault(str(index), {"name": "", "arguments": ""})
                state["arguments"] += partial
        elif kind == "content_block_start":
            index = event.get("index")
            block = event.get("content_block")
            if type(index) is int and type(block) is dict and block.get("type") == "tool_use":
                name, initial = block.get("name"), block.get("input", {})
                if type(name) is not str or type(initial) is not dict:
                    raise ChatServiceError(ChatErrorCodeV1.PROVIDER_INVALID_RESPONSE)
                tool_states[str(index)] = {
                    "name": name,
                    "arguments": "",
                }
        elif kind == "content_block_stop":
            index = event.get("index")
            if type(index) is int:
                key = str(index)
                stopped_state = tool_states.get(key)
                if stopped_state is not None:
                    del tool_states[key]
                    output.append(_tool_chunk(stopped_state))
        elif kind == "message_delta":
            usage = event.get("usage")
            output_count = usage.get("output_tokens") if type(usage) is dict else None
            delta = event.get("delta")
            stop = delta.get("stop_reason") if type(delta) is dict else None
            if stop is not None:
                finish = _normalize_finish(stop)
    elif api_shape is ChatApiShapeV1.OPENAI_RESPONSES:
        kind = event.get("type")
        delta_text = event.get("delta")
        if kind == "response.output_text.delta" and type(delta_text) is str and delta_text:
            output.append(ProviderChunkV1(kind="text_delta", text_delta=delta_text))
        elif kind == "response.output_item.added":
            index, item = event.get("output_index"), event.get("item")
            if type(index) is int and type(item) is dict and item.get("type") == "function_call":
                name = item.get("name")
                arguments = item.get("arguments", "")
                if type(name) is not str or type(arguments) is not str:
                    raise ChatServiceError(ChatErrorCodeV1.PROVIDER_INVALID_RESPONSE)
                tool_states[str(index)] = {"name": name, "arguments": arguments}
        elif kind == "response.function_call_arguments.delta":
            index, delta = event.get("output_index"), event.get("delta")
            if type(index) is not int or type(delta) is not str:
                raise ChatServiceError(ChatErrorCodeV1.PROVIDER_INVALID_RESPONSE)
            state = tool_states.setdefault(str(index), {"name": "", "arguments": ""})
            state["arguments"] += delta
        elif kind == "response.function_call_arguments.done":
            index, arguments = event.get("output_index"), event.get("arguments")
            if type(index) is not int or type(arguments) is not str:
                raise ChatServiceError(ChatErrorCodeV1.PROVIDER_INVALID_RESPONSE)
            state = tool_states.setdefault(str(index), {"name": "", "arguments": ""})
            state["arguments"] = arguments
            output.append(_tool_chunk(tool_states.pop(str(index))))
        elif kind == "response.output_item.done":
            index, item = event.get("output_index"), event.get("item")
            if type(index) is int and type(item) is dict and item.get("type") == "function_call":
                name, arguments = item.get("name"), item.get("arguments")
                if type(name) is not str or type(arguments) is not str:
                    raise ChatServiceError(ChatErrorCodeV1.PROVIDER_INVALID_RESPONSE)
                output.append(_tool_chunk({"name": name, "arguments": arguments}))
        elif kind == "response.completed":
            response = event.get("response")
            usage = response.get("usage") if type(response) is dict else None
            if type(usage) is dict:
                input_count = usage.get("input_tokens")
                output_count = usage.get("output_tokens")
            if type(response) is dict:
                finish = _normalize_finish(response.get("status"))
            for key in sorted(tool_states):
                output.append(_tool_chunk(tool_states[key]))
            tool_states.clear()
    else:
        choices = event.get("choices")
        if type(choices) is list and choices and type(choices[0]) is dict:
            choice = choices[0]
            delta = choice.get("delta")
            text = delta.get("content") if type(delta) is dict else None
            if type(text) is str and text:
                output.append(ProviderChunkV1(kind="text_delta", text_delta=text))
            calls = delta.get("tool_calls", []) if type(delta) is dict else []
            if type(calls) is not list:
                raise ChatServiceError(ChatErrorCodeV1.PROVIDER_INVALID_RESPONSE)
            for call in calls:
                if type(call) is not dict or type(call.get("index")) is not int:
                    raise ChatServiceError(ChatErrorCodeV1.PROVIDER_INVALID_RESPONSE)
                state = tool_states.setdefault(str(call["index"]), {"name": "", "arguments": ""})
                function = call.get("function")
                if type(function) is dict:
                    name, arguments = function.get("name"), function.get("arguments")
                    if type(name) is str:
                        state["name"] += name
                    if type(arguments) is str:
                        state["arguments"] += arguments
            reason = choice.get("finish_reason")
            if reason is not None:
                finish = _normalize_finish(reason)
                for key in sorted(tool_states):
                    output.append(_tool_chunk(tool_states[key]))
                tool_states.clear()
        usage = event.get("usage")
        if type(usage) is dict:
            input_count = usage.get("prompt_tokens")
            output_count = usage.get("completion_tokens")
    for count in (input_count, output_count):
        if count is not None and (type(count) is not int or count < 0):
            raise ChatServiceError(ChatErrorCodeV1.PROVIDER_INVALID_RESPONSE)
    return output, (input_count, output_count), finish


def _tool_chunk(state: dict[str, str]) -> ProviderChunkV1:
    try:
        proposal = ChatToolProposalV1(
            name=state["name"],
            arguments_json=state["arguments"],
        )
    except Exception:
        raise ChatServiceError(ChatErrorCodeV1.PROVIDER_INVALID_RESPONSE) from None
    return ProviderChunkV1(kind="tool_proposal", tool_proposal=proposal)


__all__ = ["build_provider_call", "normalize_provider_response", "normalize_provider_stream"]
