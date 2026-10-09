"""Strict, provider-neutral CHAT-001 request, event, and result models."""

from __future__ import annotations

import json
import re
from decimal import Decimal
from enum import StrEnum
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    field_validator,
    model_validator,
)

_IDENTIFIER = re.compile(r"[A-Za-z][A-Za-z0-9_.:-]{0,127}\Z", re.ASCII)
_MAX_NS = 2**63 - 1
MAX_MESSAGES = 64
MAX_MESSAGE_CHARS = 32_768
MAX_TOTAL_MESSAGE_BYTES = 262_144
MAX_OUTPUT_TOKENS = 8_192


class ChatRoleV1(StrEnum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"


class ChatApiShapeV1(StrEnum):
    ANTHROPIC_MESSAGES = "anthropic_messages"
    OPENAI_CHAT_COMPLETIONS = "openai_chat_completions"
    OPENAI_RESPONSES = "openai_responses"
    OPENAI_COMPATIBLE = "openai_compatible"


class ChatErrorCodeV1(StrEnum):
    AUTH_REQUIRED = "AUTH_REQUIRED"
    REQUEST_INVALID = "REQUEST_INVALID"
    MODEL_NOT_ALLOWED = "MODEL_NOT_ALLOWED"
    POLICY_DENIED = "POLICY_DENIED"
    BUDGET_EXCEEDED = "BUDGET_EXCEEDED"
    RATE_LIMITED = "RATE_LIMITED"
    DISCLOSURE_REQUIRED = "DISCLOSURE_REQUIRED"
    CREDENTIAL_UNAVAILABLE = "CREDENTIAL_UNAVAILABLE"
    ENDPOINT_UNSAFE = "ENDPOINT_UNSAFE"
    PROVIDER_UNAVAILABLE = "PROVIDER_UNAVAILABLE"
    PROVIDER_RATE_LIMITED = "PROVIDER_RATE_LIMITED"
    PROVIDER_TIMEOUT = "PROVIDER_TIMEOUT"
    PROVIDER_INVALID_RESPONSE = "PROVIDER_INVALID_RESPONSE"
    CANCELLED = "CANCELLED"


class ChatServiceError(ValueError):
    """A content-free service error; no caller or provider text is retained."""

    def __init__(self, code: ChatErrorCodeV1) -> None:
        self.code = code
        super().__init__(code.value)


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, hide_input_in_errors=True)


class ChatMessageV1(_StrictModel):
    role: ChatRoleV1
    content: str = Field(min_length=1, max_length=MAX_MESSAGE_CHARS)


class ChatRequestV1(_StrictModel):
    request_id: str
    model_alias: str
    messages: tuple[ChatMessageV1, ...] = Field(min_length=1, max_length=MAX_MESSAGES)
    max_output_tokens: StrictInt = Field(gt=0, le=MAX_OUTPUT_TOKENS)
    stream: StrictBool = False
    hosted_egress_disclosed: StrictBool = False

    @field_validator("request_id", "model_alias")
    @classmethod
    def valid_identifier(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("identifier invalid")
        return value

    @model_validator(mode="after")
    def bounded_content(self) -> ChatRequestV1:
        if (
            sum(len(message.content.encode("utf-8")) for message in self.messages)
            > MAX_TOTAL_MESSAGE_BYTES
        ):
            raise ValueError("message size invalid")
        return self


class ChatUsageV1(_StrictModel):
    input_tokens: StrictInt = Field(ge=0, le=1_000_000_000)
    output_tokens: StrictInt = Field(ge=0, le=1_000_000_000)


class ChatToolProposalV1(_StrictModel):
    """Untrusted, non-executable provider proposal preserved as bounded JSON."""

    name: str = Field(min_length=1, max_length=128)
    arguments_json: str = Field(max_length=8_192)

    @field_validator("name")
    @classmethod
    def valid_name(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("tool name invalid")
        return value

    @field_validator("arguments_json")
    @classmethod
    def valid_arguments(cls, value: str) -> str:
        try:
            parsed = json.loads(value)
        except Exception as exc:
            raise ValueError("tool arguments invalid") from exc
        if type(parsed) is not dict:
            raise ValueError("tool arguments invalid")
        return value


class ChatRequestRecordV1(_StrictModel):
    request_id: str
    model_alias: str
    api_shape: ChatApiShapeV1
    registry_version: str
    policy_version: str
    elapsed_ns: StrictInt = Field(ge=0, le=_MAX_NS)
    usage: ChatUsageV1
    cost_status: Literal["available", "unavailable"]
    cost_usd: str | None = None
    hosted_egress_disclosed: StrictBool

    @model_validator(mode="after")
    def coherent_cost(self) -> ChatRequestRecordV1:
        if (self.cost_status == "available") != (self.cost_usd is not None):
            raise ValueError("invalid cost status")
        if self.cost_usd is not None:
            try:
                value = Decimal(self.cost_usd)
            except Exception as exc:
                raise ValueError("invalid cost") from exc
            if not value.is_finite() or value < 0:
                raise ValueError("invalid cost")
        return self


class ChatStreamEventV1(_StrictModel):
    event: Literal["start", "text_delta", "usage", "tool_proposal", "finish", "error", "record"]
    request_id: str
    text_delta: str | None = None
    usage: ChatUsageV1 | None = None
    finish_reason: Literal["stop", "length", "tool_calls"] | None = None
    tool_proposal: ChatToolProposalV1 | None = None
    error_code: ChatErrorCodeV1 | None = None
    record: ChatRequestRecordV1 | None = None

    @field_validator("request_id")
    @classmethod
    def valid_request_id(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("identifier invalid")
        return value

    @model_validator(mode="after")
    def event_shape(self) -> ChatStreamEventV1:
        values = {
            "text_delta": self.text_delta,
            "usage": self.usage,
            "tool_proposal": self.tool_proposal,
            "finish": self.finish_reason,
            "error": self.error_code,
            "record": self.record,
        }
        active = [name for name, value in values.items() if value is not None]
        if self.event == "start":
            if active:
                raise ValueError("invalid event shape")
        elif active != [self.event]:
            raise ValueError("invalid event shape")
        if self.text_delta is not None and len(self.text_delta.encode("utf-8")) > 16_384:
            raise ValueError("delta too large")
        return self


class ChatResultV1(_StrictModel):
    events: tuple[ChatStreamEventV1, ...] = Field(max_length=4_096)
    record: ChatRequestRecordV1


class ChatModelPublicV1(_StrictModel):
    alias: str
    provider: str
    model_version: str
    registry_version: str
    modalities: tuple[str, ...]
    max_context_tokens: StrictInt
    max_output_tokens: StrictInt


__all__ = [
    "MAX_MESSAGES",
    "MAX_MESSAGE_CHARS",
    "MAX_OUTPUT_TOKENS",
    "MAX_TOTAL_MESSAGE_BYTES",
    "ChatApiShapeV1",
    "ChatErrorCodeV1",
    "ChatMessageV1",
    "ChatModelPublicV1",
    "ChatRequestRecordV1",
    "ChatRequestV1",
    "ChatResultV1",
    "ChatRoleV1",
    "ChatServiceError",
    "ChatStreamEventV1",
    "ChatToolProposalV1",
    "ChatUsageV1",
]
