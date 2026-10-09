"""Typed ports and trusted configuration for CHAT-001 provider calls."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import AsyncIterator, Callable
from decimal import Decimal
from typing import Literal, Protocol
from urllib.parse import urlsplit

from pydantic import (
    Field,
    SecretStr,
    StrictBool,
    StrictInt,
    field_validator,
    model_validator,
)

from leviathan_core.agent_council.model_registry import ModelRegistryEntryV1
from leviathan_core.numeric import parse_decimal
from leviathan_core.security.authz_models import TrustedPrincipalV1

from .models import (
    ChatApiShapeV1,
    ChatMessageV1,
    ChatModelPublicV1,
    ChatRequestV1,
    ChatResultV1,
    ChatStreamEventV1,
    ChatToolProposalV1,
    ChatUsageV1,
    _StrictModel,
)

_ID = re.compile(r"[A-Za-z][A-Za-z0-9_.:-]{0,127}\Z", re.ASCII)
_MAX_NS = 2**63 - 1


class ChatModelBindingV1(_StrictModel):
    """Admin-owned binding of one approved AGENT-003 entry to a closed API shape."""

    entry_id: str
    api_shape: ChatApiShapeV1
    endpoint_id: str | None = None
    timeout_ms: StrictInt = Field(gt=0, le=120_000)
    max_retries: Literal[0] = 0

    @field_validator("entry_id", "endpoint_id")
    @classmethod
    def valid_id(cls, value: str | None) -> str | None:
        if value is not None and _ID.fullmatch(value) is None:
            raise ValueError("identifier invalid")
        return value

    @model_validator(mode="after")
    def coherent(self) -> ChatModelBindingV1:
        if (self.api_shape is ChatApiShapeV1.OPENAI_COMPATIBLE) != (self.endpoint_id is not None):
            raise ValueError("compatible endpoint binding invalid")
        return self


class TrustedCompatibleEndpointV1(_StrictModel):
    """Explicit server-side compatible endpoint with DNS addresses pinned at config time."""

    endpoint_id: str
    base_url: str = Field(min_length=1, max_length=2_048)
    pinned_addresses: tuple[str, ...] = Field(min_length=1, max_length=16)
    allow_private_network: StrictBool = False
    local_endpoint: StrictBool = False

    @field_validator("endpoint_id")
    @classmethod
    def valid_id(cls, value: str) -> str:
        if _ID.fullmatch(value) is None:
            raise ValueError("identifier invalid")
        return value

    @field_validator("pinned_addresses")
    @classmethod
    def valid_addresses(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(values)) != len(values):
            raise ValueError("duplicate address")
        for value in values:
            try:
                ipaddress.ip_address(value)
            except ValueError as exc:
                raise ValueError("invalid pinned address") from exc
        return values

    @model_validator(mode="after")
    def safe_endpoint(self) -> TrustedCompatibleEndpointV1:
        parts = urlsplit(self.base_url)
        if (
            parts.scheme not in ("https", "http")
            or not parts.hostname
            or parts.username is not None
            or parts.password is not None
            or parts.query
            or parts.fragment
            or parts.path not in ("", "/")
        ):
            raise ValueError("endpoint invalid")
        try:
            ipaddress.ip_address(parts.hostname)
            host_is_ip = True
        except ValueError:
            host_is_ip = False
        if self.local_endpoint:
            if parts.scheme != "http" or not self.allow_private_network:
                raise ValueError("local endpoint requires explicit private HTTP allowance")
            if any(
                not ipaddress.ip_address(address).is_loopback for address in self.pinned_addresses
            ):
                raise ValueError("local endpoint address must be loopback")
            if not (
                parts.hostname == "localhost"
                or (host_is_ip and ipaddress.ip_address(parts.hostname).is_loopback)
            ):
                raise ValueError("local endpoint host must be loopback")
        else:
            if parts.scheme != "https" or self.allow_private_network:
                raise ValueError("public compatible endpoint must use HTTPS")
            for address in self.pinned_addresses:
                ip = ipaddress.ip_address(address)
                if not ip.is_global:
                    raise ValueError("unsafe pinned address")
            if host_is_ip and not ipaddress.ip_address(parts.hostname).is_global:
                raise ValueError("unsafe endpoint host")
        return self


class ChatPolicyDecisionV1(_StrictModel):
    allowed: StrictBool
    code: str = Field(min_length=1, max_length=64)
    policy_version: str = Field(min_length=1, max_length=32)
    remaining_cost_usd: Decimal
    max_output_tokens: StrictInt = Field(gt=0, le=1_000_000_000)
    remaining_tokens: StrictInt = Field(ge=0, le=1_000_000_000)

    @field_validator("remaining_cost_usd", mode="before")
    @classmethod
    def valid_remaining_cost(cls, value: object) -> Decimal:
        return parse_decimal(value, field="remaining_cost_usd", min_value="0", max_value="1000000")


class ChatPolicyPort(Protocol):
    """Account authorization, alias allowlist, capability and budget decision.

    Implementations are the cross-process authority for the current token/cost
    budget decision. The service checks the bounded estimate before any provider
    call; the local rate window is only an abuse guard.
    """

    def authorize(
        self,
        principal: TrustedPrincipalV1,
        request: ChatRequestV1,
        model: ModelRegistryEntryV1,
    ) -> ChatPolicyDecisionV1: ...


class ChatDisclosurePort(Protocol):
    """Read the server-side record of the account holder's one-time egress notice."""

    def acknowledged(self, principal: TrustedPrincipalV1, provider: str) -> bool: ...


ChatSecretResolver = Callable[[str], str | None]


class ChatPriceV1(_StrictModel):
    model_alias: str
    input_usd_per_million_tokens: Decimal
    output_usd_per_million_tokens: Decimal

    @field_validator("model_alias")
    @classmethod
    def valid_alias(cls, value: str) -> str:
        if _ID.fullmatch(value) is None:
            raise ValueError("identifier invalid")
        return value

    @field_validator("input_usd_per_million_tokens", "output_usd_per_million_tokens", mode="before")
    @classmethod
    def valid_price(cls, value: object) -> Decimal:
        return parse_decimal(value, field="price", min_value="0", max_value="1000000")


class ChatPriceScheduleV1(_StrictModel):
    version: str
    prices: tuple[ChatPriceV1, ...] = Field(max_length=256)

    @model_validator(mode="after")
    def unique_aliases(self) -> ChatPriceScheduleV1:
        aliases = tuple(item.model_alias for item in self.prices)
        if len(set(aliases)) != len(aliases):
            raise ValueError("duplicate price alias")
        return self


class ProviderCallV1(_StrictModel):
    api_shape: ChatApiShapeV1
    endpoint: str = Field(min_length=1, max_length=2_048)
    pinned_addresses: tuple[str, ...] = Field(max_length=16)
    model_id: str = Field(min_length=1, max_length=128)
    messages: tuple[ChatMessageV1, ...] = Field(min_length=1, max_length=64)
    max_output_tokens: StrictInt = Field(gt=0, le=8_192)
    timeout_ms: StrictInt = Field(gt=0, le=120_000)
    follow_redirects: Literal[False] = False
    credential: SecretStr
    body_json: str = Field(min_length=2, max_length=300_000)

    def __repr__(self) -> str:
        return (
            "ProviderCallV1(api_shape="
            + repr(self.api_shape)
            + ", endpoint=<redacted>, model_id=<approved>, credential=<redacted>)"
        )


class ProviderReplyV1(_StrictModel):
    text: str = Field(max_length=1_000_000)
    usage: ChatUsageV1
    finish_reason: str = Field(min_length=1, max_length=32)
    tool_proposals: tuple[ChatToolProposalV1, ...] = Field(max_length=64)


class ProviderHttpResponseV1(_StrictModel):
    status_code: StrictInt = Field(ge=100, le=599)
    body: bytes = Field(max_length=2_000_000)


class ProviderChunkV1(_StrictModel):
    kind: str = Field(pattern=r"^(text_delta|usage|tool_proposal|finish)$")
    text_delta: str | None = Field(default=None, max_length=16_384)
    usage: ChatUsageV1 | None = None
    tool_proposal: ChatToolProposalV1 | None = None
    finish_reason: str | None = Field(default=None, max_length=32)

    @model_validator(mode="after")
    def coherent(self) -> ProviderChunkV1:
        active = sum(
            value is not None
            for value in (self.text_delta, self.usage, self.tool_proposal, self.finish_reason)
        )
        if active != 1:
            raise ValueError("invalid provider chunk")
        if self.kind == "text_delta" and self.text_delta is None:
            raise ValueError("invalid provider chunk")
        if self.kind == "usage" and self.usage is None:
            raise ValueError("invalid provider chunk")
        if self.kind == "tool_proposal" and self.tool_proposal is None:
            raise ValueError("invalid provider chunk")
        if self.kind == "finish" and self.finish_reason is None:
            raise ValueError("invalid provider chunk")
        return self


class ChatTransportPort(Protocol):
    """Injected HTTP transport with strict egress requirements.

    Implementations must dial a configured compatible endpoint only through its
    supplied pinned addresses, preserve the configured hostname for TLS SNI and
    certificate checks, enforce call.timeout_ms, and never follow redirects.
    Hosted endpoints are fixed by the adapter and receive no caller URL.
    """

    async def complete(self, call: ProviderCallV1) -> ProviderHttpResponseV1: ...

    def stream(self, call: ProviderCallV1) -> AsyncIterator[bytes]: ...


class ChatModelPort(Protocol):
    """Typed provider-neutral application boundary consumed by the router."""

    def list_models(self, principal: TrustedPrincipalV1) -> tuple[ChatModelPublicV1, ...]: ...

    async def complete(
        self, principal: TrustedPrincipalV1, request: ChatRequestV1
    ) -> ChatResultV1: ...

    def stream(
        self, principal: TrustedPrincipalV1, request: ChatRequestV1
    ) -> AsyncIterator[ChatStreamEventV1]: ...


class ProviderTransportError(ValueError):
    """Fixed provider transport failure with no retained vendor response text."""

    def __init__(
        self,
        code: Literal[
            "PROVIDER_UNAVAILABLE",
            "PROVIDER_RATE_LIMITED",
            "PROVIDER_TIMEOUT",
            "PROVIDER_INVALID_RESPONSE",
        ],
    ) -> None:
        if code not in {
            "PROVIDER_UNAVAILABLE",
            "PROVIDER_RATE_LIMITED",
            "PROVIDER_TIMEOUT",
            "PROVIDER_INVALID_RESPONSE",
        }:
            raise TypeError("CHAT_PROVIDER_ERROR_INVALID")
        self.code = code
        super().__init__(code)


__all__ = [
    "ChatDisclosurePort",
    "ChatModelBindingV1",
    "ChatModelPort",
    "ChatPolicyDecisionV1",
    "ChatPolicyPort",
    "ChatPriceScheduleV1",
    "ChatPriceV1",
    "ChatSecretResolver",
    "ChatTransportPort",
    "ProviderCallV1",
    "ProviderChunkV1",
    "ProviderHttpResponseV1",
    "ProviderReplyV1",
    "ProviderTransportError",
    "TrustedCompatibleEndpointV1",
]
