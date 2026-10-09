"""Typed, injected ports and response DTOs for the local connections API.

The runtime deliberately contains no credential values or provider transport.
Credential entry is delegated to CRED-UI-001, while these ports expose only
catalog, status and short-lived connection workflow metadata.
"""

from __future__ import annotations

import base64
import binascii
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal, Protocol
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class ProviderV1(StrEnum):
    IBKR = "ibkr"
    ALPACA = "alpaca"
    MT5 = "mt5"
    MCP = "mcp"
    SNAPTRADE = "snaptrade"
    TASTYTRADE = "tastytrade"
    CTRADER = "ctrader"
    COINBASE = "coinbase"
    KRAKEN = "kraken"
    BINANCE_US = "binance_us"
    FOREX_COM_MT5 = "forex_com_mt5"
    RITHMIC = "rithmic"
    KALSHI = "kalshi"
    ANTHROPIC = "anthropic"
    OPENAI = "openai"
    OPENAI_COMPATIBLE = "openai_compatible"


class CapabilityV1(StrEnum):
    ACCOUNT_READ = "ACCOUNT_READ"
    BALANCE_READ = "BALANCE_READ"
    POSITION_READ = "POSITION_READ"
    QUOTE_READ = "QUOTE_READ"
    HISTORICAL_DATA_READ = "HISTORICAL_DATA_READ"
    ORDER_SUBMIT = "ORDER_SUBMIT"
    ORDER_CANCEL = "ORDER_CANCEL"
    ORDER_STATUS = "ORDER_STATUS"
    STREAMING = "STREAMING"
    OAUTH_CONNECT = "OAUTH_CONNECT"
    API_KEY_CONNECT = "API_KEY_CONNECT"
    MT5_LOGIN_CONNECT = "MT5_LOGIN_CONNECT"
    AI_INFERENCE = "AI_INFERENCE"


class EnvironmentV1(StrEnum):
    DEVELOPMENT = "DEVELOPMENT"
    TEST = "TEST"
    PAPER = "PAPER"
    DEMO = "DEMO"
    TESTNET = "TESTNET"
    LIVE = "LIVE"


AuthMethodV1 = Literal["oauth", "api_key", "mt5_login"]


class _DTO(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        hide_input_in_errors=True,
        validate_default=True,
    )


def _valid_host(value: str) -> bool:
    try:
        parsed = urlsplit(f"https://{value}")
        return (
            bool(parsed.hostname)
            and parsed.username is None
            and parsed.password is None
            and parsed.path == ""
            and parsed.query == ""
            and parsed.fragment == ""
            and parsed.netloc == value
            and (parsed.port is None or 1 <= parsed.port <= 65535)
        )
    except (ValueError, TypeError):
        return False


class ConnectionCatalogEntryV1(_DTO):
    provider_id: ProviderV1
    capabilities: tuple[CapabilityV1, ...] = Field(max_length=32)
    environments: tuple[EnvironmentV1, ...] = Field(min_length=1, max_length=6)
    auth_method: AuthMethodV1
    default_route: bool

    @model_validator(mode="after")
    def _unique_values(self) -> ConnectionCatalogEntryV1:
        if len(set(self.capabilities)) != len(self.capabilities):
            raise ValueError("INVALID_CONNECTION_SNAPSHOT")
        if len(set(self.environments)) != len(self.environments):
            raise ValueError("INVALID_CONNECTION_SNAPSHOT")
        return self


class ConnectionCatalogV1(_DTO):
    providers: tuple[ConnectionCatalogEntryV1, ...] = Field(max_length=64)

    @model_validator(mode="after")
    def _unique_providers(self) -> ConnectionCatalogV1:
        if len({row.provider_id for row in self.providers}) != len(self.providers):
            raise ValueError("INVALID_CONNECTION_SNAPSHOT")
        return self


class ConnectionStateV1(StrEnum):
    DISCONNECTED = "DISCONNECTED"
    PENDING = "PENDING"
    CONNECTED = "CONNECTED"
    ERROR = "ERROR"


class ConnectionStatusV1(_DTO):
    provider_id: ProviderV1
    environment: EnvironmentV1
    state: ConnectionStateV1
    configured: bool


_STATE = re.compile(r"[A-Za-z0-9_-]+\Z", re.ASCII)
_ENTRY_HANDLE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{7,127}\Z", re.ASCII)
_DECIMAL_NS = re.compile(r"(?:0|[1-9][0-9]{0,19})\Z", re.ASCII)
_REQUEST_ID = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}\Z", re.ASCII)


class ConnectInitiateV1(_DTO):
    provider_id: ProviderV1
    environment: EnvironmentV1
    auth_method: Literal["oauth"]
    authorization_url: str = Field(min_length=1, max_length=2048)
    authorization_host: str = Field(min_length=1, max_length=253)
    redirect_uri: str = Field(min_length=1, max_length=128)
    state: str = Field(min_length=43, max_length=256, repr=False)
    expires_at_ns: str = Field(min_length=1, max_length=20)
    single_use: Literal[True]
    request_id: str = Field(min_length=1, max_length=64)

    @field_validator("state")
    @classmethod
    def _valid_state(cls, value: str) -> str:
        if _STATE.fullmatch(value) is None or "=" in value:
            raise ValueError("INVALID_CONNECTION_SNAPSHOT")
        try:
            decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        except (ValueError, binascii.Error):
            raise ValueError("INVALID_CONNECTION_SNAPSHOT") from None
        if (
            len(decoded) < 32
            or base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != value
        ):
            raise ValueError("INVALID_CONNECTION_SNAPSHOT")
        return value

    @field_validator("authorization_url")
    @classmethod
    def _https_authorization_url(cls, value: str) -> str:
        try:
            parsed = urlsplit(value)
            valid = (
                parsed.scheme == "https"
                and bool(parsed.hostname)
                and parsed.username is None
                and parsed.password is None
                and parsed.fragment == ""
                and parsed.netloc != ""
            )
        except (ValueError, TypeError):
            valid = False
        if not valid:
            raise ValueError("INVALID_CONNECTION_SNAPSHOT")
        return value

    @field_validator("authorization_host")
    @classmethod
    def _valid_authorization_host(cls, value: str) -> str:
        if value != value.lower() or not _valid_host(value):
            raise ValueError("INVALID_CONNECTION_SNAPSHOT")
        return value

    @field_validator("redirect_uri")
    @classmethod
    def _valid_redirect_uri(cls, value: str) -> str:
        if re.fullmatch(r"http://127\.0\.0\.1:[1-9][0-9]{0,4}/callback", value, re.ASCII) is None:
            raise ValueError("INVALID_CONNECTION_SNAPSHOT")
        port_text = value.rsplit(":", 1)[1].split("/", 1)[0]
        if int(port_text) > 65535:
            raise ValueError("INVALID_CONNECTION_SNAPSHOT")
        return value

    @field_validator("expires_at_ns")
    @classmethod
    def _valid_expiry(cls, value: str) -> str:
        if _DECIMAL_NS.fullmatch(value) is None:
            raise ValueError("INVALID_CONNECTION_SNAPSHOT")
        return value

    @field_validator("request_id")
    @classmethod
    def _valid_request_id(cls, value: str) -> str:
        if _REQUEST_ID.fullmatch(value) is None:
            raise ValueError("INVALID_CONNECTION_SNAPSHOT")
        return value


class CredentialConnectInitiateV1(_DTO):
    provider_id: ProviderV1
    environment: EnvironmentV1
    auth_method: Literal["api_key", "mt5_login"]
    credential_entry_handle: str = Field(min_length=8, max_length=128)

    @field_validator("credential_entry_handle")
    @classmethod
    def _valid_entry_handle(cls, value: str) -> str:
        if _ENTRY_HANDLE.fullmatch(value) is None:
            raise ValueError("INVALID_CONNECTION_SNAPSHOT")
        return value


ConnectInitiationV1 = ConnectInitiateV1 | CredentialConnectInitiateV1


class ConnectionActionResultV1(StrEnum):
    CANCELLED = "CANCELLED"
    DISCONNECTED = "DISCONNECTED"
    ALREADY_DISCONNECTED = "ALREADY_DISCONNECTED"


class ConnectionActionV1(_DTO):
    provider_id: ProviderV1
    environment: EnvironmentV1
    result: ConnectionActionResultV1


class ConnectionCatalogPortV1(Protocol):
    def get_catalog(self, project_id: str) -> ConnectionCatalogV1: ...


class ConnectionStatusPortV1(Protocol):
    def get_status(
        self, project_id: str, environment: EnvironmentV1
    ) -> tuple[ConnectionStatusV1, ...]: ...


class ConnectionInitiatePortV1(Protocol):
    def initiate_connect(
        self, project_id: str, provider: ProviderV1, environment: EnvironmentV1
    ) -> ConnectInitiationV1: ...


class ConnectionCancelPortV1(Protocol):
    def cancel_connect(
        self, project_id: str, provider: ProviderV1, environment: EnvironmentV1
    ) -> ConnectionActionV1: ...


class ConnectionDisconnectPortV1(Protocol):
    def disconnect(
        self, project_id: str, provider: ProviderV1, environment: EnvironmentV1
    ) -> ConnectionActionV1: ...


@dataclass(frozen=True, slots=True)
class ConnectionsRuntimeV1:
    catalog_port: ConnectionCatalogPortV1 | None = None
    status_port: ConnectionStatusPortV1 | None = None
    connect_port: ConnectionInitiatePortV1 | None = None
    cancel_port: ConnectionCancelPortV1 | None = None
    disconnect_port: ConnectionDisconnectPortV1 | None = None
    clock_ns: Callable[[], int] = time.time_ns
    oauth_host_allowlist: tuple[tuple[ProviderV1, str], ...] = ()

    def __post_init__(self) -> None:
        methods = (
            (self.catalog_port, "get_catalog"),
            (self.status_port, "get_status"),
            (self.connect_port, "initiate_connect"),
            (self.cancel_port, "cancel_connect"),
            (self.disconnect_port, "disconnect"),
        )
        if any(
            port is not None and not callable(getattr(port, method, None))
            for port, method in methods
        ):
            raise TypeError("INVALID_CONNECTION_RUNTIME")
        if not callable(self.clock_ns):
            raise TypeError("INVALID_CONNECTION_RUNTIME")
        if type(self.oauth_host_allowlist) is not tuple:
            raise TypeError("INVALID_CONNECTION_RUNTIME")
        for binding in self.oauth_host_allowlist:
            if (
                type(binding) is not tuple
                or len(binding) != 2
                or type(binding[0]) is not ProviderV1
                or type(binding[1]) is not str
                or binding[1] != binding[1].lower()
                or not _valid_host(binding[1])
            ):
                raise TypeError("INVALID_CONNECTION_RUNTIME")
        if len(set(self.oauth_host_allowlist)) != len(self.oauth_host_allowlist):
            raise TypeError("INVALID_CONNECTION_RUNTIME")


__all__ = [
    "AuthMethodV1",
    "CapabilityV1",
    "ConnectInitiateV1",
    "ConnectInitiationV1",
    "ConnectionActionResultV1",
    "ConnectionActionV1",
    "ConnectionCancelPortV1",
    "ConnectionCatalogEntryV1",
    "ConnectionCatalogPortV1",
    "ConnectionCatalogV1",
    "ConnectionDisconnectPortV1",
    "ConnectionInitiatePortV1",
    "ConnectionStateV1",
    "ConnectionStatusPortV1",
    "ConnectionStatusV1",
    "ConnectionsRuntimeV1",
    "CredentialConnectInitiateV1",
    "EnvironmentV1",
    "ProviderV1",
]
