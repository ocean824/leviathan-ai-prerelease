"""Runtime operator credentials protected by the current OS vault."""

from __future__ import annotations

import base64
import ctypes
import hashlib
import json
import os
import re
import secrets
import sys
import tempfile
import threading
from collections.abc import Mapping
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType
from typing import Any, Literal, Protocol
from urllib.parse import urlsplit

from pydantic import ConfigDict, Field, SecretStr, ValidationError, field_validator, model_validator

from leviathan_core.seal import Issuer, SealedModel, require

REPARSE_POINT = 0x400
CRYPTPROTECT_UI_FORBIDDEN = 0x1
MAX_SECRET_BYTES = 4096
MAX_TEXT_CHARS = 256
MAX_REQUEST_BODY_BYTES = 16 * 1024
MAX_PROFILE_RECORD_BYTES = 64 * 1024
MAX_ACTIVE_PROFILES_PER_GROUP = 256
MAX_PROFILE_IDENTITIES_PER_GROUP = 4096
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_DEVICE_RE = re.compile(r"^(con|prn|aux|nul|com[1-9]|lpt[1-9])$")
_ISSUER = Issuer("leviathan_vault.app_credentials.profile.v1")
Provider = Literal[
    "ALPACA",
    "IBKR",
    "MT5",
    "MCP",
    "SNAPTRADE",
    "TASTYTRADE",
    "CTRADER",
    "COINBASE",
    "KRAKEN",
    "BINANCE_US",
    "FOREX_COM_MT5",
    "RITHMIC",
    "KALSHI",
    "ANTHROPIC",
    "OPENAI",
    "OPENAI_COMPATIBLE",
    "ROUTING",
]
Environment = Literal["PAPER", "DEMO", "LIVE"]
_ENVIRONMENTS: dict[str, frozenset[str]] = {
    "ALPACA": frozenset({"PAPER", "LIVE"}),
    "IBKR": frozenset({"PAPER", "LIVE"}),
    "MT5": frozenset({"DEMO", "LIVE"}),
    "MCP": frozenset({"PAPER"}),
    "SNAPTRADE": frozenset({"PAPER", "DEMO", "LIVE"}),
    "TASTYTRADE": frozenset({"PAPER", "DEMO", "LIVE"}),
    "CTRADER": frozenset({"PAPER", "DEMO", "LIVE"}),
    "COINBASE": frozenset({"PAPER", "DEMO", "LIVE"}),
    "KRAKEN": frozenset({"PAPER", "DEMO", "LIVE"}),
    "BINANCE_US": frozenset({"PAPER", "DEMO", "LIVE"}),
    "FOREX_COM_MT5": frozenset({"DEMO", "LIVE"}),
    "RITHMIC": frozenset({"PAPER", "DEMO", "LIVE"}),
    "KALSHI": frozenset({"PAPER", "DEMO", "LIVE"}),
    "ANTHROPIC": frozenset({"PAPER"}),
    "OPENAI": frozenset({"PAPER"}),
    "OPENAI_COMPATIBLE": frozenset({"PAPER"}),
    "ROUTING": frozenset({"PAPER", "DEMO", "LIVE"}),
}
_SECRET_FIELDS: dict[str, tuple[str, ...]] = {
    "ALPACA": ("key_id", "secret_key", "access_token", "refresh_token"),
    "IBKR": (),
    "MT5": ("password",),
    "MCP": ("token",),
    "SNAPTRADE": ("api_key", "api_secret"),
    "TASTYTRADE": ("oauth_client_secret", "access_token", "refresh_token"),
    "CTRADER": ("oauth_client_secret", "access_token", "refresh_token"),
    "COINBASE": ("private_key", "access_token", "refresh_token"),
    "KRAKEN": ("api_key", "api_secret"),
    "BINANCE_US": ("api_key", "api_secret"),
    "FOREX_COM_MT5": ("password",),
    "RITHMIC": ("password",),
    "KALSHI": ("api_key", "api_secret"),
    "ANTHROPIC": ("api_key",),
    "OPENAI": ("api_key",),
    "OPENAI_COMPATIBLE": ("api_key",),
    "ROUTING": (),
}
_CONFIGURED_FIELDS: dict[str, tuple[str, ...]] = {
    provider: tuple(fields) for provider, fields in _SECRET_FIELDS.items()
}
_CONFIGURED_FIELDS["ALPACA"] = ("key_id", "secret_key")
_REQUIRED_SECRET_GROUPS: dict[str, tuple[frozenset[str], ...]] = {
    "ALPACA": (frozenset({"key_id", "secret_key"}), frozenset({"access_token"})),
    "TASTYTRADE": (frozenset({"oauth_client_secret", "access_token"}),),
    "CTRADER": (frozenset({"oauth_client_secret", "access_token"}),),
    "COINBASE": (frozenset({"private_key"}), frozenset({"access_token"})),
}
_PROVIDER_FIELDS: dict[str, frozenset[str]] = {
    "ALPACA": frozenset(),
    "IBKR": frozenset({"host", "port", "client_id", "account_id"}),
    "MT5": frozenset({"server", "login"}),
    "MCP": frozenset({"server_id"}),
    "SNAPTRADE": frozenset(),
    "TASTYTRADE": frozenset({"oauth_client_id", "token_expires_at"}),
    "CTRADER": frozenset({"oauth_client_id", "token_expires_at"}),
    "COINBASE": frozenset(),
    "KRAKEN": frozenset(),
    "BINANCE_US": frozenset(),
    "FOREX_COM_MT5": frozenset({"server", "login"}),
    "RITHMIC": frozenset({"server", "login"}),
    "KALSHI": frozenset(),
    "ANTHROPIC": frozenset(),
    "OPENAI": frozenset(),
    "OPENAI_COMPATIBLE": frozenset({"base_url", "display_label"}),
    "ROUTING": frozenset({"default_route"}),
}
_OPTIONAL_PROVIDER_FIELDS: dict[str, frozenset[str]] = {
    "OPENAI": frozenset({"organization"}),
    "COINBASE": frozenset({"key_name", "token_expires_at"}),
}
_REQUIRED_SECRET_FIELDS: dict[str, frozenset[str]] = {
    "OPENAI_COMPATIBLE": frozenset(),
}
SNAPTRADE_SUPPORTED_PROVIDERS = frozenset({"SNAPTRADE"})
_ERROR_CODES = frozenset(
    {
        "CORRUPT",
        "INVALID_BASE_URL",
        "INVALID_DEFAULT_ROUTE",
        "FORBIDDEN_OPERATION",
        "INVALID_CONFIGURED_FIELDS",
        "INVALID_ENVIRONMENT",
        "INVALID_FIELDS",
        "INVALID_HOST",
        "INVALID_IBKR_FIELDS",
        "INVALID_ID",
        "INVALID_PROFILE",
        "INVALID_PROVIDER",
        "INVALID_PROVIDER_ENVIRONMENT",
        "INVALID_PROVIDER_FIELDS",
        "INVALID_REVISION",
        "INVALID_SECRET",
        "INVALID_TIMESTAMP",
        "LIMIT_EXCEEDED",
        "LIVE_CONFIRMATION_REQUIRED",
        "NOT_CONFIGURED",
        "NOT_FOUND",
        "PATH_DENIED",
        "UNAVAILABLE",
    }
)


class CredentialError(ValueError):
    """A content-free runtime credential error code."""

    def __init__(self, code: str, loc: tuple[str, ...] = ()) -> None:
        self.code = code if code in _ERROR_CODES else "INVALID_PROFILE"
        self.loc = loc
        super().__init__(self.code)


def _validate_id(value: object, field: str) -> str:
    if type(value) is not str or not _ID_RE.fullmatch(value) or _DEVICE_RE.fullmatch(value):
        raise CredentialError("INVALID_ID", (field,))
    return value


def _validate_compatible_url(value: object) -> str:
    if type(value) is not str or not value or len(value) > 2048:
        raise ValueError("INVALID_BASE_URL")
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        valid = (parsed.scheme == "https" and hostname is not None) or (
            parsed.scheme == "http" and hostname in {"127.0.0.1", "localhost"}
        )
        if (
            not valid
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or not parsed.netloc
        ):
            raise ValueError("INVALID_BASE_URL")
        return value
    except ValueError:
        raise ValueError("INVALID_BASE_URL") from None


class CredentialProfileV1(SealedModel):
    """Sealed metadata only; secret material is deliberately outside SEAL-001."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        strict=True,
        revalidate_instances="always",
        validate_default=True,
        hide_input_in_errors=True,
    )

    provider: Provider
    environment: Environment
    profile_id: str
    server_id: str | None = None
    host: str | None = Field(default=None, repr=False)
    port: int | None = Field(default=None, repr=False)
    client_id: int | None = Field(default=None, repr=False)
    account_id: str | None = Field(default=None, repr=False)
    server: str | None = None
    login: str | None = Field(default=None, repr=False)
    oauth_client_id: str | None = Field(default=None, repr=False)
    key_name: str | None = Field(default=None, repr=False)
    organization: str | None = None
    base_url: str | None = None
    display_label: str | None = None
    token_expires_at: datetime | None = None
    default_route: Literal["SNAPTRADE", "DIRECT"] | None = None
    configured: dict[str, bool]
    revision: int
    updated_at: datetime

    @field_validator("profile_id")
    @classmethod
    def profile_id_is_safe(cls, value: str) -> str:
        return _validate_id(value, "profile_id")

    @field_validator("server_id")
    @classmethod
    def server_id_is_safe(cls, value: str | None) -> str | None:
        return None if value is None else _validate_id(value, "server_id")

    @model_validator(mode="after")
    def provider_shape(self) -> CredentialProfileV1:
        if self.environment not in _ENVIRONMENTS[self.provider]:
            raise ValueError("INVALID_PROVIDER_ENVIRONMENT")
        if self.updated_at.tzinfo is not UTC:
            raise ValueError("INVALID_TIMESTAMP")
        if self.provider == "IBKR" and self.host not in {"127.0.0.1", "::1"}:
            raise ValueError("INVALID_HOST")
        expected = set(_CONFIGURED_FIELDS[self.provider])
        if set(self.configured) != expected or any(
            type(flag) is not bool for flag in self.configured.values()
        ):
            raise ValueError("INVALID_CONFIGURED_FIELDS")
        if type(self.revision) is not int or self.revision < 1:
            raise ValueError("INVALID_REVISION")
        provider_fields = _PROVIDER_FIELDS[self.provider] | _OPTIONAL_PROVIDER_FIELDS.get(
            self.provider, frozenset()
        )
        supplied = {name for name in provider_fields if getattr(self, name) is not None}
        if not set(_PROVIDER_FIELDS[self.provider]) <= supplied or not (
            supplied - set(_PROVIDER_FIELDS[self.provider])
        ) <= _OPTIONAL_PROVIDER_FIELDS.get(self.provider, frozenset()):
            raise ValueError("INVALID_PROVIDER_FIELDS")
        if self.provider == "IBKR" and (
            type(self.port) is not int
            or not 1 <= self.port <= 65535
            or type(self.client_id) is not int
            or self.client_id < 0
        ):
            raise ValueError("INVALID_IBKR_FIELDS")
        if self.provider == "OPENAI_COMPATIBLE":
            _validate_compatible_url(self.base_url)
        if self.provider == "ROUTING" and self.default_route not in {"SNAPTRADE", "DIRECT"}:
            raise ValueError("INVALID_DEFAULT_ROUTE")
        if self.token_expires_at is not None and self.token_expires_at.tzinfo is not UTC:
            raise ValueError("INVALID_TIMESTAMP")
        return self


def issue_profile(**values: Any) -> CredentialProfileV1:
    try:
        profile = CredentialProfileV1(**values)
    except CredentialError:
        raise
    except (ValidationError, ValueError, TypeError):
        raise CredentialError("INVALID_PROFILE") from None
    return _ISSUER.issue(profile)


class ResolvedCredentialV1:
    """Secret-bearing resolver value. It intentionally has no serialization or copy API."""

    __slots__ = ("_locked", "_profile", "_secrets")

    _locked: bool
    _profile: CredentialProfileV1
    _secrets: Mapping[str, SecretStr]

    def __init__(self, profile: CredentialProfileV1, values: dict[str, SecretStr]) -> None:
        object.__setattr__(self, "_profile", profile)
        object.__setattr__(self, "_secrets", MappingProxyType(dict(values)))
        object.__setattr__(self, "_locked", True)

    def __setattr__(self, name: str, value: object) -> None:
        raise CredentialError("FORBIDDEN_OPERATION")

    @property
    def profile(self) -> CredentialProfileV1:
        require(self._profile, _ISSUER.tag)
        return self._profile

    @property
    def revision(self) -> int:
        return self.profile.revision

    def secret(self, name: str) -> SecretStr:
        require(self._profile, _ISSUER.tag)
        try:
            return self._secrets[name]
        except KeyError:
            raise CredentialError("NOT_CONFIGURED") from None

    def __repr__(self) -> str:
        return "ResolvedCredentialV1(<redacted>)"

    def __str__(self) -> str:
        return "ResolvedCredentialV1(<redacted>)"

    def model_dump(self, *args: object, **kwargs: object) -> None:
        raise CredentialError("FORBIDDEN_OPERATION")

    def model_dump_json(self, *args: object, **kwargs: object) -> None:
        raise CredentialError("FORBIDDEN_OPERATION")

    def __reduce__(self) -> str | tuple[Any, ...]:
        raise CredentialError("FORBIDDEN_OPERATION")

    def __copy__(self) -> None:
        raise CredentialError("FORBIDDEN_OPERATION")

    def __deepcopy__(self, memo: object) -> None:
        raise CredentialError("FORBIDDEN_OPERATION")


class CredentialStore(Protocol):
    def put_profile(
        self, provider: str, environment: str, profile_id: str, fields: dict[str, object]
    ) -> CredentialProfileV1: ...
    def delete_profile(self, provider: str, environment: str, profile_id: str) -> None: ...
    def status_all(self) -> tuple[CredentialProfileV1, ...]: ...
    def corrupt_profiles(self) -> tuple[tuple[str, str, str], ...]: ...
    def resolve(self, provider: str, environment: str, profile_id: str) -> ResolvedCredentialV1: ...
    def set_default_route(
        self, environment: str, profile_id: str, route: str
    ) -> CredentialProfileV1: ...
    def get_default_route(self, provider: str, environment: str, profile_id: str) -> str: ...


def _identity(provider: object, environment: object, profile_id: object) -> tuple[str, str, str]:
    if type(provider) is not str or provider not in _ENVIRONMENTS:
        raise CredentialError("INVALID_PROVIDER", ("provider",))
    if type(environment) is not str or environment not in _ENVIRONMENTS[provider]:
        raise CredentialError("INVALID_ENVIRONMENT", ("environment",))
    return provider, environment, _validate_id(profile_id, "profile_id")


def _validate_fields(provider: str, fields: dict[str, object]) -> None:
    for name, value in fields.items():
        if name in _SECRET_FIELDS[provider] and value is not None:
            if type(value) is not SecretStr:
                raise CredentialError("INVALID_SECRET", (name,))
            if (
                not value.get_secret_value()
                or len(value.get_secret_value().encode("utf-8")) > MAX_SECRET_BYTES
            ):
                raise CredentialError("INVALID_SECRET", (name,))
        elif (
            name
            in {
                "host",
                "account_id",
                "server",
                "login",
                "oauth_client_id",
                "key_name",
                "organization",
                "display_label",
                "default_route",
                "base_url",
            }
            and value is not None
        ):
            limit = 2048 if name == "base_url" else MAX_TEXT_CHARS
            if type(value) is not str or not value or len(value) > limit:
                raise CredentialError("INVALID_FIELDS", (name,))
        elif name == "token_expires_at" and value is not None:
            if type(value) is not datetime or value.tzinfo is not UTC:
                raise CredentialError("INVALID_TIMESTAMP", (name,))
    if provider == "OPENAI_COMPATIBLE" and "base_url" in fields:
        try:
            _validate_compatible_url(fields.get("base_url"))
        except ValueError:
            raise CredentialError("INVALID_BASE_URL", ("base_url",)) from None
    if (
        provider == "ROUTING"
        and "default_route" in fields
        and fields.get("default_route") not in {"SNAPTRADE", "DIRECT"}
    ):
        raise CredentialError("INVALID_DEFAULT_ROUTE", ("default_route",))


def _profile_from(
    identity: tuple[str, str, str],
    fields: dict[str, object],
    secret_values: dict[str, SecretStr],
    revision: int,
    updated_at: datetime,
) -> CredentialProfileV1:
    provider, environment, profile_id = identity
    if provider == "MCP":
        _validate_id(fields.get("server_id"), "server_id")
    metadata = {
        key: value
        for key, value in fields.items()
        if key not in _SECRET_FIELDS[provider] and key != "confirm_environment"
    }
    expected = set(_PROVIDER_FIELDS[provider])
    optional = _OPTIONAL_PROVIDER_FIELDS.get(provider, frozenset())
    metadata_fields = set(metadata)
    invalid_fields = (expected - metadata_fields) | (metadata_fields - expected - optional)
    if not expected <= metadata_fields or not metadata_fields - expected <= optional:
        raise CredentialError("INVALID_FIELDS", tuple(sorted(invalid_fields)))
    return issue_profile(
        provider=provider,
        environment=environment,
        profile_id=profile_id,
        **metadata,
        configured={name: name in secret_values for name in _CONFIGURED_FIELDS[provider]},
        revision=revision,
        updated_at=updated_at,
    )


class InMemoryCredentialStore:
    """Thread-safe store for tests; secret-bearing values stay as SecretStr."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._records: dict[
            tuple[str, str, str], tuple[dict[str, object], dict[str, SecretStr], int, datetime]
        ] = {}
        self._revisions: dict[tuple[str, str, str], int] = {}

    def put_profile(
        self, provider: str, environment: str, profile_id: str, fields: dict[str, object]
    ) -> CredentialProfileV1:
        identity = _identity(provider, environment, profile_id)
        secret_fields = set(_SECRET_FIELDS[provider])
        allowed = (
            _PROVIDER_FIELDS[provider]
            | _OPTIONAL_PROVIDER_FIELDS.get(provider, frozenset())
            | secret_fields
            | {"confirm_environment"}
        )
        if set(fields) - allowed:
            raise CredentialError("INVALID_FIELDS", ("body",))
        _validate_fields(provider, fields)
        with self._lock:
            previous = self._records.get(identity)
            group = (provider, environment)
            active_count = sum(1 for item in self._records if item[:2] == group)
            identity_count = sum(1 for item in self._revisions if item[:2] == group)
            if previous is None and active_count >= MAX_ACTIVE_PROFILES_PER_GROUP:
                raise CredentialError("LIMIT_EXCEEDED")
            if (
                identity not in self._revisions
                and identity_count >= MAX_PROFILE_IDENTITIES_PER_GROUP
            ):
                raise CredentialError("LIMIT_EXCEEDED")
            metadata: dict[str, object] = {} if previous is None else dict(previous[0])
            values = {} if previous is None else dict(previous[1])
            for name in secret_fields:
                value = fields.get(name)
                if name in fields:
                    if type(value) is not SecretStr or not value.get_secret_value():
                        raise CredentialError("INVALID_SECRET", (name,))
                    values[name] = value
            provider_fields = _PROVIDER_FIELDS[provider] | _OPTIONAL_PROVIDER_FIELDS.get(
                provider, frozenset()
            )
            for name in provider_fields:
                if name in fields:
                    metadata[name] = fields[name]
            clean = {key: val for key, val in metadata.items() if val is not None}
            if provider == "COINBASE" and "private_key" in values and "key_name" not in clean:
                raise CredentialError("INVALID_FIELDS", ("key_name",))
            revision = self._revisions.get(identity, 0) + 1
            updated_at = datetime.now(UTC)
            profile = _profile_from(identity, clean, values, revision, updated_at)
            self._records[identity] = (clean, values, revision, updated_at)
            self._revisions[identity] = revision
            return profile

    def delete_profile(self, provider: str, environment: str, profile_id: str) -> None:
        identity = _identity(provider, environment, profile_id)
        with self._lock:
            if identity not in self._records:
                return
            self._records.pop(identity, None)
            self._revisions[identity] = self._revisions.get(identity, 0) + 1

    def status_all(self) -> tuple[CredentialProfileV1, ...]:
        with self._lock:
            result = [
                _profile_from(identity, metadata, values, revision, updated)
                for identity, (metadata, values, revision, updated) in self._records.items()
            ]
        return tuple(
            sorted(result, key=lambda item: (item.provider, item.environment, item.profile_id))
        )

    def corrupt_profiles(self) -> tuple[tuple[str, str, str], ...]:
        return ()

    def resolve(self, provider: str, environment: str, profile_id: str) -> ResolvedCredentialV1:
        identity = _identity(provider, environment, profile_id)
        with self._lock:
            record = self._records.get(identity)
            if record is None:
                raise CredentialError("NOT_CONFIGURED")
            metadata, values, revision, updated = record
            profile = _profile_from(identity, metadata, values, revision, updated)
            required_groups = _REQUIRED_SECRET_GROUPS.get(
                provider,
                (
                    frozenset(
                        _REQUIRED_SECRET_FIELDS.get(provider, frozenset(_SECRET_FIELDS[provider]))
                    ),
                ),
            )
            if not any(all(name in values for name in group) for group in required_groups):
                raise CredentialError("NOT_CONFIGURED")
            return ResolvedCredentialV1(profile, values)

    def set_default_route(
        self, environment: str, profile_id: str, route: str
    ) -> CredentialProfileV1:
        if route not in {"SNAPTRADE", "DIRECT"}:
            raise CredentialError("INVALID_DEFAULT_ROUTE", ("default_route",))
        return self.put_profile("ROUTING", environment, profile_id, {"default_route": route})

    def get_default_route(self, provider: str, environment: str, profile_id: str) -> str:
        _identity(provider, environment, profile_id)
        try:
            profile = next(
                item
                for item in self.status_all()
                if (item.provider, item.environment, item.profile_id)
                == ("ROUTING", environment, profile_id)
            )
            assert profile.default_route is not None
            if (
                profile.default_route == "SNAPTRADE"
                and provider not in SNAPTRADE_SUPPORTED_PROVIDERS
            ):
                return "DIRECT"
            return profile.default_route
        except StopIteration:
            return "SNAPTRADE" if provider in SNAPTRADE_SUPPORTED_PROVIDERS else "DIRECT"

    def is_stale(self, profile: CredentialProfileV1) -> bool:
        require(profile, _ISSUER.tag)
        current = next(
            (
                item
                for item in self.status_all()
                if (item.provider, item.environment, item.profile_id)
                == (profile.provider, profile.environment, profile.profile_id)
            ),
            None,
        )
        return current is None or current.revision != profile.revision


class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_uint32), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


def _blob(data: bytearray) -> tuple[_DataBlob, Any]:
    buffer = (ctypes.c_ubyte * len(data)).from_buffer(data)
    return _DataBlob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte))), buffer


def _crypt(data: bytearray, entropy: bytearray, *, decrypt: bool) -> bytearray:
    if sys.platform == "darwin":
        try:
            import keyring  # type: ignore[import-not-found]

            backend = keyring.get_keyring()
            if not backend.__class__.__module__.startswith("keyring.backends.macOS"):
                raise CredentialError("UNAVAILABLE")
            account = hashlib.sha256(entropy).hexdigest()
            if decrypt:
                if data != b"keychain:v1":
                    raise CredentialError("CORRUPT")
                saved = keyring.get_password("com.xyrasystems.leviathanai.credentials", account)
                if saved is None:
                    raise CredentialError("CORRUPT")
                return bytearray(base64.b64decode(saved, validate=True))
            keyring.set_password(
                "com.xyrasystems.leviathanai.credentials",
                account,
                base64.b64encode(data).decode("ascii"),
            )
            return bytearray(b"keychain:v1")
        except CredentialError:
            raise
        except Exception:
            raise CredentialError("CORRUPT" if decrypt else "UNAVAILABLE") from None
    if os.name != "nt":
        raise CredentialError("UNAVAILABLE")
    source, source_buffer = _blob(data)
    extra, extra_buffer = _blob(entropy)
    output = _DataBlob()
    crypt32 = getattr(ctypes, "WinDLL")("crypt32", use_last_error=True)  # noqa: B009
    kernel32 = getattr(ctypes, "WinDLL")("kernel32", use_last_error=True)  # noqa: B009
    protect = crypt32.CryptUnprotectData if decrypt else crypt32.CryptProtectData
    protect.restype = ctypes.c_int
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    try:
        if decrypt:
            protect.argtypes = [
                ctypes.POINTER(_DataBlob),
                ctypes.c_void_p,
                ctypes.POINTER(_DataBlob),
                ctypes.c_void_p,
                ctypes.c_void_p,
                ctypes.c_uint32,
                ctypes.POINTER(_DataBlob),
            ]
            ok = protect(
                ctypes.byref(source),
                None,
                ctypes.byref(extra),
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                ctypes.byref(output),
            )
        else:
            protect.argtypes = [
                ctypes.POINTER(_DataBlob),
                ctypes.c_wchar_p,
                ctypes.POINTER(_DataBlob),
                ctypes.c_void_p,
                ctypes.c_void_p,
                ctypes.c_uint32,
                ctypes.POINTER(_DataBlob),
            ]
            ok = protect(
                ctypes.byref(source),
                "Leviathan runtime credential",
                ctypes.byref(extra),
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                ctypes.byref(output),
            )
        if not ok or not output.pbData or output.cbData == 0:
            raise CredentialError("CORRUPT" if decrypt else "UNAVAILABLE")
        return bytearray(
            (ctypes.c_ubyte * output.cbData).from_address(ctypes.addressof(output.pbData.contents))
        )
    except CredentialError:
        raise
    except Exception:
        raise CredentialError("CORRUPT" if decrypt else "UNAVAILABLE") from None
    finally:
        if output.pbData:
            ctypes.memset(output.pbData, 0, output.cbData)
            kernel32.LocalFree(output.pbData)
        _ = source_buffer, extra_buffer


class DPAPICredentialStore(InMemoryCredentialStore):
    """DPAPI CurrentUser backend with per-install entropy and atomic profile records."""

    def __init__(self, root: Path) -> None:
        if os.name != "nt" and sys.platform != "darwin":
            raise CredentialError("UNAVAILABLE")
        self.root = Path(root).absolute()
        self.root.mkdir(parents=True, exist_ok=True)
        self._check_path(self.root)
        self._lock = threading.RLock()
        self._records = {}
        self._revisions = {}
        entropy_path = self.root / ".entropy"
        self._check_path(entropy_path)
        if sys.platform == "darwin":
            self._entropy = bytearray(32)
        elif not entropy_path.exists():
            entropy = secrets.token_bytes(32)
            fd, temporary = tempfile.mkstemp(prefix=".entropy-", dir=self.root)
            try:
                with os.fdopen(fd, "wb") as stream:
                    stream.write(entropy)
                    stream.flush()
                    os.fsync(stream.fileno())
                self._check_path(Path(temporary))
                with suppress(FileExistsError):
                    os.link(temporary, entropy_path)
            except Exception:
                raise CredentialError("UNAVAILABLE") from None
            finally:
                with suppress(OSError):
                    os.unlink(temporary)
            self._check_path(entropy_path)
            if not entropy_path.exists():
                raise CredentialError("UNAVAILABLE")
        if sys.platform != "darwin":
            self._entropy = bytearray(entropy_path.read_bytes())
            if len(self._entropy) != 32:
                raise CredentialError("CORRUPT")
        self._corrupt: dict[
            tuple[str, str, str], tuple[dict[str, object], int, datetime | None]
        ] = {}
        self._load_metadata()

    def _check_path(self, path: Path) -> None:
        if not path.is_absolute() or not path.is_relative_to(self.root):
            raise CredentialError("PATH_DENIED")
        root_chain = []
        current = self.root
        while current != current.parent:
            root_chain.append(current)
            current = current.parent
        candidates = list(reversed(root_chain))
        current = self.root
        for part in path.relative_to(self.root).parts:
            current = current / part
            candidates.append(current)
        for candidate in candidates:
            try:
                st = candidate.lstat()
            except FileNotFoundError:
                continue
            if candidate.is_symlink() or getattr(st, "st_file_attributes", 0) & REPARSE_POINT:
                raise CredentialError("PATH_DENIED")

    def _profile_dir(self, identity: tuple[str, str, str]) -> Path:
        provider, environment, profile_id = identity
        path = self.root / environment / provider / profile_id
        try:
            is_within_root = path.resolve(strict=False).is_relative_to(self.root.resolve())
        except (OSError, RuntimeError):
            raise CredentialError("PATH_DENIED") from None
        if not is_within_root:
            raise CredentialError("PATH_DENIED")
        self._check_path(path)
        return path

    def _atomic(self, path: Path, payload: bytes) -> None:
        self._check_path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self._check_path(path)
        fd, temporary = tempfile.mkstemp(prefix=".write-", dir=path.parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            self._check_path(Path(temporary))
            os.replace(temporary, path)
        except Exception:
            with suppress(OSError):
                os.unlink(temporary)
            raise CredentialError("UNAVAILABLE") from None

    def _profile_entropy(self, identity: tuple[str, str, str]) -> bytearray:
        context = "\0".join(identity).encode("utf-8")
        return bytearray(
            hashlib.sha256(b"leviathan-runtime-credential-v1\0" + self._entropy + context).digest()
        )

    def _mark_corrupt(
        self,
        identity: tuple[str, str, str],
        fields: dict[str, object] | None = None,
        revision: int = 1,
        updated: datetime | None = None,
    ) -> None:
        self._corrupt[identity] = ({} if fields is None else fields, revision, updated)
        self._revisions[identity] = max(self._revisions.get(identity, 0), revision)

    def _load_metadata(self) -> None:
        for marker in self.root.glob("*/*/.*.revision"):
            self._check_path(marker)
            try:
                environment, provider = marker.parent.parent.name, marker.parent.name
                profile_id = marker.name[1 : -len(".revision")]
                identity = _identity(provider, environment, profile_id)
                revision = int(marker.read_text(encoding="ascii"))
                if revision < 1:
                    raise ValueError
                self._revisions[identity] = revision
            except CredentialError:
                continue
            except Exception:
                continue
        for metadata_path in self.root.glob("*/*/*/profile.json"):
            self._check_path(metadata_path)
            directory = metadata_path.parent
            try:
                identity = _identity(
                    directory.parent.name, directory.parent.parent.name, directory.name
                )
            except CredentialError:
                continue
            fields: dict[str, object] = {}
            revision = max(1, self._revisions.get(identity, 1))
            updated: datetime | None = None
            try:
                if metadata_path.stat().st_size > MAX_PROFILE_RECORD_BYTES:
                    self._mark_corrupt(identity, fields, revision, updated)
                    continue
                data = json.loads(metadata_path.read_text(encoding="utf-8"))
                stored_identity = _identity(
                    data["provider"], data["environment"], data["profile_id"]
                )
                if stored_identity != identity:
                    raise CredentialError("CORRUPT")
                if type(data["fields"]) is not dict:
                    raise CredentialError("CORRUPT")
                fields = data["fields"]
                if "token_expires_at" in fields:
                    expiry = fields["token_expires_at"]
                    if type(expiry) is not str:
                        raise CredentialError("CORRUPT")
                    fields["token_expires_at"] = datetime.fromisoformat(expiry)
                revision = data["revision"]
                if type(revision) is not int or revision < 1:
                    raise CredentialError("CORRUPT")
                updated = datetime.fromisoformat(data["updated_at"])
                if updated.tzinfo is not UTC:
                    raise CredentialError("CORRUPT")
                if self._revisions.get(identity, 0) >= revision:
                    continue
                ciphertext = bytearray(base64.b64decode(data["envelope"], validate=True))
                entropy = self._profile_entropy(identity)
                clear = _crypt(ciphertext, entropy, decrypt=True)
                try:
                    envelope = json.loads(clear.decode("utf-8", errors="strict"))
                finally:
                    clear[:] = b"\0" * len(clear)
                    ciphertext[:] = b"\0" * len(ciphertext)
                    entropy[:] = b"\0" * len(entropy)
                envelope_identity = (
                    envelope.get("provider"),
                    envelope.get("environment"),
                    envelope.get("profile_id"),
                )
                if envelope_identity != identity or envelope.get("revision") != revision:
                    raise CredentialError("CORRUPT")
                raw_values = envelope.get("secrets")
                if type(raw_values) is not dict or set(raw_values) - set(
                    _SECRET_FIELDS[identity[0]]
                ):
                    raise CredentialError("CORRUPT")
                values: dict[str, SecretStr] = {}
                for name, raw_value in raw_values.items():
                    if (
                        type(raw_value) is not str
                        or not raw_value
                        or len(raw_value.encode("utf-8")) > MAX_SECRET_BYTES
                    ):
                        raise CredentialError("CORRUPT")
                    values[name] = SecretStr(raw_value)
                _validate_fields(identity[0], {**fields, **values})
                profile = _profile_from(identity, fields, values, revision, updated)
                require(profile, _ISSUER.tag)
                self._records[identity] = (fields, values, revision, updated)
                self._revisions[identity] = revision
            except CredentialError as exc:
                if exc.code == "PATH_DENIED":
                    raise
                self._mark_corrupt(identity, fields, revision, updated)
            except Exception:
                self._mark_corrupt(identity, fields, revision, updated)

    def corrupt_profiles(self) -> tuple[tuple[str, str, str], ...]:
        with self._lock:
            return tuple(sorted(self._corrupt))

    def resolve(self, provider: str, environment: str, profile_id: str) -> ResolvedCredentialV1:
        identity = _identity(provider, environment, profile_id)
        with self._lock:
            if identity in self._corrupt:
                raise CredentialError("CORRUPT")
        return super().resolve(provider, environment, profile_id)

    def put_profile(
        self, provider: str, environment: str, profile_id: str, fields: dict[str, object]
    ) -> CredentialProfileV1:
        identity = _identity(provider, environment, profile_id)
        allowed = (
            _PROVIDER_FIELDS[provider]
            | _OPTIONAL_PROVIDER_FIELDS.get(provider, frozenset())
            | frozenset(_SECRET_FIELDS[provider])
            | {"confirm_environment"}
        )
        if set(fields) - allowed:
            raise CredentialError("INVALID_FIELDS", ("body",))
        _validate_fields(provider, fields)
        with self._lock:
            if identity in self._corrupt:
                raise CredentialError("CORRUPT")
            old = self._records.get(identity)
            group = (provider, environment)
            active_count = sum(1 for item in self._records if item[:2] == group)
            active_count += sum(1 for item in self._corrupt if item[:2] == group)
            identity_count = sum(1 for item in self._revisions if item[:2] == group)
            if old is None and active_count >= MAX_ACTIVE_PROFILES_PER_GROUP:
                raise CredentialError("LIMIT_EXCEEDED")
            if (
                identity not in self._revisions
                and identity_count >= MAX_PROFILE_IDENTITIES_PER_GROUP
            ):
                raise CredentialError("LIMIT_EXCEEDED")
            old_values = {} if old is None else dict(old[1])
            staged: dict[str, SecretStr] = dict(old_values)
            for name in _SECRET_FIELDS[provider]:
                value = fields.get(name)
                if name in fields:
                    if type(value) is not SecretStr or not value.get_secret_value():
                        raise CredentialError("INVALID_SECRET", (name,))
                    staged[name] = value
            metadata: dict[str, object] = {} if old is None else dict(old[0])
            provider_fields = _PROVIDER_FIELDS[provider] | _OPTIONAL_PROVIDER_FIELDS.get(
                provider, frozenset()
            )
            for name in provider_fields:
                if name in fields:
                    metadata[name] = fields[name]
            metadata = {key: value for key, value in metadata.items() if value is not None}
            if provider == "COINBASE" and "private_key" in staged and "key_name" not in metadata:
                raise CredentialError("INVALID_FIELDS", ("key_name",))
            revision = self._revisions.get(identity, 0) + 1
            updated = datetime.now(UTC)
            profile = _profile_from(identity, metadata, staged, revision, updated)
            directory = self._profile_dir(identity)
            directory.mkdir(parents=True, exist_ok=True)
            envelope_raw = bytearray(
                json.dumps(
                    {
                        "environment": environment,
                        "provider": provider,
                        "profile_id": profile_id,
                        "revision": revision,
                        "secrets": {
                            name: value.get_secret_value() for name, value in staged.items()
                        },
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            )
            entropy = self._profile_entropy(identity)
            try:
                encrypted = _crypt(envelope_raw, entropy, decrypt=False)
                try:
                    envelope = base64.b64encode(encrypted).decode("ascii")
                finally:
                    encrypted[:] = b"\0" * len(encrypted)
            finally:
                envelope_raw[:] = b"\0" * len(envelope_raw)
                entropy[:] = b"\0" * len(entropy)
            payload = json.dumps(
                {
                    "provider": provider,
                    "environment": environment,
                    "profile_id": profile_id,
                    "fields": {
                        key: value.isoformat() if isinstance(value, datetime) else value
                        for key, value in metadata.items()
                    },
                    "revision": revision,
                    "updated_at": updated.isoformat(),
                    "envelope": envelope,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            if len(payload) > MAX_PROFILE_RECORD_BYTES:
                raise CredentialError("LIMIT_EXCEEDED")
            self._atomic(directory / "profile.json", payload)
            self._records[identity] = (metadata, staged, revision, updated)
            self._revisions[identity] = revision
            return profile

    def delete_profile(self, provider: str, environment: str, profile_id: str) -> None:
        identity = _identity(provider, environment, profile_id)
        with self._lock:
            old = self._records.get(identity)
            was_corrupt = identity in self._corrupt
            if old is None and not was_corrupt:
                return
            revision = self._revisions.get(identity, 0) + 1
            directory = self._profile_dir(identity)
            if sys.platform == "darwin":
                entropy = self._profile_entropy(identity)
                try:
                    import keyring

                    backend = keyring.get_keyring()
                    if not backend.__class__.__module__.startswith("keyring.backends.macOS"):
                        raise CredentialError("UNAVAILABLE")
                    account = hashlib.sha256(entropy).hexdigest()
                    if (
                        keyring.get_password("com.xyrasystems.leviathanai.credentials", account)
                        is not None
                    ):
                        keyring.delete_password("com.xyrasystems.leviathanai.credentials", account)
                except CredentialError:
                    raise
                except Exception:
                    raise CredentialError("UNAVAILABLE") from None
                finally:
                    entropy[:] = b"\0" * len(entropy)
            marker = self.root / environment / provider / f".{profile_id}.revision"
            self._atomic(marker, str(revision).encode("ascii"))
            self._records.pop(identity, None)
            self._corrupt.pop(identity, None)
            self._revisions[identity] = revision
            if directory.exists():
                self._check_path(directory)
                for item in directory.iterdir():
                    self._check_path(item)
                    item.unlink()
                directory.rmdir()


CredentialResolverPort = CredentialStore


class MacOSKeychainCredentialStore(DPAPICredentialStore):
    """Credential store whose secret envelopes are held in macOS Keychain."""

    def __init__(self, root: Path) -> None:
        if sys.platform != "darwin":
            raise CredentialError("UNAVAILABLE")
        super().__init__(root)


def credential_store_for_platform(root: Path) -> CredentialStore:
    if os.name == "nt":
        return DPAPICredentialStore(root)
    if sys.platform == "darwin":
        return MacOSKeychainCredentialStore(root)
    raise CredentialError("UNAVAILABLE")
