"""Write-only credential actions shared by Connections and future venue testers."""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import re
import secrets
import threading
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from typing import Literal, Protocol
from urllib.parse import urlsplit

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

from leviathan_api.routers.credentials import (
    CredentialDeleteRequest,
    CredentialPutRequest,
)
from leviathan_api.routers.credentials import (
    status as legacy_status,
)
from leviathan_core.seal import require
from leviathan_core.security.authz_models import (
    AuthorizationModelError,
    TrustedPrincipalV1,
    require_trusted_principal,
)
from leviathan_vault.app_credentials import CredentialProfileV1, CredentialStore, _validate_id
from leviathan_vault.project_secrets import ProjectSecretStorePort

_ID = re.compile(r"[a-z][a-z0-9_]{0,63}\Z", re.ASCII)
_MAX_SECRET_BYTES = 16_384
_MAX_KALSHI_KEY_BYTES = 64 * 1024
_PROFILE = "default"
_NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}

DATA_SECRET_NAMES: dict[str, str] = {
    "databento": "DATABENTO_API_KEY",
    "massive": "MASSIVE_API_KEY",
    "unusual_whales": "UNUSUAL_WHALES_API_KEY",
    "fred": "FRED_API_KEY",
    "bea": "BEA_API_KEY",
    "eia": "EIA_API_KEY",
    "trading_economics": "TRADING_ECONOMICS_API_KEY",
    "census": "CENSUS_API_KEY",
    "usda": "USDA_API_KEY",
    "quiver": "QUIVER_API_KEY",
    "copernicus": "COPERNICUS_API_KEY",
}
DATA_KEYLESS = frozenset({"bls"})
_LEGACY_PROVIDERS: dict[str, tuple[str, str]] = {
    "ALPACA": ("alpaca", "ALPACA"),
    "IBKR": ("ibkr", "IBKR"),
    "MT5": ("mt5_forexcom", "MT5"),
    "MCP": ("mcp", "MCP"),
}
_LEGACY_MCP_FIELDS = frozenset({"server_id", "token"})
BROKER_IDS: dict[str, str] = {
    "alpaca": "ALPACA",
    "ibkr": "IBKR",
    "mt5_forexcom": "MT5_FOREXCOM",
    "coinbase_spot": "COINBASE_SPOT",
    "kalshi": "KALSHI",
    "polymarket": "POLYMARKET",
}
BROKER_FIELDS: dict[str, frozenset[str]] = {
    "alpaca": frozenset({"key_id", "secret_key", "account_id"}),
    "ibkr": frozenset({"host", "port", "client_id", "account_id"}),
    "mt5_forexcom": frozenset({"server", "login", "password"}),
    "coinbase_spot": frozenset({"key_name", "private_key"}),
    "kalshi": frozenset({"key_name", "api_secret"}),
    "polymarket": frozenset(
        {"account_id", "wallet_private_key", "api_key", "api_secret", "api_passphrase"}
    ),
}
BROKER_ENVIRONMENTS: dict[str, tuple[str, ...]] = {
    "alpaca": ("PAPER", "LIVE"),
    "ibkr": ("PAPER", "LIVE"),
    "mt5_forexcom": ("DEMO", "LIVE"),
    "coinbase_spot": ("PAPER", "LIVE"),
    "kalshi": ("PAPER", "DEMO", "LIVE"),
    "polymarket": ("PAPER", "LIVE"),
}
_SAFE_TEST_ERRORS = frozenset(
    {
        "AUTH_FAILED",
        "CREDENTIALS_UNAVAILABLE",
        "INVALID_CREDENTIAL",
        "PROVIDER_UNAVAILABLE",
        "RATE_LIMITED",
        "TEST_UNAVAILABLE",
    }
)
_SECRET_FIELDS = frozenset(
    {
        "key_id",
        "secret_key",
        "password",
        "private_key",
        "api_key",
        "api_secret",
        "api_passphrase",
        "wallet_private_key",
    }
)


class CredentialConnectionError(ValueError):
    """Fixed response code without user or provider text."""

    def __init__(self, code: str, status_code: int = 503) -> None:
        self.code = code
        self.status_code = status_code
        super().__init__(code)


class CredentialActionRequestV1(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)
    fields: dict[str, str | int] = Field(default_factory=dict, max_length=8)
    secrets: dict[str, SecretStr] = Field(default_factory=dict, max_length=8)
    confirm_environment: Literal["LIVE"] | None = None
    confirmation_token: SecretStr | None = Field(default=None, max_length=128)

    @field_validator("fields")
    @classmethod
    def _bounded_fields(cls, values: dict[str, str | int]) -> dict[str, str | int]:
        if any(
            type(key) is not str
            or len(key) > 64
            or (type(value) is str and len(value) > 256)
            or type(value) not in {str, int}
            for key, value in values.items()
        ):
            raise ValueError("INVALID_CREDENTIAL")
        return values

    @field_validator("secrets")
    @classmethod
    def _bounded_secrets(cls, values: dict[str, SecretStr]) -> dict[str, SecretStr]:
        if any(
            type(value) is not SecretStr
            or not value.get_secret_value()
            or len(value.get_secret_value().encode("utf-8")) > _MAX_SECRET_BYTES
            for value in values.values()
        ):
            raise ValueError("INVALID_CREDENTIAL")
        return values


class CredentialStatusV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    provider_id: str
    environment: str
    configured: bool
    verified: bool = False
    last_tested_ns: int | None = None
    last_rotated_ns: int | None = None
    error_code: str | None = None


class CredentialReferenceV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    provider_id: str
    environment: str
    profile_id: str = _PROFILE
    revision: int = Field(ge=0)
    vault_reference: str | None = None


class CredentialTestResultV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    verified: bool
    error_code: str | None = None


class CredentialTesterPortV1(Protocol):
    """Provider-specific testers resolve their secret internally and return status only."""

    def test(self, reference: CredentialReferenceV1) -> CredentialTestResultV1: ...


class CredentialAuditEventV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    provider_id: str
    action: Literal["REPLACE", "REMOVE", "TEST"]
    outcome: Literal["SUCCEEDED", "FAILED"]
    actor_id: str
    occurred_at_ns: int = Field(ge=0)
    profile_id: str = _PROFILE
    error_code: str | None = None


class CredentialAuditPortV1(Protocol):
    def append(self, event: CredentialAuditEventV1) -> None: ...


class CredentialConfirmationPortV1(Protocol):
    """Single-use confirmation tokens bound to one principal and credential action."""

    def issue(
        self,
        *,
        principal_id: str,
        provider_id: str,
        environment: str,
        profile_id: str,
        action: Literal["REMOVE"],
        now_ns: int,
    ) -> tuple[str, int]: ...

    def consume(
        self,
        *,
        token: str,
        principal_id: str,
        provider_id: str,
        environment: str,
        profile_id: str,
        action: Literal["REMOVE"],
        now_ns: int,
    ) -> bool: ...


class InMemoryCredentialConfirmationPortV1:
    """Bounded process-local one-use token store; only token digests are retained."""

    _TTL_NS = 60_000_000_000
    _MAX_ENTRIES = 2048

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: dict[bytes, tuple[str, str, str, str, str, int]] = {}

    @staticmethod
    def _digest(token: str) -> bytes:
        return hashlib.sha256(token.encode("utf-8")).digest()

    def issue(
        self,
        *,
        principal_id: str,
        provider_id: str,
        environment: str,
        profile_id: str,
        action: Literal["REMOVE"],
        now_ns: int,
    ) -> tuple[str, int]:
        expires_at_ns = now_ns + self._TTL_NS
        token = secrets.token_urlsafe(32)
        digest = self._digest(token)
        with self._lock:
            self._entries = {
                key: entry for key, entry in self._entries.items() if entry[-1] > now_ns
            }
            if len(self._entries) >= self._MAX_ENTRIES:
                raise RuntimeError("CONFIRMATION_UNAVAILABLE")
            self._entries[digest] = (
                principal_id,
                provider_id,
                environment,
                profile_id,
                action,
                expires_at_ns,
            )
        return token, expires_at_ns

    def consume(
        self,
        *,
        token: str,
        principal_id: str,
        provider_id: str,
        environment: str,
        profile_id: str,
        action: Literal["REMOVE"],
        now_ns: int,
    ) -> bool:
        if type(token) is not str or not 32 <= len(token) <= 128:
            return False
        digest = self._digest(token)
        expected = (principal_id, provider_id, environment, profile_id, action)
        with self._lock:
            entry = self._entries.pop(digest, None)
            return entry is not None and entry[:-1] == expected and now_ns < entry[-1]


class LiveCredentialBindingV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    organization_id: str
    account_id: str
    venue: str
    account_identifier: str

    @field_validator("organization_id", "account_id", "venue", "account_identifier")
    @classmethod
    def _valid_binding_identifiers(cls, value: str) -> str:
        if not _ID.fullmatch(value) and not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", value
        ):
            raise ValueError("INVALID_LIVE_BINDING")
        return value


class CredentialLiveBindingPortV1(Protocol):
    """Resolve authoritative LIVE bindings; ``None`` means the query is indeterminate."""

    def resolve_bindings(
        self, provider_id: str, account_identifier: str
    ) -> tuple[LiveCredentialBindingV1, ...] | None: ...
    def bump_credential_revision(
        self, organization_id: str, account_id: str, provider_id: str
    ) -> None: ...


class CredentialStatusPortV1(Protocol):
    def read_status(self, reference: CredentialReferenceV1) -> CredentialStatusV1: ...
    def record_status(self, status: CredentialStatusV1) -> None: ...


@dataclass(frozen=True, slots=True)
class CredentialConnectionsRuntimeV1:
    credential_store: CredentialStore | None
    project_secret_store: ProjectSecretStorePort | None
    tester: CredentialTesterPortV1
    audit: CredentialAuditPortV1
    status: CredentialStatusPortV1
    live_bindings: CredentialLiveBindingPortV1
    clock_ns: Callable[[], int]
    confirmation_port: CredentialConfirmationPortV1 | None = None

    def __post_init__(self) -> None:
        for port, methods in (
            (self.tester, ("test",)),
            (self.audit, ("append",)),
            (self.status, ("read_status", "record_status")),
            (self.live_bindings, ("resolve_bindings", "bump_credential_revision")),
        ):
            if any(not callable(getattr(port, method, None)) for method in methods):
                raise TypeError("CREDENTIALS_NOT_CONFIGURED")
        if self.confirmation_port is not None and any(
            not callable(getattr(self.confirmation_port, method, None))
            for method in ("issue", "consume")
        ):
            raise TypeError("CREDENTIALS_NOT_CONFIGURED")
        if not callable(self.clock_ns):
            raise TypeError("CREDENTIALS_NOT_CONFIGURED")


def _json_error(status: int, code: str) -> JSONResponse:
    return JSONResponse(status_code=status, content={"code": code}, headers=_NO_STORE)


def _safe_test_error(value: str | None) -> str | None:
    return value if value in _SAFE_TEST_ERRORS else (None if value is None else "TEST_UNAVAILABLE")


def _record_status(
    runtime: CredentialConnectionsRuntimeV1,
    reference: CredentialReferenceV1,
    *,
    configured: bool,
    verified: bool = False,
    tested_ns: int | None = None,
    rotated_ns: int | None = None,
    error_code: str | None = None,
) -> CredentialStatusV1:
    status = CredentialStatusV1(
        provider_id=reference.provider_id,
        environment=reference.environment,
        configured=configured,
        verified=verified,
        last_tested_ns=tested_ns,
        last_rotated_ns=rotated_ns,
        error_code=_safe_test_error(error_code),
    )
    runtime.status.record_status(status)
    return status


def _principal(request: Request) -> TrustedPrincipalV1 | JSONResponse:
    try:
        principal = require_trusted_principal(getattr(request.state, "trusted_principal", None))
    except AuthorizationModelError:
        return _json_error(401, "PRINCIPAL_UNTRUSTED")
    if not ({"operator", "admin"} & set(principal.roles)):
        return _json_error(403, "CONNECTION_FORBIDDEN")
    return principal


def _same_origin_loopback(request: Request) -> bool:
    client = request.client
    origin = request.headers.get("origin")
    try:
        client_ip = ipaddress.ip_address(client.host if client is not None else "")
        request_url = urlsplit(str(request.base_url))
        origin_url = urlsplit(origin or "")
        request_ip = ipaddress.ip_address(request_url.hostname or "")
    except ValueError:
        return False
    return (
        client_ip.is_loopback
        and request_ip.is_loopback
        and origin_url.scheme == request_url.scheme
        and origin_url.netloc.lower() == request_url.netloc.lower()
        and not origin_url.username
        and not origin_url.password
        and origin_url.path in {"", "/"}
        and not origin_url.query
        and not origin_url.fragment
    )


def _reference(
    provider: str, environment: str
) -> tuple[CredentialReferenceV1, str | None, str | None]:
    if type(provider) is not str or _ID.fullmatch(provider) is None:
        raise CredentialConnectionError("INVALID_PROVIDER", 400)
    if provider in DATA_SECRET_NAMES:
        if environment != "DEVELOPMENT":
            raise CredentialConnectionError("INVALID_ENVIRONMENT", 400)
        name = DATA_SECRET_NAMES[provider]
        return (
            CredentialReferenceV1(
                provider_id=provider,
                environment=environment,
                revision=0,
                vault_reference=f"vault://leviathan-ai/development/{provider.upper()}/{name}",
            ),
            name,
            None,
        )
    if provider in DATA_KEYLESS:
        if environment != "DEVELOPMENT":
            raise CredentialConnectionError("INVALID_ENVIRONMENT", 400)
        return (
            CredentialReferenceV1(provider_id=provider, environment=environment, revision=0),
            None,
            None,
        )
    broker = BROKER_IDS.get(provider)
    if broker is None:
        raise CredentialConnectionError("PROVIDER_NOT_FOUND", 404)
    allowed = {"PAPER", "DEMO", "LIVE"} if broker != "MT5_FOREXCOM" else {"DEMO", "LIVE"}
    if environment not in allowed:
        raise CredentialConnectionError("INVALID_ENVIRONMENT", 400)
    return (
        CredentialReferenceV1(provider_id=provider, environment=environment, revision=0),
        None,
        broker,
    )


def _profile_revision(
    runtime: CredentialConnectionsRuntimeV1, broker: str | None, environment: str
) -> int:
    if broker is None or runtime.credential_store is None:
        return 0
    for profile in runtime.credential_store.status_all():
        if (
            profile.provider == broker
            and profile.environment == environment
            and profile.profile_id == _PROFILE
        ):
            return profile.revision
    return 0


_LIVE_VENUE_IDENTIFIERS: dict[str, tuple[str, ...]] = {
    "alpaca": ("account_id",),
    "ibkr": ("account_id",),
    "mt5_forexcom": ("server", "login"),
    "coinbase_spot": ("key_name",),
    "kalshi": ("key_name",),
    "polymarket": ("account_id",),
}
_LIVE_VENUE_NAMES: dict[str, str] = {provider: name for provider, name in BROKER_IDS.items()}


def _account_identifier(fields: dict[str, str | int], provider: str) -> str | None:
    names = _LIVE_VENUE_IDENTIFIERS.get(provider)
    if names is None:
        return None
    values = tuple(fields.get(name) for name in names)
    if any(type(value) not in {str, int} or not str(value) for value in values):
        return None
    return ":".join(str(value) for value in values)


def _affected_live_accounts(
    runtime: CredentialConnectionsRuntimeV1,
    provider: str,
    broker: str,
    current_fields: dict[str, str | int],
) -> tuple[LiveCredentialBindingV1, ...]:
    account_id = _account_identifier(current_fields, provider)
    if account_id is None:
        raise CredentialConnectionError("LIVE_BINDING_UNAVAILABLE")
    try:
        venue = _LIVE_VENUE_NAMES.get(provider)
        if venue is None:
            raise CredentialConnectionError("LIVE_BINDING_UNAVAILABLE")
        rows = runtime.live_bindings.resolve_bindings(venue, account_id)
    except Exception:
        raise CredentialConnectionError("LIVE_BINDING_UNAVAILABLE") from None
    if (
        rows is None
        or type(rows) is not tuple
        or len(rows) > 64
        or any(type(row) is not LiveCredentialBindingV1 for row in rows)
    ):
        raise CredentialConnectionError("LIVE_BINDING_UNAVAILABLE")
    pairs = {(row.organization_id, row.account_id) for row in rows}
    if len(pairs) != len(rows):
        raise CredentialConnectionError("LIVE_BINDING_UNAVAILABLE")
    if any(row.account_identifier != account_id or row.venue != venue for row in rows):
        raise CredentialConnectionError("LIVE_BINDING_UNAVAILABLE")
    return rows


def _affected_live_accounts_for_rotation(
    runtime: CredentialConnectionsRuntimeV1,
    provider: str,
    broker: str,
    old_fields: dict[str, str | int],
    replacement_fields: dict[str, str | int],
) -> tuple[LiveCredentialBindingV1, ...]:
    """Resolve both the current and replacement identity before changing a profile."""
    identities: list[dict[str, str | int]] = []
    if old_fields:
        identities.append(old_fields)
    if replacement_fields:
        identities.append({**old_fields, **replacement_fields})
    if not identities:
        raise CredentialConnectionError("LIVE_BINDING_UNAVAILABLE")
    rows: dict[tuple[str, str], LiveCredentialBindingV1] = {}
    for fields in identities:
        resolved = _affected_live_accounts(runtime, provider, broker, fields)
        for row in resolved:
            rows[(row.organization_id, row.account_id)] = row
    return tuple(rows[key] for key in sorted(rows))


def _account_meta(profile: object, broker: str) -> dict[str, str | int]:
    fields: dict[str, str | int] = {}
    for name in ("account_id", "login", "server", "key_name"):
        value = getattr(profile, name, None)
        if type(value) is str or type(value) is int:
            fields[name] = value
    if broker == "IBKR":
        fields["account_id"] = getattr(profile, "account_id", "")
    return fields


def _deactivate(
    request: Request,
    runtime: CredentialConnectionsRuntimeV1,
    rows: tuple[LiveCredentialBindingV1, ...],
) -> None:
    if not rows:
        return
    gate = getattr(request.app.state, "live_activation_gate", None)
    deactivate = getattr(gate, "deactivate_account_checked", None)
    if not callable(deactivate):
        raise CredentialConnectionError("LIVE_ACTIVATION_UNAVAILABLE")
    for row in rows:
        try:
            deactivate(row.organization_id, row.account_id)
        except Exception:
            raise CredentialConnectionError("LIVE_ACTIVATION_UNAVAILABLE") from None


def _replace_broker_profile(
    request: Request,
    runtime: CredentialConnectionsRuntimeV1,
    *,
    provider: str,
    broker: str,
    environment: str,
    profile_id: str,
    fields: dict[str, str | int],
    secrets: dict[str, SecretStr],
    confirm_environment: str | None,
    allowed_fields: frozenset[str] | None = None,
    live_provider: str | None = None,
    allow_custom_profile: bool = False,
) -> tuple[CredentialProfileV1, CredentialReferenceV1, CredentialStatusV1]:
    """Shared broker-profile replacement path for Connections and legacy URLs."""
    if profile_id != _PROFILE and broker != "MCP" and not allow_custom_profile:
        raise CredentialConnectionError("PROFILE_NOT_FOUND", 404)
    allowed = allowed_fields or BROKER_FIELDS.get(provider)
    if allowed is None or (set(fields) | set(secrets)) - allowed or set(fields) & set(secrets):
        raise CredentialConnectionError("INVALID_CREDENTIAL", 422)
    if provider == "polymarket":
        pem = secrets.get("wallet_private_key")
        if pem is not None and len(pem.get_secret_value()) > 8192:
            raise CredentialConnectionError("INVALID_CREDENTIAL", 422)
    if environment == "LIVE" and confirm_environment != "LIVE":
        raise CredentialConnectionError("LIVE_CONFIRMATION_REQUIRED", 409)
    if runtime.credential_store is None:
        raise CredentialConnectionError("CREDENTIALS_NOT_CONFIGURED")

    old_profile = next(
        (
            item
            for item in runtime.credential_store.status_all()
            if item.provider == broker
            and item.environment == environment
            and item.profile_id == profile_id
        ),
        None,
    )
    old_fields = {} if old_profile is None else _account_meta(old_profile, broker)
    live_rows: tuple[LiveCredentialBindingV1, ...] = ()
    if environment == "LIVE":
        if live_provider is None:
            raise CredentialConnectionError("LIVE_BINDING_UNAVAILABLE")
        live_rows = _affected_live_accounts_for_rotation(
            runtime, live_provider, broker, old_fields, fields
        )
        _deactivate(request, runtime, live_rows)

    values: dict[str, object] = dict(fields)
    values.update(secrets)
    if environment == "LIVE":
        values["confirm_environment"] = "LIVE"
    profile = runtime.credential_store.put_profile(broker, environment, profile_id, values)
    for row in live_rows:
        assert live_provider is not None
        runtime.live_bindings.bump_credential_revision(
            row.organization_id, row.account_id, live_provider
        )
    reference = CredentialReferenceV1(
        provider_id=live_provider or provider,
        environment=environment,
        profile_id=profile_id,
        revision=profile.revision,
    )
    status = _record_status(
        runtime,
        reference,
        configured=True,
        tested_ns=runtime.status.read_status(reference).last_tested_ns,
        rotated_ns=runtime.clock_ns(),
    )
    return profile, reference, status


def _remove_broker_profile(
    request: Request,
    runtime: CredentialConnectionsRuntimeV1,
    *,
    provider: str,
    broker: str,
    environment: str,
    profile_id: str,
    live_provider: str | None = None,
) -> CredentialReferenceV1:
    """Shared broker-profile removal path for Connections and legacy URLs."""
    if runtime.credential_store is None:
        raise CredentialConnectionError("CREDENTIALS_NOT_CONFIGURED")
    old_profile = next(
        (
            item
            for item in runtime.credential_store.status_all()
            if item.provider == broker
            and item.environment == environment
            and item.profile_id == profile_id
        ),
        None,
    )
    old_fields = {} if old_profile is None else _account_meta(old_profile, broker)
    live_rows: tuple[LiveCredentialBindingV1, ...] = ()
    if environment == "LIVE":
        if live_provider is None:
            raise CredentialConnectionError("LIVE_BINDING_UNAVAILABLE")
        live_rows = _affected_live_accounts(runtime, live_provider, broker, old_fields)
        _deactivate(request, runtime, live_rows)
    runtime.credential_store.delete_profile(broker, environment, profile_id)
    for row in live_rows:
        assert live_provider is not None
        runtime.live_bindings.bump_credential_revision(
            row.organization_id, row.account_id, live_provider
        )
    return CredentialReferenceV1(
        provider_id=live_provider or provider,
        environment=environment,
        profile_id=profile_id,
        revision=0 if old_profile is None else old_profile.revision,
    )


def _validate_private_key_pem(buffer: bytearray) -> str:
    """Validate a bounded PEM envelope and DER sequence without persisting a temp file."""
    try:
        value = buffer.decode("ascii")
        lines = value.strip().splitlines()
        if len(lines) < 3 or not lines[0].startswith("-----BEGIN "):
            raise ValueError
        label = lines[0][11:-5]
        if label not in {"PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"}:
            raise ValueError
        if lines[-1] != f"-----END {label}-----":
            raise ValueError
        encoded = "".join(lines[1:-1])
        if not encoded or re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", encoded, re.ASCII) is None:
            raise ValueError
        der = base64.b64decode(encoded, validate=True)
        if len(der) < 16 or der[0] != 0x30:
            raise ValueError
        first_length = der[1]
        if first_length < 0x80:
            header_size = 2
            content_length = first_length
        else:
            length_octets = first_length & 0x7F
            if length_octets == 0 or length_octets > 4 or len(der) < 2 + length_octets:
                raise ValueError
            header_size = 2 + length_octets
            content_length = int.from_bytes(der[2:header_size], "big")
        if header_size + content_length != len(der):
            raise ValueError
        return value
    except (UnicodeDecodeError, ValueError, TypeError):
        raise CredentialConnectionError("INVALID_CREDENTIAL", 422) from None


def _record(
    runtime: CredentialConnectionsRuntimeV1,
    provider: str,
    action: Literal["REPLACE", "REMOVE", "TEST"],
    outcome: Literal["SUCCEEDED", "FAILED"],
    actor: str,
    code: str | None = None,
) -> None:
    try:
        now = runtime.clock_ns()
        if type(now) is not int or now < 0:
            raise ValueError
        runtime.audit.append(
            CredentialAuditEventV1(
                provider_id=provider,
                action=action,
                outcome=outcome,
                actor_id=actor,
                occurred_at_ns=now,
                error_code=code,
            )
        )
    except Exception:
        raise CredentialConnectionError("AUDIT_UNAVAILABLE") from None


def create_credential_connections_router(
    runtime: CredentialConnectionsRuntimeV1 | None,
    *,
    include_connections: bool = True,
    include_legacy: bool = True,
) -> APIRouter:
    if runtime is not None and type(runtime) is not CredentialConnectionsRuntimeV1:
        raise TypeError("CREDENTIALS_NOT_CONFIGURED")
    router = APIRouter()
    connections_router = APIRouter(prefix="/connections/credentials", tags=["connections"])
    legacy_router = APIRouter(prefix="/live-trading/credentials", tags=["credentials"])
    legacy_router.add_api_route("", legacy_status, methods=["GET"])
    confirmation_port = (
        runtime.confirmation_port
        if runtime is not None and runtime.confirmation_port is not None
        else InMemoryCredentialConfirmationPortV1()
    )

    @connections_router.get("")
    def list_status(request: Request) -> JSONResponse:
        if runtime is None:
            return _json_error(503, "CREDENTIALS_NOT_CONFIGURED")
        principal = _principal(request)
        if isinstance(principal, JSONResponse):
            return principal
        rows: list[dict[str, object]] = []
        for provider in sorted((*DATA_SECRET_NAMES, *DATA_KEYLESS, *BROKER_IDS)):
            environments = (
                ("DEVELOPMENT",)
                if provider in DATA_SECRET_NAMES or provider in DATA_KEYLESS
                else BROKER_ENVIRONMENTS[provider]
            )
            for environment in dict.fromkeys(environments):
                reference, name, broker = _reference(provider, environment)
                try:
                    if name is not None:
                        configured = bool(
                            runtime.project_secret_store
                            and runtime.project_secret_store.configured(
                                reference.vault_reference or "", name
                            )
                        )
                    elif broker is not None:
                        configured = _profile_revision(runtime, broker, environment) > 0
                    else:
                        configured = True
                    status = runtime.status.read_status(reference)
                    if type(status) is not CredentialStatusV1:
                        raise ValueError
                    status = status.model_copy(
                        update={"error_code": _safe_test_error(status.error_code)}
                    )
                except Exception:
                    return _json_error(503, "CREDENTIALS_UNAVAILABLE")
                rows.append(
                    status.model_copy(update={"configured": configured}).model_dump(mode="json")
                )
        return JSONResponse(content={"credentials": rows}, headers=_NO_STORE)

    @connections_router.post("/{provider}/{environment}/{profile_id}/replace-intent")
    def replace_intent(
        provider: str, environment: str, profile_id: str, request: Request
    ) -> JSONResponse:
        if runtime is None:
            return _json_error(503, "CREDENTIALS_NOT_CONFIGURED")
        principal = _principal(request)
        if isinstance(principal, JSONResponse):
            return principal
        if profile_id != _PROFILE:
            return _json_error(404, "PROFILE_NOT_FOUND")
        try:
            _reference(provider, environment)
            if provider in DATA_KEYLESS:
                return _json_error(422, "REPLACE_NOT_SUPPORTED")
        except CredentialConnectionError as exc:
            return _json_error(exc.status_code, exc.code)
        return JSONResponse(
            content={
                "intent": "OPEN_REPLACE_FORM",
                "provider_id": provider,
                "environment": environment,
                "profile_id": profile_id,
            },
            headers=_NO_STORE,
        )

    @connections_router.post("/{provider}/{environment}/{profile_id}/remove-confirmation")
    def issue_remove_confirmation(
        provider: str, environment: str, profile_id: str, request: Request
    ) -> JSONResponse:
        if runtime is None:
            return _json_error(503, "CREDENTIALS_NOT_CONFIGURED")
        principal = _principal(request)
        if isinstance(principal, JSONResponse):
            return principal
        if not _same_origin_loopback(request):
            return _json_error(403, "CONFIRMATION_ORIGIN_DENIED")
        if profile_id != _PROFILE:
            return _json_error(404, "PROFILE_NOT_FOUND")
        try:
            _reference(provider, environment)
            token, expires_at_ns = confirmation_port.issue(
                principal_id=principal.principal_id,
                provider_id=provider,
                environment=environment,
                profile_id=profile_id,
                action="REMOVE",
                now_ns=runtime.clock_ns(),
            )
        except CredentialConnectionError as exc:
            return _json_error(exc.status_code, exc.code)
        except Exception:
            return _json_error(503, "CONFIRMATION_UNAVAILABLE")
        return JSONResponse(
            content={"confirmation_token": token, "expires_at_ns": str(expires_at_ns)},
            headers=_NO_STORE,
        )

    @connections_router.put("/{provider}/{environment}/{profile_id}")
    def replace(
        provider: str,
        environment: str,
        profile_id: str,
        body: CredentialActionRequestV1,
        request: Request,
    ) -> JSONResponse:
        if runtime is None:
            return _json_error(503, "CREDENTIALS_NOT_CONFIGURED")
        principal = _principal(request)
        if isinstance(principal, JSONResponse):
            return principal
        if profile_id != _PROFILE:
            return _json_error(404, "PROFILE_NOT_FOUND")
        try:
            reference, data_name, broker = _reference(provider, environment)
            if data_name is not None:
                if (
                    set(body.secrets) != {"api_key"}
                    or body.fields
                    or runtime.project_secret_store is None
                ):
                    raise CredentialConnectionError("INVALID_CREDENTIAL", 422)
                if body.secrets["api_key"].get_secret_value().lstrip().startswith("-----BEGIN"):
                    raise CredentialConnectionError("INVALID_CREDENTIAL", 422)
                runtime.project_secret_store.put(
                    reference.vault_reference or "", data_name, body.secrets["api_key"]
                )
                now = runtime.clock_ns()
                previous = runtime.status.read_status(reference)
                status = _record_status(
                    runtime,
                    reference,
                    configured=True,
                    tested_ns=previous.last_tested_ns,
                    rotated_ns=now,
                )
            elif broker is not None:
                if provider == "kalshi":
                    raise CredentialConnectionError("INVALID_CREDENTIAL", 422)
                _profile, reference, status = _replace_broker_profile(
                    request,
                    runtime,
                    provider=provider,
                    broker=broker,
                    environment=environment,
                    profile_id=profile_id,
                    fields=body.fields,
                    secrets=body.secrets,
                    confirm_environment=body.confirm_environment,
                    live_provider=provider,
                )
            else:
                raise CredentialConnectionError("PROVIDER_NOT_FOUND", 404)
            _record(runtime, provider, "REPLACE", "SUCCEEDED", principal.principal_id)
            status = runtime.status.read_status(reference)
            if type(status) is not CredentialStatusV1:
                raise CredentialConnectionError("CREDENTIALS_UNAVAILABLE")
            payload = status.model_dump(mode="json")
            payload["configured"] = True
            return JSONResponse(content=payload, headers=_NO_STORE)
        except CredentialConnectionError as exc:
            with suppress(CredentialConnectionError):
                _record(runtime, provider, "REPLACE", "FAILED", principal.principal_id, exc.code)
            return _json_error(exc.status_code, exc.code)
        except Exception:
            with suppress(CredentialConnectionError):
                _record(
                    runtime,
                    provider,
                    "REPLACE",
                    "FAILED",
                    principal.principal_id,
                    "CREDENTIALS_UNAVAILABLE",
                )
            return _json_error(503, "CREDENTIALS_UNAVAILABLE")

    @connections_router.post("/{provider}/{environment}/{profile_id}/test")
    def test(provider: str, environment: str, profile_id: str, request: Request) -> JSONResponse:
        if runtime is None:
            return _json_error(503, "CREDENTIALS_NOT_CONFIGURED")
        principal = _principal(request)
        if isinstance(principal, JSONResponse):
            return principal
        try:
            if profile_id != _PROFILE:
                raise CredentialConnectionError("PROFILE_NOT_FOUND", 404)
            reference, name, broker = _reference(provider, environment)
            revision = _profile_revision(runtime, broker, environment)
            reference = reference.model_copy(update={"revision": revision})
            result = runtime.tester.test(reference)
            if type(result) is not CredentialTestResultV1:
                raise CredentialConnectionError("TEST_UNAVAILABLE")
            safe_error = _safe_test_error(result.error_code)
            runtime.status.record_status(
                CredentialStatusV1(
                    provider_id=provider,
                    environment=environment,
                    configured=(
                        runtime.project_secret_store.configured(
                            reference.vault_reference or "", name
                        )
                        if name and runtime.project_secret_store
                        else revision > 0
                    ),
                    verified=result.verified,
                    last_tested_ns=runtime.clock_ns(),
                    error_code=safe_error,
                )
            )
            _record(
                runtime,
                provider,
                "TEST",
                "SUCCEEDED" if result.verified else "FAILED",
                principal.principal_id,
                safe_error,
            )
            return JSONResponse(
                content={
                    "provider_id": provider,
                    "verified": result.verified,
                    "error_code": safe_error,
                },
                headers=_NO_STORE,
            )
        except CredentialConnectionError as exc:
            with suppress(CredentialConnectionError):
                _record(runtime, provider, "TEST", "FAILED", principal.principal_id, exc.code)
            return _json_error(exc.status_code, exc.code)
        except Exception:
            with suppress(CredentialConnectionError):
                _record(
                    runtime, provider, "TEST", "FAILED", principal.principal_id, "TEST_UNAVAILABLE"
                )
            return _json_error(503, "TEST_UNAVAILABLE")

    @connections_router.put("/{provider}/{environment}/{profile_id}/private-key")
    async def upload_kalshi_private_key(
        provider: str, environment: str, profile_id: str, request: Request
    ) -> JSONResponse:
        if runtime is None:
            return _json_error(503, "CREDENTIALS_NOT_CONFIGURED")
        principal = _principal(request)
        if isinstance(principal, JSONResponse):
            return principal
        buffer = bytearray()
        try:
            if provider != "kalshi" or profile_id != _PROFILE:
                raise CredentialConnectionError("PROVIDER_NOT_FOUND", 404)
            reference, _name, broker = _reference(provider, environment)
            if broker != "KALSHI" or runtime.credential_store is None:
                raise CredentialConnectionError("CREDENTIALS_NOT_CONFIGURED")
            if environment == "LIVE" and request.headers.get("x-confirm-environment") != "LIVE":
                raise CredentialConnectionError("LIVE_CONFIRMATION_REQUIRED", 409)
            if (
                request.headers.get("content-type", "").split(";", 1)[0]
                != "application/octet-stream"
            ):
                raise CredentialConnectionError("INVALID_CREDENTIAL", 422)
            key_name = request.headers.get("x-credential-key-name", "")
            if (
                not key_name
                or len(key_name) > 128
                or not re.fullmatch(r"[A-Za-z0-9._-]+", key_name)
            ):
                raise CredentialConnectionError("INVALID_CREDENTIAL", 422)
            try:
                declared_size = int(request.headers.get("content-length", "0"))
            except ValueError:
                raise CredentialConnectionError("INVALID_CREDENTIAL", 422) from None
            if declared_size < 1 or declared_size > _MAX_KALSHI_KEY_BYTES:
                raise CredentialConnectionError("INVALID_CREDENTIAL", 422)
            async for chunk in request.stream():
                if len(buffer) + len(chunk) > _MAX_KALSHI_KEY_BYTES:
                    raise CredentialConnectionError("INVALID_CREDENTIAL", 422)
                buffer.extend(chunk)
            if len(buffer) != declared_size or not buffer.startswith(b"-----BEGIN "):
                raise CredentialConnectionError("INVALID_CREDENTIAL", 422)
            private_key = _validate_private_key_pem(buffer)
            old_profile = next(
                (
                    item
                    for item in runtime.credential_store.status_all()
                    if item.provider == broker
                    and item.environment == environment
                    and item.profile_id == profile_id
                ),
                None,
            )
            old_fields = {} if old_profile is None else _account_meta(old_profile, broker)
            rows: tuple[LiveCredentialBindingV1, ...] = ()
            if environment == "LIVE":
                rows = _affected_live_accounts_for_rotation(
                    runtime, provider, broker, old_fields, {"key_name": key_name}
                )
                _deactivate(request, runtime, rows)
            profile = runtime.credential_store.put_profile(
                broker,
                environment,
                profile_id,
                {
                    "key_name": key_name,
                    "api_key": SecretStr(key_name),
                    "api_secret": SecretStr(private_key),
                },
            )
            for row in rows:
                runtime.live_bindings.bump_credential_revision(
                    row.organization_id, row.account_id, provider
                )
            reference = reference.model_copy(update={"revision": profile.revision})
            status = _record_status(
                runtime, reference, configured=True, rotated_ns=runtime.clock_ns()
            )
            _record(runtime, provider, "REPLACE", "SUCCEEDED", principal.principal_id)
            return JSONResponse(
                content=status.model_dump(mode="json"),
                headers=_NO_STORE,
            )
        except CredentialConnectionError as exc:
            with suppress(CredentialConnectionError):
                _record(runtime, provider, "REPLACE", "FAILED", principal.principal_id, exc.code)
            return _json_error(exc.status_code, exc.code)
        except Exception:
            with suppress(CredentialConnectionError):
                _record(
                    runtime,
                    provider,
                    "REPLACE",
                    "FAILED",
                    principal.principal_id,
                    "CREDENTIALS_UNAVAILABLE",
                )
            return _json_error(503, "CREDENTIALS_UNAVAILABLE")
        finally:
            buffer[:] = b"\x00" * len(buffer)

    @connections_router.delete("/{provider}/{environment}/{profile_id}")
    def remove(
        provider: str,
        environment: str,
        profile_id: str,
        body: CredentialActionRequestV1,
        request: Request,
    ) -> JSONResponse:
        if runtime is None:
            return _json_error(503, "CREDENTIALS_NOT_CONFIGURED")
        principal = _principal(request)
        if isinstance(principal, JSONResponse):
            return principal
        try:
            if profile_id != _PROFILE or body.confirm_environment not in {"LIVE", None}:
                raise CredentialConnectionError("INVALID_CREDENTIAL", 422)
            reference, name, broker = _reference(provider, environment)
            if environment == "LIVE" and body.confirm_environment != "LIVE":
                raise CredentialConnectionError("LIVE_CONFIRMATION_REQUIRED", 409)
            token = (
                body.confirmation_token.get_secret_value()
                if body.confirmation_token is not None
                else ""
            )
            if not confirmation_port.consume(
                token=token,
                principal_id=principal.principal_id,
                provider_id=provider,
                environment=environment,
                profile_id=profile_id,
                action="REMOVE",
                now_ns=runtime.clock_ns(),
            ):
                raise CredentialConnectionError("CONFIRMATION_REQUIRED", 403)
            if broker is not None:
                reference = _remove_broker_profile(
                    request,
                    runtime,
                    provider=provider,
                    broker=broker,
                    environment=environment,
                    profile_id=profile_id,
                    live_provider=provider,
                )
            elif name is not None and runtime.project_secret_store is not None:
                runtime.project_secret_store.remove(reference.vault_reference or "", name)
            else:
                raise CredentialConnectionError("CREDENTIALS_NOT_CONFIGURED")
            now = runtime.clock_ns()
            _record_status(runtime, reference, configured=False, rotated_ns=now)
            _record(runtime, provider, "REMOVE", "SUCCEEDED", principal.principal_id)
            return JSONResponse(
                content={"provider_id": provider, "removed": True}, headers=_NO_STORE
            )
        except CredentialConnectionError as exc:
            with suppress(CredentialConnectionError):
                _record(runtime, provider, "REMOVE", "FAILED", principal.principal_id, exc.code)
            return _json_error(exc.status_code, exc.code)
        except Exception:
            with suppress(CredentialConnectionError):
                _record(
                    runtime,
                    provider,
                    "REMOVE",
                    "FAILED",
                    principal.principal_id,
                    "CREDENTIALS_UNAVAILABLE",
                )
            return _json_error(503, "CREDENTIALS_UNAVAILABLE")

    @legacy_router.put("/{provider}/{environment}/{profile_id}")
    def legacy_replace(
        provider: str,
        environment: str,
        profile_id: str,
        body: CredentialPutRequest,
        request: Request,
    ) -> JSONResponse:
        if runtime is None:
            return _json_error(503, "CREDENTIALS_NOT_CONFIGURED")
        principal = _principal(request)
        if isinstance(principal, JSONResponse):
            return principal
        provider_config = _LEGACY_PROVIDERS.get(provider.upper())
        if provider_config is None:
            return _json_error(404, "PROVIDER_NOT_FOUND")
        provider_id, broker = provider_config
        try:
            _validate_id(profile_id, "profile_id")
        except Exception:
            return _json_error(404, "PROFILE_NOT_FOUND")
        if provider_id == "mcp":
            if environment != "PAPER" or body.server_id != profile_id:
                return _json_error(422, "INVALID_CREDENTIAL")
            allowed_fields = _LEGACY_MCP_FIELDS
            live_provider = None
        else:
            try:
                _reference(provider_id, environment)
            except CredentialConnectionError as exc:
                return _json_error(exc.status_code, exc.code)
            allowed_fields = BROKER_FIELDS[provider_id]
            live_provider = provider_id
        try:
            payload = body.model_dump(exclude_unset=True)
            confirm_environment = payload.pop("confirm_environment", None)
            secret_names = {"key_id", "secret_key", "password", "token"}
            fields = {
                key: value
                for key, value in payload.items()
                if key not in secret_names and value is not None
            }
            secrets_by_name = {
                key: value
                for key, value in payload.items()
                if key in secret_names and value is not None
            }
            profile, _reference_value, status = _replace_broker_profile(
                request,
                runtime,
                provider=provider_id,
                broker=broker,
                environment=environment,
                profile_id=profile_id,
                fields=fields,
                secrets=secrets_by_name,
                confirm_environment=confirm_environment,
                allowed_fields=allowed_fields,
                live_provider=live_provider,
                allow_custom_profile=True,
            )
            _record(runtime, provider_id, "REPLACE", "SUCCEEDED", principal.principal_id)
            require(profile, "leviathan_vault.app_credentials.profile.v1")
            return JSONResponse(
                content={
                    "provider": profile.provider,
                    "environment": profile.environment,
                    "profile": profile.profile_id,
                    "revision": profile.revision,
                    "configured": dict(profile.configured),
                    "updated_at": profile.updated_at.isoformat(),
                    "verified": status.verified,
                },
                headers=_NO_STORE,
            )
        except CredentialConnectionError as exc:
            with suppress(CredentialConnectionError):
                _record(runtime, provider_id, "REPLACE", "FAILED", principal.principal_id, exc.code)
            return _json_error(exc.status_code, exc.code)
        except Exception:
            with suppress(CredentialConnectionError):
                _record(
                    runtime,
                    provider_id,
                    "REPLACE",
                    "FAILED",
                    principal.principal_id,
                    "CREDENTIALS_UNAVAILABLE",
                )
            return _json_error(503, "CREDENTIALS_UNAVAILABLE")

    @legacy_router.post("/{provider}/{environment}/{profile_id}/remove-confirmation")
    def legacy_remove_confirmation(
        provider: str, environment: str, profile_id: str, request: Request
    ) -> JSONResponse:
        if runtime is None:
            return _json_error(503, "CREDENTIALS_NOT_CONFIGURED")
        principal = _principal(request)
        if isinstance(principal, JSONResponse):
            return principal
        if not _same_origin_loopback(request):
            return _json_error(403, "CONFIRMATION_ORIGIN_DENIED")
        provider_config = _LEGACY_PROVIDERS.get(provider.upper())
        if provider_config is None:
            return _json_error(404, "PROVIDER_NOT_FOUND")
        provider_id, _broker = provider_config
        try:
            _validate_id(profile_id, "profile_id")
        except Exception:
            return _json_error(404, "PROFILE_NOT_FOUND")
        try:
            if provider_id == "mcp":
                if environment != "PAPER":
                    raise CredentialConnectionError("INVALID_ENVIRONMENT", 400)
            else:
                _reference(provider_id, environment)
            token, expires_at_ns = confirmation_port.issue(
                principal_id=principal.principal_id,
                provider_id=provider_id,
                environment=environment,
                profile_id=profile_id,
                action="REMOVE",
                now_ns=runtime.clock_ns(),
            )
            return JSONResponse(
                content={"confirmation_token": token, "expires_at_ns": str(expires_at_ns)},
                headers=_NO_STORE,
            )
        except CredentialConnectionError as exc:
            return _json_error(exc.status_code, exc.code)
        except Exception:
            return _json_error(503, "CONFIRMATION_UNAVAILABLE")

    @legacy_router.delete("/{provider}/{environment}/{profile_id}", status_code=204)
    def legacy_remove(
        provider: str,
        environment: str,
        profile_id: str,
        request: Request,
        body: CredentialDeleteRequest | None = None,
    ) -> Response:
        if runtime is None:
            return _json_error(503, "CREDENTIALS_NOT_CONFIGURED")
        principal = _principal(request)
        if isinstance(principal, JSONResponse):
            return principal
        provider_config = _LEGACY_PROVIDERS.get(provider.upper())
        if provider_config is None:
            return _json_error(404, "PROVIDER_NOT_FOUND")
        provider_id, broker = provider_config
        try:
            _validate_id(profile_id, "profile_id")
        except Exception:
            return _json_error(404, "PROFILE_NOT_FOUND")
        if provider_id == "mcp":
            if environment != "PAPER":
                return _json_error(400, "INVALID_ENVIRONMENT")
            live_provider = None
        else:
            try:
                _reference(provider_id, environment)
            except CredentialConnectionError as exc:
                return _json_error(exc.status_code, exc.code)
            live_provider = provider_id
        if environment == "LIVE" and (body is None or body.confirm_environment != "LIVE"):
            return _json_error(409, "LIVE_CONFIRMATION_REQUIRED")
        token = (
            body.confirmation_token.get_secret_value()
            if body is not None and body.confirmation_token is not None
            else ""
        )
        try:
            if not confirmation_port.consume(
                token=token,
                principal_id=principal.principal_id,
                provider_id=provider_id,
                environment=environment,
                profile_id=profile_id,
                action="REMOVE",
                now_ns=runtime.clock_ns(),
            ):
                raise CredentialConnectionError("CONFIRMATION_REQUIRED", 403)
            reference = _remove_broker_profile(
                request,
                runtime,
                provider=provider_id,
                broker=broker,
                environment=environment,
                profile_id=profile_id,
                live_provider=live_provider,
            )
            _record_status(runtime, reference, configured=False, rotated_ns=runtime.clock_ns())
            _record(runtime, provider_id, "REMOVE", "SUCCEEDED", principal.principal_id)
            return Response(status_code=204, headers=_NO_STORE)
        except CredentialConnectionError as exc:
            with suppress(CredentialConnectionError):
                _record(runtime, provider_id, "REMOVE", "FAILED", principal.principal_id, exc.code)
            return _json_error(exc.status_code, exc.code)
        except Exception:
            with suppress(CredentialConnectionError):
                _record(
                    runtime,
                    provider_id,
                    "REMOVE",
                    "FAILED",
                    principal.principal_id,
                    "CREDENTIALS_UNAVAILABLE",
                )
            return _json_error(503, "CREDENTIALS_UNAVAILABLE")

    if include_connections:
        router.include_router(connections_router)
    if include_legacy:
        router.include_router(legacy_router)
    return router


__all__ = [
    "CredentialActionRequestV1",
    "CredentialAuditEventV1",
    "CredentialAuditPortV1",
    "CredentialConfirmationPortV1",
    "CredentialConnectionError",
    "CredentialConnectionsRuntimeV1",
    "CredentialLiveBindingPortV1",
    "CredentialStatusPortV1",
    "CredentialStatusV1",
    "CredentialTestResultV1",
    "CredentialTesterPortV1",
    "InMemoryCredentialConfirmationPortV1",
    "LiveCredentialBindingV1",
    "create_credential_connections_router",
]
