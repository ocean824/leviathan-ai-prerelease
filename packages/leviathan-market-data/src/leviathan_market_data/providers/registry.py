"""Injected, in-memory registry for provider availability and health."""

from __future__ import annotations

import re
from collections.abc import Callable
from enum import StrEnum
from threading import RLock
from types import ModuleType
from typing import Final, Protocol

from pydantic import model_validator

from leviathan_market_data.schema import INT64_MAX, MarketDataValueError, MarketModel

_PROVIDER_ID: Final[re.Pattern[str]] = re.compile(r"^[a-z][a-z0-9._-]{0,63}$")
_CAPABILITY: Final[re.Pattern[str]] = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_CREDENTIAL_NAME: Final[re.Pattern[str]] = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_VAULT_REF: Final[re.Pattern[str]] = re.compile(
    r"^vault://leviathan-ai/development/[A-Z0-9_-]+/[A-Z0-9_-]+$"
)


class CredentialRouteV1(StrEnum):
    """Where a configured provider resolves credentials; never carries a key."""

    VAULT_REF = "vault_ref"
    GATEWAY = "gateway"


class DataSourceStatusV1(StrEnum):
    NOT_CONFIGURED = "NOT_CONFIGURED"
    READY = "READY"
    DEGRADED = "DEGRADED"
    EXTERNAL_GATE = "EXTERNAL_GATE"
    DISABLED = "DISABLED"


class HealthErrorCodeV1(StrEnum):
    """Closed, content-free health error vocabulary safe for operator display."""

    AUTH_REJECTED = "AUTH_REJECTED"
    NETWORK_UNAVAILABLE = "NETWORK_UNAVAILABLE"
    PROVIDER_ERROR = "PROVIDER_ERROR"
    QUOTA_EXHAUSTED = "QUOTA_EXHAUSTED"
    RATE_LIMITED = "RATE_LIMITED"
    SCHEMA_MISMATCH = "SCHEMA_MISMATCH"
    SOURCE_STALE = "SOURCE_STALE"
    UNKNOWN = "UNKNOWN"


class ProviderRegistrationV1(MarketModel):
    """Non-secret provider metadata registered by an adapter or composition root."""

    provider_id: str
    display_name: str
    capabilities: tuple[str, ...]
    credential_names: tuple[str, ...]
    credential_route: CredentialRouteV1 | None = None
    credential_ref: str | None = None

    @model_validator(mode="after")
    def _validate_registration(self) -> ProviderRegistrationV1:
        if not _PROVIDER_ID.fullmatch(self.provider_id):
            raise MarketDataValueError("INVALID_PROVIDER_ID")
        if not self.display_name or len(self.display_name) > 128:
            raise MarketDataValueError("INVALID_PROVIDER_METADATA")
        if (
            not self.capabilities
            or any(not _CAPABILITY.fullmatch(capability) for capability in self.capabilities)
            or len(set(self.capabilities)) != len(self.capabilities)
        ):
            raise MarketDataValueError("INVALID_CAPABILITIES")
        if any(not _CREDENTIAL_NAME.fullmatch(name) for name in self.credential_names) or (
            len(set(self.credential_names)) != len(self.credential_names)
        ):
            raise MarketDataValueError("INVALID_CREDENTIAL_NAMES")
        if self.credential_route is None:
            if self.credential_ref is not None:
                raise MarketDataValueError("INVALID_CREDENTIAL_ROUTE")
            return self
        elif self.credential_route is CredentialRouteV1.VAULT_REF:
            if self.credential_ref is not None and not _VAULT_REF.fullmatch(self.credential_ref):
                raise MarketDataValueError("INVALID_CREDENTIAL_REFERENCE")
        elif self.credential_ref is not None:
            # Gateway credentials stay remote; desktop metadata carries no credential reference.
            raise MarketDataValueError("INVALID_CREDENTIAL_REFERENCE")
        if not self.credential_names and self.credential_route is not None:
            raise MarketDataValueError("UNEXPECTED_CREDENTIAL_ROUTE")
        if self.credential_route is CredentialRouteV1.VAULT_REF and self.credential_ref is None:
            raise MarketDataValueError("INVALID_CREDENTIAL_REFERENCE")
        return self


class ProviderHealthV1(MarketModel):
    """Sanitized provider health; event/source time and receipt time stay distinct."""

    provider_id: str
    status: DataSourceStatusV1
    source_time_ns: int | None = None
    received_time_ns: int | None = None
    error_code: HealthErrorCodeV1 | None = None

    @model_validator(mode="after")
    def _validate_health(self) -> ProviderHealthV1:
        if not _PROVIDER_ID.fullmatch(self.provider_id):
            raise MarketDataValueError("INVALID_PROVIDER_ID")
        times = (self.source_time_ns, self.received_time_ns)
        if any(
            value is not None and (type(value) is not int or value <= 0 or value > INT64_MAX)
            for value in times
        ):
            raise MarketDataValueError("INVALID_TIME")
        if (self.source_time_ns is None) != (self.received_time_ns is None):
            raise MarketDataValueError("INCOMPLETE_HEALTH_TIMES")
        if self.status is DataSourceStatusV1.NOT_CONFIGURED and (
            any(value is not None for value in times) or self.error_code is not None
        ):
            raise MarketDataValueError("INVALID_NOT_CONFIGURED_HEALTH")
        return self


class DataSourceSnapshotV1(MarketModel):
    """Operator-safe view of one registered provider and its latest health."""

    provider_id: str
    display_name: str
    capabilities: tuple[str, ...]
    requires_credentials: bool
    credential_route: CredentialRouteV1 | None
    status: DataSourceStatusV1
    source_time_ns: int | None
    received_time_ns: int | None
    error_code: HealthErrorCodeV1 | None


class ProviderAdapterModuleV1(Protocol):
    """Exact module-level surface required from Wave 34 provider adapters."""

    PROVIDER_ID: str
    CAPABILITIES: frozenset[str]
    CREDENTIAL_NAMES: tuple[str, ...]

    def build_adapter(
        self,
        *,
        resolve_secret: Callable[[str], str],
        transport: object,
    ) -> object: ...


class CredentialResolversV1:
    """Injected local and gateway routes; gateway results are proxy credentials."""

    __slots__ = ("gateway", "vault_ref")

    def __init__(
        self,
        *,
        vault_ref: Callable[[str, str], str] | None = None,
        gateway: Callable[[str, str], str] | None = None,
    ) -> None:
        self.vault_ref = vault_ref
        self.gateway = gateway


class DataSourceRegistryV1:
    """Thread-safe in-memory registry. It performs no I/O or credential resolution."""

    __slots__ = ("_adapters", "_health", "_lock", "_registrations")

    def __init__(self) -> None:
        self._lock = RLock()
        self._registrations: dict[str, ProviderRegistrationV1] = {}
        self._health: dict[str, ProviderHealthV1] = {}
        self._adapters: dict[str, object] = {}

    def register(self, registration: ProviderRegistrationV1) -> None:
        if type(registration) is not ProviderRegistrationV1:
            raise MarketDataValueError("INVALID_PROVIDER_REGISTRATION")
        with self._lock:
            if registration.provider_id in self._registrations:
                raise MarketDataValueError("DUPLICATE_PROVIDER")
            self._registrations[registration.provider_id] = registration

    def register_module(
        self,
        module: ProviderAdapterModuleV1 | ModuleType,
        *,
        credential_route: CredentialRouteV1 | None,
        credential_ref: str | None,
        resolvers: CredentialResolversV1,
        transport: object,
        display_name: str | None = None,
    ) -> object:
        """Register and build an adapter from its closed module-level contract."""
        provider_id = getattr(module, "PROVIDER_ID", None)
        capabilities = getattr(module, "CAPABILITIES", None)
        credential_names = getattr(module, "CREDENTIAL_NAMES", None)
        build_adapter = getattr(module, "build_adapter", None)
        if (
            type(provider_id) is not str
            or type(capabilities) is not frozenset
            or type(credential_names) is not tuple
            or any(type(capability) is not str for capability in capabilities)
            or any(type(name) is not str for name in credential_names)
            or not callable(build_adapter)
        ):
            raise MarketDataValueError("INVALID_ADAPTER_MODULE")
        registration = ProviderRegistrationV1(
            provider_id=provider_id,
            display_name=display_name or provider_id.replace("_", " ").title(),
            capabilities=tuple(sorted(capabilities)),
            credential_names=credential_names,
            credential_route=credential_route,
            credential_ref=credential_ref,
        )

        def resolve_secret(name: str) -> str:
            if type(name) is not str or name not in registration.credential_names:
                raise MarketDataValueError("CREDENTIAL_NAME_NOT_DECLARED")
            if registration.credential_route is CredentialRouteV1.VAULT_REF:
                resolver = resolvers.vault_ref
                reference = registration.credential_ref
                if resolver is None or reference is None:
                    raise MarketDataValueError("CREDENTIAL_ROUTE_UNAVAILABLE")
                try:
                    value = resolver(reference, name)
                except Exception:
                    raise MarketDataValueError("CREDENTIAL_UNAVAILABLE") from None
            elif registration.credential_route is CredentialRouteV1.GATEWAY:
                resolver = resolvers.gateway
                if resolver is None:
                    raise MarketDataValueError("CREDENTIAL_ROUTE_UNAVAILABLE")
                try:
                    # The gateway resolver returns only its proxy authorization material.
                    # The provider credential remains in the remote gateway.
                    value = resolver(registration.provider_id, name)
                except Exception:
                    raise MarketDataValueError("CREDENTIAL_UNAVAILABLE") from None
            else:
                raise MarketDataValueError("CREDENTIAL_ROUTE_NOT_CONFIGURED")
            if type(value) is not str or not value:
                raise MarketDataValueError("CREDENTIAL_UNAVAILABLE")
            return value

        try:
            adapter = build_adapter(resolve_secret=resolve_secret, transport=transport)
        except Exception:
            raise MarketDataValueError("ADAPTER_BUILD_FAILED") from None
        with self._lock:
            if registration.provider_id in self._registrations:
                raise MarketDataValueError("DUPLICATE_PROVIDER")
            self._registrations[registration.provider_id] = registration
            self._adapters[registration.provider_id] = adapter
        return adapter

    def adapter(self, provider_id: str) -> object | None:
        with self._lock:
            return self._adapters.get(provider_id)

    def update_health(self, health: ProviderHealthV1) -> None:
        if type(health) is not ProviderHealthV1:
            raise MarketDataValueError("INVALID_PROVIDER_HEALTH")
        with self._lock:
            registration = self._registrations.get(health.provider_id)
            if registration is None:
                raise MarketDataValueError("PROVIDER_NOT_REGISTERED")
            if (
                health.status is DataSourceStatusV1.READY
                and registration.credential_names
                and registration.credential_route is None
            ):
                raise MarketDataValueError("CREDENTIAL_ROUTE_NOT_CONFIGURED")
            self._health[health.provider_id] = health

    def get(self, provider_id: str) -> DataSourceSnapshotV1 | None:
        with self._lock:
            registration = self._registrations.get(provider_id)
            if registration is None:
                return None
            return _snapshot(registration, self._health.get(provider_id))

    def list_sources(self) -> tuple[DataSourceSnapshotV1, ...]:
        with self._lock:
            return tuple(
                _snapshot(self._registrations[provider_id], self._health.get(provider_id))
                for provider_id in sorted(self._registrations)
            )


def _snapshot(
    registration: ProviderRegistrationV1,
    health: ProviderHealthV1 | None,
) -> DataSourceSnapshotV1:
    status = DataSourceStatusV1.NOT_CONFIGURED if health is None else health.status
    return DataSourceSnapshotV1(
        provider_id=registration.provider_id,
        display_name=registration.display_name,
        capabilities=registration.capabilities,
        requires_credentials=bool(registration.credential_names),
        credential_route=registration.credential_route,
        status=status,
        source_time_ns=None if health is None else health.source_time_ns,
        received_time_ns=None if health is None else health.received_time_ns,
        error_code=None if health is None else health.error_code,
    )


__all__ = [
    "CredentialResolversV1",
    "CredentialRouteV1",
    "DataSourceRegistryV1",
    "DataSourceSnapshotV1",
    "DataSourceStatusV1",
    "HealthErrorCodeV1",
    "ProviderAdapterModuleV1",
    "ProviderHealthV1",
    "ProviderRegistrationV1",
]
