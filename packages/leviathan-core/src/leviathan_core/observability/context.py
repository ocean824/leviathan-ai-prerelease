"""Explicit closed-value provenance for local diagnostic context."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Never, SupportsIndex
from uuid import RFC_4122, UUID

_SLUG = re.compile(r"[a-z][a-z0-9-]{1,63}\Z", re.ASCII)
_STRATEGY = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}\Z", re.ASCII)
_INSTRUMENT = re.compile(r"[A-Z0-9][A-Z0-9._:/-]{0,63}\Z", re.ASCII)
_MIC = re.compile(r"[A-Z0-9]{4}\Z", re.ASCII)
_ULID = re.compile(r"[0-7][0-9A-HJKMNP-TV-Z]{25}\Z", re.ASCII)
_TRACE_ID = re.compile(r"[0-9a-f]{32}\Z", re.ASCII)
_SPAN_ID = re.compile(r"[0-9a-f]{16}\Z", re.ASCII)
_SEMVER = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+){0,2}))?\Z",
    re.ASCII,
)
_ENVS = frozenset({"development", "staging", "production"})


class DiagnosticRegistryError(ValueError):
    """Safe registry error containing only a fixed code and field label."""

    def __init__(self, code: str, field_name: str) -> None:
        self.code = code
        self.field_name = field_name
        super().__init__(f"{code} field={field_name}")


class ObservationContextError(ValueError):
    """Safe context error containing no caller value."""

    def __init__(self, code: str, field_name: str) -> None:
        self.code = code
        self.field_name = field_name
        super().__init__(f"{code} field={field_name}")


class DiagnosticIdError(ValueError):
    """Safe generated-ID error containing no candidate identifier."""

    def __init__(self, kind: str) -> None:
        self.code = "INVALID_GENERATED_ID"
        super().__init__(f"{self.code} kind={kind}")


def _digest_strings(values: Iterable[str]) -> str:
    encoded = json.dumps(sorted(values), ensure_ascii=True, separators=(",", ":")).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _digest_ordered_strings(values: Iterable[str]) -> str:
    encoded = json.dumps(list(values), ensure_ascii=True, separators=(",", ":")).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class RegistrySnapshotV1:
    """Immutable trusted registry snapshot with a content-derived ID."""

    members: frozenset[str]
    snapshot_id: str = field(init=False)

    def __post_init__(self) -> None:
        try:
            members = frozenset(self.members)
        except TypeError as exc:
            raise DiagnosticRegistryError("REGISTRY_INVALID", "members") from exc
        if not members or any(
            not isinstance(member, str)
            or not member.isascii()
            or not 1 <= len(member) <= 128
            or any(ord(char) < 33 or ord(char) > 126 for char in member)
            for member in members
        ):
            raise DiagnosticRegistryError("REGISTRY_INVALID", "members")
        object.__setattr__(self, "members", members)
        object.__setattr__(self, "snapshot_id", _digest_strings(members))

    @classmethod
    def from_members(cls, members: Iterable[str]) -> RegistrySnapshotV1:
        return cls(frozenset(members))


@dataclass(frozen=True, slots=True)
class DiagnosticRegistriesV1:
    """Five injected snapshots; no code-defined default or dynamic members."""

    services: RegistrySnapshotV1
    components: RegistrySnapshotV1
    strategies: RegistrySnapshotV1
    instruments: RegistrySnapshotV1
    venues: RegistrySnapshotV1
    registry_bundle_id: str = field(init=False)

    def __post_init__(self) -> None:
        for name, grammar in (
            ("services", _SLUG),
            ("components", _SLUG),
            ("strategies", _STRATEGY),
            ("instruments", _INSTRUMENT),
            ("venues", _MIC),
        ):
            snapshot = getattr(self, name)
            if not isinstance(snapshot, RegistrySnapshotV1):
                raise DiagnosticRegistryError("REGISTRY_REQUIRED", name)
            if any(grammar.fullmatch(member) is None for member in snapshot.members):
                raise DiagnosticRegistryError("REGISTRY_INVALID", name)
        object.__setattr__(
            self,
            "registry_bundle_id",
            _digest_ordered_strings(
                (
                    self.services.snapshot_id,
                    self.components.snapshot_id,
                    self.strategies.snapshot_id,
                    self.instruments.snapshot_id,
                    self.venues.snapshot_id,
                )
            ),
        )


@dataclass(frozen=True, slots=True, init=False)
class GeneratedIdV1:
    """A factory-issued identifier token; its issuer is private to that factory."""

    value: str
    kind: str
    _issuer: object = field(repr=False, compare=False)

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError("use DiagnosticIdFactoryV1")

    def is_issued_by(self, issuer: object) -> bool:
        """Check issuer identity without exposing or copying the capability."""
        return self._issuer is issuer

    def __copy__(self) -> Never:
        raise TypeError("generated identifier cannot be copied")

    def __deepcopy__(self, memo: dict[int, object]) -> Never:
        raise TypeError("generated identifier cannot be copied")

    def __reduce__(self) -> Never:
        raise TypeError("generated identifier cannot be pickled")

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        raise TypeError("generated identifier cannot be pickled")


def _make_generated_id(*, value: str, kind: str, issuer: object) -> GeneratedIdV1:
    """Internal keyword-only constructor for trusted in-process factory code."""
    token = object.__new__(GeneratedIdV1)
    object.__setattr__(token, "value", value)
    object.__setattr__(token, "kind", kind)
    object.__setattr__(token, "_issuer", issuer)
    return token


@dataclass(frozen=True, slots=True)
class DiagnosticIdFactoryV1:
    """Trusted injected generator; never wraps inbound strings as generated IDs."""

    uuid4_factory: Callable[[], UUID] = field(repr=False)
    order_id_factory: Callable[[], str] | None = field(default=None, repr=False)
    _issuer: object = field(default_factory=object, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not callable(self.uuid4_factory):
            raise DiagnosticIdError("uuid4_factory")
        if self.order_id_factory is not None and not callable(self.order_id_factory):
            raise DiagnosticIdError("order_id_factory")

    def _uuid4(self, kind: str) -> UUID:
        value = self.uuid4_factory()
        if not isinstance(value, UUID) or value.variant != RFC_4122 or value.version != 4:
            raise DiagnosticIdError(kind)
        return value

    def _mint_uuid(self, kind: str) -> GeneratedIdV1:
        return _make_generated_id(
            value=str(self._uuid4(kind)), kind=kind, issuer=self._issuer
        )

    def mint_correlation_id(self) -> GeneratedIdV1:
        return self._mint_uuid("correlation")

    def mint_request_id(self) -> GeneratedIdV1:
        return self._mint_uuid("request")

    def mint_event_id(self) -> GeneratedIdV1:
        return self._mint_uuid("event")

    def mint_order_id(self) -> GeneratedIdV1:
        if self.order_id_factory is None:
            return self._mint_uuid("order")
        value = self.order_id_factory()
        if not isinstance(value, str) or not (
            _is_uuid4(value) or _ULID.fullmatch(value) is not None
        ):
            raise DiagnosticIdError("order")
        return _make_generated_id(
            value=value, kind="order", issuer=self._issuer
        )

    def mint_trace_id(self) -> GeneratedIdV1:
        value = self._uuid4("trace").hex
        return _make_generated_id(
            value=value, kind="trace", issuer=self._issuer
        )

    def mint_span_id(self) -> GeneratedIdV1:
        value = self._uuid4("span").hex[:16]
        return _make_generated_id(
            value=value, kind="span", issuer=self._issuer
        )

    def owns(self, token: object, kind: str) -> bool:
        if not isinstance(token, GeneratedIdV1):
            return False
        try:
            if not token.is_issued_by(self._issuer) or token.kind != kind:
                return False
            value = token.value
        except AttributeError:
            return False
        if kind in {"correlation", "request", "event"}:
            return _is_uuid4(value)
        if kind == "order":
            return _is_uuid4(value) or _ULID.fullmatch(value) is not None
        if kind == "trace":
            return _TRACE_ID.fullmatch(value) is not None and value != "0" * 32
        if kind == "span":
            return _SPAN_ID.fullmatch(value) is not None and value != "0" * 16
        return False

    def __copy__(self) -> Never:
        raise TypeError("diagnostic ID factory cannot be copied")

    def __deepcopy__(self, memo: dict[int, object]) -> Never:
        raise TypeError("diagnostic ID factory cannot be copied")

    def __reduce__(self) -> Never:
        raise TypeError("diagnostic ID factory cannot be pickled")

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        raise TypeError("diagnostic ID factory cannot be pickled")


def _is_uuid4(value: str) -> bool:
    try:
        parsed = UUID(value)
    except (TypeError, ValueError, AttributeError):
        return False
    return parsed.variant == RFC_4122 and parsed.version == 4 and str(parsed) == value


@dataclass(frozen=True, slots=True)
class BuildIdentityV1:
    """Build-manifest identity injected once by the hosting process."""

    version: str

    def __post_init__(self) -> None:
        match = (
            _SEMVER.fullmatch(self.version)
            if isinstance(self.version, str) and len(self.version) <= 64
            else None
        )
        if match is None:
            raise ObservationContextError("BUILD_IDENTITY_INVALID", "version")
        prerelease = match.group(1)
        if prerelease is not None:
            parts = prerelease.split(".")
            if any(
                len(part) > 16 or (len(part) > 1 and part.startswith("0") and part.isdigit())
                for part in parts
            ):
                raise ObservationContextError("BUILD_IDENTITY_INVALID", "version")


@dataclass(frozen=True, slots=True)
class DiagnosticRuntimeV1:
    """Process-injected immutable dependencies, never ambient globals."""

    registries: DiagnosticRegistriesV1
    id_factory: DiagnosticIdFactoryV1
    build_identity: BuildIdentityV1

    def __post_init__(self) -> None:
        if not isinstance(self.registries, DiagnosticRegistriesV1):
            raise DiagnosticRegistryError("REGISTRY_REQUIRED", "registries")
        if not isinstance(self.id_factory, DiagnosticIdFactoryV1):
            raise ObservationContextError("ID_FACTORY_REQUIRED", "id_factory")
        if not isinstance(self.build_identity, BuildIdentityV1):
            raise ObservationContextError("BUILD_IDENTITY_REQUIRED", "build_identity")


@dataclass(frozen=True, slots=True, init=False, repr=False)
class ObservationContextV1:
    """Diagnostic identity produced only through create or explicit propagation."""

    runtime: DiagnosticRuntimeV1 = field(repr=False)
    service: str
    component: str
    version: str
    env: str
    registry_bundle_id: str
    correlation_id: UUID
    request_id: str
    trace_id: str | None
    span_id: str | None
    parent_span_id: str | None
    strategy_id: str | None
    order_id: str | None
    symbol: str | None
    venue: str | None

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError("use ObservationContextV1.create")

    @classmethod
    def _construct(cls, **values: object) -> ObservationContextV1:
        """Internal keyword-only constructor after create/copy_context validation."""
        result = object.__new__(cls)
        for name in cls.__dataclass_fields__:
            object.__setattr__(result, name, values[name])
        return result

    @classmethod
    def create(
        cls,
        *,
        runtime: DiagnosticRuntimeV1,
        service: str,
        component: str,
        env: str,
        strategy_id: str | None = None,
        order_id: GeneratedIdV1 | None = None,
        symbol: str | None = None,
        venue: str | None = None,
        trace: bool = False,
    ) -> ObservationContextV1:
        if not isinstance(runtime, DiagnosticRuntimeV1):
            raise DiagnosticRegistryError("REGISTRY_REQUIRED", "runtime")
        registries = runtime.registries
        for name, value, snapshot in (
            ("service", service, registries.services),
            ("component", component, registries.components),
            ("strategy_id", strategy_id, registries.strategies),
            ("symbol", symbol, registries.instruments),
            ("venue", venue, registries.venues),
        ):
            if value is not None and (not isinstance(value, str) or value not in snapshot.members):
                raise ObservationContextError("REGISTRY_NON_MEMBER", name)
        if not isinstance(env, str) or env not in _ENVS:
            raise ObservationContextError("CONTEXT_ENUM_INVALID", "env")
        if order_id is not None and not runtime.id_factory.owns(order_id, "order"):
            raise ObservationContextError("GENERATED_ID_REQUIRED", "order_id")
        if not isinstance(trace, bool):
            raise ObservationContextError("CONTEXT_ENUM_INVALID", "trace")
        correlation = runtime.id_factory.mint_correlation_id()
        request = runtime.id_factory.mint_request_id()
        trace_id = runtime.id_factory.mint_trace_id().value if trace else None
        span_id = runtime.id_factory.mint_span_id().value if trace else None
        return cls._construct(
            runtime=runtime,
            service=service,
            component=component,
            version=runtime.build_identity.version,
            env=env,
            registry_bundle_id=registries.registry_bundle_id,
            correlation_id=UUID(correlation.value),
            request_id=request.value,
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=None,
            strategy_id=strategy_id,
            order_id=order_id.value if order_id is not None else None,
            symbol=symbol,
            venue=venue,
        )

    def child_span(self) -> ObservationContextV1:
        """Create an explicit child span with a fresh OBS-001-issued span ID."""
        if self.trace_id is None or self.span_id is None:
            raise ObservationContextError("CONTEXT_TRACE_REQUIRED", "span_id")
        span = self.runtime.id_factory.mint_span_id()
        if not self.runtime.id_factory.owns(span, "span"):
            raise ObservationContextError("GENERATED_ID_REQUIRED", "span_id")
        values = {
            name: getattr(self, name) for name in self.__dataclass_fields__
        }
        values["span_id"] = span.value
        values["parent_span_id"] = self.span_id
        return self._construct(**values)

    def __copy__(self) -> ObservationContextV1:
        raise TypeError("use copy_context")

    def __deepcopy__(self, memo: dict[int, object]) -> ObservationContextV1:
        raise TypeError("use copy_context")

    def __reduce__(self) -> Never:
        raise TypeError("diagnostic context cannot be pickled")

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        raise TypeError("diagnostic context cannot be pickled")

    def copy_explicit(self) -> ObservationContextV1:
        """Internal propagation operation used by the public copy_context helper."""
        return self._construct(
            **{name: getattr(self, name) for name in self.__dataclass_fields__}
        )


def copy_context(context: ObservationContextV1) -> ObservationContextV1:
    """Copy across a task or queue boundary only at an explicit call site."""
    if not isinstance(context, ObservationContextV1):
        raise TypeError("context must be ObservationContextV1")
    return context.copy_explicit()
