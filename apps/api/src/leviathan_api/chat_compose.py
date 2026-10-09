"""Production composition for the provider-neutral CHAT-001 service."""

from __future__ import annotations

import ipaddress
import json
import socket
import ssl
import threading
import time
from collections.abc import AsyncIterator, Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from urllib.parse import urlsplit

import httpcore
import httpx
from leviathan_store.preferences import PreferencesError

from leviathan_api.chat.models import ChatApiShapeV1, ChatRequestV1
from leviathan_api.chat.port import (
    ChatDisclosurePort,
    ChatModelBindingV1,
    ChatPolicyDecisionV1,
    ChatPriceScheduleV1,
    ChatPriceV1,
    ChatTransportPort,
    ProviderCallV1,
    ProviderHttpResponseV1,
    ProviderTransportError,
    TrustedCompatibleEndpointV1,
)
from leviathan_api.chat.service import ChatServiceV1
from leviathan_api.routers.preferences import PreferencesHttpPort
from leviathan_core.agent_council.model_registry import ModelRegistryEntryV1, ModelRegistryV1
from leviathan_core.security.authz_models import TrustedPrincipalV1
from leviathan_vault.app_credentials import CredentialStore

_MAX_CATALOG_BYTES = 1_048_576
_MAX_RESPONSE_BYTES = 2_000_000
_MAX_OUTPUT_TOKENS = 4_096
_DEFAULT_DAILY_CAP = Decimal("5.00")
_MAX_DAILY_CAP = Decimal("100.00")
_MAX_NS = 2**63 - 1
_PREFERENCE_POLICY = "chat.policy"
_PREFERENCE_DISCLOSURE = "chat.disclosure"
_SocketOption = (
    tuple[int, int, int] | tuple[int, int, bytes | bytearray] | tuple[int, int, None, int]
)
_SocketOptions = Iterable[_SocketOption] | None
_SHAPE_CREDENTIALS = {
    "ANTHROPIC_API_KEY": ("ANTHROPIC", "api_key"),
    "OPENAI_API_KEY": ("OPENAI", "api_key"),
    "OPENAI_COMPATIBLE_API_KEY": ("OPENAI_COMPATIBLE", "api_key"),
    "anthropic_api_key": ("ANTHROPIC", "api_key"),
    "openai_api_key": ("OPENAI", "api_key"),
    "openai_compatible_api_key": ("OPENAI_COMPATIBLE", "api_key"),
}


class ChatCompositionError(ValueError):
    """Content-free model-catalog or composition failure."""

    def __init__(self, code: str = "CHAT_CONFIGURATION_INVALID") -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class ChatCompositionV1:
    service: ChatServiceV1
    registry: ModelRegistryV1
    bound_models: tuple[str, ...]


def _read_catalog(path: Path) -> tuple[str, tuple[ModelRegistryEntryV1, ...]]:
    try:
        raw = path.read_bytes()
        if len(raw) > _MAX_CATALOG_BYTES:
            raise ChatCompositionError("MODEL_CATALOG_INVALID")
        document = json.loads(raw.decode("utf-8", errors="strict"))
        if type(document) is not dict or set(document) - {
            "version",
            "entries",
            "compatible_template",
            "schema_version",
            "sources",
        }:
            raise ChatCompositionError("MODEL_CATALOG_INVALID")
        sources = document.get("sources", [])
        if type(sources) is not list or any(type(item) is not str for item in sources):
            raise ChatCompositionError("MODEL_CATALOG_INVALID")
        entries = document.get("entries")
        if type(entries) is not list:
            raise ChatCompositionError("MODEL_CATALOG_INVALID")
        clean_entries = []
        for entry in entries:
            if type(entry) is not dict:
                raise ChatCompositionError("MODEL_CATALOG_INVALID")
            credential_name = entry.get("credential_name")
            if credential_name is not None and type(credential_name) is not str:
                raise ChatCompositionError("MODEL_CATALOG_INVALID")
            expected_credential = (
                {
                    "ANTHROPIC_API_KEY": "ANTHROPIC",
                    "OPENAI_API_KEY": "OPENAI",
                    "OPENAI_COMPATIBLE_API_KEY": "OPENAI_COMPATIBLE",
                }.get(credential_name)
                if isinstance(credential_name, str)
                else None
            )
            if (
                "enabled_when_credential" in entry
                and entry.get("enabled_when_credential") != expected_credential
            ):
                raise ChatCompositionError("MODEL_CATALOG_INVALID")
            clean_entry = {
                key: value for key, value in entry.items() if key != "enabled_when_credential"
            }
            capability = clean_entry.get("capability")
            if type(capability) is not dict:
                raise ChatCompositionError("MODEL_CATALOG_INVALID")
            clean_entry["capability"] = {
                key: tuple(value) if key in {"modalities", "tools", "output_schemas"} else value
                for key, value in capability.items()
            }
            for key in ("supported_regions",):
                if type(clean_entry.get(key)) is list:
                    clean_entry[key] = tuple(clean_entry[key])
            clean_entries.append(clean_entry)
        version = document.get("version")
        if type(version) is not str:
            raise ChatCompositionError("MODEL_CATALOG_INVALID")
        entries = tuple(ModelRegistryEntryV1(**item) for item in clean_entries)
        registry = ModelRegistryV1(version=version, entries=entries)
        return registry.version, registry.entries
    except ChatCompositionError:
        raise
    except Exception:
        raise ChatCompositionError("MODEL_CATALOG_INVALID") from None


def load_model_catalog(default_path: Path, user_path: Path | None) -> ModelRegistryV1:
    """Load shipped models and merge user entries by stable alias/entry identity.

    User entries replace shipped entries that share either their entry id or
    public alias. Other user entries are appended. A user registry version is
    authoritative for the merged snapshot, and the shipped metadata is rebased
    to that version.
    """
    default_version, default_entries = _read_catalog(Path(default_path))
    if user_path is None or not Path(user_path).exists():
        return ModelRegistryV1(version=default_version, entries=default_entries)
    user_version, user_entries = _read_catalog(Path(user_path))
    merged: list[ModelRegistryEntryV1] = []
    for entry in default_entries:
        if any(
            candidate.entry_id == entry.entry_id or candidate.alias == entry.alias
            for candidate in user_entries
        ):
            continue
        merged.append(entry.model_copy(update={"registry_version": user_version}))
    merged.extend(user_entries)
    try:
        return ModelRegistryV1(version=user_version, entries=tuple(merged))
    except Exception:
        raise ChatCompositionError("MODEL_CATALOG_INVALID") from None


class _PinnedNetworkBackend(httpcore.AsyncNetworkBackend):
    """Connect to configuration-time addresses while TLS keeps the URL host."""

    def __init__(
        self,
        hostname: str,
        addresses: tuple[str, ...],
        delegate: httpcore.AsyncNetworkBackend | None = None,
    ) -> None:
        if not addresses:
            raise ChatCompositionError("ENDPOINT_UNSAFE")
        self._hostname = hostname.casefold()
        try:
            self._addresses = tuple(ipaddress.ip_address(item).compressed for item in addresses)
        except ValueError:
            raise ChatCompositionError("ENDPOINT_UNSAFE") from None
        self._delegate = delegate or httpcore.AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: _SocketOptions = None,
    ) -> httpcore.AsyncNetworkStream:
        if host.casefold() != self._hostname:
            raise httpcore.ConnectError("HOST_NOT_PINNED")
        return await self._delegate.connect_tcp(
            self._addresses[0],
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: _SocketOptions = None,
    ) -> httpcore.AsyncNetworkStream:
        raise httpcore.ConnectError("UNIX_SOCKET_NOT_ALLOWED")

    async def sleep(self, seconds: float) -> None:
        await self._delegate.sleep(seconds)


class _PinnedHTTPXTransport(httpx.AsyncHTTPTransport):
    """HTTPX transport with a fixed dial address and URL-host TLS identity."""

    def __init__(self, hostname: str, addresses: tuple[str, ...]) -> None:
        super().__init__(trust_env=False)
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=ssl.create_default_context(),
            network_backend=_PinnedNetworkBackend(hostname, addresses),
        )


class HttpxChatTransportV1:
    """Bounded HTTPX transport for CHAT-001 complete and server-sent events.

    Tests may provide ``httpx.MockTransport`` as ``http_transport``; when
    supplied, HTTPX never opens a socket. No request or response bodies are
    logged or included in transport errors.
    """

    def __init__(
        self,
        *,
        http_transport: httpx.AsyncBaseTransport | None = None,
        connect_timeout_s: float = 5.0,
        read_timeout_s: float = 30.0,
    ) -> None:
        if (
            type(connect_timeout_s) not in (int, float)
            or type(read_timeout_s) not in (int, float)
            or not 0 < connect_timeout_s <= 30
            or not 0 < read_timeout_s <= 120
        ):
            raise ChatCompositionError()
        self._transport = http_transport
        self._connect_timeout_s = float(connect_timeout_s)
        self._read_timeout_s = float(read_timeout_s)

    def _client(self, call: ProviderCallV1) -> httpx.AsyncClient:
        timeout = httpx.Timeout(
            connect=self._connect_timeout_s,
            read=min(self._read_timeout_s, max(call.timeout_ms / 1000, 0.001)),
            write=min(self._read_timeout_s, max(call.timeout_ms / 1000, 0.001)),
            pool=self._connect_timeout_s,
        )
        transport = self._transport
        if transport is None and call.pinned_addresses:
            hostname = urlsplit(call.endpoint).hostname
            if not hostname:
                raise ProviderTransportError("PROVIDER_UNAVAILABLE")
            transport = _PinnedHTTPXTransport(hostname, call.pinned_addresses)
        return httpx.AsyncClient(
            transport=transport,
            timeout=timeout,
            follow_redirects=False,
            trust_env=False,
        )

    @staticmethod
    def _headers(call: ProviderCallV1) -> dict[str, str]:
        secret = call.credential.get_secret_value()
        if call.api_shape is ChatApiShapeV1.ANTHROPIC_MESSAGES:
            return {
                "content-type": "application/json",
                "anthropic-version": "2023-06-01",
                "x-api-key": secret,
            }
        return {"content-type": "application/json", "authorization": f"Bearer {secret}"}

    @staticmethod
    def _raise_status(status_code: int) -> None:
        if status_code == 429:
            raise ProviderTransportError("PROVIDER_RATE_LIMITED")
        if not 200 <= status_code < 300:
            raise ProviderTransportError("PROVIDER_UNAVAILABLE")

    async def complete(self, call: ProviderCallV1) -> ProviderHttpResponseV1:
        for attempt in range(2):
            try:
                async with (
                    self._client(call) as client,
                    client.stream(
                        "POST",
                        call.endpoint,
                        content=call.body_json.encode("utf-8"),
                        headers=self._headers(call),
                    ) as response,
                ):
                    self._raise_status(response.status_code)
                    chunks: list[bytes] = []
                    size = 0
                    async for chunk in response.aiter_bytes():
                        size += len(chunk)
                        if size > _MAX_RESPONSE_BYTES:
                            raise ProviderTransportError("PROVIDER_INVALID_RESPONSE")
                        chunks.append(chunk)
                    return ProviderHttpResponseV1(
                        status_code=response.status_code, body=b"".join(chunks)
                    )
            except httpx.ConnectError:
                if attempt == 0:
                    continue
                raise ProviderTransportError("PROVIDER_UNAVAILABLE") from None
            except httpx.TimeoutException:
                raise ProviderTransportError("PROVIDER_TIMEOUT") from None
            except ProviderTransportError:
                raise
            except Exception:
                raise ProviderTransportError("PROVIDER_UNAVAILABLE") from None
        raise ProviderTransportError("PROVIDER_UNAVAILABLE")

    def stream(self, call: ProviderCallV1) -> AsyncIterator[bytes]:
        async def chunks() -> AsyncIterator[bytes]:
            for attempt in range(2):
                emitted = False
                try:
                    async with (
                        self._client(call) as client,
                        client.stream(
                            "POST",
                            call.endpoint,
                            content=call.body_json.encode("utf-8"),
                            headers=self._headers(call),
                        ) as response,
                    ):
                        self._raise_status(response.status_code)
                        size = 0
                        async for chunk in response.aiter_bytes():
                            size += len(chunk)
                            if size > _MAX_RESPONSE_BYTES:
                                raise ProviderTransportError("PROVIDER_INVALID_RESPONSE")
                            emitted = True
                            yield chunk
                    return
                except httpx.ConnectError:
                    if attempt == 0 and not emitted:
                        continue
                    raise ProviderTransportError("PROVIDER_UNAVAILABLE") from None
                except httpx.TimeoutException:
                    raise ProviderTransportError("PROVIDER_TIMEOUT") from None
                except ProviderTransportError:
                    raise
                except Exception:
                    raise ProviderTransportError("PROVIDER_UNAVAILABLE") from None

        return chunks()


class _PreferencesPolicy:
    def __init__(
        self,
        store: PreferencesHttpPort | None,
        clock_ns: Callable[[], int],
    ) -> None:
        self._store = store
        self._clock_ns = clock_ns
        self._local_lock = threading.RLock()
        self._local_spend: dict[tuple[str, str], Decimal] = {}

    def authorize(
        self,
        principal: TrustedPrincipalV1,
        request: ChatRequestV1,
        model: ModelRegistryEntryV1,
    ) -> ChatPolicyDecisionV1:
        scope = principal.principal_id
        try:
            now_ns = self._clock_ns()
            if type(now_ns) is not int or now_ns < 0:
                raise ValueError
            utc_day = datetime.fromtimestamp(now_ns / 1_000_000_000, UTC).date().isoformat()
            cap = self._daily_cap(scope)
            input_tokens = sum(len(item.content.encode("utf-8")) for item in request.messages)
            estimate = (
                Decimal(input_tokens) * model.input_cost_per_million_tokens_usd
                + Decimal(request.max_output_tokens) * model.output_cost_per_million_tokens_usd
            ) / Decimal(1_000_000)
            if request.max_output_tokens > _MAX_OUTPUT_TOKENS:
                return self._decision(False, "BUDGET_EXCEEDED", cap, 0)
            if request.request_id == "model-list":
                return self._decision(True, "ALLOWED", cap, _MAX_OUTPUT_TOKENS)
            if self._store is None:
                with self._local_lock:
                    key = (scope, utc_day)
                    spent = self._local_spend.get(key, Decimal("0"))
                    allowed = spent + estimate <= cap
                    if allowed:
                        self._local_spend[key] = spent + estimate
                return self._decision(
                    allowed,
                    "ALLOWED" if allowed else "BUDGET_EXCEEDED",
                    cap - spent,
                    _MAX_OUTPUT_TOKENS,
                )
            return self._reserve(scope, utc_day, estimate, cap)
        except Exception:
            return self._decision(False, "POLICY_DENIED", Decimal(0), 0)

    def _daily_cap(self, scope: str) -> Decimal:
        if self._store is None:
            return _DEFAULT_DAILY_CAP
        record = self._store.get(scope, _PREFERENCE_POLICY)
        if record is None:
            return _DEFAULT_DAILY_CAP
        document = record.document
        raw_cap = document.get("daily_cost_cap_usd", "5.00")
        if type(raw_cap) is not str:
            raise ValueError
        cap = Decimal(raw_cap)
        if not cap.is_finite() or cap < 0 or cap > _MAX_DAILY_CAP:
            raise ValueError
        return cap

    def _reserve(
        self, scope: str, utc_day: str, estimate: Decimal, cap: Decimal
    ) -> ChatPolicyDecisionV1:
        assert self._store is not None
        for _ in range(4):
            record = self._store.get(scope, _PREFERENCE_POLICY)
            document = {} if record is None else dict(record.document)
            raw_cap = document.get("daily_cost_cap_usd", "5.00")
            raw_day = document.get("utc_day")
            raw_reserved = document.get("daily_reserved_cost_usd", "0")
            if type(raw_cap) is not str or type(raw_reserved) is not str:
                raise ValueError
            current_cap = Decimal(raw_cap)
            reserved = Decimal(raw_reserved) if raw_day == utc_day else Decimal(0)
            if (
                not current_cap.is_finite()
                or current_cap < 0
                or current_cap > _MAX_DAILY_CAP
                or not reserved.is_finite()
                or reserved < 0
            ):
                raise ValueError
            allowed = reserved + estimate <= current_cap
            if not allowed:
                return self._decision(
                    False, "BUDGET_EXCEEDED", current_cap - reserved, _MAX_OUTPUT_TOKENS
                )
            document["daily_cost_cap_usd"] = format(current_cap, "f")
            document["utc_day"] = utc_day
            document["daily_reserved_cost_usd"] = format(reserved + estimate, "f")
            try:
                self._store.put(
                    scope,
                    _PREFERENCE_POLICY,
                    document,
                    if_match="*" if record is None else str(record.revision),
                )
                return self._decision(True, "ALLOWED", current_cap - reserved, _MAX_OUTPUT_TOKENS)
            except PreferencesError as exc:
                if exc.code != "REVISION_CONFLICT":
                    raise
        raise PreferencesError("REVISION_CONFLICT")

    @staticmethod
    def _decision(
        allowed: bool, code: str, remaining_cost: Decimal, remaining_tokens: int
    ) -> ChatPolicyDecisionV1:
        return ChatPolicyDecisionV1(
            allowed=allowed,
            code=code,
            policy_version="chat-policy-v1",
            remaining_cost_usd=max(Decimal(0), remaining_cost),
            max_output_tokens=_MAX_OUTPUT_TOKENS,
            remaining_tokens=max(0, remaining_tokens),
        )


class _PreferencesDisclosure(ChatDisclosurePort):
    def __init__(self, store: PreferencesHttpPort | None) -> None:
        self._store = store

    def acknowledged(self, principal: TrustedPrincipalV1, provider: str) -> bool:
        if self._store is None:
            return False
        try:
            record = self._store.get(principal.principal_id, _PREFERENCE_DISCLOSURE)
            if record is None:
                return False
            providers = record.document.get("providers")
            return type(providers) is dict and providers.get(provider) is True
        except Exception:
            return False


def _system_address_resolver(host: str, port: int) -> tuple[str, ...]:
    try:
        results = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        return tuple(sorted({str(item[4][0]) for item in results}))
    except Exception:
        raise ChatCompositionError("ENDPOINT_UNSAFE") from None


def _endpoint_addresses(
    base_url: str,
    address_resolver: Callable[[str, int], tuple[str, ...]] | None = None,
) -> tuple[tuple[str, ...], bool, bool]:
    parsed = urlsplit(base_url)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise ChatCompositionError("ENDPOINT_UNSAFE")
    addresses: tuple[str, ...]
    try:
        ip = ipaddress.ip_address(parsed.hostname)
        addresses = (ip.compressed,)
    except ValueError:
        if parsed.hostname.casefold() == "localhost":
            addresses = ("127.0.0.1",)
        else:
            try:
                resolved = (address_resolver or _system_address_resolver)(
                    parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)
                )
                if (
                    type(resolved) is not tuple
                    or not resolved
                    or len(resolved) > 16
                    or any(type(value) is not str for value in resolved)
                ):
                    raise ValueError
                addresses = tuple(
                    sorted({ipaddress.ip_address(value).compressed for value in resolved})
                )
                if not addresses:
                    raise ValueError
            except Exception:
                raise ChatCompositionError("ENDPOINT_UNSAFE") from None
    local = parsed.scheme == "http" and all(
        ipaddress.ip_address(value).is_loopback for value in addresses
    )
    if local:
        if (
            parsed.hostname.casefold() != "localhost"
            and not ipaddress.ip_address(parsed.hostname).is_loopback
        ):
            raise ChatCompositionError("ENDPOINT_UNSAFE")
        return addresses, True, True
    if parsed.scheme != "https" or any(
        not ipaddress.ip_address(value).is_global for value in addresses
    ):
        raise ChatCompositionError("ENDPOINT_UNSAFE")
    return addresses, False, False


def _eligible_profiles(
    store: CredentialStore, environment: str, profile_id: str
) -> dict[str, object]:
    try:
        return {
            profile.provider: profile
            for profile in store.status_all()
            if profile.environment == environment
            and profile.profile_id == profile_id
            and profile.provider in {"ANTHROPIC", "OPENAI", "OPENAI_COMPATIBLE"}
            and profile.configured.get("api_key") is True
        }
    except Exception:
        return {}


def compose_chat_service(
    *,
    app_data_dir: Path,
    credential_store: CredentialStore,
    profile_id: str,
    environment: str,
    preferences_store: PreferencesHttpPort | None,
    transport: ChatTransportPort | None = None,
    clock_ns: Callable[[], int] = time.time_ns,
    catalog_path: Path | None = None,
    address_resolver: Callable[[str, int], tuple[str, ...]] | None = None,
) -> ChatCompositionV1:
    """Compose the merged catalog, provider bindings, policy, and transport."""
    try:
        if environment not in {"PAPER", "DEMO", "LIVE"}:
            raise ChatCompositionError("CREDENTIAL_ENVIRONMENT_INVALID")
        if type(profile_id) is not str or not profile_id or len(profile_id) > 64:
            raise ChatCompositionError("CREDENTIAL_PROFILE_INVALID")
        app_root = Path(app_data_dir)
        user_path = app_root / "chat" / "model-registry-v1.json"
        user_path.parent.mkdir(parents=True, exist_ok=True)
        default_path = (
            catalog_path
            or Path(__file__).resolve().parents[4] / "infra" / "chat" / "model-catalog-v1.json"
        )
        registry = load_model_catalog(default_path, user_path)
        profiles = _eligible_profiles(credential_store, environment, profile_id)
        bindings: list[ChatModelBindingV1] = []
        endpoints: dict[str, TrustedCompatibleEndpointV1] = {}
        secret_name_by_entry: dict[str, str] = {}
        for entry in registry.entries:
            if not entry.approved or not entry.available:
                continue
            credential = entry.credential_name
            requirement = _SHAPE_CREDENTIALS.get(credential)
            if requirement is None:
                continue
            provider_kind, _field = requirement
            profile = profiles.get(provider_kind)
            if profile is None:
                continue
            if provider_kind == "ANTHROPIC" and entry.provider != "claude":
                continue
            if provider_kind in {"OPENAI", "OPENAI_COMPATIBLE"} and entry.provider != "gpt":
                continue
            if provider_kind == "OPENAI_COMPATIBLE":
                base_url = getattr(profile, "base_url", None)
                if type(base_url) is not str:
                    continue
                try:
                    pinned, allow_private, local = _endpoint_addresses(base_url, address_resolver)
                    endpoint_id = "compatible." + profile_id
                    endpoint = TrustedCompatibleEndpointV1(
                        endpoint_id=endpoint_id,
                        base_url=base_url,
                        pinned_addresses=pinned,
                        allow_private_network=allow_private,
                        local_endpoint=local,
                    )
                except Exception:
                    continue
                endpoints[endpoint_id] = endpoint
                binding = ChatModelBindingV1(
                    entry_id=entry.entry_id,
                    api_shape=ChatApiShapeV1.OPENAI_COMPATIBLE,
                    endpoint_id=endpoint_id,
                    timeout_ms=30_000,
                    max_retries=0,
                )
            else:
                shape = (
                    ChatApiShapeV1.ANTHROPIC_MESSAGES
                    if provider_kind == "ANTHROPIC"
                    else ChatApiShapeV1.OPENAI_RESPONSES
                )
                binding = ChatModelBindingV1(
                    entry_id=entry.entry_id,
                    api_shape=shape,
                    timeout_ms=30_000,
                    max_retries=0,
                )
            bindings.append(binding)
            secret_name_by_entry[entry.entry_id] = credential

        def resolve_secret(name: str) -> str | None:
            provider = _SHAPE_CREDENTIALS.get(name)
            if provider is None:
                return None
            provider_kind, secret_field = provider
            if provider_kind not in profiles:
                return None
            try:
                resolved = credential_store.resolve(provider_kind, environment, profile_id)
                return resolved.secret(secret_field).get_secret_value()
            except Exception:
                return None

        selected_transport = transport or HttpxChatTransportV1()
        service = ChatServiceV1(
            registry=registry,
            bindings=tuple(bindings),
            endpoints=tuple(endpoints.values()),
            policy=_PreferencesPolicy(preferences_store, clock_ns),
            resolve_secret=resolve_secret,
            transport=selected_transport,
            disclosure=_PreferencesDisclosure(preferences_store),
            price_schedule=ChatPriceScheduleV1(
                version=registry.version,
                prices=tuple(
                    ChatPriceV1(
                        model_alias=entry.alias,
                        input_usd_per_million_tokens=entry.input_cost_per_million_tokens_usd,
                        output_usd_per_million_tokens=entry.output_cost_per_million_tokens_usd,
                    )
                    for entry in registry.entries
                ),
            ),
            clock_ns=clock_ns,
        )
        return ChatCompositionV1(
            service=service,
            registry=registry,
            bound_models=tuple(
                sorted(
                    entry.alias
                    for entry in registry.entries
                    if entry.entry_id in secret_name_by_entry
                )
            ),
        )
    except ChatCompositionError:
        raise
    except Exception:
        raise ChatCompositionError() from None


__all__ = [
    "ChatCompositionError",
    "ChatCompositionV1",
    "HttpxChatTransportV1",
    "compose_chat_service",
    "load_model_catalog",
]
