from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import cast

import pytest

from leviathan_market_data.providers.alternative_schema import AlternativeObservationV1
from leviathan_market_data.providers.registry import (
    CredentialResolversV1,
    CredentialRouteV1,
    DataSourceRegistryV1,
    DataSourceStatusV1,
    HealthErrorCodeV1,
    ProviderAdapterModuleV1,
    ProviderHealthV1,
)
from leviathan_market_data.schema import MarketDataValueError


@dataclass
class FakeAdapter:
    resolve_secret: Callable[[str], str]
    transport: object


@dataclass
class FakeModule:
    PROVIDER_ID: str = "sample_feed"
    CAPABILITIES: frozenset[str] = frozenset({"TRADES", "QUOTES"})
    CREDENTIAL_NAMES: tuple[str, ...] = ("api_key",)

    def build_adapter(
        self,
        *,
        resolve_secret: Callable[[str], str],
        transport: object,
    ) -> FakeAdapter:
        return FakeAdapter(resolve_secret=resolve_secret, transport=transport)


def _module(*, credential_names: tuple[str, ...] = ("api_key",)) -> ProviderAdapterModuleV1:
    return FakeModule(CREDENTIAL_NAMES=credential_names)


def test_module_surface_registers_adapter_and_routes_vault_reference_without_exposure() -> None:
    calls: list[tuple[str, str]] = []
    registry = DataSourceRegistryV1()

    def resolve_vault(reference: str, name: str) -> str:
        calls.append((reference, name))
        return "test-secret"

    adapter = cast(
        FakeAdapter,
        registry.register_module(
            _module(),
            credential_route=CredentialRouteV1.VAULT_REF,
            credential_ref="vault://leviathan-ai/development/SAMPLE_FEED/DEFAULT",
            resolvers=CredentialResolversV1(vault_ref=resolve_vault),
            transport=object(),
        ),
    )

    assert registry.adapter("sample_feed") is adapter
    assert adapter.transport is not None
    assert adapter.resolve_secret("api_key") == "test-secret"
    assert calls == [("vault://leviathan-ai/development/SAMPLE_FEED/DEFAULT", "api_key")]
    snapshot = registry.get("sample_feed")
    assert snapshot is not None
    assert snapshot.status is DataSourceStatusV1.NOT_CONFIGURED
    assert snapshot.credential_route is CredentialRouteV1.VAULT_REF
    assert "vault://" not in repr(snapshot)


def test_module_surface_routes_gateway_credentials_without_local_provider_reference() -> None:
    calls: list[tuple[str, str]] = []
    registry = DataSourceRegistryV1()

    def resolve_gateway(provider: str, name: str) -> str:
        calls.append((provider, name))
        return "gateway-proxy-token"

    adapter = cast(
        FakeAdapter,
        registry.register_module(
            _module(),
            credential_route=CredentialRouteV1.GATEWAY,
            credential_ref=None,
            resolvers=CredentialResolversV1(gateway=resolve_gateway),
            transport=object(),
        ),
    )

    assert adapter.resolve_secret("api_key") == "gateway-proxy-token"
    assert calls == [("sample_feed", "api_key")]
    snapshot = registry.get("sample_feed")
    assert snapshot is not None
    assert snapshot.credential_route is CredentialRouteV1.GATEWAY
    assert "gateway-proxy-token" not in repr(snapshot)


def test_missing_route_is_not_configured_and_never_calls_a_resolver() -> None:
    calls: list[str] = []
    registry = DataSourceRegistryV1()

    def resolve_vault(_reference: str, _name: str) -> str:
        calls.append("vault")
        return "unused"

    def resolve_gateway(_provider: str, _name: str) -> str:
        calls.append("gateway")
        return "unused"

    adapter = cast(
        FakeAdapter,
        registry.register_module(
            _module(),
            credential_route=None,
            credential_ref=None,
            resolvers=CredentialResolversV1(vault_ref=resolve_vault, gateway=resolve_gateway),
            transport=object(),
        ),
    )

    with pytest.raises(MarketDataValueError, match="CREDENTIAL_ROUTE_NOT_CONFIGURED"):
        adapter.resolve_secret("api_key")
    assert calls == []
    snapshot = registry.get("sample_feed")
    assert snapshot is not None
    assert snapshot.status is DataSourceStatusV1.NOT_CONFIGURED


def test_registry_rejects_undeclared_credentials_duplicate_and_unregistered_health() -> None:
    registry = DataSourceRegistryV1()
    adapter = cast(
        FakeAdapter,
        registry.register_module(
            _module(),
            credential_route=CredentialRouteV1.GATEWAY,
            credential_ref=None,
            resolvers=CredentialResolversV1(gateway=lambda _provider, _name: "proxy"),
            transport=object(),
        ),
    )
    with pytest.raises(MarketDataValueError, match="CREDENTIAL_NAME_NOT_DECLARED"):
        adapter.resolve_secret("private_key")
    with pytest.raises(MarketDataValueError, match="DUPLICATE_PROVIDER"):
        registry.register_module(
            _module(),
            credential_route=CredentialRouteV1.GATEWAY,
            credential_ref=None,
            resolvers=CredentialResolversV1(gateway=lambda _provider, _name: "proxy"),
            transport=object(),
        )
    with pytest.raises(MarketDataValueError, match="PROVIDER_NOT_REGISTERED"):
        registry.update_health(
            ProviderHealthV1(provider_id="other", status=DataSourceStatusV1.READY)
        )


def test_health_preserves_source_and_receipt_times_and_only_closed_error_codes() -> None:
    registry = DataSourceRegistryV1()
    registry.register_module(
        _module(credential_names=()),
        credential_route=None,
        credential_ref=None,
        resolvers=CredentialResolversV1(),
        transport=object(),
    )
    registry.update_health(
        ProviderHealthV1(
            provider_id="sample_feed",
            status=DataSourceStatusV1.DEGRADED,
            source_time_ns=100,
            received_time_ns=125,
            error_code=HealthErrorCodeV1.SOURCE_STALE,
        )
    )
    snapshot = registry.get("sample_feed")
    assert snapshot is not None
    assert snapshot.model_dump(mode="json") == {
        "provider_id": "sample_feed",
        "display_name": "Sample Feed",
        "capabilities": ["QUOTES", "TRADES"],
        "requires_credentials": False,
        "credential_route": None,
        "status": "DEGRADED",
        "source_time_ns": 100,
        "received_time_ns": 125,
        "error_code": "SOURCE_STALE",
    }
    with pytest.raises(MarketDataValueError, match="INCOMPLETE_HEALTH_TIMES"):
        ProviderHealthV1(
            provider_id="sample_feed",
            status=DataSourceStatusV1.READY,
            source_time_ns=100,
        )
    with pytest.raises(MarketDataValueError, match="INCOMPLETE_HEALTH_TIMES"):
        ProviderHealthV1.model_validate(
            {
                "provider_id": "sample_feed",
                "status": DataSourceStatusV1.READY,
                "source_time_ns": 100,
            }
        )


def test_alternative_observation_keeps_typed_time_units_mapping_and_provenance() -> None:
    observation = AlternativeObservationV1(
        source_id="weather-feed",
        dataset_id="daily-rainfall",
        observation_id="site-17:2026-10-06",
        event_time_ns=1_797_264_000_000_000_000,
        ingest_time_ns=1_797_264_000_100_000_000,
        value="4.2",
        unit="mm",
        mapping_version="noaa-v1",
        provenance_digest="a" * 64,
        source_revision="2026-10-06-r2",
    )
    assert observation.schema_version == "leviathan.alternative-observation/1"
    assert observation.event_time_ns < observation.ingest_time_ns
    assert observation.unit == "mm"
    assert observation.mapping_version == "noaa-v1"
    assert observation.provenance_digest == "a" * 64


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("event_time_ns", 0, "INVALID_TIME"),
        ("ingest_time_ns", True, "INVALID_TIME"),
        ("unit", "", "INVALID_UNIT"),
        ("provenance_digest", "secret-bearing-invalid-input", "INVALID_PROVENANCE_DIGEST"),
    ],
)
def test_alternative_observation_rejects_invalid_metadata_without_echo(
    field: str, value: object, code: str
) -> None:
    data: dict[str, object] = {
        "source_id": "sample",
        "dataset_id": "sample-dataset",
        "observation_id": "sample-1",
        "event_time_ns": 10,
        "ingest_time_ns": 11,
        "value": "5",
        "unit": "count",
        "mapping_version": "mapping-v1",
        "provenance_digest": "b" * 64,
    }
    data[field] = value
    with pytest.raises(MarketDataValueError) as caught:
        AlternativeObservationV1(**data)
    assert caught.value.code == code
    assert "secret-bearing-invalid-input" not in str(caught.value)
