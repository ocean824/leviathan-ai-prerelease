from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from leviathan_market_data.providers.alternative_schema import AlternativeObservationV1
from leviathan_market_data.providers.registry import (
    CredentialResolversV1,
    CredentialRouteV1,
    DataSourceRegistryV1,
    DataSourceStatusV1,
    HealthErrorCodeV1,
    ProviderHealthV1,
)
from leviathan_market_data.schema import MarketDataValueError


class _Adapter:
    def __init__(self, resolve_secret: Any, transport: object) -> None:
        self._resolve_secret = resolve_secret
        self.transport = transport

    def credential(self) -> str:
        return self._resolve_secret("api_key")


def _module(provider_id: str = "fixture.provider") -> SimpleNamespace:
    return SimpleNamespace(
        PROVIDER_ID=provider_id,
        CAPABILITIES=frozenset({"HISTORICAL", "ALTERNATIVE_DATA"}),
        CREDENTIAL_NAMES=("api_key",),
        build_adapter=lambda *, resolve_secret, transport: _Adapter(
            resolve_secret, transport
        ),
    )


def test_module_registration_builds_adapter_and_keeps_vault_material_out_of_snapshot() -> None:
    registry = DataSourceRegistryV1()
    expected_secret = "fixture-provider-secret-do-not-expose"
    transport = object()
    calls: list[tuple[str, str]] = []

    def resolve(reference: str, name: str) -> str:
        calls.append((reference, name))
        return expected_secret

    adapter = registry.register_module(
        _module(),
        credential_route=CredentialRouteV1.VAULT_REF,
        credential_ref="vault://leviathan-ai/development/FIXTURE/API_KEY",
        resolvers=CredentialResolversV1(vault_ref=resolve),
        transport=transport,
    )

    assert registry.adapter("fixture.provider") is adapter
    assert adapter.transport is transport
    assert adapter.credential() == expected_secret
    assert calls == [
        ("vault://leviathan-ai/development/FIXTURE/API_KEY", "api_key")
    ]

    snapshot = registry.get("fixture.provider")
    assert snapshot is not None
    assert snapshot.status is DataSourceStatusV1.NOT_CONFIGURED
    assert snapshot.credential_route is CredentialRouteV1.VAULT_REF
    assert snapshot.requires_credentials is True
    serialized = repr(snapshot.model_dump())
    assert "credential_ref" not in serialized
    assert expected_secret not in serialized


def test_gateway_route_uses_injected_gateway_and_snapshot_contains_no_secret_or_ref() -> None:
    registry = DataSourceRegistryV1()
    proxy_authorization = "fixture-gateway-proxy-material-do-not-expose"
    calls: list[tuple[str, str]] = []

    def gateway(provider_id: str, name: str) -> str:
        calls.append((provider_id, name))
        return proxy_authorization

    adapter = registry.register_module(
        _module("remote.fixture"),
        credential_route=CredentialRouteV1.GATEWAY,
        credential_ref=None,
        resolvers=CredentialResolversV1(gateway=gateway),
        transport=object(),
    )

    assert adapter.credential() == proxy_authorization
    assert calls == [("remote.fixture", "api_key")]
    snapshot = registry.get("remote.fixture")
    assert snapshot is not None
    assert snapshot.credential_route is CredentialRouteV1.GATEWAY
    assert "credential_ref" not in snapshot.model_dump()
    assert proxy_authorization not in repr(snapshot.model_dump())


def test_credential_resolver_failure_is_sanitized_and_undeclared_names_are_rejected() -> None:
    registry = DataSourceRegistryV1()
    internal_detail = "fixture-secret=never-echo-this"

    def failing_resolver(reference: str, name: str) -> str:
        raise RuntimeError(internal_detail)

    adapter = registry.register_module(
        _module(),
        credential_route=CredentialRouteV1.VAULT_REF,
        credential_ref="vault://leviathan-ai/development/FIXTURE/API_KEY",
        resolvers=CredentialResolversV1(vault_ref=failing_resolver),
        transport=object(),
    )

    with pytest.raises(MarketDataValueError) as failure:
        adapter.credential()
    assert "CREDENTIAL_UNAVAILABLE" in str(failure.value)
    assert internal_detail not in str(failure.value)


@pytest.mark.parametrize(
    "status",
    [
        DataSourceStatusV1.READY,
        DataSourceStatusV1.DEGRADED,
        DataSourceStatusV1.EXTERNAL_GATE,
        DataSourceStatusV1.DISABLED,
    ],
)
def test_health_states_keep_source_and_receipt_times_distinct_and_errors_closed(
    status: DataSourceStatusV1,
) -> None:
    registry = DataSourceRegistryV1()
    registry.register_module(
        _module(),
        credential_route=CredentialRouteV1.VAULT_REF,
        credential_ref="vault://leviathan-ai/development/FIXTURE/API_KEY",
        resolvers=CredentialResolversV1(),
        transport=object(),
    )

    source_time_ns = 1_800_000_000_000_000_111
    received_time_ns = 1_800_000_000_000_000_222
    registry.update_health(
        ProviderHealthV1(
            provider_id="fixture.provider",
            status=status,
            source_time_ns=source_time_ns,
            received_time_ns=received_time_ns,
            error_code=(
                HealthErrorCodeV1.NETWORK_UNAVAILABLE
                if status is DataSourceStatusV1.DEGRADED
                else None
            ),
        )
    )

    snapshot = registry.get("fixture.provider")
    assert snapshot is not None
    assert snapshot.status is status
    assert snapshot.source_time_ns == source_time_ns
    assert snapshot.received_time_ns == received_time_ns
    assert snapshot.source_time_ns != snapshot.received_time_ns
    assert snapshot.error_code == (
        HealthErrorCodeV1.NETWORK_UNAVAILABLE
        if status is DataSourceStatusV1.DEGRADED
        else None
    )


def test_unregistered_and_registered_without_health_are_not_configured() -> None:
    registry = DataSourceRegistryV1()
    assert registry.get("missing.provider") is None
    assert registry.list_sources() == ()

    registry.register_module(
        _module(),
        credential_route=None,
        credential_ref=None,
        resolvers=CredentialResolversV1(),
        transport=object(),
    )
    snapshot = registry.list_sources()[0]
    assert snapshot.status is DataSourceStatusV1.NOT_CONFIGURED
    assert snapshot.source_time_ns is None
    assert snapshot.received_time_ns is None
    assert snapshot.error_code is None


def test_public_registry_rejects_uppercase_provider_ids() -> None:
    registry = DataSourceRegistryV1()
    with pytest.raises(MarketDataValueError, match="INVALID_PROVIDER_ID"):
        registry.register_module(
            _module("Uppercase.provider"),
            credential_route=None,
            credential_ref=None,
            resolvers=CredentialResolversV1(),
            transport=object(),
        )

    assert registry.list_sources() == ()


def test_alternative_observation_preserves_event_and_ingest_times_and_provenance() -> None:
    observation = AlternativeObservationV1(
        source_id="fixture-source",
        dataset_id="fixture.dataset",
        observation_id="row-17",
        event_time_ns=1_800_000_000_000_000_111,
        ingest_time_ns=1_800_000_000_000_000_222,
        value="42.75",
        unit="USD",
        mapping_version="mapping-v1",
        provenance_digest="a" * 64,
        source_revision="revision-3",
    )

    assert observation.schema_version == "leviathan.alternative-observation/1"
    assert observation.event_time_ns != observation.ingest_time_ns
    assert observation.value == "42.75"
    assert observation.unit == "USD"
    assert observation.provenance_digest == "a" * 64
