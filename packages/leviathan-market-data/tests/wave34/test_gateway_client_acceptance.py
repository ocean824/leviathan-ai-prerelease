from __future__ import annotations

import base64
import re
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from leviathan_market_data.providers import databento
from leviathan_market_data.providers.gateway_client import (
    GatewayClientError,
    GatewayConfigV1,
    GatewayCredentialResolverV1,
    GatewayHttpRequestV1,
    GatewayHttpResponseV1,
    GatewayTransportV1,
)
from leviathan_market_data.providers.registry import (
    CredentialResolversV1,
    CredentialRouteV1,
    DataSourceRegistryV1,
)

DEVICE_BEARER = "synthetic-device-bearer-for-tests"
PROVIDER_KEY = "synthetic-provider-key-must-not-be-local"


class _FakeGatewayPort:
    def __init__(self) -> None:
        self.requests: list[GatewayHttpRequestV1] = []

    def request(self, request: GatewayHttpRequestV1) -> GatewayHttpResponseV1:
        self.requests.append(request)
        return GatewayHttpResponseV1(200, {"content-type": "application/json"}, b"{}")


def _config() -> GatewayConfigV1:
    return GatewayConfigV1("https://gateway.example", DEVICE_BEARER)


def _get(transport: GatewayTransportV1, url: str, *, params: dict[str, str] | None = None) -> Any:
    return transport.get(
        url,
        headers={
            "Authorization": f"Bearer {DEVICE_BEARER}",
            "X-API-Key": PROVIDER_KEY,
            "Cookie": "synthetic-cookie=must-not-forward",
        },
        params=params or {"series_id": "GDP", "api_key": PROVIDER_KEY},
        connect_timeout_s=3.0,
        read_timeout_s=5.0,
        total_timeout_s=10.0,
        allow_redirects=False,
    )


def test_gateway_resolver_and_registry_expose_device_bearer_only() -> None:
    config = _config()
    resolver = GatewayCredentialResolverV1(config)
    declarations = {
        "databento": "databento_api_key",
        "massive": "massive_api_key",
        "fred": "fred_api_key",
        "bea": "bea_api_key",
        "eia": "eia_api_key",
        "unusual_whales": "unusual_whales_api_key",
    }
    for provider_id, credential_name in declarations.items():
        assert resolver(provider_id, credential_name) == DEVICE_BEARER

    with pytest.raises(GatewayClientError) as denied:
        resolver("fred", "databento_api_key")
    assert denied.value.code == "INVALID_REQUEST"
    assert DEVICE_BEARER not in repr(config)
    assert PROVIDER_KEY not in repr(config)

    registry = DataSourceRegistryV1()
    module = SimpleNamespace(
        PROVIDER_ID="fred",
        CAPABILITIES=frozenset({"HISTORICAL"}),
        CREDENTIAL_NAMES=("fred_api_key",),
        build_adapter=lambda *, resolve_secret, transport: {
            "device_bearer": resolve_secret("fred_api_key"),
            "transport": transport,
        },
    )
    adapter = registry.register_module(
        module,
        credential_route=CredentialRouteV1.GATEWAY,
        credential_ref=None,
        resolvers=CredentialResolversV1(gateway=resolver),
        transport=object(),
    )
    assert adapter["device_bearer"] == DEVICE_BEARER
    source = registry.get("fred")
    assert source is not None
    assert DEVICE_BEARER not in repr(source.model_dump())
    assert PROVIDER_KEY not in repr(source.model_dump())


def test_deployment_comments_do_not_contain_secret_values() -> None:
    wrangler = (
        Path(__file__).resolve().parents[4] / "workers" / "data-gateway" / "wrangler.toml"
    ).read_text(encoding="utf-8")
    comments = "\n".join(line for line in wrangler.splitlines() if line.lstrip().startswith("#"))
    assert PROVIDER_KEY not in comments
    assert DEVICE_BEARER not in comments
    assert "-----BEGIN PRIVATE KEY-----" not in comments
    assert not re.search(
        r"(?:api[_-]?key|token|secret)\s*(?:=|:)\s*[\"']?[A-Za-z0-9+/_=-]{16,}",
        comments,
        flags=re.IGNORECASE,
    )
    assert not re.search(
        r"\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b",
        comments,
    )


def test_get_routes_registered_provider_origin_through_gateway_and_strips_credentials() -> None:
    port = _FakeGatewayPort()
    transport = GatewayTransportV1(_config(), port)
    response = _get(
        transport,
        "https://api.stlouisfed.org/fred/series/observations",
        params={
            "series_id": "GDP",
            "file_type": "json",
            "api_key": PROVIDER_KEY,
            "X-API-KEY": PROVIDER_KEY,
            "token": DEVICE_BEARER,
        },
    )
    assert response.status_code == 200
    assert len(port.requests) == 1
    request = port.requests[0]
    assert request.url.startswith("https://gateway.example/v1/fred/fred/series/observations?")
    assert "series_id=GDP" in request.url
    assert "file_type=json" in request.url
    for credential in (PROVIDER_KEY, DEVICE_BEARER, "api_key", "X-API-KEY", "token="):
        assert credential not in request.url
    assert request.headers == {
        "Authorization": f"Bearer {DEVICE_BEARER}",
        "Accept": "application/json",
    }
    assert request.allow_redirects is False
    assert PROVIDER_KEY not in repr(request)
    assert DEVICE_BEARER not in repr(request)


def test_databento_routes_through_gateway_and_strips_provider_credentials() -> None:
    port = _FakeGatewayPort()
    transport = GatewayTransportV1(_config(), port)
    device_basic = "Basic " + base64.b64encode(f"{DEVICE_BEARER}:".encode("ascii")).decode("ascii")
    request = databento.HttpRequest(
        method="POST",
        url="https://hist.databento.com/v0/timeseries.get_range",
        query_params={},
        headers={
            "Authorization": device_basic,
            "X-API-Key": PROVIDER_KEY,
            "Cookie": "synthetic-cookie=must-not-forward",
        },
        form_data={
            "dataset": "GLBX.MDP3",
            "symbols": "ESM6",
            "schema": "trades",
            "start": "2026-01-01",
            "end": "2026-01-02",
            "stype_in": "raw_symbol",
            "limit": "10",
            "api_key": PROVIDER_KEY,
            "token": DEVICE_BEARER,
            "x-api-key": PROVIDER_KEY,
        },
    )
    response = transport.request(request)
    assert type(response) is databento.HttpResponse
    assert response.status_code == 200
    assert len(port.requests) == 1
    forwarded = port.requests[0]
    assert forwarded.url == "https://gateway.example/v1/databento/v0/timeseries.get_range"
    assert forwarded.headers["Authorization"] == f"Bearer {DEVICE_BEARER}"
    assert "X-API-Key" not in forwarded.headers
    assert "Cookie" not in forwarded.headers
    assert forwarded.body is not None
    body = forwarded.body.decode("ascii")
    assert "dataset=GLBX.MDP3" in body
    assert PROVIDER_KEY not in body
    assert DEVICE_BEARER not in body
    assert "api_key" not in body.lower()
    assert "token=" not in body.lower()
    assert forwarded.allow_redirects is False


@pytest.mark.parametrize(
    "url",
    [
        "https://attacker.example/v1/fred/fred/series/observations",
        "https://api.stlouisfed.org@attacker.example/fred/series/observations",
        "https://attacker.example@api.stlouisfed.org/fred/series/observations",
        "https://api.stlouisfed.org/admin/keys",
        "https://api.stlouisfed.org/fred/series/observations/../../admin",
        "https://api.stlouisfed.org/fred/series/observations/%2e%2e/admin",
        "https://api.stlouisfed.org/fred/series/observations/%252e%252e/admin",
        "https://api.stlouisfed.org/fred/series/observations/%25252e%25252e/admin",
        "https://api.stlouisfed.org/fred/series/observations/%252fadmin",
        "https://api.stlouisfed.org/fred/series/observations/%255cadmin",
        "https://api.stlouisfed.org//attacker.example/fred/series/observations",
        "https://api.stlouisfed.org/@attacker.example/fred/series/observations",
        "http://api.stlouisfed.org/fred/series/observations",
        "https://api.stlouisfed.org/fred/series/observations?api_key=secret",
    ],
)
def test_absolute_host_override_and_path_tricks_never_reach_transport(url: str) -> None:
    port = _FakeGatewayPort()
    transport = GatewayTransportV1(_config(), port)
    with pytest.raises(GatewayClientError) as denied:
        _get(transport, url)
    assert denied.value.code == "INVALID_REQUEST"
    assert not port.requests
