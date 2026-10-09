from __future__ import annotations

import base64

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


class _FakeGatewayHttpPort:
    def __init__(self, response: GatewayHttpResponseV1 | None = None) -> None:
        self.requests: list[GatewayHttpRequestV1] = []
        self.response = response or GatewayHttpResponseV1(
            200, {"content-type": "application/json"}, b"{}"
        )

    def request(self, request: GatewayHttpRequestV1) -> GatewayHttpResponseV1:
        self.requests.append(request)
        return self.response


def test_registry_credential_resolver_returns_device_token_only() -> None:
    config = GatewayConfigV1("https://gateway.example", "synthetic-device-bearer")
    resolver = GatewayCredentialResolverV1(config)

    assert resolver("databento", "databento_api_key") == "synthetic-device-bearer"
    assert resolver("fred", "fred_api_key") == "synthetic-device-bearer"
    with pytest.raises(GatewayClientError) as caught:
        resolver("databento", "fred_api_key")
    assert caught.value.code == "INVALID_REQUEST"
    assert "synthetic-device-bearer" not in str(caught.value)
    assert "synthetic-device-bearer" not in repr(config)


def test_client_requires_tls_and_hides_invalid_configuration() -> None:
    with pytest.raises(GatewayClientError) as caught:
        GatewayConfigV1("http://gateway.example", "synthetic-device-bearer")
    assert caught.value.code == "INVALID_CONFIG"
    assert "gateway.example" not in str(caught.value)
    assert "synthetic-device-bearer" not in str(caught.value)


def test_gateway_get_maps_origin_strips_provider_auth_and_disables_redirects() -> None:
    config = GatewayConfigV1("https://gateway.example/", "synthetic-device-bearer")
    fake = _FakeGatewayHttpPort()
    transport = GatewayTransportV1(config, fake)

    response = transport.get(
        "https://api.stlouisfed.org/fred/series/observations",
        headers={
            "Authorization": "Bearer synthetic-device-bearer",
            "X-Provider-Key": "should-not-forward",
        },
        params={
            "series_id": "GDP",
            "api_key": "synthetic-device-bearer",
            "file_type": "json",
        },
        connect_timeout_s=3.0,
        read_timeout_s=5.0,
        total_timeout_s=10.0,
        allow_redirects=False,
    )

    assert response.status_code == 200
    assert len(fake.requests) == 1
    request = fake.requests[0]
    assert request.method == "GET"
    assert request.url == (
        "https://gateway.example/v1/fred/fred/series/observations?series_id=GDP&file_type=json"
    )
    assert request.headers == {
        "Authorization": "Bearer synthetic-device-bearer",
        "Accept": "application/json",
    }
    assert request.allow_redirects is False
    assert "should-not-forward" not in repr(request)
    assert "synthetic-device-bearer" not in repr(request)


def test_databento_request_translates_device_auth_and_form_body() -> None:
    config = GatewayConfigV1("https://gateway.example", "synthetic-device-bearer")
    fake = _FakeGatewayHttpPort(
        GatewayHttpResponseV1(
            200,
            {"content-type": "application/json"},
            b'{"ok":true}',
        )
    )
    transport = GatewayTransportV1(config, fake)
    provider_auth = "Basic " + base64.b64encode(b"synthetic-device-bearer:").decode("ascii")
    request = databento.HttpRequest(
        method="POST",
        url="https://hist.databento.com/v0/timeseries.get_range",
        query_params={},
        headers={"Authorization": provider_auth},
        form_data={
            "dataset": "GLBX.MDP3",
            "symbols": "ESM6",
            "schema": "trades",
            "start": "2026-01-01",
            "end": "2026-01-02",
            "stype_in": "raw_symbol",
            "limit": "10",
            "token": "client-supplied-token",
            "api_key": "client-supplied-key",
            "Authorization": "client-supplied-auth",
        },
    )

    response = transport.request(request)

    assert type(response) is databento.HttpResponse
    assert response.status_code == 200
    assert fake.requests[0].url == "https://gateway.example/v1/databento/v0/timeseries.get_range"
    assert fake.requests[0].headers["Authorization"] == "Bearer synthetic-device-bearer"
    assert fake.requests[0].body is not None
    assert fake.requests[0].body == (
        b"dataset=GLBX.MDP3&symbols=ESM6&schema=trades&start=2026-01-01"
        b"&end=2026-01-02&stype_in=raw_symbol&limit=10"
    )
    assert b"client-supplied" not in fake.requests[0].body


@pytest.mark.parametrize(
    "url",
    [
        "https://attacker.example/v1/evil",
        "https://api.stlouisfed.org/admin/keys",
        "https://api.stlouisfed.org/fred/series/observations/../../admin",
        "https://api.stlouisfed.org/fred/series/observations/%2e%2e/admin",
        "https://api.stlouisfed.org/fred/series/observations/%252e%252e/admin",
        "https://api.stlouisfed.org/fred/series/observations/%25252e%25252e/admin",
        "https://api.stlouisfed.org/fred/series/observations/%252fadmin",
        "http://api.stlouisfed.org/fred/series/observations",
    ],
)
def test_unregistered_origin_and_path_are_rejected_before_io(url: str) -> None:
    fake = _FakeGatewayHttpPort()
    transport = GatewayTransportV1(
        GatewayConfigV1("https://gateway.example", "synthetic-device-bearer"), fake
    )

    with pytest.raises(GatewayClientError) as caught:
        transport.get(
            url,
            headers={},
            params={},
            connect_timeout_s=3.0,
            read_timeout_s=5.0,
            total_timeout_s=10.0,
            allow_redirects=False,
        )

    assert caught.value.code == "INVALID_REQUEST"
    assert not fake.requests


def test_gateway_url_does_not_embed_device_bearer() -> None:
    fake = _FakeGatewayHttpPort()
    transport = GatewayTransportV1(
        GatewayConfigV1("https://gateway.example", "synthetic-device-bearer"), fake
    )
    transport.get(
        "https://api.massive.com/v3/trades/AAPL",
        headers={"Authorization": "Bearer synthetic-device-bearer"},
        params={"limit": "5"},
        connect_timeout_s=3.0,
        read_timeout_s=5.0,
        total_timeout_s=10.0,
        allow_redirects=False,
    )
    request = fake.requests[0]
    assert "synthetic-device-bearer" not in request.url
