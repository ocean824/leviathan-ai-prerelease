"""Read-only client for the remote data-key gateway.

The local adapter receives only a device bearer. Provider credentials remain in
the Worker environment and are never accepted by this client.
"""

from __future__ import annotations

import base64
import re
import urllib.error
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass, field
from time import time_ns
from typing import Protocol
from urllib.parse import urlencode, urlsplit

from leviathan_market_data.providers import databento

_PROVIDER_ORIGINS: Mapping[str, str] = {
    "databento": "https://hist.databento.com",
    "massive": "https://api.massive.com",
    "fred": "https://api.stlouisfed.org",
    "bea": "https://apps.bea.gov",
    "eia": "https://api.eia.gov",
    "unusual_whales": "https://api.unusualwhales.com",
}
_PROVIDER_PATH_PREFIXES: Mapping[str, tuple[str, ...]] = {
    "databento": ("/v0/metadata.get_cost", "/v0/timeseries.get_range"),
    "massive": ("/v3/trades/", "/v3/quotes/", "/v2/aggs/ticker/", "/benzinga/v2/news"),
    "fred": ("/fred/series/observations",),
    "bea": ("/api/data/",),
    "eia": ("/v2/",),
    "unusual_whales": ("/api/option-trades", "/api/stock/"),
}
_CREDENTIAL_NAMES: Mapping[str, str] = {
    "databento": "databento_api_key",
    "massive": "massive_api_key",
    "fred": "fred_api_key",
    "bea": "bea_api_key",
    "eia": "eia_api_key",
    "unusual_whales": "unusual_whales_api_key",
}
_CREDENTIAL_QUERY_KEYS = frozenset(
    {
        "api_key",
        "apikey",
        "api-key",
        "x-api-key",
        "key",
        "token",
        "access_token",
        "client_secret",
        "secret",
        "authorization",
        "userid",
    }
)
_MAX_RESPONSE_BYTES = 2_097_152
_MAX_URL_CHARS = 4_096
_MAX_DEVICE_TOKEN_CHARS = 4_096
_SAFE_PATH = re.compile(r"/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*\Z", re.ASCII)
_ENCODED_PATH_TRAVERSAL = re.compile(r"%(?:25)*(?:2e|2f|5c)", re.IGNORECASE | re.ASCII)


class GatewayClientError(ValueError):
    """A content-free, closed gateway-client error."""

    def __init__(self, code: str) -> None:
        self.code = (
            code
            if code in {"INVALID_CONFIG", "INVALID_REQUEST", "HTTP_STATUS", "OVERSIZE"}
            else "HTTP_STATUS"
        )
        super().__init__(self.code)


@dataclass(frozen=True, slots=True)
class GatewayConfigV1:
    base_url: str
    device_token: str = field(repr=False)

    def __post_init__(self) -> None:
        if type(self.base_url) is not str or len(self.base_url) > 2_048:
            raise GatewayClientError("INVALID_CONFIG")
        try:
            parsed = urlsplit(self.base_url)
        except ValueError:
            raise GatewayClientError("INVALID_CONFIG") from None
        if (
            parsed.scheme != "https"
            or not parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
            or type(self.device_token) is not str
            or not 8 <= len(self.device_token) <= _MAX_DEVICE_TOKEN_CHARS
            or any(ord(char) < 0x21 or ord(char) > 0x7E for char in self.device_token)
        ):
            raise GatewayClientError("INVALID_CONFIG")
        object.__setattr__(self, "base_url", f"{parsed.scheme}://{parsed.netloc}")


class GatewayCredentialResolverV1:
    """Registry resolver that returns the device bearer, never a provider key."""

    __slots__ = ("_config",)

    def __init__(self, config: GatewayConfigV1) -> None:
        if type(config) is not GatewayConfigV1:
            raise GatewayClientError("INVALID_CONFIG")
        self._config = config

    def __call__(self, provider_id: str, credential_name: str) -> str:
        if (
            type(provider_id) is not str
            or type(credential_name) is not str
            or _CREDENTIAL_NAMES.get(provider_id) != credential_name
        ):
            raise GatewayClientError("INVALID_REQUEST")
        return self._config.device_token


@dataclass(frozen=True, slots=True)
class GatewayHttpRequestV1:
    method: str
    url: str
    headers: Mapping[str, str] = field(repr=False)
    body: bytes | None
    timeout_s: float
    allow_redirects: bool = False


@dataclass(frozen=True, slots=True)
class GatewayHttpResponseV1:
    status_code: int
    headers: Mapping[str, str]
    body: bytes


class GatewayHttpPortV1(Protocol):
    def request(self, request: GatewayHttpRequestV1) -> GatewayHttpResponseV1: ...


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self, req: object, fp: object, code: int, msg: str, headers: object, newurl: str
    ) -> None:
        return None


class _UrllibGatewayHttpPort:
    """Small standard-library transport with redirects disabled and bounded reads."""

    __slots__ = ()

    def request(self, request: GatewayHttpRequestV1) -> GatewayHttpResponseV1:
        opener = urllib.request.build_opener(_NoRedirect())
        native = urllib.request.Request(
            request.url,
            data=request.body,
            headers=dict(request.headers),
            method=request.method,
        )
        try:
            response = opener.open(native, timeout=request.timeout_s)
        except urllib.error.HTTPError as exc:
            response = exc
        except Exception:
            raise GatewayClientError("HTTP_STATUS") from None
        try:
            try:
                body = response.read(_MAX_RESPONSE_BYTES + 1)
                if len(body) > _MAX_RESPONSE_BYTES:
                    raise GatewayClientError("OVERSIZE")
                headers = {key.lower(): value for key, value in response.headers.items()}
                return GatewayHttpResponseV1(int(response.status), headers, body)
            except GatewayClientError:
                raise
            except Exception:
                raise GatewayClientError("HTTP_STATUS") from None
        finally:
            response.close()


class GatewayTransportV1:
    """Implements the GET and Databento request shapes used by provider adapters."""

    __slots__ = ("_config", "_port")

    def __init__(self, config: GatewayConfigV1, transport: GatewayHttpPortV1 | None = None) -> None:
        if type(config) is not GatewayConfigV1:
            raise GatewayClientError("INVALID_CONFIG")
        if transport is not None and not callable(getattr(transport, "request", None)):
            raise GatewayClientError("INVALID_CONFIG")
        self._config = config
        self._port = transport or _UrllibGatewayHttpPort()

    def clock_ns(self) -> int:
        """Supply the clock seam required by the Unusual Whales adapter."""
        return time_ns()

    def get(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        params: Mapping[str, str],
        connect_timeout_s: float,
        read_timeout_s: float,
        total_timeout_s: float,
        allow_redirects: bool,
    ) -> GatewayHttpResponseV1:
        if (
            not isinstance(headers, Mapping)
            or not isinstance(params, Mapping)
            or type(allow_redirects) is not bool
            or allow_redirects
            or any(type(k) is not str or type(v) is not str for k, v in headers.items())
            or any(type(k) is not str or type(v) is not str for k, v in params.items())
            or any(
                type(value) is not float or not 0.0 < value <= 60.0
                for value in (connect_timeout_s, read_timeout_s, total_timeout_s)
            )
        ):
            raise GatewayClientError("INVALID_REQUEST")
        request_url, provider_id = self._map_upstream_url(url)
        outgoing_params = {
            key: value for key, value in params.items() if key.lower() not in _CREDENTIAL_QUERY_KEYS
        }
        return self._send(
            "GET", request_url, provider_id, outgoing_params, None, min(total_timeout_s, 15.0)
        )

    def request(self, request: databento.HttpRequest) -> databento.HttpResponse:
        if type(request) is not databento.HttpRequest or request.allow_redirects:
            raise GatewayClientError("INVALID_REQUEST")
        request_url, provider_id = self._map_upstream_url(request.url)
        expected_method = "GET" if request.url.endswith("metadata.get_cost") else "POST"
        if request.method != expected_method:
            raise GatewayClientError("INVALID_REQUEST")
        authorization = request.headers.get("Authorization")
        expected = "Basic " + base64.b64encode(
            f"{self._config.device_token}:".encode("ascii")
        ).decode("ascii")
        if authorization != expected:
            raise GatewayClientError("INVALID_REQUEST")
        query = request.query_params if request.method == "GET" else {}
        form = (
            {
                key: value
                for key, value in request.form_data.items()
                if key.lower() not in _CREDENTIAL_QUERY_KEYS
            }
            if request.method == "POST"
            else {}
        )
        response = self._send(
            request.method,
            request_url,
            provider_id,
            {
                key: value
                for key, value in query.items()
                if key.lower() not in _CREDENTIAL_QUERY_KEYS
            },
            form,
            min(request.total_timeout_s, 15.0),
        )
        return databento.HttpResponse(response.status_code, response.headers, response.body)

    def _map_upstream_url(self, value: str) -> tuple[str, str]:
        if type(value) is not str or len(value) > _MAX_URL_CHARS:
            raise GatewayClientError("INVALID_REQUEST")
        try:
            parsed = urlsplit(value)
        except ValueError:
            raise GatewayClientError("INVALID_REQUEST") from None
        provider_id = next(
            (
                key
                for key, origin in _PROVIDER_ORIGINS.items()
                if f"{parsed.scheme}://{parsed.netloc}" == origin
            ),
            None,
        )
        if (
            provider_id is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or _SAFE_PATH.fullmatch(parsed.path) is None
            or "\\" in parsed.path
            or _ENCODED_PATH_TRAVERSAL.search(parsed.path) is not None
            or any(segment in {".", ".."} for segment in parsed.path.split("/"))
            or not any(
                _path_is_allowed(parsed.path, prefix)
                for prefix in _PROVIDER_PATH_PREFIXES[provider_id]
            )
        ):
            raise GatewayClientError("INVALID_REQUEST")
        return f"{self._config.base_url}/v1/{provider_id}{parsed.path}", provider_id

    def _send(
        self,
        method: str,
        url: str,
        provider_id: str,
        params: Mapping[str, str],
        form: Mapping[str, str] | None,
        timeout_s: float,
    ) -> GatewayHttpResponseV1:
        if method not in {"GET", "POST"} or not 0.1 <= timeout_s <= 60.0:
            raise GatewayClientError("INVALID_REQUEST")
        query = urlencode(params, doseq=False)
        target = f"{url}?{query}" if query else url
        body = urlencode(form, doseq=False).encode("ascii") if form else None
        headers = {
            "Authorization": f"Bearer {self._config.device_token}",
            "Accept": "application/json",
        }
        if body is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        result = self._port.request(GatewayHttpRequestV1(method, target, headers, body, timeout_s))
        if (
            type(result) is not GatewayHttpResponseV1
            or type(result.status_code) is not int
            or type(result.body) is not bytes
        ):
            raise GatewayClientError("HTTP_STATUS")
        if len(result.body) > _MAX_RESPONSE_BYTES:
            raise GatewayClientError("OVERSIZE")
        return result


def _path_is_allowed(path: str, prefix: str) -> bool:
    return (
        path.startswith(prefix)
        if prefix.endswith("/")
        else path == prefix or path.startswith(f"{prefix}/")
    )
