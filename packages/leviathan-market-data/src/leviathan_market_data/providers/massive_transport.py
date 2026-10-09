"""Direct, bounded HTTP transport for the existing Massive history adapter."""

from __future__ import annotations

import re
import urllib.error
import urllib.request
from collections.abc import Mapping
from urllib.parse import urlsplit

from leviathan_market_data.providers.massive import (
    MAX_RESPONSE_BYTES,
    MassiveAdapterError,
    MassiveHTTPResponse,
)

_ALLOWED_PATH_PREFIXES = (
    "/v3/trades/",
    "/v3/quotes/",
    "/v2/aggs/ticker/",
    "/benzinga/v2/news",
)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: object,
        code: int,
        msg: str,
        headers: object,
        newurl: str,
    ) -> None:
        del req, fp, code, msg, headers, newurl
        return None


class UrllibMassiveTransport:
    """Implements the Massive adapter's existing transport port without redirects."""

    __slots__ = ()

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
    ) -> MassiveHTTPResponse:
        if (
            not self._allowed_url(url)
            or not isinstance(headers, Mapping)
            or not isinstance(params, Mapping)
            or any(type(key) is not str or type(value) is not str for key, value in headers.items())
            or any(type(key) is not str or type(value) is not str for key, value in params.items())
            or type(allow_redirects) is not bool
            or allow_redirects
            or not all(
                type(value) is float and 0.0 < value <= 30.0
                for value in (connect_timeout_s, read_timeout_s, total_timeout_s)
            )
        ):
            raise MassiveAdapterError("MALFORMED_RECORD") from None
        authorization = headers.get("Authorization")
        if type(authorization) is not str or not authorization.startswith("Bearer "):
            raise MassiveAdapterError("AUTH_DENIED") from None
        query_url = url
        if params:
            from urllib.parse import urlencode

            query_url = f"{url}?{urlencode(params)}"
        request = urllib.request.Request(
            query_url,
            headers=dict(headers),
            method="GET",
        )
        opener = urllib.request.build_opener(_NoRedirect())
        try:
            response = opener.open(
                request, timeout=min(connect_timeout_s, read_timeout_s, total_timeout_s)
            )
        except urllib.error.HTTPError as error:
            # Preserve only status and empty body for redirects and failures.
            status = int(error.code)
            error.close()
            return MassiveHTTPResponse(status, {}, b"")
        except TimeoutError:
            raise TimeoutError from None
        except Exception:
            raise MassiveAdapterError("HTTP_STATUS") from None
        try:
            status = int(response.status)
            response_headers = {key.lower(): value for key, value in response.headers.items()}
            body = response.read(MAX_RESPONSE_BYTES + 1)
            if len(body) > MAX_RESPONSE_BYTES:
                raise MassiveAdapterError("OVERSIZE") from None
            return MassiveHTTPResponse(status, response_headers, body)
        except MassiveAdapterError:
            raise
        except Exception:
            raise MassiveAdapterError("HTTP_STATUS") from None
        finally:
            response.close()

    @staticmethod
    def _allowed_url(url: object) -> bool:
        if type(url) is not str or len(url) > 4_096:
            return False
        try:
            parsed = urlsplit(url)
            return (
                parsed.scheme == "https"
                and parsed.hostname == "api.massive.com"
                and parsed.port in (None, 443)
                and parsed.username is None
                and parsed.password is None
                and not parsed.query
                and not parsed.fragment
                and "\\" not in parsed.path
                and not any(part in {".", ".."} for part in parsed.path.split("/"))
                and not re.search(r"%(?:25)*(?:2e|2f|5c)", parsed.path, re.IGNORECASE)
                and any(
                    parsed.path.startswith(prefix)
                    if prefix.endswith("/")
                    else parsed.path == prefix or parsed.path.startswith(f"{prefix}/")
                    for prefix in _ALLOWED_PATH_PREFIXES
                )
            )
        except ValueError:
            return False


__all__ = ["UrllibMassiveTransport"]
