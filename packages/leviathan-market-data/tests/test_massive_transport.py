from __future__ import annotations

import urllib.error
from collections.abc import Mapping

import pytest

from leviathan_market_data.providers.massive import MAX_RESPONSE_BYTES, MassiveAdapterError
from leviathan_market_data.providers.massive_transport import UrllibMassiveTransport

_URL = "https://api.massive.com/v3/trades/AAPL"
_SECRET = "synthetic-only-secret-value"


class _Response:
    status = 200
    headers: Mapping[str, str] = {"Content-Type": "application/json"}

    def __init__(self, body: bytes) -> None:
        self.body = body
        self.read_limit: int | None = None
        self.closed = False

    def read(self, limit: int) -> bytes:
        self.read_limit = limit
        return self.body[:limit]

    def close(self) -> None:
        self.closed = True


class _Opener:
    def __init__(self, response: object) -> None:
        self.response = response
        self.calls: list[tuple[object, float]] = []

    def open(self, request: object, *, timeout: float) -> object:
        self.calls.append((request, timeout))
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def _get(transport: UrllibMassiveTransport, url: str = _URL):
    return transport.get(
        url,
        headers={"Authorization": f"Bearer {_SECRET}"},
        params={"limit": "10"},
        connect_timeout_s=3.0,
        read_timeout_s=5.0,
        total_timeout_s=10.0,
        allow_redirects=False,
    )


@pytest.mark.parametrize(
    "url",
    [
        "http://api.massive.com/v3/trades/AAPL",
        "https://evil.test/v3/trades/AAPL",
        "https://user@api.massive.com/v3/trades/AAPL",
        "https://api.massive.com/v1/trades/AAPL",
        "https://api.massive.com/v3/trades/%2e%2e/quotes/AAPL",
    ],
)
def test_host_and_path_are_pinned_before_open(url: str, monkeypatch: pytest.MonkeyPatch) -> None:
    opener = _Opener(_Response(b"{}"))
    monkeypatch.setattr("urllib.request.build_opener", lambda *_args: opener)
    with pytest.raises(MassiveAdapterError) as error:
        _get(UrllibMassiveTransport(), url)
    assert error.value.code == "MALFORMED_RECORD"
    assert opener.calls == []


def test_transport_reads_at_cap_plus_one_and_closes_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = _Response(b"x" * (MAX_RESPONSE_BYTES + 1))
    opener = _Opener(response)
    monkeypatch.setattr("urllib.request.build_opener", lambda *_args: opener)
    with pytest.raises(MassiveAdapterError) as error:
        _get(UrllibMassiveTransport())
    assert error.value.code == "OVERSIZE"
    assert response.read_limit == MAX_RESPONSE_BYTES + 1
    assert response.closed


def test_transport_refuses_redirect_without_following_it(monkeypatch: pytest.MonkeyPatch) -> None:
    redirect = urllib.error.HTTPError(_URL, 302, "redirect", {}, None)
    opener = _Opener(redirect)
    monkeypatch.setattr("urllib.request.build_opener", lambda *_args: opener)
    response = _get(UrllibMassiveTransport())
    assert response.status_code == 302
    assert response.body == b""
    assert len(opener.calls) == 1


def test_transport_errors_never_retain_the_authorization_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opener = _Opener(OSError(f"failure containing {_SECRET}"))
    monkeypatch.setattr("urllib.request.build_opener", lambda *_args: opener)
    with pytest.raises(MassiveAdapterError) as error:
        _get(UrllibMassiveTransport())
    assert error.value.code == "HTTP_STATUS"
    assert _SECRET not in str(error.value)
    assert error.value.__cause__ is None
