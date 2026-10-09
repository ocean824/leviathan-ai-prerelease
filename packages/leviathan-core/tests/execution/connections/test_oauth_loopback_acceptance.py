from __future__ import annotations

import base64
import hashlib
import socket
from datetime import UTC, datetime
from urllib.parse import parse_qs, urlsplit

import pytest
from pydantic import SecretStr

from leviathan_core.execution.connections.oauth_loopback import (
    OAuthFlowError,
    OAuthLoopbackV1,
    OAuthTokenResponseV1,
    authorization_host,
)
from leviathan_vault.app_credentials import InMemoryCredentialStore

REDIRECT = "http://127.0.0.1:49152/oauth/callback"


class Clock:
    def __init__(self) -> None:
        self.now = 10_000

    def __call__(self) -> int:
        return self.now


def _flow(clock: Clock, store: InMemoryCredentialStore | None = None) -> OAuthLoopbackV1:
    return OAuthLoopbackV1(
        allowed_redirect_uris={
            "ALPACA": frozenset({REDIRECT}),
            "TASTYTRADE": frozenset({REDIRECT}),
            "CTRADER": frozenset({REDIRECT}),
            "COINBASE": frozenset({REDIRECT}),
            "SNAPTRADE": frozenset({REDIRECT}),
        },
        credential_store=InMemoryCredentialStore() if store is None else store,
        clock_ns=clock,
        max_ttl_ns=300_000_000_000,
    )


def _begin(flow: OAuthLoopbackV1):
    return flow.begin(
        provider="TASTYTRADE",
        environment="DEMO",
        profile_id="default",
        client_id="synthetic-client-id",
        redirect_uri=REDIRECT,
        scopes=("read", "trade"),
        profile_fields={"oauth_client_secret": SecretStr("synthetic-client-secret")},
    )


def _callback(start, **query_updates: str) -> tuple[str, str]:
    parts = urlsplit(start.authorization_url)
    query = parse_qs(parts.query)
    params = {key: values[0] for key, values in query.items()}
    params.update({"code": "synthetic-auth-code", **query_updates})
    return f"{REDIRECT}?" + "&".join(f"{key}={value}" for key, value in params.items()), params[
        "state"
    ]


def test_pkce_is_s256_and_token_exchange_persists_only_to_injected_store() -> None:
    clock, store = Clock(), InMemoryCredentialStore()
    flow = _flow(clock, store)
    start = _begin(flow)
    query = parse_qs(urlsplit(start.authorization_url).query)
    assert query["code_challenge_method"] == ["S256"]
    assert query["state"] and query["nonce"]
    assert "synthetic-client-secret" not in start.authorization_url
    assert "synthetic-auth-code" not in start.authorization_url

    callback, _state = _callback(start)
    requests = []

    def exchange(request):
        requests.append(request)
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(request.code_verifier.encode("ascii")).digest()
        )
        assert challenge.rstrip(b"=").decode("ascii") == query["code_challenge"][0]
        assert request.provider == "TASTYTRADE"
        assert request.redirect_uri == REDIRECT
        assert request.code == "synthetic-auth-code"
        return OAuthTokenResponseV1(
            "synthetic-access-token",
            "synthetic-refresh-token",
            datetime(2030, 1, 1, tzinfo=UTC),
            request.nonce,
        )

    result = flow.complete(callback_url=callback, exchange=exchange)
    assert (result.provider, result.environment, result.profile_id) == (
        "TASTYTRADE",
        "DEMO",
        "default",
    )
    assert len(requests) == 1
    assert "synthetic-auth-code" not in repr(requests[0])
    assert "synthetic-access-token" not in repr(
        OAuthTokenResponseV1(
            "synthetic-access-token", None, datetime(2030, 1, 1, tzinfo=UTC), requests[0].nonce
        )
    )
    resolved = store.resolve("TASTYTRADE", "DEMO", "default")
    assert resolved.secret("access_token").get_secret_value() == "synthetic-access-token"
    assert resolved.secret("refresh_token").get_secret_value() == "synthetic-refresh-token"
    assert resolved.secret("oauth_client_secret").get_secret_value() == "synthetic-client-secret"

    with pytest.raises(OAuthFlowError) as caught:
        flow.complete(callback_url=callback, exchange=exchange)
    assert caught.value.code == "STATE_REPLAY"


@pytest.mark.parametrize(
    "bad_redirect",
    (
        "https://127.0.0.1:49152/oauth/callback",
        "http://localhost:49152/oauth/callback",
        "http://0.0.0.0:49152/oauth/callback",
        "http://192.0.2.1:49152/oauth/callback",
        "http://127.0.0.1/oauth/callback",
        "http://user@127.0.0.1:49152/oauth/callback",
    ),
)
def test_only_exact_loopback_redirects_are_accepted(bad_redirect) -> None:
    with pytest.raises(OAuthFlowError) as caught:
        OAuthLoopbackV1(
            allowed_redirect_uris={"TASTYTRADE": frozenset({bad_redirect})},
            credential_store=InMemoryCredentialStore(),
            clock_ns=Clock(),
        )
    assert caught.value.code == "INVALID_REDIRECT_URI"


@pytest.mark.parametrize(
    "mutation",
    (
        lambda url: url.replace("127.0.0.1", "localhost"),
        lambda url: url.replace(":49152/", ":49153/"),
        lambda url: url.replace("/oauth/callback", "/oauth/other"),
        lambda url: url.replace("http://", "https://"),
    ),
)
def test_callback_authority_or_path_mismatch_consumes_state_without_exchange(mutation) -> None:
    flow = _flow(Clock())
    start = _begin(flow)
    callback, _state = _callback(start)
    callback = mutation(callback)
    calls = 0

    def exchange(_request):
        nonlocal calls
        calls += 1
        return OAuthTokenResponseV1("token", None, datetime(2030, 1, 1, tzinfo=UTC), "nonce")

    with pytest.raises(OAuthFlowError) as caught:
        flow.complete(callback_url=callback, exchange=exchange)
    assert caught.value.code == "CALLBACK_INVALID"
    assert calls == 0
    with pytest.raises(OAuthFlowError) as replay:
        flow.complete(callback_url=callback, exchange=exchange)
    assert replay.value.code == "STATE_REPLAY"


def test_missing_duplicate_wrong_and_cancelled_state_are_rejected() -> None:
    flow = _flow(Clock())
    start = _begin(flow)
    _callback_url, state = _callback(start)
    with pytest.raises(OAuthFlowError) as missing:
        flow.complete(
            callback_url=f"{REDIRECT}?code=synthetic-auth-code", exchange=lambda _req: None
        )
    assert missing.value.code == "INVALID_STATE"
    with pytest.raises(OAuthFlowError) as duplicate:
        flow.complete(
            callback_url=f"{REDIRECT}?code=synthetic-auth-code&state={state}&state={state}",
            exchange=lambda _req: None,
        )
    assert duplicate.value.code == "INVALID_STATE"
    with pytest.raises(OAuthFlowError) as wrong:
        flow.complete(
            callback_url=f"{REDIRECT}?code=synthetic-auth-code&state=wrong-state",
            exchange=lambda _req: None,
        )
    assert wrong.value.code == "STATE_REPLAY"

    start = _begin(flow)
    state = parse_qs(urlsplit(start.authorization_url).query)["state"][0]
    flow.cancel(state)
    with pytest.raises(OAuthFlowError) as cancelled:
        flow.complete(
            callback_url=f"{REDIRECT}?code=synthetic-auth-code&state={state}",
            exchange=lambda _req: None,
        )
    assert cancelled.value.code == "STATE_REPLAY"


def test_expiry_is_inclusive_and_does_not_exchange_or_persist() -> None:
    clock, store = Clock(), InMemoryCredentialStore()
    flow = _flow(clock, store)
    start = flow.begin(
        provider="ALPACA",
        environment="PAPER",
        profile_id="default",
        client_id="synthetic-client-id",
        redirect_uri=REDIRECT,
        ttl_ns=100,
    )
    callback, _state = _callback(start)
    clock.now = start.expires_at_ns
    calls = 0

    def exchange(_request):
        nonlocal calls
        calls += 1
        return OAuthTokenResponseV1("token", None, datetime(2030, 1, 1, tzinfo=UTC), "nonce")

    with pytest.raises(OAuthFlowError) as caught:
        flow.complete(callback_url=callback, exchange=exchange)
    assert caught.value.code == "EXPIRED"
    assert calls == 0
    assert store.status_all() == ()


def test_nonce_mismatch_and_failed_exchange_are_content_free(caplog) -> None:
    flow = _flow(Clock())
    start = _begin(flow)
    callback, _state = _callback(start)
    canary = "synthetic-secret-canary-901"
    with pytest.raises(OAuthFlowError) as caught:
        flow.complete(
            callback_url=callback,
            exchange=lambda request: OAuthTokenResponseV1(
                "synthetic-access-token", None, datetime(2030, 1, 1, tzinfo=UTC), "wrong-nonce"
            ),
        )
    assert caught.value.code == "NONCE_MISMATCH"
    assert canary not in str(caught.value)
    assert canary not in repr(caught.value)

    start = _begin(flow)
    callback, _state = _callback(start)

    def fail(_request):
        raise RuntimeError(canary)

    with pytest.raises(OAuthFlowError) as failed:
        flow.complete(callback_url=callback, exchange=fail)
    assert failed.value.code == "TOKEN_EXCHANGE_FAILED"
    assert canary not in str(failed.value)
    assert canary not in repr(failed.value)
    chained = failed.value.__context__
    while chained is not None:
        assert canary not in str(chained)
        assert canary not in repr(chained)
        chained = chained.__context__
    assert canary not in caplog.text


def test_no_socket_is_opened_and_provider_hosts_are_pinned(monkeypatch) -> None:
    calls = 0

    def forbidden_socket(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        raise AssertionError("offline authorization engine must not open a socket")

    monkeypatch.setattr(socket, "socket", forbidden_socket)
    assert authorization_host["ALPACA"] == ("app.alpaca.markets",)
    assert authorization_host["TASTYTRADE"] == (
        "my.tastytrade.com",
        "cert-my.staging-tasty.works",
    )
    assert authorization_host["CTRADER"] == ("id.ctrader.com",)
    assert authorization_host["COINBASE"] == ("login.coinbase.com",)
    assert authorization_host["SNAPTRADE"] == ("app.snaptrade.com",)
    assert authorization_host["OPENAI_COMPATIBLE"] == ()
    with pytest.raises(TypeError):
        authorization_host["OPENAI"] = ("attacker.example",)  # type: ignore[index]
    start = _begin(_flow(Clock()))
    assert urlsplit(start.authorization_url).hostname == "cert-my.staging-tasty.works"
    assert calls == 0


def test_snaptrade_short_lived_portal_url_is_the_only_token_echo_and_is_not_persisted(
    caplog,
) -> None:
    store = InMemoryCredentialStore()
    flow = _flow(Clock(), store)
    portal_canary = "synthetic-portal-bearer-canary"
    start = flow.begin_snaptrade_portal(
        portal_url=f"https://app.snaptrade.com/snapTrade/redeemToken?token={portal_canary}",
        redirect_uri=REDIRECT,
        profile_id="default",
        environment="PAPER",
        ttl_ns=600_000_000_000,
    )
    assert start.expires_at_ns == 600_000_000_000 + 10_000
    assert portal_canary in start.authorization_url
    assert portal_canary not in repr(start)
    assert portal_canary not in caplog.text
    query = parse_qs(urlsplit(start.authorization_url).query)
    callback = f"{REDIRECT}?status=SUCCESS&connection_id=synthetic-id&state={query['state'][0]}"
    result = flow.complete_snaptrade_callback(callback_url=callback)
    assert result == ("SUCCESS", "synthetic-id")
    assert portal_canary not in repr(result)
    assert portal_canary not in caplog.text
    assert store.status_all() == ()

    cancel_start = flow.begin_snaptrade_portal(
        portal_url=f"https://app.snaptrade.com/redeem?token={portal_canary}",
        redirect_uri=REDIRECT,
        profile_id="default",
        environment="PAPER",
    )
    state = parse_qs(urlsplit(cancel_start.authorization_url).query)["state"][0]
    flow.cancel(state)
    with pytest.raises(OAuthFlowError) as cancelled:
        flow.complete_snaptrade_callback(
            callback_url=f"{REDIRECT}?status=SUCCESS&connection_id=x&state={state}"
        )
    assert cancelled.value.code == "STATE_REPLAY"
    assert portal_canary not in str(cancelled.value)
    assert portal_canary not in repr(cancelled.value)
    assert portal_canary not in caplog.text

    with pytest.raises(OAuthFlowError) as over_ttl:
        flow.begin_snaptrade_portal(
            portal_url=f"https://app.snaptrade.com/redeem?token={portal_canary}",
            redirect_uri=REDIRECT,
            profile_id="default",
            environment="PAPER",
            ttl_ns=600_000_000_001,
        )
    assert over_ttl.value.code == "CALLBACK_INVALID"
    assert portal_canary not in str(over_ttl.value)
    assert portal_canary not in repr(over_ttl.value)

    flow = _flow(Clock())
    for host in ("attacker.example", "app.snaptrade.com.evil"):
        with pytest.raises(OAuthFlowError) as caught:
            flow.begin_snaptrade_portal(
                portal_url=f"https://{host}/redeem?token=synthetic-token",
                redirect_uri=REDIRECT,
                profile_id="default",
                environment="PAPER",
            )
        assert caught.value.code == "UNSUPPORTED_PROVIDER"
