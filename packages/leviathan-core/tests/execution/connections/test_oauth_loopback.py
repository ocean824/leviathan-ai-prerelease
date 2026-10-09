from __future__ import annotations

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

REDIRECT = "http://127.0.0.1:49152/oauth/callback"


class Clock:
    def __init__(self) -> None:
        self.now = 1_000_000_000

    def __call__(self) -> int:
        return self.now


class FakeCredentialStore:
    def __init__(self) -> None:
        self.profiles: dict[tuple[str, str, str], dict[str, object]] = {}

    def put_profile(
        self, provider: str, environment: str, profile_id: str, fields: dict[str, object]
    ) -> None:
        self.profiles[(provider, environment, profile_id)] = dict(fields)


def _flow(clock: Clock, store: FakeCredentialStore) -> OAuthLoopbackV1:
    return OAuthLoopbackV1(
        allowed_redirect_uris={
            "TASTYTRADE": frozenset({REDIRECT}),
            "SNAPTRADE": frozenset({REDIRECT}),
        },
        credential_store=store,
        clock_ns=clock,
        max_ttl_ns=300_000_000_000,
    )


def _start(flow: OAuthLoopbackV1):
    return flow.begin(
        provider="TASTYTRADE",
        environment="DEMO",
        profile_id="default",
        client_id="synthetic-client-id",
        redirect_uri=REDIRECT,
        profile_fields={"oauth_client_secret": SecretStr("synthetic-client-secret")},
    )


def test_pkce_state_nonce_and_persisted_tokens() -> None:
    clock, store = Clock(), FakeCredentialStore()
    flow = _flow(clock, store)
    start = _start(flow)
    parts = urlsplit(start.authorization_url)
    query = parse_qs(parts.query)
    assert parts.hostname == "cert-my.staging-tasty.works"
    assert query["code_challenge_method"] == ["S256"]
    assert len(query["code_challenge"][0]) == 43
    assert query["state"] and query["nonce"]
    callback = f"{REDIRECT}?code=synthetic-code&state={query['state'][0]}"

    def exchange(request):
        assert request.provider == "TASTYTRADE"
        assert request.code == "synthetic-code"
        assert request.redirect_uri == REDIRECT
        assert len(request.code_verifier) >= 43
        assert "synthetic-code" not in repr(request)
        return OAuthTokenResponseV1(
            "synthetic-access-token",
            "synthetic-refresh-token",
            datetime(2030, 1, 1, tzinfo=UTC),
            request.nonce,
        )

    done = flow.complete(callback_url=callback, exchange=exchange)
    assert (done.provider, done.environment, done.profile_id) == ("TASTYTRADE", "DEMO", "default")
    fields = store.profiles[("TASTYTRADE", "DEMO", "default")]
    assert fields["access_token"].get_secret_value() == "synthetic-access-token"  # type: ignore[union-attr]
    assert fields["refresh_token"].get_secret_value() == "synthetic-refresh-token"  # type: ignore[union-attr]
    assert fields["oauth_client_secret"].get_secret_value() == "synthetic-client-secret"  # type: ignore[union-attr]
    with pytest.raises(OAuthFlowError, match="STATE_REPLAY"):
        flow.complete(callback_url=callback, exchange=exchange)


def test_callback_host_mismatch_consumes_state_and_does_not_exchange() -> None:
    clock, store = Clock(), FakeCredentialStore()
    flow = _flow(clock, store)
    query = parse_qs(urlsplit(_start(flow).authorization_url).query)
    callback = (
        f"http://localhost:49152/oauth/callback?code=synthetic-code&state={query['state'][0]}"
    )
    called = False

    def exchange(_request):
        nonlocal called
        called = True
        raise AssertionError("exchange must not run")

    with pytest.raises(OAuthFlowError, match="CALLBACK_INVALID"):
        flow.complete(callback_url=callback, exchange=exchange)
    assert not called
    with pytest.raises(OAuthFlowError, match="STATE_REPLAY"):
        flow.complete(callback_url=callback, exchange=exchange)


def test_expiry_and_nonce_mismatch_are_denied_without_persisting() -> None:
    clock, store = Clock(), FakeCredentialStore()
    flow = _flow(clock, store)
    start = _start(flow)
    query = parse_qs(urlsplit(start.authorization_url).query)
    callback = f"{REDIRECT}?code=synthetic-code&state={query['state'][0]}"
    clock.now = start.expires_at_ns + 1
    with pytest.raises(OAuthFlowError, match="EXPIRED"):
        flow.complete(callback_url=callback, exchange=lambda _req: None)  # type: ignore[arg-type]
    assert not store.profiles


def test_exchange_exception_context_cannot_retain_secret_canary() -> None:
    clock, store = Clock(), FakeCredentialStore()
    flow = _flow(clock, store)
    start = _start(flow)
    query = parse_qs(urlsplit(start.authorization_url).query)
    callback = f"{REDIRECT}?code=synthetic-code&state={query['state'][0]}"

    def exchange(_request):
        raise RuntimeError("synthetic-secret-canary-901")

    with pytest.raises(OAuthFlowError, match="TOKEN_EXCHANGE_FAILED") as caught:
        flow.complete(callback_url=callback, exchange=exchange)
    assert caught.value.__context__ is None
    assert caught.value.__cause__ is None

    clock.now = 2_000_000_000
    flow = _flow(clock, store)
    start = _start(flow)
    query = parse_qs(urlsplit(start.authorization_url).query)
    callback = f"{REDIRECT}?code=synthetic-code&state={query['state'][0]}"
    with pytest.raises(OAuthFlowError, match="NONCE_MISMATCH"):
        flow.complete(
            callback_url=callback,
            exchange=lambda req: OAuthTokenResponseV1(
                "synthetic-access-token", None, datetime(2030, 1, 1, tzinfo=UTC), "wrong-nonce"
            ),
        )
    assert not store.profiles


def test_provider_and_redirect_host_allowlists_are_closed() -> None:
    clock, store = Clock(), FakeCredentialStore()
    flow = _flow(clock, store)
    with pytest.raises(OAuthFlowError, match="UNSUPPORTED_PROVIDER"):
        flow.begin(
            provider="OPENAI",
            environment="PAPER",
            profile_id="default",
            client_id="id",
            redirect_uri=REDIRECT,
        )
    with pytest.raises(OAuthFlowError, match="INVALID_REDIRECT_URI"):
        flow.begin(
            provider="TASTYTRADE",
            environment="DEMO",
            profile_id="default",
            client_id="id",
            redirect_uri="http://127.0.0.1:49152/other",
        )
    assert authorization_host["KRAKEN"] == ()
    assert authorization_host["OPENAI_COMPATIBLE"] == ()
    with pytest.raises(TypeError):
        authorization_host["OPENAI"] = ("arbitrary.example",)  # type: ignore[index]


def test_snaptrade_portal_is_host_pinned_and_single_use_state_bound() -> None:
    clock, store = Clock(), FakeCredentialStore()
    flow = _flow(clock, store)
    start = flow.begin_snaptrade_portal(
        portal_url="https://app.snaptrade.com/snapTrade/redeemToken?token=synthetic-portal-token",
        redirect_uri=REDIRECT,
        profile_id="default",
        environment="PAPER",
    )
    query = parse_qs(urlsplit(start.authorization_url).query)
    assert query["token"] == ["synthetic-portal-token"]
    callback = (
        f"{REDIRECT}?status=SUCCESS&connection_id=synthetic-connection&state={query['state'][0]}"
    )
    assert flow.complete_snaptrade_callback(callback_url=callback) == (
        "SUCCESS",
        "synthetic-connection",
    )
    with pytest.raises(OAuthFlowError, match="STATE_REPLAY"):
        flow.complete_snaptrade_callback(callback_url=callback)
    with pytest.raises(OAuthFlowError, match="UNSUPPORTED_PROVIDER"):
        flow.begin_snaptrade_portal(
            portal_url="https://attacker.example/path?token=synthetic",
            redirect_uri=REDIRECT,
            profile_id="default",
            environment="PAPER",
        )
