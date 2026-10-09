"""Injected loopback OAuth authorization code flow; this module opens no sockets."""

from __future__ import annotations

import base64
import hashlib
import re
import secrets
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Protocol
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

from pydantic import SecretStr

# Authorization endpoints and hosts are pinned to provider documentation. The empty
# tuples are deliberate: these providers use key/login entry, not an arbitrary host.
# ALPACA: https://docs.alpaca.markets/us/docs/using-oauth2-and-trading-api
# TASTYTRADE: https://developer.tastytrade.com/oauth/
# CTRADER: https://help.ctrader.com/open-api/account-authentication/
# COINBASE: https://docs.cdp.coinbase.com/coinbase-business/authentication-authorization/oauth2/reference
# SNAPTRADE portal: https://docs.snaptrade.com/reference/Authentication/Authentication_loginSnapTradeUser
authorization_host: Mapping[str, tuple[str, ...]] = MappingProxyType(
    {
        "ALPACA": ("app.alpaca.markets",),
        "TASTYTRADE": ("my.tastytrade.com", "cert-my.staging-tasty.works"),
        "CTRADER": ("id.ctrader.com",),
        "COINBASE": ("login.coinbase.com",),
        "SNAPTRADE": ("app.snaptrade.com",),
        "IBKR": (),
        "KRAKEN": (),
        "BINANCE_US": (),
        "FOREX_COM_MT5": (),
        "RITHMIC": (),
        "KALSHI": (),
        "ANTHROPIC": (),
        "OPENAI": (),
        "OPENAI_COMPATIBLE": (),
    }
)

_AUTH_ENDPOINTS = {
    "ALPACA": "https://app.alpaca.markets/oauth/authorize",
    "TASTYTRADE": "https://my.tastytrade.com/auth.html",
    "CTRADER": "https://id.ctrader.com/my/settings/openapi/grantingaccess/",
    "COINBASE": "https://login.coinbase.com/oauth2/auth",
}
_MAX_PENDING = 128
_MAX_TTL_NS = 600_000_000_000
_PROFILE_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_FLOW_ENVIRONMENTS = {
    "ALPACA": frozenset({"PAPER", "LIVE"}),
    "TASTYTRADE": frozenset({"PAPER", "DEMO", "LIVE"}),
    "CTRADER": frozenset({"PAPER", "DEMO", "LIVE"}),
    "COINBASE": frozenset({"PAPER", "DEMO", "LIVE"}),
}
_ERROR_CODES = frozenset(
    {
        "CALLBACK_INVALID",
        "CODE_INVALID",
        "EXPIRED",
        "INVALID_PROVIDER",
        "INVALID_REDIRECT_URI",
        "INVALID_STATE",
        "LIMIT_EXCEEDED",
        "NONCE_MISMATCH",
        "PERSISTENCE_FAILED",
        "STATE_REPLAY",
        "TOKEN_EXCHANGE_FAILED",
        "UNSUPPORTED_PROVIDER",
    }
)


class OAuthFlowError(ValueError):
    """Content-free error code for the OAuth callback flow."""

    def __init__(self, code: str) -> None:
        self.code = code if code in _ERROR_CODES else "CALLBACK_INVALID"
        super().__init__(self.code)


@dataclass(frozen=True, slots=True)
class AuthorizationStartV1:
    authorization_url: str
    expires_at_ns: int

    def __repr__(self) -> str:
        return "AuthorizationStartV1(<redacted>)"


@dataclass(frozen=True, slots=True)
class OAuthTokenRequestV1:
    provider: str
    client_id: str
    code: str
    code_verifier: str
    redirect_uri: str
    nonce: str

    def __repr__(self) -> str:
        return "OAuthTokenRequestV1(<redacted>)"


@dataclass(frozen=True, slots=True)
class OAuthTokenResponseV1:
    access_token: str
    refresh_token: str | None
    expires_at: datetime
    verified_nonce: str

    def __repr__(self) -> str:
        return "OAuthTokenResponseV1(<redacted>)"


@dataclass(frozen=True, slots=True)
class OAuthCompletionV1:
    provider: str
    environment: str
    profile_id: str
    expires_at: datetime


class CredentialPersistencePort(Protocol):
    def put_profile(
        self, provider: str, environment: str, profile_id: str, fields: dict[str, object]
    ) -> object: ...


class TokenExchangePort(Protocol):
    def __call__(self, request: OAuthTokenRequestV1) -> OAuthTokenResponseV1: ...


@dataclass(slots=True)
class _Pending:
    provider: str
    environment: str
    profile_id: str
    client_id: str
    redirect_uri: str
    verifier: str | None
    nonce: str | None
    expires_at_ns: int
    profile_fields: dict[str, object]
    portal: bool = False

    def __repr__(self) -> str:
        return "_Pending(<redacted>)"


def _loopback_redirect(value: object) -> tuple[str, str, int, str]:
    if type(value) is not str or len(value) > 512:
        raise OAuthFlowError("INVALID_REDIRECT_URI")
    try:
        parts = urlsplit(value)
        if (
            parts.scheme != "http"
            or parts.hostname != "127.0.0.1"
            or parts.port is None
            or not 1 <= parts.port <= 65535
            or parts.username is not None
            or parts.password is not None
            or parts.query
            or parts.fragment
            or not parts.path.startswith("/")
        ):
            raise OAuthFlowError("INVALID_REDIRECT_URI")
        return parts.scheme, parts.hostname, parts.port, parts.path
    except ValueError:
        raise OAuthFlowError("INVALID_REDIRECT_URI") from None


def _pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge.rstrip(b"=").decode("ascii")


class OAuthLoopbackV1:
    """PKCE/state engine behind injected redirect, clock, exchange and persistence ports."""

    def __init__(
        self,
        *,
        allowed_redirect_uris: Mapping[str, frozenset[str]],
        credential_store: CredentialPersistencePort,
        clock_ns: Callable[[], int],
        max_ttl_ns: int = 300_000_000_000,
    ) -> None:
        if type(max_ttl_ns) is not int or not 1 <= max_ttl_ns <= _MAX_TTL_NS:
            raise OAuthFlowError("CALLBACK_INVALID")
        self._allowed = {key: frozenset(value) for key, value in allowed_redirect_uris.items()}
        for redirect_set in self._allowed.values():
            for redirect in redirect_set:
                _loopback_redirect(redirect)
        self._store = credential_store
        self._clock = clock_ns
        self._ttl_ns = max_ttl_ns
        self._pending: dict[str, _Pending] = {}

    def begin(
        self,
        *,
        provider: str,
        environment: str,
        profile_id: str,
        client_id: str,
        redirect_uri: str,
        scopes: tuple[str, ...] = (),
        profile_fields: Mapping[str, object] | None = None,
        ttl_ns: int | None = None,
    ) -> AuthorizationStartV1:
        endpoint = _AUTH_ENDPOINTS.get(provider)
        if endpoint is None:
            raise OAuthFlowError("UNSUPPORTED_PROVIDER")
        if provider == "TASTYTRADE" and environment == "DEMO":
            endpoint = "https://cert-my.staging-tasty.works/auth.html"
        host = urlsplit(endpoint).hostname
        if host not in authorization_host.get(provider, ()):
            raise OAuthFlowError("UNSUPPORTED_PROVIDER")
        if (
            type(environment) is not str
            or environment not in _FLOW_ENVIRONMENTS[provider]
            or type(profile_id) is not str
            or not _PROFILE_ID.fullmatch(profile_id)
            or type(client_id) is not str
            or not client_id
            or len(client_id) > 256
        ):
            raise OAuthFlowError("CALLBACK_INVALID")
        allowed = self._allowed.get(provider, frozenset())
        if redirect_uri not in allowed:
            raise OAuthFlowError("INVALID_REDIRECT_URI")
        _loopback_redirect(redirect_uri)
        ttl = self._ttl_ns if ttl_ns is None else ttl_ns
        if type(ttl) is not int or not 1 <= ttl <= _MAX_TTL_NS:
            raise OAuthFlowError("CALLBACK_INVALID")
        now = self._clock()
        self._expire(now)
        if len(self._pending) >= _MAX_PENDING:
            raise OAuthFlowError("LIMIT_EXCEEDED")
        verifier, challenge = _pkce_pair()
        state, nonce = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        expires = now + ttl
        self._pending[state] = _Pending(
            provider,
            environment,
            profile_id,
            client_id,
            redirect_uri,
            verifier,
            nonce,
            expires,
            dict(profile_fields or {}),
        )
        query: dict[str, str] = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        if scopes:
            if any(
                type(scope) is not str
                or not scope
                or len(scope) > 128
                or not re.fullmatch(r"[A-Za-z0-9:._-]+", scope)
                for scope in scopes
            ):
                self._pending.pop(state, None)
                raise OAuthFlowError("CALLBACK_INVALID")
            query["scope"] = " ".join(scopes)
        if provider == "ALPACA":
            query["response_type"] = "code"
        parts = urlsplit(endpoint)
        url = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), ""))
        return AuthorizationStartV1(url, expires)

    def begin_snaptrade_portal(
        self,
        *,
        portal_url: str,
        redirect_uri: str,
        profile_id: str,
        environment: str,
        ttl_ns: int | None = None,
    ) -> AuthorizationStartV1:
        """Bind an injected SnapTrade portal URL to one exact loopback callback/state."""
        if redirect_uri not in self._allowed.get("SNAPTRADE", frozenset()):
            raise OAuthFlowError("INVALID_REDIRECT_URI")
        if (
            type(environment) is not str
            or environment not in {"PAPER", "DEMO", "LIVE"}
            or type(profile_id) is not str
            or not _PROFILE_ID.fullmatch(profile_id)
        ):
            raise OAuthFlowError("CALLBACK_INVALID")
        _loopback_redirect(redirect_uri)
        try:
            parts = urlsplit(portal_url)
            if (
                parts.scheme != "https"
                or parts.hostname not in authorization_host["SNAPTRADE"]
                or parts.username is not None
                or parts.password is not None
                or not parts.query
                or len(portal_url) > 4096
            ):
                raise OAuthFlowError("UNSUPPORTED_PROVIDER")
            query = parse_qs(parts.query, keep_blank_values=True)
            if "token" not in query or len(query["token"]) != 1:
                raise OAuthFlowError("UNSUPPORTED_PROVIDER")
        except ValueError:
            raise OAuthFlowError("UNSUPPORTED_PROVIDER") from None
        ttl = self._ttl_ns if ttl_ns is None else ttl_ns
        if type(ttl) is not int or not 1 <= ttl <= _MAX_TTL_NS:
            raise OAuthFlowError("CALLBACK_INVALID")
        now = self._clock()
        self._expire(now)
        if len(self._pending) >= _MAX_PENDING:
            raise OAuthFlowError("LIMIT_EXCEEDED")
        state = secrets.token_urlsafe(32)
        self._pending[state] = _Pending(
            "SNAPTRADE",
            environment,
            profile_id,
            "",
            redirect_uri,
            None,
            None,
            now + ttl,
            {},
            True,
        )
        merged = parse_qs(parts.query, keep_blank_values=True)
        merged["state"] = [state]
        return AuthorizationStartV1(
            urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(merged, doseq=True), "")),
            now + ttl,
        )

    def complete(
        self,
        *,
        callback_url: str,
        exchange: TokenExchangePort,
    ) -> OAuthCompletionV1:
        _state_values, _code_values, pending, code = self._consume_callback(callback_url)
        if pending.portal:
            raise OAuthFlowError("UNSUPPORTED_PROVIDER")
        if pending.verifier is None or pending.nonce is None:
            raise OAuthFlowError("CALLBACK_INVALID")
        request = OAuthTokenRequestV1(
            pending.provider,
            pending.client_id,
            code,
            pending.verifier,
            pending.redirect_uri,
            pending.nonce,
        )
        exchange_failed = False
        tokens: object = None
        try:
            tokens = exchange(request)
        except Exception:
            exchange_failed = True
        if exchange_failed:
            raise OAuthFlowError("TOKEN_EXCHANGE_FAILED")
        if (
            type(tokens) is not OAuthTokenResponseV1
            or type(tokens.access_token) is not str
            or not tokens.access_token
            or len(tokens.access_token.encode("utf-8")) > 4096
            or tokens.verified_nonce != pending.nonce
            or (
                tokens.refresh_token is not None
                and (type(tokens.refresh_token) is not str or not tokens.refresh_token)
            )
            or type(tokens.expires_at) is not datetime
            or tokens.expires_at.tzinfo is not UTC
        ):
            raise OAuthFlowError("NONCE_MISMATCH")
        fields = dict(pending.profile_fields)
        fields["access_token"] = SecretStr(tokens.access_token)
        if tokens.refresh_token is not None:
            fields["refresh_token"] = SecretStr(tokens.refresh_token)
        fields["token_expires_at"] = tokens.expires_at
        if pending.provider in {"TASTYTRADE", "CTRADER"}:
            fields.setdefault("oauth_client_id", pending.client_id)
        persistence_failed = False
        try:
            self._store.put_profile(
                pending.provider, pending.environment, pending.profile_id, fields
            )
        except Exception:
            persistence_failed = True
        if persistence_failed:
            raise OAuthFlowError("PERSISTENCE_FAILED")
        return OAuthCompletionV1(
            pending.provider, pending.environment, pending.profile_id, tokens.expires_at
        )

    def complete_snaptrade_callback(self, *, callback_url: str) -> tuple[str, str]:
        _state_values, _code_values, pending, _code = self._consume_callback(
            callback_url, require_code=False
        )
        if not pending.portal or pending.provider != "SNAPTRADE":
            raise OAuthFlowError("CALLBACK_INVALID")
        query = parse_qs(urlsplit(callback_url).query, keep_blank_values=True)
        status = query.get("status", [""])[0]
        connection_id = query.get("connection_id", [""])[0]
        if status not in {"SUCCESS", "ERROR"} or (status == "SUCCESS" and not connection_id):
            raise OAuthFlowError("CALLBACK_INVALID")
        return status, connection_id

    def cancel(self, state: str) -> None:
        self._pending.pop(state, None)

    def _consume_callback(
        self, callback_url: str, *, require_code: bool = True
    ) -> tuple[list[str], list[str], _Pending, str]:
        try:
            parts = urlsplit(callback_url)
            query = parse_qs(parts.query, keep_blank_values=True)
            states, codes = query.get("state", []), query.get("code", [])
            if len(states) != 1:
                raise OAuthFlowError("INVALID_STATE")
            state = states[0]
            pending = self._pending.pop(state, None)
            if pending is None:
                raise OAuthFlowError("STATE_REPLAY")
            scheme, host, port, path = _loopback_redirect(pending.redirect_uri)
            if (
                parts.scheme != scheme
                or parts.hostname != host
                or parts.port != port
                or parts.path != path
                or parts.username is not None
                or parts.password is not None
                or parts.fragment
                or parts.query == ""
            ):
                raise OAuthFlowError("CALLBACK_INVALID")
            if self._clock() >= pending.expires_at_ns:
                raise OAuthFlowError("EXPIRED")
            if require_code and (len(codes) != 1 or not codes[0] or len(codes[0]) > 4096):
                raise OAuthFlowError("CODE_INVALID")
            return states, codes, pending, codes[0] if codes else ""
        except OAuthFlowError:
            raise
        except (TypeError, ValueError):
            raise OAuthFlowError("CALLBACK_INVALID") from None

    def _expire(self, now: int) -> None:
        for state, item in tuple(self._pending.items()):
            if now >= item.expires_at_ns:
                self._pending.pop(state, None)


__all__ = [
    "AuthorizationStartV1",
    "CredentialPersistencePort",
    "OAuthCompletionV1",
    "OAuthFlowError",
    "OAuthLoopbackV1",
    "OAuthTokenRequestV1",
    "OAuthTokenResponseV1",
    "authorization_host",
]
