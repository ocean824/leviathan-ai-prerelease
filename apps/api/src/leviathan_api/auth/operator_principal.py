"""AUTH-MW-001: a local operator principal from the desktop shell's per-launch evidence.

The desktop shell creates a fresh random capability for each launch and the
WebView bridge sends it as ``X-Leviathan-Capability``. This middleware re-verifies
that same evidence (and the loopback Host/Origin the sidecar guard enforces) and,
only on success, sets ``request.state.trusted_principal`` to a principal issued by
the SEC-002 ``TrustedPrincipalAdapterV1``. Roles and project scope come only from
an injected, sealed ``LocalOperatorProfileV1``.

It adds no secret, persistence or network access, never reads a principal, role or
claim from request data, and never logs. The capability is held privately and
appears in no repr, error, seal digest or response. Missing or invalid evidence
sets nothing and removes any existing ``trusted_principal``, so routes keep
their own uniform 401.

Threat model: in-process code is trusted, as for SEC-002. This protects against
untrusted requests and data, not against Python running inside the process.
"""

from __future__ import annotations

import hmac
import re
from typing import Annotated, Final

from pydantic import StringConstraints, model_validator
from starlette.types import ASGIApp, Receive, Scope, Send

from leviathan_api.auth.chart_stream_tickets import (
    ChartStreamScopeV1,
    ChartStreamTicketStore,
)
from leviathan_core.seal import Issuer, SealedModel, SealError, require
from leviathan_core.security.authz_models import (
    _VERIFIER_MARKER,
    AuthorizationModelError,
    PrincipalV1,
    TrustedPrincipalAdapterV1,
    TrustedPrincipalV1,
)

PROFILE_TAG: Final = "auth_mw001.local_operator_profile.v1"
CAPABILITY_HEADER: Final = b"x-leviathan-capability"
# Closed list of non-live environments. Anything else, including live or production
# spellings, is refused: this profile can never carry live-money authority.
ALLOWED_ENVS: Final = frozenset({"development", "test", "paper", "demo"})
DEFAULT_ROLES: Final = ("operator",)
_SAFE_METHODS: Final = frozenset({"GET", "HEAD", "OPTIONS"})
_CAPABILITY: Final = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_STREAM_TICKET: Final = re.compile(r"[A-Za-z0-9_-]{43}\Z", re.ASCII)
_LIVE: Final = re.compile(r"live|prod|real|funded", re.IGNORECASE)
_PROFILE_ISSUER: Final = Issuer(PROFILE_TAG)

_Id = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")]


class OperatorAuthError(ValueError):
    """Content-free construction error; no capability or profile value is echoed."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class LocalOperatorProfileV1(SealedModel):
    """The local operator's identity and scope. It holds no secret.

    Only ``make_local_operator_profile`` issues one. A profile built by calling the
    class directly is unissued and the middleware refuses it.
    """

    principal_id: _Id
    project_id: _Id
    env: _Id
    roles: tuple[_Id, ...]
    venue: _Id | None
    portfolio: _Id | None
    strategy: _Id | None

    @model_validator(mode="after")
    def _non_live_and_minimal(self) -> LocalOperatorProfileV1:
        if self.env not in ALLOWED_ENVS:
            raise ValueError("environment not allowed")
        if not self.roles or len(set(self.roles)) != len(self.roles):
            raise ValueError("roles must be a unique, nonempty set")
        scopes = (self.venue, self.portfolio, self.strategy)
        if any(_LIVE.search(value) for value in (*self.roles, *(s for s in scopes if s))):
            raise ValueError("live authority is not available to the local operator")
        return self


def make_local_operator_profile(
    *,
    principal_id: str,
    project_id: str,
    env: str,
    roles: tuple[str, ...] = DEFAULT_ROLES,
    venue: str | None = None,
    portfolio: str | None = None,
    strategy: str | None = None,
) -> LocalOperatorProfileV1:
    """Build and issue a profile. ``principal_id``, ``project_id`` and ``env`` are required."""
    return _PROFILE_ISSUER.issue(
        LocalOperatorProfileV1(
            principal_id=principal_id,
            project_id=project_id,
            env=env,
            roles=roles,
            venue=venue,
            portfolio=portfolio,
            strategy=strategy,
        )
    )


def require_local_operator_profile(obj: object) -> LocalOperatorProfileV1:
    """Return an issued, unmodified profile or raise a content-free error."""
    if type(obj) is not LocalOperatorProfileV1:
        raise OperatorAuthError("INVALID_PROFILE")
    try:
        return require(obj, PROFILE_TAG)
    except SealError:
        raise OperatorAuthError("INVALID_PROFILE") from None


def _header_values(scope: Scope, name: bytes) -> list[bytes]:
    return [value for key, value in scope.get("headers", ()) if key == name]


class OperatorPrincipalMiddleware:
    """Pure ASGI middleware; see the module docstring for the evidence it verifies."""

    __slots__ = ("_app", "_capability", "_features", "_host", "_origin", "_profile")

    def __init__(
        self,
        app: ASGIApp,
        *,
        capability: str,
        port: int,
        profile: object | None,
        features: frozenset[str] = frozenset(),
        allow_anonymous: bool = False,
    ) -> None:
        if type(capability) is not str or _CAPABILITY.fullmatch(capability) is None:
            raise OperatorAuthError("INVALID_CAPABILITY")
        if type(port) is not int or not 1 <= port <= 65535:
            raise OperatorAuthError("INVALID_PORT")
        if profile is None and not allow_anonymous:
            raise OperatorAuthError("INVALID_PROFILE")
        self._profile = None if profile is None else require_local_operator_profile(profile)
        self._features = features if self._profile is not None else frozenset()
        self._app = app
        self._capability = capability.encode("ascii")
        self._host = f"127.0.0.1:{port}".encode("ascii")
        self._origin = b"http://" + self._host

    def __repr__(self) -> str:
        return "OperatorPrincipalMiddleware()"

    def _evidence_failure_code(self, scope: Scope) -> str | None:
        if _header_values(scope, b"host") != [self._host]:
            return "ORIGIN_OR_HOST_INVALID"
        origins = _header_values(scope, b"origin")
        if len(origins) > 1 or (origins and origins != [self._origin]):
            return "ORIGIN_OR_HOST_INVALID"
        method = scope.get("method", "")
        if method not in _SAFE_METHODS and origins != [self._origin]:
            return "ORIGIN_OR_HOST_INVALID"
        provided = _header_values(scope, CAPABILITY_HEADER)
        if len(provided) != 1 or not hmac.compare_digest(provided[0], self._capability):
            return "CAPABILITY_INVALID"
        return None

    def _evidence_valid(self, scope: Scope) -> bool:
        # Keep the established HTTP decision exactly the same; WebSocket handshakes
        # use the same predicate and only add a pre-accept denial response.
        return self._evidence_failure_code(scope) is None

    def _origin_host_failure_code(self, scope: Scope) -> str | None:
        if _header_values(scope, b"host") != [self._host]:
            return "ORIGIN_OR_HOST_INVALID"
        origins = _header_values(scope, b"origin")
        if len(origins) != 1 or origins != [self._origin]:
            return "ORIGIN_OR_HOST_INVALID"
        return None

    @staticmethod
    def _chart_ticket(scope: Scope) -> tuple[str, ChartStreamScopeV1] | None:
        path = scope.get("path")
        if type(path) is not str or not path.endswith("/md/chart"):
            return None
        protocol_headers = _header_values(scope, b"sec-websocket-protocol")
        if len(protocol_headers) != 1 or len(protocol_headers[0]) > 512:
            return None
        try:
            protocols = [item.strip() for item in protocol_headers[0].decode("ascii").split(",")]
        except UnicodeDecodeError:
            return None
        if (
            len(protocols) != 2
            or protocols[0] != "leviathan.chart.v1"
            or not protocols[1].startswith("ticket.")
        ):
            return None
        token = protocols[1][len("ticket.") :]
        if _STREAM_TICKET.fullmatch(token) is None:
            return None
        raw_query = scope.get("query_string", b"")
        if type(raw_query) is not bytes or len(raw_query) > 2048:
            return None
        try:
            pairs = raw_query.decode("ascii").split("&")
            values: dict[str, str] = {}
            for pair in pairs:
                key, separator, value = pair.partition("=")
                if not separator or key in values:
                    return None
                from urllib.parse import unquote_to_bytes

                decoded_key = unquote_to_bytes(key.replace("+", " ")).decode("ascii")
                decoded_value = unquote_to_bytes(value.replace("+", " ")).decode("ascii")
                if decoded_key in values:
                    return None
                values[decoded_key] = decoded_value
        except (UnicodeDecodeError, ValueError):
            return None
        if set(values) != {"venue", "instrument", "type"}:
            return None
        try:
            stream_scope = ChartStreamScopeV1(
                venue=values["venue"],
                instrument=values["instrument"],
                data_type=values["type"],
            )
        except ValueError:
            return None
        return token, stream_scope

    @staticmethod
    def _ticket_store(scope: Scope) -> ChartStreamTicketStore | None:
        app = scope.get("app")
        state = getattr(app, "state", None)
        store = getattr(state, "chart_stream_ticket_store", None)
        return store if type(store) is ChartStreamTicketStore else None

    def _ticket_principal(self) -> TrustedPrincipalV1 | None:
        return self._issue()

    def _issue(self) -> TrustedPrincipalV1 | None:
        if self._profile is None:
            return None
        try:
            profile = require_local_operator_profile(self._profile)
            claims = PrincipalV1(
                principal_id=profile.principal_id,
                project_id=profile.project_id,
                roles=profile.roles,
                env=profile.env,
                venue=profile.venue,
                portfolio=profile.portfolio,
                strategy=profile.strategy,
            )
            return TrustedPrincipalAdapterV1.from_verified_claims(
                claims, verifier_marker=_VERIFIER_MARKER
            )
        except (OperatorAuthError, AuthorizationModelError, SealError, ValueError):
            return None  # fail closed: no principal

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            state = scope.setdefault("state", {})
            state.pop("trusted_principal", None)  # never inherit one from anywhere else
            state.pop("trusted_operator_profile", None)
            state.pop("trusted_operator_origin", None)
            state.pop("trusted_instance_principal_id", None)
            state.pop("trusted_instance_features", None)
            if self._evidence_valid(scope):
                principal = self._issue()
                if principal is not None:
                    state["trusted_principal"] = principal
                    state["trusted_operator_profile"] = require_local_operator_profile(
                        self._profile
                    )
                    state["trusted_operator_origin"] = self._origin.decode("ascii")
                    state["trusted_instance_principal_id"] = principal.principal_id
                    state["trusted_instance_features"] = self._features
        elif scope["type"] == "websocket":
            state = scope.setdefault("state", {})
            state.pop("trusted_principal", None)
            state.pop("trusted_operator_profile", None)
            state.pop("trusted_operator_origin", None)
            state.pop("trusted_instance_principal_id", None)
            state.pop("trusted_instance_features", None)
            state.pop("chart_ticket_authenticated", None)
            host_is_valid = _header_values(scope, b"host") == [self._host]
            origin_failure = self._origin_host_failure_code(scope)
            failure = origin_failure or self._evidence_failure_code(scope)
            principal = self._issue() if failure is None else None
            ticket_authenticated = False
            if principal is None and host_is_valid and origin_failure is None:
                provided_capability = _header_values(scope, CAPABILITY_HEADER)
                # A malformed/foreign capability must not silently fall back to a ticket.
                ticket = self._chart_ticket(scope) if not provided_capability else None
                store = self._ticket_store(scope)
                if ticket is not None and store is not None:
                    token, stream_scope = ticket
                    ticket_principal = self._ticket_principal()
                    origins = _header_values(scope, b"origin")
                    try:
                        origin = origins[0].decode("ascii") if len(origins) == 1 else ""
                        profile = require_local_operator_profile(self._profile)
                        ticket_authenticated = ticket_principal is not None and store.consume(
                            token,
                            principal=ticket_principal,
                            profile=profile,
                            origin=origin,
                            stream_scope=stream_scope,
                        )
                    except (UnicodeDecodeError, OperatorAuthError, ValueError):
                        ticket_authenticated = False
                    if ticket_authenticated and origin_failure is None:
                        principal = ticket_principal
            if principal is None:
                # Reject at the handshake boundary. Never let the route infer a
                # principal from query data or proceed to accept an unauthenticated
                # connection.
                code = 4403 if origin_failure == "ORIGIN_OR_HOST_INVALID" else 4401
                await send({"type": "websocket.close", "code": code})
                return
            state["trusted_principal"] = principal
            if self._profile is not None:
                state["trusted_operator_profile"] = require_local_operator_profile(self._profile)
                state["trusted_instance_principal_id"] = principal.principal_id
                state["trusted_instance_features"] = self._features
            state["trusted_operator_origin"] = self._origin.decode("ascii")
            if ticket_authenticated:
                state["chart_ticket_authenticated"] = True
        await self._app(scope, receive, send)


__all__ = [
    "ALLOWED_ENVS",
    "DEFAULT_ROLES",
    "PROFILE_TAG",
    "LocalOperatorProfileV1",
    "OperatorAuthError",
    "OperatorPrincipalMiddleware",
    "make_local_operator_profile",
    "require_local_operator_profile",
]
