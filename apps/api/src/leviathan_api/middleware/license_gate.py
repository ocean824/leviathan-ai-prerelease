"""Fail-closed local API licensing and feature gate.

The sidecar receives its signed licence snapshot from the trusted desktop
shell through process environment. This module deliberately performs no
network access and never logs environment values or request data.
"""

from __future__ import annotations

import json
import logging
import os
import re
from collections.abc import Mapping
from types import MappingProxyType
from typing import Final

from starlette.types import ASGIApp, Receive, Scope, Send

_STATE_ENV: Final = "LEVIATHAN_LICENSE_STATE"
_FEATURES_ENV: Final = "LEVIATHAN_LICENSE_FEATURES"
_VERIFIED_ONLINE: Final = "VERIFIED_ONLINE"
_GRACE_READ_ONLY: Final = "GRACE_READ_ONLY"
_SAFE_METHODS: Final = frozenset({"GET", "HEAD", "OPTIONS"})

FEATURE_KEYS_V1: Final = frozenset(
    {
        "paper_trading",
        "live_trading",
        "data_sources",
        "strategy_lab",
        "ea_hosting",
        "chat_terminal",
        "charts",
        "connections",
        "admin_console",
        "user_settings",
    }
)

# Closed route-template inventory mirrored from
# workers/licensing/src/entitlement/feature_catalog.ts API_FEATURE_ACTIONS_V1.
# Parameter braces denote exactly one non-empty path segment. Keep this table
# explicit: unmapped routes are pass-through and must be added deliberately.
ROUTE_FEATURES_V1: Final[tuple[tuple[str, str], ...]] = (
    ("/live-trading/credentials/{provider}/{environment}/{profile_id}", "connections"),
    ("/ingest/backfill", "data_sources"),
    ("/mcp/agents/register", "chat_terminal"),
    ("/mcp/tools/grant", "admin_console"),
    ("/mcp/sessions", "chat_terminal"),
    ("/mcp/sessions/{session_id}", "chat_terminal"),
    ("/mcp/actions", "chat_terminal"),
    ("/mcp/actions/dry-run", "chat_terminal"),
    ("/mcp/overrides", "admin_console"),
    ("/mcp/halts", "live_trading"),
    ("/omega/inquiry", "chat_terminal"),
    ("/omega/kill", "live_trading"),
    ("/v1/omega/tasks/handoff", "chat_terminal"),
    ("/v1/omega/tasks/{task_id}/accept", "chat_terminal"),
    ("/v1/omega/tasks/{task_id}/update", "chat_terminal"),
    ("/v1/omega/tasks/{task_id}/cancel", "chat_terminal"),
    ("/v1/omega/tools/use", "chat_terminal"),
    ("/orders/recover", "paper_trading"),
    ("/orders/activations", "live_trading"),
    ("/orders/activations/revoke", "live_trading"),
    ("/orders", "paper_trading"),
    ("/orders/{order_id}/submit", "paper_trading"),
    ("/orders/{order_id}/cancel", "paper_trading"),
    ("/orders/{order_id}/reconcile", "paper_trading"),
    ("/paper/mass-cancel/v1", "paper_trading"),
    ("/paper/risk/assessment/v1/preview", "paper_trading"),
    ("/pipeline/replay", "strategy_lab"),
    ("/mt5/ea-host/v1/install", "ea_hosting"),
    ("/mt5/ea-host/v1/sessions/{session_id}", "ea_hosting"),
    ("/mt5/ea-host/v1/sessions/{session_id}/kill", "ea_hosting"),
    ("/api/preferences/{namespace}", "user_settings"),
    ("/chat/history/conversations", "chat_terminal"),
    ("/chat/history/conversations/{conversation_id}/messages", "chat_terminal"),
    ("/chat/history/conversations/{conversation_id}", "chat_terminal"),
    ("/chat/history/conversations/{conversation_id}/export", "chat_terminal"),
    ("/chat/models", "chat_terminal"),
    ("/chat/complete", "chat_terminal"),
    ("/chat/stream", "chat_terminal"),
    ("/chat/tools/registry", "chat_terminal"),
    ("/chat/tools/plan", "chat_terminal"),
    ("/chat/tools/confirm", "chat_terminal"),
    ("/chat/tools/read", "chat_terminal"),
    ("/connections/catalog", "connections"),
    ("/connections/status", "connections"),
    ("/connections/{provider}/connect", "connections"),
    ("/connections/{provider}/cancel", "connections"),
    ("/connections/{provider}/disconnect", "connections"),
    ("/live-activation/status", "live_trading"),
    ("/live-activation/enable", "live_trading"),
    ("/live-activation/disable", "live_trading"),
    ("/v1/signup/checkout", "admin_console"),
    ("/v1/signup/webhook", "admin_console"),
    ("/data-sources", "data_sources"),
    ("/risk/halt", "live_trading"),
    ("/risk/halt/lift", "admin_console"),
    ("/md/chart/ticket", "charts"),
)

# Every catalog feature is represented. Chart-ticket minting opens a read-only
# chart view and is gated by the `charts` feature.
FEATURE_ROUTE_FAMILIES_V1: Final = MappingProxyType(
    {
        "paper_trading": tuple(
            path for path, feature in ROUTE_FEATURES_V1 if feature == "paper_trading"
        ),
        "live_trading": tuple(
            path for path, feature in ROUTE_FEATURES_V1 if feature == "live_trading"
        ),
        "data_sources": tuple(
            path for path, feature in ROUTE_FEATURES_V1 if feature == "data_sources"
        ),
        "strategy_lab": tuple(
            path for path, feature in ROUTE_FEATURES_V1 if feature == "strategy_lab"
        ),
        "ea_hosting": tuple(path for path, feature in ROUTE_FEATURES_V1 if feature == "ea_hosting"),
        "chat_terminal": tuple(
            path for path, feature in ROUTE_FEATURES_V1 if feature == "chat_terminal"
        ),
        "charts": tuple(path for path, feature in ROUTE_FEATURES_V1 if feature == "charts"),
        "connections": tuple(
            path for path, feature in ROUTE_FEATURES_V1 if feature == "connections"
        ),
        "admin_console": tuple(
            path for path, feature in ROUTE_FEATURES_V1 if feature == "admin_console"
        ),
        "user_settings": tuple(
            path for path, feature in ROUTE_FEATURES_V1 if feature == "user_settings"
        ),
    }
)

_GRACE_WRITE_ALLOWLIST: Final = frozenset(
    {
        ("POST", "/md/chart/ticket"),
        ("POST", "/risk/halt"),
        ("POST", "/mcp/halts"),
        ("POST", "/omega/kill"),
        ("POST", "/live-activation/disable"),
    }
)
_LIVE_ENABLE_PATHS: Final = frozenset({"/live-activation/enable", "/orders/activations"})
_TEMPLATE_PARAMETER = re.compile(r"\{[^{}]+\}")


def _route_pattern(template: str) -> re.Pattern[str]:
    pieces: list[str] = []
    cursor = 0
    for match in _TEMPLATE_PARAMETER.finditer(template):
        pieces.append(re.escape(template[cursor : match.start()]))
        pieces.append(r"[^/]+")
        cursor = match.end()
    pieces.append(re.escape(template[cursor:]))
    return re.compile("".join(pieces), re.ASCII)


_ROUTE_PATTERNS_V1: Final = tuple(
    (_route_pattern(template), feature) for template, feature in ROUTE_FEATURES_V1
)


def feature_for_path(path: str) -> str | None:
    """Return the closed feature binding for a catalog route template match."""
    if type(path) is not str or not path.startswith("/"):
        return None
    for pattern, feature in _ROUTE_PATTERNS_V1:
        if pattern.fullmatch(path) is not None:
            return feature
    return None


def _parse_features(raw: object) -> frozenset[str] | None:
    if type(raw) is not str or len(raw) > 1024:
        return None
    if raw == "":
        return frozenset()
    pieces = raw.split(",")
    if any(not item.strip() for item in pieces):
        return None
    normalized = tuple(item.strip() for item in pieces)
    if any(item not in FEATURE_KEYS_V1 for item in normalized):
        return None
    return frozenset(normalized)


async def _deny(send: Send, *, feature: str | None = None) -> None:
    body: dict[str, str] = (
        {"code": "FEATURE_NOT_ENTITLED", "feature": feature}
        if feature
        else {"code": "LICENSE_READ_ONLY"}
    )
    encoded = json.dumps(body, separators=(",", ":")).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": 403,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(encoded)).encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": encoded, "more_body": False})


class LicenseGateMiddleware:
    """Enforce grace read-only and entitlement checks for mapped API routes."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        environ: Mapping[str, str] | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        env: Mapping[str, str] = os.environ if environ is None else environ
        if not isinstance(env, Mapping):
            raise TypeError("environ must be a mapping")
        state_present = _STATE_ENV in env
        features_present = _FEATURES_ENV in env
        self.app = app
        self.logger = logger if logger is not None else logging.getLogger(__name__)
        self.active = state_present or features_present
        self.partial = False
        self.license_state: str | None = None
        self.features: frozenset[str] = frozenset()

        if not self.active:
            self.logger.warning("LICENSE_GATE_INACTIVE")
            return

        state = env.get(_STATE_ENV)
        features_raw = env.get(_FEATURES_ENV)
        parsed_features = _parse_features(features_raw) if features_present else None
        if (
            not state_present
            or not features_present
            or type(state) is not str
            or state not in {_VERIFIED_ONLINE, _GRACE_READ_ONLY}
            or parsed_features is None
        ):
            self.partial = True
            self.logger.warning("LICENSE_GATE_PARTIAL_CONFIG")
            return

        self.license_state = state
        self.features = parsed_features

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http" or not self.active:
            await self.app(scope, receive, send)
            return

        path = scope.get("path")
        method = scope.get("method")
        if type(path) is not str or type(method) is not str:
            await self.app(scope, receive, send)
            return
        method = method.upper()

        if self.partial and method not in _SAFE_METHODS:
            await _deny(send)
            return

        if self.license_state == _GRACE_READ_ONLY:
            if path in _LIVE_ENABLE_PATHS:
                await _deny(send)
                return
            if method not in _SAFE_METHODS and (method, path) not in _GRACE_WRITE_ALLOWLIST:
                await _deny(send)
                return

        feature = feature_for_path(path)
        if feature is not None and feature not in self.features:
            await _deny(send, feature=feature)
            return

        await self.app(scope, receive, send)
