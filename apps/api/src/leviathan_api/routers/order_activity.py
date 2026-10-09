"""Bounded, authenticated PAPER OMS ledger activity reads.

The router is deliberately not mounted here. It exposes ledger evidence only;
it does not ask a broker for positions, valuation, or reconciliation freshness.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
from datetime import UTC, datetime
from decimal import Decimal
from urllib.parse import parse_qs

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.routing import APIRoute
from starlette.datastructures import MutableHeaders
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.types import Message, Receive, Scope, Send

from leviathan_core.execution.broker_port_v1 import (
    BrokerEnvironment,
    VenueIdentityV1,
)
from leviathan_core.execution.oms import (
    ActivityCorrectionItem,
    ActivityFillItem,
    ActivityOrderItem,
    OrderGatewayActor,
)
from leviathan_core.execution.order_models import (
    OMSLedgerCorruption,
    OMSValidationError,
    OrderSnapshot,
)
from leviathan_core.numeric import NumericError, canonical_json, canonical_str
from leviathan_core.security.authz_models import (
    AuthorizationModelError,
    require_trusted_principal,
)

_DEFAULT_LIMIT = 50
_MAX_LIMIT = 100
_MAX_NET_GROUPS = 100
_MAX_SAFE_JSON_INT = (1 << 53) - 1
_MAX_CURSOR_CHARS = 512
_CURSOR_DOMAIN = b"leviathan-oms-paper-activity-cursor-v1\x00"
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z", re.ASCII)
_CURSOR_PART = re.compile(r"[A-Za-z0-9_-]+\Z", re.ASCII)
_ERROR_PRINCIPAL = "PRINCIPAL_UNTRUSTED"
_ERROR_FORBIDDEN = "PAPER_ACTIVITY_FORBIDDEN"
_ERROR_PAPER_SCOPE = "PAPER_SCOPE_REQUIRED"
_ERROR_UNAVAILABLE = "PAPER_ACTIVITY_UNAVAILABLE"
_ERROR_QUERY = "INVALID_ACTIVITY_QUERY"
_ERROR_CURSOR = "INVALID_ACTIVITY_CURSOR"


class _NoStoreRoute(APIRoute):
    """Apply no-store to route responses, including framework-generated 405s."""

    async def handle(self, scope: Scope, receive: Receive, send: Send) -> None:
        async def send_no_store(message: Message) -> None:
            if message["type"] == "http.response.start":
                MutableHeaders(scope=message)["Cache-Control"] = "no-store"
            await send(message)

        try:
            await super().handle(scope, receive, send_no_store)
        except StarletteHTTPException as exc:
            if exc.status_code != 405:
                raise
            response = PlainTextResponse(
                "Method Not Allowed",
                status_code=405,
                headers={"Cache-Control": "no-store"},
            )
            await response(scope, receive, send)


def _error(status: int, code: str) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": {"code": code}})


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _scope_digest(environment: str, account_id: str) -> str:
    return hashlib.sha256(
        canonical_json({"account_id": account_id, "environment": environment})
    ).hexdigest()


def _issue_cursor(key: bytes, *, scope: str, high_water: int, last_sequence: int) -> str:
    payload = canonical_json(
        {
            "version": 1,
            "scope": scope,
            "high_water_sequence": high_water,
            "last_sequence": last_sequence,
        }
    )
    signature = hmac.digest(key, _CURSOR_DOMAIN + payload, "sha256")
    return f"{_b64(payload)}.{_b64(signature)}"


def _read_cursor(
    token: str,
    key: bytes,
    *,
    expected_scope: str,
) -> tuple[int, int] | None:
    if (
        type(token) is not str
        or not token
        or len(token) > _MAX_CURSOR_CHARS
        or token.count(".") != 1
    ):
        return None
    payload_part, signature_part = token.split(".", 1)
    if (
        _CURSOR_PART.fullmatch(payload_part) is None
        or _CURSOR_PART.fullmatch(signature_part) is None
        or len(signature_part) != 43
    ):
        return None
    try:
        payload = base64.urlsafe_b64decode(payload_part + "=" * (-len(payload_part) % 4))
        signature = base64.urlsafe_b64decode(signature_part + "=")
        expected = hmac.digest(key, _CURSOR_DOMAIN + payload, "sha256")
        if not hmac.compare_digest(signature, expected):
            return None
        decoded = json.loads(payload.decode("ascii"))
        if (
            type(decoded) is not dict
            or set(decoded) != {"version", "scope", "high_water_sequence", "last_sequence"}
            or type(decoded["version"]) is not int
            or decoded["version"] != 1
            or decoded["scope"] != expected_scope
            or type(decoded["high_water_sequence"]) is not int
            or not 0 <= decoded["high_water_sequence"] <= _MAX_SAFE_JSON_INT
            or type(decoded["last_sequence"]) is not int
            or not 0 <= decoded["last_sequence"] <= decoded["high_water_sequence"]
            or canonical_json(decoded) != payload
        ):
            return None
        return decoded["high_water_sequence"], decoded["last_sequence"]
    except (ValueError, TypeError, UnicodeError, json.JSONDecodeError):
        return None


def _query(request: Request) -> tuple[int, str | None] | None:
    raw = request.scope.get("query_string", b"")
    try:
        if type(raw) is not bytes or len(raw) > 1024:
            return None
        parsed = parse_qs(
            raw.decode("ascii"),
            keep_blank_values=True,
            strict_parsing=True,
            max_num_fields=2,
        )
        if set(parsed) - {"limit", "cursor"}:
            return None
        if any(len(values) != 1 for values in parsed.values()):
            return None
        limit_text = parsed.get("limit", [str(_DEFAULT_LIMIT)])[0]
        if re.fullmatch(r"(?:0|[1-9][0-9]{0,2})", limit_text, re.ASCII) is None:
            return None
        limit = int(limit_text)
        if not 1 <= limit <= _MAX_LIMIT:
            return None
        cursor = parsed.get("cursor", [None])[0]
        if cursor is not None and (not cursor or len(cursor) > _MAX_CURSOR_CHARS):
            return None
        return limit, cursor
    except (ValueError, UnicodeError):
        return None


def _utc_text(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _serialize_order(snapshot: OrderSnapshot, created_at: datetime) -> dict[str, object]:
    request = snapshot.request
    return {
        "order_id": snapshot.order_id,
        "venue": request.venue,
        "instrument_id": request.instrument_id,
        "side": request.side,
        "state": snapshot.state.value,
        "quantity": canonical_str(request.quantity),
        "filled_quantity": canonical_str(snapshot.filled_quantity),
        "discrepancies": list(snapshot.discrepancies),
        "created_at_utc": _utc_text(created_at),
    }


def _serialize_fill(item: ActivityFillItem) -> dict[str, object]:
    fill = item.fill
    return {
        "kind": "FILL",
        "ledger_sequence": item.ledger_sequence,
        "fill": {
            "order_id": item.order_id,
            "execution_id": fill.execution_id,
            "venue": fill.venue,
            "instrument_id": item.instrument_id,
            "side": item.side,
            "quantity": canonical_str(fill.quantity),
            "price": canonical_str(fill.price),
            "commission": canonical_str(fill.commission),
            "occurred_at_utc": _utc_text(fill.occurred_at),
        },
    }


def _serialize_correction(
    item: ActivityCorrectionItem,
) -> dict[str, object]:
    correction = item.correction
    return {
        "kind": "FILL_CORRECTION",
        "ledger_sequence": item.ledger_sequence,
        "correction": {
            "order_id": item.order_id,
            "execution_id": correction.execution_id,
            "correction_id": correction.correction_id,
            "revision": correction.revision,
            "revised_quantity": canonical_str(correction.revised_quantity),
            "revised_price": (
                canonical_str(correction.revised_price)
                if correction.revised_price is not None
                else None
            ),
            "revised_commission": canonical_str(correction.revised_commission),
            "occurred_at_utc": _utc_text(correction.occurred_at),
            "instrument_id": item.instrument_id,
            "side": item.side,
        },
    }


def _serialize_net_summary(
    groups: tuple[tuple[str, str, Decimal], ...],
) -> list[dict[str, str]]:
    if len(groups) > _MAX_NET_GROUPS:
        raise OMSValidationError("ACTIVITY_TOO_LARGE")
    return [
        {
            "venue": venue,
            "instrument_id": instrument_id,
            "quantity": canonical_str(quantity),
        }
        for venue, instrument_id, quantity in groups
    ]


def create_order_activity_router(*, enabled: bool = False) -> APIRouter:
    """Create a read-only activity router; mounting remains coordinator-owned."""
    if type(enabled) is not bool:
        raise ValueError("INVALID_CONFIGURATION")
    cursor_key = secrets.token_bytes(32)
    router = APIRouter(tags=["paper-order-activity"], route_class=_NoStoreRoute)

    @router.get("/orders/activity", response_model=None)
    async def read_order_activity(request: Request) -> JSONResponse:
        if not enabled:
            return _error(503, _ERROR_UNAVAILABLE)
        try:
            principal = require_trusted_principal(getattr(request.state, "trusted_principal", None))
        except AuthorizationModelError:
            return _error(401, _ERROR_PRINCIPAL)
        if principal.project_id != "leviathan-ai" or "operator" not in principal.roles:
            return _error(403, _ERROR_FORBIDDEN)
        query = _query(request)
        if query is None:
            return _error(400, _ERROR_QUERY)
        limit, cursor = query

        application_state = getattr(request.app.state, "leviathan", None)
        runtime = getattr(application_state, "orders", None)
        actor = getattr(runtime, "actor", None)
        if (
            runtime is None
            or getattr(runtime, "configured", False) is not True
            or type(actor) is not OrderGatewayActor
        ):
            return _error(503, _ERROR_UNAVAILABLE)
        try:
            venue = actor.venue
            if type(venue) is not VenueIdentityV1:
                return _error(503, _ERROR_UNAVAILABLE)
            venue.assert_sealed()
            if venue.environment is not BrokerEnvironment.PAPER:
                return _error(403, _ERROR_PAPER_SCOPE)
            if principal.venue is not None and principal.venue != venue.venue.value:
                return _error(403, _ERROR_FORBIDDEN)
            account_id = venue.account_id
            if _ID.fullmatch(account_id) is None:
                return _error(503, _ERROR_UNAVAILABLE)
        except Exception:
            return _error(503, _ERROR_UNAVAILABLE)

        scope = _scope_digest("paper", account_id)
        high_water: int | None = None
        last_sequence = 0
        if cursor is not None:
            decoded = _read_cursor(cursor, cursor_key, expected_scope=scope)
            if decoded is None:
                return _error(400, _ERROR_CURSOR)
            high_water, last_sequence = decoded

        try:
            page = await actor.read_activity_page(
                "paper",
                account_id,
                after_sequence=last_sequence,
                high_water_sequence=high_water,
                limit=limit,
            )
            captured = page.high_water_sequence
            if captured > _MAX_SAFE_JSON_INT:
                return _error(503, _ERROR_UNAVAILABLE)
            if high_water is not None and captured != high_water:
                return _error(400, _ERROR_CURSOR)
            if any(item.ledger_sequence > _MAX_SAFE_JSON_INT for item in page.items):
                return _error(503, _ERROR_UNAVAILABLE)
            selected = page.items[:limit]
            serialized: list[dict[str, object]] = []
            for item in selected:
                if isinstance(item, ActivityOrderItem):
                    serialized.append(
                        {
                            "kind": "ORDER",
                            "ledger_sequence": item.ledger_sequence,
                            "order": _serialize_order(item.snapshot, item.created_at),
                        }
                    )
                elif isinstance(item, ActivityFillItem):
                    serialized.append(_serialize_fill(item))
                elif isinstance(item, ActivityCorrectionItem):
                    serialized.append(_serialize_correction(item))
                else:
                    raise OMSLedgerCorruption()
            next_cursor = (
                _issue_cursor(
                    cursor_key,
                    scope=scope,
                    high_water=captured,
                    last_sequence=selected[-1].ledger_sequence,
                )
                if page.has_more and selected
                else None
            )
            return JSONResponse(
                status_code=200,
                content={
                    "schema_version": 1,
                    "evidence_label": "OMS ledger evidence",
                    "environment": "paper",
                    "account_id": account_id,
                "high_water_sequence": captured,
                    "items": serialized,
                    "net_filled_units": _serialize_net_summary(page.net_filled_units),
                    "next_cursor": next_cursor,
                },
            )
        except OMSValidationError as exc:
            if exc.code == "ACTIVITY_TOO_LARGE":
                return _error(413, "ACTIVITY_TOO_LARGE")
            return _error(503, _ERROR_UNAVAILABLE)
        except NumericError:
            return _error(503, _ERROR_UNAVAILABLE)
        except Exception:
            return _error(503, _ERROR_UNAVAILABLE)

    return router


__all__ = ["create_order_activity_router"]
