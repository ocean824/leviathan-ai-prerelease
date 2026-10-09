"""Injection-only, paper-scoped HTTP adapter for bounded mass cancellation.

This module deliberately does not mount its router. The host application must
choose whether and when to mount it after the coordinator integration gate.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Literal, NoReturn, Protocol, cast

from fastapi import APIRouter, HTTPException, Request

from leviathan_core.execution.broker_port_v1 import (
    AccountViewV1,
    BrokerEnvironment,
    BrokerOutcomeUnknown,
    VenueIdentityV1,
)
from leviathan_core.execution.cancel_coordinator import (
    CancelCoordinatorError,
)
from leviathan_core.execution.cancel_policy import (
    CancelPolicyCode,
    CancelPolicyError,
    CancelRequestV1,
    MassCancelRequestV1,
    MassCancelResultV1,
    issue_cancel_request,
    issue_mass_cancel_request,
    require_mass_cancel_result,
)
from leviathan_core.execution.order_models import BrokerObservation, OrderState
from leviathan_core.security.authz_models import (
    AuthorizationModelError,
    TrustedPrincipalV1,
    require_trusted_principal,
)

_MAX_BODY_BYTES = 128 * 1024
_MAX_BATCH_ORDERS = 100
_ROOT_FIELDS = frozenset(
    {
        "account_id",
        "venue",
        "scope",
        "idempotency_key",
        "expected_broker_revision",
        "start_index",
        "requests",
    }
)
_ITEM_FIELDS = frozenset(
    {
        "order_id",
        "client_order_id",
        "venue_order_id",
        "instrument_id",
        "strategy_id",
        "side",
        "idempotency_key",
        "protective_leg",
        "gtd_expiry_ns",
    }
)
_SCOPES = frozenset({"INSTRUMENT", "STRATEGY", "ACCOUNT"})
_IDENTIFIER_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:/+-"
)


class PaperMassCancelPort(Protocol):
    """Read-only paper snapshot and authoritative HALT state for this route."""

    @property
    def venue(self) -> VenueIdentityV1: ...

    def read_account_view(self, account_id: str) -> AccountViewV1: ...

    def halt_active(self, account_id: str) -> bool: ...


class MassCancelCoordinatorPort(Protocol):
    """Coordinator seam; production uses CancelCoordinator, tests use a fake."""

    async def mass_cancel(
        self, request: MassCancelRequestV1, *, halt_active: bool
    ) -> MassCancelResultV1: ...


def _deny(status: int, code: str) -> NoReturn:
    raise HTTPException(status_code=status, detail=code)


def _identifier(value: object) -> bool:
    return (
        type(value) is str
        and 1 <= len(value) <= 128
        and value.isascii()
        and value[0].isalnum()
        and all(character in _IDENTIFIER_CHARS for character in value)
    )


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _deny(422, "INVALID_MASS_CANCEL_REQUEST")
        result[key] = value
    return result


async def _read_body(request: Request) -> dict[str, object]:
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > _MAX_BODY_BYTES:
            _deny(413, "MASS_CANCEL_BODY_TOO_LARGE")
        body.extend(chunk)
    try:
        value = json.loads(bytes(body), object_pairs_hook=_unique_pairs)
    except HTTPException:
        raise
    except (UnicodeError, ValueError, RecursionError):
        _deny(422, "INVALID_MASS_CANCEL_REQUEST")
    if type(value) is not dict or set(value) != _ROOT_FIELDS:
        _deny(422, "INVALID_MASS_CANCEL_REQUEST")
    return cast(dict[str, object], value)


def _principal(request: Request) -> TrustedPrincipalV1:
    try:
        principal = require_trusted_principal(getattr(request.state, "trusted_principal", None))
    except AuthorizationModelError:
        _deny(401, "OPERATOR_REQUIRED")
    if "operator" not in principal.roles or principal.env != "paper" or principal.break_glass:
        _deny(401, "OPERATOR_REQUIRED")
    return principal


def _paper_identity(port: PaperMassCancelPort) -> VenueIdentityV1:
    try:
        identity = port.venue
        if type(identity) is not VenueIdentityV1:
            _deny(503, "PAPER_PORT_UNAVAILABLE")
        identity.assert_sealed()
    except HTTPException:
        raise
    except Exception:
        _deny(503, "PAPER_PORT_UNAVAILABLE")
    if identity.environment is not BrokerEnvironment.PAPER:
        _deny(403, "PAPER_SCOPE_REQUIRED")
    return identity


def _observed_ns(view: AccountViewV1) -> int | None:
    observed = view.broker_observed_at
    if type(observed) is not datetime or observed.tzinfo is not UTC:
        return None
    delta = observed - datetime(1970, 1, 1, tzinfo=UTC)
    return (
        delta.days * 86_400_000_000_000 + delta.seconds * 1_000_000_000 + delta.microseconds * 1_000
    )


def _fresh_view(
    port: PaperMassCancelPort,
    *,
    identity: VenueIdentityV1,
    account_id: str,
    venue: str,
    expected_revision: object,
    maximum_snapshot_age_ns: int,
    now_ns: Callable[[], int],
) -> AccountViewV1:
    if (
        account_id != identity.account_id
        or venue != identity.venue.value
        or type(expected_revision) is not int
        or expected_revision < 0
    ):
        _deny(403, "PAPER_SCOPE_MISMATCH")
    try:
        view = port.read_account_view(account_id)
        if type(view) is not AccountViewV1:
            _deny(503, "BROKER_OUTCOME_UNKNOWN")
        view.assert_sealed()
        current = now_ns()
    except HTTPException:
        raise
    except Exception:
        _deny(503, "BROKER_OUTCOME_UNKNOWN")
    observed_ns = _observed_ns(view)
    if (
        view.account_id != account_id
        or view.broker_revision != expected_revision
        or observed_ns is None
        or type(current) is not int
        or current < observed_ns
        or current - observed_ns > maximum_snapshot_age_ns
    ):
        _deny(409, "STALE_OR_MISMATCHED_ACCOUNT_VIEW")
    return view


def _validate_items(
    raw: object,
    *,
    account_id: str,
    venue: str,
    scope: str,
    operator_id: str,
    start_index: int,
    halt_active: bool,
    view: AccountViewV1,
) -> tuple[CancelRequestV1, ...]:
    if type(raw) is not list or not 1 <= len(raw) <= _MAX_BATCH_ORDERS:
        _deny(422, "MASS_CANCEL_BATCH_LIMIT")
    if type(start_index) is not int or not 0 <= start_index < len(raw):
        _deny(422, "INVALID_MASS_CANCEL_CURSOR")
    if scope not in _SCOPES:
        _deny(422, "INVALID_MASS_CANCEL_SCOPE")

    orders_by_client: dict[str, list[BrokerObservation]] = {}
    orders_by_native: dict[str, list[BrokerObservation]] = {}
    for observation in view.open_orders:
        orders_by_client.setdefault(observation.client_order_id, []).append(observation)
        if observation.venue_order_id is not None:
            orders_by_native.setdefault(observation.venue_order_id, []).append(observation)

    built: list[CancelRequestV1] = []
    seen_order_ids: set[str] = set()
    seen_native_ids: set[str] = set()
    seen_client_ids: set[str] = set()
    seen_idempotency: set[str] = set()
    for index, item in enumerate(raw):
        if type(item) is not dict or set(item) != _ITEM_FIELDS:
            _deny(422, "INVALID_MASS_CANCEL_REQUEST")
        if any(
            not _identifier(item.get(field))
            for field in (
                "order_id",
                "client_order_id",
                "venue_order_id",
                "instrument_id",
                "strategy_id",
                "idempotency_key",
            )
        ):
            _deny(422, "INVALID_MASS_CANCEL_REQUEST")
        if (
            item["order_id"] in seen_order_ids
            or item["client_order_id"] in seen_client_ids
            or item["idempotency_key"] in seen_idempotency
        ):
            _deny(422, "DUPLICATE_MASS_CANCEL_ORDER")
        if item["venue_order_id"] in seen_native_ids:
            _deny(422, "DUPLICATE_ORDER_ID")
        seen_order_ids.add(cast(str, item["order_id"]))
        seen_native_ids.add(cast(str, item["venue_order_id"]))
        seen_client_ids.add(cast(str, item["client_order_id"]))
        seen_idempotency.add(cast(str, item["idempotency_key"]))
        if type(item["side"]) is not str or item["side"] not in {"BUY", "SELL"}:
            _deny(422, "INVALID_MASS_CANCEL_REQUEST")
        if type(item["protective_leg"]) is not bool:
            _deny(422, "INVALID_MASS_CANCEL_REQUEST")
        expiry = item["gtd_expiry_ns"]
        if expiry is not None and (type(expiry) is not int or expiry < 0):
            _deny(422, "INVALID_MASS_CANCEL_REQUEST")

        first_item = raw[0]
        if type(first_item) is not dict:
            _deny(422, "INVALID_MASS_CANCEL_REQUEST")
        if (
            scope == "INSTRUMENT"
            and index
            and item["instrument_id"] != first_item.get("instrument_id")
        ):
            _deny(422, "MASS_CANCEL_SCOPE_MISMATCH")
        if scope == "STRATEGY" and index and item["strategy_id"] != first_item.get("strategy_id"):
            _deny(422, "MASS_CANCEL_SCOPE_MISMATCH")

        # A fresh broker view must prove every remaining target is still open
        # under the exact paper account, venue, and client/native order pair.
        if index >= start_index:
            matches = orders_by_client.get(cast(str, item["client_order_id"]), [])
            if len(matches) != 1:
                _deny(409, "ORDER_MISSING_OR_STALE")
            observed = matches[0]
            native_matches = orders_by_native.get(cast(str, item["venue_order_id"]), [])
            if (
                len(native_matches) != 1
                or native_matches[0].client_order_id != item["client_order_id"]
            ):
                _deny(422, "DUPLICATE_ORDER_ID")
            if (
                observed.venue_order_id != item["venue_order_id"]
                or observed.account_id != account_id
                or observed.venue != venue
                or observed.environment != "paper"
                or observed.status not in {OrderState.WORKING, OrderState.PARTIALLY_FILLED}
            ):
                _deny(409, "ORDER_MISSING_OR_STALE")

        try:
            built.append(
                issue_cancel_request(
                    CancelRequestV1(
                        order_id=cast(str, item["order_id"]),
                        client_order_id=cast(str, item["client_order_id"]),
                        venue_order_id=cast(str, item["venue_order_id"]),
                        account_id=account_id,
                        venue=venue,
                        environment="paper",
                        instrument_id=cast(str, item["instrument_id"]),
                        strategy_id=cast(str, item["strategy_id"]),
                        side=cast(Literal["BUY", "SELL"], item["side"]),
                        operator_id=operator_id,
                        idempotency_key=cast(str, item["idempotency_key"]),
                        scope=cast(Literal["ORDER", "INSTRUMENT", "STRATEGY", "ACCOUNT"], scope),
                        trigger="HALT" if halt_active else "OPERATOR",
                        protective_leg=item["protective_leg"],
                        gtd_expiry_ns=expiry,
                    )
                )
            )
        except (TypeError, ValueError):
            _deny(422, "INVALID_MASS_CANCEL_REQUEST")
    return tuple(built)


def _result_body(result: MassCancelResultV1) -> dict[str, object]:
    return {
        "request_idempotency_key": result.request_idempotency_key,
        "start_index": result.start_index,
        "next_index": result.next_index,
        "complete": result.complete,
        "results": [
            {
                "order_id": item.order_id,
                "idempotency_key": item.idempotency_key,
                "lifecycle_state": item.lifecycle_state,
                "oms_state": item.oms_state,
                "reason_code": item.reason_code,
                "child_dispatch_stopped": item.child_dispatch_stopped,
                "cancel_sent": item.cancel_sent,
                "reconciled": item.reconciled,
                "discrepancy_codes": list(item.discrepancy_codes),
                "operator_alert_codes": list(item.operator_alert_codes),
                "fill_execution_ids": list(item.fill_execution_ids),
            }
            for item in result.results
        ],
    }


def create_paper_mass_cancel_router(
    *,
    coordinator: MassCancelCoordinatorPort,
    paper_port: PaperMassCancelPort,
    maximum_snapshot_age_ns: int,
    now_ns: Callable[[], int] = lambda: time.time_ns(),
) -> APIRouter:
    """Build an unmounted router over a coordinator and explicit paper-only port."""

    if not callable(getattr(coordinator, "mass_cancel", None)):
        raise TypeError("CANCEL_COORDINATOR_REQUIRED")
    if (
        type(maximum_snapshot_age_ns) is not int
        or not 1 <= maximum_snapshot_age_ns <= 300_000_000_000
        or not callable(now_ns)
    ):
        raise ValueError("INVALID_PAPER_MASS_CANCEL_CONFIGURATION")
    _paper_identity(paper_port)
    router = APIRouter(tags=["paper-mass-cancel-v1"])

    @router.post("/paper/mass-cancel/v1")
    async def mass_cancel(request: Request) -> dict[str, object]:
        principal = _principal(request)
        identity = _paper_identity(paper_port)
        if principal.venue is not None and principal.venue != identity.venue.value:
            _deny(403, "PRINCIPAL_VENUE_MISMATCH")
        body = await _read_body(request)
        account_id = body["account_id"]
        venue = body["venue"]
        if not _identifier(account_id) or not _identifier(venue):
            _deny(422, "INVALID_PAPER_SCOPE")
        if type(body["scope"]) is not str or body["scope"] not in _SCOPES:
            _deny(422, "INVALID_MASS_CANCEL_SCOPE")
        if not _identifier(body["idempotency_key"]):
            _deny(422, "INVALID_MASS_CANCEL_REQUEST")
        if type(body["start_index"]) is not int:
            _deny(422, "INVALID_MASS_CANCEL_CURSOR")
        view = _fresh_view(
            paper_port,
            identity=identity,
            account_id=cast(str, account_id),
            venue=cast(str, venue),
            expected_revision=body["expected_broker_revision"],
            maximum_snapshot_age_ns=maximum_snapshot_age_ns,
            now_ns=now_ns,
        )
        try:
            halt_active = paper_port.halt_active(cast(str, account_id))
        except Exception:
            _deny(503, "HALT_STATE_UNKNOWN")
        if type(halt_active) is not bool:
            _deny(503, "HALT_STATE_UNKNOWN")
        requests = _validate_items(
            body["requests"],
            account_id=cast(str, account_id),
            venue=cast(str, venue),
            scope=cast(Literal["INSTRUMENT", "STRATEGY", "ACCOUNT"], body["scope"]),
            operator_id=principal.principal_id,
            start_index=body["start_index"],
            halt_active=halt_active,
            view=view,
        )
        try:
            mass_request = issue_mass_cancel_request(
                MassCancelRequestV1(
                    account_id=cast(str, account_id),
                    venue=cast(str, venue),
                    environment="paper",
                    operator_id=principal.principal_id,
                    idempotency_key=cast(str, body["idempotency_key"]),
                    scope=cast(Literal["INSTRUMENT", "STRATEGY", "ACCOUNT"], body["scope"]),
                    requests=requests,
                    start_index=body["start_index"],
                    halt_active=halt_active,
                )
            )
            result = await coordinator.mass_cancel(mass_request, halt_active=halt_active)
            result = require_mass_cancel_result(result)
        except CancelPolicyError as error:
            code = error.code
            status = (
                403
                if code
                in {
                    CancelPolicyCode.HALT_MASS_CANCEL_DENIED.value,
                    CancelPolicyCode.OPERATOR_NOT_ALLOWED.value,
                    CancelPolicyCode.SCOPE_NOT_ALLOWED.value,
                }
                else 422
            )
            _deny(status, code)
        except (BrokerOutcomeUnknown, CancelCoordinatorError):
            _deny(503, "MASS_CANCEL_OUTCOME_UNKNOWN")
        except HTTPException:
            raise
        except Exception:
            # The coordinator may have made partial progress before failing.
            # Never translate an exception into a successful all-canceled body.
            _deny(503, "MASS_CANCEL_OUTCOME_UNKNOWN")
        count = len(result.results)
        cursor = body["start_index"]
        next_index = cursor + count
        if (
            result.request_idempotency_key != body["idempotency_key"]
            or result.start_index != cursor
            or not 1 <= count <= min(len(requests) - cursor, _MAX_BATCH_ORDERS)
            or result.complete != (result.next_index is None)
            or (result.complete and next_index != len(requests))
            or (not result.complete and result.next_index != next_index)
            or tuple(item.order_id for item in result.results)
            != tuple(item.order_id for item in requests[cursor:next_index])
        ):
            _deny(503, "MASS_CANCEL_RESULT_INVALID")
        return _result_body(result)

    return router


__all__ = [
    "MassCancelCoordinatorPort",
    "PaperMassCancelPort",
    "create_paper_mass_cancel_router",
]
