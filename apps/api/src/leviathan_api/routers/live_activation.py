"""Default-OFF, account-scoped LIVE activation API.

This router issues only an account activation event. It does not place orders,
change risk policy, bypass order scope activation, or override HALT. The LIVE
order route remains denied until a separately reviewed OMS integration.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import re
import time
from collections.abc import Awaitable
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any, Literal, Protocol, TypeVar, cast

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from leviathan_store.live_activation import LiveActivationEventV1
from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictStr
from starlette.types import Message, Receive, Scope, Send

from leviathan_core.security.authz_models import (
    AuthorizationModelError,
    TrustedPrincipalV1,
    require_trusted_principal,
)
from leviathan_core.text.safe_label import is_safe_identifier

MFA_MAX_AGE_S = 300  # PROPOSED; owner is the security/MFA contract.
EVIDENCE_MAX_AGE_S = 60  # PROPOSED; owners are the risk/provider contracts.
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z", re.ASCII)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_MAX_BODY = 4096
_MAX_OPEN_ORDERS = 200
_NON_TERMINAL_ORDER_STATES = frozenset(
    {
        "CREATED",
        "RISK_PENDING",
        "READY",
        "SUBMITTING",
        "DISPATCH_IN_FLIGHT",
        "WORKING",
        "PARTIALLY_FILLED",
        "CANCEL_PENDING",
        "CANCEL_REQUESTED_UNCONFIRMED",
        "UNKNOWN_SUBMIT",
        "UNKNOWN_CANCEL",
        "RECONCILE_REQUIRED",
    }
)
_DECIMAL_QUANTITY = re.compile(r"(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:E[+-]?[0-9]+)?\Z", re.ASCII)
_NO_STORE = {"Cache-Control": "no-store"}


class LiveActivationEvidenceError(RuntimeError):
    """Content-free error for malformed or unavailable injected evidence."""

    def __init__(self, code: str = "EVIDENCE_UNAVAILABLE") -> None:
        self.code = code
        super().__init__(code)


class _StrictEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class LiveAccountEvidenceV1(_StrictEvidence):
    account_id: StrictStr
    organization_id: StrictStr
    device_id: StrictStr
    owner_principal_id: StrictStr
    environment: Literal["live"]
    binding_revision: StrictStr
    credential_revision: StrictStr

    @classmethod
    def model_validate(cls, obj: Any, *args: Any, **kwargs: Any) -> LiveAccountEvidenceV1:
        value = super().model_validate(obj, *args, **kwargs)
        if any(
            not _safe_identifier(getattr(value, name))
            for name in (
                "account_id",
                "organization_id",
                "device_id",
                "owner_principal_id",
                "binding_revision",
                "credential_revision",
            )
        ):
            raise ValueError("invalid account evidence")
        return value


class LiveEntitlementEvidenceV1(_StrictEvidence):
    entitlement_state: Literal["VERIFIED_ONLINE", "UNKNOWN", "GRACE_OFFLINE"]
    subscription_status: StrictStr
    live_trading: StrictBool
    live_account_limit: StrictInt | None = Field(ge=0)
    live_account_count: StrictInt = Field(ge=0)
    revision: StrictStr


class LiveMfaEvidenceV1(_StrictEvidence):
    verified_at_ns: StrictInt = Field(ge=0)
    server_verified: Literal[True]


class LiveBrokerVerificationV1(_StrictEvidence):
    binding_revision: StrictStr
    credential_revision: StrictStr
    provider_verified: StrictBool
    account_permissions_verified: StrictBool
    verified_at_ns: StrictInt = Field(ge=0)


class LiveRiskAcknowledgementV1(_StrictEvidence):
    risk_policy_sha256: StrictStr
    hard_limit_revision: StrictStr
    acknowledged_policy_sha256: StrictStr
    acknowledged_hard_limit_revision: StrictStr
    acknowledged_at_ns: StrictInt = Field(ge=0)

    @classmethod
    def model_validate(cls, obj: Any, *args: Any, **kwargs: Any) -> LiveRiskAcknowledgementV1:
        value = super().model_validate(obj, *args, **kwargs)
        if any(
            type(digest) is not str or _SHA256.fullmatch(digest) is None
            for digest in (value.risk_policy_sha256, value.acknowledged_policy_sha256)
        ):
            raise ValueError("invalid risk digest")
        if not _safe_identifier(value.hard_limit_revision) or not _safe_identifier(
            value.acknowledged_hard_limit_revision
        ):
            raise ValueError("invalid hard limit revision")
        return value


class LiveReadinessEvidenceV1(_StrictEvidence):
    recovery_status: StrictStr
    feed_verified_at_ns: StrictInt = Field(ge=0)
    account_evidence_at_ns: StrictInt = Field(ge=0)
    fault_code: StrictStr | None


class LiveOpenOrderV1(_StrictEvidence):
    """One read-only, account-scoped non-terminal LIVE order projection."""

    order_id: StrictStr
    instrument_id: StrictStr
    side: Literal["BUY", "SELL"]
    quantity: StrictStr = Field(max_length=128)
    status: StrictStr
    verified_at_ns: StrictInt = Field(ge=0)

    @classmethod
    def model_validate(cls, obj: Any, *args: Any, **kwargs: Any) -> LiveOpenOrderV1:
        value = super().model_validate(obj, *args, **kwargs)
        if not is_safe_identifier(value.order_id) or not is_safe_identifier(value.instrument_id):
            raise ValueError("invalid open order identifier")
        if value.status not in _NON_TERMINAL_ORDER_STATES:
            raise ValueError("order is not non-terminal")
        if type(value.quantity) is not str or _DECIMAL_QUANTITY.fullmatch(value.quantity) is None:
            raise ValueError("invalid order quantity")
        try:
            quantity = Decimal(value.quantity)
        except InvalidOperation as exc:
            raise ValueError("invalid order quantity") from exc
        if not quantity.is_finite() or quantity <= 0:
            raise ValueError("invalid order quantity")
        return value


class LiveAccountPortV1(Protocol):
    def read_account(
        self, principal: TrustedPrincipalV1, account_id: str
    ) -> LiveAccountEvidenceV1 | None: ...


class LiveEntitlementPortV1(Protocol):
    def read_entitlement(
        self, principal: TrustedPrincipalV1, account_id: str
    ) -> LiveEntitlementEvidenceV1 | None: ...


class LiveMfaPortV1(Protocol):
    def read_mfa(self, principal: TrustedPrincipalV1) -> LiveMfaEvidenceV1 | None: ...


class LiveBrokerVerificationPortV1(Protocol):
    def read_broker_verification(
        self, principal: TrustedPrincipalV1, account_id: str
    ) -> LiveBrokerVerificationV1 | None: ...


class LiveRiskAcknowledgementPortV1(Protocol):
    def read_risk_acknowledgement(
        self, principal: TrustedPrincipalV1, account_id: str
    ) -> LiveRiskAcknowledgementV1 | None: ...


class LiveReadinessPortV1(Protocol):
    def read_readiness(
        self, principal: TrustedPrincipalV1, account_id: str
    ) -> LiveReadinessEvidenceV1 | None: ...


class LiveHaltPortV1(Protocol):
    def is_halted(self, principal: TrustedPrincipalV1, account_id: str) -> bool: ...


class LiveOpenOrdersPortV1(Protocol):
    """Read a bounded LIVE-order snapshot scoped to the trusted principal/account."""

    def read_open_orders(
        self, principal: TrustedPrincipalV1, account_id: str
    ) -> tuple[LiveOpenOrderV1, ...] | None | Awaitable[tuple[LiveOpenOrderV1, ...] | None]: ...


@dataclass(frozen=True, slots=True)
class LiveActivationPortsV1:
    """Independent trusted server-side evidence ports; no request field supplies authority."""

    accounts: LiveAccountPortV1
    entitlements: LiveEntitlementPortV1
    mfa: LiveMfaPortV1
    broker: LiveBrokerVerificationPortV1
    risk: LiveRiskAcknowledgementPortV1
    readiness: LiveReadinessPortV1
    halt: LiveHaltPortV1
    open_orders: LiveOpenOrdersPortV1 | None = None


class LiveActivationStorePortV1(Protocol):
    async def append_events(self, events: tuple[LiveActivationEventV1, ...]) -> tuple[int, ...]: ...

    async def read_events(
        self, organization_id: str, account_id: str
    ) -> tuple[LiveActivationEventV1, ...]: ...


class LiveActivationGatePortV1(Protocol):
    def live_account_enabled(self, account_id: str) -> bool: ...

    def deactivate_account(self, organization_id: str, account_id: str) -> None: ...


class LiveActivationConfigV1(_StrictEvidence):
    mfa_max_age_s: StrictInt = Field(default=MFA_MAX_AGE_S, gt=0, le=3600)
    evidence_max_age_s: StrictInt = Field(default=EVIDENCE_MAX_AGE_S, gt=0, le=3600)
    threshold_status: Literal["PROPOSED"] = "PROPOSED"


@dataclass(slots=True)
class _RuntimeActivation:
    active: bool = False
    revision: int = 0
    activated_at_ns: int | None = None
    risk_policy_sha256: str | None = None
    binding_revision: str | None = None
    credential_revision: str | None = None
    entitlement_revision: str | None = None


def _json_error(status: int, code: str) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": {"code": code}}, headers=_NO_STORE)


def _trusted_principal(request: Request) -> TrustedPrincipalV1 | None:
    try:
        return require_trusted_principal(getattr(request.state, "trusted_principal", None))
    except AuthorizationModelError:
        return None


def _safe_identifier(value: object) -> bool:
    return type(value) is str and _IDENTIFIER.fullmatch(value) is not None


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    out: dict[str, object] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate key")
        out[key] = value
    return out


async def _strict_json(request: Request, expected: frozenset[str]) -> dict[str, object] | None:
    raw = bytearray()
    try:
        async for chunk in request.stream():
            if len(raw) + len(chunk) > _MAX_BODY:
                return None
            raw.extend(chunk)
        value = json.loads(bytes(raw), object_pairs_hook=_unique_pairs)
    except (ValueError, UnicodeError, RecursionError):
        return None
    if type(value) is not dict or set(value) != expected:
        return None
    return value


def _owner_account(
    ports: LiveActivationPortsV1,
    principal: TrustedPrincipalV1,
    account_id: str,
) -> LiveAccountEvidenceV1 | None:
    try:
        account = ports.accounts.read_account(principal, account_id)
    except Exception as exc:
        raise LiveActivationEvidenceError() from exc
    if type(account) is not LiveAccountEvidenceV1:
        return None
    account = _require_exact(account, LiveAccountEvidenceV1)
    if (
        account.account_id != account_id
        or account.environment != "live"
        or account.owner_principal_id != principal.principal_id
        or principal.device_id is None
        or account.device_id != principal.device_id
    ):
        return None
    return account


def _age_is_fresh(value_ns: int, now_ns: int, max_age_s: int) -> bool:
    return 0 <= now_ns - value_ns <= max_age_s * 1_000_000_000


_EvidenceT = TypeVar("_EvidenceT", bound=BaseModel)


def _require_exact(value: object, expected: type[_EvidenceT]) -> _EvidenceT:
    if type(value) is not expected:
        raise LiveActivationEvidenceError()
    try:
        # Revalidate a plain mapping so model_construct/copy mutations cannot bypass validation.
        return expected.model_validate(cast(BaseModel, value).model_dump(mode="python"))
    except (TypeError, ValueError):
        raise LiveActivationEvidenceError() from None


def _blockers(
    ports: LiveActivationPortsV1,
    principal: TrustedPrincipalV1,
    account: LiveAccountEvidenceV1,
    *,
    now_ns: int,
    config: LiveActivationConfigV1,
) -> tuple[tuple[str, ...], str | None, int | None, str | None]:
    blockers: list[str] = []
    try:
        halted = ports.halt.is_halted(principal, account.account_id)
    except Exception as exc:
        raise LiveActivationEvidenceError("HALT_STATUS_UNAVAILABLE") from exc
    if type(halted) is not bool:
        raise LiveActivationEvidenceError("HALT_STATUS_UNAVAILABLE")
    if halted:
        return ("HALT_ACTIVE",), None, None, None

    try:
        entitlement_raw = ports.entitlements.read_entitlement(principal, account.account_id)
        mfa_raw = ports.mfa.read_mfa(principal)
        broker_raw = ports.broker.read_broker_verification(principal, account.account_id)
        risk_raw = ports.risk.read_risk_acknowledgement(principal, account.account_id)
        readiness_raw = ports.readiness.read_readiness(principal, account.account_id)
    except Exception as exc:
        raise LiveActivationEvidenceError() from exc

    entitlement = _require_exact(entitlement_raw, LiveEntitlementEvidenceV1)
    mfa = _require_exact(mfa_raw, LiveMfaEvidenceV1)
    broker = _require_exact(broker_raw, LiveBrokerVerificationV1)
    risk = _require_exact(risk_raw, LiveRiskAcknowledgementV1)
    readiness = _require_exact(readiness_raw, LiveReadinessEvidenceV1)

    if entitlement.entitlement_state != "VERIFIED_ONLINE":
        blockers.append("ENTITLEMENT_UNVERIFIED")
    if entitlement.subscription_status != "ACTIVE":
        blockers.append("SUBSCRIPTION_INACTIVE")
    if entitlement.live_trading is not True:
        blockers.append("LIVE_FEATURE_NOT_ENTITLED")
    if (
        entitlement.live_account_limit is None
        or entitlement.live_account_limit < 1
        or entitlement.live_account_count >= entitlement.live_account_limit
    ):
        blockers.append("LIVE_ACCOUNT_LIMIT_REACHED")

    if mfa.server_verified is not True:
        blockers.append("MFA_UNVERIFIED")
    elif not _age_is_fresh(mfa.verified_at_ns, now_ns, config.mfa_max_age_s):
        blockers.append("MFA_STALE")

    if (
        broker.provider_verified is not True
        or broker.account_permissions_verified is not True
        or broker.binding_revision != account.binding_revision
        or broker.credential_revision != account.credential_revision
    ):
        blockers.append("BROKER_BINDING_UNVERIFIED")
    if not _age_is_fresh(broker.verified_at_ns, now_ns, config.evidence_max_age_s):
        blockers.append("BROKER_EVIDENCE_STALE")

    if (
        _SHA256.fullmatch(risk.risk_policy_sha256) is None
        or risk.acknowledged_policy_sha256 != risk.risk_policy_sha256
        or risk.acknowledged_hard_limit_revision != risk.hard_limit_revision
    ):
        blockers.append("RISK_ACK_MISMATCH")
    if not _age_is_fresh(risk.acknowledged_at_ns, now_ns, config.evidence_max_age_s):
        blockers.append("RISK_ACK_STALE")

    if readiness.recovery_status != "READY":
        blockers.append("RECOVERY_NOT_READY")
    if readiness.fault_code is not None:
        blockers.append("FAULT_ACTIVE")
    if not _age_is_fresh(readiness.feed_verified_at_ns, now_ns, config.evidence_max_age_s):
        blockers.append("FEED_EVIDENCE_STALE")
    if not _age_is_fresh(readiness.account_evidence_at_ns, now_ns, config.evidence_max_age_s):
        blockers.append("ACCOUNT_EVIDENCE_STALE")

    verified_at = min(
        broker.verified_at_ns,
        risk.acknowledged_at_ns,
        readiness.feed_verified_at_ns,
        readiness.account_evidence_at_ns,
    )
    return (
        tuple(dict.fromkeys(blockers)),
        risk.risk_policy_sha256,
        verified_at,
        entitlement.revision,
    )


def _event(
    event_type: str,
    *,
    account: LiveAccountEvidenceV1,
    principal: TrustedPrincipalV1,
    revision: int,
    now_ns: int,
    entitlement_revision: str | None = None,
    risk_policy_sha256: str | None = None,
    reason_code: str | None = None,
) -> LiveActivationEventV1:
    return LiveActivationEventV1(
        event_type=event_type,
        organization_id=account.organization_id,
        account_id=account.account_id,
        actor_id=principal.principal_id,
        revision=revision,
        occurred_at_ns=now_ns,
        entitlement_revision=entitlement_revision,
        credential_binding_revision=account.binding_revision,
        risk_policy_sha256=risk_policy_sha256,
        reason_code=reason_code,
    )


class _NoStoreRoute(APIRoute):
    async def handle(self, scope: Scope, receive: Receive, send: Send) -> None:
        async def send_no_store(message: Message) -> None:
            if message.get("type") == "http.response.start":
                headers = [
                    (name, value)
                    for name, value in message.get("headers", [])
                    if name.lower() != b"cache-control"
                ]
                headers.append((b"cache-control", b"no-store"))
                message = {**message, "headers": headers}
            await send(message)

        if self.methods and scope["method"] not in self.methods:
            response = JSONResponse(
                status_code=405,
                content={"error": {"code": "METHOD_NOT_ALLOWED"}},
                headers={"Allow": ", ".join(sorted(self.methods)), **_NO_STORE},
            )
            await response(scope, receive, send_no_store)
            return
        await super().handle(scope, receive, send_no_store)


def create_live_activation_router(
    *,
    enabled: bool = False,
    store: LiveActivationStorePortV1 | None = None,
    ports: LiveActivationPortsV1 | None = None,
    config: LiveActivationConfigV1 | None = None,
    live_gate: LiveActivationGatePortV1 | None = None,
    clock_ns: Any = time.time_ns,
) -> APIRouter:
    """Build isolated routes. Disabled/portless routers return a fixed 503."""
    router = APIRouter(
        prefix="/live-activation", tags=["live-activation"], route_class=_NoStoreRoute
    )
    runtime: dict[tuple[str, str], _RuntimeActivation] = {}
    locks: dict[tuple[str, str], asyncio.Lock] = {}
    config_value = config if type(config) is LiveActivationConfigV1 else LiveActivationConfigV1()

    def available() -> bool:
        return enabled is True and store is not None and ports is not None

    def lock_for(key: tuple[str, str]) -> asyncio.Lock:
        return locks.setdefault(key, asyncio.Lock())

    def deactivate_gate(organization_id: str, account_id: str) -> None:
        if live_gate is None:
            return
        try:
            deactivate = getattr(live_gate, "deactivate_account", None)
            if callable(deactivate):
                deactivate(organization_id, account_id)
        except Exception:
            # Router state is already fail-closed; gate errors must not expose details.
            return

    async def events_for(account: LiveAccountEvidenceV1) -> tuple[LiveActivationEventV1, ...]:
        assert store is not None
        return await store.read_events(account.organization_id, account.account_id)

    def status_payload(
        account_id: str | None,
        state: _RuntimeActivation | None,
        blockers: tuple[str, ...],
        *,
        verified_at_ns: int | None = None,
        open_orders: tuple[LiveOpenOrderV1, ...] | None = None,
    ) -> dict[str, object]:
        is_live = state is not None and state.active and not blockers
        evidence_verified = account_id is not None and not blockers
        payload: dict[str, object] = {
            "effective_state": "LIVE" if is_live else "OFF",
            "verified": evidence_verified,
            "preconditions_verified": evidence_verified,
            "account_id": account_id,
            "activation_revision": state.revision if state else 0,
            "activated_at_ns": state.activated_at_ns if is_live and state else None,
            "last_verified_at_ns": verified_at_ns if evidence_verified else None,
            "risk_policy_sha256": state.risk_policy_sha256 if is_live and state else None,
            "blockers": list(blockers),
            "startup_state": "OFF",
            "open_orders_state": "VERIFIED" if open_orders is not None else "UNAVAILABLE",
        }
        if open_orders is not None:
            payload["open_orders"] = [row.model_dump(mode="json") for row in open_orders]
        return payload

    async def read_open_orders(
        principal: TrustedPrincipalV1, account_id: str, now_ns: int, max_age_s: int
    ) -> tuple[LiveOpenOrderV1, ...] | None:
        assert ports is not None
        try:
            if ports.open_orders is None:
                return None
            rows = ports.open_orders.read_open_orders(principal, account_id)
            if inspect.isawaitable(rows):
                rows = await rows
            if type(rows) is not tuple or len(rows) > _MAX_OPEN_ORDERS:
                return None
            validated: list[LiveOpenOrderV1] = []
            seen_ids: set[str] = set()
            for row in rows:
                checked = _require_exact(row, LiveOpenOrderV1)
                if checked.order_id in seen_ids:
                    return None
                if not _age_is_fresh(checked.verified_at_ns, now_ns, max_age_s):
                    return None
                seen_ids.add(checked.order_id)
                validated.append(checked)
            return tuple(validated)
        except Exception:
            return None

    async def validate_account(
        request: Request, account_id: str
    ) -> tuple[TrustedPrincipalV1 | None, LiveAccountEvidenceV1 | None, JSONResponse | None]:
        principal = _trusted_principal(request)
        if principal is None:
            return None, None, _json_error(401, "AUTH_REQUIRED")
        if not _safe_identifier(account_id):
            return principal, None, _json_error(422, "INVALID_ACCOUNT_ID")
        assert ports is not None
        try:
            account = _owner_account(ports, principal, account_id)
        except LiveActivationEvidenceError:
            return principal, None, _json_error(503, "ACCOUNT_EVIDENCE_UNAVAILABLE")
        if account is None:
            return principal, None, _json_error(404, "ACCOUNT_NOT_FOUND")
        return principal, account, None

    async def evaluate(
        principal: TrustedPrincipalV1, account: LiveAccountEvidenceV1
    ) -> tuple[tuple[str, ...], str | None, int | None, str | None] | JSONResponse:
        assert ports is not None
        try:
            return _blockers(ports, principal, account, now_ns=int(clock_ns()), config=config_value)
        except LiveActivationEvidenceError as exc:
            code = exc.code if exc.code in {"HALT_STATUS_UNAVAILABLE"} else "EVIDENCE_UNAVAILABLE"
            return _json_error(503, code)
        except Exception:
            return _json_error(503, "EVIDENCE_UNAVAILABLE")

    @router.get("/status", response_model=None)
    async def get_live_activation_status(request: Request) -> JSONResponse:
        if not available():
            return _json_error(503, "FEATURE_UNAVAILABLE")
        if (
            set(request.query_params.keys()) - {"account_id"}
            or len(request.query_params.getlist("account_id")) > 1
        ):
            return _json_error(400, "INVALID_QUERY")
        account_id = request.query_params.get("account_id")
        principal = _trusted_principal(request)
        if principal is None:
            return _json_error(401, "AUTH_REQUIRED")
        if account_id is None:
            return JSONResponse(
                status_code=200,
                content=status_payload(None, None, ("ACCOUNT_NOT_SELECTED",)),
                headers=_NO_STORE,
            )
        principal, account, error = await validate_account(request, account_id)
        if error is not None:
            return error
        assert principal is not None and account is not None
        key = (account.organization_id, account.account_id)
        current = runtime.setdefault(key, _RuntimeActivation())
        checked = await evaluate(principal, account)
        if isinstance(checked, JSONResponse):
            current.active = False
            deactivate_gate(account.organization_id, account.account_id)
            return checked
        blockers, digest, verified_at, entitlement_revision = checked
        if current.active and live_gate is not None:
            try:
                gate_enabled = live_gate.live_account_enabled(account.account_id) is True
            except Exception:
                gate_enabled = False
            if not gate_enabled and not blockers:
                # A synchronous order-gate check may have latched this snapshot
                # off since the previous status request. Persist that fail-closed
                # transition instead of reporting stale LIVE state.
                blockers = ("EVIDENCE_UNAVAILABLE",)
        if current.active and not blockers:
            changed_reason: str | None = None
            if (
                current.binding_revision != account.binding_revision
                or current.credential_revision != account.credential_revision
            ):
                changed_reason = "ACCOUNT_BINDING_CHANGED"
            elif current.entitlement_revision != entitlement_revision:
                changed_reason = "ENTITLEMENT_CHANGED"
            elif current.risk_policy_sha256 != digest:
                changed_reason = "RISK_POLICY_CHANGED"
            if changed_reason is not None:
                blockers = (changed_reason,)
        if current.active and blockers:
            current.active = False
            deactivate_gate(account.organization_id, account.account_id)
            try:
                assert store is not None
                prior = await events_for(account)
                rev = (prior[-1].revision if prior else 0) + 1
                await store.append_events(
                    (
                        _event(
                            "INVALIDATED",
                            account=account,
                            principal=principal,
                            revision=rev,
                            now_ns=int(clock_ns()),
                            risk_policy_sha256=digest,
                            reason_code=blockers[0],
                        ),
                    )
                )
                current.revision = rev
            except Exception:
                deactivate_gate(account.organization_id, account.account_id)
                return _json_error(503, "STORE_UNAVAILABLE")
        if current.active:
            current.risk_policy_sha256 = digest
        return JSONResponse(
            status_code=200,
            content=status_payload(
                account.account_id,
                current,
                blockers,
                verified_at_ns=verified_at,
                open_orders=await read_open_orders(
                    principal, account.account_id, int(clock_ns()), config_value.evidence_max_age_s
                ),
            ),
            headers=_NO_STORE,
        )

    @router.post("/enable", response_model=None)
    async def enable_live_activation(request: Request) -> JSONResponse:
        if not available():
            return _json_error(503, "FEATURE_UNAVAILABLE")
        body = await _strict_json(request, frozenset({"account_id", "confirmation"}))
        if body is None or not _safe_identifier(body.get("account_id")):
            return _json_error(422, "INVALID_REQUEST")
        account_id = str(body["account_id"])
        if body.get("confirmation") != f"ENABLE LIVE {account_id}":
            return _json_error(422, "CONFIRMATION_REQUIRED")
        principal, account, error = await validate_account(request, account_id)
        if error is not None:
            return error
        assert (
            principal is not None
            and account is not None
            and ports is not None
            and store is not None
        )
        key = (account.organization_id, account.account_id)
        async with lock_for(key):
            checked = await evaluate(principal, account)
            if isinstance(checked, JSONResponse):
                return checked
            blockers, digest, _verified_at, _entitlement_revision = checked
            if blockers:
                try:
                    previous = await events_for(account)
                    await store.append_events(
                        (
                            _event(
                                "ACTIVATION_REQUESTED",
                                account=account,
                                principal=principal,
                                revision=(previous[-1].revision if previous else 0) + 1,
                                now_ns=int(clock_ns()),
                                reason_code=blockers[0],
                            ),
                        )
                    )
                except Exception:
                    return _json_error(503, "STORE_UNAVAILABLE")
                status = 403 if blockers[0] == "HALT_ACTIVE" else 409
                return _json_error(status, blockers[0])
            try:
                previous = await events_for(account)
                revision = previous[-1].revision if previous else 0
                fresh_account = _owner_account(ports, principal, account_id)
                if fresh_account != account:
                    await store.append_events(
                        (
                            _event(
                                "ACTIVATION_REQUESTED",
                                account=account,
                                principal=principal,
                                revision=revision + 1,
                                now_ns=int(clock_ns()),
                                reason_code="ACCOUNT_BINDING_CHANGED",
                            ),
                        )
                    )
                    return _json_error(409, "ACCOUNT_BINDING_CHANGED")
                checked = await evaluate(principal, fresh_account)
                if isinstance(checked, JSONResponse):
                    return checked
                blockers, digest, _verified_at, entitlement_revision = checked
                if blockers:
                    await store.append_events(
                        (
                            _event(
                                "ACTIVATION_REQUESTED",
                                account=fresh_account,
                                principal=principal,
                                revision=revision + 1,
                                now_ns=int(clock_ns()),
                                reason_code=blockers[0],
                            ),
                        )
                    )
                    status = 403 if blockers[0] == "HALT_ACTIVE" else 409
                    return _json_error(status, blockers[0])
                entitlement = _require_exact(
                    ports.entitlements.read_entitlement(principal, account_id),
                    LiveEntitlementEvidenceV1,
                )
                entitlement_revision = entitlement.revision
                account = fresh_account
                now = int(clock_ns())
                append = (
                    _event(
                        "ACTIVATION_REQUESTED",
                        account=account,
                        principal=principal,
                        revision=revision + 1,
                        now_ns=now,
                        entitlement_revision=entitlement_revision,
                        risk_policy_sha256=digest,
                    ),
                    _event(
                        "ENABLED",
                        account=account,
                        principal=principal,
                        revision=revision + 2,
                        now_ns=now,
                        entitlement_revision=entitlement_revision,
                        risk_policy_sha256=digest,
                    ),
                )
                await store.append_events(append)
                # Recheck HALT after the durable write; a concurrent HALT wins.
                if ports.halt.is_halted(principal, account_id) is not False:
                    await store.append_events(
                        (
                            _event(
                                "INVALIDATED",
                                account=account,
                                principal=principal,
                                revision=revision + 3,
                                now_ns=int(clock_ns()),
                                risk_policy_sha256=digest,
                                reason_code="HALT_ACTIVE",
                            ),
                        )
                    )
                    return _json_error(409, "HALT_ACTIVE")
            except Exception:
                deactivate_gate(account.organization_id, account.account_id)
                return _json_error(503, "STORE_UNAVAILABLE")
            current = runtime.setdefault(key, _RuntimeActivation())
            current.active = True
            current.revision = revision + 2
            current.activated_at_ns = now
            current.risk_policy_sha256 = digest
            current.binding_revision = account.binding_revision
            current.credential_revision = account.credential_revision
            current.entitlement_revision = entitlement_revision
            return JSONResponse(
                status_code=200,
                content={
                    "accepted": True,
                    "effective_state": "LIVE",
                    "activation_revision": current.revision,
                },
                headers=_NO_STORE,
            )

    @router.post("/disable", response_model=None)
    async def disable_live_activation(request: Request) -> JSONResponse:
        if not available():
            return _json_error(503, "FEATURE_UNAVAILABLE")
        body = await _strict_json(request, frozenset({"account_id"}))
        if body is None or not _safe_identifier(body.get("account_id")):
            return _json_error(422, "INVALID_REQUEST")
        principal, account, error = await validate_account(request, str(body["account_id"]))
        if error is not None:
            return error
        assert principal is not None and account is not None and store is not None
        key = (account.organization_id, account.account_id)
        async with lock_for(key):
            current = runtime.setdefault(key, _RuntimeActivation())
            # Fail closed before waiting on durable I/O: OFF blocks this process immediately.
            current.active = False
            deactivate_gate(account.organization_id, account.account_id)
            try:
                previous = await events_for(account)
                revision = previous[-1].revision if previous else 0
                await store.append_events(
                    (
                        _event(
                            "DISABLED",
                            account=account,
                            principal=principal,
                            revision=revision + 1,
                            now_ns=int(clock_ns()),
                            reason_code="ACCOUNT_HOLDER_REQUESTED_OFF",
                        ),
                    )
                )
                current.revision = revision + 1
                current.activated_at_ns = None
                current.risk_policy_sha256 = None
                current.binding_revision = None
                current.credential_revision = None
                current.entitlement_revision = None
            except Exception:
                return _json_error(503, "STORE_UNAVAILABLE")
            return JSONResponse(
                status_code=200,
                content={
                    "accepted": True,
                    "effective_state": "OFF",
                    "activation_revision": current.revision,
                },
                headers=_NO_STORE,
            )

    return router


__all__ = [
    "EVIDENCE_MAX_AGE_S",
    "MFA_MAX_AGE_S",
    "LiveAccountEvidenceV1",
    "LiveActivationConfigV1",
    "LiveActivationEvidenceError",
    "LiveActivationPortsV1",
    "LiveBrokerVerificationV1",
    "LiveEntitlementEvidenceV1",
    "LiveMfaEvidenceV1",
    "LiveOpenOrderV1",
    "LiveOpenOrdersPortV1",
    "LiveReadinessEvidenceV1",
    "LiveRiskAcknowledgementV1",
    "create_live_activation_router",
]
