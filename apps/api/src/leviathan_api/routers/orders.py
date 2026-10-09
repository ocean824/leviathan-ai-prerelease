"""Default-deny paper OMS HTTP boundary. No provider or credential access."""

from __future__ import annotations

import inspect
import json
import math
import threading
from collections.abc import Awaitable, Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Literal, NoReturn, cast

from fastapi import APIRouter, HTTPException, Request

from leviathan_core.execution.broker_port_v1 import BrokerEnvironment, VenueIdentityV1
from leviathan_core.execution.live_gate import DeniedLiveGateV1, LiveActivationGatePortV1
from leviathan_core.execution.oms import DispatchGateCode, OrderGatewayActor
from leviathan_core.execution.order_models import (
    OMSConflict,
    OMSError,
    OrderRequest,
    OrderSnapshot,
    OrderState,
    PaperDispatchEvidence,
    parse_oms_decimal,
)
from leviathan_core.risk.halt import HaltAuthority
from leviathan_vault.client import VaultStatus
from leviathan_vault.trading_bindings import (
    BindingRequestV1,
    TradingAccountBindingV1,
    TradingBindingError,
    validate_binding,
    validate_binding_set,
)

if TYPE_CHECKING:
    from leviathan_api.state import AppState

router = APIRouter(prefix="/orders", tags=["orders"])
_Scope = tuple[str, str, str, str, str]
_UNKNOWN = frozenset(
    {
        OrderState.UNKNOWN_SUBMIT,
        OrderState.UNKNOWN_CANCEL,
        OrderState.RECONCILE_REQUIRED,
    }
)
_CREATE_FIELDS = frozenset(
    {
        "environment",
        "account_id",
        "venue",
        "instrument_id",
        "native_contract_id",
        "side",
        "quantity",
        "order_type",
        "time_in_force",
        "intent_idempotency_key",
        "attempt",
        "strategy_id",
        "risk_policy_digest",
        "limit_price",
        "expires_at",
    }
)
_CREATE_REQUIRED = _CREATE_FIELDS - {"limit_price", "expires_at"}
_SCOPE_FIELDS = frozenset(
    {
        "environment",
        "account_id",
        "venue",
        "instrument_id",
        "strategy_id",
    }
)
_MAX_BODY = 8192


@dataclass(frozen=True, slots=True)
class LiveSubmitCandidateV1:
    """Validated scope presented to the live predicate before request creation."""

    account_id: str
    venue: str
    instrument_id: str
    strategy_id: str
    environment: Literal["live"] = "live"

    def __post_init__(self) -> None:
        _scope(
            self.environment,
            self.account_id,
            self.venue,
            self.instrument_id,
            self.strategy_id,
            allow_live=True,
        )


def _deny(status: int, code: str) -> NoReturn:
    raise HTTPException(status_code=status, detail=code)


def _scope(
    environment: object,
    account: object,
    venue: object,
    instrument: object,
    strategy: object,
    *,
    allow_live: bool = False,
) -> _Scope:
    if type(environment) is str and environment.lower() == "live" and not allow_live:
        _deny(403, "LIVE_DISABLED")
    if type(environment) is not str:
        _deny(422, "INVALID_ENVIRONMENT")
    if environment not in (("paper", "demo", "live") if allow_live else ("paper", "demo")):
        _deny(422, "INVALID_ENVIRONMENT")
    values = (account, venue, instrument, strategy)
    if any(
        type(value) is not str or not value or len(value) > 128 or not value.isascii()
        for value in values
    ):
        _deny(422, "INVALID_ORDER_SCOPE")
    return cast(_Scope, (environment, account, venue, instrument, strategy))


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _deny(422, "INVALID_ORDER_REQUEST")
        result[key] = value
    return result


async def _json_body(
    request: Request,
    allowed: frozenset[str],
    required: frozenset[str],
) -> dict[str, object]:
    raw = bytearray()
    async for chunk in request.stream():
        if len(raw) + len(chunk) > _MAX_BODY:
            _deny(413, "ORDER_BODY_TOO_LARGE")
        raw.extend(chunk)
    try:
        value = json.loads(bytes(raw), object_pairs_hook=_unique_pairs)
    except (UnicodeError, ValueError, RecursionError):
        _deny(422, "INVALID_ORDER_REQUEST")
    if type(value) is not dict:
        _deny(422, "INVALID_ORDER_REQUEST")
    if set(value) - allowed or required - set(value):
        _deny(422, "INVALID_ORDER_REQUEST")
    return cast(dict[str, object], value)


async def _empty_body(request: Request) -> None:
    raw = bytearray()
    async for chunk in request.stream():
        if len(raw) + len(chunk) > _MAX_BODY:
            _deny(413, "ORDER_BODY_TOO_LARGE")
        raw.extend(chunk)
    if not raw:
        return
    try:
        value = json.loads(bytes(raw), object_pairs_hook=_unique_pairs)
    except (UnicodeError, ValueError, RecursionError):
        _deny(422, "INVALID_ORDER_REQUEST")
    if type(value) is not dict or value:
        _deny(422, "INVALID_ORDER_REQUEST")


def _snapshot(snapshot: OrderSnapshot) -> dict[str, object]:
    return {
        "order_id": snapshot.order_id,
        "state": snapshot.state.value,
        "version": snapshot.version,
        "environment": snapshot.request.environment,
        "account_id": snapshot.request.account_id,
        "venue": snapshot.request.venue,
        "instrument_id": snapshot.request.instrument_id,
        "strategy_id": snapshot.request.strategy_id,
        "filled_quantity": str(snapshot.filled_quantity),
        "venue_order_id": snapshot.venue_order_id,
        "discrepancies": list(snapshot.discrepancies),
        "submit_attempted": snapshot.submit_attempted,
        "cancel_attempted": snapshot.cancel_attempted,
    }


class _DispatchFence:
    """One startup-owned fence shared by dispatch and every HALT engager."""

    def __init__(self, timeout_seconds: float) -> None:
        if type(timeout_seconds) not in (int, float) or timeout_seconds <= 0:
            raise ValueError("INVALID_DISPATCH_FENCE_TIMEOUT")
        try:
            normalized_timeout = float(timeout_seconds)
        except (OverflowError, ValueError):
            raise ValueError("INVALID_DISPATCH_FENCE_TIMEOUT") from None
        if not math.isfinite(normalized_timeout):
            raise ValueError("INVALID_DISPATCH_FENCE_TIMEOUT")
        self._timeout_seconds = normalized_timeout
        self._lock = threading.Lock()
        self._bound_halt_authority: HaltAuthority | None = None

    def bind(self, halts: HaltAuthority) -> None:
        if self._bound_halt_authority is not None:
            raise RuntimeError("DISPATCH_FENCE_ALREADY_BOUND")
        halts.bind_engage_fence(self.halt_engage)
        self._bound_halt_authority = halts

    def acquire(self) -> None:
        if not self._lock.acquire(timeout=self._timeout_seconds):
            raise TimeoutError("DISPATCH_FENCE_UNAVAILABLE")

    def release(self) -> None:
        self._lock.release()

    @contextmanager
    def halt_engage(self) -> Iterator[bool]:
        acquired = self._lock.acquire(timeout=self._timeout_seconds)
        try:
            # HALT commits even after a timeout. The actor's generation check
            # then turns any concurrent transport into visible compensation.
            yield acquired
        finally:
            if acquired:
                self._lock.release()


class OrderRuntime:
    """Startup-injected fake-only actor and trusted, nonsecret paper ports."""

    def __init__(
        self,
        *,
        actor: OrderGatewayActor,
        bindings: tuple[TradingAccountBindingV1, ...],
        credential_statuses: Mapping[str, VaultStatus],
        native_contracts: Mapping[tuple[str, str], str],
        operator_authorizer: Callable[[Request], bool],
        evidence_source: Callable[
            [OrderSnapshot], PaperDispatchEvidence | Awaitable[PaperDispatchEvidence]
        ],
        dispatch_gate: PaperDispatchGate | None = None,
        live_gate: LiveActivationGatePortV1 | None = None,
        binding_source: Callable[[_Scope], TradingAccountBindingV1 | None] | None = None,
        dispatch_fence_timeout: float = 2.0,
    ) -> None:
        self.actor = actor
        self.bindings = bindings
        self.credential_statuses = credential_statuses
        self.native_contracts = native_contracts
        self.operator_authorizer = operator_authorizer
        self.evidence_source = evidence_source
        self.live_gate = DeniedLiveGateV1() if live_gate is None else live_gate
        self.binding_source = binding_source
        self.dispatch_fence = _DispatchFence(dispatch_fence_timeout)
        self.recovery_status = "UNKNOWN"
        self.activations: set[_Scope] = set()
        self.activation_generation: int | None = None
        self.halt_authority: HaltAuthority | None = None
        self.bound_dispatch_gate: PaperDispatchGate | None = None
        self.dispatch_gate_binding_valid = False
        if dispatch_gate is not None:
            dispatch_gate.bind_runtime(self)

    @property
    def configured(self) -> bool:
        if (
            type(self.actor) is not OrderGatewayActor
            or not self.dispatch_gate_binding_valid
            or self.halt_authority is None
            or self.actor.dispatch_gate is not self.bound_dispatch_gate
            or type(self.bindings) is not tuple
            or not self.bindings
            or not isinstance(self.credential_statuses, Mapping)
            or not isinstance(self.native_contracts, Mapping)
            or not self.native_contracts
            or not callable(self.operator_authorizer)
            or not callable(self.evidence_source)
        ):
            return False
        try:
            validate_binding_set(self.bindings)
        except Exception:
            return False
        # The adopted actor exposes the broker's sealed venue identity.
        try:
            venue = self.actor.venue
            if type(venue) is not VenueIdentityV1:
                return False
            venue.assert_sealed()
            if venue.environment not in {BrokerEnvironment.PAPER, BrokerEnvironment.DEMO}:
                return False
            if any(
                binding.account_ref != venue.account_id
                or binding.session_mode != venue.environment.value.lower()
                for binding in self.bindings
            ):
                return False
        except Exception:
            return False
        return len({item.account_ref for item in self.bindings}) == len(self.bindings) and all(
            binding.environment == "development" and binding.session_mode in {"paper", "demo"}
            for binding in self.bindings
        )

    def suspend(self) -> None:
        self.activations.clear()
        self.activation_generation = None
        self.recovery_status = "FAILED"

    def invalidate_stale_activation(self) -> bool:
        """Clear activations after any committed HALT mutation."""
        authority = self.halt_authority
        if authority is None or self.activation_generation is None:
            return False
        try:
            current = authority.generation
        except Exception:
            self.suspend()
            return True
        if current != self.activation_generation:
            self.suspend()
            return True
        return False

    def operator(self, request: Request) -> None:
        try:
            authorized = self.operator_authorizer(request)
        except Exception:
            authorized = False
        if type(authorized) is not bool or not authorized:
            _deny(403, "OPERATOR_REQUIRED")

    def binding_for(self, scope: _Scope) -> TradingAccountBindingV1:
        if scope[0] == "live":
            return self.authorize_live_binding(scope)
        return self._verified_binding_for(scope)

    def authorize_live_binding(self, scope: _Scope) -> TradingAccountBindingV1:
        """Require the per-account live gate before validating its exact binding."""
        if scope[0] != "live" or not self.live_account_enabled(scope[1]):
            _deny(403, "ACTIVATION_DENIED")
        if self.recovery_status != "READY":
            _deny(403, "ACTIVATION_DENIED")
        return self._verified_binding_for(scope)

    def _verified_binding_for(self, scope: _Scope) -> TradingAccountBindingV1:
        environment, account, venue, instrument, strategy = scope
        if environment == "live":
            try:
                binding = None if self.binding_source is None else self.binding_source(scope)
            except Exception:
                _deny(403, "ACTIVATION_DENIED")
            if type(binding) is not TradingAccountBindingV1:
                _deny(403, "ACTIVATION_DENIED")
        else:
            matches = [
                item
                for item in self.bindings
                if item.account_ref == account and item.session_mode == environment
            ]
            if len(matches) != 1:
                _deny(403, "ACTIVATION_DENIED")
            binding = matches[0]
        expected_binding_environment = "live" if environment == "live" else "development"
        if binding.environment != expected_binding_environment:
            _deny(403, "LIVE_DISABLED" if environment == "live" else "ACTIVATION_DENIED")
        try:
            validate_binding(
                binding,
                BindingRequestV1(
                    environment=expected_binding_environment,
                    broker=binding.broker,
                    account_ref=account,
                    session_ref=binding.session_ref,
                    venue=venue,
                    instrument=instrument,
                    instrument_mapping_revision=binding.instrument_mapping_revision,
                    strategy_id=strategy,
                    hard_risk_limit_revision=binding.hard_risk_limit_revision,
                    session_mode=environment,
                    binding_revision=binding.binding_revision,
                    credential_revision=binding.credential_revision,
                    checked_at=datetime.now(UTC),
                ),
                credential_status=(
                    None
                    if binding.credential_ref is None
                    else self.credential_statuses.get(binding.credential_ref)
                ),
            )
        except TradingBindingError:
            _deny(403, "CREDENTIAL_BINDING_DENIED")
        return binding

    @property
    def live_enabled(self) -> bool:
        """Keep the desktop update-readiness signal false until LIVE-WIRE-002."""
        return False

    def live_account_enabled(self, account_id: str) -> bool:
        """Read the startup-injected per-account gate; malformed results fail closed."""
        try:
            enabled = self.live_gate.live_account_enabled(account_id)
        except Exception:
            return False
        return type(enabled) is bool and enabled

    def require_cancel_identity(self, scope: _Scope) -> None:
        environment, account, _, _, _ = scope
        matches = [
            item
            for item in self.bindings
            if item.account_ref == account and item.session_mode == environment
        ]
        if len(matches) != 1:
            _deny(403, "ACTIVATION_DENIED")
        binding = matches[0]
        if binding.environment != "development":
            _deny(403, "LIVE_DISABLED")

    def require_activation(self, scope: _Scope) -> None:
        if self.invalidate_stale_activation():
            _deny(403, "ACTIVATION_DISABLED")
        if self.recovery_status != "READY" or scope not in self.activations:
            _deny(403, "ACTIVATION_DISABLED")
        self.binding_for(scope)

    async def close(self) -> None:
        self.suspend()
        if type(self.actor) is OrderGatewayActor:
            await self.actor.close()


def _dispatch_code(name: str) -> DispatchGateCode:
    return DispatchGateCode[name]


def _evaluate_dispatch(
    runtime: OrderRuntime | None,
    state: AppState,
    action: Literal["SUBMIT", "CANCEL"],
    scope: OrderSnapshot | LiveSubmitCandidateV1,
) -> str:
    """One synchronous rule for HTTP and the actor's final transport seam."""
    try:
        if runtime is None or not runtime.configured:
            return "DENY_UNAVAILABLE"
        if action not in {"SUBMIT", "CANCEL"}:
            return "DENY_UNAVAILABLE"
        if type(scope) is LiveSubmitCandidateV1:
            if action != "SUBMIT":
                return "DENY_SCOPE"
            exact = _scope(
                scope.environment,
                scope.account_id,
                scope.venue,
                scope.instrument_id,
                scope.strategy_id,
                allow_live=True,
            )
            environment: str = scope.environment
        elif type(scope) is OrderSnapshot:
            request = scope.request
            exact = _scope(
                request.environment,
                request.account_id,
                request.venue,
                request.instrument_id,
                request.strategy_id,
                allow_live=False,
            )
            environment = request.environment
        else:
            return "DENY_SCOPE"
        if action == "SUBMIT":
            if runtime.invalidate_stale_activation():
                return "DENY_HALT"
            if state.halts.fault_code is not None or state.halts.halted:
                runtime.suspend()
                return "DENY_HALT"
            if state.killed_providers:
                runtime.suspend()
                return "DENY_KILL"
            if environment == "live":
                runtime.authorize_live_binding(exact)
                return "ALLOW"
        # The snapshot comes from the durable OMS ledger, not process memory.
        # Exact venue and scope come from the durable order snapshot. Cancel
        # checks the unique account/session binding but ignores current policy
        # changes, including expiry, revocation and allowlist removal.
        if action == "CANCEL":
            runtime.require_cancel_identity(exact)
            return "ALLOW"
        runtime.binding_for(exact)
        if runtime.recovery_status != "READY" or exact not in runtime.activations:
            return "DENY_SCOPE"
        return "ALLOW"
    except HTTPException:
        return "DENY_SCOPE"
    except Exception:
        return "DENY_UNAVAILABLE"


class PaperDispatchGate:
    """Final-seam gate injected into OMS-PORT-ADOPT's actor at startup."""

    def __init__(self, state: AppState) -> None:
        if state.dispatch_gate is not None:
            raise RuntimeError("DISPATCH_GATE_ALREADY_REGISTERED")
        self._state = state
        self._runtime: OrderRuntime | None = None
        state.dispatch_gate = self

    def bind_runtime(self, runtime: OrderRuntime) -> None:
        if type(runtime) is not OrderRuntime:
            return
        if self._runtime is runtime:
            return
        if self._runtime is not None:
            runtime.dispatch_gate_binding_valid = False
            return
        self._runtime = runtime
        runtime.dispatch_fence.bind(self._state.halts)
        self._state.dispatch_fence = runtime.dispatch_fence
        runtime.halt_authority = self._state.halts
        runtime.bound_dispatch_gate = self
        runtime.dispatch_gate_binding_valid = runtime.actor.dispatch_gate is self

    def acquire_submit_fence(self) -> int:
        runtime = self._runtime
        if runtime is None:
            raise RuntimeError("DISPATCH_FENCE_UNAVAILABLE")
        runtime.dispatch_fence.acquire()
        try:
            return self._state.halts.generation
        except Exception:
            runtime.dispatch_fence.release()
            raise

    def submit_generation_current(self, generation: int) -> bool:
        return self._state.halts.generation == generation

    def release_submit_fence(self) -> None:
        runtime = self._runtime
        if runtime is None:
            raise RuntimeError("DISPATCH_FENCE_UNAVAILABLE")
        runtime.dispatch_fence.release()

    def check(
        self,
        action: Literal["SUBMIT", "CANCEL"],
        scope: OrderSnapshot,
    ) -> DispatchGateCode:
        runtime = self._runtime
        if runtime is None:
            # The actor factory owns gate construction. Resolve only the
            # runtime installed by the application factory after startup.
            candidate = getattr(self._state, "orders", None)
            if type(candidate) is OrderRuntime:
                try:
                    self.bind_runtime(candidate)
                except HTTPException:
                    return DispatchGateCode.DENY_UNAVAILABLE
                runtime = candidate
        return _dispatch_code(_evaluate_dispatch(runtime, self._state, action, scope))


def _runtime(request: Request) -> OrderRuntime:
    state = getattr(request.app.state, "leviathan", None)
    if state is None:
        _deny(503, "NOT_CONFIGURED")
    runtime = getattr(state, "orders", None)
    if not isinstance(runtime, OrderRuntime) or not runtime.configured:
        _deny(503, "NOT_CONFIGURED")
    if state.halts.fault_code is not None or state.halts.halted or state.killed_providers:
        runtime.suspend()
    return runtime


def _oms_error(exc: OMSError) -> None:
    if isinstance(exc, OMSConflict):
        _deny(409, exc.code)
    _deny(422, exc.code)


@router.get("/status")
def status(request: Request) -> dict[str, object]:
    runtime = _runtime(request)
    runtime.operator(request)
    return {
        "live_enabled": False,
        "recovery_status": runtime.recovery_status,
        "activation_count": len(runtime.activations),
    }


@router.post("/recover")
async def recover(request: Request) -> dict[str, object]:
    runtime = _runtime(request)
    runtime.operator(request)
    await _empty_body(request)
    runtime.suspend()
    state = request.app.state.leviathan
    if state.halts.fault_code is not None or state.halts.halted or state.killed_providers:
        _deny(503, "HALT_ACTIVE")
    try:
        recovered = await runtime.actor.recover_uncertain()
    except Exception:
        _deny(503, "RECOVERY_FAILED")
    if any(item.state in _UNKNOWN for item in recovered):
        _deny(503, "RECOVERY_FAILED")
    runtime.recovery_status = "READY"
    runtime.activation_generation = state.halts.generation
    return {"recovery_status": "READY", "unresolved": []}


@router.post("/activations", status_code=201)
async def activate(request: Request) -> dict[str, object]:
    runtime = _runtime(request)
    runtime.operator(request)
    body = await _json_body(request, _SCOPE_FIELDS, _SCOPE_FIELDS)
    scope = _scope(
        body["environment"],
        body["account_id"],
        body["venue"],
        body["instrument_id"],
        body["strategy_id"],
    )
    if runtime.recovery_status != "READY":
        _deny(403, "ACTIVATION_DISABLED")
    if runtime.invalidate_stale_activation():
        _deny(403, "ACTIVATION_DISABLED")
    if runtime.activation_generation is None:
        runtime.activation_generation = request.app.state.leviathan.halts.generation
    runtime.binding_for(scope)
    runtime.activations.add(scope)
    return {"active": True}


@router.post("/activations/revoke")
async def revoke(request: Request) -> dict[str, object]:
    runtime = _runtime(request)
    runtime.operator(request)
    body = await _json_body(request, _SCOPE_FIELDS, _SCOPE_FIELDS)
    scope = _scope(
        body["environment"],
        body["account_id"],
        body["venue"],
        body["instrument_id"],
        body["strategy_id"],
    )
    runtime.activations.discard(scope)
    return {"active": False}


def _order_request(body: dict[str, object]) -> OrderRequest:
    _scope(
        body["environment"],
        body["account_id"],
        body["venue"],
        body["instrument_id"],
        body["strategy_id"],
    )
    if type(body["quantity"]) is not str or (
        body.get("limit_price") is not None and type(body["limit_price"]) is not str
    ):
        _deny(422, "INVALID_ORDER_REQUEST")
    text_fields = (
        "environment",
        "account_id",
        "venue",
        "instrument_id",
        "native_contract_id",
        "side",
        "order_type",
        "time_in_force",
        "intent_idempotency_key",
        "strategy_id",
        "risk_policy_digest",
    )
    if any(type(body[name]) is not str for name in text_fields):
        _deny(422, "INVALID_ORDER_REQUEST")
    if type(body["attempt"]) is not int:
        _deny(422, "INVALID_ORDER_REQUEST")
    values = {name: cast(str, body[name]) for name in text_fields}
    try:
        quantity = parse_oms_decimal(body["quantity"], positive=True, code="INVALID_STORED_REQUEST")
    except OMSError:
        _deny(422, "INVALID_QUANTITY")
    try:
        limit_price = (
            None
            if body.get("limit_price") is None
            else parse_oms_decimal(
                body["limit_price"], positive=True, code="INVALID_STORED_REQUEST"
            )
        )
    except OMSError:
        _deny(422, "INVALID_LIMIT_PRICE")
    try:
        expiry = body.get("expires_at")
        if expiry is not None and type(expiry) is not str:
            _deny(422, "INVALID_ORDER_REQUEST")
        return OrderRequest(
            project_id="leviathan-ai",
            environment=values["environment"],
            account_id=values["account_id"],
            venue=values["venue"],
            instrument_id=values["instrument_id"],
            native_contract_id=values["native_contract_id"],
            side=values["side"],
            quantity=quantity,
            order_type=values["order_type"],
            time_in_force=values["time_in_force"],
            client_order_id=None,
            intent_idempotency_key=values["intent_idempotency_key"],
            attempt=body["attempt"],
            strategy_id=values["strategy_id"],
            risk_policy_digest=values["risk_policy_digest"],
            actor_id="paper-api",
            capability="paper",
            limit_price=limit_price,
            expires_at=None if expiry is None else datetime.fromisoformat(expiry),
        )
    except (OMSError, TypeError, ValueError) as exc:
        if isinstance(exc, OMSError):
            _oms_error(exc)
        _deny(422, "INVALID_ORDER_REQUEST")


@router.post("", status_code=201)
async def create(request: Request) -> dict[str, object]:
    runtime = _runtime(request)
    runtime.operator(request)
    body = await _json_body(request, _CREATE_FIELDS, _CREATE_REQUIRED)
    order = _order_request(body)
    scope = _scope(
        order.environment,
        order.account_id,
        order.venue,
        order.instrument_id,
        order.strategy_id,
    )
    runtime.require_activation(scope)
    if runtime.native_contracts.get((order.venue, order.instrument_id)) != order.native_contract_id:
        _deny(403, "NATIVE_CONTRACT_DENIED")
    try:
        snapshot = await runtime.actor.create(order)
    except OMSError as exc:
        _oms_error(exc)
    return _snapshot(snapshot)


async def _get_order(runtime: OrderRuntime, order_id: str) -> OrderSnapshot:
    try:
        snapshot = await runtime.actor.get(order_id)
    except OMSError as exc:
        _oms_error(exc)
    if snapshot is None:
        _deny(404, "ORDER_NOT_FOUND")
    return snapshot


@router.get("/{order_id}")
async def read_order(request: Request, order_id: str) -> dict[str, object]:
    runtime = _runtime(request)
    runtime.operator(request)
    return _snapshot(await _get_order(runtime, order_id))


@router.post("/{order_id}/submit")
async def submit(request: Request, order_id: str) -> dict[str, object]:
    runtime = _runtime(request)
    runtime.operator(request)
    await _empty_body(request)
    order = await _get_order(runtime, order_id)
    scope = _scope(
        order.request.environment,
        order.request.account_id,
        order.request.venue,
        order.request.instrument_id,
        order.request.strategy_id,
    )
    state = request.app.state.leviathan
    if state.halts.fault_code is not None or state.halts.halted or state.killed_providers:
        runtime.suspend()
        _deny(403, "HALT_ACTIVE")
    runtime.require_activation(scope)
    try:
        evidence = runtime.evidence_source(order)
        if inspect.isawaitable(evidence):
            evidence = await evidence
    except Exception:
        _deny(503, "EVIDENCE_UNAVAILABLE")
    if not isinstance(evidence, PaperDispatchEvidence):
        _deny(503, "EVIDENCE_UNAVAILABLE")
    # Recheck after the trusted evidence port; the actor owns the final permit.
    if state.halts.fault_code is not None or state.halts.halted or state.killed_providers:
        runtime.suspend()
        _deny(403, "HALT_ACTIVE")
    runtime.require_activation(scope)
    if evidence.denial_code(order.request, order_id) is not None:
        _deny(403, "PAPER_EVIDENCE_DENIED")
    try:
        result = await runtime.actor.submit(order_id, evidence)
    except OMSError as exc:
        _oms_error(exc)
    return _snapshot(result)


@router.post("/{order_id}/cancel")
async def cancel(request: Request, order_id: str) -> dict[str, object]:
    runtime = _runtime(request)
    runtime.operator(request)
    await _empty_body(request)
    order = await _get_order(runtime, order_id)
    if _evaluate_dispatch(runtime, request.app.state.leviathan, "CANCEL", order) != "ALLOW":
        _deny(403, "ACTIVATION_DENIED")
    try:
        result = await runtime.actor.cancel(order_id)
    except OMSError as exc:
        _oms_error(exc)
    return _snapshot(result)


@router.post("/{order_id}/reconcile")
async def reconcile(request: Request, order_id: str) -> dict[str, object]:
    runtime = _runtime(request)
    runtime.operator(request)
    await _empty_body(request)
    order = await _get_order(runtime, order_id)
    if _evaluate_dispatch(runtime, request.app.state.leviathan, "CANCEL", order) != "ALLOW":
        _deny(403, "ACTIVATION_DENIED")
    try:
        result = await runtime.actor.reconcile(order_id)
    except OMSError as exc:
        runtime.suspend()
        _oms_error(exc)
    return _snapshot(result)
