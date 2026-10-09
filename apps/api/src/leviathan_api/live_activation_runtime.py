"""Production composition for the fail-closed LIVE activation boundary.

This module adapts existing trusted application state and the OMS read API to
the narrow ports consumed by :mod:`leviathan_api.routers.live_activation`.
Missing governance evidence is represented as ``None``; no evidence is
inferred from configuration or from a prepared trading binding.
"""

from __future__ import annotations

import inspect
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Literal, Protocol, cast

from leviathan_store.live_activation import (
    LiveActivationEventV1,
    LiveActivationStoreV1,
)
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from leviathan_api.routers.live_activation import (
    LiveAccountEvidenceV1,
    LiveActivationConfigV1,
    LiveActivationPortsV1,
    LiveBrokerVerificationV1,
    LiveEntitlementEvidenceV1,
    LiveMfaEvidenceV1,
    LiveOpenOrderV1,
    LiveReadinessEvidenceV1,
    LiveRiskAcknowledgementV1,
    _blockers,
    _owner_account,
)
from leviathan_api.state import AppState
from leviathan_core.execution.oms import OrderGatewayActor, OrderLedgerPort
from leviathan_core.execution.order_models import OrderSnapshot, OrderState
from leviathan_core.security.authz_models import TrustedPrincipalV1


class _LiveActivationGatePort(Protocol):
    def live_account_enabled(self, account_id: str) -> bool: ...


ClockNs = Callable[[], int]


class ProductionLiveActivationStorePortV1:
    """Named production adapter over the store package's append/read service."""

    def __init__(self, sessions: async_sessionmaker[AsyncSession]) -> None:
        self._store = LiveActivationStoreV1(sessions)

    async def append_events(self, events: tuple[LiveActivationEventV1, ...]) -> tuple[int, ...]:
        return await self._store.append_events(events)

    async def read_events(
        self, organization_id: str, account_id: str
    ) -> tuple[LiveActivationEventV1, ...]:
        return await self._store.read_events(organization_id, account_id)


class _UnavailableAccountPort:
    """The current trading binding has no owner/org/device identity fields."""

    def __init__(self, _app_state: AppState) -> None:
        pass

    def read_account(
        self, _principal: TrustedPrincipalV1, _account_id: str
    ) -> LiveAccountEvidenceV1 | None:
        # TradingAccountBindingV1 is a prepared execution binding, not the
        # account-owner binding required by the LIVE entitlement contract.
        return None


class _UnavailableEntitlementPort:
    def read_entitlement(
        self, _principal: TrustedPrincipalV1, _account_id: str
    ) -> LiveEntitlementEvidenceV1 | None:
        # DESKTOP-SIGNIN-001 owns the verified subscription/entitlement source.
        return None


class _UnavailableMfaPort:
    def read_mfa(self, _principal: TrustedPrincipalV1) -> LiveMfaEvidenceV1 | None:
        # No server-verified recent MFA evidence source is integrated yet.
        return None


class _UnavailableBrokerVerificationPort:
    def read_broker_verification(
        self, _principal: TrustedPrincipalV1, _account_id: str
    ) -> LiveBrokerVerificationV1 | None:
        # CONN-003's verified broker/account-permission read source is not
        # mounted in this application snapshot. A prepared binding is not proof.
        return None


class _UnavailableRiskAcknowledgementPort:
    def read_risk_acknowledgement(
        self, _principal: TrustedPrincipalV1, _account_id: str
    ) -> LiveRiskAcknowledgementV1 | None:
        # The risk-policy digest alone is not an operator acknowledgement.
        return None


class _UnavailableReadinessPort:
    def read_readiness(
        self, _principal: TrustedPrincipalV1, _account_id: str
    ) -> LiveReadinessEvidenceV1 | None:
        # The paper-readiness source does not yet provide LIVE feed/account
        # freshness evidence, so it cannot satisfy this contract.
        return None


class _AppHaltPort:
    def __init__(self, app_state: AppState) -> None:
        self._app_state = app_state

    def is_halted(self, _principal: TrustedPrincipalV1, _account_id: str) -> bool:
        authority = self._app_state.halts
        if authority.fault_code is not None:
            raise RuntimeError("HALT_STATUS_UNAVAILABLE")
        return authority.halted


_NON_TERMINAL_STATES = frozenset(
    {
        OrderState.CREATED,
        OrderState.RISK_PENDING,
        OrderState.READY,
        OrderState.SUBMITTING,
        OrderState.DISPATCH_IN_FLIGHT,
        OrderState.WORKING,
        OrderState.PARTIALLY_FILLED,
        OrderState.CANCEL_PENDING,
        OrderState.CANCEL_REQUESTED_UNCONFIRMED,
        OrderState.UNKNOWN_SUBMIT,
        OrderState.UNKNOWN_CANCEL,
        OrderState.RECONCILE_REQUIRED,
    }
)


class OrderLedgerOpenOrdersPortV1:
    """Read-only adapter over ``OrderLedger.account_inventory``.

    The OMS ledger read is async. Synchronous test doubles are also accepted,
    but no event-loop blocking or alternate data path is used.
    """

    def __init__(self, ledger: OrderLedgerPort | None, clock_ns: ClockNs = time.time_ns) -> None:
        self._ledger = ledger
        self._clock_ns = clock_ns

    async def read_open_orders(
        self, _principal: TrustedPrincipalV1, account_id: str
    ) -> tuple[LiveOpenOrderV1, ...] | None:
        ledger = self._ledger
        if ledger is None or not callable(getattr(ledger, "account_inventory", None)):
            return None
        try:
            inventory_reader = cast(Any, ledger.account_inventory)
            snapshots: Any = inventory_reader("live", account_id)
            if inspect.isawaitable(snapshots):
                snapshots = await snapshots
            if type(snapshots) is not tuple:
                return None
            rows: list[LiveOpenOrderV1] = []
            for snapshot in snapshots:
                if type(snapshot) is not OrderSnapshot:
                    return None
                request = snapshot.request
                if request.environment != "live" or request.account_id != account_id:
                    continue
                if snapshot.state not in _NON_TERMINAL_STATES:
                    continue
                quantity = request.quantity
                if type(quantity) is not Decimal or not quantity.is_finite() or quantity <= 0:
                    return None
                rows.append(
                    LiveOpenOrderV1(
                        order_id=snapshot.order_id,
                        instrument_id=request.instrument_id,
                        side=cast(Literal["BUY", "SELL"], request.side),
                        quantity=format(quantity, "f"),
                        status=snapshot.state.value,
                        verified_at_ns=int(self._clock_ns()),
                    )
                )
                if len(rows) > 200:
                    return None
            return tuple(rows)
        except Exception:
            return None


def _oms_ledger(app_state: AppState) -> OrderLedgerPort | None:
    runtime = app_state.orders
    actor = getattr(runtime, "actor", None)
    if type(actor) is not OrderGatewayActor:
        return None
    ledger = getattr(actor, "_ledger", None)
    if ledger is None or not callable(getattr(ledger, "account_inventory", None)):
        return None
    return cast(OrderLedgerPort, ledger)


def build_production_live_activation_ports(
    app_state: AppState, *, clock_ns: ClockNs = time.time_ns
) -> LiveActivationPortsV1:
    """Build ports solely from integrated canonical application sources."""
    return LiveActivationPortsV1(
        accounts=_UnavailableAccountPort(app_state),
        entitlements=_UnavailableEntitlementPort(),
        mfa=_UnavailableMfaPort(),
        broker=_UnavailableBrokerVerificationPort(),
        risk=_UnavailableRiskAcknowledgementPort(),
        readiness=_UnavailableReadinessPort(),
        halt=_AppHaltPort(app_state),
        open_orders=OrderLedgerOpenOrdersPortV1(_oms_ledger(app_state), clock_ns),
    )


@dataclass(frozen=True, slots=True)
class _ActivationSnapshot:
    principal: TrustedPrincipalV1
    account: LiveAccountEvidenceV1
    entitlement_revision: str
    risk_policy_sha256: str


class LiveActivationEvidenceCaptureV1:
    """Retain authenticated evidence observed by the router for gate checks."""

    def __init__(self, ports: LiveActivationPortsV1) -> None:
        self.source = ports
        self.principals: dict[str, TrustedPrincipalV1] = {}
        self.accounts: dict[str, LiveAccountEvidenceV1] = {}
        self.entitlements: dict[str, LiveEntitlementEvidenceV1] = {}
        self.risks: dict[str, LiveRiskAcknowledgementV1] = {}
        self._snapshots: dict[str, _ActivationSnapshot] = {}
        self.ports = LiveActivationPortsV1(
            accounts=_CaptureAccount(self),
            entitlements=_CaptureEntitlement(self),
            mfa=_CaptureMfa(self),
            broker=_CaptureBroker(self),
            risk=_CaptureRisk(self),
            readiness=_CaptureReadiness(self),
            halt=ports.halt,
            open_orders=ports.open_orders,
        )

    def record(self, events: tuple[LiveActivationEventV1, ...]) -> None:
        for event in events:
            account_id = event.account_id
            if event.event_type == "ENABLED":
                principal = self.principals.get(account_id)
                account = self.accounts.get(account_id)
                entitlement = self.entitlements.get(account_id)
                risk = self.risks.get(account_id)
                if (
                    principal is not None
                    and account is not None
                    and entitlement is not None
                    and risk is not None
                    and event.organization_id == account.organization_id
                    and event.actor_id == principal.principal_id
                    and event.credential_binding_revision == account.binding_revision
                    and event.risk_policy_sha256 == risk.risk_policy_sha256
                    and event.entitlement_revision == entitlement.revision
                ):
                    self._snapshots[account_id] = _ActivationSnapshot(
                        principal=principal,
                        account=account,
                        entitlement_revision=entitlement.revision,
                        risk_policy_sha256=risk.risk_policy_sha256,
                    )
                else:
                    self._snapshots.pop(account_id, None)

    def revoke(self, events: tuple[LiveActivationEventV1, ...]) -> None:
        """Revoke gate snapshots before a disable/invalidation write can block or fail."""
        for event in events:
            if event.event_type in {"DISABLED", "INVALIDATED"}:
                self._snapshots.pop(event.account_id, None)

    def deactivate(self, organization_id: str, account_id: str) -> None:
        """Drop a gate snapshot when the router fails closed without a durable event."""
        snapshot = self._snapshots.get(account_id)
        if snapshot is not None and snapshot.account.organization_id == organization_id:
            self._snapshots.pop(account_id, None)

    def is_enabled(self, account_id: str, *, now_ns: int, config: LiveActivationConfigV1) -> bool:
        snapshot = self._snapshots.get(account_id)
        if snapshot is None:
            return False
        try:
            principal = snapshot.principal
            account = _owner_account(self.ports, principal, account_id)
            if account is None or account.organization_id != snapshot.account.organization_id:
                self._snapshots.pop(account_id, None)
                return False
            if (
                account.binding_revision != snapshot.account.binding_revision
                or account.credential_revision != snapshot.account.credential_revision
            ):
                self._snapshots.pop(account_id, None)
                return False
            blockers, digest, _verified_at, entitlement_revision = _blockers(
                self.ports, principal, account, now_ns=now_ns, config=config
            )
            if (
                blockers
                or digest != snapshot.risk_policy_sha256
                or entitlement_revision != snapshot.entitlement_revision
            ):
                self._snapshots.pop(account_id, None)
                return False
            return True
        except Exception:
            self._snapshots.pop(account_id, None)
            return False


class _CaptureAccount:
    def __init__(self, capture: LiveActivationEvidenceCaptureV1) -> None:
        self._capture = capture

    def read_account(
        self, principal: TrustedPrincipalV1, account_id: str
    ) -> LiveAccountEvidenceV1 | None:
        value = self._capture.source.accounts.read_account(principal, account_id)
        if type(value) is LiveAccountEvidenceV1:
            self._capture.principals[account_id] = principal
            self._capture.accounts[account_id] = value
        return value


class _CaptureEntitlement:
    def __init__(self, capture: LiveActivationEvidenceCaptureV1) -> None:
        self._capture = capture

    def read_entitlement(
        self, principal: TrustedPrincipalV1, account_id: str
    ) -> LiveEntitlementEvidenceV1 | None:
        value = self._capture.source.entitlements.read_entitlement(principal, account_id)
        if type(value) is LiveEntitlementEvidenceV1:
            self._capture.entitlements[account_id] = value
        return value


class _CaptureMfa:
    def __init__(self, capture: LiveActivationEvidenceCaptureV1) -> None:
        self._capture = capture

    def read_mfa(self, principal: TrustedPrincipalV1) -> LiveMfaEvidenceV1 | None:
        return self._capture.source.mfa.read_mfa(principal)


class _CaptureBroker:
    def __init__(self, capture: LiveActivationEvidenceCaptureV1) -> None:
        self._capture = capture

    def read_broker_verification(
        self, principal: TrustedPrincipalV1, account_id: str
    ) -> LiveBrokerVerificationV1 | None:
        return self._capture.source.broker.read_broker_verification(principal, account_id)


class _CaptureRisk:
    def __init__(self, capture: LiveActivationEvidenceCaptureV1) -> None:
        self._capture = capture

    def read_risk_acknowledgement(
        self, principal: TrustedPrincipalV1, account_id: str
    ) -> LiveRiskAcknowledgementV1 | None:
        value = self._capture.source.risk.read_risk_acknowledgement(principal, account_id)
        if type(value) is LiveRiskAcknowledgementV1:
            self._capture.risks[account_id] = value
        return value


class _CaptureReadiness:
    def __init__(self, capture: LiveActivationEvidenceCaptureV1) -> None:
        self._capture = capture

    def read_readiness(
        self, principal: TrustedPrincipalV1, account_id: str
    ) -> LiveReadinessEvidenceV1 | None:
        return self._capture.source.readiness.read_readiness(principal, account_id)


class ObservedLiveActivationStorePortV1:
    """Store decorator that maintains a process-local fail-closed gate cache."""

    def __init__(self, store: Any, capture: LiveActivationEvidenceCaptureV1) -> None:
        self._store = store
        self._capture = capture

    async def append_events(self, events: tuple[LiveActivationEventV1, ...]) -> tuple[int, ...]:
        self._capture.revoke(events)
        result = cast(tuple[int, ...], await self._store.append_events(events))
        self._capture.record(events)
        return result

    async def read_events(
        self, organization_id: str, account_id: str
    ) -> tuple[LiveActivationEventV1, ...]:
        return cast(
            tuple[LiveActivationEventV1, ...],
            await self._store.read_events(organization_id, account_id),
        )


class LiveActivationProjectionV1:
    """Synchronous order-gate projection over activation events and live evidence."""

    def __init__(
        self,
        capture: LiveActivationEvidenceCaptureV1,
        config: LiveActivationConfigV1,
        clock_ns: ClockNs = time.time_ns,
    ) -> None:
        self._capture = capture
        self._config = config
        self._clock_ns = clock_ns

    def live_account_enabled(self, account_id: str) -> bool:
        if type(account_id) is not str or not account_id:
            return False
        try:
            return self._capture.is_enabled(
                account_id, now_ns=int(self._clock_ns()), config=self._config
            )
        except Exception:
            return False

    def deactivate_account(self, organization_id: str, account_id: str) -> None:
        self._capture.deactivate(organization_id, account_id)


class LazyLiveActivationGateV1:
    """Pre-lifespan gate placeholder; unbound and faulty states deny LIVE."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._projection: _LiveActivationGatePort | None = None

    def bind(self, projection: _LiveActivationGatePort) -> None:
        if not callable(getattr(projection, "live_account_enabled", None)):
            raise TypeError("LIVE_ACTIVATION_GATE_INVALID")
        with self._lock:
            self._projection = projection

    def live_account_enabled(self, account_id: str) -> bool:
        with self._lock:
            projection = self._projection
        if projection is None:
            return False
        try:
            result = projection.live_account_enabled(account_id)
            return result is True
        except Exception:
            return False

    def deactivate_account(self, organization_id: str, account_id: str) -> None:
        with self._lock:
            projection = self._projection
        if projection is None:
            return
        try:
            deactivate = getattr(projection, "deactivate_account", None)
            if callable(deactivate):
                deactivate(organization_id, account_id)
        except Exception:
            return


class DeniedLiveActivationPortsV1:
    """Return no unsupported account evidence while preserving real HALT reads."""

    @staticmethod
    def create(app_state: AppState, *, clock_ns: ClockNs = time.time_ns) -> LiveActivationPortsV1:
        return build_production_live_activation_ports(app_state, clock_ns=clock_ns)


__all__ = [
    "DeniedLiveActivationPortsV1",
    "LazyLiveActivationGateV1",
    "LiveActivationEvidenceCaptureV1",
    "LiveActivationProjectionV1",
    "ObservedLiveActivationStorePortV1",
    "OrderLedgerOpenOrdersPortV1",
    "ProductionLiveActivationStorePortV1",
    "build_production_live_activation_ports",
]
