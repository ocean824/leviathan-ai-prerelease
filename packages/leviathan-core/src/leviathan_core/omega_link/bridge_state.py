"""Pure OMEGA bridge decisions. Adapters own authentication, I/O, and HALT calls."""

from __future__ import annotations

import hashlib
import json

from .state_models import (
    Action,
    AgentSessionV1,
    BridgeDecisionV1,
    BridgeHealthV1,
    BridgeState,
    CapabilityManifestV1,
    DecisionReason,
    HandoffTaskV1,
    KillSyncIntentV1,
    OmegaPolicyV1,
    TaskState,
    _identifier,
    _nonnegative_ns,
)

_TERMINAL = frozenset({"succeeded", "failed", "cancelled", "expired"})
_NONFINANCIAL_TOOL_REGISTRY = frozenset({"research.read", "risk.inspect"})


def _halt_key(prefix: str, peer_system: str, tool_id: str | None = None) -> str:
    # Hash a typed payload so peer/tool delimiters cannot produce the same HALT key.
    canonical = json.dumps(
        {"prefix": prefix, "peer_system": peer_system, "tool_id": tool_id},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return prefix + ":" + hashlib.sha256(canonical.encode("ascii")).hexdigest()


def _state(health: BridgeHealthV1, now_ns: int, policy: OmegaPolicyV1) -> BridgeState:
    at = health.heartbeat_at_ns
    expiry = health.heartbeat_expires_ns
    if (
        not health.transport_verified
        or at is None
        or expiry is None
        or at > now_ns
        or now_ns - at > policy.max_heartbeat_age_ns
        or now_ns >= expiry
        or (health.previous_heartbeat_at_ns is not None and at < health.previous_heartbeat_at_ns)
    ):
        return "disconnected"
    if health.degraded or health.peer_kill_pending or health.peer_killed or health.halt_reasons:
        return "degraded"
    return "connected"


def _health_intent(health: BridgeHealthV1, state: BridgeState, now_ns: int) -> KillSyncIntentV1:
    reason = f"omega_bridge_{state}"
    canonical = json.dumps(
        {
            "peer_system": health.peer_system,
            "reason": reason,
            "heartbeat_at_ns": health.heartbeat_at_ns,
            "halt_version": health.halt_version,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    request_id = "health_" + hashlib.sha256(canonical.encode("ascii")).hexdigest()
    return KillSyncIntentV1(
        version="1",
        request_id=request_id,
        peer_system=health.peer_system,
        reason_code=reason,
        requested_at_ns=now_ns,
        halt_version=health.halt_version,
        halt_reason=_halt_key(reason, health.peer_system),
    )


def _decision(
    *,
    allowed: bool,
    reason_code: DecisionReason,
    bridge_state: BridgeState,
    next_task: HandoffTaskV1 | None = None,
    kill_intent: KillSyncIntentV1 | None = None,
) -> BridgeDecisionV1:
    return BridgeDecisionV1(
        version="1",
        allowed=allowed,
        reason_code=reason_code,
        bridge_state=bridge_state,
        next_task=next_task,
        kill_intent=kill_intent,
    )


def evaluate_bridge(
    health: BridgeHealthV1, *, now_ns: int, policy: OmegaPolicyV1
) -> BridgeDecisionV1:
    """Assess trusted health and petition HALT on degraded or lost bridge health."""
    _nonnegative_ns(now_ns)
    state = _state(health, now_ns, policy)
    if health.halt_reasons:
        return _decision(allowed=False, reason_code="HALT_ACTIVE", bridge_state=state)
    if health.peer_kill_pending or health.peer_killed:
        return _decision(allowed=False, reason_code="PEER_KILLED", bridge_state=state)
    if state != "connected":
        return _decision(
            allowed=False,
            reason_code="BRIDGE_DEGRADED" if state == "degraded" else "BRIDGE_DISCONNECTED",
            bridge_state=state,
            kill_intent=_health_intent(health, state, now_ns),
        )
    return _decision(allowed=True, reason_code="BRIDGE_READY", bridge_state=state)


def request_kill(
    health: BridgeHealthV1,
    *,
    request_id: str,
    now_ns: int,
    reason_code: str,
    tool_id: str | None = None,
) -> KillSyncIntentV1:
    """Construct a HALT-001 engage request; authentication/replay belong to OMEGA-002."""
    _identifier(request_id)
    _identifier(reason_code)
    if tool_id is not None:
        _identifier(tool_id)
    _nonnegative_ns(now_ns)
    halt_reason = _halt_key("omega_kill", health.peer_system, tool_id)
    return KillSyncIntentV1(
        version="1",
        request_id=request_id,
        peer_system=health.peer_system,
        tool_id=tool_id,
        reason_code=reason_code,
        requested_at_ns=now_ns,
        halt_version=health.halt_version,
        halt_reason=halt_reason,
    )


def _with_state(task: HandoffTaskV1, state: TaskState) -> HandoffTaskV1:
    return HandoffTaskV1.model_validate({**task.model_dump(), "state": state})


def evaluate_action(
    action: Action,
    *,
    health: BridgeHealthV1,
    session: AgentSessionV1,
    manifest: CapabilityManifestV1,
    policy: OmegaPolicyV1,
    now_ns: int,
    actor_id: str,
    task: HandoffTaskV1 | None = None,
    to_state: TaskState | None = None,
    tool_id: str | None = None,
    risk_guard_ok: bool = False,
) -> BridgeDecisionV1:
    """Decide a task or nonfinancial tool state transition without invoking effects."""
    _nonnegative_ns(now_ns)
    _identifier(actor_id)
    if action not in ("task_accept", "task_update", "task_cancel", "tool_use"):
        return _decision(
            allowed=False, reason_code="UNKNOWN_ACTION", bridge_state=_state(health, now_ns, policy)
        )
    if task is not None and task.state not in _TERMINAL and now_ns >= task.expires_at_ns:
        return _decision(
            allowed=False,
            reason_code="TASK_EXPIRED",
            bridge_state=_state(health, now_ns, policy),
            next_task=_with_state(task, "expired"),
        )
    bridge = evaluate_bridge(health, now_ns=now_ns, policy=policy)
    if not bridge.allowed:
        return bridge
    if not session.verified or session.peer_system != health.peer_system:
        return _decision(
            allowed=False, reason_code="SESSION_UNVERIFIED", bridge_state=bridge.bridge_state
        )
    if session.status != "active" or not session.issued_at_ns <= now_ns < session.expires_at_ns:
        return _decision(
            allowed=False, reason_code="SESSION_INACTIVE", bridge_state=bridge.bridge_state
        )
    if session.agent_id != actor_id:
        return _decision(
            allowed=False, reason_code="ACTOR_MISMATCH", bridge_state=bridge.bridge_state
        )
    if session.manifest_hash != manifest.manifest_hash:
        return _decision(
            allowed=False, reason_code="MANIFEST_MISMATCH", bridge_state=bridge.bridge_state
        )
    if session.action_budget <= 0:
        return _decision(
            allowed=False, reason_code="BUDGET_EXHAUSTED", bridge_state=bridge.bridge_state
        )
    if task is None:
        return _decision(
            allowed=False, reason_code="TASK_REQUIRED", bridge_state=bridge.bridge_state
        )
    if task.state in _TERMINAL:
        return _decision(
            allowed=False, reason_code="TASK_TERMINAL", bridge_state=bridge.bridge_state
        )

    if action == "task_cancel":
        if actor_id != task.created_by:
            return _decision(
                allowed=False, reason_code="CREATOR_REQUIRED", bridge_state=bridge.bridge_state
            )
        return _decision(
            allowed=True,
            reason_code="TASK_CANCELLED",
            bridge_state=bridge.bridge_state,
            next_task=_with_state(task, "cancelled"),
        )
    if task.assigned_to != actor_id:
        return _decision(
            allowed=False, reason_code="OWNER_REQUIRED", bridge_state=bridge.bridge_state
        )
    if action == "task_accept":
        if task.state != "pending":
            return _decision(
                allowed=False, reason_code="INVALID_TRANSITION", bridge_state=bridge.bridge_state
            )
        return _decision(
            allowed=True,
            reason_code="TASK_ACCEPTED",
            bridge_state=bridge.bridge_state,
            next_task=_with_state(task, "in_progress"),
        )
    if action == "task_update":
        transitions: dict[str, tuple[str, ...]] = {
            "in_progress": ("waiting", "succeeded", "failed"),
            "waiting": ("in_progress", "succeeded", "failed"),
        }
        if to_state not in transitions.get(task.state, ()):
            return _decision(
                allowed=False, reason_code="INVALID_TRANSITION", bridge_state=bridge.bridge_state
            )
        assert to_state is not None
        return _decision(
            allowed=True,
            reason_code="TASK_UPDATED",
            bridge_state=bridge.bridge_state,
            next_task=_with_state(task, to_state),
        )

    if task.state != "in_progress":
        return _decision(
            allowed=False, reason_code="INVALID_TRANSITION", bridge_state=bridge.bridge_state
        )
    if tool_id is None:
        return _decision(
            allowed=False, reason_code="TOOL_REQUIRED", bridge_state=bridge.bridge_state
        )
    if not isinstance(tool_id, str) or not tool_id.isascii():
        return _decision(allowed=False, reason_code="TOOL_DENIED", bridge_state=bridge.bridge_state)
    if tool_id in health.tool_kill_pending or tool_id in health.killed_tools:
        return _decision(allowed=False, reason_code="TOOL_KILLED", bridge_state=bridge.bridge_state)
    if tool_id in manifest.financial_tools:
        return _decision(
            allowed=False, reason_code="FINANCIAL_ROUTE_DENIED", bridge_state=bridge.bridge_state
        )
    if tool_id not in _NONFINANCIAL_TOOL_REGISTRY:
        return _decision(allowed=False, reason_code="TOOL_DENIED", bridge_state=bridge.bridge_state)
    if tool_id not in task.tool_allowlist or tool_id not in manifest.tools:
        return _decision(allowed=False, reason_code="TOOL_DENIED", bridge_state=bridge.bridge_state)
    if f"tool:use.{tool_id}" not in session.scopes:
        return _decision(
            allowed=False, reason_code="SCOPE_DENIED", bridge_state=bridge.bridge_state
        )
    # This slice exposes no financial/order path; risk_guard_ok is reserved for the later adapter.
    _ = risk_guard_ok
    return _decision(allowed=True, reason_code="TOOL_ALLOWED", bridge_state=bridge.bridge_state)
