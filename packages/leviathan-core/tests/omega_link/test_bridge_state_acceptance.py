"""Independent adversarial acceptance tests for the OMEGA-001 state kernel."""

from __future__ import annotations

import copy
import json
import pickle

import pytest

from leviathan_core.omega_link import (
    AgentSessionV1,
    BridgeDecisionV1,
    BridgeHealthV1,
    CapabilityManifestV1,
    HandoffTaskV1,
    KillSyncIntentV1,
    OmegaPolicyV1,
    OmegaValidationError,
    evaluate_action,
    evaluate_bridge,
    request_kill,
)
from leviathan_core.omega_link.state_models import _from_trusted_adapter

NOW_NS = 10_000_000_000
PEER = "omega"
AGENT = "agent-7"
CREATOR = "operator-2"
MANIFEST_TOOLS = ("research.read", "risk.inspect")
POLICY = OmegaPolicyV1(version="1", max_heartbeat_age_ns=2_000_000_000)


def fresh_health(**overrides: object) -> BridgeHealthV1:
    values: dict[str, object] = {
        "version": "1",
        "peer_system": PEER,
        "transport_verified": True,
        "heartbeat_at_ns": NOW_NS - 100,
        "heartbeat_expires_ns": NOW_NS + 5_000,
        "previous_heartbeat_at_ns": NOW_NS - 200,
        "degraded": False,
        "peer_kill_pending": False,
        "peer_killed": False,
        "tool_kill_pending": (),
        "killed_tools": (),
        "halt_reasons": (),
        "halt_version": 0,
    }
    values.update(overrides)
    return BridgeHealthV1(**values)


def valid_manifest() -> CapabilityManifestV1:
    return CapabilityManifestV1(
        version="1",
        tools=MANIFEST_TOOLS,
        datasets=(),
        actions=(),
        limits=(),
        financial_tools=(),
    )


def valid_session(
    manifest: CapabilityManifestV1 | None = None,
    *,
    agent_id: str = AGENT,
    scopes: tuple[str, ...] = ("tool:use.research.read", "tool:use.risk.inspect"),
) -> AgentSessionV1:
    active_manifest = manifest or valid_manifest()
    return _from_trusted_adapter(
        session=AgentSessionV1(
            version="1",
            session_id="session-1",
            peer_system=PEER,
            agent_id=agent_id,
            scopes=scopes,
            manifest_hash=active_manifest.manifest_hash,
            status="active",
            issued_at_ns=NOW_NS - 1_000,
            expires_at_ns=NOW_NS + 60_000,
            action_budget=10,
        )
    )


def valid_task(**overrides: object) -> HandoffTaskV1:
    values: dict[str, object] = {
        "version": "1",
        "task_id": "task-1",
        "task_type": "research",
        "created_by": CREATOR,
        "assigned_to": AGENT,
        "state": "pending",
        "created_at_ns": NOW_NS - 100,
        "ttl_ms": 5_000,
        "sla_ms": 1_000,
        "context_hash": "a" * 64,
        "tool_allowlist": ("research.read",),
        "audit_ref": None,
    }
    values.update(overrides)
    return HandoffTaskV1(**values)


def decide_action(
    action: str,
    *,
    health: BridgeHealthV1 | None = None,
    session: AgentSessionV1 | None = None,
    manifest: CapabilityManifestV1 | None = None,
    actor_id: str = AGENT,
    task: HandoffTaskV1 | None = None,
    to_state: str | None = None,
    tool_id: str | None = None,
    policy: OmegaPolicyV1 = POLICY,
):
    active_manifest = manifest or valid_manifest()
    return evaluate_action(
        action,
        health=health or fresh_health(),
        session=session or valid_session(active_manifest),
        manifest=active_manifest,
        policy=policy,
        now_ns=NOW_NS,
        actor_id=actor_id,
        task=task,
        to_state=to_state,
        tool_id=tool_id,
        risk_guard_ok=False,
    )


def test_fresh_verified_heartbeat_is_connected() -> None:
    result = evaluate_bridge(fresh_health(), now_ns=NOW_NS, policy=POLICY)

    assert isinstance(result, BridgeDecisionV1)
    assert result.allowed is True
    assert result.bridge_state == "connected"


@pytest.mark.parametrize(
    ("health", "expected_states"),
    [
        (fresh_health(transport_verified=False), {"disconnected"}),
        (
            fresh_health(heartbeat_at_ns=NOW_NS - 10_000, heartbeat_expires_ns=NOW_NS - 1),
            {"disconnected"},
        ),
        (
            fresh_health(heartbeat_at_ns=NOW_NS - 500, previous_heartbeat_at_ns=NOW_NS - 100),
            {"disconnected"},
        ),
        (fresh_health(degraded=True), {"degraded", "disconnected"}),
        (fresh_health(peer_kill_pending=True), {"degraded", "disconnected"}),
        (fresh_health(peer_killed=True), {"degraded", "disconnected"}),
        (fresh_health(halt_reasons=("operator_halt",)), {"degraded", "disconnected"}),
    ],
    ids=["offline", "stale", "regressed", "degraded", "kill-pending", "peer-killed", "halt-active"],
)
def test_unhealthy_or_halted_bridge_fails_closed(
    health: BridgeHealthV1, expected_states: set[str]
) -> None:
    result = evaluate_bridge(health, now_ns=NOW_NS, policy=POLICY)

    assert result.allowed is False
    assert result.bridge_state in expected_states


def test_missing_heartbeat_cannot_be_treated_as_connected() -> None:
    values = fresh_health().model_dump()
    values["heartbeat_at_ns"] = None
    values["heartbeat_expires_ns"] = None

    try:
        health = BridgeHealthV1(**values)
    except (TypeError, OmegaValidationError, ValueError):
        return

    result = evaluate_bridge(health, now_ns=NOW_NS, policy=POLICY)
    assert result.allowed is False
    assert result.bridge_state == "disconnected"


@pytest.mark.parametrize(
    "validation_method",
    ["constructor", "model_validate", "model_validate_json", "model_validate_strings"],
)
def test_invalid_peer_validation_errors_redact_secret_input(validation_method: str) -> None:
    secret = "SECRET bad id"
    payload = fresh_health().model_dump()
    payload["peer_system"] = secret

    with pytest.raises(OmegaValidationError) as caught:
        if validation_method == "constructor":
            BridgeHealthV1(**payload)
        elif validation_method == "model_validate":
            BridgeHealthV1.model_validate(payload)
        elif validation_method == "model_validate_json":
            BridgeHealthV1.model_validate_json(json.dumps(payload))
        else:
            BridgeHealthV1.model_validate_strings(payload)

    error = caught.value
    assert error.code == "OMEGA_INVALID_INPUT"
    assert error.args == ("OMEGA_INVALID_INPUT",)
    assert error.loc == ("peer_system",)
    rendered = (str(error), repr(error.args), repr(error.errors()), error.json())
    assert all(secret not in view for view in rendered)


def test_unknown_extra_field_error_redacts_name_and_value() -> None:
    secret = "SECRET bad id"
    payload = fresh_health().model_dump()
    payload["SECRET bad field"] = secret

    with pytest.raises(OmegaValidationError) as caught:
        BridgeHealthV1(**payload)

    error = caught.value
    assert error.loc == ("unknown_field",)
    assert all(
        secret not in view
        for view in (str(error), repr(error.args), repr(error.errors()), error.json())
    )


@pytest.mark.parametrize(
    ("operation", "expected_loc"),
    [
        ("known_assignment", ("peer_system",)),
        ("unknown_assignment", ("unknown_field",)),
        ("known_deletion", ("peer_system",)),
        ("unknown_deletion", ("unknown_field",)),
    ],
)
def test_frozen_mutation_errors_are_typed_and_redact_canary(
    operation: str, expected_loc: tuple[str, ...]
) -> None:
    canary = "SECRET bad id"
    health = fresh_health()

    with pytest.raises(OmegaValidationError) as caught:
        if operation == "known_assignment":
            health.peer_system = canary
        elif operation == "unknown_assignment":
            setattr(health, canary, canary)
        elif operation == "known_deletion":
            del health.peer_system
        else:
            delattr(health, canary)

    error = caught.value
    assert error.code == "OMEGA_FROZEN_RECORD"
    assert error.error_type == "frozen_instance"
    assert error.loc == expected_loc
    rendered = (
        str(error),
        repr(error.args),
        repr(error.errors()),
        error.json(),
        repr(getattr(error, "context", None)),
    )
    assert all(canary not in view for view in rendered)


def test_expiry_boundary_is_exclusive() -> None:
    health = fresh_health(heartbeat_expires_ns=NOW_NS)

    result = evaluate_bridge(health, now_ns=NOW_NS, policy=POLICY)

    assert result.allowed is False
    assert result.bridge_state == "disconnected"


def test_heartbeat_age_bound_is_inclusive_and_future_expiry_cannot_extend_it() -> None:
    age_limit = POLICY.max_heartbeat_age_ns
    at_limit = fresh_health(
        heartbeat_at_ns=NOW_NS - age_limit,
        heartbeat_expires_ns=NOW_NS + 10_000_000_000,
        previous_heartbeat_at_ns=None,
    )
    older_with_future_expiry = fresh_health(
        heartbeat_at_ns=NOW_NS - age_limit - 1,
        heartbeat_expires_ns=NOW_NS + 10_000_000_000,
        previous_heartbeat_at_ns=None,
    )

    assert evaluate_bridge(at_limit, now_ns=NOW_NS, policy=POLICY).bridge_state == "connected"
    stale = evaluate_bridge(older_with_future_expiry, now_ns=NOW_NS, policy=POLICY)
    assert stale.allowed is False
    assert stale.bridge_state == "disconnected"


def test_heartbeat_expiry_before_observation_is_rejected() -> None:
    with pytest.raises(OmegaValidationError):
        fresh_health(
            heartbeat_at_ns=NOW_NS - 1,
            heartbeat_expires_ns=NOW_NS - 2,
        )


@pytest.mark.parametrize("max_age_ns", [0, -1, 1_800_000_000_001, True])
def test_heartbeat_policy_rejects_invalid_age_bounds(max_age_ns: int) -> None:
    with pytest.raises(OmegaValidationError):
        OmegaPolicyV1(version="1", max_heartbeat_age_ns=max_age_ns)


def test_heartbeat_policy_accepts_thirty_minute_upper_bound() -> None:
    policy = OmegaPolicyV1(version="1", max_heartbeat_age_ns=1_800_000_000_000)

    assert policy.max_heartbeat_age_ns == 1_800_000_000_000


def test_unverified_session_record_cannot_claim_creator_identity() -> None:
    claims = valid_session().model_dump()
    claims["agent_id"] = CREATOR
    unverified = AgentSessionV1.model_validate(claims)

    decision = decide_action(
        "task_cancel",
        session=unverified,
        actor_id=CREATOR,
        task=valid_task(),
    )

    assert unverified.verified is False
    assert decision.allowed is False
    assert decision.reason_code == "SESSION_UNVERIFIED"


@pytest.mark.parametrize(
    "method",
    ["model_copy", "model_construct", "copy", "copy.copy", "copy.deepcopy", "pickle"],
)
def test_verified_session_identity_cannot_be_changed_or_serialized(method: str) -> None:
    session = valid_session()
    claims = session.model_dump()

    with pytest.raises(TypeError):
        if method == "model_copy":
            session.model_copy(update={"agent_id": CREATOR})
        elif method == "model_construct":
            AgentSessionV1.model_construct(**{**claims, "agent_id": CREATOR})
        elif method == "copy":
            session.copy(update={"agent_id": CREATOR})
        elif method == "copy.copy":
            copy.copy(session)
        elif method == "copy.deepcopy":
            copy.deepcopy(session)
        else:
            pickle.dumps(session)

    denied = decide_action(
        "task_cancel",
        session=session,
        actor_id=AGENT,
        task=valid_task(),
    )
    assert session.verified is True
    assert session.agent_id == AGENT
    assert denied.allowed is False
    assert denied.reason_code == "CREATOR_REQUIRED"


@pytest.mark.parametrize("action", ["task_accept", "task_update", "task_cancel", "tool_use"])
def test_offline_bridge_denies_every_effect_action(action: str) -> None:
    health = fresh_health(transport_verified=False)
    task = valid_task()

    result = decide_action(
        action,
        health=health,
        task=task,
        to_state="waiting" if action == "task_update" else None,
        tool_id="research.read" if action == "tool_use" else None,
    )

    assert result.allowed is False
    assert result.next_task is None


@pytest.mark.parametrize("ttl_ms", [1_000, 1_800_000])
def test_handoff_ttl_accepts_inclusive_contract_boundaries(ttl_ms: int) -> None:
    task = valid_task(ttl_ms=ttl_ms)

    assert task.ttl_ms == ttl_ms
    assert task.expires_at_ns == task.created_at_ns + ttl_ms * 1_000_000


@pytest.mark.parametrize("ttl_ms", [999, 1_800_001])
def test_handoff_ttl_rejects_values_outside_contract_bounds(ttl_ms: int) -> None:
    with pytest.raises(OmegaValidationError):
        valid_task(ttl_ms=ttl_ms)


def test_only_assigned_task_owner_can_accept_handoff() -> None:
    task = valid_task()

    accepted = decide_action("task_accept", task=task, actor_id=AGENT)
    rejected = decide_action("task_accept", task=task, actor_id="different-agent")

    assert accepted.allowed is True
    assert accepted.next_task is not None
    assert accepted.next_task.state == "in_progress"
    assert rejected.allowed is False
    assert rejected.next_task is None


def test_only_creator_can_cancel_handoff() -> None:
    task = valid_task()

    cancelled = evaluate_action(
        "task_cancel",
        health=fresh_health(),
        session=valid_session(agent_id=CREATOR),
        manifest=valid_manifest(),
        policy=POLICY,
        now_ns=NOW_NS,
        actor_id=CREATOR,
        task=task,
    )
    rejected = decide_action("task_cancel", task=task, actor_id=AGENT)

    assert cancelled.allowed is True
    assert cancelled.next_task is not None
    assert cancelled.next_task.state == "cancelled"
    assert rejected.allowed is False
    assert rejected.next_task is None


def test_expired_handoff_cannot_be_accepted_or_updated() -> None:
    task = valid_task(created_at_ns=NOW_NS - 5_000_000_000, ttl_ms=1_000)

    accept = decide_action("task_accept", task=task)
    update = decide_action("task_update", task=task, to_state="waiting")

    assert accept.allowed is False
    assert update.allowed is False
    assert accept.next_task is not None
    assert update.next_task is not None
    assert accept.next_task.state == "expired"
    assert update.next_task.state == "expired"


def test_expired_task_cannot_transition_back_to_active() -> None:
    result = decide_action(
        "task_update",
        task=valid_task(state="expired"),
        to_state="in_progress",
    )

    assert result.allowed is False


def test_unknown_task_transition_is_denied() -> None:
    result = decide_action(
        "task_update",
        task=valid_task(state="in_progress"),
        to_state="live_order_placed",
    )

    assert result.allowed is False
    assert result.next_task is None


def test_tool_use_requires_manifest_scope_and_task_allowlist() -> None:
    task = valid_task(state="in_progress", tool_allowlist=("research.read",))

    permitted = decide_action("tool_use", task=task, tool_id="research.read")
    unregistered = decide_action("tool_use", task=task, tool_id="oms.order")
    not_in_task = decide_action(
        "tool_use",
        task=valid_task(state="in_progress", tool_allowlist=()),
        tool_id="research.read",
    )
    pending_task = decide_action(
        "tool_use",
        task=valid_task(state="pending", tool_allowlist=("research.read",)),
        tool_id="research.read",
    )

    assert permitted.allowed is True
    assert unregistered.allowed is False
    assert not_in_task.allowed is False
    assert pending_task.allowed is False


def test_kill_returns_only_typed_halt_request_without_mutating_halt_state() -> None:
    health = fresh_health()
    before = health.model_dump()

    intent = request_kill(
        health,
        request_id="correlation-123",
        now_ns=NOW_NS,
        reason_code="operator_requested",
    )

    assert isinstance(intent, KillSyncIntentV1)
    assert intent.peer_system == PEER
    assert intent.reason_code == "operator_requested"
    assert intent.requested_at_ns == NOW_NS
    assert health.model_dump() == before
    assert health.peer_kill_pending is False
    assert health.peer_killed is False
    assert health.halt_reasons == ()
    assert not any(
        name in type(intent).model_fields
        for name in ("route", "order", "permit", "execute")
    )


def test_pending_halt_request_does_not_grant_actions_or_clear_existing_halt() -> None:
    health = fresh_health(halt_reasons=("risk_halt",), halt_version=3)
    intent = request_kill(
        health,
        request_id="correlation-456",
        now_ns=NOW_NS,
        reason_code="bridge_failure",
    )

    result = evaluate_action(
        "task_accept",
        health=health,
        session=valid_session(),
        manifest=valid_manifest(),
        policy=POLICY,
        now_ns=NOW_NS,
        actor_id=AGENT,
        task=valid_task(),
    )

    assert isinstance(intent, KillSyncIntentV1)
    assert intent.halt_version == 3
    assert result.allowed is False
    assert result.next_task is None


def test_decisions_expose_no_order_route_or_execution_permit() -> None:
    decision = decide_action(
        "tool_use",
        task=valid_task(state="in_progress", tool_allowlist=("research.read",)),
        tool_id="research.read",
    )

    assert isinstance(decision, BridgeDecisionV1)
    assert not any(
        name in type(decision).model_fields
        for name in ("route", "order", "permit", "execution_token")
    )


@pytest.mark.parametrize(
    "order_tool",
    [
        "broker.submit_order",
        "broker.cancel_order",
        "broker.replace_order",
        "broker.close_position",
        "order.place.live",
        "oms.order.submit",
        "trade.execute",
    ],
)
@pytest.mark.parametrize("include_financial_registry", [False, True])
@pytest.mark.parametrize("risk_guard_ok", [False, True])
def test_order_capable_tools_are_never_authorized(
    order_tool: str, include_financial_registry: bool, risk_guard_ok: bool
) -> None:
    manifest = CapabilityManifestV1(
        version="1",
        tools=(order_tool,),
        datasets=(),
        actions=(),
        limits=(),
        financial_tools=(order_tool,) if include_financial_registry else (),
    )
    session = valid_session(manifest, scopes=(f"tool:use.{order_tool}",))
    task = valid_task(state="in_progress", tool_allowlist=(order_tool,))

    decision = evaluate_action(
        "tool_use",
        health=fresh_health(),
        session=session,
        manifest=manifest,
        policy=POLICY,
        now_ns=NOW_NS,
        actor_id=AGENT,
        task=task,
        tool_id=order_tool,
        risk_guard_ok=risk_guard_ok,
    )

    assert decision.allowed is False
