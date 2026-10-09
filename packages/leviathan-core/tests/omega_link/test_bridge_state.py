"""Contract-facing unit checks for the pure OMEGA bridge kernel."""

from __future__ import annotations

import copy
import json
import pickle
from dataclasses import replace
from typing import Any

import pytest

from leviathan_core.omega_link import (
    AgentSessionV1,
    BridgeHealthV1,
    CapabilityManifestV1,
    HandoffTaskV1,
    OmegaPolicyV1,
    OmegaValidationError,
    evaluate_action,
    evaluate_bridge,
    request_kill,
)
from leviathan_core.omega_link.state_models import _from_trusted_adapter

NOW = 1_000_000_000_000
DIGEST = "a" * 64
POLICY = OmegaPolicyV1(version="1", max_heartbeat_age_ns=2_000_000_000)


def _fixture() -> tuple[BridgeHealthV1, AgentSessionV1, CapabilityManifestV1, HandoffTaskV1]:
    manifest = CapabilityManifestV1(version="1", tools=("research.read",))
    health = BridgeHealthV1(
        version="1",
        peer_system="omega",
        transport_verified=True,
        heartbeat_at_ns=NOW - 1_000_000_000,
        heartbeat_expires_ns=NOW + 1_000_000_000,
    )
    session = _from_trusted_adapter(
        session=AgentSessionV1(
            version="1",
            session_id="session1",
            peer_system="omega",
            agent_id="agent1",
            scopes=("tool:use.research.read",),
            manifest_hash=manifest.manifest_hash,
            issued_at_ns=NOW - 1_000_000_000,
            expires_at_ns=NOW + 100_000_000_000,
            action_budget=2,
        )
    )
    task = HandoffTaskV1(
        version="1",
        task_id="task1",
        task_type="research",
        created_by="agent0",
        assigned_to="agent1",
        created_at_ns=NOW - 1_000_000_000,
        ttl_ms=5_000,
        sla_ms=4_000,
        context_hash=DIGEST,
        tool_allowlist=("research.read",),
    )
    return health, session, manifest, task


def test_connected_owner_transition_and_tool_scope() -> None:
    health, session, manifest, task = _fixture()
    accepted = evaluate_action(
        "task_accept",
        health=health,
        session=session,
        manifest=manifest,
        policy=POLICY,
        now_ns=NOW,
        actor_id="agent1",
        task=task,
    )
    assert accepted.allowed and accepted.next_task is not None
    assert accepted.next_task.state == "in_progress"
    assert evaluate_action(
        "tool_use",
        health=health,
        session=session,
        manifest=manifest,
        policy=POLICY,
        now_ns=NOW,
        actor_id="agent1",
        task=accepted.next_task,
        tool_id="research.read",
    ).allowed
    assert not evaluate_action(
        "task_cancel",
        health=health,
        session=session,
        manifest=manifest,
        policy=POLICY,
        now_ns=NOW,
        actor_id="agent1",
        task=accepted.next_task,
    ).allowed


@pytest.mark.parametrize(
    "changes",
    [
        {"transport_verified": False},
        {"heartbeat_expires_ns": NOW},
        {"heartbeat_at_ns": None, "heartbeat_expires_ns": None},
        {"previous_heartbeat_at_ns": NOW},
        {"degraded": True},
    ],
)
def test_bad_health_denies_and_petitions_halt(changes: dict[str, Any]) -> None:
    health, session, manifest, task = _fixture()
    health = BridgeHealthV1.model_validate({**health.model_dump(), **changes})
    decision = evaluate_bridge(health, now_ns=NOW, policy=POLICY)
    assert not decision.allowed
    assert decision.kill_intent is not None
    assert not evaluate_action(
        "task_accept",
        health=health,
        session=session,
        manifest=manifest,
        policy=POLICY,
        now_ns=NOW,
        actor_id="agent1",
        task=task,
    ).allowed


def test_expiry_halt_and_kill_do_not_mutate_authority() -> None:
    health, session, manifest, task = _fixture()
    halt_snapshot = ("sovereign",)
    halted = BridgeHealthV1.model_validate({**health.model_dump(), "halt_reasons": halt_snapshot})
    assert (
        evaluate_action(
            "task_accept",
            health=halted,
            session=session,
            manifest=manifest,
            policy=POLICY,
            now_ns=NOW,
            actor_id="agent1",
            task=task,
        ).reason_code
        == "HALT_ACTIVE"
    )
    expired = evaluate_action(
        "task_accept",
        health=health,
        session=session,
        manifest=manifest,
        policy=POLICY,
        now_ns=task.expires_at_ns,
        actor_id="agent1",
        task=task,
    )
    assert expired.next_task is not None and expired.next_task.state == "expired"
    petition = request_kill(health, request_id="kill1", now_ns=NOW, reason_code="risk")
    assert petition.halt_reason.startswith("omega_kill:")
    assert health.halt_reasons == ()
    assert halted.halt_reasons == halt_snapshot


@pytest.mark.parametrize("ttl_ms", [999, 1_800_001])
def test_ttl_outside_backend_bounds_rejected(ttl_ms: int) -> None:
    *_, task = _fixture()
    with pytest.raises(OmegaValidationError):
        HandoffTaskV1.model_validate({**task.model_dump(), "ttl_ms": ttl_ms})


def test_verified_session_cannot_be_copied_or_reconstructed_for_creator_cancel() -> None:
    health, session, manifest, task = _fixture()
    assert session.verified
    unverified = AgentSessionV1.model_validate(
        {**session.model_dump(), "agent_id": task.created_by}
    )
    assert not unverified.verified
    denied = evaluate_action(
        "task_cancel",
        health=health,
        session=unverified,
        manifest=manifest,
        policy=POLICY,
        now_ns=NOW,
        actor_id=task.created_by,
        task=task,
    )
    assert denied.reason_code == "SESSION_UNVERIFIED"
    with pytest.raises(TypeError):
        session.model_copy(update={"agent_id": task.created_by})
    with pytest.raises(TypeError):
        session.model_copy(update={"verified": "false"})
    with pytest.raises(TypeError):
        AgentSessionV1.model_construct(**session.model_dump())
    with pytest.raises(OmegaValidationError):
        AgentSessionV1.model_validate({**session.model_dump(), "verified": True})
    with pytest.raises(TypeError):
        replace(session, agent_id=task.created_by)


def test_boundary_models_reject_copy_deepcopy_and_pickle() -> None:
    health, session, manifest, task = _fixture()
    for record in (health, session, manifest, task, POLICY):
        with pytest.raises(TypeError):
            copy.copy(record)
        with pytest.raises(TypeError):
            copy.deepcopy(record)
        with pytest.raises(TypeError):
            pickle.dumps(record)
        with pytest.raises(TypeError):
            record.model_copy()
        with pytest.raises(TypeError):
            record.copy()
        with pytest.raises(TypeError):
            type(record).model_construct(**record.model_dump())


def test_heartbeat_age_overrides_claimed_future_expiry() -> None:
    health, *_ = _fixture()
    stale = BridgeHealthV1.model_validate(
        {
            **health.model_dump(),
            "heartbeat_at_ns": NOW - POLICY.max_heartbeat_age_ns - 1,
            "heartbeat_expires_ns": NOW + 100_000_000_000,
        }
    )
    result = evaluate_bridge(stale, now_ns=NOW, policy=POLICY)
    assert not result.allowed and result.bridge_state == "disconnected"
    assert result.kill_intent is not None
    fresh_boundary = BridgeHealthV1.model_validate(
        {
            **health.model_dump(),
            "heartbeat_at_ns": NOW - POLICY.max_heartbeat_age_ns,
        }
    )
    assert evaluate_bridge(fresh_boundary, now_ns=NOW, policy=POLICY).allowed
    with pytest.raises(OmegaValidationError):
        BridgeHealthV1.model_validate(
            {
                **health.model_dump(),
                "heartbeat_at_ns": NOW,
                "heartbeat_expires_ns": NOW - 1,
            }
        )
    with pytest.raises(OmegaValidationError):
        BridgeHealthV1.model_validate({**health.model_dump(), "transport_verified": "false"})
    with pytest.raises(OmegaValidationError):
        OmegaPolicyV1(version="1", max_heartbeat_age_ns=True)
    with pytest.raises(OmegaValidationError):
        OmegaPolicyV1(version="1", max_heartbeat_age_ns=0)
    with pytest.raises(OmegaValidationError):
        OmegaPolicyV1(version="1", max_heartbeat_age_ns=1_800_000_000_001)


def test_broker_submit_order_denied_even_when_unmarked_and_risk_guard_true() -> None:
    health, _, _, task = _fixture()
    manifest = CapabilityManifestV1(version="1", tools=("broker.submit_order",))
    session = _from_trusted_adapter(
        session=AgentSessionV1(
            version="1",
            session_id="order_session",
            peer_system="omega",
            agent_id="agent1",
            scopes=("tool:use.broker.submit_order",),
            manifest_hash=manifest.manifest_hash,
            issued_at_ns=NOW - 1_000_000_000,
            expires_at_ns=NOW + 100_000_000_000,
            action_budget=2,
        )
    )
    active_task = HandoffTaskV1.model_validate(
        {
            **task.model_dump(),
            "state": "in_progress",
            "tool_allowlist": ("broker.submit_order",),
        }
    )
    decision = evaluate_action(
        "tool_use",
        health=health,
        session=session,
        manifest=manifest,
        policy=POLICY,
        now_ns=NOW,
        actor_id="agent1",
        task=active_task,
        tool_id="broker.submit_order",
        risk_guard_ok=True,
    )
    assert not decision.allowed and decision.reason_code == "TOOL_DENIED"


def test_kill_reason_key_does_not_confuse_peer_and_tool_delimiters() -> None:
    health, *_ = _fixture()
    first = BridgeHealthV1.model_validate({**health.model_dump(), "peer_system": "a:b"})
    second = BridgeHealthV1.model_validate({**health.model_dump(), "peer_system": "a"})
    first_intent = request_kill(
        first, request_id="kill1", now_ns=NOW, reason_code="risk", tool_id="c"
    )
    second_intent = request_kill(
        second, request_id="kill2", now_ns=NOW, reason_code="risk", tool_id="b:c"
    )
    assert first_intent.halt_reason != second_intent.halt_reason


@pytest.mark.parametrize(
    "create",
    [
        lambda data: BridgeHealthV1(**data),
        BridgeHealthV1.model_validate,
        lambda data: BridgeHealthV1.model_validate_json(json.dumps(data)),
        BridgeHealthV1.model_validate_strings,
    ],
)
def test_invalid_input_never_appears_in_public_error_views(create: Any) -> None:
    health, *_ = _fixture()
    canary = "SECRET bad id"
    with pytest.raises(OmegaValidationError) as caught:
        create({**health.model_dump(), "peer_system": canary})
    error = caught.value
    assert error.code == "OMEGA_INVALID_INPUT"
    assert error.loc == ("peer_system",)
    assert set(error.errors()[0]) == {"code", "loc", "type"}
    for view in (str(error), repr(error.args), repr(error.errors()), error.json()):
        assert canary not in view
    assert error.__context__ is None


def test_unknown_extra_field_name_is_redacted() -> None:
    health, *_ = _fixture()
    canary = "SECRET_field_name"
    with pytest.raises(OmegaValidationError) as caught:
        BridgeHealthV1.model_validate({**health.model_dump(), canary: "secret value"})
    error = caught.value
    assert error.loc == ("unknown_field",)
    for view in (str(error), repr(error.args), repr(error.errors()), error.json()):
        assert canary not in view
        assert "secret value" not in view


def test_frozen_mutation_errors_never_echo_values_or_unknown_field_names() -> None:
    health, *_ = _fixture()
    canary = "SECRET_CANARY"
    operations = (
        lambda: setattr(health, "peer_system", canary),
        lambda: setattr(health, canary, canary),
        lambda: delattr(health, "peer_system"),
        lambda: delattr(health, canary),
    )
    for operation, expected_loc in zip(
        operations,
        (("peer_system",), ("unknown_field",), ("peer_system",), ("unknown_field",)),
        strict=True,
    ):
        with pytest.raises(OmegaValidationError) as caught:
            operation()
        error = caught.value
        assert error.code == "OMEGA_FROZEN_RECORD"
        assert error.error_type == "frozen_instance"
        assert error.loc == expected_loc
        assert set(error.errors()[0]) == {"code", "loc", "type"}
        assert error.__context__ is None
        for view in (str(error), repr(error.args), repr(error.errors()), error.json()):
            assert canary not in view
    assert health.peer_system == "omega"
