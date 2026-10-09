"""Independent acceptance for durable, peer-isolated OMEGA task storage."""

from __future__ import annotations

import asyncio
import copy
import hashlib
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from leviathan_store.engine import (
    create_engine_and_sessionmaker,
    create_sync_engine_and_sessionmaker,
    init_schema,
    init_sync_schema,
)
from leviathan_store.omega_due_queue import OmegaDueQueueStore
from leviathan_store.tables import OmegaTaskRow, StoreBase
from sqlalchemy import inspect, text, update

from leviathan_core.agent_council.model_policy import (
    AgentModelPolicyV1,
    AIRequestV1,
    RouteUsageV1,
    ScopePrivacyV1,
)
from leviathan_core.agent_council.model_registry import (
    ModelCapabilityV1,
    ModelRegistryEntryV1,
    ModelRegistryV1,
)
from leviathan_core.agent_council.model_router import RouteDecisionV1, route_model
from leviathan_core.execution.order_models import LedgerIntegrityKey
from leviathan_core.mcp_control.policy_models import PolicyDecisionV1
from leviathan_core.numeric import canonical_json
from leviathan_core.omega_link.state_models import HandoffTaskV1
from leviathan_core.omega_link.task_bridge import (
    IDEMPOTENCY_RETENTION_NS,
    TaskBridgeError,
    issue_task_record,
    require_task_record,
    revise_task_record,
)

_NOW_NS = 10_000_000_000
_ROUTE_NOW_NS = 1_000
_PEER = "peer.alpha"
_AGENT = "agent.alpha"
_TOOL = "research.read"
_KEY = LedgerIntegrityKey(b"independent-omega-due-acceptance-key-material")


class _SyntheticTrust:
    def principal_decision(self, _request: AIRequestV1) -> object:
        from leviathan_core.security.authz_models import (
            AuthorizationDecisionV1,
            AuthorizationExplanationV1,
            EffectV1,
            ReasonCodeV1,
        )

        return AuthorizationDecisionV1(
            AuthorizationExplanationV1(
                rule_id=None,
                decision=EffectV1.ALLOW,
                reason_code=ReasonCodeV1.AUTHORIZED,
            )
        )

    def tool_decision(self, _request: AIRequestV1, _tool_name: str) -> PolicyDecisionV1:
        return PolicyDecisionV1(
            allowed=True,
            effect_allowed=False,
            status="approved",
            reason_codes=("SYNTHETIC_ALLOW",),
        )

    def usage_is_verified(self, _request: AIRequestV1, _usage: RouteUsageV1) -> bool:
        return True

    def evaluation_time_ns(self, request: AIRequestV1) -> int:
        return request.at_ns

    def credential_is_bound(self, _request: AIRequestV1, _credential_ref: str) -> bool:
        return True


def _route() -> RouteDecisionV1:
    capability = ModelCapabilityV1(
        modalities=("text",),
        tools=(_TOOL,),
        output_schemas=("answer@v1",),
        structured_output=True,
        max_context_tokens=1_000,
        max_output_tokens=100,
        quality_class="advanced",
        privacy_class="restricted",
    )
    entry = ModelRegistryEntryV1(
        entry_id="entry.acceptance",
        alias="analyst",
        provider="gpt",
        model_id="gpt.synthetic",
        model_version="v1",
        registry_version="v1",
        capability=capability,
        supported_regions=("us-test",),
        approved=True,
        available=True,
        available_from_ns=1,
        available_until_ns=10_000,
        credential_name="SYNTHETIC_KEY",
        input_cost_per_million_tokens_usd=Decimal("1"),
        output_cost_per_million_tokens_usd=Decimal("2"),
        cost_class="low",
        latency_class="low",
        latency_reservation_ns=10,
    )
    policy = AgentModelPolicyV1(
        version="v1",
        agent_id=_AGENT,
        project_id="leviathan-ai",
        environment="development",
        allowed_aliases=("analyst",),
        allowed_providers=("gpt",),
        allowed_tools=(_TOOL,),
        allowed_data_scopes=("research",),
        scope_privacy_classes=(ScopePrivacyV1(scope="research", min_privacy_class="internal"),),
        allowed_output_schemas=("answer@v1",),
        allowed_regions=("us-test",),
        fallback_aliases=(),
        min_quality_class="standard",
        min_privacy_class="internal",
        max_latency_class="low",
        max_cost_class="low",
        max_context_tokens=1_000,
        max_calls=3,
        max_tokens=100,
        max_elapsed_ns=100,
        max_cost_usd=Decimal("0.000010"),
        max_attempts=2,
    )
    request = AIRequestV1(
        request_id="route.acceptance",
        agent_id=_AGENT,
        project_id="leviathan-ai",
        environment="development",
        alias="analyst",
        task_type="analysis",
        data_scope="research",
        modality="text",
        output_schema="answer@v1",
        required_tools=(_TOOL,),
        input_tokens=3,
        output_tokens=2,
        min_quality_class="standard",
        privacy_class="internal",
        max_latency_class="low",
        prompt_version="v1",
        at_ns=_ROUTE_NOW_NS,
        region="us-test",
    )
    route = route_model(
        request,
        policy,
        ModelRegistryV1(version="v1", entries=(entry,)),
        RouteUsageV1(
            snapshot_revision=1,
            calls_used=0,
            tokens_used=0,
            elapsed_ns=0,
            cost_spent_usd=Decimal("0"),
        ),
        _SyntheticTrust(),
    )
    assert type(route) is RouteDecisionV1
    return route


def _record(
    *,
    peer_system: str = _PEER,
    task_id: str = "task.alpha",
    created_at_ns: int = _NOW_NS,
    ttl_ms: int = 1_000,
    sla_ms: int = 500,
    state: str = "pending",
    requires_risk_guard: bool = False,
) -> Any:
    context = canonical_json({"question": "synthetic task for acceptance"})
    task = HandoffTaskV1(
        version="1",
        task_id=task_id,
        task_type="analysis",
        created_by=_AGENT,
        assigned_to="agent.worker",
        state=state,
        created_at_ns=created_at_ns,
        ttl_ms=ttl_ms,
        sla_ms=sla_ms,
        context_hash=hashlib.sha256(context).hexdigest(),
        tool_allowlist=(_TOOL,),
        audit_ref="audit.acceptance",
    )
    return issue_task_record(
        peer_system=peer_system,
        task=task,
        priority="normal",
        requires_risk_guard=requires_risk_guard,
        context_payload=context,
        model_route=_route(),
    )


@pytest.fixture
def database(tmp_path: Path):
    path = tmp_path / "omega-acceptance.sqlite"
    engine, sessions = create_sync_engine_and_sessionmaker(f"sqlite:///{path}")
    init_sync_schema(engine)
    yield {
        "engine": engine,
        "sessions": sessions,
        "path": path,
        "store": OmegaDueQueueStore(sessions, key=_KEY),
    }
    engine.dispose()


def _create(
    store: OmegaDueQueueStore,
    record: Any,
    *,
    idempotency_key: str | None = None,
    request_digest: str | None = None,
) -> Any:
    return store.create(
        peer_system=record.peer_system,
        record=record,
        idempotency_key=idempotency_key or f"idem.{record.task.task_id}",
        request_digest=request_digest or hashlib.sha256(record.task.task_id.encode()).hexdigest(),
        idempotency_expires_at_ns=_NOW_NS + IDEMPOTENCY_RETENTION_NS,
    )


def _assert_store_unavailable(error: TaskBridgeError) -> None:
    assert error.code == "TASK_STORE_UNAVAILABLE"
    assert str(error) == "TASK_STORE_UNAVAILABLE"
    assert error.args == ("TASK_STORE_UNAVAILABLE",)


def test_async_schema_initializer_registers_the_due_table(tmp_path: Path) -> None:
    path = tmp_path / "omega-async-schema.sqlite"
    engine, _ = create_engine_and_sessionmaker(f"sqlite+aiosqlite:///{path}")
    try:
        asyncio.run(init_schema(engine))
        sync_engine, _ = create_sync_engine_and_sessionmaker(f"sqlite:///{path}")
        try:
            assert "omega_tasks" in inspect(sync_engine).get_table_names()
        finally:
            sync_engine.dispose()
    finally:
        asyncio.run(engine.dispose())


def test_schema_registration_and_idempotent_create_get(database: dict[str, Any]) -> None:
    assert "omega_tasks" in StoreBase.metadata.tables
    assert "omega_tasks" in inspect(database["engine"]).get_table_names()

    record = _record()
    created = _create(database["store"], record)
    assert created.disposition == "created"
    assert created.record is not None
    assert require_task_record(created.record).task.task_id == record.task.task_id

    duplicate = _create(database["store"], _record())
    assert duplicate.disposition == "duplicate"
    assert duplicate.record is not None
    assert database["store"].get_task(_PEER, record.task.task_id).task == record.task
    assert database["store"].get_task("peer.other", record.task.task_id) is None

    conflict = _create(
        database["store"],
        _record(task_id="task.conflict"),
        idempotency_key=f"idem.{record.task.task_id}",
        request_digest="b" * 64,
    )
    assert conflict.disposition == "conflict"
    assert conflict.record is not None
    assert conflict.record.task.task_id == record.task.task_id


def test_due_query_is_peer_scoped_bounded_and_deterministically_ordered(
    database: dict[str, Any],
) -> None:
    own_later_id = _record(task_id="task.z", created_at_ns=_NOW_NS - 2_000_000_000)
    own_earlier_id = _record(task_id="task.a", created_at_ns=_NOW_NS - 2_000_000_000)
    foreign_earliest = _record(
        peer_system="peer.foreign",
        task_id="task.foreign",
        created_at_ns=_NOW_NS - 4_000_000_000,
    )
    sla_only = _record(
        task_id="task.sla",
        created_at_ns=_NOW_NS - 700_000_000,
        state="in_progress",
    )
    still_future = _record(task_id="task.future", created_at_ns=_NOW_NS)
    terminal = _record(
        task_id="task.terminal",
        created_at_ns=_NOW_NS - 4_000_000_000,
        state="failed",
    )
    for record in (
        own_later_id,
        own_earlier_id,
        foreign_earliest,
        sla_only,
        still_future,
        terminal,
    ):
        _create(database["store"], record)

    page = database["store"].list_due_for_peer(
        peer_system=_PEER, now_ns=_NOW_NS, limit=2
    )
    assert [item.task.task_id for item in page] == ["task.a", "task.z"]
    assert all(item.peer_system == _PEER for item in page)

    due = database["store"].list_due_for_peer(
        peer_system=_PEER, now_ns=_NOW_NS + 600_000_000, limit=10
    )
    assert [item.task.task_id for item in due] == ["task.a", "task.z", "task.sla"]
    global_due = database["store"].list_due(now_ns=_NOW_NS, limit=10)
    assert [item.task.task_id for item in global_due] == [
        "task.foreign",
        "task.a",
        "task.z",
        "task.sla",
    ]


def test_replace_is_revision_compare_and_swap(database: dict[str, Any]) -> None:
    original = _record()
    _create(database["store"], original)
    updated_task = HandoffTaskV1.model_validate(
        {**original.task.model_dump(mode="json"), "state": "in_progress"}
    )
    accepted = revise_task_record(prior=original, task=updated_task)
    stale_competitor = revise_task_record(prior=original, task=original.task)

    assert database["store"].replace_task(
        peer_system=_PEER,
        task_id=original.task.task_id,
        expected_revision=1,
        record=accepted,
    ) is True
    assert database["store"].replace_task(
        peer_system=_PEER,
        task_id=original.task.task_id,
        expected_revision=1,
        record=stale_competitor,
    ) is False
    current = database["store"].get_task(_PEER, original.task.task_id)
    assert current is not None
    assert (current.revision, current.task.state) == (2, "in_progress")


@pytest.mark.parametrize("field", ["risk_guard", "model_route", "revision", "peer", "due_time"])
def test_direct_sql_mutation_fails_with_fixed_error(
    database: dict[str, Any], field: str
) -> None:
    record = _record()
    _create(database["store"], record)
    with database["sessions"].begin() as session:
        row = session.get(OmegaTaskRow, (_PEER, record.task.task_id))
        assert row is not None
        if field in {"risk_guard", "model_route", "due_time"}:
            payload = copy.deepcopy(row.payload)
            if field == "risk_guard":
                payload["requires_risk_guard"] = True
            elif field == "model_route":
                payload["model_route_json"] += " "
            else:
                payload["task"]["ttl_ms"] += 1
                row.expires_at_ns += 1_000_000
                row.sla_due_at_ns += 1_000_000
            values = {"payload": payload}
            if field == "due_time":
                values["expires_at_ns"] = row.expires_at_ns
                values["sla_due_at_ns"] = row.sla_due_at_ns
            session.execute(
                update(OmegaTaskRow)
                .where(
                    OmegaTaskRow.peer_system == _PEER,
                    OmegaTaskRow.task_id == record.task.task_id,
                )
                .values(**values)
            )
        elif field == "revision":
            row.revision += 1
        else:
            payload = copy.deepcopy(row.payload)
            payload["peer_system"] = "peer.attacker"
            row.peer_system = "peer.attacker"
            row.payload = payload

    lookup_peer = "peer.attacker" if field == "peer" else _PEER
    with pytest.raises(TaskBridgeError) as failure:
        database["store"].get_task(lookup_peer, record.task.task_id)
    _assert_store_unavailable(failure.value)


def test_copied_row_wrong_key_and_page_corruption_fail_without_partial_results(
    database: dict[str, Any],
) -> None:
    first = _record(task_id="task.a", created_at_ns=_NOW_NS - 3_000_000_000)
    second = _record(task_id="task.b", created_at_ns=_NOW_NS - 2_000_000_000)
    _create(database["store"], first)
    _create(database["store"], second)

    with database["sessions"].begin() as session:
        row = session.get(OmegaTaskRow, (_PEER, second.task.task_id))
        assert row is not None
        session.add(
            OmegaTaskRow(
                peer_system="peer.attacker",
                task_id=row.task_id,
                state=row.state,
                expires_at_ns=row.expires_at_ns,
                sla_due_at_ns=row.sla_due_at_ns,
                revision=row.revision,
                payload={**copy.deepcopy(row.payload), "peer_system": "peer.attacker"},
                row_hmac=row.row_hmac,
                idempotency_key=row.idempotency_key,
                request_digest=row.request_digest,
                idempotency_expires_at_ns=row.idempotency_expires_at_ns,
            )
        )

    with pytest.raises(TaskBridgeError) as copied:
        database["store"].get_task("peer.attacker", second.task.task_id)
    _assert_store_unavailable(copied.value)

    wrong_key_store = OmegaDueQueueStore(
        database["sessions"], key=LedgerIntegrityKey(b"wrong-independent-omega-integrity-key")
    )
    with pytest.raises(TaskBridgeError) as wrong_key:
        wrong_key_store.get_task(_PEER, first.task.task_id)
    _assert_store_unavailable(wrong_key.value)

    with database["sessions"].begin() as session:
        row = session.get(OmegaTaskRow, (_PEER, second.task.task_id))
        assert row is not None
        row.revision += 1
    with pytest.raises(TaskBridgeError) as page_error:
        database["store"].list_due_for_peer(
            peer_system=_PEER, now_ns=_NOW_NS, limit=10
        )
    _assert_store_unavailable(page_error.value)


def test_reopen_with_correct_key_restores_sealed_record(database: dict[str, Any]) -> None:
    record = _record(requires_risk_guard=True)
    _create(database["store"], record)
    database["engine"].dispose()

    reopened_engine, reopened_sessions = create_sync_engine_and_sessionmaker(
        f"sqlite:///{database['path']}"
    )
    try:
        init_sync_schema(reopened_engine)
        restored = OmegaDueQueueStore(reopened_sessions, key=_KEY).get_task(
            _PEER, record.task.task_id
        )
        assert restored is not None
        assert require_task_record(restored) is restored
        assert restored.model_dump(mode="json") == record.model_dump(mode="json")
        assert restored.context_payload == record.context_payload
    finally:
        reopened_engine.dispose()


def test_insert_failure_rolls_back_without_partial_task(database: dict[str, Any]) -> None:
    record = _record(task_id="task.rollback")
    with database["engine"].begin() as connection:
        connection.execute(
            text(
                "CREATE TRIGGER reject_acceptance_task BEFORE INSERT ON omega_tasks "
                "WHEN NEW.task_id = 'task.rollback' BEGIN SELECT RAISE(ABORT, 'synthetic'); END"
            )
        )
    with pytest.raises(TaskBridgeError) as failure:
        _create(database["store"], record)
    _assert_store_unavailable(failure.value)
    assert database["store"].get_task(_PEER, record.task.task_id) is None

    with database["engine"].begin() as connection:
        connection.execute(text("DROP TRIGGER reject_acceptance_task"))
    assert _create(database["store"], record).disposition == "created"

