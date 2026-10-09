"""Transactional durability and integrity tests for the OMEGA task store."""

from __future__ import annotations

import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
from pathlib import Path
from threading import Barrier
from types import SimpleNamespace
from typing import Any

import pytest
from leviathan_store.engine import (
    create_sync_engine_and_sessionmaker,
    init_sync_schema,
)
from leviathan_store.omega_due_queue import OmegaDueQueueStore
from leviathan_store.tables import OmegaTaskRow
from sqlalchemy import select, text, update

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
    require_task_create_result,
    restore_task_record,
    revise_task_record,
)
from leviathan_core.security.authz_models import (
    AuthorizationDecisionV1,
    AuthorizationExplanationV1,
    EffectV1,
    ReasonCodeV1,
)

_NOW_NS = 10_000_000_000
_ROUTE_NOW_NS = 1_000
_PEER = "peer.alpha"
_AGENT = "agent.alpha"
_TOOL = "tool.read"
_KEY_MATERIAL = b"omega-due-store-test-integrity-key-material"


class _Trust:
    def principal_decision(self, request: AIRequestV1) -> object:
        return AuthorizationDecisionV1(
            AuthorizationExplanationV1(
                rule_id=None,
                decision=EffectV1.ALLOW,
                reason_code=ReasonCodeV1.AUTHORIZED,
            )
        )

    def tool_decision(self, request: AIRequestV1, tool_name: str) -> object:
        return PolicyDecisionV1(
            allowed=True,
            effect_allowed=False,
            status="approved",
            reason_codes=("FIXTURE_ALLOW",),
        )

    def usage_is_verified(self, request: AIRequestV1, usage: RouteUsageV1) -> object:
        return True

    def evaluation_time_ns(self, request: AIRequestV1) -> object:
        return request.at_ns

    def credential_is_bound(self, request: AIRequestV1, credential_ref: str) -> object:
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
        entry_id="entry.primary",
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
        credential_name="GPT_FIXTURE_KEY",
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
        request_id="request.fixture",
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
    result = route_model(
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
        _Trust(),
    )
    assert type(result) is RouteDecisionV1
    return result


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
    payload = canonical_json({"question": "synthetic question"})
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
        context_hash=hashlib.sha256(payload).hexdigest(),
        tool_allowlist=(_TOOL,),
        audit_ref="audit.synthetic",
    )
    return issue_task_record(
        peer_system=peer_system,
        task=task,
        priority="normal",
        requires_risk_guard=requires_risk_guard,
        context_payload=payload,
        model_route=_route(),
    )


@pytest.fixture
def database(tmp_path: Path):
    engine, sessions = create_sync_engine_and_sessionmaker(
        f"sqlite:///{tmp_path / 'omega-due.db'}"
    )
    init_sync_schema(engine)
    key = LedgerIntegrityKey(_KEY_MATERIAL)
    yield SimpleNamespace(
        engine=engine,
        sessions=sessions,
        key=key,
        store=OmegaDueQueueStore(sessions, key=key),
    )
    engine.dispose()


def _create(
    store: OmegaDueQueueStore,
    record: Any,
    *,
    key: str = "idem.alpha",
    digest: str = "a" * 64,
    expires_at_ns: int = _NOW_NS + IDEMPOTENCY_RETENTION_NS,
):
    return require_task_create_result(
        store.create(
            peer_system=record.peer_system,
            record=record,
            idempotency_key=key,
            request_digest=digest,
            idempotency_expires_at_ns=expires_at_ns,
        )
    )


def test_create_idempotency_peer_isolation_and_reopen_round_trip(database: Any, tmp_path: Path):
    created = _create(database.store, _record())
    assert created.disposition == "created"
    assert created.record is not None
    assert created.record.task.task_id == "task.alpha"
    assert _create(database.store, _record()).disposition == "duplicate"

    conflict = _create(
        database.store,
        _record(task_id="task.other"),
        digest="b" * 64,
    )
    assert conflict.disposition == "conflict"
    assert conflict.record is not None and conflict.record.task.task_id == "task.alpha"
    assert database.store.get_task("peer.other", "task.alpha") is None

    database.engine.dispose()
    reopened_engine, reopened_sessions = create_sync_engine_and_sessionmaker(
        f"sqlite:///{tmp_path / 'omega-due.db'}"
    )
    init_sync_schema(reopened_engine)
    reopened = OmegaDueQueueStore(reopened_sessions, key=database.key)
    restored = reopened.get_task(_PEER, "task.alpha")
    assert restored is not None
    assert restored.task.task_id == "task.alpha"
    assert restored.requires_risk_guard is False
    assert restored.context_payload == canonical_json({"question": "synthetic question"})
    assert reopened.list_due_for_peer(
        peer_system=_PEER, now_ns=_NOW_NS + 2_000_000_000, limit=10
    ) == (restored,)
    reopened_engine.dispose()


def test_expired_idempotency_key_can_be_reused_without_replacing_prior_task(database: Any):
    first = _record(task_id="task.first")
    second = _record(task_id="task.second")
    assert _create(database.store, first, key="idem.reuse").disposition == "created"
    later_expiry = _NOW_NS + 2 * IDEMPOTENCY_RETENTION_NS
    assert (
        _create(
            database.store,
            second,
            key="idem.reuse",
            digest="b" * 64,
            expires_at_ns=later_expiry,
        ).disposition
        == "created"
    )
    assert database.store.get_task(_PEER, "task.first") is not None
    assert database.store.get_task(_PEER, "task.second") is not None


def test_peer_filter_is_applied_before_bounded_due_limit(database: Any):
    own_early = _record(task_id="task.own.early", created_at_ns=_NOW_NS - 3_000_000_000)
    own_later = _record(task_id="task.own.later", created_at_ns=_NOW_NS - 2_000_000_000)
    foreign = _record(
        peer_system="peer.foreign",
        task_id="task.foreign.early",
        created_at_ns=_NOW_NS - 4_000_000_000,
    )
    _create(database.store, own_early, key="idem.own.early")
    _create(database.store, own_later, key="idem.own.later")
    _create(database.store, foreign, key="idem.foreign")
    result = database.store.list_due_for_peer(
        peer_system=_PEER, now_ns=_NOW_NS, limit=1
    )
    assert [record.task.task_id for record in result] == ["task.own.early"]
    assert all(record.peer_system == _PEER for record in result)
    global_records = database.store.list_due(now_ns=_NOW_NS, limit=10)
    assert [record.task.task_id for record in global_records] == [
        "task.foreign.early",
        "task.own.early",
        "task.own.later",
    ]


def test_replace_uses_revision_compare_and_swap(database: Any):
    original = _record()
    _create(database.store, original)
    accepted_task = HandoffTaskV1.model_validate(
        {**original.task.model_dump(mode="json"), "state": "in_progress"}
    )
    accepted = revise_task_record(prior=original, task=accepted_task)
    competing_task = HandoffTaskV1.model_validate(
        {**original.task.model_dump(mode="json"), "state": "failed"}
    )
    competing = revise_task_record(prior=original, task=competing_task)
    assert database.store.replace_task(
        peer_system=_PEER,
        task_id=original.task.task_id,
        expected_revision=1,
        record=accepted,
    ) is True
    assert database.store.replace_task(
        peer_system=_PEER,
        task_id=original.task.task_id,
        expected_revision=1,
        record=competing,
    ) is False
    current = database.store.get_task(_PEER, original.task.task_id)
    assert current is not None and current.task.state == "in_progress"
    assert current.revision == 2


def test_racing_replacements_commit_at_most_one_revision(database: Any):
    original = _record()
    _create(database.store, original)
    candidates = tuple(
        revise_task_record(
            prior=original,
            task=HandoffTaskV1.model_validate(
                {**original.task.model_dump(mode="json"), "state": state}
            ),
        )
        for state in ("in_progress", "failed")
    )
    barrier = Barrier(3)

    def replace(candidate: Any) -> bool:
        barrier.wait()
        return database.store.replace_task(
            peer_system=_PEER,
            task_id=original.task.task_id,
            expected_revision=1,
            record=candidate,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(replace, candidate) for candidate in candidates]
        barrier.wait()
        outcomes = [future.result() for future in futures]
    assert outcomes.count(True) == 1
    assert outcomes.count(False) == 1
    current = database.store.get_task(_PEER, original.task.task_id)
    assert current is not None and current.revision == 2


@pytest.mark.parametrize(
    "column, mutation",
    [
        ("risk", "payload"),
        ("route", "payload"),
        ("revision", "column"),
        ("peer", "column"),
        ("expiry", "column"),
    ],
)
def test_hmac_detects_direct_record_and_index_mutation(
    database: Any, column: str, mutation: str
):
    record = _record()
    _create(database.store, record)
    with database.sessions.begin() as session:
        row = session.get(OmegaTaskRow, (_PEER, record.task.task_id))
        assert row is not None
        if mutation == "payload":
            payload = json.loads(json.dumps(row.payload))
            if column == "risk":
                payload["requires_risk_guard"] = True
            else:
                payload["model_route_json"] = "{}"
            session.execute(
                update(OmegaTaskRow)
                .where(
                    OmegaTaskRow.peer_system == _PEER,
                    OmegaTaskRow.task_id == record.task.task_id,
                )
                .values(payload=payload)
            )
        elif column == "revision":
            row.revision = 2
        elif column == "peer":
            row.peer_system = "peer.attacker"
        else:
            row.expires_at_ns += 1
    lookup_peer = "peer.attacker" if column == "peer" else _PEER
    with pytest.raises(TaskBridgeError) as failure:
        database.store.get_task(lookup_peer, record.task.task_id)
    assert (failure.value.code, str(failure.value), failure.value.args) == (
        "TASK_STORE_UNAVAILABLE",
        "TASK_STORE_UNAVAILABLE",
        ("TASK_STORE_UNAVAILABLE",),
    )


def test_cross_peer_row_copy_and_wrong_key_fail_closed(database: Any):
    record = _record()
    _create(database.store, record)
    with database.sessions.begin() as session:
        row = session.get(OmegaTaskRow, (_PEER, record.task.task_id))
        assert row is not None
        session.add(
            OmegaTaskRow(
                peer_system="peer.attacker",
                task_id=row.task_id,
                state=row.state,
                expires_at_ns=row.expires_at_ns,
                sla_due_at_ns=row.sla_due_at_ns,
                revision=row.revision,
                payload=row.payload,
                row_hmac=row.row_hmac,
                idempotency_key=None,
                request_digest=None,
                idempotency_expires_at_ns=None,
            )
        )
    wrong_key = LedgerIntegrityKey(b"wrong-omega-due-store-key-material-value")
    wrong_store = OmegaDueQueueStore(database.sessions, key=wrong_key)
    for store, peer in (
        (database.store, "peer.attacker"),
        (wrong_store, _PEER),
    ):
        with pytest.raises(TaskBridgeError) as failure:
            store.get_task(peer, record.task.task_id)
        assert failure.value.code == "TASK_STORE_UNAVAILABLE"


def test_due_page_fails_as_a_whole_on_corrupt_row(database: Any):
    records = (_record(task_id="task.a"), _record(task_id="task.b"))
    for index, record in enumerate(records):
        _create(database.store, record, key=f"idem.{index}")
    with database.sessions.begin() as session:
        row = session.get(OmegaTaskRow, (_PEER, "task.b"))
        assert row is not None
        row.sla_due_at_ns += 1
    with pytest.raises(TaskBridgeError, match="TASK_STORE_UNAVAILABLE"):
        database.store.list_due_for_peer(
            peer_system=_PEER, now_ns=_NOW_NS + 2_000_000_000, limit=10
        )


def test_restore_factory_revalidates_context_route_and_record_fields():
    record = _record()
    common = {
        "peer_system": record.peer_system,
        "task": record.task,
        "priority": record.priority,
        "requires_risk_guard": record.requires_risk_guard,
        "context_payload_hex": record.context_payload_hex,
        "model_route_json": record.model_route_json,
        "revision": record.revision,
    }
    malicious_payload = canonical_json({"question": "sk_live_synthetic_secret"})
    malicious_task = HandoffTaskV1.model_validate(
        {
            **record.task.model_dump(mode="json"),
            "context_hash": hashlib.sha256(malicious_payload).hexdigest(),
        }
    )
    route_data = json.loads(record.model_route_json)
    route_data["agent_id"] = "agent.foreign"
    cases = (
        {**common, "priority": "emergency"},
        {**common, "context_payload_hex": malicious_payload.hex(), "task": malicious_task},
        {**common, "model_route_json": "{}"},
        {
            **common,
            "model_route_json": canonical_json(route_data).decode("ascii"),
        },
        {**common, "revision": True},
    )
    for fields in cases:
        with pytest.raises(TaskBridgeError) as failure:
            restore_task_record(**fields)
        assert failure.value.code == "TASK_STORE_UNAVAILABLE"
        assert "sk_live_synthetic_secret" not in str(failure.value)
        assert "sk_live_synthetic_secret" not in repr(failure.value.args)


def test_failed_insert_rolls_back_without_partial_task(database: Any):
    with database.sessions.begin() as session:
        session.execute(
            text(
                "CREATE TRIGGER reject_omega_task BEFORE INSERT ON omega_tasks "
                "BEGIN SELECT RAISE(ABORT, 'synthetic write failure'); END"
            )
        )
    record = _record()
    with pytest.raises(TaskBridgeError) as failure:
        _create(database.store, record)
    assert failure.value.code == "TASK_STORE_UNAVAILABLE"
    with database.sessions() as session:
        assert session.scalar(select(OmegaTaskRow.task_id)) is None
