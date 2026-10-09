from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from leviathan_store.migrations.risk_limits_v1 import migrate_risk_limits_v1
from leviathan_store.risk_limit_events import (
    RiskLimitEventStore,
    RiskLimitEventStoreError,
    _hash_event,
    risk_audit_events,
    risk_audit_head,
)
from sqlalchemy import insert, update
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from leviathan_core.reporting import risk_evidence_chain
from leviathan_core.reporting.risk_evidence_chain import (
    RiskAuditChainDiagnosticV1,
    RiskAuditChainProvenanceV1,
    RiskAuditChainVerificationV1,
    RiskEvidenceChainError,
    require_risk_audit_chain_verification,
    verify_risk_audit_segment,
)
from leviathan_core.risk_limits.approval import SoftApprovalPolicyV1
from leviathan_core.risk_limits.audit_port import (
    RISK_AUDIT_GENESIS_HASH,
    RiskAuditEventV1,
    _issue_event,
    risk_audit_event_hash,
)
from leviathan_core.security.authz_models import (
    AuthorizationPolicyV1,
    EffectV1,
    PolicyRuleV1,
)

_DECISION = "dec_0123456789ab"
_FOREIGN = "dec_abcdef012345"
_ZERO = "0" * 64
_NOW = datetime(2026, 10, 6, 12, 0, tzinfo=UTC)


class _MigrationWriterGuard:
    async def acquire(self, _writer_name: str) -> bool:
        return True

    async def release(self, _writer_name: str) -> None:
        return None


def _store_authorization_policy() -> AuthorizationPolicyV1:
    return AuthorizationPolicyV1(
        version="v1",
        project_id="chain-acceptance-project",
        expires_at=datetime(2035, 1, 1, tzinfo=UTC),
        rules=(
            PolicyRuleV1(
                rule_id="chain-acceptance-deny",
                effect=EffectV1.DENY,
                roles=("synthetic",),
                actions=("risk:limits:read",),
                resources=("acct_synthetic_001",),
                env="test",
                not_before=datetime(2020, 1, 1, tzinfo=UTC),
                not_after=datetime(2035, 1, 1, tzinfo=UTC),
                portfolio="acct_synthetic_001",
            ),
        ),
    )


def _event(
    *,
    sequence: int,
    correlation_id: str,
    action: str,
    predecessor_hash: str,
    invalid_hash: bool = False,
    scope: str | None = None,
) -> RiskAuditEventV1:
    values: dict[str, object] = {
        "sequence": sequence,
        "event_id": _ZERO,
        "correlation_id": correlation_id,
        "attempt_id": f"attempt-{sequence}",
        "actor_ref": "a" * 64,
        "action": action,
        "decision": "RECORDED",
        "reason_code": "SYNTHETIC_ACCEPTANCE",
        "environment": "test",
        "account_id": "acct_synthetic_001",
        "scope": (
            scope
            if scope is not None
            else ("ACCOUNT" if action == "LIMIT_POLICY_CHANGE" else "ORDER")
        ),
        "before_digest": None,
        "after_digest": None,
        "source_event_ids": (),
        "recorded_at_ns": 1_800_000_000_000_000_000 + sequence,
        "predecessor_hash": predecessor_hash,
        "event_hash": _ZERO,
    }
    draft = _issue_event(**values)
    digest = risk_audit_event_hash(draft, predecessor_hash)
    values["event_id"] = digest
    values["event_hash"] = "f" * 64 if invalid_hash else digest
    return _issue_event(**values)


def _valid_chain() -> tuple[RiskAuditEventV1, ...]:
    events: list[RiskAuditEventV1] = []
    predecessor = RISK_AUDIT_GENESIS_HASH
    for sequence, correlation_id, action in (
        (1, _FOREIGN, "LIMIT_POLICY_CHANGE"),
        (2, _DECISION, "SOFT_APPROVAL_ISSUED"),
        (3, _DECISION, "SOFT_APPROVAL_CONSUMED"),
    ):
        event = _event(
            sequence=sequence,
            correlation_id=correlation_id,
            action=action,
            predecessor_hash=predecessor,
        )
        events.append(event)
        predecessor = event.event_hash
    return tuple(events)


def _verify(
    events: tuple[RiskAuditEventV1, ...], *, head_digest: str | None = None
) -> RiskAuditChainVerificationV1 | RiskAuditChainDiagnosticV1:
    return verify_risk_audit_segment(
        events,
        decision_ref=_DECISION,
        head_digest=head_digest or events[-1].event_hash,
    )


def test_complete_genesis_chain_returns_decision_bound_verified_result() -> None:
    events = _valid_chain()

    result = _verify(events)

    assert type(result) is RiskAuditChainVerificationV1
    assert result.decision_ref == _DECISION
    assert result.event_count == 3
    assert result.head_digest == events[-1].event_hash
    assert result.terminal_event_id == events[-1].event_id
    assert result.terminal_action == "SOFT_APPROVAL_CONSUMED"
    assert result.terminal_decision == events[-1].decision
    assert (
        result.decision_binding.value
        == "CORRELATION_ID_STRING_ONLY_NOT_C101_AUTHENTICATED"
    )
    assert (
        result.provenance
        is RiskAuditChainProvenanceV1.CHAIN_VERIFIED_TO_SUPPLIED_HEAD_CORRELATION_ONLY
    )
    assert result.provenance.value == "CHAIN_VERIFIED_TO_SUPPLIED_HEAD_CORRELATION_ONLY"
    description = " ".join(
        (
            risk_evidence_chain.__doc__ or "",
            RiskAuditChainVerificationV1.__doc__ or "",
            RiskAuditChainProvenanceV1.__doc__ or "",
        )
    ).lower()
    assert "correlation_id" in description
    assert "c-101" in description
    assert "unauthenticated" in description or "not authenticated" in description
    assert "does not prove" in description
    assert require_risk_audit_chain_verification(result) is result


def test_hash_corruption_returns_fixed_non_success_diagnostic() -> None:
    first = _event(
        sequence=1,
        correlation_id=_DECISION,
        action="SOFT_APPROVAL_ISSUED",
        predecessor_hash=RISK_AUDIT_GENESIS_HASH,
        invalid_hash=True,
    )

    result = _verify((first,))

    assert result is RiskAuditChainDiagnosticV1.HASH_MISMATCH


def test_truncated_segment_before_target_terminal_is_incomplete() -> None:
    events = _valid_chain()

    result = _verify(events[:-1], head_digest=events[-2].event_hash)

    assert result is RiskAuditChainDiagnosticV1.DECISION_INCOMPLETE


def test_reordered_noncontiguous_segment_is_a_gap() -> None:
    events = _valid_chain()

    result = _verify((events[0], events[2], events[1]))

    assert result is RiskAuditChainDiagnosticV1.GAP


def test_foreign_decision_chain_does_not_verify_for_requested_decision() -> None:
    foreign_events: list[RiskAuditEventV1] = []
    predecessor = RISK_AUDIT_GENESIS_HASH
    for sequence, action in (
        (1, "LIMIT_POLICY_CHANGE"),
        (2, "SOFT_APPROVAL_CONSUMED"),
    ):
        event = _event(
            sequence=sequence,
            correlation_id=_FOREIGN,
            action=action,
            predecessor_hash=predecessor,
        )
        foreign_events.append(event)
        predecessor = event.event_hash

    result = _verify(tuple(foreign_events))

    assert result is RiskAuditChainDiagnosticV1.DECISION_ABSENT


def test_target_correlated_policy_change_is_not_an_order_decision_event() -> None:
    event = _event(
        sequence=1,
        correlation_id=_DECISION,
        action="LIMIT_POLICY_CHANGE",
        predecessor_hash=RISK_AUDIT_GENESIS_HASH,
        scope="ACCOUNT",
    )

    result = _verify((event,))

    assert result is RiskAuditChainDiagnosticV1.DECISION_INCOMPLETE


def test_wrong_event_type_returns_type_invalid() -> None:
    result = verify_risk_audit_segment(
        (object(),),  # type: ignore[arg-type]
        decision_ref=_DECISION,
        head_digest=_ZERO,
    )

    assert result is RiskAuditChainDiagnosticV1.TYPE_INVALID


def test_tampered_issued_event_is_rejected_without_success_marker() -> None:
    event = _valid_chain()[0]
    object.__setattr__(event, "reason_code", "ALTERED_AFTER_ISSUANCE")

    result = _verify((event,))

    assert result is RiskAuditChainDiagnosticV1.TYPE_INVALID


def test_non_genesis_segment_is_rejected() -> None:
    event = _event(
        sequence=2,
        correlation_id=_DECISION,
        action="SOFT_APPROVAL_CONSUMED",
        predecessor_hash=RISK_AUDIT_GENESIS_HASH,
    )

    result = _verify((event,))

    assert result is RiskAuditChainDiagnosticV1.NOT_GENESIS


def test_wrong_supplied_head_is_rejected() -> None:
    events = _valid_chain()

    result = _verify(events, head_digest="b" * 64)

    assert result is RiskAuditChainDiagnosticV1.HEAD_MISMATCH


def test_forged_or_tampered_verification_is_rejected_by_require() -> None:
    issued = _verify(_valid_chain())
    assert type(issued) is RiskAuditChainVerificationV1
    object.__setattr__(issued, "head_digest", "c" * 64)

    with pytest.raises(RiskEvidenceChainError) as error:
        require_risk_audit_chain_verification(issued)

    assert error.value.code == "UNVERIFIED_SEAL"
    assert str(error.value) == "UNVERIFIED_SEAL"


def test_verification_does_not_mutate_audit_state_or_input_events() -> None:
    events = _valid_chain()
    before = tuple(event.model_dump(mode="python") for event in events)

    first = _verify(events)
    second = _verify(events)
    after = tuple(event.model_dump(mode="python") for event in events)

    assert type(first) is RiskAuditChainVerificationV1
    assert type(second) is RiskAuditChainVerificationV1
    assert first.head_digest == second.head_digest
    assert before == after


@pytest.mark.asyncio
async def test_invalid_persisted_tail_is_chain_invalid_without_retry(tmp_path: Path) -> None:
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'chain-tail.sqlite'}")
    try:
        await migrate_risk_limits_v1(
            engine,
            writer_guard=_MigrationWriterGuard(),
            applied_at_ns=1_800_000_000_000_000_000,
        )
        tail_hash = "d" * 64
        async with engine.begin() as connection:
            await connection.execute(
                insert(risk_audit_events).values(
                    sequence=1,
                    event_id=tail_hash,
                    correlation_id=_DECISION,
                    attempt_id="attempt-persisted-tail",
                    actor_ref="a" * 64,
                    action="SOFT_APPROVAL_CONSUMED",
                    decision="ALLOW",
                    reason_code="SYNTHETIC_TAIL",
                    environment="test",
                    account_id="acct_synthetic_001",
                    scope="INVALID_SCOPE",
                    before_digest=None,
                    after_digest=None,
                    source_event_ids=[],
                    recorded_at_ns=1_800_000_000_000_000_000,
                    predecessor_hash=RISK_AUDIT_GENESIS_HASH,
                    event_hash=tail_hash,
                )
            )
            await connection.execute(
                update(risk_audit_head)
                .where(risk_audit_head.c.head_id == 1)
                .values(sequence=1, chain_tip=tail_hash)
            )

        store = RiskLimitEventStore(
            async_sessionmaker(engine, expire_on_commit=False),
            authorization_policy=_store_authorization_policy(),
            soft_approval_policy=SoftApprovalPolicyV1(rules=()),
            clock=lambda: _NOW,
        )
        trusted_now_calls = 0
        original_trusted_now_ns = store.trusted_now_ns

        async def counted_trusted_now_ns() -> int:
            nonlocal trusted_now_calls
            trusted_now_calls += 1
            return await original_trusted_now_ns()

        store.trusted_now_ns = counted_trusted_now_ns  # type: ignore[method-assign]
        with pytest.raises(RiskLimitEventStoreError) as error:
            await store._trusted_now_with_retry()

        assert error.value.code == "AUDIT_CHAIN_INVALID"
        assert trusted_now_calls == 1
        assert await store.verify_audit_chain() is False
    finally:
        await engine.dispose()


def test_invalid_append_body_remains_store_failure() -> None:
    event = _valid_chain()[-1]
    body = event.model_dump(mode="python")
    body["scope"] = "INVALID_SCOPE"

    with pytest.raises(RiskLimitEventStoreError) as error:
        _hash_event(body, event.predecessor_hash)

    assert error.value.code == "STORE_FAILURE"
