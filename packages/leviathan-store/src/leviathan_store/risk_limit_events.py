"""Atomic versioned risk-policy updates and append-only audit persistence."""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Awaitable, Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from functools import wraps
from typing import Any, Concatenate, ParamSpec, Protocol, TypeVar, cast

from pydantic import ConfigDict, Field
from sqlalchemy import (
    JSON,
    BigInteger,
    Column,
    Integer,
    MetaData,
    String,
    Table,
    func,
    insert,
    select,
    update,
)
from sqlalchemy.engine import CursorResult
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from leviathan_core.execution.order_models import LedgerIntegrityKey
from leviathan_core.numeric import NumericError
from leviathan_core.risk_limits.approval import (
    LimitPolicyChangeV1,
    SoftApprovalPolicyV1,
    SoftApprovalRequestV1,
    SoftApprovalV1,
    is_issued_soft_approval,
    policy_is_no_looser,
)
from leviathan_core.risk_limits.audit_checkpoint import (
    MAX_CHECKPOINT_SUFFIX_ROWS,
    RiskAuditCheckpointError,
    RiskAuditCheckpointV1,
    RiskAuditHeadV1,
    RiskAuditScopeV1,
    authenticate_risk_audit_checkpoint,
    verify_suffix_from_checkpoint,
)
from leviathan_core.risk_limits.audit_port import (
    RiskAuditEventHashError,
    RiskAuditEventV1,
    _issue_event,
    risk_audit_event_hash,
)
from leviathan_core.risk_limits.models import (
    HardLimitsV1,
    VerifiedHardLimitsV1,
)
from leviathan_core.seal import Issuer, SealedModel, SealError, require
from leviathan_core.security import (
    ActionV1,
    AuthorizationContextV1,
    AuthorizationPolicyV1,
    ResourceV1,
    TrustedPrincipalV1,
    authorize,
)

RISK_LIMITS_METADATA = MetaData()

risk_policy_state = Table(
    "risk_policy_state",
    RISK_LIMITS_METADATA,
    Column("environment", String(128), primary_key=True),
    Column("account_id", String(128), primary_key=True),
    Column("version", Integer, nullable=False),
    Column("policy_digest", String(64), nullable=False),
    Column("policy_payload", JSON, nullable=False),
    Column("last_event_id", String(64), nullable=False),
)

risk_audit_events = Table(
    "risk_audit_events",
    RISK_LIMITS_METADATA,
    Column("sequence", Integer, primary_key=True, autoincrement=True),
    Column("event_id", String(64), nullable=False, unique=True),
    Column("correlation_id", String(128), nullable=False),
    Column("attempt_id", String(128), nullable=False),
    Column("actor_ref", String(64), nullable=False),
    Column("action", String(64), nullable=False),
    Column("decision", String(16), nullable=False),
    Column("reason_code", String(64), nullable=False),
    Column("environment", String(128), nullable=False),
    Column("account_id", String(128), nullable=False),
    Column("scope", String(16), nullable=False),
    Column("before_digest", String(64), nullable=True),
    Column("after_digest", String(64), nullable=True),
    Column("source_event_ids", JSON, nullable=False),
    Column("recorded_at_ns", BigInteger, nullable=False),
    Column("predecessor_hash", String(64), nullable=False),
    Column("event_hash", String(64), nullable=False),
)

risk_audit_head = Table(
    "risk_audit_head",
    RISK_LIMITS_METADATA,
    Column("head_id", Integer, primary_key=True),
    Column("sequence", Integer, nullable=False),
    Column("chain_tip", String(64), nullable=False),
)

risk_soft_approval_claims = Table(
    "risk_soft_approval_claims",
    RISK_LIMITS_METADATA,
    Column("approval_id", String(64), primary_key=True),
    Column("order_digest", String(64), nullable=False),
    Column("claimed_at_ns", BigInteger, nullable=False),
    Column("event_id", String(64), nullable=False),
)

risk_soft_approvals = Table(
    "risk_soft_approvals",
    RISK_LIMITS_METADATA,
    Column("approval_id", String(64), primary_key=True),
    Column("environment", String(128), nullable=False),
    Column("account_id", String(128), nullable=False),
    Column("strategy_id", String(128), nullable=False),
    Column("venue_id", String(128), nullable=False),
    Column("instrument_id", String(128), nullable=False),
    Column("order_digest", String(64), nullable=False),
    Column("soft_rule_id", String(128), nullable=False),
    Column("policy_version", Integer, nullable=False),
    Column("requester_id", String(128), nullable=False),
    Column("approver_ids", JSON, nullable=False),
    Column("requested_at_ns", BigInteger, nullable=False),
    Column("expires_at_ns", BigInteger, nullable=False),
    Column("correlation_id", String(128), nullable=False),
    Column("event_id", String(64), nullable=False),
    Column("consumed_at_ns", BigInteger, nullable=True),
    Column("consume_event_id", String(64), nullable=True),
)

risk_limit_migration_versions = Table(
    "risk_limit_migration_versions",
    RISK_LIMITS_METADATA,
    Column("version", Integer, primary_key=True),
    Column("name", String(128), nullable=False, unique=True),
    Column("applied_at_ns", BigInteger, nullable=False),
)

_GENESIS = hashlib.sha256(b"leviathan.risk005.audit.genesis.v1").hexdigest()
_VERIFIED_SUFFIX_ISSUER = Issuer(
    "risk.audit_checkpoint.verified_suffix.v1", max_digest_nodes=25_000
)


class VerifiedRiskAuditSuffixV1(SealedModel):
    """Store-issued projection of a persisted, verified global suffix."""

    model_config = ConfigDict(
        frozen=True, extra="forbid", strict=True, revalidate_instances="always"
    )

    scope: RiskAuditScopeV1
    checkpoint_sequence: int = Field(ge=0)
    supplied_head: RiskAuditHeadV1
    events: tuple[RiskAuditEventV1, ...]


_ZERO = "0" * 64
_MAX_NS = 253_402_300_799_999_999_999
_P = ParamSpec("_P")
_R = TypeVar("_R")


def _serialized_write(
    method: Callable[Concatenate[RiskLimitEventStore, _P], Awaitable[_R]],
) -> Callable[Concatenate[RiskLimitEventStore, _P], Awaitable[_R]]:
    @wraps(method)
    async def wrapped(self: RiskLimitEventStore, *args: _P.args, **kwargs: _P.kwargs) -> _R:
        async with self._write_lock:
            return await method(self, *args, **kwargs)

    return cast(Callable[Concatenate[Any, _P], Awaitable[_R]], wrapped)


class RiskLimitEventStoreError(ValueError):
    """Content-free error from the atomic risk-limit persistence boundary."""

    def __init__(self, code: str) -> None:
        self.code = code if code in _STORE_ERRORS else "STORE_FAILURE"
        super().__init__(self.code)


_STORE_ERRORS = frozenset(
    {
        "STORE_FAILURE",
        "MIGRATION_REQUIRED",
        "VERSION_CONFLICT",
        "AUDIT_CHAIN_INVALID",
        "AUDIT_SUFFIX_LIMIT",
        "ACTOR_UNAUTHORIZED",
        "POLICY_WOULD_LOOSEN",
        "POLICY_DIGEST_MISMATCH",
        "POLICY_SCOPE_MISMATCH",
        "SOFT_APPROVAL_INVALID",
        "SOFT_APPROVAL_REPLAY",
        "HARD_LIMIT_DENIED",
        "CLOCK_REGRESSION",
        "APPROVAL_POLICY_MISSING",
    }
)


def require_verified_risk_audit_suffix(value: object) -> VerifiedRiskAuditSuffixV1:
    """Require a suffix issued by the persisted store verification path."""
    if type(value) is not VerifiedRiskAuditSuffixV1:
        raise RiskAuditCheckpointError from None
    try:
        require(value, _VERIFIED_SUFFIX_ISSUER.tag)
        VerifiedRiskAuditSuffixV1.model_validate(value.model_dump(mode="python"))
    except (SealError, TypeError, ValueError):
        raise RiskAuditCheckpointError from None
    return value


class _ApprovalReplayError(Exception):
    """Internal rollback marker for a lost one-use claim race."""


class _AuditAppendRaceError(Exception):
    """Internal rollback marker when another writer advances the audit head."""


class MigrationWriterGuard(Protocol):
    """Coordinator-provided exclusive slot lease for schema writes."""

    async def acquire(self, writer_name: str) -> bool: ...

    async def release(self, writer_name: str) -> None: ...


def _payload(policies: tuple[HardLimitsV1, ...]) -> list[dict[str, Any]]:
    result = []
    for policy in policies:
        data = (
            {key: value for key, value in policy.__dict__.items()}
            if hasattr(policy, "__dict__")
            else {field: getattr(policy, field) for field in policy.__dataclass_fields__}
        )
        data["allowed_instruments"] = (
            [
                {
                    "instrument_id": item.instrument_id,
                    "effective_from_ns": item.effective_from_ns,
                    "effective_until_ns": item.effective_until_ns,
                }
                for item in (policy.allowed_instruments or ())
            ]
            if policy.allowed_instruments is not None
            else None
        )
        result.append(data)
    return result


def _hash_event(body: dict[str, Any], predecessor: str) -> str:
    try:
        event = RiskAuditEventV1.model_validate(
            {
                **body,
                "event_id": "0" * 64,
                "event_hash": "0" * 64,
            }
        )
        digest = risk_audit_event_hash(event, predecessor)
    except (NumericError, RiskAuditEventHashError, TypeError, ValueError):
        raise RiskLimitEventStoreError("STORE_FAILURE") from None
    return digest


async def _append_event(
    session: AsyncSession,
    *,
    change: LimitPolicyChangeV1,
    actor_id: str,
    action: str,
    decision: str,
    reason_code: str,
    before_digest: str | None,
    after_digest: str | None,
    source_event_ids: tuple[str, ...] = (),
) -> RiskAuditEventV1:
    previous = await session.execute(
        select(risk_audit_head.c.sequence, risk_audit_head.c.chain_tip)
        .where(risk_audit_head.c.head_id == 1)
        .with_for_update()
    )
    row = previous.first()
    if row is None:
        raise RiskLimitEventStoreError("MIGRATION_REQUIRED")
    head_sequence = int(row.sequence)
    predecessor = cast(str, row.chain_tip)
    tail_time = await _validate_chain_tail(session, head_sequence, predecessor)
    if change.recorded_at_ns < tail_time:
        raise RiskLimitEventStoreError("CLOCK_REGRESSION")
    sequence = head_sequence + 1
    actor_ref = hashlib.sha256(actor_id.encode("utf-8")).hexdigest()
    body: dict[str, Any] = {
        "schema_version": 1,
        "sequence": sequence,
        "correlation_id": change.correlation_id,
        "attempt_id": change.attempt_id,
        "actor_ref": actor_ref,
        "action": action,
        "decision": decision,
        "reason_code": reason_code,
        "environment": change.environment,
        "account_id": change.account_id,
        "scope": "ACCOUNT" if action == "LIMIT_POLICY_CHANGE" else "ORDER",
        "before_digest": before_digest,
        "after_digest": after_digest,
        "source_event_ids": source_event_ids,
        "recorded_at_ns": change.recorded_at_ns,
        "predecessor_hash": predecessor,
    }
    event_hash = _hash_event(body, predecessor)
    event_id = event_hash
    body["event_id"] = event_id
    body["event_hash"] = event_hash
    event = _issue_event(**body)
    await session.execute(
        insert(risk_audit_events).values(
            sequence=sequence,
            event_id=event_id,
            correlation_id=change.correlation_id,
            attempt_id=change.attempt_id,
            actor_ref=actor_ref,
            action=action,
            decision=decision,
            reason_code=reason_code,
            environment=change.environment,
            account_id=change.account_id,
            scope=body["scope"],
            before_digest=before_digest,
            after_digest=after_digest,
            source_event_ids=list(source_event_ids),
            recorded_at_ns=change.recorded_at_ns,
            predecessor_hash=predecessor,
            event_hash=event_hash,
        )
    )
    changed = cast(
        CursorResult[Any],
        await session.execute(
            update(risk_audit_head)
            .where(risk_audit_head.c.head_id == 1)
            .where(risk_audit_head.c.sequence == sequence - 1)
            .values(sequence=sequence, chain_tip=event_hash)
        ),
    )
    if changed.rowcount != 1:
        if action in {"SOFT_APPROVAL_ISSUED", "SOFT_APPROVAL_CONSUMED"}:
            raise _AuditAppendRaceError
        raise RiskLimitEventStoreError("AUDIT_CHAIN_INVALID")
    return event


async def _validate_chain_tail(session: AsyncSession, head_sequence: int, chain_tip: str) -> int:
    """Validate the O(1) persisted tail/head binding and return its timestamp."""
    if head_sequence == 0:
        if chain_tip != _GENESIS:
            raise RiskLimitEventStoreError("AUDIT_CHAIN_INVALID")
        return 0
    result = await session.execute(
        select(risk_audit_events).where(risk_audit_events.c.sequence == head_sequence)
    )
    row = result.mappings().first()
    if row is None or row["event_hash"] != chain_tip or row["event_id"] != chain_tip:
        raise RiskLimitEventStoreError("AUDIT_CHAIN_INVALID")
    body = {
        "schema_version": 1,
        "sequence": row["sequence"],
        "correlation_id": row["correlation_id"],
        "attempt_id": row["attempt_id"],
        "actor_ref": row["actor_ref"],
        "action": row["action"],
        "decision": row["decision"],
        "reason_code": row["reason_code"],
        "environment": row["environment"],
        "account_id": row["account_id"],
        "scope": row["scope"],
        "before_digest": row["before_digest"],
        "after_digest": row["after_digest"],
        "source_event_ids": tuple(row["source_event_ids"]),
        "recorded_at_ns": row["recorded_at_ns"],
        "predecessor_hash": row["predecessor_hash"],
    }
    try:
        expected = _hash_event(body, cast(str, row["predecessor_hash"]))
    except RiskLimitEventStoreError:
        raise RiskLimitEventStoreError("AUDIT_CHAIN_INVALID") from None
    if expected != chain_tip:
        raise RiskLimitEventStoreError("AUDIT_CHAIN_INVALID")
    if head_sequence == 1:
        if row["predecessor_hash"] != _GENESIS:
            raise RiskLimitEventStoreError("AUDIT_CHAIN_INVALID")
    else:
        prior = await session.execute(
            select(risk_audit_events.c.event_hash).where(
                risk_audit_events.c.sequence == head_sequence - 1
            )
        )
        prior_row = prior.first()
        if prior_row is None or prior_row.event_hash != row["predecessor_hash"]:
            raise RiskLimitEventStoreError("AUDIT_CHAIN_INVALID")
    return int(row["recorded_at_ns"])


async def _committed_event_matches(session: AsyncSession, event: RiskAuditEventV1 | None) -> bool:
    """Recognize our own commit when a driver reports an error after COMMIT."""
    if type(event) is not RiskAuditEventV1:
        return False
    result = await session.execute(
        select(risk_audit_events).where(risk_audit_events.c.event_id == event.event_id)
    )
    row = result.mappings().first()
    return (
        row is not None
        and all(
            row[column] == getattr(event, attribute)
            for column, attribute in (
                ("event_id", "event_id"),
                ("event_hash", "event_hash"),
                ("sequence", "sequence"),
                ("actor_ref", "actor_ref"),
                ("action", "action"),
                ("decision", "decision"),
                ("reason_code", "reason_code"),
                ("environment", "environment"),
                ("account_id", "account_id"),
                ("correlation_id", "correlation_id"),
                ("attempt_id", "attempt_id"),
                ("recorded_at_ns", "recorded_at_ns"),
            )
        )
        and tuple(row["source_event_ids"]) == event.source_event_ids
    )


def _authorized(
    actor: object,
    policy: object,
    *,
    action_name: str,
    environment: str,
    account_id: str,
    at_ns: int,
    strategy_id: str | None = None,
    venue_id: str | None = None,
) -> bool:
    if type(actor) is not TrustedPrincipalV1 or type(policy) is not AuthorizationPolicyV1:
        return False
    if (
        actor.project_id != policy.project_id
        or actor.env != environment
        or actor.portfolio != account_id
        or (actor.venue is not None and actor.venue != venue_id)
        or (actor.strategy is not None and actor.strategy != strategy_id)
        or type(at_ns) is not int
        or at_ns < 0
    ):
        return False
    try:
        at = datetime(1970, 1, 1, tzinfo=UTC) + timedelta(microseconds=(at_ns + 999) // 1000)
        resource = ResourceV1(
            resource_id=account_id,
            project_id=actor.project_id,
            env=environment,
            venue=venue_id,
            portfolio=account_id,
            strategy=strategy_id,
        )
        context = AuthorizationContextV1(
            project_id=actor.project_id,
            env=environment,
            at=at,
            venue=venue_id,
            portfolio=account_id,
            strategy=strategy_id,
        )
        return authorize(actor, ActionV1(action_name), resource, context, policy).allowed
    except Exception:
        return False


def _policy_record(change: LimitPolicyChangeV1, proposed: VerifiedHardLimitsV1) -> dict[str, Any]:
    return {
        "version": change.expected_version + 1,
        "policy_digest": proposed.verification.policy_digest,
        "policy_payload": _payload(proposed.policies),
    }


def _make_soft_change(
    approval: SoftApprovalV1,
    *,
    environment: str,
    now_ns: int,
    actor_id: str,
) -> LimitPolicyChangeV1:
    return LimitPolicyChangeV1(
        environment=environment,
        account_id=approval.account_id,
        expected_version=approval.policy_version,
        before_digest=_ZERO,
        after_digest=approval.approval_id,
        actor_id=actor_id,
        reason="scoped soft approval claimed",
        recorded_at_ns=now_ns,
        correlation_id=approval.correlation_id,
        attempt_id=approval.approval_id[:32],
    )


class RiskLimitEventStore:
    """SQL store whose policy mutation/approval claim and audit append share a transaction."""

    def __init__(
        self,
        sessions: async_sessionmaker[AsyncSession],
        *,
        authorization_policy: AuthorizationPolicyV1,
        soft_approval_policy: SoftApprovalPolicyV1,
        clock: Callable[[], datetime],
    ) -> None:
        if (
            type(authorization_policy) is not AuthorizationPolicyV1
            or type(soft_approval_policy) is not SoftApprovalPolicyV1
            or not callable(clock)
        ):
            raise RiskLimitEventStoreError("ACTOR_UNAUTHORIZED")
        self._sessions = sessions
        self._authorization_policy = authorization_policy
        self._soft_approval_policy = soft_approval_policy
        self._clock: Callable[[], datetime] = clock
        self._write_lock = asyncio.Lock()
        self._clock_guard = asyncio.Lock()
        self._last_clock_ns = 0

    def required_approvers(self, soft_rule_id: str) -> int:
        try:
            return self._soft_approval_policy.required_approvers(soft_rule_id)
        except Exception:
            raise RiskLimitEventStoreError("APPROVAL_POLICY_MISSING") from None

    def _clock_now_ns(self) -> int:
        try:
            instant = self._clock()
            if (
                type(instant) is not datetime
                or instant.tzinfo is None
                or instant.utcoffset() != timedelta(0)
            ):
                raise ValueError
            epoch = datetime(1970, 1, 1, tzinfo=UTC)
            delta = instant.astimezone(UTC) - epoch
            now_ns = (delta.days * 86_400 + delta.seconds) * 1_000_000_000
            now_ns += delta.microseconds * 1_000
            if not 0 <= now_ns <= _MAX_NS:
                raise ValueError
            return now_ns
        except Exception:
            raise RiskLimitEventStoreError("CLOCK_REGRESSION") from None

    async def trusted_now_ns(self) -> int:
        """Return UTC time only after checking it does not precede the persisted tail."""
        now_ns = self._clock_now_ns()
        async with self._clock_guard:
            if now_ns < self._last_clock_ns:
                raise RiskLimitEventStoreError("CLOCK_REGRESSION")
            try:
                async with self._sessions() as session, session.begin():
                    head = await session.execute(
                        select(risk_audit_head.c.sequence, risk_audit_head.c.chain_tip)
                        .where(risk_audit_head.c.head_id == 1)
                        .with_for_update()
                    )
                    row = head.first()
                    if row is None:
                        raise RiskLimitEventStoreError("MIGRATION_REQUIRED")
                    tail_ns = await _validate_chain_tail(
                        session, int(row.sequence), cast(str, row.chain_tip)
                    )
                    if now_ns < tail_ns:
                        raise RiskLimitEventStoreError("CLOCK_REGRESSION")
                self._last_clock_ns = now_ns
                return now_ns
            except RiskLimitEventStoreError:
                raise
            except SQLAlchemyError:
                raise RiskLimitEventStoreError("STORE_FAILURE") from None

    async def _trusted_now_with_retry(self) -> int:
        for attempt in range(3):
            try:
                return await self.trusted_now_ns()
            except RiskLimitEventStoreError as exc:
                if exc.code != "STORE_FAILURE" or attempt == 2:
                    raise
                await asyncio.sleep(0.01 * (attempt + 1))
        raise RiskLimitEventStoreError("STORE_FAILURE")

    @_serialized_write
    async def apply_policy_change(
        self,
        *,
        change: object,
        current_policy: object,
        proposed_policy: object,
        actor: object,
        authorization_policy: object,
    ) -> RiskAuditEventV1:
        if (
            type(change) is not LimitPolicyChangeV1
            or type(current_policy) is not VerifiedHardLimitsV1
            or type(proposed_policy) is not VerifiedHardLimitsV1
            or type(actor) is not TrustedPrincipalV1
            or authorization_policy is not self._authorization_policy
        ):
            raise RiskLimitEventStoreError("POLICY_DIGEST_MISMATCH")
        now_ns = await self._trusted_now_with_retry()
        change = replace(change, recorded_at_ns=now_ns)
        allowed = _authorized(
            actor,
            self._authorization_policy,
            action_name="risk:limits:change",
            environment=change.environment,
            account_id=change.account_id,
            at_ns=change.recorded_at_ns,
        )
        code = "UPDATED"
        if change.before_digest != current_policy.verification.policy_digest or (
            change.after_digest != proposed_policy.verification.policy_digest
        ):
            allowed, code = False, "POLICY_DIGEST_MISMATCH"
        elif any(
            (item.environment, item.account_id) != (change.environment, change.account_id)
            for item in (*current_policy.policies, *proposed_policy.policies)
        ):
            allowed, code = False, "POLICY_SCOPE_MISMATCH"
        elif actor.principal_id != change.actor_id or not allowed:
            allowed, code = False, "ACTOR_UNAUTHORIZED"
        elif not policy_is_no_looser(current_policy, proposed_policy):
            allowed, code = False, "POLICY_WOULD_LOOSEN"

        event: RiskAuditEventV1
        try:
            async with self._sessions() as session, session.begin():
                stored = await session.execute(
                    select(risk_policy_state.c.version, risk_policy_state.c.policy_digest)
                    .where(risk_policy_state.c.environment == change.environment)
                    .where(risk_policy_state.c.account_id == change.account_id)
                    .with_for_update()
                )
                existing = stored.first()
                expected_stored_version = 0 if existing is None else int(existing.version)
                if expected_stored_version != change.expected_version:
                    allowed, code = False, "VERSION_CONFLICT"
                elif existing is not None and existing.policy_digest != change.before_digest:
                    allowed, code = False, "POLICY_DIGEST_MISMATCH"
                event = await _append_event(
                    session,
                    change=change,
                    actor_id=actor.principal_id,
                    action="LIMIT_POLICY_CHANGE",
                    decision="ALLOW" if allowed else "DENY",
                    reason_code=code,
                    before_digest=change.before_digest,
                    after_digest=change.after_digest,
                )
                if allowed:
                    record = _policy_record(change, proposed_policy)
                    if existing is None:
                        await session.execute(
                            insert(risk_policy_state).values(
                                environment=change.environment,
                                account_id=change.account_id,
                                **record,
                                last_event_id=event.event_id,
                            )
                        )
                    else:
                        result = cast(
                            CursorResult[Any],
                            await session.execute(
                                update(risk_policy_state)
                                .where(risk_policy_state.c.environment == change.environment)
                                .where(risk_policy_state.c.account_id == change.account_id)
                                .where(risk_policy_state.c.version == change.expected_version)
                                .values(**record, last_event_id=event.event_id)
                            ),
                        )
                        if result.rowcount != 1:
                            raise RiskLimitEventStoreError("VERSION_CONFLICT")
        except RiskLimitEventStoreError:
            raise
        except (IntegrityError, SQLAlchemyError, NumericError):
            raise RiskLimitEventStoreError("STORE_FAILURE") from None
        return event

    @_serialized_write
    async def consume_soft_approval(
        self,
        *,
        approval: object,
        order_digest: str,
        environment: str,
        account_id: str,
        strategy_id: str,
        venue_id: str,
        instrument_id: str,
        soft_rule_id: str,
        policy_version: int,
        consumer: object,
    ) -> RiskAuditEventV1:
        if type(approval) is not SoftApprovalV1:
            raise RiskLimitEventStoreError("SOFT_APPROVAL_INVALID")
        if type(consumer) is not TrustedPrincipalV1:
            raise RiskLimitEventStoreError("ACTOR_UNAUTHORIZED")
        now_ns = await self._trusted_now_with_retry()
        consumer_authorized = _authorized(
            consumer,
            self._authorization_policy,
            action_name="risk:soft-consume",
            environment=environment,
            account_id=account_id,
            at_ns=now_ns,
            strategy_id=strategy_id,
            venue_id=venue_id,
        )
        change = _make_soft_change(
            approval, environment=environment, now_ns=now_ns, actor_id=consumer.principal_id
        )
        valid = (
            is_issued_soft_approval(approval)
            and approval.requested_at_ns <= now_ns < approval.expires_at_ns
            and approval.order_digest == order_digest
            and approval.environment == environment
            and approval.account_id == account_id
            and approval.strategy_id == strategy_id
            and approval.venue_id == venue_id
            and approval.instrument_id == instrument_id
            and approval.soft_rule_id == soft_rule_id
            and type(policy_version) is int
            and approval.policy_version == policy_version
            and consumer_authorized
        )
        event: RiskAuditEventV1 | None = None
        try:
            async with self._sessions() as session, session.begin():
                current_policy = await session.execute(
                    select(risk_policy_state.c.version)
                    .where(risk_policy_state.c.environment == environment)
                    .where(risk_policy_state.c.account_id == account_id)
                    .with_for_update()
                )
                policy_row = current_policy.first()
                policy_is_current = (
                    policy_row is not None and int(policy_row.version) == policy_version
                )
                persisted = await session.execute(
                    select(risk_soft_approvals)
                    .where(risk_soft_approvals.c.approval_id == approval.approval_id)
                    .with_for_update()
                )
                persisted_row = persisted.mappings().first()
                fields_match = (
                    persisted_row is not None
                    and all(
                        persisted_row[field] == getattr(approval, field)
                        for field in (
                            "environment",
                            "account_id",
                            "strategy_id",
                            "venue_id",
                            "instrument_id",
                            "order_digest",
                            "soft_rule_id",
                            "policy_version",
                            "requester_id",
                            "requested_at_ns",
                            "expires_at_ns",
                            "correlation_id",
                        )
                    )
                    and tuple(persisted_row["approver_ids"]) == approval.approver_ids
                )
                valid_before_policy = valid and fields_match
                valid = valid_before_policy and policy_is_current
                event = await _append_event(
                    session,
                    change=change,
                    actor_id=consumer.principal_id,
                    action="SOFT_APPROVAL_CONSUMED",
                    decision="ALLOW" if valid else "DENY",
                    reason_code=(
                        "SOFT_RULE_SATISFIED"
                        if valid
                        else "VERSION_CONFLICT"
                        if valid_before_policy and not policy_is_current
                        else "SOFT_APPROVAL_INVALID"
                    ),
                    before_digest=None,
                    after_digest=approval.approval_id,
                    source_event_ids=(
                        (cast(str, persisted_row["event_id"]),) if persisted_row is not None else ()
                    ),
                )
                if valid:
                    await session.execute(
                        insert(risk_soft_approval_claims).values(
                            approval_id=approval.approval_id,
                            order_digest=approval.order_digest,
                            claimed_at_ns=now_ns,
                            event_id=event.event_id,
                        )
                    )
                    changed = cast(
                        CursorResult[Any],
                        await session.execute(
                            update(risk_soft_approvals)
                            .where(risk_soft_approvals.c.approval_id == approval.approval_id)
                            .where(risk_soft_approvals.c.consumed_at_ns.is_(None))
                            .values(consumed_at_ns=now_ns, consume_event_id=event.event_id)
                        ),
                    )
                    if changed.rowcount != 1:
                        raise _ApprovalReplayError
            if not valid:
                return event
            return event
        except (IntegrityError, _ApprovalReplayError):
            # The failed claim and provisional event rolled back together. Append
            # the replay denial in a fresh transaction so the audit remains durable.
            for attempt in range(3):
                try:
                    async with self._sessions() as session, session.begin():
                        if await _committed_event_matches(session, event):
                            return cast(RiskAuditEventV1, event)
                        approval_row = await session.execute(
                            select(risk_soft_approvals.c.event_id).where(
                                risk_soft_approvals.c.approval_id == approval.approval_id
                            )
                        )
                        source = approval_row.first()
                        return await _append_event(
                            session,
                            change=change,
                            actor_id=consumer.principal_id,
                            action="SOFT_APPROVAL_CONSUMED",
                            decision="DENY",
                            reason_code="SOFT_APPROVAL_REPLAY",
                            before_digest=None,
                            after_digest=approval.approval_id,
                            source_event_ids=((cast(str, source.event_id),) if source else ()),
                        )
                except (SQLAlchemyError, NumericError, _AuditAppendRaceError):
                    if attempt == 2:
                        raise RiskLimitEventStoreError("STORE_FAILURE") from None
                    await asyncio.sleep(0.01 * (attempt + 1))
            else:
                raise RiskLimitEventStoreError("STORE_FAILURE") from None
        except (SQLAlchemyError, _AuditAppendRaceError):
            # Some engines report a concurrent claim as a transient lock/write
            # error rather than a uniqueness violation. Re-read the claim and
            # persist the denial when the database is writable again.
            for attempt in range(3):
                try:
                    async with self._sessions() as session, session.begin():
                        if await _committed_event_matches(session, event):
                            return cast(RiskAuditEventV1, event)
                        claim = await session.execute(
                            select(risk_soft_approval_claims.c.approval_id).where(
                                risk_soft_approval_claims.c.approval_id == approval.approval_id
                            )
                        )
                        claimed = claim.first() is not None
                        approval_row = await session.execute(
                            select(risk_soft_approvals.c.event_id).where(
                                risk_soft_approvals.c.approval_id == approval.approval_id
                            )
                        )
                        source = approval_row.first()
                        return await _append_event(
                            session,
                            change=change,
                            actor_id=consumer.principal_id,
                            action="SOFT_APPROVAL_CONSUMED",
                            decision="DENY",
                            reason_code=("SOFT_APPROVAL_REPLAY" if claimed else "STORE_FAILURE"),
                            before_digest=None,
                            after_digest=approval.approval_id,
                            source_event_ids=((cast(str, source.event_id),) if source else ()),
                        )
                except RiskLimitEventStoreError as exc:
                    if exc.code != "STORE_FAILURE" or attempt == 2:
                        raise
                    await asyncio.sleep(0.01 * (attempt + 1))
                except (SQLAlchemyError, NumericError, _AuditAppendRaceError):
                    if attempt == 2:
                        raise RiskLimitEventStoreError("STORE_FAILURE") from None
                    await asyncio.sleep(0.01 * (attempt + 1))
            raise RiskLimitEventStoreError("STORE_FAILURE") from None

    @_serialized_write
    async def issue_soft_approval(
        self,
        *,
        request: object,
        requester: object,
        approval: object,
        approvers: tuple[object, ...],
    ) -> RiskAuditEventV1:
        if type(request) is not SoftApprovalRequestV1:
            raise RiskLimitEventStoreError("SOFT_APPROVAL_INVALID")
        if type(requester) is not TrustedPrincipalV1:
            raise RiskLimitEventStoreError("ACTOR_UNAUTHORIZED")
        now_ns = await self._trusted_now_with_retry()
        trusted_approvers = (
            tuple(actor for actor in approvers if type(actor) is TrustedPrincipalV1)
            if type(approvers) is tuple
            else ()
        )
        try:
            minimum = self.required_approvers(request.soft_rule_id)
        except RiskLimitEventStoreError:
            minimum = 0
        valid = (
            type(approval) is SoftApprovalV1
            and is_issued_soft_approval(approval)
            and type(approvers) is tuple
            and now_ns < request.expires_at_ns
            and request.expires_at_ns - now_ns <= 1_800_000_000_000
            and requester.portfolio == request.account_id
            and _authorized(
                requester,
                self._authorization_policy,
                action_name="risk:soft-request",
                environment=request.environment,
                account_id=request.account_id,
                at_ns=now_ns,
                strategy_id=request.strategy_id,
                venue_id=request.venue_id,
            )
            and all(type(actor) is TrustedPrincipalV1 for actor in approvers)
            and len(approvers) == minimum
            and tuple(
                getattr(approval, field)
                for field in (
                    "environment",
                    "account_id",
                    "strategy_id",
                    "venue_id",
                    "instrument_id",
                    "order_digest",
                    "soft_rule_id",
                    "policy_version",
                    "expires_at_ns",
                    "correlation_id",
                )
            )
            == (
                request.environment,
                request.account_id,
                request.strategy_id,
                request.venue_id,
                request.instrument_id,
                request.order_digest,
                request.soft_rule_id,
                request.policy_version,
                request.expires_at_ns,
                request.correlation_id,
            )
            and approval.requester_id == requester.principal_id
            and approval.requested_at_ns <= now_ns
            and len(trusted_approvers) == len(approvers)
            and tuple(actor.principal_id for actor in trusted_approvers) == approval.approver_ids
            and requester.principal_id not in approval.approver_ids
            and len(set(approval.approver_ids)) == len(approval.approver_ids)
        )
        if valid:
            valid = bool(approvers) and all(
                _authorized(
                    actor,
                    self._authorization_policy,
                    action_name="risk:soft-approve",
                    environment=request.environment,
                    account_id=request.account_id,
                    at_ns=now_ns,
                    strategy_id=request.strategy_id,
                    venue_id=request.venue_id,
                )
                for actor in approvers
            )
        candidate = approval if type(approval) is SoftApprovalV1 else None
        actor_id = requester.principal_id
        change = LimitPolicyChangeV1(
            environment=request.environment,
            account_id=request.account_id,
            expected_version=request.policy_version,
            before_digest=_ZERO,
            after_digest=(candidate.approval_id if candidate is not None else _ZERO),
            actor_id=actor_id,
            reason="scoped soft approval issuance",
            recorded_at_ns=now_ns,
            correlation_id=request.correlation_id,
            attempt_id=(
                candidate.approval_id[:32] if candidate is not None else request.correlation_id
            ),
        )
        event: RiskAuditEventV1 | None = None
        try:
            async with self._sessions() as session, session.begin():
                current_policy = await session.execute(
                    select(risk_policy_state.c.version)
                    .where(risk_policy_state.c.environment == request.environment)
                    .where(risk_policy_state.c.account_id == request.account_id)
                    .with_for_update()
                )
                policy_row = current_policy.first()
                policy_is_current = (
                    policy_row is not None and int(policy_row.version) == request.policy_version
                )
                valid_before_policy = valid
                valid = valid_before_policy and policy_is_current
                event = await _append_event(
                    session,
                    change=change,
                    actor_id=actor_id,
                    action="SOFT_APPROVAL_ISSUED",
                    decision="ALLOW" if valid else "DENY",
                    reason_code=(
                        "SOFT_APPROVAL_ISSUED"
                        if valid
                        else "VERSION_CONFLICT"
                        if valid_before_policy and not policy_is_current
                        else "SOFT_APPROVAL_EXPIRED"
                        if now_ns >= request.expires_at_ns
                        else "ACTOR_UNAUTHORIZED"
                    ),
                    before_digest=None,
                    after_digest=candidate.approval_id if candidate is not None else None,
                    source_event_ids=(),
                )
                if valid and candidate is not None:
                    await session.execute(
                        insert(risk_soft_approvals).values(
                            approval_id=candidate.approval_id,
                            environment=candidate.environment,
                            account_id=candidate.account_id,
                            strategy_id=candidate.strategy_id,
                            venue_id=candidate.venue_id,
                            instrument_id=candidate.instrument_id,
                            order_digest=candidate.order_digest,
                            soft_rule_id=candidate.soft_rule_id,
                            policy_version=candidate.policy_version,
                            requester_id=candidate.requester_id,
                            approver_ids=list(candidate.approver_ids),
                            requested_at_ns=candidate.requested_at_ns,
                            expires_at_ns=candidate.expires_at_ns,
                            correlation_id=candidate.correlation_id,
                            event_id=event.event_id,
                            consumed_at_ns=None,
                            consume_event_id=None,
                        )
                    )
            return event
        except IntegrityError:
            # Duplicate issuance is an auditable denial, never a silent conflict.
            for attempt in range(3):
                try:
                    async with self._sessions() as session, session.begin():
                        if await _committed_event_matches(session, event):
                            return cast(RiskAuditEventV1, event)
                        return await _append_event(
                            session,
                            change=change,
                            actor_id=actor_id,
                            action="SOFT_APPROVAL_ISSUED",
                            decision="DENY",
                            reason_code="SOFT_APPROVAL_REPLAY",
                            before_digest=None,
                            after_digest=candidate.approval_id if candidate is not None else None,
                            source_event_ids=(),
                        )
                except (SQLAlchemyError, NumericError, _AuditAppendRaceError):
                    if attempt == 2:
                        raise RiskLimitEventStoreError("STORE_FAILURE") from None
                    await asyncio.sleep(0.01 * (attempt + 1))
            else:
                raise RiskLimitEventStoreError("STORE_FAILURE") from None
        except (SQLAlchemyError, _AuditAppendRaceError):
            # A contended duplicate can surface as a transient lock error on
            # SQLite rather than a uniqueness violation. Verify durable presence
            # before appending the replay denial.
            if candidate is not None:
                for attempt in range(3):
                    try:
                        async with self._sessions() as session, session.begin():
                            if await _committed_event_matches(session, event):
                                return cast(RiskAuditEventV1, event)
                            existing = await session.execute(
                                select(risk_soft_approvals.c.approval_id).where(
                                    risk_soft_approvals.c.approval_id == candidate.approval_id
                                )
                            )
                            if existing.first() is not None:
                                return await _append_event(
                                    session,
                                    change=change,
                                    actor_id=actor_id,
                                    action="SOFT_APPROVAL_ISSUED",
                                    decision="DENY",
                                    reason_code="SOFT_APPROVAL_REPLAY",
                                    before_digest=None,
                                    after_digest=candidate.approval_id,
                                    source_event_ids=(),
                                )
                    except RiskLimitEventStoreError as exc:
                        if exc.code != "STORE_FAILURE" or attempt == 2:
                            raise
                    except (SQLAlchemyError, NumericError, _AuditAppendRaceError):
                        if attempt == 2:
                            raise RiskLimitEventStoreError("STORE_FAILURE") from None
                    await asyncio.sleep(0.01 * (attempt + 1))
            raise RiskLimitEventStoreError("STORE_FAILURE") from None
        except NumericError:
            raise RiskLimitEventStoreError("STORE_FAILURE") from None

    async def verify_audit_chain(self) -> bool:
        try:
            async with self._sessions() as session:
                result = await session.execute(
                    select(risk_audit_events).order_by(risk_audit_events.c.sequence)
                )
                rows = result.mappings().all()
            previous = _GENESIS
            for index, row in enumerate(rows, 1):
                body = {
                    "schema_version": 1,
                    "sequence": row["sequence"],
                    "correlation_id": row["correlation_id"],
                    "attempt_id": row["attempt_id"],
                    "actor_ref": row["actor_ref"],
                    "action": row["action"],
                    "decision": row["decision"],
                    "reason_code": row["reason_code"],
                    "environment": row["environment"],
                    "account_id": row["account_id"],
                    "scope": row["scope"],
                    "before_digest": row["before_digest"],
                    "after_digest": row["after_digest"],
                    "source_event_ids": tuple(row["source_event_ids"]),
                    "recorded_at_ns": row["recorded_at_ns"],
                    "predecessor_hash": previous,
                }
                expected = _hash_event(body, previous)
                if (
                    row["sequence"] != index
                    or row["predecessor_hash"] != previous
                    or row["event_hash"] != expected
                    or row["event_id"] != expected
                ):
                    return False
                previous = expected
            async with self._sessions() as session:
                head = await session.execute(
                    select(risk_audit_head.c.sequence, risk_audit_head.c.chain_tip).where(
                        risk_audit_head.c.head_id == 1
                    )
                )
                actual_head = head.first()
                if actual_head is None or (
                    int(actual_head.sequence) != len(rows) or actual_head.chain_tip != previous
                ):
                    return False
            return True
        except (SQLAlchemyError, NumericError, ValueError, TypeError):
            return False

    async def verify_audit_suffix_from_checkpoint(
        self,
        checkpoint: RiskAuditCheckpointV1,
        *,
        supplied_head: RiskAuditHeadV1,
        key: LedgerIntegrityKey,
        scope: RiskAuditScopeV1,
    ) -> VerifiedRiskAuditSuffixV1:
        """Verify the persisted global suffix after a caller-held checkpoint.

        The checkpoint anchor, requested head, current persisted head, and all
        global rows between the checkpoint and supplied head are checked
        before scope projection. Full genesis replay remains available through
        :meth:`verify_audit_chain` and is not replaced by this method.
        """
        try:
            if type(checkpoint) is not RiskAuditCheckpointV1:
                raise RiskLimitEventStoreError("AUDIT_CHAIN_INVALID")
            authenticate_risk_audit_checkpoint(checkpoint, key=key, scope=scope)
            if (
                type(supplied_head) is not RiskAuditHeadV1
                or type(checkpoint.sequence) is not int
                or type(supplied_head.sequence) is not int
                or checkpoint.sequence < 0
                or supplied_head.sequence < checkpoint.sequence
            ):
                raise RiskLimitEventStoreError("AUDIT_CHAIN_INVALID")
            # Authentication is pure and happens first; enforce the bounded
            # suffix before opening a session or reading persisted state.
            if supplied_head.sequence - checkpoint.sequence > MAX_CHECKPOINT_SUFFIX_ROWS:
                raise RiskLimitEventStoreError("AUDIT_SUFFIX_LIMIT")
            async with self._sessions() as session:
                stored_head = await session.execute(
                    select(risk_audit_head.c.sequence, risk_audit_head.c.chain_tip).where(
                        risk_audit_head.c.head_id == 1
                    )
                )
                stored = stored_head.first()
                if stored is None:
                    raise RiskLimitEventStoreError("AUDIT_CHAIN_INVALID")
                max_result = await session.execute(select(func.max(risk_audit_events.c.sequence)))
                persisted_max = max_result.scalar_one_or_none()
                persisted_max = 0 if persisted_max is None else int(persisted_max)
                current_sequence = int(stored.sequence)
                current_hash = str(stored.chain_tip)
                if (
                    type(checkpoint.sequence) is not int
                    or type(supplied_head.sequence) is not int
                    or checkpoint.sequence < 0
                    or supplied_head.sequence < checkpoint.sequence
                ):
                    raise RiskLimitEventStoreError("AUDIT_CHAIN_INVALID")
                if checkpoint.sequence > persisted_max or supplied_head.sequence > persisted_max:
                    raise RiskLimitEventStoreError("AUDIT_CHAIN_INVALID")
                if current_sequence != persisted_max:
                    raise RiskLimitEventStoreError("AUDIT_CHAIN_INVALID")
                if current_sequence == 0:
                    if current_hash != _GENESIS:
                        raise RiskLimitEventStoreError("AUDIT_CHAIN_INVALID")
                else:
                    await _validate_chain_tail(session, current_sequence, current_hash)

                if checkpoint.sequence > persisted_max:
                    raise RiskLimitEventStoreError("AUDIT_CHAIN_INVALID")
                if checkpoint.sequence == 0:
                    if checkpoint.head_hash != _GENESIS:
                        raise RiskLimitEventStoreError("AUDIT_CHAIN_INVALID")
                else:
                    anchor_result = await session.execute(
                        select(risk_audit_events.c.event_hash).where(
                            risk_audit_events.c.sequence == checkpoint.sequence
                        )
                    )
                    anchor = anchor_result.first()
                    if anchor is None or anchor.event_hash != checkpoint.head_hash:
                        raise RiskLimitEventStoreError("AUDIT_CHAIN_INVALID")
                    await _validate_chain_tail(session, checkpoint.sequence, checkpoint.head_hash)

                if supplied_head.sequence > persisted_max:
                    raise RiskLimitEventStoreError("AUDIT_CHAIN_INVALID")
                if supplied_head.sequence == 0:
                    if supplied_head.head_hash != _GENESIS:
                        raise RiskLimitEventStoreError("AUDIT_CHAIN_INVALID")
                else:
                    requested_result = await session.execute(
                        select(risk_audit_events.c.event_hash).where(
                            risk_audit_events.c.sequence == supplied_head.sequence
                        )
                    )
                    requested = requested_result.first()
                    if requested is None or requested.event_hash != supplied_head.head_hash:
                        raise RiskLimitEventStoreError("AUDIT_CHAIN_INVALID")
                    await _validate_chain_tail(
                        session, supplied_head.sequence, supplied_head.head_hash
                    )

                suffix_result = await session.execute(
                    select(risk_audit_events)
                    .where(risk_audit_events.c.sequence > checkpoint.sequence)
                    .where(risk_audit_events.c.sequence <= supplied_head.sequence)
                    .order_by(risk_audit_events.c.sequence)
                    .limit(MAX_CHECKPOINT_SUFFIX_ROWS + 1)
                )
                suffix_rows = suffix_result.mappings().all()
                if len(suffix_rows) > MAX_CHECKPOINT_SUFFIX_ROWS:
                    raise RiskLimitEventStoreError("AUDIT_SUFFIX_LIMIT")
            events = tuple(
                _issue_event(
                    schema_version=1,
                    sequence=row["sequence"],
                    event_id=row["event_id"],
                    correlation_id=row["correlation_id"],
                    attempt_id=row["attempt_id"],
                    actor_ref=row["actor_ref"],
                    action=row["action"],
                    decision=row["decision"],
                    reason_code=row["reason_code"],
                    environment=row["environment"],
                    account_id=row["account_id"],
                    scope=row["scope"],
                    before_digest=row["before_digest"],
                    after_digest=row["after_digest"],
                    source_event_ids=tuple(row["source_event_ids"]),
                    recorded_at_ns=row["recorded_at_ns"],
                    predecessor_hash=row["predecessor_hash"],
                    event_hash=row["event_hash"],
                )
                for row in suffix_rows
            )
            candidate = verify_suffix_from_checkpoint(
                checkpoint,
                events,
                supplied_head=supplied_head,
                key=key,
                scope=scope,
            )
            issued = VerifiedRiskAuditSuffixV1(
                scope=candidate.scope,
                checkpoint_sequence=candidate.checkpoint_sequence,
                supplied_head=candidate.supplied_head,
                events=candidate.events,
            )
            return _VERIFIED_SUFFIX_ISSUER.issue(issued)
        except RiskLimitEventStoreError:
            raise
        except (RiskAuditCheckpointError, SQLAlchemyError, NumericError, TypeError, ValueError):
            raise RiskLimitEventStoreError("AUDIT_CHAIN_INVALID") from None


__all__ = [
    "MigrationWriterGuard",
    "RiskLimitEventStore",
    "RiskLimitEventStoreError",
    "VerifiedRiskAuditSuffixV1",
    "require_verified_risk_audit_suffix",
]
