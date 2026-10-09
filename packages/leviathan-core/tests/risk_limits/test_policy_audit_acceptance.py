"""Independent contract tests for versioned policy changes and soft approvals."""

from __future__ import annotations

import asyncio
import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from leviathan_store.engine import create_engine_and_sessionmaker
from leviathan_store.migrations.risk_limits_v1 import migrate_risk_limits_v1
from leviathan_store.risk_limit_events import (
    RiskLimitEventStore,
    RiskLimitEventStoreError,
    risk_audit_events,
    risk_policy_state,
    risk_soft_approval_claims,
    risk_soft_approvals,
)
from sqlalchemy import select

from leviathan_core.risk_limits.approval import (
    LimitPolicyChangeV1,
    RiskApprovalError,
    SoftApprovalPolicyV1,
    SoftApprovalRequestV1,
    SoftApprovalRuleRequirementV1,
    change_limit_policy,
    consume_soft_approval,
    issue_soft_approval,
    validate_soft_approval,
)
from leviathan_core.risk_limits.models import (
    DatedInstrumentV1,
    HardLimitsV1,
    LimitAssessmentV1,
    PolicyVerificationV1,
    VerifiedHardLimitsV1,
)
from leviathan_core.security import (
    AuthorizationPolicyV1,
    EffectV1,
    PolicyRuleV1,
    PrincipalV1,
    TrustedPrincipalAdapterV1,
    TrustedPrincipalV1,
)
from leviathan_core.security.authz_models import _VERIFIER_MARKER

NOW_NS = 1_800_000_000_000_000_000
PROJECT = "fixture-project"
ENV = "PAPER"
ACCOUNT = "fixture-account"
STRATEGY = "fixture-strategy"
VENUE = "fixture-venue"
INSTRUMENT = "FIXTURE-XYZ"
ORDER_DIGEST = "a" * 64
SOFT_RULE = "soft-rate-limit"


class _FixtureVerifier:
    def verify(self, _policies: tuple[HardLimitsV1, ...], digest: str) -> PolicyVerificationV1:
        return PolicyVerificationV1("fixture-verifier", "fixture-key", digest)


class _PermitGuard:
    def __init__(self, allowed: bool = True) -> None:
        self.allowed = allowed
        self.calls: list[tuple[str, str]] = []

    async def acquire(self, writer_name: str) -> bool:
        self.calls.append(("acquire", writer_name))
        return self.allowed

    async def release(self, writer_name: str) -> None:
        self.calls.append(("release", writer_name))


def _principal(
    principal_id: str,
    role: str,
    *,
    project_id: str = PROJECT,
    environment: str = ENV,
    account_id: str = ACCOUNT,
    venue: str | None = None,
    strategy: str | None = None,
) -> TrustedPrincipalV1:
    claims = PrincipalV1(
        principal_id=principal_id,
        project_id=project_id,
        roles=(role,),
        env=environment,
        venue=venue,
        portfolio=account_id,
        strategy=strategy,
    )
    return TrustedPrincipalAdapterV1.from_verified_claims(
        claims, verifier_marker=_VERIFIER_MARKER
    )


def _auth_policy() -> AuthorizationPolicyV1:
    start = datetime(2020, 1, 1, tzinfo=UTC)
    end = datetime(2035, 1, 1, tzinfo=UTC)
    rules = []
    for role in ("risk_officer", "risk_admin"):
        rules.extend(
            (
                PolicyRuleV1(
                    rule_id=f"{role}-change",
                    effect=EffectV1.ALLOW,
                    roles=(role,),
                    actions=("risk:limits:change",),
                    resources=(ACCOUNT,),
                    env=ENV,
                    not_before=start,
                    not_after=end,
                    portfolio=ACCOUNT,
                ),
                PolicyRuleV1(
                    rule_id=f"{role}-soft-approve",
                    effect=EffectV1.ALLOW,
                    roles=(role,),
                    actions=("risk:soft-approve",),
                    resources=(ACCOUNT,),
                    env=ENV,
                    not_before=start,
                    not_after=end,
                    venue=VENUE,
                    portfolio=ACCOUNT,
                    strategy=STRATEGY,
                ),
                PolicyRuleV1(
                    rule_id=f"{role}-soft-request",
                    effect=EffectV1.ALLOW,
                    roles=(role,),
                    actions=("risk:soft-request",),
                    resources=(ACCOUNT,),
                    env=ENV,
                    not_before=start,
                    not_after=end,
                    venue=VENUE,
                    portfolio=ACCOUNT,
                    strategy=STRATEGY,
                ),
                PolicyRuleV1(
                    rule_id=f"{role}-soft-consume",
                    effect=EffectV1.ALLOW,
                    roles=(role,),
                    actions=("risk:soft-consume",),
                    resources=(ACCOUNT,),
                    env=ENV,
                    not_before=start,
                    not_after=end,
                    venue=VENUE,
                    portfolio=ACCOUNT,
                    strategy=STRATEGY,
                ),
            )
        )
    for action_name in ("risk:soft-request", "risk:soft-consume"):
        rules.append(
            PolicyRuleV1(
                rule_id=f"trader-{action_name.rsplit(':', 1)[1]}",
                effect=EffectV1.ALLOW,
                roles=("trader",),
                actions=(action_name,),
                resources=(ACCOUNT,),
                env=ENV,
                not_before=start,
                not_after=end,
                venue=VENUE,
                portfolio=ACCOUNT,
                strategy=STRATEGY,
            )
        )
    return AuthorizationPolicyV1(
        version="v1",
        project_id=PROJECT,
        expires_at=end,
        rules=tuple(rules),
    )


def _hard_policy(
    *,
    revision: str,
    max_notional: str,
    environment: str = ENV,
    account_id: str = ACCOUNT,
) -> VerifiedHardLimitsV1:
    policy = HardLimitsV1(
        version=1,
        revision=revision,
        environment=environment,
        account_id=account_id,
        scope="ACCOUNT",
        effective_from_ns=0,
        effective_until_ns=9_000_000_000_000_000_000,
        limit_currency="USD",
        max_order_quantity="10",
        max_order_notional=max_notional,
        max_projected_position="100",
        max_gross_exposure="10000",
        max_net_exposure="5000",
        max_leverage="5",
        max_daily_loss="1000",
        max_order_rate=10,
        order_rate_window_ns=60_000_000_000,
        max_data_age_ns=300_000_000_000,
        allowed_strategies=(STRATEGY,),
        allowed_venues=(VENUE,),
        allowed_instruments=(DatedInstrumentV1(INSTRUMENT, 0, 9_000_000_000_000_000_000),),
    )
    from leviathan_core.risk_limits.kernel import verify_hard_limits

    return verify_hard_limits((policy,), _FixtureVerifier())


def _policy_change(
    current: VerifiedHardLimitsV1,
    proposed: VerifiedHardLimitsV1,
    *,
    actor_id: str,
    expected_version: int = 0,
    environment: str = ENV,
    account_id: str = ACCOUNT,
    recorded_at_ns: int = NOW_NS,
) -> LimitPolicyChangeV1:
    return LimitPolicyChangeV1(
        environment=environment,
        account_id=account_id,
        expected_version=expected_version,
        before_digest=current.verification.policy_digest,
        after_digest=proposed.verification.policy_digest,
        actor_id=actor_id,
        reason="fixture policy review",
        recorded_at_ns=recorded_at_ns,
        correlation_id=f"correlation-{expected_version}",
        attempt_id=f"attempt-{expected_version}",
    )


def _approval_request(*, expires_at_ns: int | None = None) -> SoftApprovalRequestV1:
    return SoftApprovalRequestV1(
        environment=ENV,
        account_id=ACCOUNT,
        strategy_id=STRATEGY,
        venue_id=VENUE,
        instrument_id=INSTRUMENT,
        order_digest=ORDER_DIGEST,
        soft_rule_id=SOFT_RULE,
        policy_version=1,
        expires_at_ns=NOW_NS + 60_000_000_000 if expires_at_ns is None else expires_at_ns,
        correlation_id="soft-approval-correlation",
    )


class _MutableClock:
    def __init__(self, now_ns: int) -> None:
        self.now_ns = now_ns

    def __call__(self) -> datetime:
        epoch = datetime(1970, 1, 1, tzinfo=UTC)
        return epoch + timedelta(microseconds=self.now_ns // 1_000)


def _soft_policy(required_approvers: int = 1) -> SoftApprovalPolicyV1:
    return SoftApprovalPolicyV1(
        rules=(
            SoftApprovalRuleRequirementV1(
                soft_rule_id=SOFT_RULE,
                required_approvers=required_approvers,
            ),
        )
    )


async def _seed_policy_version_one(
    store: RiskLimitEventStore, authorization_policy: AuthorizationPolicyV1
) -> None:
    base = _hard_policy(revision="fixture-risk-v0", max_notional="1000")
    current = _hard_policy(revision="fixture-risk-v1", max_notional="900")
    actor = _principal("fixture-risk-admin", "risk_admin")
    event = await change_limit_policy(
        _policy_change(base, current, actor_id=actor.principal_id),
        base,
        current,
        actor,
        authorization_policy,
        store,
    )
    assert event.decision == "ALLOW"


def _assessment(decision: str) -> LimitAssessmentV1:
    return LimitAssessmentV1(
        decision=decision,
        reason_codes=("FIXTURE_HARD_LIMIT",) if decision == "DENY" else (),
        matched_policy_revisions=(),
        observed_values=(),
        projected_values=(),
        state_event_id=None,
        evidence_digest="b" * 64,
    )


async def _store(
    policy: AuthorizationPolicyV1,
    database_url: str = "sqlite+aiosqlite:///:memory:",
    *,
    required_approvers: int = 1,
    clock: _MutableClock | None = None,
    seed_policy_state: bool = False,
) -> tuple[object, object, RiskLimitEventStore]:
    engine, sessions = create_engine_and_sessionmaker(database_url)
    await migrate_risk_limits_v1(engine, writer_guard=_PermitGuard(), applied_at_ns=NOW_NS)
    store = RiskLimitEventStore(
        sessions,
        authorization_policy=policy,
        soft_approval_policy=_soft_policy(required_approvers),
        clock=clock if clock is not None else _MutableClock(NOW_NS + 1_000_000),
    )
    if seed_policy_state:
        await _seed_policy_version_one(store, policy)
    return engine, sessions, store


@pytest.mark.asyncio
async def test_soft_approval_is_not_a_hard_allow_and_scope_failure_does_not_consume() -> None:
    policy = _auth_policy()
    engine, sessions, store = await _store(policy, seed_policy_state=True)
    try:
        requester = _principal("fixture-trader", "trader", venue=VENUE, strategy=STRATEGY)
        approver = _principal(
            "fixture-risk-officer", "risk_officer", venue=VENUE, strategy=STRATEGY
        )
        approval = await issue_soft_approval(
            _approval_request(),
            requester,
            (approver,),
            policy,
            audit_store=store,
        )
        async with sessions() as session:
            issued = (await session.execute(select(risk_soft_approvals))).mappings().all()
            assert len(issued) == 1
            assert issued[0]["approval_id"] == approval.approval_id
            issue_event = (
                await session.execute(
                    select(risk_audit_events).where(
                        risk_audit_events.c.event_id == issued[0]["event_id"]
                    )
                )
            ).mappings().one()
            assert issue_event["source_event_ids"] == []
        wrong_environment = await consume_soft_approval(
            approval,
            order_digest=ORDER_DIGEST,
            environment="LIVE",
            account_id=ACCOUNT,
            strategy_id=STRATEGY,
            venue_id=VENUE,
            instrument_id=INSTRUMENT,
            soft_rule_id=SOFT_RULE,
            policy_version=1,
            consumer=requester,
            audit_store=store,
        )
        assert wrong_environment.decision == "DENY"
        assert wrong_environment.reason_code == "SOFT_APPROVAL_INVALID"
        assert await validate_soft_approval(
            approval,
            order_digest=ORDER_DIGEST,
            environment=ENV,
            account_id=ACCOUNT,
            strategy_id=STRATEGY,
            venue_id=VENUE,
            instrument_id=INSTRUMENT,
            soft_rule_id=SOFT_RULE,
            policy_version=1,
            audit_store=store,
        )
        assert not await validate_soft_approval(
            approval,
            order_digest=ORDER_DIGEST,
            environment="LIVE",
            account_id=ACCOUNT,
            strategy_id=STRATEGY,
            venue_id=VENUE,
            instrument_id=INSTRUMENT,
            soft_rule_id=SOFT_RULE,
            policy_version=1,
            audit_store=store,
        )

        # RISK-005 does not accept caller-asserted hard assessments. A fabricated
        # ALLOW object cannot turn this soft capability into a hard-limit decision.
        with pytest.raises(TypeError):
            await consume_soft_approval(
                approval,
                order_digest=ORDER_DIGEST,
                environment=ENV,
                account_id=ACCOUNT,
                strategy_id=STRATEGY,
                venue_id=VENUE,
                instrument_id=INSTRUMENT,
                soft_rule_id=SOFT_RULE,
                policy_version=1,
                consumer=requester,
                hard_assessment=_assessment("ALLOW"),  # type: ignore[call-arg]
                audit_store=store,
            )
        async with sessions() as session:
            assert (
                await session.execute(select(risk_soft_approval_claims.c.approval_id))
            ).first() is None

        allowed = await consume_soft_approval(
            approval,
            order_digest=ORDER_DIGEST,
            environment=ENV,
            account_id=ACCOUNT,
            strategy_id=STRATEGY,
            venue_id=VENUE,
            instrument_id=INSTRUMENT,
            soft_rule_id=SOFT_RULE,
            policy_version=1,
            consumer=requester,
            audit_store=store,
        )
        assert allowed.decision == "ALLOW"
        assert allowed.reason_code == "SOFT_RULE_SATISFIED"
        async with sessions() as session:
            claim = (
                await session.execute(select(risk_soft_approval_claims.c.approval_id))
            ).one()
            consumed = (
                await session.execute(
                    select(risk_audit_events).where(
                        risk_audit_events.c.event_hash == allowed.event_hash
                    )
                )
            ).mappings().one()
        assert claim.approval_id == approval.approval_id
        assert consumed["actor_ref"] == hashlib.sha256(
            requester.principal_id.encode("utf-8")
        ).hexdigest()
        assert consumed["reason_code"] == "SOFT_RULE_SATISFIED"
        assert consumed["source_event_ids"] == [issue_event["event_id"]]

        # Replay is denied and audited, never converted into a second use.
        replay = await consume_soft_approval(
            approval,
            order_digest=ORDER_DIGEST,
            environment=ENV,
            account_id=ACCOUNT,
            strategy_id=STRATEGY,
            venue_id=VENUE,
            instrument_id=INSTRUMENT,
            soft_rule_id=SOFT_RULE,
            policy_version=1,
            consumer=requester,
            audit_store=store,
        )
        assert replay.decision == "DENY"
        assert replay.reason_code == "SOFT_APPROVAL_REPLAY"
        assert await store.verify_audit_chain()
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_trusted_policy_rbac_denies_trader_and_policy_loosening_is_audited() -> None:
    policy = _auth_policy()
    engine, sessions, store = await _store(policy)
    try:
        current = _hard_policy(revision="fixture-r1", max_notional="1000")
        loosened = _hard_policy(revision="fixture-r2", max_notional="2000")
        trader = _principal("fixture-trader", "trader")
        change = _policy_change(current, loosened, actor_id="fixture-trader")
        event = await change_limit_policy(change, current, loosened, trader, policy, store)
        assert event.decision == "DENY"
        assert event.reason_code == "ACTOR_UNAUTHORIZED"
        async with sessions() as session:
            assert (await session.execute(select(risk_policy_state))).first() is None

        risk_officer = _principal("fixture-risk-officer", "risk_officer")
        authorized_change = _policy_change(current, loosened, actor_id="fixture-risk-officer")
        loosen_event = await change_limit_policy(
            authorized_change, current, loosened, risk_officer, policy, store
        )
        assert loosen_event.decision == "DENY"
        assert loosen_event.reason_code == "POLICY_WOULD_LOOSEN"
        assert await store.verify_audit_chain()
        async with sessions() as session:
            assert (await session.execute(select(risk_policy_state))).first() is None

        tightened = _hard_policy(revision="fixture-r2-tight", max_notional="900")
        tight_change = _policy_change(current, tightened, actor_id="fixture-risk-officer")
        accepted = await change_limit_policy(
            tight_change, current, tightened, risk_officer, policy, store
        )
        assert accepted.decision == "ALLOW"
        async with sessions() as session:
            saved = (await session.execute(select(risk_policy_state))).mappings().one()
            assert saved["version"] == 1
            assert saved["policy_digest"] == tightened.verification.policy_digest
        assert await store.verify_audit_chain()
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_soft_approval_requires_distinct_scoped_humans_and_exact_scope() -> None:
    policy = _auth_policy()
    engine, sessions, store = await _store(
        policy, required_approvers=2, seed_policy_state=True
    )
    try:
        request = _approval_request()
        requester = _principal("fixture-trader", "trader", venue=VENUE, strategy=STRATEGY)
        officer_a = _principal(
            "fixture-risk-a", "risk_officer", venue=VENUE, strategy=STRATEGY
        )
        officer_b = _principal(
            "fixture-risk-b", "risk_admin", venue=VENUE, strategy=STRATEGY
        )
        with pytest.raises(RiskApprovalError) as one_person:
            await issue_soft_approval(
                request,
                requester,
                (officer_a,),
                policy,
                audit_store=store,
            )
        assert one_person.value.code == "ACTOR_UNAUTHORIZED"
        assert store.required_approvers(SOFT_RULE) == 2
        with pytest.raises(TypeError):
            await issue_soft_approval(
                request,
                requester,
                (officer_a,),
                policy,
                audit_store=store,
                require_two_approvers=False,  # type: ignore[call-arg]
            )
        trader = _principal("fixture-trader", "trader", venue=VENUE, strategy=STRATEGY)
        with pytest.raises(RiskApprovalError) as unauthorized:
            await issue_soft_approval(
                request,
                requester,
                (trader,),
                policy,
                audit_store=store,
            )
        assert unauthorized.value.code == "ACTOR_UNAUTHORIZED"

        # The requester is derived from the trusted principal, not a request field
        # that could name a different identity.
        with pytest.raises(TypeError):
            replace(request, requester_id=officer_b.principal_id)
        with pytest.raises(RiskApprovalError) as self_approval:
            await issue_soft_approval(
                request,
                officer_a,
                (officer_a,),
                policy,
                audit_store=store,
            )
        assert self_approval.value.code == "ACTOR_UNAUTHORIZED"

        approval = await issue_soft_approval(
            request,
            requester,
            (officer_a, officer_b),
            policy,
            audit_store=store,
        )
        assert approval.approver_ids == ("fixture-risk-a", "fixture-risk-b")
        kwargs = {
            "order_digest": ORDER_DIGEST,
            "environment": ENV,
            "account_id": ACCOUNT,
            "strategy_id": STRATEGY,
            "venue_id": VENUE,
            "instrument_id": INSTRUMENT,
            "soft_rule_id": SOFT_RULE,
            "policy_version": 1,
            "audit_store": store,
        }
        assert await validate_soft_approval(approval, **kwargs)
        assert not await validate_soft_approval(
            approval, **(kwargs | {"order_digest": "c" * 64})
        )
        assert not await validate_soft_approval(
            approval, **(kwargs | {"account_id": "other-account"})
        )
        assert not await validate_soft_approval(
            approval, **(kwargs | {"strategy_id": "other-strategy"})
        )
        assert not await validate_soft_approval(
            approval, **(kwargs | {"policy_version": 2})
        )
        async with sessions() as session:
            audit = (await session.execute(select(risk_audit_events))).mappings().all()
            assert sum(row["decision"] == "DENY" for row in audit) == 3
            assert sum(row["action"] == "SOFT_APPROVAL_ISSUED" for row in audit) == 4
        assert await store.verify_audit_chain()
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_rewound_trusted_clock_denies_without_consuming_or_claiming() -> None:
    policy = _auth_policy()
    clock = _MutableClock(NOW_NS + 5_000_000_000)
    engine, sessions, store = await _store(policy, clock=clock, seed_policy_state=True)
    try:
        requester = _principal("fixture-trader", "trader", venue=VENUE, strategy=STRATEGY)
        approver = _principal(
            "fixture-risk-officer", "risk_officer", venue=VENUE, strategy=STRATEGY
        )
        approval = await issue_soft_approval(
            _approval_request(),
            requester,
            (approver,),
            policy,
            audit_store=store,
        )
        clock.now_ns -= 1_000_000_000
        with pytest.raises(RiskLimitEventStoreError) as regressed:
            await consume_soft_approval(
                approval,
                order_digest=ORDER_DIGEST,
                environment=ENV,
                account_id=ACCOUNT,
                strategy_id=STRATEGY,
                venue_id=VENUE,
                instrument_id=INSTRUMENT,
                soft_rule_id=SOFT_RULE,
                policy_version=1,
                consumer=requester,
                audit_store=store,
            )
        assert regressed.value.code == "CLOCK_REGRESSION"
        async with sessions() as session:
            assert (
                await session.execute(select(risk_soft_approval_claims))
            ).first() is None
            persisted = (
                await session.execute(
                    select(risk_soft_approvals).where(
                        risk_soft_approvals.c.approval_id == approval.approval_id
                    )
                )
            ).mappings().one()
            assert persisted["consumed_at_ns"] is None
            consume_events = (
                await session.execute(
                    select(risk_audit_events.c.action).where(
                        risk_audit_events.c.action == "SOFT_APPROVAL_CONSUMED"
                    )
                )
            ).all()
        assert consume_events == []
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_current_policy_version_revokes_older_soft_approval() -> None:
    policy = _auth_policy()
    engine, sessions, store = await _store(policy, seed_policy_state=True)
    try:
        requester = _principal("fixture-trader", "trader", venue=VENUE, strategy=STRATEGY)
        approver = _principal(
            "fixture-risk-officer", "risk_officer", venue=VENUE, strategy=STRATEGY
        )
        approval = await issue_soft_approval(
            _approval_request(), requester, (approver,), policy, audit_store=store
        )
        current = _hard_policy(revision="fixture-risk-v1", max_notional="900")
        tightened = _hard_policy(revision="fixture-risk-v2", max_notional="800")
        change_actor = _principal("fixture-risk-admin", "risk_admin")
        changed = await change_limit_policy(
            _policy_change(
                current,
                tightened,
                actor_id=change_actor.principal_id,
                expected_version=1,
            ),
            current,
            tightened,
            change_actor,
            policy,
            store,
        )
        assert changed.decision == "ALLOW"

        result = await consume_soft_approval(
            approval,
            order_digest=ORDER_DIGEST,
            environment=ENV,
            account_id=ACCOUNT,
            strategy_id=STRATEGY,
            venue_id=VENUE,
            instrument_id=INSTRUMENT,
            soft_rule_id=SOFT_RULE,
            policy_version=1,
            consumer=requester,
            audit_store=store,
        )
        assert result.decision == "DENY"
        assert result.reason_code == "VERSION_CONFLICT"
        async with sessions() as session:
            assert (
                await session.execute(select(risk_soft_approval_claims))
            ).first() is None
            state = (await session.execute(select(risk_policy_state))).mappings().one()
            assert state["version"] == 2
        assert await store.verify_audit_chain()
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_policy_change_uses_trusted_clock_and_binds_policy_scope() -> None:
    policy = _auth_policy()
    clock = _MutableClock(NOW_NS + 5_000_000_000)
    engine, sessions, store = await _store(policy, clock=clock)
    try:
        current = _hard_policy(revision="fixture-current", max_notional="1000")
        tightened = _hard_policy(revision="fixture-tight", max_notional="900")
        actor = _principal("fixture-risk-officer", "risk_officer")
        far_future = NOW_NS + 100 * 365 * 24 * 60 * 60 * 1_000_000_000
        accepted = await change_limit_policy(
            _policy_change(
                current,
                tightened,
                actor_id=actor.principal_id,
                recorded_at_ns=far_future,
            ),
            current,
            tightened,
            actor,
            policy,
            store,
        )
        assert accepted.decision == "ALLOW"
        assert accepted.recorded_at_ns == clock.now_ns
        assert await store.trusted_now_ns() == clock.now_ns

        mismatched = _hard_policy(
            revision="fixture-other-account",
            max_notional="900",
            account_id="other-account",
        )
        mismatch = await change_limit_policy(
            _policy_change(
                tightened,
                mismatched,
                actor_id=actor.principal_id,
                expected_version=1,
            ),
            tightened,
            mismatched,
            actor,
            policy,
            store,
        )
        assert mismatch.decision == "DENY"
        assert mismatch.reason_code == "POLICY_SCOPE_MISMATCH"
        async with sessions() as session:
            state = (await session.execute(select(risk_policy_state))).mappings().one()
            assert state["version"] == 1
            assert state["policy_digest"] == tightened.verification.policy_digest
        assert await store.verify_audit_chain()
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_wrong_scope_requester_and_consumer_are_audited_without_claim() -> None:
    policy = _auth_policy()
    engine, sessions, store = await _store(policy, seed_policy_state=True)
    try:
        approver = _principal(
            "fixture-risk-officer", "risk_officer", venue=VENUE, strategy=STRATEGY
        )
        wrong_project = _principal(
            "fixture-outsider",
            "trader",
            project_id="other-project",
            venue=VENUE,
            strategy=STRATEGY,
        )
        with pytest.raises(RiskApprovalError) as rejected:
            await issue_soft_approval(
                _approval_request(), wrong_project, (approver,), policy, audit_store=store
            )
        assert rejected.value.code == "ACTOR_UNAUTHORIZED"

        requester = _principal("fixture-trader", "trader", venue=VENUE, strategy=STRATEGY)
        approval = await issue_soft_approval(
            _approval_request(), requester, (approver,), policy, audit_store=store
        )
        wrong_scope_consumer = _principal(
            "fixture-wrong-scope-consumer",
            "trader",
            account_id="other-account",
            venue=VENUE,
            strategy=STRATEGY,
        )
        denied = await consume_soft_approval(
            approval,
            order_digest=ORDER_DIGEST,
            environment=ENV,
            account_id=ACCOUNT,
            strategy_id=STRATEGY,
            venue_id=VENUE,
            instrument_id=INSTRUMENT,
            soft_rule_id=SOFT_RULE,
            policy_version=1,
            consumer=wrong_scope_consumer,
            audit_store=store,
        )
        assert denied.decision == "DENY"
        assert denied.reason_code == "SOFT_APPROVAL_INVALID"
        async with sessions() as session:
            assert (
                await session.execute(select(risk_soft_approval_claims))
            ).first() is None
            events = (await session.execute(select(risk_audit_events))).mappings().all()
            requester_denial = next(
                row for row in events
                if row["action"] == "SOFT_APPROVAL_ISSUED"
                and row["decision"] == "DENY"
            )
            assert requester_denial["reason_code"] == "ACTOR_UNAUTHORIZED"
            consumer_denial = next(
                row for row in events
                if row["action"] == "SOFT_APPROVAL_CONSUMED"
                and row["decision"] == "DENY"
            )
            assert consumer_denial["actor_ref"] == hashlib.sha256(
                wrong_scope_consumer.principal_id.encode("utf-8")
            ).hexdigest()
        assert await store.verify_audit_chain()
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_audit_chain_survives_restart_and_detects_tampering(tmp_path: Path) -> None:
    policy = _auth_policy()
    database = tmp_path / "risk-audit-restart.sqlite"
    engine, sessions, store = await _store(policy, f"sqlite+aiosqlite:///{database}")
    try:
        current = _hard_policy(revision="fixture-r1", max_notional="1000")
        tightened = _hard_policy(revision="fixture-r2", max_notional="900")
        actor = _principal("fixture-risk-officer", "risk_officer")
        first = await change_limit_policy(
            _policy_change(current, tightened, actor_id=actor.principal_id),
            current,
            tightened,
            actor,
            policy,
            store,
        )
        stale = await change_limit_policy(
            _policy_change(current, tightened, actor_id=actor.principal_id),
            current,
            tightened,
            actor,
            policy,
            store,
        )
        assert (first.sequence, stale.sequence) == (1, 2)
        assert stale.decision == "DENY"
        assert stale.reason_code == "VERSION_CONFLICT"
        assert stale.predecessor_hash == first.event_hash
        assert first.actor_ref != actor.principal_id
        assert await store.verify_audit_chain()

        await engine.dispose()
        engine, sessions = create_engine_and_sessionmaker(f"sqlite+aiosqlite:///{database}")
        store = RiskLimitEventStore(
            sessions,
            authorization_policy=policy,
            soft_approval_policy=_soft_policy(),
            clock=_MutableClock(NOW_NS + 1_000_000),
        )
        assert await store.verify_audit_chain()
        async with sessions() as session, session.begin():
            await session.execute(
                risk_audit_events.update()
                .where(risk_audit_events.c.sequence == 1)
                .values(reason_code="ALTERED_FIXTURE")
            )
        assert not await store.verify_audit_chain()
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_policy_change_and_audit_append_rollback_together_on_write_failure() -> None:
    from sqlalchemy import event
    from sqlalchemy.exc import SQLAlchemyError

    policy = _auth_policy()
    engine, sessions = create_engine_and_sessionmaker("sqlite+aiosqlite:///:memory:")
    await migrate_risk_limits_v1(engine, writer_guard=_PermitGuard(), applied_at_ns=NOW_NS)
    store = RiskLimitEventStore(
        sessions,
        authorization_policy=policy,
        soft_approval_policy=_soft_policy(),
        clock=_MutableClock(NOW_NS + 1_000_000),
    )
    current = _hard_policy(revision="fixture-r1", max_notional="1000")
    tightened = _hard_policy(revision="fixture-r2", max_notional="900")
    actor = _principal("fixture-risk-officer", "risk_officer")

    def fail_policy_insert(
        _conn: object, _cursor: object, statement: str, _parameters: object, _context: object,
        _executemany: bool,
    ) -> None:
        if statement.lstrip().upper().startswith("INSERT INTO RISK_POLICY_STATE"):
            raise SQLAlchemyError("synthetic injected storage failure")

    event.listen(engine.sync_engine, "before_cursor_execute", fail_policy_insert)
    try:
        with pytest.raises(RiskLimitEventStoreError) as failure:
            await change_limit_policy(
                _policy_change(current, tightened, actor_id=actor.principal_id),
                current,
                tightened,
                actor,
                policy,
                store,
            )
        assert failure.value.code == "STORE_FAILURE"
        event.remove(engine.sync_engine, "before_cursor_execute", fail_policy_insert)
        async with sessions() as session:
            assert (await session.execute(select(risk_policy_state))).first() is None
            assert (await session.execute(select(risk_audit_events))).first() is None
        assert await store.verify_audit_chain()

        base = _hard_policy(revision="fixture-seed-v0", max_notional="1000")
        current = _hard_policy(revision="fixture-seed-v1", max_notional="900")
        seed_actor = _principal("fixture-risk-admin", "risk_admin")
        seed_event = await change_limit_policy(
            _policy_change(base, current, actor_id=seed_actor.principal_id),
            base,
            current,
            seed_actor,
            policy,
            store,
        )
        assert seed_event.decision == "ALLOW"

        def fail_soft_approval_insert(
            _conn: object, _cursor: object, statement: str, _parameters: object,
            _context: object, _executemany: bool,
        ) -> None:
            if statement.lstrip().upper().startswith("INSERT INTO RISK_SOFT_APPROVALS"):
                raise SQLAlchemyError("synthetic injected storage failure")

        event.listen(engine.sync_engine, "before_cursor_execute", fail_soft_approval_insert)
        approver = _principal(
            "fixture-risk-officer", "risk_officer", venue=VENUE, strategy=STRATEGY
        )
        requester = _principal("fixture-trader", "trader", venue=VENUE, strategy=STRATEGY)
        with pytest.raises(RiskLimitEventStoreError) as approval_failure:
            await issue_soft_approval(
                _approval_request(),
                requester,
                (approver,),
                policy,
                audit_store=store,
            )
        assert approval_failure.value.code == "STORE_FAILURE"
        assert str(approval_failure.value) == "STORE_FAILURE"
        assert approval_failure.value.args == ("STORE_FAILURE",)
        event.remove(engine.sync_engine, "before_cursor_execute", fail_soft_approval_insert)
        async with sessions() as session:
            events = (await session.execute(select(risk_audit_events))).mappings().all()
            assert [row["event_id"] for row in events] == [seed_event.event_id]
            assert (await session.execute(select(risk_soft_approvals))).first() is None
            saved_policy = (await session.execute(select(risk_policy_state))).mappings().one()
            assert saved_policy["version"] == 1
            assert saved_policy["policy_digest"] == current.verification.policy_digest
        assert await store.verify_audit_chain()
    finally:
        if event.contains(engine.sync_engine, "before_cursor_execute", fail_policy_insert):
            event.remove(engine.sync_engine, "before_cursor_execute", fail_policy_insert)
        await engine.dispose()


@pytest.mark.asyncio
async def test_request_requires_reason_and_bounded_ttl() -> None:
    with pytest.raises(RiskApprovalError) as no_reason:
        LimitPolicyChangeV1(
            environment=ENV,
            account_id=ACCOUNT,
            expected_version=0,
            before_digest="a" * 64,
            after_digest="b" * 64,
            actor_id="fixture-risk",
            reason="  ",
            recorded_at_ns=NOW_NS,
            correlation_id="fixture-correlation",
            attempt_id="fixture-attempt",
        )
    assert no_reason.value.code == "INPUT_INVALID"
    assert str(no_reason.value) == "INPUT_INVALID"
    assert no_reason.value.args == ("INPUT_INVALID",)

    store_policy = _auth_policy()
    engine, _sessions, store = await _store(store_policy, seed_policy_state=True)
    try:
        approver = _principal(
            "fixture-risk-officer", "risk_officer", venue=VENUE, strategy=STRATEGY
        )
        requester = _principal("fixture-trader", "trader", venue=VENUE, strategy=STRATEGY)
        with pytest.raises(RiskApprovalError) as excessive_ttl:
            await issue_soft_approval(
                _approval_request(
                    expires_at_ns=NOW_NS + 1_800_001_000_001
                ),
                requester,
                (approver,),
                store_policy,
                audit_store=store,
            )
        assert excessive_ttl.value.code == "ACTOR_UNAUTHORIZED"
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_concurrent_use_of_one_approval_has_at_most_one_allow() -> None:
    policy = _auth_policy()
    engine, _sessions, store = await _store(policy, seed_policy_state=True)
    try:
        approver = _principal(
            "fixture-risk-officer", "risk_officer", venue=VENUE, strategy=STRATEGY
        )
        requester = _principal("fixture-trader", "trader", venue=VENUE, strategy=STRATEGY)
        approval = await issue_soft_approval(
            _approval_request(),
            requester,
            (approver,),
            policy,
            audit_store=store,
        )
        async def consume():
            return await consume_soft_approval(
                approval,
                order_digest=ORDER_DIGEST,
                environment=ENV,
                account_id=ACCOUNT,
                strategy_id=STRATEGY,
                venue_id=VENUE,
                instrument_id=INSTRUMENT,
                soft_rule_id=SOFT_RULE,
                policy_version=1,
                consumer=requester,
                audit_store=store,
            )

        first, second = await asyncio.gather(consume(), consume())
        assert sorted((first.decision, second.decision)) == ["ALLOW", "DENY"]
        assert await store.verify_audit_chain()
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_two_store_instances_reconcile_concurrent_consumption(tmp_path: Path) -> None:
    policy = _auth_policy()
    database = tmp_path / "risk005-two-store-race.sqlite"
    engine, sessions, first_store = await _store(
        policy,
        f"sqlite+aiosqlite:///{database}",
        seed_policy_state=True,
    )
    second_store = RiskLimitEventStore(
        sessions,
        authorization_policy=policy,
        soft_approval_policy=_soft_policy(),
        clock=_MutableClock(NOW_NS + 1_000_000),
    )
    try:
        requester = _principal("fixture-trader", "trader", venue=VENUE, strategy=STRATEGY)
        approver = _principal(
            "fixture-risk-officer", "risk_officer", venue=VENUE, strategy=STRATEGY
        )
        approval = await issue_soft_approval(
            _approval_request(), requester, (approver,), policy, audit_store=first_store
        )

        async def consume(store: RiskLimitEventStore):
            return await consume_soft_approval(
                approval,
                order_digest=ORDER_DIGEST,
                environment=ENV,
                account_id=ACCOUNT,
                strategy_id=STRATEGY,
                venue_id=VENUE,
                instrument_id=INSTRUMENT,
                soft_rule_id=SOFT_RULE,
                policy_version=1,
                consumer=requester,
                audit_store=store,
            )

        outcomes = await asyncio.gather(consume(first_store), consume(second_store))
        assert sorted(event.decision for event in outcomes) == ["ALLOW", "DENY"]
        denial = next(event for event in outcomes if event.decision == "DENY")
        assert denial.reason_code in {"SOFT_APPROVAL_REPLAY", "STORE_FAILURE"}
        async with sessions() as session:
            claims = (await session.execute(select(risk_soft_approval_claims))).mappings().all()
            events = (await session.execute(select(risk_audit_events))).mappings().all()
        assert len(claims) == 1
        assert sum(
            row["action"] == "SOFT_APPROVAL_CONSUMED" and row["decision"] == "DENY"
            for row in events
        ) >= 1
        assert await first_store.verify_audit_chain()
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_post_commit_error_reconciles_committed_soft_consumption() -> None:
    from sqlalchemy import event
    from sqlalchemy.exc import SQLAlchemyError
    from sqlalchemy.orm import Session

    policy = _auth_policy()
    engine, sessions, store = await _store(policy, seed_policy_state=True)
    try:
        requester = _principal("fixture-trader", "trader", venue=VENUE, strategy=STRATEGY)
        approver = _principal(
            "fixture-risk-officer", "risk_officer", venue=VENUE, strategy=STRATEGY
        )
        approval = await issue_soft_approval(
            _approval_request(), requester, (approver,), policy, audit_store=store
        )
        commits = 0

        def fail_after_durable_consume(_session: object) -> None:
            nonlocal commits
            commits += 1
            # trusted_now_ns commits once; the second commit is the atomic
            # approval-claim + audit transaction, now durable before callback.
            if commits == 2:
                raise SQLAlchemyError("synthetic post-commit disconnect")

        event.listen(Session, "after_commit", fail_after_durable_consume)
        try:
            result = await consume_soft_approval(
                approval,
                order_digest=ORDER_DIGEST,
                environment=ENV,
                account_id=ACCOUNT,
                strategy_id=STRATEGY,
                venue_id=VENUE,
                instrument_id=INSTRUMENT,
                soft_rule_id=SOFT_RULE,
                policy_version=1,
                consumer=requester,
                audit_store=store,
            )
        finally:
            event.remove(Session, "after_commit", fail_after_durable_consume)

        assert result.decision == "ALLOW"
        assert commits >= 2
        async with sessions() as session:
            claims = (await session.execute(select(risk_soft_approval_claims))).mappings().all()
            matching = (
                await session.execute(
                    select(risk_audit_events).where(
                        risk_audit_events.c.event_hash == result.event_hash
                    )
                )
            ).mappings().one()
        assert len(claims) == 1
        assert matching["decision"] == "ALLOW"
        assert await store.verify_audit_chain()
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_post_commit_error_reconciles_committed_soft_issuance() -> None:
    from sqlalchemy import event
    from sqlalchemy.exc import SQLAlchemyError
    from sqlalchemy.orm import Session

    policy = _auth_policy()
    engine, sessions, store = await _store(policy, seed_policy_state=True)
    try:
        requester = _principal("fixture-trader", "trader", venue=VENUE, strategy=STRATEGY)
        approver = _principal(
            "fixture-risk-officer", "risk_officer", venue=VENUE, strategy=STRATEGY
        )
        commits = 0

        def fail_after_durable_issue(_session: object) -> None:
            nonlocal commits
            commits += 1
            # One commit reads the trusted clock; the next atomically writes
            # the issued token and its audit event.
            if commits == 2:
                raise SQLAlchemyError("synthetic post-commit disconnect")

        event.listen(Session, "after_commit", fail_after_durable_issue)
        try:
            approval = await issue_soft_approval(
                _approval_request(), requester, (approver,), policy, audit_store=store
            )
        finally:
            event.remove(Session, "after_commit", fail_after_durable_issue)

        assert commits >= 2
        async with sessions() as session:
            persisted = (
                await session.execute(
                    select(risk_soft_approvals).where(
                        risk_soft_approvals.c.approval_id == approval.approval_id
                    )
                )
            ).mappings().one()
            issuance = (
                await session.execute(
                    select(risk_audit_events).where(
                        risk_audit_events.c.event_id == persisted["event_id"]
                    )
                )
            ).mappings().one()
        assert persisted["approval_id"] == approval.approval_id
        assert issuance["decision"] == "ALLOW"
        assert issuance["source_event_ids"] == []
        assert await store.verify_audit_chain()
    finally:
        await engine.dispose()
