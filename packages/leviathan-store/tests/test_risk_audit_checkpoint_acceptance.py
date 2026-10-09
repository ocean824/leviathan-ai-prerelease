"""Black-box acceptance for signed, scoped risk-audit checkpoints."""

from __future__ import annotations

import asyncio
import base64
import json
import math
import random
from dataclasses import replace
from datetime import UTC, datetime
from functools import cache, lru_cache
from hashlib import sha256
from pathlib import Path
from typing import Any

import pytest
from leviathan_store.migrations.risk_limits_v1 import migrate_risk_limits_v1
from leviathan_store.risk_limit_events import (
    RiskLimitEventStore,
    RiskLimitEventStoreError,
    VerifiedRiskAuditSuffixV1,
    require_verified_risk_audit_suffix,
    risk_audit_events,
    risk_audit_head,
)
from sqlalchemy import delete, insert, update
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

# API adapter: keep writer-specific import names and constructor bindings here.
from leviathan_core.execution.order_models import LedgerIntegrityKey
from leviathan_core.risk_limits.approval import SoftApprovalPolicyV1, SoftApprovalRequestV1
from leviathan_core.risk_limits.audit_checkpoint import (
    RiskAuditCheckpointError,
    RiskAuditCheckpointV1,
    RiskAuditHeadV1,
    RiskAuditScopeV1,
    create_risk_audit_checkpoint,
    verify_suffix_from_checkpoint,
)
from leviathan_core.risk_limits.audit_port import (
    RiskAuditEventV1,
)
from leviathan_core.security.authz_models import (
    AuthorizationPolicyV1,
    EffectV1,
    PolicyRuleV1,
)
from leviathan_core.security.principal_verifier import (
    PrincipalVerifier,
    RSAPublicKeyV1,
    TrustedIssuerV1,
)

NOW_NS = 1_800_000_000_000_000_000
STORE_NOW = datetime(2027, 1, 1, tzinfo=UTC)
TEST_KEY = LedgerIntegrityKey(b"synthetic acceptance key only; never a production secret")
TEST_KEY_OTHER = LedgerIntegrityKey(b"another synthetic acceptance key for wrong-key cases")
SCOPE = RiskAuditScopeV1(environment="PAPER", account_id="acct-checkpoint-test")


class _WriterGuard:
    async def acquire(self, writer_name: str) -> bool:
        return writer_name == "risk_limits_v1"

    async def release(self, writer_name: str) -> None:
        return None


def _prime(rng: random.Random) -> int:
    """Deterministic synthetic RSA prime generation for the test identity only."""
    while True:
        candidate = rng.getrandbits(1024) | (3 << 1022) | 1
        if any(candidate % divisor == 0 for divisor in (3, 5, 7, 11, 13, 17, 19, 23, 29)):
            continue
        s, d = 0, candidate - 1
        while d % 2 == 0:
            s, d = s + 1, d // 2
        for base in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
            x = pow(base, d, candidate)
            if x in (1, candidate - 1):
                continue
            for _ in range(s - 1):
                x = pow(x, 2, candidate)
                if x == candidate - 1:
                    break
            else:
                break
        else:
            return candidate


@lru_cache(maxsize=1)
def _synthetic_rsa() -> tuple[RSAPublicKeyV1, int]:
    rng = random.Random(0xA0D17)
    p, q = _prime(rng), _prime(rng)
    while q == p or math.gcd(65537, (p - 1) * (q - 1)) != 1:
        q = _prime(rng)
    modulus = p * q
    return RSAPublicKeyV1(modulus, 65537), pow(65537, -1, (p - 1) * (q - 1))


class _KeySet:
    def get_key(self, issuer: str, kid: str) -> RSAPublicKeyV1 | None:
        public, _ = _synthetic_rsa()
        if issuer == "issuer.synthetic" and kid == "acceptance.1":
            return public
        return None


class _Revocations:
    def is_revoked(self, issuer: str, jti: str) -> bool:
        return False


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


@cache
def _trusted_principal(account_id: str) -> object:
    public, private = _synthetic_rsa()
    verifier = PrincipalVerifier(
        trusted_issuer=TrustedIssuerV1(
            "issuer.synthetic", "api.synthetic", "org.synthetic", "checkpoint-acceptance", "PAPER"
        ),
        key_set=_KeySet(),
        revocations=_Revocations(),
        clock=lambda: STORE_NOW,
    )
    seconds = int(STORE_NOW.timestamp())
    header = {"alg": "RS256", "kid": "acceptance.1"}
    claims = {
        "iss": "issuer.synthetic",
        "aud": "api.synthetic",
        "org": "org.synthetic",
        "sub": "synthetic-requester",
        "role": "synthetic-role",
        "scope": ["research.read"],
        "env": "PAPER",
        "portfolio": account_id,
        "jti": f"checkpoint-jti-{account_id}",
        "iat": seconds - 10,
        "nbf": seconds - 10,
        "exp": seconds + 100,
    }
    encoded_header, encoded_claims = (
        _b64(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())
        for value in (header, claims)
    )
    signing_input = f"{encoded_header}.{encoded_claims}"
    digest_info = (
        bytes.fromhex("3031300d060960864801650304020105000420")
        + sha256(signing_input.encode("ascii")).digest()
    )
    size = (public.modulus.bit_length() + 7) // 8
    block = b"\x00\x01" + b"\xff" * (size - len(digest_info) - 3) + b"\x00" + digest_info
    signature = pow(int.from_bytes(block, "big"), private, public.modulus).to_bytes(size, "big")
    token = f"{signing_input}.{_b64(signature)}"
    verified = verifier.verify(token)
    return verifier.to_trusted_principal(verified)


async def _create_event_chain(
    count: int,
    *,
    scope: RiskAuditScopeV1 = SCOPE,
    variant: str = "base",
) -> tuple[RiskAuditEventV1, ...]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    try:
        await migrate_risk_limits_v1(engine, writer_guard=_WriterGuard(), applied_at_ns=NOW_NS)
        store = _store(async_sessionmaker(engine, expire_on_commit=False))
        requester = _trusted_principal(scope.account_id)
        events: list[RiskAuditEventV1] = []
        now_ns = int(STORE_NOW.timestamp()) * 1_000_000_000
        for sequence in range(1, count + 1):
            request = SoftApprovalRequestV1(
                environment=scope.environment,
                account_id=scope.account_id,
                strategy_id="synthetic-strategy",
                venue_id="synthetic-venue",
                instrument_id="synthetic-instrument",
                order_digest=sha256(f"{variant}:{sequence}".encode()).hexdigest(),
                soft_rule_id="synthetic-rule",
                policy_version=1,
                expires_at_ns=now_ns + 120_000_000_000,
                correlation_id=f"checkpoint-{variant}-{sequence}",
            )
            event = await store.issue_soft_approval(
                request=request,
                requester=requester,
                approval=None,
                approvers=(),
            )
            events.append(event)
        return tuple(events)
    finally:
        await engine.dispose()


async def _create_interleaved_event_chain(
    accounts: tuple[str, ...],
) -> tuple[RiskAuditEventV1, ...]:
    """Issue one global chain whose account scopes are interleaved."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    try:
        await migrate_risk_limits_v1(engine, writer_guard=_WriterGuard(), applied_at_ns=NOW_NS)
        store = _store(async_sessionmaker(engine, expire_on_commit=False))
        principals = {account: _trusted_principal(account) for account in set(accounts)}
        events: list[RiskAuditEventV1] = []
        now_ns = int(STORE_NOW.timestamp()) * 1_000_000_000
        for sequence, account_id in enumerate(accounts, 1):
            request = SoftApprovalRequestV1(
                environment="PAPER",
                account_id=account_id,
                strategy_id="synthetic-strategy",
                venue_id="synthetic-venue",
                instrument_id="synthetic-instrument",
                order_digest=sha256(f"interleaved:{sequence}".encode()).hexdigest(),
                soft_rule_id="synthetic-rule",
                policy_version=1,
                expires_at_ns=now_ns + 120_000_000_000,
                correlation_id=f"checkpoint-interleaved-{sequence}",
            )
            event = await store.issue_soft_approval(
                request=request,
                requester=principals[account_id],
                approval=None,
                approvers=(),
            )
            events.append(event)
        return tuple(events)
    finally:
        await engine.dispose()


async def _persist_chain(
    path: Path,
    events: tuple[RiskAuditEventV1, ...],
) -> tuple[Any, RiskLimitEventStore]:
    engine = create_async_engine(f"sqlite+aiosqlite:///{path}")
    await migrate_risk_limits_v1(engine, writer_guard=_WriterGuard(), applied_at_ns=NOW_NS)
    async with engine.begin() as connection:
        for event in events:
            row = event.model_dump(exclude={"schema_version"})
            row["source_event_ids"] = list(event.source_event_ids)
            await connection.execute(insert(risk_audit_events).values(**row))
        await connection.execute(
            update(risk_audit_head)
            .where(risk_audit_head.c.head_id == 1)
            .values(sequence=len(events), chain_tip=events[-1].event_hash if events else None)
        )
    return engine, _store(async_sessionmaker(engine, expire_on_commit=False))


@cache
def _event_chain(
    count: int,
    *,
    scope: RiskAuditScopeV1 = SCOPE,
    variant: str = "base",
) -> tuple[RiskAuditEventV1, ...]:
    return asyncio.run(_create_event_chain(count, scope=scope, variant=variant))


def _issue(
    events: tuple[RiskAuditEventV1, ...],
    *,
    scope: RiskAuditScopeV1 = SCOPE,
    key: LedgerIntegrityKey = TEST_KEY,
) -> RiskAuditCheckpointV1:
    return create_risk_audit_checkpoint(
        events,
        key=key,
        scope=scope,
    )


def _verify(
    checkpoint: RiskAuditCheckpointV1,
    events: tuple[RiskAuditEventV1, ...],
    *,
    head: RiskAuditHeadV1,
    scope: RiskAuditScopeV1 = SCOPE,
    key: LedgerIntegrityKey = TEST_KEY,
) -> object:
    return verify_suffix_from_checkpoint(
        checkpoint,
        events,
        supplied_head=head,
        key=key,
        scope=scope,
    )


def _tamper_checkpoint(
    checkpoint: RiskAuditCheckpointV1, **changes: object
) -> RiskAuditCheckpointV1:
    """Produce an adversarial copy without relying on the model's constructor style."""
    model_copy = getattr(checkpoint, "model_copy", None)
    if callable(model_copy):
        return model_copy(update=changes)
    return replace(checkpoint, **changes)


def _store(sessions: async_sessionmaker[Any]) -> RiskLimitEventStore:
    policy = AuthorizationPolicyV1(
        version="v1",
        project_id="checkpoint-acceptance",
        expires_at=datetime(2028, 1, 1, tzinfo=UTC),
        rules=(
            PolicyRuleV1(
                rule_id="synthetic-acceptance-rule",
                effect=EffectV1.DENY,
                roles=("synthetic-role",),
                actions=("risk:limits:change",),
                resources=("synthetic-resource",),
                env="PAPER",
                not_before=datetime(2026, 1, 1, tzinfo=UTC),
                not_after=datetime(2028, 1, 1, tzinfo=UTC),
            ),
        ),
    )
    return RiskLimitEventStore(
        sessions,
        authorization_policy=policy,
        soft_approval_policy=SoftApprovalPolicyV1(rules=()),
        clock=lambda: STORE_NOW,
    )


class _UnexpectedSessionFactory:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(self) -> Any:
        self.calls += 1
        raise AssertionError("invalid checkpoints must be rejected before persistence access")


def test_checkpoint_signature_changes_when_each_bound_claim_changes() -> None:
    one = _event_chain(1)
    two = _event_chain(2)
    baseline = _issue(one)

    # Scope, sequence, head hash, and key identity are independently signed.
    other_scope = RiskAuditScopeV1(environment="PAPER", account_id="other-account")
    other_scope_cp = _issue(_event_chain(1, scope=other_scope), scope=other_scope)
    next_sequence_cp = _issue(two)
    other_key_cp = _issue(one, key=TEST_KEY_OTHER)
    different_head_cp = _issue(_event_chain(1, variant="different-head"))
    assert (
        len(
            {
                baseline.signature,
                other_scope_cp.signature,
                next_sequence_cp.signature,
                other_key_cp.signature,
                different_head_cp.signature,
            }
        )
        == 5
    )
    assert baseline.head_hash != next_sequence_cp.head_hash
    assert baseline.head_hash != different_head_cp.head_hash
    assert baseline.key_id != other_key_cp.key_id
    assert (
        baseline.key_id
        == sha256(
            TEST_KEY.sign(b"leviathan/risk-audit-checkpoint/key-id/v1").encode("ascii")
        ).hexdigest()
    )
    same_material_key = LedgerIntegrityKey(
        b"synthetic acceptance key only; never a production secret"
    )
    assert _issue(one, key=same_material_key).key_id == baseline.key_id

    with pytest.raises(RiskAuditCheckpointError):
        changed_key_id = _tamper_checkpoint(baseline, key_id=other_key_cp.key_id)
        _verify(
            changed_key_id,
            (),
            head=RiskAuditHeadV1(sequence=1, head_hash=baseline.head_hash),
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema_version", 2),
        ("environment", "PAPER-OTHER"),
        ("account_id", "acct-other"),
        ("sequence", 2),
        ("head_hash", "f" * 64),
    ],
)
def test_each_checkpoint_claim_is_covered_by_the_signature(field: str, value: object) -> None:
    checkpoint = _issue(_event_chain(1))
    changes = {field: value}
    with pytest.raises(RiskAuditCheckpointError):
        changed = _tamper_checkpoint(checkpoint, **changes)
        supplied_head = RiskAuditHeadV1(sequence=changed.sequence, head_hash=changed.head_hash)
        expected_scope = RiskAuditScopeV1(
            environment=changed.environment, account_id=changed.account_id
        )
        _verify(changed, (), head=supplied_head, scope=expected_scope)


def test_core_suffix_candidate_is_not_the_store_issued_verdict() -> None:
    events = _event_chain(3)
    checkpoint = _issue(events[:1])
    head = RiskAuditHeadV1(sequence=3, head_hash=events[-1].event_hash)

    candidate = _verify(checkpoint, events[1:], head=head)
    with pytest.raises(RiskAuditCheckpointError) as invalid:
        require_verified_risk_audit_suffix(candidate)
    assert invalid.value.code == "CHECKPOINT_INVALID"
    assert str(invalid.value) == "CHECKPOINT_INVALID"


@pytest.mark.asyncio
async def test_invalid_checkpoint_authentication_precedes_bound_and_session_access() -> None:
    sessions = _UnexpectedSessionFactory()
    store = _store(sessions)  # type: ignore[arg-type]
    checkpoints = (
        _tamper_checkpoint(_issue(()), signature="0" * 64),
        _tamper_checkpoint(_issue(_event_chain(1)), signature="1" * 64),
        _tamper_checkpoint(_issue(()), sequence=2**53, signature="2" * 64),
    )
    supplied_head = RiskAuditHeadV1(sequence=257, head_hash="f" * 64)
    failures: list[tuple[str, str]] = []
    for checkpoint in checkpoints:
        with pytest.raises(RiskLimitEventStoreError) as invalid:
            await store.verify_audit_suffix_from_checkpoint(
                checkpoint,
                supplied_head=supplied_head,
                key=TEST_KEY,
                scope=SCOPE,
            )
        failures.append((invalid.value.code, str(invalid.value)))
    assert failures == [("AUDIT_CHAIN_INVALID", "AUDIT_CHAIN_INVALID")] * 3
    assert sessions.calls == 0


@pytest.mark.parametrize("mutation", ["signature", "scope", "key"])
def test_rejects_altered_signature_wrong_scope_and_wrong_key(mutation: str) -> None:
    events = _event_chain(2)
    checkpoint = _issue(events[:1])
    head = RiskAuditHeadV1(sequence=2, head_hash=events[-1].event_hash)
    kwargs: dict[str, Any] = {}
    if mutation == "signature":
        checkpoint = _tamper_checkpoint(checkpoint, signature="0" * 64)
    elif mutation == "scope":
        kwargs["scope"] = RiskAuditScopeV1(environment="PAPER", account_id="wrong-account")
    elif mutation == "key":
        kwargs["key"] = TEST_KEY_OTHER
    else:
        pytest.fail(f"unknown mutation: {mutation}")
    with pytest.raises(RiskAuditCheckpointError):
        _verify(
            checkpoint,
            events[1:],
            head=head,
            **kwargs,
        )


@pytest.mark.parametrize("damage", ["stale", "future", "reordered", "truncated", "missing", "head"])
def test_rejects_bad_checkpoint_suffix_or_nonmatching_head(damage: str) -> None:
    events = _event_chain(3)
    if damage == "stale":
        old_chain = _event_chain(2, variant="old")
        checkpoint = _issue(old_chain[:1])
        suffix = events[1:]
        head = RiskAuditHeadV1(sequence=3, head_hash=events[-1].event_hash)
    elif damage == "future":
        checkpoint = _issue(events)
        suffix = ()
        head = RiskAuditHeadV1(sequence=2, head_hash=events[1].event_hash)
    else:
        checkpoint = _issue(events[:1])
        suffix = events[1:]
        head = RiskAuditHeadV1(sequence=3, head_hash=events[-1].event_hash)
        if damage == "reordered":
            suffix = (events[2], events[1])
        elif damage == "truncated":
            suffix = suffix[:1]
        elif damage == "missing":
            suffix = ()
        elif damage == "head":
            head = RiskAuditHeadV1(sequence=3, head_hash="f" * 64)

    with pytest.raises(RiskAuditCheckpointError):
        _verify(checkpoint, suffix, head=head)


def test_core_verifier_rejects_a_gap_in_the_supplied_suffix() -> None:
    events = _event_chain(3)
    checkpoint = _issue(events[:2])
    assert checkpoint.sequence == 2

    assert verify_suffix_from_checkpoint(
        checkpoint,
        events[2:],
        supplied_head=RiskAuditHeadV1(sequence=3, head_hash=events[-1].event_hash),
        key=TEST_KEY,
        scope=SCOPE,
    )
    with pytest.raises(RiskAuditCheckpointError):
        verify_suffix_from_checkpoint(
            checkpoint,
            events[:1] + events[2:],
            supplied_head=RiskAuditHeadV1(sequence=3, head_hash=events[-1].event_hash),
            key=TEST_KEY,
            scope=SCOPE,
        )


@pytest.mark.asyncio
async def test_store_checks_suffix_against_persisted_exact_head_and_full_genesis(
    tmp_path: Path,
) -> None:
    events = await _create_event_chain(3)
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'checkpoint.sqlite'}")
    try:
        await migrate_risk_limits_v1(engine, writer_guard=_WriterGuard(), applied_at_ns=NOW_NS)
        async with engine.begin() as connection:
            for event in events:
                row = event.model_dump(exclude={"schema_version"})
                row["source_event_ids"] = list(event.source_event_ids)
                await connection.execute(insert(risk_audit_events).values(**row))
            await connection.execute(
                update(risk_audit_head)
                .where(risk_audit_head.c.head_id == 1)
                .values(sequence=3, chain_tip=events[-1].event_hash)
            )
        sessions = async_sessionmaker(engine, expire_on_commit=False)
        store = _store(sessions)
        checkpoint = _issue(events[:1])
        supplied = RiskAuditHeadV1(sequence=3, head_hash=events[-1].event_hash)
        verified = await store.verify_audit_suffix_from_checkpoint(
            checkpoint,
            supplied_head=supplied,
            key=TEST_KEY,
            scope=SCOPE,
        )
        issued = require_verified_risk_audit_suffix(verified)
        assert type(issued) is VerifiedRiskAuditSuffixV1
        assert issued.supplied_head == supplied
        assert issued.checkpoint_sequence == checkpoint.sequence
        assert issued.events == events[1:]
        assert await store.verify_audit_chain()

        with pytest.raises(RiskLimitEventStoreError) as wrong_head:
            await store.verify_audit_suffix_from_checkpoint(
                checkpoint,
                supplied_head=RiskAuditHeadV1(sequence=3, head_hash="f" * 64),
                key=TEST_KEY,
                scope=SCOPE,
            )
        assert wrong_head.value.code == "AUDIT_CHAIN_INVALID"

        stale_checkpoint = _issue(await _create_event_chain(1, scope=SCOPE, variant="stale-anchor"))
        with pytest.raises(RiskLimitEventStoreError) as stale_anchor:
            await store.verify_audit_suffix_from_checkpoint(
                stale_checkpoint,
                supplied_head=supplied,
                key=TEST_KEY,
                scope=SCOPE,
            )
        assert stale_anchor.value.code == "AUDIT_CHAIN_INVALID"

        async with engine.begin() as connection:
            await connection.execute(
                delete(risk_audit_events).where(risk_audit_events.c.sequence == 1)
            )
        assert not await store.verify_audit_chain()
        with pytest.raises(RiskLimitEventStoreError) as invalid:
            await store.verify_audit_suffix_from_checkpoint(
                checkpoint,
                supplied_head=supplied,
                key=TEST_KEY,
                scope=SCOPE,
            )
        assert invalid.value.code == "AUDIT_CHAIN_INVALID"
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_store_accepts_the_256_row_limit_and_rejects_257_before_loading(
    tmp_path: Path,
) -> None:
    other_account = "acct-checkpoint-other"
    events = await _create_interleaved_event_chain(
        tuple(SCOPE.account_id if sequence % 2 else other_account for sequence in range(1, 258))
    )
    genesis_checkpoint = _issue(())

    engine_256, store_256 = await _persist_chain(tmp_path / "suffix-256.sqlite", events[:256])
    try:
        verified = await store_256.verify_audit_suffix_from_checkpoint(
            genesis_checkpoint,
            supplied_head=RiskAuditHeadV1(sequence=256, head_hash=events[255].event_hash),
            key=TEST_KEY,
            scope=SCOPE,
        )
        issued = require_verified_risk_audit_suffix(verified)
        assert type(issued) is VerifiedRiskAuditSuffixV1
        expected_projection = tuple(
            event
            for event in events[:256]
            if event.environment == SCOPE.environment and event.account_id == SCOPE.account_id
        )
        assert len(expected_projection) == 128
        assert issued.events == expected_projection
    finally:
        await engine_256.dispose()

    engine_257, store_257 = await _persist_chain(tmp_path / "suffix-257.sqlite", events)
    try:
        supplied_head = RiskAuditHeadV1(sequence=257, head_hash=events[256].event_hash)
        with pytest.raises(RiskLimitEventStoreError) as too_many:
            await store_257.verify_audit_suffix_from_checkpoint(
                genesis_checkpoint,
                supplied_head=supplied_head,
                key=TEST_KEY,
                scope=SCOPE,
            )
        assert too_many.value.code == "AUDIT_SUFFIX_LIMIT"
        assert str(too_many.value) == "AUDIT_SUFFIX_LIMIT"

        invalid_checkpoints = (
            _tamper_checkpoint(genesis_checkpoint, signature="0" * 64),
            _tamper_checkpoint(_issue(events[:1]), signature="1" * 64),
            _tamper_checkpoint(
                genesis_checkpoint,
                sequence=2**53,
                signature="2" * 64,
            ),
        )
        failures: list[tuple[str, str]] = []
        for invalid_checkpoint in invalid_checkpoints:
            with pytest.raises(RiskLimitEventStoreError) as invalid:
                await store_257.verify_audit_suffix_from_checkpoint(
                    invalid_checkpoint,
                    supplied_head=supplied_head,
                    key=TEST_KEY,
                    scope=SCOPE,
                )
            failures.append((invalid.value.code, str(invalid.value)))
        assert failures == [
            ("AUDIT_CHAIN_INVALID", "AUDIT_CHAIN_INVALID"),
            ("AUDIT_CHAIN_INVALID", "AUDIT_CHAIN_INVALID"),
            ("AUDIT_CHAIN_INVALID", "AUDIT_CHAIN_INVALID"),
        ]
    finally:
        await engine_257.dispose()


@pytest.mark.asyncio
async def test_store_verifies_interleaved_accounts_globally_then_projects_scope(
    tmp_path: Path,
) -> None:
    other_account = "acct-checkpoint-other"
    interleaved = await _create_interleaved_event_chain(
        (SCOPE.account_id, other_account, SCOPE.account_id, other_account)
    )
    engine, store = await _persist_chain(tmp_path / "interleaved.sqlite", interleaved)
    try:
        checkpoint = _issue(interleaved[:1])
        verified = await store.verify_audit_suffix_from_checkpoint(
            checkpoint,
            supplied_head=RiskAuditHeadV1(
                sequence=len(interleaved), head_hash=interleaved[-1].event_hash
            ),
            key=TEST_KEY,
            scope=SCOPE,
        )
        issued = require_verified_risk_audit_suffix(verified)
        assert issued.events == tuple(
            event
            for event in interleaved[1:]
            if event.environment == SCOPE.environment and event.account_id == SCOPE.account_id
        )
        assert len(issued.events) == 1
        assert await store.verify_audit_chain()
    finally:
        await engine.dispose()
