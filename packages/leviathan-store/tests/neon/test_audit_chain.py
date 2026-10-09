"""Unit coverage for the SEC-005 immutable fake-Neon audit chain."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from leviathan_store.neon.audit_models import (
    AuditActionV1,
    AuditDecisionV1,
    AuditEntryV1,
    AuditEventV1,
    AuditReasonCodeV1,
)
from leviathan_store.neon.audit_repository import (
    MAX_AUDIT_PAYLOAD_BYTES,
    MAX_PAGE_ENTRIES,
    AuditPersistenceError,
    NeonAuditRepositoryV1,
    require_audit_entry,
)

from leviathan_core.security.authz_models import (
    _VERIFIER_MARKER,
    AuthorizationPolicyV1,
    EffectV1,
    PolicyRuleV1,
    PrincipalV1,
    TrustedPrincipalAdapterV1,
    TrustedPrincipalV1,
)

NOW = datetime(2026, 10, 6, 12, 0, tzinfo=UTC)


def _trusted(
    principal_id: str = "actor-a", project_id: str = "project-a"
) -> TrustedPrincipalV1:
    claims = PrincipalV1(
        principal_id=principal_id,
        project_id=project_id,
        roles=("operator",),
        env="test",
    )
    return TrustedPrincipalAdapterV1.from_verified_claims(claims, verifier_marker=_VERIFIER_MARKER)


def _event() -> AuditEventV1:
    return AuditEventV1(
        action=AuditActionV1.AUTHZ_DECISION,
        decision=AuditDecisionV1.ALLOW,
        reason_code=AuditReasonCodeV1.AUTHORIZED,
        target_ref="sha256:" + "a" * 64,
        correlation_id="sha256:" + "c" * 64,
        trace_id="b" * 32,
    )


def _read_policy(
    *,
    org_id: str = "org-a",
    effect: EffectV1 = EffectV1.ALLOW,
    resource: str | None = None,
) -> AuthorizationPolicyV1:
    return AuthorizationPolicyV1(
        version="v1",
        project_id="project-a",
        expires_at=NOW + timedelta(hours=1),
        rules=(
            PolicyRuleV1(
                rule_id="audit-read",
                effect=effect,
                roles=("operator",),
                actions=("audit:read", "audit:append"),
                resources=(resource or f"audit-journal:{org_id}",),
                env="test",
                not_before=NOW - timedelta(hours=1),
                not_after=NOW + timedelta(hours=1),
            ),
        ),
    )


def _repo(
    *,
    clock: Callable[[], datetime] = lambda: NOW,
    policy: AuthorizationPolicyV1 | None = None,
) -> NeonAuditRepositoryV1:
    repo = NeonAuditRepositoryV1(
        clock=clock, policy=_read_policy() if policy is None else policy
    )
    repo.register_org("org-a", "project-a")
    return repo


def test_entries_are_sealed_hash_chained_and_actor_is_redacted() -> None:
    repo = _repo()
    first = require_audit_entry(repo.append("org-a", _trusted(), _event()))
    second = require_audit_entry(repo.append("org-a", _trusted("actor-b"), _event()))

    assert first.sequence == 1
    assert first.previous_hash == "0" * 64
    assert second.sequence == 2
    assert second.previous_hash == first.entry_hash
    assert second.actor_ref == "sha256:" + hashlib.sha256(b"actor-b").hexdigest()
    assert "actor-b" not in second.model_dump_json()
    verified = repo.verify_chain("org-a", _trusted())
    assert verified.valid is True
    assert (verified.entries_checked, verified.chain_tip) == (2, second.entry_hash)


def test_append_failure_and_invalid_clock_commit_nothing() -> None:
    repo = _repo()
    with pytest.raises(AuditPersistenceError) as failed:
        repo.append("org-a", _trusted(), _event(), fail_before_commit=True)
    assert failed.value.code == "FAKE_TRANSACTION_ABORTED"
    assert failed.value.__cause__ is None
    assert failed.value.__context__ is None
    assert repo._state.rows["org-a"] == []

    invalid_clock = _repo(clock=lambda: datetime(2026, 10, 6, 12, 0))
    with pytest.raises(AuditPersistenceError) as bad_clock:
        invalid_clock.append("org-a", _trusted(), _event())
    assert bad_clock.value.code == "AUDIT_APPEND_DENIED"
    assert invalid_clock._state.rows["org-a"] == []


def test_untrusted_or_wrong_tenant_principal_is_denied() -> None:
    repo = _repo()
    claims = PrincipalV1("actor-a", "project-a", ("operator",), "test")
    for principal, expected in (
        (claims, "AUDIT_APPEND_DENIED"),
        (_trusted(project_id="project-b"), "AUDIT_APPEND_DENIED"),
    ):
        with pytest.raises(AuditPersistenceError) as caught:
            repo.append("org-a", principal, _event())  # type: ignore[arg-type]
        assert caught.value.code == expected
        assert caught.value.__context__ is None
    assert repo._state.rows["org-a"] == []


def test_page_cursor_is_tenant_scoped_and_chain_is_reopened() -> None:
    repo = _repo()
    first = repo.append("org-a", _trusted(), _event())
    repo.append("org-a", _trusted(), _event())
    principal = _trusted()
    policy = _read_policy()
    page = repo.read_page("org-a", principal, limit=1)
    assert len(page.entries) == 1
    assert page.entries[0].entry_hash == first.entry_hash
    assert require_audit_entry(page.entries[0]).entry_hash == first.entry_hash
    assert page.next_cursor == first.entry_hash
    second_page = repo.read_page("org-a", principal, cursor=page.next_cursor, limit=1)
    assert len(second_page.entries) == 1
    assert second_page.next_cursor is None
    with pytest.raises(AuditPersistenceError) as missing_cursor:
        repo.read_page("org-a", principal, cursor="f" * 64)
    assert missing_cursor.value.code == "INVALID_CURSOR"

    reopened = NeonAuditRepositoryV1(
        clock=lambda: NOW, policy=policy, _state=repo._state
    )
    assert reopened.verify_chain("org-a", principal).valid is True


def test_hash_tampering_gap_reorder_and_tail_deletion_fail_closed() -> None:
    for mutation in ("tamper", "gap", "reorder", "tail"):
        repo = _repo()
        for _ in range(3):
            repo.append("org-a", _trusted(), _event())
        rows = repo._state.rows["org-a"]
        if mutation == "tamper":
            payload = rows[1].payload.replace(b"AUTHORIZED", b"NOT_AUTHORIZED")
            rows[1] = replace(rows[1], payload=payload)
        elif mutation == "gap":
            del rows[1]
        elif mutation == "reorder":
            rows[0], rows[1] = rows[1], rows[0]
        else:
            rows.pop()

        verification = repo.verify_chain("org-a", _trusted())
        assert verification.valid is False
        assert verification.failure_code == "CHAIN_INVALID"
        with pytest.raises(AuditPersistenceError) as caught:
            repo.read_page("org-a", _trusted())
        assert caught.value.code == "CHAIN_INVALID"
        with pytest.raises(AuditPersistenceError) as append_error:
            repo.append("org-a", _trusted(), _event())
        assert append_error.value.code == "CHAIN_INVALID"


def test_audit_reads_require_audit_read_and_tenant_scope() -> None:
    repo = _repo()
    repo.append("org-a", _trusted(), _event())
    denied_repo = _repo(policy=_read_policy(effect=EffectV1.DENY))
    with pytest.raises(AuditPersistenceError) as denied:
        denied_repo.read_page("org-a", _trusted())
    assert denied.value.code == "READ_NOT_AUTHORIZED"

    repo.register_org("org-b", "project-b")
    with pytest.raises(AuditPersistenceError) as cross_tenant:
        repo.read_page("org-b", _trusted())
    assert cross_tenant.value.code == "READ_NOT_AUTHORIZED"


def test_verify_chain_checks_registered_project_before_wildcard_policy() -> None:
    repo = _repo(policy=_read_policy(resource="*"))
    repo.register_org("org-b", "project-b")
    with pytest.raises(AuditPersistenceError) as caught:
        repo.verify_chain("org-b", _trusted(project_id="project-a"))
    assert caught.value.code == "READ_NOT_AUTHORIZED"
    assert caught.value.args == ("READ_NOT_AUTHORIZED",)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def test_append_authorization_precedes_and_hides_missing_org_and_project_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _repo(policy=_read_policy(resource="*"))
    repo.register_org("org-b", "project-b")
    authorized_calls: list[tuple[str, str]] = []
    original_authorize = repo._authorization_allowed

    def record_authorization(
        org: str, principal: TrustedPrincipalV1, action: str, at: datetime
    ) -> bool:
        authorized_calls.append((org, action))
        return original_authorize(org, principal, action, at)

    monkeypatch.setattr(repo, "_authorization_allowed", record_authorization)
    for org_id, principal in (
        ("org-missing", _trusted()),
        ("org-b", _trusted(project_id="project-a")),
    ):
        with pytest.raises(AuditPersistenceError) as caught:
            repo.append(org_id, principal, _event())
        assert caught.value.code == "AUDIT_APPEND_DENIED"
        assert caught.value.args == ("AUDIT_APPEND_DENIED",)
        assert caught.value.__cause__ is None
        assert caught.value.__context__ is None

    assert authorized_calls == [
        ("org-missing", "audit:append"),
        ("org-b", "audit:append"),
    ]
    assert repo._state.rows["org-a"] == []
    assert repo._state.rows["org-b"] == []


def test_concurrent_appends_have_unique_monotonic_sequences() -> None:
    repo = _repo()
    with ThreadPoolExecutor(max_workers=8) as executor:
        entries = tuple(
            executor.map(
                lambda index: repo.append("org-a", _trusted(f"actor-{index}"), _event()),
                range(24),
            )
        )
    assert sorted(entry.sequence for entry in entries) == list(range(1, 25))
    assert repo.verify_chain("org-a", _trusted()).valid is True


def test_duplicate_generated_entry_id_is_rejected_before_commit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _repo()
    duplicate = type("FixedUUID", (), {"hex": "d" * 32})()
    monkeypatch.setattr("leviathan_store.neon.audit_repository.uuid.uuid4", lambda: duplicate)
    first = repo.append("org-a", _trusted(), _event())
    assert first.sequence == 1
    with pytest.raises(AuditPersistenceError) as caught:
        repo.append("org-a", _trusted(), _event())
    assert caught.value.code == "CHAIN_INVALID"
    assert repo.verify_chain("org-a", _trusted()).entries_checked == 1


def test_event_data_is_closed_and_contains_no_raw_diff_values() -> None:
    with pytest.raises(ValueError):
        AuditEventV1(
            action="CUSTOM_SECRET_ACTION",  # type: ignore[arg-type]
            decision=AuditDecisionV1.DENY,
            reason_code=AuditReasonCodeV1.REJECTED,
            target_ref="secret-target",
        )
    with pytest.raises(ValueError):
        AuditEventV1(
            action=AuditActionV1.AUTHZ_DECISION,
            decision=AuditDecisionV1.DENY,
            reason_code=AuditReasonCodeV1.REJECTED,
            target_ref="sha256:" + "a" * 64,
            correlation_id="customer@example.com",
        )


def test_append_and_verify_require_constructor_injected_policy() -> None:
    principal = _trusted()
    missing_policy = NeonAuditRepositoryV1(clock=lambda: NOW)
    missing_policy.register_org("org-a", "project-a")
    with pytest.raises(AuditPersistenceError) as append_denied:
        missing_policy.append("org-a", principal, _event())
    assert append_denied.value.code == "AUDIT_APPEND_DENIED"
    assert missing_policy._state.rows["org-a"] == []
    with pytest.raises(AuditPersistenceError) as verify_denied:
        missing_policy.verify_chain("org-a", principal)
    assert verify_denied.value.code == "READ_NOT_AUTHORIZED"

    denied_policy_repo = _repo(policy=_read_policy(effect=EffectV1.DENY))
    for repo, org_id in ((denied_policy_repo, "org-a"),):
        with pytest.raises(AuditPersistenceError) as caught:
            repo.verify_chain(org_id, principal)
        assert caught.value.code == "READ_NOT_AUTHORIZED"

    unknown_org_repo = NeonAuditRepositoryV1(
        clock=lambda: NOW, policy=_read_policy(org_id="org-missing")
    )
    with pytest.raises(AuditPersistenceError) as unknown:
        unknown_org_repo.verify_chain("org-missing", principal)
    assert unknown.value.code == "READ_NOT_AUTHORIZED"
    assert unknown.value.__cause__ is None
    assert unknown.value.__context__ is None


def test_append_rejects_clock_regression_without_committing() -> None:
    now = [NOW]
    repo = _repo(clock=lambda: now[0])
    first = repo.append("org-a", _trusted(), _event())
    now[0] = NOW - timedelta(microseconds=1)
    with pytest.raises(AuditPersistenceError) as caught:
        repo.append("org-a", _trusted(), _event())
    assert caught.value.code == "CLOCK_REGRESSION"
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert len(repo._state.rows["org-a"]) == 1
    now[0] = NOW
    assert repo.verify_chain("org-a", _trusted()).chain_tip == first.entry_hash


def test_append_payload_and_page_size_limits_are_enforced(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _repo()
    assert MAX_AUDIT_PAYLOAD_BYTES == 16_384
    assert MAX_PAGE_ENTRIES == 500
    assert len(_event().model_dump_json()) < MAX_AUDIT_PAYLOAD_BYTES
    monkeypatch.setattr(
        "leviathan_store.neon.audit_repository.MAX_AUDIT_PAYLOAD_BYTES", 1
    )
    with pytest.raises(AuditPersistenceError) as too_large:
        repo.append("org-a", _trusted(), _event())
    assert too_large.value.code == "PAYLOAD_TOO_LARGE"
    assert repo._state.rows["org-a"] == []
    monkeypatch.undo()
    with pytest.raises(AuditPersistenceError) as over_page:
        repo.read_page("org-a", _trusted(), limit=MAX_PAGE_ENTRIES + 1)
    assert over_page.value.code == "INVALID_LIMIT"


def test_two_thousand_appends_have_flat_cost_and_page_decode_is_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _repo()
    original_decode = repo._decode_row
    decode_count = 0

    def count_decode(row: object) -> AuditEntryV1:
        nonlocal decode_count
        decode_count += 1
        return original_decode(row)  # type: ignore[arg-type]

    monkeypatch.setattr(repo, "_decode_row", count_decode)
    decode_counts: list[int] = []
    principal, event = _trusted(), _event()
    for _ in range(2_000):
        before_count = decode_count
        repo.append("org-a", principal, event)
        decode_counts.append(decode_count - before_count)

    first_100 = sum(decode_counts[:100])
    last_100 = sum(decode_counts[-100:])
    assert last_100 < first_100 * 3
    assert max(decode_counts) <= 2
    assert repo.verify_chain("org-a", _trusted()).entries_checked == 2_000

    decode_count = 0
    cursor = repo._decode_row(repo._state.rows["org-a"][999]).entry_hash
    decode_count = 0
    page = repo.read_page("org-a", _trusted(), cursor=cursor, limit=10)
    assert len(page.entries) == 10
    assert decode_count == len(page.entries)
