"""Independent contract acceptance for the synthetic SEC-005 audit journal."""

from __future__ import annotations

import copy
import hashlib
import pickle
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta, timezone
from itertools import pairwise

import pytest
from leviathan_store.neon.audit_models import (
    AuditActionV1,
    AuditDecisionV1,
    AuditDiffFieldV1,
    AuditDiffV1,
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
from pydantic import ValidationError

from leviathan_core.seal import SealError
from leviathan_core.security import (
    AuthorizationPolicyV1,
    EffectV1,
    PolicyRuleV1,
    PrincipalV1,
    TrustedPrincipalAdapterV1,
    TrustedPrincipalV1,
)
from leviathan_core.security.authz_models import _VERIFIER_MARKER

ORG = "org-alpha"
PROJECT = "project-alpha"
OTHER_ORG = "org-beta"
OTHER_PROJECT = "project-beta"
AT = datetime(2026, 10, 6, 15, 30, tzinfo=UTC)
REF_A = "sha256:" + "a" * 64
REF_B = "sha256:" + "b" * 64
HASH_A = "a" * 64
HASH_B = "b" * 64


def _principal(
    *,
    project_id: str = PROJECT,
    env: str = "development",
    principal_id: str = "operator.7",
    roles: tuple[str, ...] = ("security.audit", "org.admin"),
) -> TrustedPrincipalV1:
    claims = PrincipalV1(
        principal_id=principal_id,
        project_id=project_id,
        roles=roles,
        env=env,
    )
    return TrustedPrincipalAdapterV1.from_verified_claims(claims, verifier_marker=_VERIFIER_MARKER)


def _event(*, target_ref: str = REF_A, correlation_id: str | None = None) -> AuditEventV1:
    return AuditEventV1(
        action=AuditActionV1.AUTHZ_DECISION,
        decision=AuditDecisionV1.DENY,
        reason_code=AuditReasonCodeV1.NOT_AUTHORIZED,
        target_ref=target_ref,
        diff=(
            AuditDiffV1(
                field=AuditDiffFieldV1.ROLE,
                before_sha256=HASH_A,
                after_sha256=HASH_B,
            ),
        ),
        correlation_id=(
            "sha256:" + hashlib.sha256(correlation_id.encode("utf-8")).hexdigest()
            if correlation_id is not None
            else None
        ),
        trace_id="0123456789abcdef0123456789abcdef",
    )


def _repo(
    *,
    now: datetime = AT,
    org_id: str = ORG,
    project_id: str = PROJECT,
    policy: AuthorizationPolicyV1 | None = None,
) -> NeonAuditRepositoryV1:
    principal = _principal(project_id=project_id)
    repo = NeonAuditRepositoryV1(
        clock=lambda: now,
        policy=_policy(principal, org_ids=(org_id,)) if policy is None else policy,
    )
    repo.register_org(org_id, project_id)
    return repo


def _policy(
    principal: TrustedPrincipalV1,
    *,
    org_ids: tuple[str, ...] = (ORG,),
    wildcard_resource: bool = False,
    read_effect: EffectV1 = EffectV1.ALLOW,
    append_effect: EffectV1 = EffectV1.ALLOW,
) -> AuthorizationPolicyV1:
    resources = ("*",) if wildcard_resource else tuple(
        f"audit-journal:{org_id}" for org_id in org_ids
    )
    return AuthorizationPolicyV1(
        version="v1",
        project_id=principal.project_id,
        expires_at=AT + timedelta(days=1),
        rules=(
            PolicyRuleV1(
                rule_id="audit-append-allow"
                if append_effect is EffectV1.ALLOW
                else "audit-append-deny",
                effect=append_effect,
                roles=("security.audit",),
                actions=("audit:append",),
                resources=resources,
                env=principal.env,
                not_before=AT - timedelta(days=1),
                not_after=AT + timedelta(days=1),
            ),
            PolicyRuleV1(
                rule_id=(
                    "audit-read-allow"
                    if read_effect is EffectV1.ALLOW
                    else "audit-read-deny"
                ),
                effect=read_effect,
                roles=("security.audit",),
                actions=("audit:read",),
                resources=resources,
                env=principal.env,
                not_before=AT - timedelta(days=1),
                not_after=AT + timedelta(days=1),
            ),
        ),
    )


def _read_page(
    repo: NeonAuditRepositoryV1,
    org_id: str,
    principal: TrustedPrincipalV1,
    *,
    cursor: str | None = None,
    limit: int = 100,
):
    return repo.read_page(org_id, principal, cursor=cursor, limit=limit)


def _assert_code(action: object, code: str) -> None:
    with pytest.raises(AuditPersistenceError) as caught:
        action()  # type: ignore[operator]
    assert caught.value.code == code
    assert str(caught.value) == code
    assert caught.value.args == (code,)
    assert code not in {"INVALID_EVENT", "INVALID_PRINCIPAL"} or caught.value.__cause__ is None


def test_append_issues_redacted_immutable_hash_chained_entry() -> None:
    repo = _repo()
    entry = repo.append(ORG, _principal(), _event(correlation_id="trace-7"))

    assert require_audit_entry(entry) is entry
    assert entry.org_id == ORG
    assert entry.env == "development"
    assert entry.sequence == 1
    assert entry.recorded_at == AT
    assert entry.actor_ref == "sha256:" + hashlib.sha256(b"operator.7").hexdigest()
    assert entry.actor_ref != "operator.7"
    assert entry.target_ref == REF_A
    assert entry.previous_hash == "0" * 64
    assert len(entry.entry_hash) == 64 and entry.entry_hash != entry.previous_hash
    assert repo.verify_chain(ORG, _principal()).valid


def test_untrusted_or_wrong_project_principal_cannot_append() -> None:
    repo = _repo()
    raw_claims = PrincipalV1(
        principal_id="operator.7", project_id=PROJECT, roles=("org.admin",), env="development"
    )
    _assert_code(
        lambda: repo.append(ORG, raw_claims, _event()),  # type: ignore[arg-type]
        "AUDIT_APPEND_DENIED",
    )
    _assert_code(
        lambda: repo.append(ORG, _principal(project_id=OTHER_PROJECT), _event()),
        "AUDIT_APPEND_DENIED",
    )
    assert repo.verify_chain(ORG, _principal()).entries_checked == 0


def test_audit_input_accepts_only_closed_codes_and_digest_references_without_echo() -> None:
    with pytest.raises(ValidationError) as raw_target:
        AuditEventV1(
            action="AUTHZ_DECISION",
            decision="DENY",
            reason_code="NOT_AUTHORIZED",
            target_ref="customer-secret-raw-value",
        )
    assert "customer-secret-raw-value" not in str(raw_target.value)

    with pytest.raises(ValidationError) as raw_diff:
        AuditDiffV1(
            field="password-value",
            before_sha256="secret-before",
            after_sha256=HASH_B,
        )
    assert "secret-before" not in str(raw_diff.value)
    assert "password-value" not in str(raw_diff.value)

    with pytest.raises(ValidationError):
        AuditEventV1(
            action="UNRECOGNIZED_ACTION",
            decision="DENY",
            reason_code="NOT_AUTHORIZED",
            target_ref=REF_A,
        )


def test_append_failpoint_and_bool_in_int_fail_closed_without_partial_commit() -> None:
    repo = _repo()
    _assert_code(
        lambda: repo.append(ORG, _principal(), _event(), fail_before_commit=True),
        "FAKE_TRANSACTION_ABORTED",
    )
    _assert_code(
        lambda: repo.append(ORG, _principal(), _event(), fail_before_commit=1),  # type: ignore[arg-type]
        "INVALID_FAILPOINT",
    )
    assert repo.verify_chain(ORG, _principal()).entries_checked == 0
    committed = repo.append(ORG, _principal(), _event())
    assert committed.sequence == 1


def test_clock_must_be_exact_utc_and_clock_failures_are_content_free() -> None:
    offset = timezone(timedelta(hours=0), "synthetic-zero-offset")
    bad_clock_repo = _repo(now=AT.astimezone(offset))
    _assert_code(
        lambda: bad_clock_repo.append(ORG, _principal(), _event()),
        "AUDIT_APPEND_DENIED",
    )
    principal = _principal()
    invalid_clock_repo = NeonAuditRepositoryV1(
        clock=lambda: "secret-clock-result", policy=_policy(principal)
    )
    invalid_clock_repo.register_org(ORG, PROJECT)
    _assert_code(
        lambda: invalid_clock_repo.append(ORG, principal, _event()),
        "AUDIT_APPEND_DENIED",
    )


def test_pagination_is_stable_tenant_scoped_and_survives_repository_reopen() -> None:
    principal = _principal()
    repo = _repo(policy=_policy(principal, org_ids=(ORG, OTHER_ORG)))
    repo.register_org(OTHER_ORG, PROJECT)
    repo.append(ORG, _principal(), _event(correlation_id="a-1"))
    repo.append(ORG, _principal(), _event(target_ref=REF_B, correlation_id="a-2"))
    repo.append(OTHER_ORG, principal, _event())

    first = _read_page(repo, ORG, principal, limit=1)
    assert len(first.entries) == 1
    assert first.entries[0].sequence == 1
    assert first.next_cursor == first.entries[0].entry_hash
    second = _read_page(repo, ORG, principal, cursor=first.next_cursor, limit=1)
    assert [entry.sequence for entry in second.entries] == [2]
    assert second.next_cursor is None
    _assert_code(
        lambda: _read_page(
            repo,
            OTHER_ORG,
            principal,
            cursor=first.entries[0].entry_hash,
        ),
        "INVALID_CURSOR",
    )

    reopened = NeonAuditRepositoryV1(
        clock=lambda: AT,
        policy=_policy(principal, org_ids=(ORG, OTHER_ORG)),
        _state=repo._state,
    )
    assert reopened.verify_chain(ORG, principal).valid
    assert [item.sequence for item in _read_page(reopened, ORG, principal).entries] == [1, 2]


def test_read_requires_sec002_audit_read_allow_and_cannot_cross_tenant_scope() -> None:
    repo = _repo()
    repo.append(ORG, _principal(), _event())
    allowed = _principal()
    assert [entry.sequence for entry in _read_page(repo, ORG, allowed).entries] == [1]

    denied_repo = _repo(policy=_policy(allowed, read_effect=EffectV1.DENY))
    with pytest.raises(AuditPersistenceError):
        denied_repo.read_page(ORG, allowed)
    no_policy = NeonAuditRepositoryV1(clock=lambda: AT)
    no_policy.register_org(ORG, PROJECT)
    _assert_code(lambda: no_policy.read_page(ORG, allowed), "READ_NOT_AUTHORIZED")

    other_project = _principal(project_id=OTHER_PROJECT)
    wrong_project_repo = _repo(policy=_policy(other_project, org_ids=(ORG,)))
    with pytest.raises(AuditPersistenceError):
        _read_page(wrong_project_repo, ORG, other_project)
    assert repo.verify_chain(ORG, allowed).entries_checked == 1


def test_concurrent_appends_have_unique_monotonic_sequences_and_one_valid_chain() -> None:
    repo = _repo()
    with ThreadPoolExecutor(max_workers=8) as pool:
        entries = tuple(
            pool.map(
                lambda index: repo.append(
                    ORG, _principal(), _event(correlation_id=f"parallel-{index}")
                ),
                range(32),
            )
        )

    assert len({entry.entry_id for entry in entries}) == 32
    ordered = sorted(entries, key=lambda entry: entry.sequence)
    assert [entry.sequence for entry in ordered] == list(range(1, 33))
    assert ordered[0].previous_hash == "0" * 64
    assert all(left.entry_hash == right.previous_hash for left, right in pairwise(ordered))
    verification = repo.verify_chain(ORG, _principal())
    assert verification.valid and verification.entries_checked == 32


def test_entry_issuance_cannot_be_forged_copied_pickled_or_tampered() -> None:
    entry = _repo().append(ORG, _principal(), _event())
    fields = entry.model_dump(mode="python")
    forged = AuditEntryV1(**fields)
    with pytest.raises(SealError):
        require_audit_entry(forged)
    parsed = AuditEntryV1.model_validate(fields)
    with pytest.raises(SealError):
        require_audit_entry(parsed)

    operations = (
        lambda: copy.copy(entry),
        lambda: copy.deepcopy(entry),
        lambda: pickle.dumps(entry),
    )
    for operation in operations:
        with pytest.raises((SealError, TypeError)):
            operation()

    object.__getattribute__(entry, "__dict__")["sequence"] = 99
    with pytest.raises(SealError):
        require_audit_entry(entry)


def test_tampering_deletion_and_reordering_are_detected_and_block_future_writes() -> None:
    for mutation in (
        lambda rows: rows.__setitem__(0, type(rows[0])(payload=b"{}")),
        lambda rows: rows.pop(),
        lambda rows: rows.reverse(),
    ):
        repo = _repo()
        repo.append(ORG, _principal(), _event(correlation_id="first"))
        repo.append(ORG, _principal(), _event(target_ref=REF_B, correlation_id="second"))
        mutation(repo._state.rows[ORG])
        result = repo.verify_chain(ORG, _principal())
        assert not result.valid
        assert result.failure_code == "CHAIN_INVALID"
        _assert_code(lambda repo=repo: repo.append(ORG, _principal(), _event()), "CHAIN_INVALID")


def test_duplicate_entry_id_cannot_enter_the_append_only_chain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _repo()
    duplicate = type("FixedUUID", (), {"hex": "d" * 32})()
    monkeypatch.setattr("leviathan_store.neon.audit_repository.uuid.uuid4", lambda: duplicate)
    first = repo.append(ORG, _principal(), _event(correlation_id="first"))
    assert first.sequence == 1
    _assert_code(
        lambda: repo.append(ORG, _principal(), _event(target_ref=REF_B)),
        "CHAIN_INVALID",
    )
    assert repo.verify_chain(ORG, _principal()).entries_checked == 1


def test_read_page_rejects_bool_limit_and_invalid_or_unknown_cursors() -> None:
    repo = _repo()
    principal = _principal()
    _assert_code(lambda: _read_page(repo, ORG, principal, limit=True), "INVALID_LIMIT")
    _assert_code(lambda: _read_page(repo, ORG, principal, limit=0), "INVALID_LIMIT")
    _assert_code(lambda: _read_page(repo, ORG, principal, cursor="secret-cursor"), "INVALID_CURSOR")
    _assert_code(lambda: _read_page(repo, ORG, principal, cursor="f" * 64), "INVALID_CURSOR")


def test_append_rejects_clock_regression_without_writing() -> None:
    principal = _principal()
    moments = (AT, AT - timedelta(microseconds=1), AT)
    calls = 0

    def clock() -> datetime:
        nonlocal calls
        current = moments[min(calls, len(moments) - 1)]
        calls += 1
        return current

    repo = NeonAuditRepositoryV1(
        clock=clock,
        policy=_policy(principal),
    )
    repo.register_org(ORG, PROJECT)
    first = repo.append(ORG, principal, _event(correlation_id="clock-first"))
    assert first.sequence == 1

    _assert_code(
        lambda: repo.append(ORG, principal, _event(correlation_id="clock-regressed")),
        "CLOCK_REGRESSION",
    )
    page = repo.read_page(ORG, principal)
    assert len(page.entries) == 1
    assert page.entries[0].entry_hash == first.entry_hash
    assert repo.verify_chain(ORG, principal).valid


def test_payload_and_page_size_bounds_are_enforced() -> None:
    roles = ("role-" + str(index) + "x" * 70 for index in range(300))
    principal = _principal(roles=("security.audit", *roles))
    repo = _repo()
    assert MAX_AUDIT_PAYLOAD_BYTES == 16_384
    _assert_code(lambda: repo.append(ORG, principal, _event()), "PAYLOAD_TOO_LARGE")
    assert repo.read_page(ORG, principal).entries == ()

    assert MAX_PAGE_ENTRIES == 500
    assert repo.read_page(ORG, principal, limit=MAX_PAGE_ENTRIES).entries == ()
    _assert_code(
        lambda: repo.read_page(ORG, principal, limit=MAX_PAGE_ENTRIES + 1),
        "INVALID_LIMIT",
    )


def test_verify_chain_requires_read_access_and_hides_unknown_org() -> None:
    principal = _principal()
    repo = _repo()
    repo.append(ORG, principal, _event())
    assert repo.verify_chain(ORG, principal).valid

    no_access = _principal(roles=("org.admin",))
    denied = _capture_code(lambda: repo.verify_chain(ORG, no_access))
    unknown = _capture_code(lambda: repo.verify_chain("org-unknown", principal))
    assert denied == unknown == ("READ_NOT_AUTHORIZED", "READ_NOT_AUTHORIZED")

    no_policy = NeonAuditRepositoryV1(clock=lambda: AT)
    no_policy.register_org(ORG, PROJECT)
    _assert_code(lambda: no_policy.verify_chain(ORG, principal), "READ_NOT_AUTHORIZED")
    _assert_code(lambda: no_policy.append(ORG, principal, _event()), "AUDIT_APPEND_DENIED")


def _capture_code(action: object) -> tuple[str, str]:
    with pytest.raises(AuditPersistenceError) as caught:
        action()  # type: ignore[operator]
    return caught.value.code, str(caught.value)


def test_append_and_page_decoder_work_stays_bounded_as_chain_grows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _repo()
    principal = _principal()
    decoder_calls = 0
    original_decode = repo._decode_row

    def counted_decode(row):
        nonlocal decoder_calls
        decoder_calls += 1
        return original_decode(row)

    monkeypatch.setattr(repo, "_decode_row", counted_decode)
    first_hundred_calls = 0
    calls_before_last_hundred = 0
    for index in range(2_000):
        repo.append(ORG, principal, _event(correlation_id=f"scale-{index}"))
        if index == 99:
            first_hundred_calls = decoder_calls
        if index == 1_899:
            calls_before_last_hundred = decoder_calls

    last_hundred_calls = decoder_calls - calls_before_last_hundred
    assert decoder_calls <= 2 * 2_000
    assert first_hundred_calls > 0
    assert last_hundred_calls < 3 * first_hundred_calls

    decoder_calls = 0
    page = repo.read_page(ORG, principal, limit=37)
    assert len(page.entries) == 37
    assert decoder_calls == len(page.entries)


def test_wildcard_read_policy_does_not_cross_project_for_chain_verification() -> None:
    in_scope = _principal()
    repo = _repo(policy=_policy(in_scope, wildcard_resource=True))
    repo.append(ORG, in_scope, _event())
    assert repo.verify_chain(ORG, in_scope).valid

    other_project = _principal(project_id=OTHER_PROJECT)
    _assert_code(
        lambda: repo.verify_chain(ORG, other_project), "READ_NOT_AUTHORIZED"
    )


def test_append_authorization_denial_precedes_org_and_project_scope_errors() -> None:
    repo = _repo()
    principal = _principal()
    unknown_org = _capture_code(
        lambda: repo.append("org-unknown", principal, _event())
    )
    wrong_project = _capture_code(
        lambda: repo.append(ORG, _principal(project_id=OTHER_PROJECT), _event())
    )

    assert unknown_org == wrong_project == (
        "AUDIT_APPEND_DENIED",
        "AUDIT_APPEND_DENIED",
    )
    assert repo.verify_chain(ORG, principal).entries_checked == 0
