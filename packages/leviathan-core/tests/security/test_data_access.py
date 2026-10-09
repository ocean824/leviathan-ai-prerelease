"""Focused SEC-008 tests for pure policy decisions and audit-before-release."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

import leviathan_core.security.authz_models as authz_models
import leviathan_core.security.egress_policy as egress_policy_module
from leviathan_core.security import (
    AuthorizationPolicyV1,
    EffectV1,
    PolicyRuleV1,
    PrincipalV1,
    TrustedPrincipalAdapterV1,
    TrustedPrincipalV1,
)
from leviathan_core.security.data_access import (
    REDACTED_VALUE,
    DataAccessFormatV1,
    DataAccessGuard,
    DataAccessOperationV1,
    DataAccessPolicyV1,
    DataAccessRequestV1,
    DataCellV1,
    DataClassificationV1,
    DataColumnV1,
    DataRowV1,
    DatasetScopeV1,
    require_data_access_release,
)
from leviathan_core.security.egress_policy import (
    EgressGuard,
    EgressOperationV1,
    EgressPolicyV1,
    EgressRequestV1,
    EgressRuleV1,
    OrgProjectBindingV1,
    egress_release_is_usable,
    require_egress_audit_record,
    require_egress_decision,
    require_egress_release,
)

NOW = datetime(2026, 10, 6, 12, 0, tzinfo=UTC)
PROJECT = "project-a"
ORG = "org-a"


def trusted(
    *, roles: tuple[str, ...] = ("market-data.read",), **changes: object
) -> TrustedPrincipalV1:
    project_id = str(changes.pop("project_id", PROJECT))
    claims = PrincipalV1(
        principal_id="principal-a",
        project_id=project_id,
        roles=roles,
        env="paper",
        venue="XNAS",
        **changes,
    )
    return TrustedPrincipalAdapterV1.from_verified_claims(
        claims, verifier_marker=authz_models._VERIFIER_MARKER
    )


def auth_policy(
    action: str, resource: str, *, role: str = "market-data.read"
) -> AuthorizationPolicyV1:
    rule = PolicyRuleV1(
        rule_id="allow-sec008",
        effect=EffectV1.ALLOW,
        roles=(role,),
        actions=(action,),
        resources=(resource,),
        env="paper",
        not_before=NOW - timedelta(minutes=1),
        not_after=NOW + timedelta(hours=1),
        venue="XNAS",
    )
    return AuthorizationPolicyV1(
        version="v1",
        project_id=PROJECT,
        expires_at=NOW + timedelta(days=1),
        rules=(rule,),
    )


class RecordingAudit:
    def __init__(self, *, error: Exception | None = None) -> None:
        self.records = []
        self.error = error

    def append(self, record: object, *, deadline_monotonic_ns: int) -> None:
        self.deadline_monotonic_ns = deadline_monotonic_ns
        if self.error is not None:
            raise self.error
        self.records.append(record)


def data_fixture(
    *, policy: AuthorizationPolicyV1 | None = None, org_id: str = ORG
) -> DataAccessPolicyV1:
    return DataAccessPolicyV1(
        policy=policy or auth_policy("data:read", "dataset:prices"),
        datasets=(
            DatasetScopeV1(
                org_id=ORG,
                project_id=PROJECT,
                env="paper",
                dataset_id="prices",
                columns=(
                    DataColumnV1("symbol"),
                    DataColumnV1("holder", DataClassificationV1.PII),
                    DataColumnV1("api_token", DataClassificationV1.API_KEY),
                    DataColumnV1("analyst_note", DataClassificationV1.PRIVATE_ANNOTATION),
                ),
            ),
        ),
        clock=lambda: NOW,
        allowed_purposes=("customer-support", "synthetic-support-case"),
    )


def data_request(
    *,
    org_id: str = ORG,
    operation: DataAccessOperationV1 = DataAccessOperationV1.READ,
    columns: tuple[str, ...] = (),
    purpose: str | None = None,
    output_format: DataAccessFormatV1 = DataAccessFormatV1.JSON,
) -> DataAccessRequestV1:
    return DataAccessRequestV1(
        org_id,
        "prices",
        "row-1",
        operation,
        columns=columns,
        purpose=purpose,
        output_format=output_format,
    )


def test_data_access_denies_unknown_and_cross_tenant_before_policy() -> None:
    policy = data_fixture()
    principal = trusted()
    unknown = policy.evaluate(principal, data_request(org_id="org-unknown"))
    cross_project_principal = trusted(project_id="project-b")
    cross_project = policy.evaluate(cross_project_principal, data_request())
    assert unknown.decision is cross_project.decision is EffectV1.DENY
    assert unknown.reason_code == cross_project.reason_code
    assert unknown.columns == cross_project.columns == ()


@pytest.mark.parametrize("operation", list(DataAccessOperationV1))
def test_data_access_default_deny_for_missing_policy(operation: DataAccessOperationV1) -> None:
    policy = DataAccessPolicyV1(policy=None, datasets=(), clock=lambda: NOW)
    result = policy.evaluate(trusted(), data_request(operation=operation))
    assert result.decision is EffectV1.DENY
    assert result.columns == ()


def test_data_access_redacts_sensitive_columns_and_requires_purpose_and_policy_to_unmask() -> None:
    policy = data_fixture()
    principal = trusted()
    decision = policy.evaluate(principal, data_request())
    assert decision.allowed
    assert decision.redacted_columns == ("holder", "api_token", "analyst_note")

    privileged = trusted(roles=("market-data.read", "security.pii.read"))
    pii_policy = AuthorizationPolicyV1(
        version="v1",
        project_id=PROJECT,
        expires_at=NOW + timedelta(days=1),
        rules=(
            PolicyRuleV1(
                rule_id="allow-data",
                effect=EffectV1.ALLOW,
                roles=("market-data.read",),
                actions=("data:read",),
                resources=("dataset:prices",),
                env="paper",
                not_before=NOW - timedelta(minutes=1),
                not_after=NOW + timedelta(hours=1),
                venue="XNAS",
            ),
            PolicyRuleV1(
                rule_id="allow-pii",
                effect=EffectV1.ALLOW,
                roles=("security.pii.read",),
                actions=("security:pii:read",),
                resources=("dataset:prices",),
                env="paper",
                not_before=NOW - timedelta(minutes=1),
                not_after=NOW + timedelta(hours=1),
                venue="XNAS",
            ),
        ),
    )
    pii_access = data_fixture(policy=pii_policy)
    no_purpose = pii_access.evaluate(privileged, data_request())
    with_purpose = pii_access.evaluate(privileged, data_request(purpose="customer-support"))
    assert no_purpose.redacted_columns == ("holder", "api_token", "analyst_note")
    assert with_purpose.allowed and with_purpose.redacted_columns == ()


@pytest.mark.parametrize(
    "operation,action",
    [
        (DataAccessOperationV1.FILTER, "data:filter"),
        (DataAccessOperationV1.SEARCH, "data:search"),
    ],
)
def test_filter_and_search_deny_sensitive_columns_without_full_unmask_authority(
    operation: DataAccessOperationV1, action: str
) -> None:
    policy = AuthorizationPolicyV1(
        version="v1",
        project_id=PROJECT,
        expires_at=NOW + timedelta(days=1),
        rules=(
            PolicyRuleV1(
                rule_id="allow-sensitive-query",
                effect=EffectV1.ALLOW,
                roles=("market-data.read",),
                actions=(action,),
                resources=("dataset:prices",),
                env="paper",
                not_before=NOW - timedelta(minutes=1),
                not_after=NOW + timedelta(hours=1),
                venue="XNAS",
            ),
        ),
    )
    access = data_fixture(policy=policy)
    request = data_request(
        operation=operation,
        columns=("holder",),
        purpose="customer-support",
    )
    assert not access.evaluate(trusted(), request).allowed


def test_sensitive_filter_is_allowed_only_with_full_unmask_authority() -> None:
    policy = AuthorizationPolicyV1(
        version="v1",
        project_id=PROJECT,
        expires_at=NOW + timedelta(days=1),
        rules=(
            PolicyRuleV1(
                rule_id="allow-filter",
                effect=EffectV1.ALLOW,
                roles=("market-data.read",),
                actions=("data:filter",),
                resources=("dataset:prices",),
                env="paper",
                not_before=NOW - timedelta(minutes=1),
                not_after=NOW + timedelta(hours=1),
                venue="XNAS",
            ),
            PolicyRuleV1(
                rule_id="allow-pii",
                effect=EffectV1.ALLOW,
                roles=("security.pii.read",),
                actions=("security:pii:read",),
                resources=("dataset:prices",),
                env="paper",
                not_before=NOW - timedelta(minutes=1),
                not_after=NOW + timedelta(hours=1),
                venue="XNAS",
            ),
        ),
    )
    decision = data_fixture(policy=policy).evaluate(
        trusted(roles=("market-data.read", "security.pii.read")),
        data_request(
            operation=DataAccessOperationV1.FILTER,
            columns=("holder",),
            purpose="customer-support",
        ),
    )
    assert decision.allowed and decision.redacted_columns == ()


def test_closed_purpose_set_and_csv_formula_injection() -> None:
    policy = data_fixture()
    assert not policy.evaluate(trusted(), data_request(purpose="arbitrary-purpose")).allowed
    with pytest.raises(ValueError):
        data_request(purpose="Uppercase Purpose")
    export_policy = data_fixture(policy=auth_policy("data:export", "dataset:prices"))
    row = DataRowV1(
        ORG,
        "prices",
        "row-1",
        (
            DataCellV1("symbol", '=HYPERLINK("https://attacker.invalid")'),
            DataCellV1("holder", "+1+1"),
            DataCellV1("api_token", "@SUM(1,1)"),
            DataCellV1("analyst_note", "\t=1+1"),
        ),
    )
    # All sensitive columns are redacted; the public symbol must be formula-safe.
    release = DataAccessGuard(policy=export_policy, audit=RecordingAudit()).release(
        trusted(),
        data_request(operation=DataAccessOperationV1.EXPORT, output_format=DataAccessFormatV1.CSV),
        row,
    )
    assert release.allowed and release.payload is not None
    assert "'=HYPERLINK" in release.payload
    assert "synthetic" not in release.payload


@pytest.mark.parametrize(
    ("value", "expected"),
    (
        (-5, "-5"),
        (-0.25, "-0.25"),
        ("-5", "-5"),
        ("-0.25", "-0.25"),
        ("-2+3", "'-2+3"),
    ),
)
def test_csv_neutralizes_negative_formulas_but_preserves_numeric_literals(
    value: object, expected: str
) -> None:
    export_policy = data_fixture(policy=auth_policy("data:export", "dataset:prices"))
    row = DataRowV1(ORG, "prices", "row-1", (DataCellV1("symbol", value),))
    result = DataAccessGuard(policy=export_policy, audit=RecordingAudit()).release(
        trusted(),
        data_request(
            operation=DataAccessOperationV1.EXPORT,
            columns=("symbol",),
            output_format=DataAccessFormatV1.CSV,
        ),
        row,
    )
    assert result.allowed and result.payload == f'"symbol"\r\n"{expected}"\r\n'


def test_data_access_guard_returns_only_redacted_payload_after_audit_success() -> None:
    audit = RecordingAudit()
    guard = DataAccessGuard(policy=data_fixture(), audit=audit)
    row = DataRowV1(
        ORG,
        "prices",
        "row-1",
        (
            DataCellV1("symbol", "XYZ"),
            DataCellV1("holder", "synthetic person"),
            DataCellV1("api_token", "synthetic-token"),
            DataCellV1("analyst_note", "private synthetic note"),
        ),
    )
    released = guard.release(trusted(), data_request(), row)
    require_data_access_release(released)
    assert released.allowed and released.payload is not None
    assert "synthetic person" not in released.payload
    assert "synthetic-token" not in released.payload
    assert "private synthetic note" not in released.payload
    assert REDACTED_VALUE in released.payload
    assert len(audit.records) == 1
    require_egress_audit_record(audit.records[0])


def test_csv_export_redacts_sensitive_values_too() -> None:
    guard = DataAccessGuard(
        policy=data_fixture(policy=auth_policy("data:export", "dataset:prices")),
        audit=RecordingAudit(),
    )
    row = DataRowV1(
        ORG,
        "prices",
        "row-1",
        (
            DataCellV1("symbol", "XYZ"),
            DataCellV1("holder", "synthetic person"),
            DataCellV1("api_token", "synthetic-token"),
            DataCellV1("analyst_note", "private synthetic note"),
        ),
    )
    result = guard.release(
        trusted(),
        data_request(
            operation=DataAccessOperationV1.EXPORT,
            output_format=DataAccessFormatV1.CSV,
        ),
        row,
    )
    assert result.allowed and result.payload is not None
    assert "synthetic person" not in result.payload
    assert "synthetic-token" not in result.payload
    assert "private synthetic note" not in result.payload
    assert result.payload.count(REDACTED_VALUE) == 3


@pytest.mark.parametrize(
    "audit",
    [
        None,
        RecordingAudit(error=RuntimeError("synthetic failure")),
        RecordingAudit(error=TimeoutError("synthetic timeout")),
    ],
)
def test_data_access_audit_failure_denies_without_payload(audit: RecordingAudit | None) -> None:
    guard = DataAccessGuard(policy=data_fixture(), audit=audit)
    row = DataRowV1(ORG, "prices", "row-1", (DataCellV1("symbol", "XYZ"),))
    result = guard.release(trusted(), data_request(), row)
    assert not result.allowed and result.payload is None
    assert result.reason_code.value == "NOT_AUTHORIZED"


def egress_fixture(
    *, policy: AuthorizationPolicyV1 | None = None
) -> tuple[EgressPolicyV1, EgressRequestV1]:
    request = EgressRequestV1(
        org_id=ORG,
        service_role="market-data.read",
        venue="XNAS",
        host="feed.example.test",
        port=443,
        resolved_addresses=("192.0.2.10",),
    )
    egress_policy = EgressPolicyV1(
        policy=policy or auth_policy("egress:connect", "egress:feed.example.test:443"),
        org_projects=(OrgProjectBindingV1(ORG, PROJECT),),
        rules=(
            EgressRuleV1(
                ORG, "market-data.read", "XNAS", "paper", "feed.example.test", 443, ("192.0.2.10",)
            ),
        ),
        clock=lambda: NOW,
    )
    return egress_policy, request


def test_egress_exact_allowlist_and_pinned_address_enforcement() -> None:
    policy, request = egress_fixture()
    principal = trusted()
    allowed = policy.evaluate(principal, request)
    require_egress_decision(allowed)
    assert allowed.allowed
    for changed in (
        EgressRequestV1(ORG, "market-data.read", "XNAS", "feed.example.test", 443, ("192.0.2.11",)),
        EgressRequestV1(
            ORG, "market-data.read", "XNAS", "other.example.test", 443, ("192.0.2.10",)
        ),
        EgressRequestV1(
            ORG,
            "market-data.read",
            "XNAS",
            "feed.example.test",
            443,
            ("192.0.2.10",),
            redirect_chain=("other.example.test",),
        ),
        EgressRequestV1(
            ORG,
            "market-data.read",
            "XNAS",
            "feed.example.test",
            443,
            ("192.0.2.10",),
            operation=EgressOperationV1.LIVE_ORDER,
        ),
    ):
        result = policy.evaluate(principal, changed)
        assert not result.allowed and result.reason_code.value == "NOT_AUTHORIZED"


def test_pinned_address_set_is_order_insensitive() -> None:
    request = EgressRequestV1(
        ORG,
        "market-data.read",
        "XNAS",
        "feed.example.test",
        443,
        ("192.0.2.11", "192.0.2.10"),
    )
    policy = EgressPolicyV1(
        policy=auth_policy("egress:connect", "egress:feed.example.test:443"),
        org_projects=(OrgProjectBindingV1(ORG, PROJECT),),
        rules=(
            EgressRuleV1(
                ORG,
                "market-data.read",
                "XNAS",
                "paper",
                "feed.example.test",
                443,
                ("192.0.2.10", "192.0.2.11"),
            ),
        ),
        clock=lambda: NOW,
    )
    assert policy.evaluate(trusted(), request).allowed


def test_egress_ownership_precedes_policy_and_wildcard_host_is_invalid() -> None:
    policy, request = egress_fixture()
    unknown = policy.evaluate(
        trusted(),
        EgressRequestV1(
            "org-unknown",
            request.service_role,
            request.venue,
            request.host,
            request.port,
            request.resolved_addresses,
        ),
    )
    cross_project = policy.evaluate(trusted(project_id="project-b"), request)
    assert unknown.decision is cross_project.decision is EffectV1.DENY
    with pytest.raises(ValueError):
        EgressRuleV1(
            ORG, "market-data.read", "XNAS", "paper", "*.example.test", 443, ("192.0.2.10",)
        )


def test_egress_guard_audits_before_release_and_fail_closes() -> None:
    policy, request = egress_fixture()
    audit = RecordingAudit()
    guard = EgressGuard(policy=policy, audit=audit)
    result = guard.release(trusted(), request, "synthetic payload")
    require_egress_release(result)
    assert result.allowed and result.payload == "synthetic payload"
    record = require_egress_audit_record(audit.records[0])
    assert record.org_id == ORG and record.decision is EffectV1.ALLOW
    assert len(record.request_digest) == len(record.decision_digest) == 64
    assert result.request_digest == record.request_digest
    assert result.destination_scheme == "https"
    assert result.destination_host == "feed.example.test"
    assert result.destination_port == 443
    assert result.expires_at_ns > 0
    assert egress_release_is_usable(
        result,
        request_digest=result.request_digest,
        scheme="https",
        host="feed.example.test",
        port=443,
        now=NOW,
    )
    assert not egress_release_is_usable(
        result,
        request_digest="0" * 64,
        scheme="https",
        host="feed.example.test",
        port=443,
        now=NOW,
    )
    assert not egress_release_is_usable(
        result,
        request_digest=result.request_digest,
        scheme="https",
        host="different.example.test",
        port=443,
        now=NOW,
    )
    assert not egress_release_is_usable(
        result,
        request_digest=result.request_digest,
        scheme="https",
        host="feed.example.test",
        port=443,
        now=NOW + timedelta(seconds=31),
    )
    too_long = EgressGuard(policy=policy, audit=RecordingAudit(), ttl_seconds=301).release(
        trusted(), request, "payload"
    )
    assert not too_long.allowed and too_long.payload is None


def test_egress_release_default_and_maximum_ttl_are_bounded() -> None:
    policy, request = egress_fixture()
    expected_now_ns = int(NOW.timestamp()) * 1_000_000_000
    default_release = EgressGuard(policy=policy, audit=RecordingAudit()).release(
        trusted(), request, "payload"
    )
    assert default_release.allowed
    assert default_release.expires_at_ns - expected_now_ns == 30_000_000_000
    max_release = EgressGuard(
        policy=policy,
        audit=RecordingAudit(),
        ttl_seconds=300,
    ).release(trusted(), request, "payload")
    assert max_release.allowed
    assert max_release.expires_at_ns - expected_now_ns == 300_000_000_000

    for failed_audit in (
        None,
        RecordingAudit(error=RuntimeError("synthetic failure")),
        RecordingAudit(error=TimeoutError("synthetic timeout")),
    ):
        denied = EgressGuard(policy=policy, audit=failed_audit).release(
            trusted(), request, "secret"
        )
        assert not denied.allowed and denied.payload is None


def test_denial_is_content_free_and_audit_failure_does_not_change_it() -> None:
    _allowed_policy, request = egress_fixture()
    policy = EgressPolicyV1(
        policy=None,
        org_projects=(OrgProjectBindingV1(ORG, PROJECT),),
        rules=(
            EgressRuleV1(
                ORG,
                "market-data.read",
                "XNAS",
                "paper",
                "feed.example.test",
                443,
                ("192.0.2.10",),
            ),
        ),
        clock=lambda: NOW,
    )
    successful = EgressGuard(policy=policy, audit=RecordingAudit()).release(
        trusted(), request, "secret"
    )
    failed = EgressGuard(
        policy=policy, audit=RecordingAudit(error=RuntimeError("synthetic"))
    ).release(trusted(), request, "secret")
    assert not successful.allowed and successful.payload is None
    assert not failed.allowed and failed.payload is None
    assert successful.reason_code is failed.reason_code


def test_live_money_destinations_and_order_labels_are_always_denied() -> None:
    _, request = egress_fixture()
    live_money_rule = EgressRuleV1(
        ORG,
        "market-data.read",
        "XNAS",
        "paper",
        request.host,
        request.port,
        request.resolved_addresses,
        live_money=True,
    )
    policy = EgressPolicyV1(
        policy=auth_policy("egress:connect", "egress:feed.example.test:443"),
        org_projects=(OrgProjectBindingV1(ORG, PROJECT),),
        rules=(live_money_rule,),
        clock=lambda: NOW,
    )
    assert not policy.evaluate(trusted(), request).allowed
    other_role_rule = EgressRuleV1(
        ORG,
        "broker",
        "XNAS",
        "paper",
        request.host,
        request.port,
        request.resolved_addresses,
    )
    with pytest.raises(ValueError) as error:
        EgressPolicyV1(
            policy=auth_policy("egress:connect", "egress:feed.example.test:443"),
            org_projects=(OrgProjectBindingV1(ORG, PROJECT),),
            rules=(live_money_rule, other_role_rule),
            clock=lambda: NOW,
        )
    assert str(error.value) == "LIVE_ENDPOINT_CONFLICT"
    with pytest.raises(ValueError):
        EgressRuleV1(
            ORG,
            "market-data.read",
            "XNAS",
            "paper",
            request.host,
            request.port,
            request.resolved_addresses,
            allowed_operations=(EgressOperationV1.LIVE_ORDER,),
        )


def test_egress_audit_overrun_denies_and_issuer_is_private(monkeypatch: pytest.MonkeyPatch) -> None:
    policy, request = egress_fixture()
    ticks = iter((100, 151))
    monkeypatch.setattr(egress_policy_module.time, "monotonic_ns", lambda: next(ticks))
    audit = RecordingAudit()
    result = EgressGuard(
        policy=policy,
        audit=audit,
        audit_timeout_ns=50,
    ).release(trusted(), request, "synthetic")
    assert not result.allowed and result.payload is None
    assert audit.records
    assert audit.deadline_monotonic_ns == 150
    assert not hasattr(egress_policy_module, "issue_egress_audit_record")
    assert "issue_egress_audit_record" not in egress_policy_module.__all__
