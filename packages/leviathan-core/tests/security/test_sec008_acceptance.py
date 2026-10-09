"""Independent synthetic acceptance for SEC-008 redaction and egress controls."""

from __future__ import annotations

import copy
import pickle
import time
from datetime import UTC, datetime, timedelta

import pytest

import leviathan_core.security.authz_models as authz_models
import leviathan_core.security.egress_policy as egress_models
from leviathan_core.seal import SealError
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
    require_data_access_decision,
    require_data_access_release,
)
from leviathan_core.security.egress_policy import (
    EgressGuard,
    EgressOperationV1,
    EgressPolicyError,
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
ORG_A = "org-a"
ORG_B = "org-b"
PROJECT_A = "project-a"
PROJECT_B = "project-b"
DATASET = "prices"
HOST = "feed.example.test"
IP = "192.0.2.10"


def _principal(
    *,
    org_project: str = PROJECT_A,
    roles: tuple[str, ...] = ("market-data.read",),
    env: str = "paper",
    venue: str = "XNAS",
) -> TrustedPrincipalV1:
    claims = PrincipalV1(
        principal_id="synthetic-principal",
        project_id=org_project,
        roles=roles,
        env=env,
        venue=venue,
    )
    return TrustedPrincipalAdapterV1.from_verified_claims(
        claims, verifier_marker=authz_models._VERIFIER_MARKER
    )


def _policy(*rules: PolicyRuleV1) -> AuthorizationPolicyV1:
    return AuthorizationPolicyV1(
        version="v1",
        project_id=PROJECT_A,
        expires_at=NOW + timedelta(days=1),
        rules=tuple(rules),
    )


def _rule(
    action: str,
    resource: str,
    *,
    role: str = "market-data.read",
    env: str = "paper",
    venue: str = "XNAS",
) -> PolicyRuleV1:
    return PolicyRuleV1(
        rule_id=f"rule-{action.replace(':', '-')}",
        effect=EffectV1.ALLOW,
        roles=(role,),
        actions=(action,),
        resources=(resource,),
        env=env,
        not_before=NOW - timedelta(minutes=1),
        not_after=NOW + timedelta(hours=1),
        venue=venue,
    )


def _columns() -> tuple[DataColumnV1, ...]:
    return (
        DataColumnV1("symbol"),
        DataColumnV1("holder", DataClassificationV1.PII),
        DataColumnV1("api_token", DataClassificationV1.API_KEY),
        DataColumnV1("analyst_note", DataClassificationV1.PRIVATE_ANNOTATION),
    )


def _dataset(org: str = ORG_A, project: str = PROJECT_A, env: str = "paper") -> DatasetScopeV1:
    return DatasetScopeV1(org, project, env, DATASET, _columns())


def _data_policy(
    *,
    policy: AuthorizationPolicyV1 | None = None,
    datasets: tuple[DatasetScopeV1, ...] | None = None,
) -> DataAccessPolicyV1:
    return DataAccessPolicyV1(
        policy=policy
        if policy is not None
        else _policy(
            *(
                _rule(action, f"dataset:{DATASET}")
                for action in (
                    "data:read",
                    "data:export",
                    "data:filter",
                    "data:search",
                    "data:tooltip",
                )
            )
        ),
        datasets=datasets if datasets is not None else (_dataset(),),
        clock=lambda: NOW,
        allowed_purposes=("synthetic-support-case",),
    )


def _data_request(
    *,
    org: str = ORG_A,
    operation: DataAccessOperationV1 = DataAccessOperationV1.READ,
    purpose: str | None = None,
    output: DataAccessFormatV1 = DataAccessFormatV1.JSON,
    columns: tuple[str, ...] = (),
) -> DataAccessRequestV1:
    return DataAccessRequestV1(org, DATASET, "row-secret-1", operation, columns, purpose, output)


def _data_row(org: str = ORG_A) -> DataRowV1:
    return DataRowV1(
        org,
        DATASET,
        "row-secret-1",
        (
            DataCellV1("symbol", "SYN"),
            DataCellV1("holder", "SYNTHETIC_PERSON_SECRET"),
            DataCellV1("api_token", "SYNTHETIC_API_KEY_SECRET"),
            DataCellV1("analyst_note", "SYNTHETIC_PRIVATE_NOTE"),
        ),
    )


class _Audit:
    def __init__(self, error: Exception | None = None) -> None:
        self.records: list[object] = []
        self.deadlines: list[int] = []
        self.error = error

    def append(self, record: object, *, deadline_monotonic_ns: int) -> None:
        if self.error is not None:
            raise self.error
        self.records.append(record)
        self.deadlines.append(deadline_monotonic_ns)


@pytest.mark.parametrize(
    "operation",
    (
        DataAccessOperationV1.READ,
        DataAccessOperationV1.EXPORT,
        DataAccessOperationV1.TOOLTIP,
    ),
)
@pytest.mark.parametrize("output", tuple(DataAccessFormatV1))
def test_sensitive_values_are_redacted_on_every_data_surface(
    operation: DataAccessOperationV1, output: DataAccessFormatV1
) -> None:
    request = _data_request(operation=operation, output=output)
    guard = DataAccessGuard(policy=_data_policy(), audit=_Audit())
    release = guard.release(_principal(), request, _data_row())
    require_data_access_release(release)
    assert release.allowed and release.payload is not None
    for secret in (
        "SYNTHETIC_PERSON_SECRET",
        "SYNTHETIC_API_KEY_SECRET",
        "SYNTHETIC_PRIVATE_NOTE",
    ):
        assert secret not in release.payload
    assert release.payload.count(REDACTED_VALUE) == 3


def test_unmask_requires_role_explicit_purpose_and_separate_authorization() -> None:
    rules = (
        _rule("data:read", f"dataset:{DATASET}"),
        _rule(
            "security:pii:read",
            f"dataset:{DATASET}",
            role="security.pii.read",
        ),
    )
    policy = _data_policy(policy=_policy(*rules))
    principal = _principal(roles=("market-data.read", "security.pii.read"))
    assert policy.evaluate(principal, _data_request()).redacted_columns == (
        "holder",
        "api_token",
        "analyst_note",
    )
    request = _data_request(purpose="synthetic-support-case")
    decision = policy.evaluate(principal, request)
    require_data_access_decision(decision)
    assert decision.allowed and decision.redacted_columns == ()

    no_pii_role = _principal()
    assert policy.evaluate(no_pii_role, request).redacted_columns == (
        "holder",
        "api_token",
        "analyst_note",
    )
    policy_without_pii_grant = _data_policy(
        policy=_policy(_rule("data:read", f"dataset:{DATASET}"))
    )
    assert policy_without_pii_grant.evaluate(principal, request).redacted_columns == (
        "holder",
        "api_token",
        "analyst_note",
    )


@pytest.mark.parametrize("operation", (DataAccessOperationV1.FILTER, DataAccessOperationV1.SEARCH))
def test_sensitive_filter_and_search_deny_oracle_without_full_unmask_authority(
    operation: DataAccessOperationV1,
) -> None:
    auth = _policy(
        _rule(f"data:{operation.value.lower()}", f"dataset:{DATASET}"),
        _rule("security:pii:read", f"dataset:{DATASET}", role="security.pii.read"),
    )
    policy = _data_policy(policy=auth)
    request = _data_request(
        operation=operation, columns=("holder",), purpose="synthetic-support-case"
    )
    row = _data_row()
    denied_for_role = DataAccessGuard(policy=policy, audit=_Audit()).release(
        _principal(), request, row
    )
    denied_for_purpose = DataAccessGuard(policy=policy, audit=_Audit()).release(
        _principal(roles=("market-data.read", "security.pii.read")),
        _data_request(operation=operation, columns=("holder",)),
        row,
    )
    assert not denied_for_role.allowed and denied_for_role.payload is None
    assert not denied_for_purpose.allowed and denied_for_purpose.payload is None
    authorized = DataAccessGuard(policy=policy, audit=_Audit()).release(
        _principal(roles=("market-data.read", "security.pii.read")), request, row
    )
    assert authorized.allowed and authorized.payload is not None
    assert "SYNTHETIC_PERSON_SECRET" in authorized.payload


def test_purpose_closed_set_and_unregistered_columns_deny() -> None:
    policy = _data_policy()
    assert not policy.evaluate(_principal(), _data_request(purpose="unconfigured-purpose")).allowed
    assert not policy.evaluate(_principal(), _data_request(columns=("not-in-schema",))).allowed


@pytest.mark.parametrize(
    "dangerous", ("=1+1", "+1+1", "-cmd|...", "-2+3", "@SUM(A1:A2)", "\t1", "\r1")
)
def test_csv_formula_prefixes_are_neutralized(dangerous: str) -> None:
    row = DataRowV1(
        ORG_A,
        DATASET,
        "row-secret-1",
        (DataCellV1("symbol", dangerous),),
    )
    request = _data_request(
        output=DataAccessFormatV1.CSV,
        columns=("symbol",),
    )
    result = DataAccessGuard(policy=_data_policy(), audit=_Audit()).release(
        _principal(), request, row
    )
    assert result.allowed and result.payload is not None
    assert f"'{dangerous}" in result.payload


@pytest.mark.parametrize("numeric", ("-5", "-0.25"))
def test_csv_negative_numeric_literal_is_not_neutralized(numeric: str) -> None:
    row = DataRowV1(
        ORG_A,
        DATASET,
        "row-secret-1",
        (DataCellV1("symbol", numeric),),
    )
    request = _data_request(output=DataAccessFormatV1.CSV, columns=("symbol",))
    result = DataAccessGuard(policy=_data_policy(), audit=_Audit()).release(
        _principal(), request, row
    )
    assert result.allowed and result.payload is not None
    assert f'"{numeric}"' in result.payload
    assert f'"\'{numeric}"' not in result.payload


def test_tenant_environment_and_row_identity_fail_closed_without_payload() -> None:
    # The adapter binds the supplied row and schema; this does not claim row-level ABAC
    # evaluation or execute an actual filter/search query against a backing store.
    policy = _data_policy(
        datasets=(
            _dataset(),
            _dataset(ORG_B, PROJECT_B, "paper"),
            _dataset("org-live", PROJECT_A, "live"),
        )
    )
    guard = DataAccessGuard(policy=policy, audit=_Audit())
    wrong_project = guard.release(_principal(org_project=PROJECT_B), _data_request(), _data_row())
    unknown_tenant = guard.release(
        _principal(), _data_request(org="org-unknown"), _data_row("org-unknown")
    )
    wrong_environment = guard.release(
        _principal(env="live"), _data_request(org="org-live"), _data_row("org-live")
    )
    mismatched_row = guard.release(
        _principal(), _data_request(), DataRowV1(ORG_B, DATASET, "row-secret-1", _data_row().cells)
    )
    results = (wrong_project, unknown_tenant, wrong_environment, mismatched_row)
    for result in results:
        require_data_access_release(result)
        assert not result.allowed and result.payload is None
    assert len({(item.allowed, item.reason_code) for item in results}) == 1


def test_data_policy_and_audit_are_both_required_before_release() -> None:
    request = _data_request()
    row = _data_row()
    assert (
        not DataAccessGuard(policy=None, audit=_Audit()).release(_principal(), request, row).allowed
    )
    assert (
        not DataAccessGuard(policy=_data_policy(), audit=None)
        .release(_principal(), request, row)
        .allowed
    )
    failed = DataAccessGuard(
        policy=_data_policy(), audit=_Audit(RuntimeError("synthetic audit unavailable"))
    ).release(_principal(), request, row)
    assert not failed.allowed and failed.payload is None

    audit = _Audit()
    allowed = DataAccessGuard(policy=_data_policy(), audit=audit).release(
        _principal(), request, row
    )
    assert allowed.allowed and allowed.payload is not None
    assert len(audit.records) == 1
    require_egress_audit_record(audit.records[0])


def _egress_request(
    *,
    org: str = ORG_A,
    role: str = "market-data.read",
    venue: str = "XNAS",
    host: str = HOST,
    port: int = 443,
    addresses: tuple[str, ...] = (IP,),
    operation: EgressOperationV1 = EgressOperationV1.DATA_EGRESS,
    redirects: tuple[str, ...] = (),
    scheme: str = "https",
) -> EgressRequestV1:
    return EgressRequestV1(org, role, venue, host, port, addresses, operation, redirects, scheme)


def _egress_policy(*, policy: AuthorizationPolicyV1 | None = None) -> EgressPolicyV1:
    auth = policy if policy is not None else _policy(_rule("egress:connect", f"egress:{HOST}:443"))
    return EgressPolicyV1(
        policy=auth,
        org_projects=(OrgProjectBindingV1(ORG_A, PROJECT_A),),
        rules=(EgressRuleV1(ORG_A, "market-data.read", "XNAS", "paper", HOST, 443, (IP,)),),
        clock=lambda: NOW,
    )


def test_egress_requires_exact_org_role_venue_host_port_and_dns_pin() -> None:
    policy = _egress_policy()
    valid = policy.evaluate(_principal(), _egress_request())
    require_egress_decision(valid)
    assert valid.allowed
    invalids = (
        ("cross tenant", _principal(), _egress_request(org="org-other")),
        ("wrong project", _principal(org_project=PROJECT_B), _egress_request()),
        ("wrong environment", _principal(env="live"), _egress_request()),
        ("wrong venue", _principal(venue="XNYS"), _egress_request()),
        ("unentitled role", _principal(roles=("operator.read",)), _egress_request()),
        ("wrong service role", _principal(), _egress_request(role="operator.read")),
        ("wrong hostname", _principal(), _egress_request(host="other.example.test")),
        ("wrong port", _principal(), _egress_request(port=8443)),
        ("DNS rebinding", _principal(), _egress_request(addresses=("192.0.2.11",))),
        ("private address change", _principal(), _egress_request(addresses=("127.0.0.1",))),
        ("redirect", _principal(), _egress_request(redirects=("other.example.test",))),
    )
    for _label, principal, request in invalids:
        decision = policy.evaluate(principal, request)
        require_egress_decision(decision)
        assert not decision.allowed
        assert decision.reason_code.value == "NOT_AUTHORIZED"


def test_live_order_is_hard_denied_even_with_exact_rule_and_auth_grant() -> None:
    request = _egress_request(operation=EgressOperationV1.LIVE_ORDER)
    policy = EgressPolicyV1(
        policy=_policy(_rule("egress:connect", f"egress:{HOST}:443")),
        org_projects=(OrgProjectBindingV1(ORG_A, PROJECT_A),),
        rules=(EgressRuleV1(ORG_A, "market-data.read", "XNAS", "paper", HOST, 443, (IP,)),),
        clock=lambda: NOW,
    )
    result = policy.evaluate(_principal(), request)
    require_egress_decision(result)
    assert not result.allowed
    released = EgressGuard(policy=policy, audit=_Audit()).release(
        _principal(), request, "SYNTHETIC_ORDER_PAYLOAD"
    )
    assert not released.allowed and released.payload is None


@pytest.mark.parametrize(
    "operation", (EgressOperationV1.DATA_EGRESS, EgressOperationV1.MARKET_DATA)
)
def test_broker_live_money_destination_cannot_be_relabelled_as_nonorder_egress(
    operation: EgressOperationV1,
) -> None:
    data_role = "market-data.read"
    broker_role = "broker"
    request = _egress_request(role=data_role, operation=operation)
    policy = EgressPolicyV1(
        policy=_policy(_rule("egress:connect", f"egress:{HOST}:443", role=data_role)),
        org_projects=(OrgProjectBindingV1(ORG_A, PROJECT_A),),
        rules=(
            EgressRuleV1(
                ORG_A,
                broker_role,
                "XNAS",
                "paper",
                HOST,
                443,
                (IP,),
                allowed_operations=(EgressOperationV1.DATA_EGRESS, EgressOperationV1.MARKET_DATA),
                live_money=True,
            ),
        ),
        clock=lambda: NOW,
    )
    # A different service role and DATA_EGRESS/MARKET_DATA label cannot bypass
    # the endpoint-wide live-money mark. A matching ordinary rule is separately
    # rejected by the registry-construction conflict case below.
    principal = _principal(roles=(data_role,))
    assert not policy.evaluate(principal, request).allowed
    released = EgressGuard(policy=policy, audit=_Audit()).release(
        principal, request, "SYNTHETIC_BROKER_PAYLOAD"
    )
    assert not released.allowed and released.payload is None


def test_endpoint_registry_rejects_live_money_endpoint_conflict_content_free() -> None:
    rules = (
        EgressRuleV1(ORG_A, "market-data.read", "XNAS", "paper", HOST, 443, (IP,)),
        EgressRuleV1(
            ORG_A,
            "broker",
            "XNAS",
            "paper",
            HOST,
            443,
            (IP,),
            live_money=True,
        ),
    )
    with pytest.raises(EgressPolicyError) as error:
        EgressPolicyV1(
            policy=_policy(_rule("egress:connect", f"egress:{HOST}:443")),
            org_projects=(OrgProjectBindingV1(ORG_A, PROJECT_A),),
            rules=rules,
            clock=lambda: NOW,
        )
    assert error.value.code == "LIVE_ENDPOINT_CONFLICT"
    assert str(error.value) == "LIVE_ENDPOINT_CONFLICT"
    assert HOST not in str(error.value)


def test_dns_address_pin_is_order_insensitive_but_still_exact() -> None:
    addresses = ("192.0.2.10", "192.0.2.11")
    rule = EgressRuleV1(ORG_A, "market-data.read", "XNAS", "paper", HOST, 443, addresses)
    policy = EgressPolicyV1(
        policy=_policy(_rule("egress:connect", f"egress:{HOST}:443")),
        org_projects=(OrgProjectBindingV1(ORG_A, PROJECT_A),),
        rules=(rule,),
        clock=lambda: NOW,
    )
    forward = _egress_request(addresses=addresses)
    reverse = _egress_request(addresses=tuple(reversed(addresses)))
    first = policy.evaluate(_principal(), forward)
    second = policy.evaluate(_principal(), reverse)
    assert first.allowed and second.allowed
    assert first.request_digest == second.request_digest
    assert not policy.evaluate(
        _principal(), _egress_request(addresses=(addresses[0], "192.0.2.12"))
    ).allowed


@pytest.mark.parametrize("bad_host", ("*.example.test", "feed.*.test", "FEED.example.test"))
def test_wildcard_or_noncanonical_destination_is_rejected_at_configuration(
    bad_host: str,
) -> None:
    with pytest.raises(ValueError):
        EgressRuleV1(ORG_A, "market-data.read", "XNAS", "paper", bad_host, 443, (IP,))


def test_egress_release_requires_audit_success_and_returns_no_denied_payload() -> None:
    request = _egress_request()
    no_audit = EgressGuard(policy=_egress_policy(), audit=None).release(
        _principal(), request, "SYNTHETIC_EGRESS_PAYLOAD"
    )
    failed_audit = EgressGuard(
        policy=_egress_policy(), audit=_Audit(TimeoutError("synthetic timeout"))
    ).release(_principal(), request, "SYNTHETIC_EGRESS_PAYLOAD")
    for denied in (no_audit, failed_audit):
        require_egress_release(denied)
        assert not denied.allowed and denied.payload is None

    audit = _Audit()
    released = EgressGuard(policy=_egress_policy(), audit=audit).release(
        _principal(), request, "SYNTHETIC_EGRESS_PAYLOAD"
    )
    require_egress_release(released)
    assert released.allowed and released.payload == "SYNTHETIC_EGRESS_PAYLOAD"
    assert len(audit.records) == 1
    record = require_egress_audit_record(audit.records[0])
    assert record.org_id == ORG_A
    assert record.decision is EffectV1.ALLOW
    assert len(record.request_digest) == len(record.decision_digest) == 64
    assert audit.deadlines and audit.deadlines[0] > 0


def test_egress_missing_policy_fails_closed_even_with_audit_port() -> None:
    policy = EgressPolicyV1(
        policy=None,
        org_projects=(OrgProjectBindingV1(ORG_A, PROJECT_A),),
        rules=(EgressRuleV1(ORG_A, "market-data.read", "XNAS", "paper", HOST, 443, (IP,)),),
        clock=lambda: NOW,
    )
    audit = _Audit()
    result = EgressGuard(policy=policy, audit=audit).release(
        _principal(), _egress_request(), "SYNTHETIC_EGRESS_PAYLOAD"
    )
    assert not result.allowed and result.payload is None
    assert len(audit.records) == 1
    assert require_egress_audit_record(audit.records[0]).decision is EffectV1.DENY


def _datetime_ns(value: datetime) -> int:
    delta = value - datetime(1970, 1, 1, tzinfo=UTC)
    return (
        delta.days * 86_400_000_000_000 + delta.seconds * 1_000_000_000 + delta.microseconds * 1_000
    )


def test_egress_release_is_bound_to_request_destination_and_expiry() -> None:
    request = _egress_request()
    released = EgressGuard(policy=_egress_policy(), audit=_Audit(), ttl_seconds=300).release(
        _principal(), request, "SYNTHETIC_PAYLOAD"
    )
    assert released.allowed and released.expires_at_ns == _datetime_ns(NOW) + 300_000_000_000
    before_expiry = NOW + timedelta(seconds=299, microseconds=999_999)
    assert egress_release_is_usable(
        released,
        request_digest=released.request_digest,
        scheme="https",
        host=HOST,
        port=443,
        now=before_expiry,
    )
    invalidations = (
        {"request_digest": "0" * 64, "scheme": "https", "host": HOST, "port": 443},
        {"request_digest": released.request_digest, "scheme": "wss", "host": HOST, "port": 443},
        {
            "request_digest": released.request_digest,
            "scheme": "https",
            "host": "other.example.test",
            "port": 443,
        },
        {"request_digest": released.request_digest, "scheme": "https", "host": HOST, "port": 8443},
    )
    for binding in invalidations:
        assert not egress_release_is_usable(released, now=before_expiry, **binding)
    assert not egress_release_is_usable(
        released,
        request_digest=released.request_digest,
        scheme="https",
        host=HOST,
        port=443,
        now=NOW + timedelta(seconds=300),
    )
    overlong = EgressGuard(policy=_egress_policy(), audit=_Audit(), ttl_seconds=301).release(
        _principal(), request, "SYNTHETIC_PAYLOAD"
    )
    assert not overlong.allowed and overlong.expires_at_ns == 0


class _SlowAudit(_Audit):
    def append(self, record: object, *, deadline_monotonic_ns: int) -> None:
        time.sleep(0.01)
        super().append(record, deadline_monotonic_ns=deadline_monotonic_ns)


def test_audit_append_overrun_denies_release() -> None:
    audit = _SlowAudit()
    result = EgressGuard(policy=_egress_policy(), audit=audit, audit_timeout_ns=1_000_000).release(
        _principal(), _egress_request(), "SYNTHETIC_PAYLOAD"
    )
    assert not result.allowed and result.payload is None
    assert len(audit.records) == 1
    assert audit.deadlines[0] > 0


def test_transport_resolver_is_not_claimed_and_public_audit_issuer_is_absent() -> None:
    # The pure kernel consumes caller-supplied synthetic IP pins; it performs no DNS or I/O.
    assert not hasattr(egress_models, "issue_egress_audit_record")
    policy = _egress_policy()
    assert policy.evaluate(_principal(), _egress_request()).allowed
    redirect = policy.evaluate(_principal(), _egress_request(redirects=("redirect.example.test",)))
    assert not redirect.allowed


def test_public_issued_results_are_sealed_and_not_copyable_or_serializable() -> None:
    data_decision = _data_policy().evaluate(_principal(), _data_request())
    data_release = DataAccessGuard(policy=_data_policy(), audit=_Audit()).release(
        _principal(), _data_request(), _data_row()
    )
    egress_policy = _egress_policy()
    egress_decision = egress_policy.evaluate(_principal(), _egress_request())
    egress_release = EgressGuard(policy=egress_policy, audit=_Audit()).release(
        _principal(), _egress_request(), "synthetic"
    )
    audit_record = _Audit()
    EgressGuard(policy=egress_policy, audit=audit_record).release(
        _principal(), _egress_request(), "synthetic"
    )
    records = (
        data_decision,
        data_release,
        egress_decision,
        egress_release,
        audit_record.records[0],
    )
    for value in records:
        for operation in (copy.copy, copy.deepcopy, pickle.dumps):
            with pytest.raises((SealError, TypeError)):
                operation(value)

    object.__setattr__(egress_decision, "decision", EffectV1.DENY)
    with pytest.raises(SealError):
        require_egress_decision(egress_decision)
