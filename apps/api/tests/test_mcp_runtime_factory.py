from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from leviathan_api.mcp_runtime_factory import (
    McpControlBinding,
    McpRuntimeFactoryConfigV1,
    McpRuntimeFactoryError,
    build_mcp_control,
)
from leviathan_api.routers.mcp_control import (
    DRY_RUN_DENIAL_LIMIT,
    McpControlRuntime,
    _check_dry_run_rate_limit,
    _dry_run_audit_only_revision,
)
from leviathan_api.security.mcp_principal_resolver import (
    McpPrincipalResolutionCodeV1,
    McpPrincipalResolutionError,
)
from leviathan_core.mcp_control.control_service import (
    empty_control_snapshot,
    record_request_denial,
    register_agent,
    start_session,
    submit_action,
)
from leviathan_core.mcp_control.policy_models import (
    ActionRequestV1,
    PolicyContextV1,
    ToolGrantV1,
    ToolRegistrationV1,
)
from leviathan_core.mcp_control.state_models import CONTROL_VERSION, AttestationEvidenceV1
from leviathan_core.mcp_control.tool_policy import evaluate_tool_policy
from leviathan_core.risk.halt import HaltAuthority


def _runtime(
    *,
    audit_sink=None,
    allow_unaudited_for_tests: bool | None = None,
) -> McpControlRuntime:
    if allow_unaudited_for_tests is None:
        allow_unaudited_for_tests = audit_sink is None
    return McpControlRuntime(
        context_resolver=lambda *args, **kwargs: None,
        grants_resolver=lambda *args, **kwargs: (),
        attestation_resolver=lambda *args, **kwargs: None,
        approval_resolver=lambda *args, **kwargs: None,
        audit_sink=audit_sink,
        allow_unaudited_for_tests=allow_unaudited_for_tests,
    )


def _revised(snapshot, *, reason: str = "TEST_DENIAL"):
    return record_request_denial(
        snapshot,
        org_id="org-a",
        principal_id="principal-a",
        reason_code=reason,
        now_ns=1,
    )


def test_runtime_commit_calls_audit_sink_before_publishing_snapshot() -> None:
    current = empty_control_snapshot()
    observations: list[tuple[object, ...]] = []
    runtime_box: dict[str, McpControlRuntime] = {}

    def sink(events) -> None:
        runtime = runtime_box["runtime"]
        assert runtime.snapshot is current
        observations.append(events)

    runtime = McpControlRuntime(
        context_resolver=lambda *args, **kwargs: None,
        grants_resolver=lambda *args, **kwargs: (),
        attestation_resolver=lambda *args, **kwargs: None,
        approval_resolver=lambda *args, **kwargs: None,
        snapshot=current,
        audit_sink=sink,
    )
    runtime_box["runtime"] = runtime
    revised = _revised(current)

    runtime.commit(revised)

    assert observations == [(revised.audit_events[-1],)]
    assert runtime.snapshot is revised


def test_runtime_commit_sink_failure_does_not_publish_or_echo_exception() -> None:
    def fail(_events) -> None:
        raise RuntimeError("synthetic-secret-payload")

    runtime = _runtime(audit_sink=fail)
    current = runtime.snapshot

    with pytest.raises(HTTPException) as caught:
        runtime.commit(_revised(current))

    assert caught.value.status_code == 503
    assert caught.value.detail == "AUDIT_UNAVAILABLE"
    assert "synthetic-secret-payload" not in str(caught.value)
    assert runtime.snapshot is current


def test_runtime_commit_rejects_non_prefix_snapshot() -> None:
    runtime = _runtime()
    initial = runtime.snapshot
    first = _revised(initial, reason="FIRST")
    divergent = _revised(initial, reason="SECOND")
    runtime.commit(first)

    with pytest.raises(HTTPException) as caught:
        runtime.commit(divergent)

    assert caught.value.status_code == 503
    assert caught.value.detail == "AUDIT_UNAVAILABLE"
    assert runtime.snapshot is first


def test_runtime_without_sink_or_test_opt_in_fails_closed() -> None:
    runtime = _runtime(allow_unaudited_for_tests=False)
    original = runtime.snapshot

    with pytest.raises(HTTPException) as caught:
        runtime.commit(_revised(original))

    assert caught.value.status_code == 503
    assert caught.value.detail == "AUDIT_UNAVAILABLE"
    assert runtime.snapshot is original


def test_runtime_snapshot_and_audit_sink_are_read_only() -> None:
    runtime = _runtime(audit_sink=lambda _events: None)

    with pytest.raises(AttributeError):
        runtime.audit_sink = None
    with pytest.raises(AttributeError):
        runtime.snapshot = empty_control_snapshot()


def test_router_modules_have_no_snapshot_assignment_outside_runtime_commit() -> None:
    router_root = Path(__file__).parents[1] / "src" / "leviathan_api" / "routers"
    violations: list[str] = []

    class SnapshotAssignmentVisitor(ast.NodeVisitor):
        def __init__(self, path: Path) -> None:
            self.path = path
            self.class_name: str | None = None
            self.function_name: str | None = None

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            prior_class = self.class_name
            self.class_name = node.name
            self.generic_visit(node)
            self.class_name = prior_class

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            prior_function = self.function_name
            self.function_name = node.name
            self.generic_visit(node)
            self.function_name = prior_function

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            self.visit_FunctionDef(node)

        def visit_Attribute(self, node: ast.Attribute) -> None:
            if (
                isinstance(node.ctx, ast.Store)
                and node.attr == "snapshot"
                and (
                    self.class_name != "McpControlRuntime"
                    or self.function_name not in {"__init__", "commit"}
                )
            ):
                violations.append(f"{self.path.relative_to(router_root)}:{node.lineno}")
            self.generic_visit(node)

    for path in sorted(router_root.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        SnapshotAssignmentVisitor(path).visit(tree)

    assert violations == []


def test_accepted_and_denied_dry_runs_use_separate_rate_limit_buckets() -> None:
    runtime = _runtime()
    principal = SimpleNamespace(org_id="org-a", subject_id="subject-a")

    for index in range(DRY_RUN_DENIAL_LIMIT):
        _check_dry_run_rate_limit(runtime, principal, index + 1, accepted=True)

    with pytest.raises(HTTPException) as caught:
        _check_dry_run_rate_limit(runtime, principal, DRY_RUN_DENIAL_LIMIT + 1, accepted=True)

    assert caught.value.status_code == 429
    assert caught.value.detail == "DRY_RUN_RATE_LIMIT"
    key = ("org-a", "subject-a")
    assert len(runtime.dry_run_accepted_timestamps_ns[key]) == DRY_RUN_DENIAL_LIMIT
    assert runtime.dry_run_denial_timestamps_ns == {}

    _check_dry_run_rate_limit(runtime, principal, DRY_RUN_DENIAL_LIMIT + 1, accepted=False)
    assert len(runtime.dry_run_denial_timestamps_ns[key]) == 1


def test_runtime_without_audit_sink_preserves_in_memory_commit_behavior() -> None:
    runtime = _runtime()
    revised = _revised(runtime.snapshot)

    runtime.commit(revised)

    assert runtime.snapshot is revised
    assert runtime.snapshot.audit_events == revised.audit_events


def test_runtime_rejects_non_callable_audit_sink() -> None:
    with pytest.raises(TypeError, match="MCP runtime dependencies are invalid"):
        _runtime(audit_sink=object())


def _accepted_dry_run_fixture(*, audit_sink=None):
    now_ns = 1_800_000_000_000_000_000
    org_id, desk_id, agent_id, session_id = "org-a", "desk-a", "agent-a", "session-a"
    tool_id, resource, scope = "quotes.read", f"{org_id}:quotes:SYNTH", "market:read"
    registration = ToolRegistrationV1(
        org_id=org_id,
        tool_id=tool_id,
        resource_pattern=resource,
        tool_class="data",
        capabilities=frozenset({"read", "update"}),
        environments=frozenset({"paper"}),
        scope=scope,
        bridge_required=False,
        order_or_route=False,
        financial=False,
        config_change=True,
        data_egress=False,
    )
    context = PolicyContextV1._from_trusted_adapter(
        version=CONTROL_VERSION,
        org_id=org_id,
        desk_id=desk_id,
        agent_id=agent_id,
        session_id=session_id,
        evaluation_time_ns=now_ns,
        principal_verified=True,
        attestation_verified=True,
        session_active=True,
        halt_clear=True,
        risk_snapshot_at_ns=now_ns,
        risk_snapshot_max_age_ns=10_000_000_000,
        bridge_online=True,
        tools=(registration,),
        global_max_notional=None,
        global_max_leverage=None,
        live_financial_enabled=False,
        market_open=True,
        liquidity_ok=True,
        egress_allowed=True,
        allowed_egress_domains=(),
        config_approvals=(),
        rate_remaining=100,
        max_session_quota=10,
        max_session_lifetime_ns=100_000_000,
        elevation_requires_approval=False,
        allowed_venues=(),
        blocked_symbols=(),
        allowed_order_types=(),
    )
    attestation = AttestationEvidenceV1._from_trusted_adapter(
        version=CONTROL_VERSION,
        attestation_id="attestation-a",
        org_id=org_id,
        desk_id=desk_id,
        agent_id=agent_id,
        origin="LEVIATHAN",
        signature_digest="a" * 64,
        issued_at_ns=now_ns,
        expires_at_ns=now_ns + 100_000_000,
    )
    snapshot = register_agent(
        empty_control_snapshot(), context=context, attestation=attestation, now_ns=now_ns
    )
    snapshot = start_session(
        snapshot,
        context=context,
        expires_at_ns=now_ns + 100_000_000,
        quota=10,
        scope_elevated=False,
        now_ns=now_ns,
    )
    grant = ToolGrantV1._from_trusted_adapter(
        version=CONTROL_VERSION,
        grant_id="grant-a",
        org_id=org_id,
        desk_id=desk_id,
        agent_id=agent_id,
        session_id=session_id,
        tool_id=tool_id,
        resource_pattern=resource,
        scope=scope,
        capabilities=frozenset({"read", "update"}),
        environments=frozenset({"paper"}),
        expires_at_ns=now_ns + 100_000_000,
        issued_at_ns=now_ns - 1,
        max_notional=None,
        max_leverage=None,
        deny=False,
    )
    action = ActionRequestV1(
        version=CONTROL_VERSION,
        org_id=org_id,
        desk_id=desk_id,
        agent_id=agent_id,
        session_id=session_id,
        environment="paper",
        action_idempotency_key="idempotency-a",
        tool_id=tool_id,
        resource=resource,
        scope=scope,
        capability="read",
        timestamp_ns=now_ns,
    )
    decision = evaluate_tool_policy(action, context, (grant,))
    runtime = McpControlRuntime(
        context_resolver=lambda *args, **kwargs: context,
        grants_resolver=lambda *args, **kwargs: (grant,),
        attestation_resolver=lambda *args, **kwargs: attestation,
        approval_resolver=lambda *args, **kwargs: None,
        snapshot=snapshot,
        now_ns=lambda: now_ns,
        audit_sink=audit_sink,
    )
    return now_ns, runtime, context, action, (grant,), decision


def test_dry_run_audits_without_consuming_identical_real_submit() -> None:
    runtime_box: dict[str, McpControlRuntime] = {}
    snapshot_box = {}
    sink_calls = []

    def sink(events) -> None:
        assert runtime_box["runtime"].snapshot is snapshot_box["original"]
        sink_calls.append(events)

    now_ns, runtime, context, action, grants, decision = _accepted_dry_run_fixture(audit_sink=sink)
    runtime_box["runtime"] = runtime
    original = runtime.snapshot
    snapshot_box["original"] = original
    candidate, dry_run = submit_action(
        original,
        request=action,
        context=context,
        grants=grants,
        decision=decision,
        now_ns=now_ns,
        dry_run=True,
    )
    assert dry_run.state == "dry_run"
    assert candidate.actions and candidate.audit_events[-1].kind == "action_dry_run"
    audit_only = _dry_run_audit_only_revision(original, candidate)

    runtime.commit(audit_only)
    real_after_dry_run, result_after_dry_run = submit_action(
        runtime.snapshot,
        request=action,
        context=context,
        grants=grants,
        decision=decision,
        now_ns=now_ns,
        dry_run=False,
    )
    real_without_dry_run, result_without_dry_run = submit_action(
        original,
        request=action,
        context=context,
        grants=grants,
        decision=decision,
        now_ns=now_ns,
        dry_run=False,
    )

    assert runtime.snapshot.actions == original.actions
    assert runtime.snapshot.outbox_event_ids == original.outbox_event_ids
    assert runtime.snapshot.audit_events[-1].kind == "action_dry_run"
    assert len(sink_calls) == 1 and sink_calls[0] == (audit_only.audit_events[-1],)
    assert result_after_dry_run.state == result_without_dry_run.state == "approved"
    assert result_after_dry_run.reason_codes == result_without_dry_run.reason_codes == ()
    assert real_after_dry_run.actions[-1].state == real_without_dry_run.actions[-1].state


def test_dry_run_audit_sink_failure_keeps_runtime_snapshot_unchanged() -> None:
    def fail_sink(_events) -> None:
        raise RuntimeError("secret")

    now_ns, runtime, context, action, grants, decision = _accepted_dry_run_fixture(
        audit_sink=fail_sink
    )
    original = runtime.snapshot
    candidate, dry_run = submit_action(
        original,
        request=action,
        context=context,
        grants=grants,
        decision=decision,
        now_ns=now_ns,
        dry_run=True,
    )
    assert dry_run.state == "dry_run"
    with pytest.raises(HTTPException) as caught:
        runtime.commit(_dry_run_audit_only_revision(original, candidate))

    assert caught.value.status_code == 503
    assert caught.value.detail == "AUDIT_UNAVAILABLE"
    assert runtime.snapshot is original


class _Audit:
    def __init__(self) -> None:
        self.events = []
        self.batches = []

    def append_batch(self, events) -> None:
        self.batches.append(events)
        self.events.extend(events)


class _Resolver:
    def __init__(self) -> None:
        self.calls = []

    def resolve_verified(self, token, *, peer_certificate_der=None):
        self.calls.append((token, peer_certificate_der))
        raise McpPrincipalResolutionError(McpPrincipalResolutionCodeV1.PRINCIPAL_REJECTED)


class _UnavailableResolver:
    def resolve_verified(self, token, *, peer_certificate_der=None):
        raise McpPrincipalResolutionError(McpPrincipalResolutionCodeV1.VERIFIER_UNAVAILABLE)


def _configured_runtime(*, allow_unaudited_for_tests: bool = False) -> McpControlRuntime:
    return McpControlRuntime(
        context_resolver=lambda *args, **kwargs: None,
        grants_resolver=lambda *args, **kwargs: (),
        attestation_resolver=lambda *args, **kwargs: None,
        approval_resolver=lambda *args, **kwargs: None,
        halt_authority=HaltAuthority(clock=lambda: 1),
        allow_unaudited_for_tests=allow_unaudited_for_tests,
    )


def _mounted_binding() -> tuple[TestClient, McpControlBinding, _Resolver]:
    resolver = _Resolver()
    binding = build_mcp_control(
        McpRuntimeFactoryConfigV1(runtime=_configured_runtime(), resolver=resolver, audit=_Audit())
    )
    app = FastAPI()
    app.state.mcp_control_runtime = binding.runtime
    app.state.mcp_control_principal_resolver = binding.principal_resolver
    app.include_router(binding.router)
    return TestClient(app), binding, resolver


def test_factory_submits_one_complete_event_batch_before_snapshot_commit() -> None:
    runtime = _configured_runtime()
    audit = _Audit()
    binding = build_mcp_control(
        McpRuntimeFactoryConfigV1(runtime=runtime, resolver=_Resolver(), audit=audit)
    )
    first = _revised(runtime.snapshot, reason="FIRST_DENIAL")
    candidate = _revised(first, reason="SECOND_DENIAL")

    runtime.commit(candidate)

    assert audit.batches == [candidate.audit_events]
    assert audit.events == list(candidate.audit_events)
    assert runtime.snapshot is candidate

    runtime.commit(candidate)

    assert audit.batches == [candidate.audit_events, ()]
    binding.close()


def test_factory_batch_failure_keeps_store_and_snapshot_unchanged() -> None:
    class MidBatchFailure:
        def __init__(self) -> None:
            self.persisted: list[object] = []
            self.calls: list[tuple[object, ...]] = []

        def append_batch(self, events) -> None:
            self.calls.append(events)
            staged = list(self.persisted)
            for index, event in enumerate(events):
                staged.append(event)
                if index == 1:
                    raise RuntimeError("private-store-detail")
            self.persisted = staged

    runtime = _configured_runtime()
    audit = MidBatchFailure()
    binding = build_mcp_control(
        McpRuntimeFactoryConfigV1(runtime=runtime, resolver=_Resolver(), audit=audit)
    )
    original = runtime.snapshot
    candidate = _revised(_revised(original, reason="FIRST_DENIAL"), reason="SECOND_DENIAL")

    with pytest.raises(HTTPException) as caught:
        runtime.commit(candidate)

    assert caught.value.status_code == 503
    assert caught.value.detail == "AUDIT_UNAVAILABLE"
    assert len(audit.calls) == 1
    assert audit.calls[0] == candidate.audit_events
    assert audit.persisted == []
    assert runtime.snapshot is original
    binding.close()


def test_factory_requires_runtime_resolver_and_audit_at_construction() -> None:
    with pytest.raises(McpRuntimeFactoryError) as caught:
        build_mcp_control(
            McpRuntimeFactoryConfigV1(
                runtime=_configured_runtime(), resolver=_Resolver(), audit=None
            )
        )
    assert str(caught.value) == "MCP_CONTROL_UNAVAILABLE"


def test_factory_refuses_test_only_unaudited_runtime() -> None:
    with pytest.raises(McpRuntimeFactoryError) as caught:
        build_mcp_control(
            McpRuntimeFactoryConfigV1(
                runtime=_configured_runtime(allow_unaudited_for_tests=True),
                resolver=_Resolver(),
                audit=_Audit(),
            )
        )

    assert str(caught.value) == "MCP_CONTROL_UNAVAILABLE"


def test_factory_config_and_binding_repr_redact_injected_ports() -> None:
    class ReprAudit(_Audit):
        def __repr__(self) -> str:
            return "audit-dsn-canary"

    class ReprResolver(_Resolver):
        def __repr__(self) -> str:
            return "resolver-token-canary"

    config = McpRuntimeFactoryConfigV1(
        runtime=_configured_runtime(),
        resolver=ReprResolver(),
        audit=ReprAudit(),
    )
    config_repr = repr(config)
    binding = build_mcp_control(config)
    binding_repr = repr(binding)

    assert "audit-dsn-canary" not in config_repr + binding_repr
    assert "resolver-token-canary" not in config_repr + binding_repr
    binding.close()


def test_factory_rejects_runtime_without_halt_authority() -> None:
    runtime = _runtime()
    with pytest.raises(McpRuntimeFactoryError):
        build_mcp_control(
            McpRuntimeFactoryConfigV1(runtime=runtime, resolver=_Resolver(), audit=_Audit())
        )


def test_factory_rejects_missing_resolver_without_fallback_and_no_store() -> None:
    client, binding, _resolver = _mounted_binding()
    client.app.state.mcp_control_principal_resolver = None

    response = client.get("/mcp/tools", params={"agent_id": "agent-a", "session_id": "s-a"})

    assert response.status_code == 503
    assert response.json() == {"detail": "MCP_CONTROL_UNAVAILABLE"}
    assert response.headers["cache-control"] == "no-store"
    binding.close()
    binding.close()
    client.close()


def test_bound_runtime_cannot_remove_or_replace_its_audit_sink() -> None:
    client, binding, _resolver = _mounted_binding()
    runtime = binding.runtime

    assert runtime.write_ahead_required is True
    assert runtime.audit_sink is not None
    with pytest.raises(AttributeError):
        runtime.audit_sink = None
    with pytest.raises(TypeError):
        runtime.bind_write_ahead_audit_sink(lambda _events: None)

    client.close()


def test_factory_accepts_only_one_well_formed_bearer_header_and_no_store_errors() -> None:
    client, binding, resolver = _mounted_binding()
    params = {"agent_id": "agent-a", "session_id": "s-a"}

    missing = client.get("/mcp/tools", params=params)
    malformed = client.get("/mcp/tools", params=params, headers={"Authorization": "Basic opaque"})
    rejected = client.get("/mcp/tools", params=params, headers={"Authorization": "Bearer token"})
    duplicate = client.get(
        "/mcp/tools",
        params=params,
        headers=[("Authorization", "Bearer one"), ("Authorization", "Bearer two")],
    )
    method_mismatch = client.post("/mcp/tools")

    assert missing.status_code == malformed.status_code == duplicate.status_code == 401
    assert rejected.status_code == 401
    assert all(
        response.json() == {"detail": "UNAUTHENTICATED"}
        for response in (missing, malformed, rejected, duplicate)
    )
    assert all(
        response.headers["cache-control"] == "no-store"
        for response in (missing, malformed, rejected, duplicate, method_mismatch)
    )
    assert resolver.calls == [("token", None)]
    assert method_mismatch.status_code == 405
    binding.close()
    client.close()


def test_unavailable_verifier_returns_fixed_503_without_store() -> None:
    binding = build_mcp_control(
        McpRuntimeFactoryConfigV1(
            runtime=_configured_runtime(), resolver=_UnavailableResolver(), audit=_Audit()
        )
    )
    app = FastAPI()
    app.state.mcp_control_runtime = binding.runtime
    app.state.mcp_control_principal_resolver = binding.principal_resolver
    app.include_router(binding.router)
    with TestClient(app) as client:
        response = client.get(
            "/mcp/tools",
            params={"agent_id": "agent-a", "session_id": "s-a"},
            headers={"Authorization": "Bearer token"},
        )
    assert response.status_code == 503
    assert response.json() == {"detail": "MCP_CONTROL_UNAVAILABLE"}
    assert response.headers["cache-control"] == "no-store"
    binding.close()


def test_closed_binding_denies_requests_with_fixed_no_store_response() -> None:
    client, binding, resolver = _mounted_binding()
    binding.close()

    response = client.get(
        "/mcp/tools",
        params={"agent_id": "agent-a", "session_id": "s-a"},
        headers={"Authorization": "Bearer token"},
    )

    assert response.status_code == 503
    assert response.json() == {"detail": "MCP_CONTROL_UNAVAILABLE"}
    assert response.headers["cache-control"] == "no-store"
    assert resolver.calls == []
    client.close()
