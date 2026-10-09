"""Independent offline acceptance for DEP-002 reviewed apply and rollback."""

from __future__ import annotations

import copy
import hashlib
import json
import pickle
import socket
import sys
import urllib.request
from datetime import UTC, date, datetime, timedelta
from decimal import ROUND_DOWN, Decimal, localcontext
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from infra.cloud.apply_gate import (  # noqa: E402
    ApplyPlanV1,
    ApprovalEvidenceV1,
    CostEvidenceV1,
    FakeApplyReceiptV1,
    FreshnessPolicyV1,
    GateError,
    InventoryResourceV1,
    InventorySnapshotV1,
    build_apply_plan,
    build_rollback_plan,
    evaluate_apply,
    inventory_digest_for,
    resource_spec_digest,
)
from infra.cloud.validate_resource_intent import ResourceIntentRegistries  # noqa: E402

from leviathan_core.seal import SealError, verify  # noqa: E402

TODAY = date(2026, 10, 5)
NOW_UTC = datetime(2026, 10, 5, 18, 30, tzinfo=UTC)
NOW_NS = int(NOW_UTC.timestamp()) * 1_000_000_000
PRICE_URL = "https://example.com/pricing"
ARTIFACT = "a" * 64
CHANGE_TICKET = "DEP-002-acceptance"
MAX_AGE = 2 * 86_400_000_000_000


def _registry() -> ResourceIntentRegistries:
    requirements = b"requirements:\n  - id: LEV-REQ-001\n  - id: LEV-REQ-006\n  - id: LEV-REQ-009\n"

    def members_digest(values: tuple[str, ...]) -> str:
        raw = json.dumps(sorted(values), separators=(",", ":")).encode("ascii")
        return hashlib.sha256(raw).hexdigest()

    owners = ("data-team", "platform-team", "release-manager")
    sources = (PRICE_URL,)
    payload = {
        "schema_version": 1,
        "owners": list(owners),
        "owner_snapshot_id": members_digest(owners),
        "price_sources": list(sources),
        "price_source_snapshot_id": members_digest(sources),
        "requirements_map_sha256": hashlib.sha256(requirements).hexdigest(),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii")
    return ResourceIntentRegistries(encoded, requirements)


def _resource(
    env: str,
    provider: str,
    kind: str,
    name: str,
    alias_provider: str,
) -> dict[str, Any]:
    resource: dict[str, Any] = {
        "provider": provider,
        "kind": kind,
        "name": name,
        "purpose": "licensing" if kind != "r2" else "cold_archive",
        "requirements": ["LEV-REQ-001" if kind == "worker" else "LEV-REQ-009"],
        "owner": "data-team" if kind == "r2" else "platform-team",
        "approver": "release-manager",
        "region": "us-central",
        "jurisdiction": "US",
        "data_classification": "confidential",
        "tier": "minimum",
        "minimum_tier": True,
        "cost": {
            "currency": "USD",
            "monthly_cap": "12.50",
            "price_source": PRICE_URL,
            "retrieved_on": TODAY.isoformat(),
        },
        "credential_aliases": [
            "vault://leviathan-ai/"
            f"{'live' if env == 'live' else 'development'}/{alias_provider}/"
            f"{name.upper().replace('-', '_')}"
        ],
    }
    if provider == "neon":
        resource["neon"] = {
            "project": f"project-{env}",
            "branch": f"branch-{env}",
            "role": "licensing-reader",
        }
    else:
        resource["binding"] = f"binding-{name}"
    if kind == "r2":
        resource["retention"] = {
            "days": 2557,
            "lock_intent": "required",
            "legal_hold": True,
            "delete_on_destroy": False,
        }
    return resource


def _manifest(*, include_r2: bool = False) -> dict[str, Any]:
    environments: dict[str, Any] = {}
    for env in ("development", "staging", "live"):
        resources = [
            _resource(
                env,
                "cloudflare",
                "worker",
                f"licensing-worker-{env}",
                "cloudflare",
            ),
            _resource(env, "neon", "database", f"licensing-db-{env}", "neon"),
        ]
        if include_r2 and env == "live":
            resources.append(_resource("live", "cloudflare", "r2", "archive-live", "cloudflare-r2"))
        environments[env] = {"identity": f"leviathan-{env}", "resources": resources}
    return {"schema_version": 1, "project": "leviathan-ai", "environments": environments}


def _setup(
    env: str = "staging", *, include_r2: bool = False, capture_ns: int = NOW_NS,
    worker_name: str | None = None,
) -> dict[str, Any]:
    intent = _manifest(include_r2=include_r2)
    resources = intent["environments"][env]["resources"]
    if worker_name is not None:
        resources[0] = _resource(env, "cloudflare", "worker", worker_name, "cloudflare")
    costs = tuple(
        CostEvidenceV1(
            provider=item["provider"],
            kind=item["kind"],
            name=item["name"],
            currency="USD",
            monthly_estimate=Decimal("10.00"),
            monthly_cap=Decimal(item["cost"]["monthly_cap"]),
            price_source=PRICE_URL,
            retrieved_on=TODAY,
        )
        for item in resources
    )
    inventory_resources = tuple(
        InventoryResourceV1(
            provider=item["provider"],
            kind=item["kind"],
            name=item["name"],
            provider_resource_id=f"fake-{item['kind']}-{item['name']}",
            owner=item["owner"],
            spec_digest=resource_spec_digest(item),
            retention_days=(item.get("retention") or {}).get("days"),
            legal_hold=(item.get("retention") or {}).get("legal_hold", False),
        )
        for item in resources
    )
    inventory = InventorySnapshotV1(
        project="leviathan-ai",
        environment=env,
        captured_utc_ns=capture_ns,
        resources=inventory_resources,
        inventory_digest=inventory_digest_for("leviathan-ai", env, capture_ns, inventory_resources),
    )
    freshness = FreshnessPolicyV1(
        max_inventory_age_ns=MAX_AGE,
        max_price_age_days=30,
        max_approval_age_ns=MAX_AGE,
        max_plan_age_ns=MAX_AGE,
    )
    return {
        "intent": intent,
        "registries": _registry(),
        "environment": env,
        "inventory": inventory,
        "costs": costs,
        "freshness": freshness,
        "now_utc_ns": NOW_NS,
        "change_ticket": CHANGE_TICKET,
        "artifact_digest": ARTIFACT,
    }


def _plan(args: dict[str, Any], **updates: Any) -> ApplyPlanV1:
    call = args.copy()
    call.update(updates)
    return build_apply_plan(call.pop("intent"), **call)


def _approvals(plan: ApplyPlanV1, *, same_actor: bool = False) -> tuple[ApprovalEvidenceV1, ...]:
    manager = "reviewer-acceptance" if same_actor else "manager-acceptance"
    roles = (("Reviewer", "reviewer-acceptance"), ("Release Manager", manager))
    return tuple(
        ApprovalEvidenceV1(
            plan_hash=plan.plan_hash,
            environment=plan.environment,
            actor_id=actor,
            role=role,
            approved_utc_ns=NOW_NS,
            change_ticket=plan.change_ticket,
            artifact_digest=plan.artifact_digest,
        )
        for role, actor in roles
    )


def _evaluate(args: dict[str, Any], plan: ApplyPlanV1, **updates: Any) -> Any:
    call = {
        key: args[key]
        for key in ("intent", "registries", "inventory", "costs", "freshness", "now_utc_ns")
    }
    call.update(approvals=_approvals(plan), idempotency_key=plan.idempotency_key)
    call.update(updates)
    return evaluate_apply(plan, **call)


def _assert_gate_error(call: Any, code: str) -> None:
    with pytest.raises(GateError) as caught:
        call()
    assert caught.value.code == code
    assert caught.value.args == (code,)
    assert str(caught.value) == code


def test_offline_plan_is_redacted_sealed_and_binds_inventory_cost_and_idempotency() -> None:
    args = _setup()
    plan = _plan(args)
    assert plan.environment == "staging"
    assert plan.required_roles == ("Reviewer",)
    assert plan.monthly_estimate == Decimal("20.00")
    assert plan.monthly_cap == Decimal("25.00")
    assert plan.provider_resource_ids == tuple(
        sorted(item.provider_resource_id for item in args["inventory"].resources)
    )
    assert all("vault://" not in line for line in plan.redacted_diff)
    assert all(
        "licensing-worker" not in line and "licensing-db" not in line for line in plan.redacted_diff
    )
    assert verify(plan, "dep002.apply_plan.v1")
    assert not verify(plan, "dep002.apply_result.v1")

    result = _evaluate(args, plan)
    assert result.status == "ELIGIBLE"
    assert result.actor_ids == ("manager-acceptance", "reviewer-acceptance")
    assert _evaluate(args, plan, previous_result=result) is result

    clone = ApplyPlanV1(**plan.model_dump())
    assert not verify(clone, "dep002.apply_plan.v1")
    _assert_gate_error(
        lambda: evaluate_apply(
            clone,
            intent=args["intent"],
            registries=args["registries"],
            inventory=args["inventory"],
            costs=args["costs"],
            approvals=_approvals(plan),
            freshness=args["freshness"],
            now_utc_ns=NOW_NS,
            idempotency_key=plan.idempotency_key,
        ),
        "PLAN_UNTRUSTED",
    )

    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(SealError):
            operation(plan)
    with pytest.raises(SealError):
        plan.environment = "live"
    with pytest.raises(SealError):
        del plan.environment
    with pytest.raises(SealError):
        ApplyPlanV1.model_construct(**plan.model_dump())

    tampered = _plan(args)
    object.__setattr__(tampered, "environment", "live")
    with pytest.raises(GateError) as caught:
        evaluate_apply(
            tampered,
            intent=args["intent"],
            registries=args["registries"],
            inventory=args["inventory"],
            costs=args["costs"],
            approvals=_approvals(plan),
            freshness=args["freshness"],
            now_utc_ns=NOW_NS,
            idempotency_key=plan.idempotency_key,
        )
    assert caught.value.code == "PLAN_UNTRUSTED"


def test_missing_stale_or_over_cap_cost_and_absent_policy_fail_closed() -> None:
    args = _setup()
    _assert_gate_error(lambda: _plan(args, freshness=None), "FRESHNESS_POLICY_MISSING_OR_INVALID")
    _assert_gate_error(lambda: _plan(args, costs=()), "COST_EVIDENCE_MISSING")
    _assert_gate_error(lambda: _plan(args, costs=args["costs"][:1]), "COST_EVIDENCE_MISSING")

    stale_date = TODAY - timedelta(days=2)
    stale_intent = json.loads(json.dumps(args["intent"]))
    for row in stale_intent["environments"]["staging"]["resources"]:
        row["cost"]["retrieved_on"] = stale_date.isoformat()
    stale_costs = tuple(
        item.model_copy(update={"retrieved_on": stale_date}) for item in args["costs"]
    )
    strict_freshness = args["freshness"].model_copy(update={"max_price_age_days": 1})
    _assert_gate_error(
        lambda: _plan(
            args | {"intent": stale_intent, "costs": stale_costs, "freshness": strict_freshness}
        ),
        "PRICE_EVIDENCE_STALE",
    )

    too_expensive = list(args["costs"])
    too_expensive[0] = too_expensive[0].model_copy(update={"monthly_estimate": Decimal("12.51")})
    _assert_gate_error(lambda: _plan(args, costs=tuple(too_expensive)), "COST_CAP_EXCEEDED")


def test_plan_digest_is_order_invariant_and_decimal_context_does_not_change_costs() -> None:
    args = _setup()
    first = _plan(args)
    reverse_resources = tuple(reversed(args["inventory"].resources))
    reverse_inventory = InventorySnapshotV1(
        project=args["inventory"].project,
        environment=args["inventory"].environment,
        captured_utc_ns=NOW_NS,
        resources=reverse_resources,
        inventory_digest=inventory_digest_for("leviathan-ai", "staging", NOW_NS, reverse_resources),
    )
    with localcontext() as context:
        context.prec = 2
        context.rounding = ROUND_DOWN
        second = _plan(
            args,
            costs=tuple(reversed(args["costs"])),
            inventory=reverse_inventory,
        )
    assert first.plan_hash == second.plan_hash
    assert first.monthly_estimate == second.monthly_estimate == Decimal("20.00")

    padded = list(args["costs"])
    padded[0] = padded[0].model_copy(update={"monthly_estimate": Decimal("10." + "0" * 50)})
    padded_plan = _plan(args, costs=tuple(padded))
    assert padded_plan.monthly_estimate == Decimal("20.00")


def test_exact_cap_equality_is_allowed_but_currency_and_cap_mismatches_fail() -> None:
    args = _setup()
    at_cap = tuple(
        row.model_copy(update={"monthly_estimate": Decimal("12.50")}) for row in args["costs"]
    )
    plan = _plan(args, costs=at_cap)
    assert plan.monthly_estimate == plan.monthly_cap == Decimal("25.00")

    wrong_cap = list(args["costs"])
    wrong_cap[0] = wrong_cap[0].model_copy(update={"monthly_cap": Decimal("13.00")})
    _assert_gate_error(lambda: _plan(args, costs=tuple(wrong_cap)), "COST_EVIDENCE_MISMATCH")
    wrong_currency = list(args["costs"])
    wrong_currency[0] = wrong_currency[0].model_copy(update={"currency": "EUR"})
    _assert_gate_error(lambda: _plan(args, costs=tuple(wrong_currency)), "COST_EVIDENCE_MISMATCH")


def test_non_destructive_create_is_explicitly_redacted() -> None:
    args = _setup()
    capture = args["inventory"].captured_utc_ns
    empty = InventorySnapshotV1(
        project="leviathan-ai",
        environment="staging",
        captured_utc_ns=capture,
        resources=(),
        inventory_digest=inventory_digest_for("leviathan-ai", "staging", capture, ()),
    )
    plan = _plan(args, inventory=empty)
    assert len(plan.redacted_diff) == 2
    assert all(row.startswith("CREATE ") for row in plan.redacted_diff)
    assert all("licensing-" not in row and "vault://" not in row for row in plan.redacted_diff)


def test_identity_and_content_seals_survive_base_model_reentry_and_tampering() -> None:
    args = _setup()
    plan = _plan(args)
    result = _evaluate(args, plan)
    twin = type(plan)(**plan.model_dump())
    assert twin.plan_hash == plan.plan_hash
    assert not verify(twin, "dep002.apply_plan.v1")

    object.__setattr__(result, "status", "UNKNOWN")
    with pytest.raises(GateError) as caught:
        evaluate_apply(
            plan,
            intent=args["intent"],
            registries=args["registries"],
            inventory=args["inventory"],
            costs=args["costs"],
            approvals=_approvals(plan),
            freshness=args["freshness"],
            now_utc_ns=NOW_NS,
            idempotency_key=plan.idempotency_key,
            previous_result=result,
        )
    assert caught.value.code == "RESULT_UNTRUSTED"

    with pytest.raises(SealError):
        BaseModel.__init__(plan, environment="live")
    assert verify(plan, "dep002.apply_plan.v1")
    with pytest.raises(SealError):
        BaseModel.__setstate__(plan, {"__dict__": {**plan.__dict__, "environment": "live"}})
    assert verify(plan, "dep002.apply_plan.v1")


def test_all_public_integer_timestamps_reject_bool() -> None:
    with pytest.raises(SealError):
        InventorySnapshotV1(
            project="leviathan-ai",
            environment="staging",
            captured_utc_ns=True,
            resources=(),
            inventory_digest="a" * 64,
        )
    with pytest.raises(SealError):
        ApprovalEvidenceV1(
            plan_hash="a" * 64,
            environment="live",
            actor_id="reviewer",
            role="Reviewer",
            approved_utc_ns=True,
            change_ticket=CHANGE_TICKET,
            artifact_digest=ARTIFACT,
        )
    with pytest.raises(SealError):
        FakeApplyReceiptV1(outcome="partial", observed_utc_ns=True)


def test_boolean_time_limits_and_unbounded_decimal_inputs_fail_closed() -> None:
    args = _setup()
    with pytest.raises(SealError):
        FreshnessPolicyV1(
            max_inventory_age_ns=True,
            max_price_age_days=30,
            max_approval_age_ns=MAX_AGE,
            max_plan_age_ns=MAX_AGE,
        )

    invalid_costs = list(args["costs"])
    invalid_costs[0] = invalid_costs[0].model_copy(update={"monthly_estimate": Decimal("9" * 35)})
    _assert_gate_error(lambda: _plan(args, costs=tuple(invalid_costs)), "COST_ESTIMATE_INVALID")
    exponent_costs = list(args["costs"])
    exponent_costs[0] = exponent_costs[0].model_copy(update={"monthly_estimate": Decimal("1E+39")})
    _assert_gate_error(lambda: _plan(args, costs=tuple(exponent_costs)), "COST_ESTIMATE_INVALID")


def test_plan_staleness_previous_result_binding_and_mutable_model_inputs_fail_closed() -> None:
    args = _setup()
    plan = _plan(args)
    result = _evaluate(args, plan)
    short_plan_life = args["freshness"].model_copy(update={"max_plan_age_ns": 1})
    _assert_gate_error(
        lambda: evaluate_apply(
            plan,
            intent=args["intent"],
            registries=args["registries"],
            inventory=args["inventory"],
            costs=args["costs"],
            approvals=_approvals(plan),
            freshness=short_plan_life,
            now_utc_ns=NOW_NS + 2,
            idempotency_key=plan.idempotency_key,
        ),
        "PLAN_STALE",
    )

    other_plan = _plan(args | {"change_ticket": "DEP-002-other"})
    _assert_gate_error(
        lambda: _evaluate(args, other_plan, previous_result=result),
        "IDEMPOTENCY_KEY_CONFLICT",
    )
    with pytest.raises(SealError):
        args["inventory"].model_copy(update={"resources": []})


def test_inventory_age_scope_digest_and_manifest_drift_are_checked() -> None:
    args = _setup()
    _assert_gate_error(lambda: _plan(args, inventory=None), "INVENTORY_MISSING")
    wrong_scope = InventorySnapshotV1(
        project="leviathan-ai",
        environment="live",
        captured_utc_ns=NOW_NS,
        resources=(),
        inventory_digest=inventory_digest_for("leviathan-ai", "live", NOW_NS, ()),
    )
    _assert_gate_error(lambda: _plan(args, inventory=wrong_scope), "INVENTORY_SCOPE_MISMATCH")
    stale_ns = NOW_NS - MAX_AGE - 1
    stale = InventorySnapshotV1(
        project="leviathan-ai",
        environment="staging",
        captured_utc_ns=stale_ns,
        resources=(),
        inventory_digest=inventory_digest_for("leviathan-ai", "staging", stale_ns, ()),
    )
    _assert_gate_error(lambda: _plan(args, inventory=stale), "INVENTORY_STALE")

    altered = args["inventory"].model_copy(update={"inventory_digest": "f" * 64})
    _assert_gate_error(lambda: _plan(args, inventory=altered), "INVENTORY_DIGEST_MISMATCH")

    changed_manifest = json.loads(json.dumps(args["intent"]))
    changed_manifest["environments"]["development"]["identity"] = "other-development"
    plan = _plan(args)
    _assert_gate_error(
        lambda: _evaluate(args | {"intent": changed_manifest}, plan),
        "PLAN_OR_INVENTORY_CHANGED",
    )


def test_fresh_identical_inventory_is_accepted_and_fresh_drift_is_rejected() -> None:
    args = _setup("live")
    plan = _plan(args)
    captured = NOW_NS + 3_600_000_000_000
    same_rows = args["inventory"].resources
    identical = InventorySnapshotV1(
        project=args["inventory"].project,
        environment=args["inventory"].environment,
        captured_utc_ns=captured,
        resources=same_rows,
        inventory_digest=inventory_digest_for(
            args["inventory"].project,
            args["inventory"].environment,
            captured,
            same_rows,
        ),
    )
    assert identical.inventory_digest == plan.inventory_digest
    current = args | {"inventory": identical, "now_utc_ns": captured}
    assert _evaluate(current, plan).status == "ELIGIBLE"

    drifted_row = InventoryResourceV1(
        provider=same_rows[0].provider,
        kind=same_rows[0].kind,
        name=same_rows[0].name,
        provider_resource_id="fake-drifted-resource-id",
        owner=same_rows[0].owner,
        spec_digest=same_rows[0].spec_digest,
        retention_days=same_rows[0].retention_days,
        legal_hold=same_rows[0].legal_hold,
    )
    drifted_rows = (drifted_row, *same_rows[1:])
    drifted = InventorySnapshotV1(
        project=identical.project,
        environment=identical.environment,
        captured_utc_ns=captured,
        resources=drifted_rows,
        inventory_digest=inventory_digest_for(
            identical.project, identical.environment, captured, drifted_rows
        ),
    )
    _assert_gate_error(
        lambda: _evaluate(current | {"inventory": drifted}, plan),
        "INVENTORY_DRIFT",
    )


def test_unreviewed_destructive_diff_provider_mismatch_and_freeze_are_blocked() -> None:
    args = _setup()
    extra = InventoryResourceV1(
        provider="cloudflare",
        kind="queue",
        name="unrequested-queue",
        provider_resource_id="fake-extra-queue",
        owner="platform-team",
        spec_digest="b" * 64,
    )
    old = args["inventory"]
    rows = (*old.resources, extra)
    snapshot = InventorySnapshotV1(
        project=old.project,
        environment=old.environment,
        captured_utc_ns=old.captured_utc_ns,
        resources=rows,
        inventory_digest=inventory_digest_for(
            old.project, old.environment, old.captured_utc_ns, rows
        ),
    )
    _assert_gate_error(lambda: _plan(args, inventory=snapshot), "UNREVIEWED_DESTRUCTIVE_DIFF")
    _assert_gate_error(lambda: _plan(args, freeze_window=True), "FREEZE_WINDOW")
    _assert_gate_error(
        lambda: _plan(args, change_ticket="EMERGENCY-OVERRIDE", freeze_window=True), "FREEZE_WINDOW"
    )

    wrong_provider = json.loads(json.dumps(args["intent"]))
    wrong_provider["environments"]["staging"]["resources"][0]["provider"] = "aws"
    _assert_gate_error(lambda: _plan(args | {"intent": wrong_provider}), "INTENT_NOT_READY")


def test_approvals_are_fresh_plan_bound_and_two_distinct_humans_for_live() -> None:
    args = _setup("live")
    plan = _plan(args)
    assert set(plan.required_roles) == {"Reviewer", "Release Manager"}
    for approvals, code in (
        (_approvals(plan)[:1], "APPROVAL_MISSING"),
        (_approvals(plan, same_actor=True), "APPROVAL_INVALID"),
    ):
        _assert_gate_error(
            lambda approvals=approvals: _evaluate(args, plan, approvals=approvals), code
        )

    stale = tuple(
        approval.model_copy(update={"approved_utc_ns": NOW_NS - MAX_AGE - 1})
        for approval in _approvals(plan)
    )
    _assert_gate_error(lambda: _evaluate(args, plan, approvals=stale), "APPROVAL_STALE")
    wrong_digest = (
        _approvals(plan)[0].model_copy(update={"artifact_digest": "c" * 64}),
        _approvals(plan)[1],
    )
    _assert_gate_error(lambda: _evaluate(args, plan, approvals=wrong_digest), "APPROVAL_INVALID")
    _assert_gate_error(
        lambda: _evaluate(args, plan, idempotency_key="d" * 64),
        "IDEMPOTENCY_KEY_MISMATCH",
    )


def test_approval_created_before_plan_is_rejected() -> None:
    args = _setup("live")
    plan = _plan(args)
    approvals = tuple(
        approval.model_copy(update={"approved_utc_ns": NOW_NS - 1})
        for approval in _approvals(plan)
    )
    _assert_gate_error(
        lambda: _evaluate(args, plan, approvals=approvals), "APPROVAL_BEFORE_PLAN"
    )


@pytest.mark.parametrize(
    "name", ("risk-ledger", "task-queue", "disk-archive", "tokenizer-worker")
)
def test_valid_resource_name_substrings_are_not_false_positives(name: str) -> None:
    args = _setup("live", worker_name=name)
    plan = _plan(args)
    assert plan.environment == "live"
    assert args["inventory"].resources[0].name == name
    assert _evaluate(args, plan).status == "ELIGIBLE"


@pytest.mark.parametrize("outcome", ["partial", "uncertain", "failed", "reported_success"])
def test_fake_receipt_outcomes_never_claim_success(outcome: str) -> None:
    args = _setup()
    plan = _plan(args)
    receipt = FakeApplyReceiptV1(
        outcome=outcome,
        observed_utc_ns=NOW_NS,
        provider_ids=("fake-provider-resource",),
    )
    result = _evaluate(args, plan, fake_receipt=receipt)
    assert result.status == "UNKNOWN"
    assert result.provider_ids == ("fake-provider-resource",)


def test_idempotent_retry_requires_same_issued_result_and_plan_binding() -> None:
    args = _setup()
    plan = _plan(args)
    result = _evaluate(args, plan)
    assert _evaluate(args, plan, previous_result=result) is result
    unissued = type(result)(**result.model_dump())
    _assert_gate_error(lambda: _evaluate(args, plan, previous_result=unissued), "RESULT_UNTRUSTED")


def test_rollback_is_new_review_only_plan_on_fresh_inventory_and_preserves_r2_hold() -> None:
    args = _setup("live", include_r2=True)
    plan = _plan(args)
    result = _evaluate(
        args, plan, fake_receipt=FakeApplyReceiptV1(outcome="uncertain", observed_utc_ns=NOW_NS)
    )
    assert result.status == "UNKNOWN"
    assert len(result.r2_hold_ids) == 1

    fresh_ns = NOW_NS + 1_000_000_000
    newer = _setup("live", include_r2=True, capture_ns=fresh_ns)["inventory"]
    rollback = build_rollback_plan(
        result,
        inventory=newer,
        freshness=args["freshness"],
        now_utc_ns=fresh_ns,
        known_good_revision="known-good-2026-10-04",
        known_good_artifact_digest="b" * 64,
    )
    assert rollback.status == "PENDING_REVIEW"
    assert rollback.preserved_r2_holds == result.r2_hold_ids
    assert rollback.required_roles == ("Reviewer", "Release Manager")
    assert verify(rollback, "dep002.rollback_plan.v1")

    missing_hold = newer.model_copy(
        update={
            "resources": tuple(row for row in newer.resources if row.kind != "r2"),
        }
    )
    missing_hold = missing_hold.model_copy(
        update={
            "inventory_digest": inventory_digest_for(
                missing_hold.project,
                missing_hold.environment,
                missing_hold.captured_utc_ns,
                missing_hold.resources,
            ),
        }
    )
    with pytest.raises(GateError) as caught:
        build_rollback_plan(
            result,
            inventory=missing_hold,
            freshness=args["freshness"],
            now_utc_ns=fresh_ns,
            known_good_revision="known-good-2026-10-04",
            known_good_artifact_digest="b" * 64,
        )
    assert caught.value.code == "R2_LEGAL_HOLD_MISSING"


def test_rollback_rejects_inventory_not_strictly_after_event() -> None:
    args = _setup("live")
    plan = _plan(args)
    event_ns = NOW_NS + 3_600_000_000_000
    result = _evaluate(
        args,
        plan,
        now_utc_ns=event_ns,
        approvals=tuple(
            approval.model_copy(update={"approved_utc_ns": event_ns})
            for approval in _approvals(plan)
        ),
        fake_receipt=FakeApplyReceiptV1(outcome="uncertain", observed_utc_ns=event_ns),
    )
    at_event = _setup("live", capture_ns=event_ns)["inventory"]
    with pytest.raises(GateError) as caught:
        build_rollback_plan(
            result,
            inventory=at_event,
            freshness=args["freshness"],
            now_utc_ns=event_ns + 1_000_000_000,
            known_good_revision="known-good-2026-10-04",
            known_good_artifact_digest="b" * 64,
        )
    assert caught.value.code == "ROLLBACK_INVENTORY_NOT_FRESH"


def test_all_calls_are_network_free_and_gate_errors_are_content_free(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def no_network(*_args: object, **_kwargs: object) -> None:
        calls.append("network")
        raise AssertionError("DEP-002 acceptance must not perform cloud/network calls")

    monkeypatch.setattr(socket.socket, "connect", no_network)
    monkeypatch.setattr(socket, "getaddrinfo", no_network)
    monkeypatch.setattr(urllib.request, "urlopen", no_network)
    args = _setup()
    plan = _plan(args)
    assert _evaluate(args, plan).status == "ELIGIBLE"
    assert calls == []

    canary = "SYNTHETIC_CLOUD_TOKEN_CANARY"
    bad_intent = json.loads(json.dumps(args["intent"]))
    bad_intent["environments"]["staging"]["resources"][0]["owner"] = canary
    with pytest.raises(GateError) as caught:
        _plan(args | {"intent": bad_intent})
    error = caught.value
    assert error.args == (error.code,)
    assert str(error) == error.code
    assert canary not in repr(error)
    assert canary not in repr(error.args)
    assert error.__cause__ is None
    assert error.__context__ is None or canary not in repr(error.__context__)
    assert calls == []
