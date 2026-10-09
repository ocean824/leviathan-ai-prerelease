"""Owned offline tests for the reviewed apply policy."""

from __future__ import annotations

import copy
import hashlib
import json
import sys
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest
from pydantic import BaseModel

from leviathan_core.seal import SealError

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from infra.cloud.apply_gate import (  # noqa: E402
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
from infra.cloud.validate_resource_intent import (  # noqa: E402
    ResourceIntentRegistries,
    load_manifest,
)

NOW = int(datetime(2026, 9, 30, tzinfo=UTC).timestamp()) * 1_000_000_000
PRICE = "https://developers.cloudflare.com/plans/"
ARTIFACT = "a" * 64


def _registry() -> ResourceIntentRegistries:
    requirements = (
        b"requirements:\n  - id: LEV-REQ-001\n  - id: LEV-REQ-006\n"
        b"  - id: LEV-REQ-009\n"
    )

    def snapshot(values: list[str]) -> str:
        raw = json.dumps(sorted(values), ensure_ascii=True, separators=(",", ":"))
        return hashlib.sha256(raw.encode("ascii")).hexdigest()

    owners = ["data-team", "platform-team", "release-manager"]
    document = {
        "schema_version": 1,
        "owners": owners,
        "owner_snapshot_id": snapshot(owners),
        "price_sources": [PRICE],
        "price_source_snapshot_id": snapshot([PRICE]),
        "requirements_map_sha256": hashlib.sha256(requirements).hexdigest(),
    }
    raw = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii")
    return ResourceIntentRegistries(raw, requirements)


@pytest.fixture
def setup() -> tuple[dict, ResourceIntentRegistries, tuple[CostEvidenceV1, ...],
                     InventorySnapshotV1, FreshnessPolicyV1]:
    intent = load_manifest(ROOT / "infra/cloud/resource_intent.example.yaml")
    assert isinstance(intent, dict)
    for env in intent["environments"].values():
        for resource in env["resources"]:
            resource["cost"] = {
                "currency": "USD", "monthly_cap": "12.50",
                "price_source": PRICE, "retrieved_on": "2026-09-30",
            }
    costs = tuple(
        CostEvidenceV1(
            provider=item["provider"], kind=item["kind"], name=item["name"],
            currency="USD", monthly_estimate=Decimal("10.00"),
            monthly_cap=Decimal("12.50"), price_source=PRICE,
            retrieved_on=datetime(2026, 9, 30, tzinfo=UTC).date(),
        )
        for item in intent["environments"]["live"]["resources"]
    )
    inventory = InventorySnapshotV1(
        project="leviathan-ai", environment="live", captured_utc_ns=NOW,
        resources=(), inventory_digest=inventory_digest_for("leviathan-ai", "live", NOW, ()),
    )
    freshness = FreshnessPolicyV1(
        max_inventory_age_ns=2 * 86_400_000_000_000, max_price_age_days=30,
        max_approval_age_ns=86_400_000_000_000,
        max_plan_age_ns=86_400_000_000_000,
    )
    return intent, _registry(), costs, inventory, freshness


def _plan_args(setup: tuple) -> dict:
    _, registries, costs, inventory, freshness = setup
    return dict(
        registries=registries, environment="live", inventory=inventory, costs=costs,
        freshness=freshness, now_utc_ns=NOW, change_ticket="DEP-002",
        artifact_digest=ARTIFACT,
    )


def _approvals(plan: object) -> tuple[ApprovalEvidenceV1, ...]:
    return tuple(
        ApprovalEvidenceV1(
            plan_hash=plan.plan_hash, environment="live", actor_id=actor,
            role=role, approved_utc_ns=NOW, change_ticket="DEP-002",
            artifact_digest=ARTIFACT,
        )
        for role, actor in (("Reviewer", "reviewer-1"),
                            ("Release Manager", "manager-2"))
    )


def _evaluate_args(setup: tuple, plan: object) -> dict:
    intent, registries, costs, inventory, freshness = setup
    return dict(
        intent=intent, registries=registries, inventory=inventory, costs=costs,
        approvals=_approvals(plan), freshness=freshness, now_utc_ns=NOW,
        idempotency_key=plan.idempotency_key,
    )


def test_plan_is_redacted_and_live_needs_two_distinct_humans(setup: tuple) -> None:
    intent = setup[0]
    plan = build_apply_plan(intent, **_plan_args(setup))
    assert len(plan.redacted_diff) == 2
    assert all("vault://" not in row and "leviathan-" not in row for row in plan.redacted_diff)
    assert plan.monthly_estimate == Decimal("20.00")
    assert plan.monthly_cap == Decimal("25.00")
    assert plan.price_evidence == ((PRICE, "2026-09-30"),)
    kwargs = _evaluate_args(setup, plan)
    kwargs["approvals"] = kwargs["approvals"][:1]
    with pytest.raises(GateError, match="APPROVAL_MISSING"):
        evaluate_apply(plan, **kwargs)
    kwargs["approvals"] = _approvals(plan)
    result = evaluate_apply(plan, **kwargs)
    assert result.status == "ELIGIBLE"
    assert evaluate_apply(plan, **kwargs, previous_result=result) is result


def test_missing_policy_or_cost_and_freeze_fail_closed(setup: tuple) -> None:
    intent = setup[0]
    args = _plan_args(setup)
    for change, code in (
        ({"freshness": None}, "FRESHNESS_POLICY_MISSING_OR_INVALID"),
        ({"costs": ()}, "COST_EVIDENCE_MISSING"),
        ({"freeze_window": True}, "FREEZE_WINDOW"),
    ):
        with pytest.raises(GateError) as error:
            build_apply_plan(intent, **(args | change))
        assert error.value.code == code


def test_inventory_drift_and_plan_twin_rejected(setup: tuple) -> None:
    intent = setup[0]
    plan = build_apply_plan(intent, **_plan_args(setup))
    args = _evaluate_args(setup, plan)
    duplicate = type(plan)(**plan.model_dump())
    with pytest.raises(GateError, match="PLAN_UNTRUSTED"):
        evaluate_apply(duplicate, **args)
    changed_resource = intent["environments"]["live"]["resources"][0]
    resource = InventoryResourceV1(
        provider=changed_resource["provider"], kind=changed_resource["kind"],
        name=changed_resource["name"], provider_resource_id="fake-neon-id",
        owner=changed_resource["owner"], spec_digest=resource_spec_digest(changed_resource),
    )
    changed = InventorySnapshotV1(
        project="leviathan-ai", environment="live", captured_utc_ns=NOW,
        resources=(resource,), inventory_digest=inventory_digest_for(
            "leviathan-ai", "live", NOW, (resource,)
        ),
    )
    args["inventory"] = changed
    with pytest.raises(GateError, match="INVENTORY_DRIFT"):
        evaluate_apply(plan, **args)


def test_fake_partial_is_unknown_and_rollback_preserves_r2_hold(setup: tuple) -> None:
    intent = setup[0]
    plan = build_apply_plan(intent, **_plan_args(setup))
    receipt = FakeApplyReceiptV1(outcome="partial", observed_utc_ns=NOW)
    result = evaluate_apply(plan, **_evaluate_args(setup, plan), fake_receipt=receipt)
    assert result.status == "UNKNOWN"
    held = InventoryResourceV1(
        provider="cloudflare", kind="r2", name="held-live-bucket",
        provider_resource_id="fake-r2-held", owner="data-team",
        spec_digest="b" * 64, retention_days=2557,
        legal_hold=True,
    )
    capture = NOW + 1_000_000_000
    inventory = InventorySnapshotV1(
        project="leviathan-ai", environment="live", captured_utc_ns=capture,
        resources=(held,), inventory_digest=inventory_digest_for(
            "leviathan-ai", "live", capture, (held,)
        ),
    )
    rollback = build_rollback_plan(
        result, inventory=inventory, freshness=setup[4], now_utc_ns=capture,
        known_good_revision="good-revision-1", known_good_artifact_digest="b" * 64,
    )
    assert rollback.status == "PENDING_REVIEW"
    assert rollback.preserved_r2_holds == ("fake-r2-held",)


def test_sealed_plan_reinit_copy_and_tamper_fail_closed(setup: tuple) -> None:
    plan = build_apply_plan(setup[0], **_plan_args(setup))
    kwargs = _evaluate_args(setup, plan)
    with pytest.raises(SealError):
        copy.copy(plan)
    with pytest.raises(SealError):
        copy.deepcopy(plan)
    modified = plan.model_copy(update={"monthly_cap": Decimal("999")})
    with pytest.raises(GateError, match="PLAN_UNTRUSTED"):
        evaluate_apply(modified, **kwargs)
    with pytest.raises(SealError):
        BaseModel.__init__(plan, **plan.model_dump())
    with pytest.raises(SealError):
        plan.monthly_cap = Decimal("999")
    with pytest.raises(SealError):
        FreshnessPolicyV1(max_inventory_age_ns=True, max_price_age_days=30,
                          max_approval_age_ns=1, max_plan_age_ns=1)
    assert evaluate_apply(plan, **kwargs).status == "ELIGIBLE"
    with pytest.raises(SealError):
        BaseModel.__setstate__(plan, {"__dict__": {"monthly_cap": Decimal("999")}})
    assert evaluate_apply(plan, **kwargs).status == "ELIGIBLE"


def test_fresh_identical_inventory_passes_and_fresh_drift_rejects(setup: tuple) -> None:
    plan = build_apply_plan(setup[0], **_plan_args(setup))
    captured = NOW + 3_600_000_000_000
    fresh = InventorySnapshotV1(
        project="leviathan-ai", environment="live", captured_utc_ns=captured,
        resources=(), inventory_digest=inventory_digest_for(
            "leviathan-ai", "live", captured, ()
        ),
    )
    assert fresh.inventory_digest == plan.inventory_digest
    kwargs = _evaluate_args(setup, plan) | {"inventory": fresh, "now_utc_ns": captured}
    assert evaluate_apply(plan, **kwargs).status == "ELIGIBLE"
    item = setup[0]["environments"]["live"]["resources"][0]
    resource = InventoryResourceV1(
        provider=item["provider"], kind=item["kind"], name=item["name"],
        provider_resource_id="fake-neon-id", owner=item["owner"],
        spec_digest=resource_spec_digest(item),
    )
    drifted = InventorySnapshotV1(
        project="leviathan-ai", environment="live", captured_utc_ns=captured,
        resources=(resource,), inventory_digest=inventory_digest_for(
            "leviathan-ai", "live", captured, (resource,)
        ),
    )
    with pytest.raises(GateError, match="INVENTORY_DRIFT"):
        evaluate_apply(plan, **(kwargs | {"inventory": drifted}))


def test_rollback_snapshot_must_follow_apply_event(setup: tuple) -> None:
    plan = build_apply_plan(setup[0], **_plan_args(setup))
    event = NOW + 3_600_000_000_000
    at_event = InventorySnapshotV1(
        project="leviathan-ai", environment="live", captured_utc_ns=event,
        resources=(), inventory_digest=inventory_digest_for(
            "leviathan-ai", "live", event, ()
        ),
    )
    receipt = FakeApplyReceiptV1(outcome="uncertain", observed_utc_ns=event)
    result = evaluate_apply(
        plan, **(_evaluate_args(setup, plan) | {"inventory": at_event,
                                               "now_utc_ns": event}),
        fake_receipt=receipt,
    )
    before_event = NOW + 1_800_000_000_000
    prior = InventorySnapshotV1(
        project="leviathan-ai", environment="live", captured_utc_ns=before_event,
        resources=(), inventory_digest=inventory_digest_for(
            "leviathan-ai", "live", before_event, ()
        ),
    )
    with pytest.raises(GateError, match="ROLLBACK_INVENTORY_NOT_FRESH"):
        build_rollback_plan(
            result, inventory=prior, freshness=setup[4],
            now_utc_ns=event + 1_000_000_000,
            known_good_revision="good-revision-1",
            known_good_artifact_digest="b" * 64,
        )


def test_approval_must_follow_plan_creation(setup: tuple) -> None:
    plan = build_apply_plan(setup[0], **_plan_args(setup))
    approvals = list(_approvals(plan))
    approvals[0] = approvals[0].model_copy(
        update={"approved_utc_ns": NOW - 3_600_000_000_000}
    )
    with pytest.raises(GateError, match="APPROVAL_BEFORE_PLAN"):
        evaluate_apply(
            plan, **(_evaluate_args(setup, plan) | {"approvals": tuple(approvals)})
        )


@pytest.mark.parametrize("name", [
    "risk-ledger", "task-queue", "disk-archive", "tokenizer-worker",
])
def test_safe_substrings_are_allowed_in_resource_names(setup: tuple, name: str) -> None:
    intent = copy.deepcopy(setup[0])
    resource = intent["environments"]["live"]["resources"][0]
    resource["name"] = name
    live = InventoryResourceV1(
        provider=resource["provider"], kind=resource["kind"], name=name,
        provider_resource_id="fake-neon-id", owner=resource["owner"],
        spec_digest=resource_spec_digest(resource),
    )
    inventory = InventorySnapshotV1(
        project="leviathan-ai", environment="live", captured_utc_ns=NOW,
        resources=(live,), inventory_digest=inventory_digest_for(
            "leviathan-ai", "live", NOW, (live,)
        ),
    )
    costs = (setup[2][0].model_copy(update={"name": name}), setup[2][1])
    plan = build_apply_plan(
        intent, **(_plan_args(setup) | {"inventory": inventory,
                                        "costs": costs, "change_ticket": "TASK-123"})
    )
    assert plan.environment == "live"
