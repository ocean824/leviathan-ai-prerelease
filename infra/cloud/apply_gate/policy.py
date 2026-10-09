"""Pure, offline policy for reviewed plans over injected fake inventory."""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any, Literal, NoReturn, cast

from infra.cloud.validate_resource_intent import (
    ResourceIntentRegistries,
    validate_resource_intent,
)

from leviathan_core.numeric import NumericError, canonical_json, exact_add, parse_decimal
from leviathan_core.seal import Issuer, SealError, require

from .models import (
    ApplyPlanV1,
    ApplyResultV1,
    ApprovalEvidenceV1,
    CostEvidenceV1,
    FakeApplyReceiptV1,
    FreshnessPolicyV1,
    GateError,
    InventoryResourceV1,
    InventorySnapshotV1,
    RollbackPlanV1,
)

_PLAN_ISSUER = Issuer("dep002.apply_plan.v1")
_RESULT_ISSUER = Issuer("dep002.apply_result.v1")
_ROLLBACK_ISSUER = Issuer("dep002.rollback_plan.v1")
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[a-zA-Z][a-zA-Z0-9_.:-]{0,127}\Z")
_SECRET_SEGMENT = re.compile(
    r"(?:^|[-_.:])(?:token|secret|password|passwd|credential|"
    r"api[-_]?key|private[-_]?key|sk)(?:[-_.:]|$)", re.I,
)
_ENVIRONMENTS = frozenset({"development", "staging", "live"})
_KINDS = frozenset({("neon", "database"), ("cloudflare", "worker"),
                    ("cloudflare", "queue"), ("cloudflare", "r2")})
_DAY_NS = 86_400_000_000_000


def _reject(code: str) -> NoReturn:
    raise GateError(code)


def _hash(value: object) -> str:
    try:
        return hashlib.sha256(canonical_json(value)).hexdigest()
    except NumericError:
        _reject("INPUT_INVALID")


def _safe_id(value: object) -> bool:
    return (
        type(value) is str and bool(_ID.fullmatch(value))
        and _SECRET_SEGMENT.search(value) is None
    )


def _hex(value: object) -> bool:
    return type(value) is str and bool(_HEX.fullmatch(value))


def _now_date(now_utc_ns: int) -> datetime:
    if type(now_utc_ns) is not int or now_utc_ns < 1:
        _reject("UTC_TIME_INVALID")
    try:
        seconds, _ = divmod(now_utc_ns, 1_000_000_000)
        return datetime.fromtimestamp(seconds, UTC)
    except (OverflowError, OSError, ValueError):
        _reject("UTC_TIME_INVALID")


def _age(now: int, earlier: int, maximum: int, code: str) -> None:
    if type(earlier) is not int or earlier < 1 or earlier > now or now - earlier > maximum:
        _reject(code)


def _freshness(policy: FreshnessPolicyV1 | None) -> FreshnessPolicyV1:
    if type(policy) is not FreshnessPolicyV1 or any(
        type(value) is not int or value < 1 for value in (
            policy.max_inventory_age_ns, policy.max_price_age_days,
            policy.max_approval_age_ns, policy.max_plan_age_ns,
        )
    ):
        _reject("FRESHNESS_POLICY_MISSING_OR_INVALID")
    return policy


def resource_spec_digest(resource: dict[str, Any]) -> str:
    """Full intent resource fingerprint, including scope/retention but no cleartext output."""
    if type(resource) is not dict:
        _reject("RESOURCE_INVALID")
    return _hash(resource)


def inventory_digest_for(
    project: str, environment: str, captured_utc_ns: int,
    resources: tuple[InventoryResourceV1, ...],
) -> str:
    """Content digest for a fake snapshot; capture time is checked separately."""
    if not _safe_id(project) or environment not in _ENVIRONMENTS or type(resources) is not tuple:
        _reject("INVENTORY_INVALID")
    rows: list[dict[str, object]] = []
    for item in resources:
        if type(item) is not InventoryResourceV1:
            _reject("INVENTORY_INVALID")
        rows.append(item.model_dump(mode="python"))
    rows.sort(key=lambda row: (str(row["provider"]), str(row["kind"]), str(row["name"])))
    return _hash({"version": 1, "project": project, "environment": environment,
                  "resources": rows})


def _inventory(
    snapshot: InventorySnapshotV1, *, project: str, environment: str,
    now_utc_ns: int, freshness: FreshnessPolicyV1,
) -> dict[tuple[str, str, str], InventoryResourceV1]:
    if type(snapshot) is not InventorySnapshotV1:
        _reject("INVENTORY_MISSING")
    if snapshot.project != project or snapshot.environment != environment:
        _reject("INVENTORY_SCOPE_MISMATCH")
    _age(now_utc_ns, snapshot.captured_utc_ns, freshness.max_inventory_age_ns,
         "INVENTORY_STALE")
    if snapshot.inventory_digest != inventory_digest_for(
        snapshot.project, snapshot.environment, snapshot.captured_utc_ns,
        snapshot.resources,
    ):
        _reject("INVENTORY_DIGEST_MISMATCH")
    found: dict[tuple[str, str, str], InventoryResourceV1] = {}
    ids: set[str] = set()
    for item in snapshot.resources:
        key = item.provider, item.kind, item.name
        if (
            key in found or (item.provider, item.kind) not in _KINDS
            or not _safe_id(item.name) or not _safe_id(item.owner)
            or not _safe_id(item.provider_resource_id)
            or item.provider_resource_id in ids or not _hex(item.spec_digest)
            or (item.retention_days is not None and item.retention_days < 0)
        ):
            _reject("INVENTORY_INVALID")
        found[key] = item
        ids.add(item.provider_resource_id)
    return found


def _intent(
    manifest: object, registries: ResourceIntentRegistries | None,
    environment: str, now: datetime,
) -> tuple[str, str, list[dict[str, Any]]]:
    if type(registries) is not ResourceIntentRegistries:
        _reject("REGISTRY_MISSING")
    if environment not in _ENVIRONMENTS:
        _reject("ENVIRONMENT_INVALID")
    verdict = validate_resource_intent(manifest, today=now.date(), registries=registries)
    if verdict.exit_code != 0:
        _reject("INTENT_NOT_READY")
    if not isinstance(manifest, dict) or manifest.get("project") != "leviathan-ai":
        _reject("INTENT_SCOPE_MISMATCH")
    environments = manifest.get("environments")
    if not isinstance(environments, dict) or environment not in environments:
        _reject("INTENT_SCOPE_MISMATCH")
    resources = environments[environment].get("resources")
    if type(resources) is not list:
        _reject("INTENT_NOT_READY")
    return cast(str, manifest["project"]), _hash(manifest), cast(list[dict[str, Any]], resources)


def _money(value: Decimal, code: str) -> Decimal:
    try:
        return parse_decimal(value, field="amount", max_sig_digits=34, max_abs_adjusted=38)
    except NumericError:
        _reject(code)


def _plan_payload(
    intent: object, *, registries: ResourceIntentRegistries | None,
    environment: str, inventory: InventorySnapshotV1,
    costs: tuple[CostEvidenceV1, ...], freshness: FreshnessPolicyV1 | None,
    now_utc_ns: int, created_utc_ns: int, change_ticket: str,
    artifact_digest: str, freeze_window: bool,
) -> dict[str, Any]:
    now = _now_date(now_utc_ns)
    policy = _freshness(freshness)
    if type(freeze_window) is not bool or freeze_window:
        _reject("FREEZE_WINDOW")
    if not _safe_id(change_ticket) or not _hex(artifact_digest):
        _reject("CHANGE_EVIDENCE_INVALID")
    project, intent_hash, requested = _intent(intent, registries, environment, now)
    existing = _inventory(inventory, project=project, environment=environment,
                          now_utc_ns=now_utc_ns, freshness=policy)
    if type(costs) is not tuple:
        _reject("COST_EVIDENCE_MISSING")
    cost_by_key: dict[tuple[str, str, str], CostEvidenceV1] = {}
    for cost in costs:
        if type(cost) is not CostEvidenceV1:
            _reject("COST_EVIDENCE_INVALID")
        key: tuple[str, str, str] = cost.provider, cost.kind, cost.name
        if key in cost_by_key:
            _reject("COST_EVIDENCE_INVALID")
        cost_by_key[key] = cost
    requested_by_key: dict[tuple[str, str, str], dict[str, Any]] = {}
    for item in requested:
        key = cast(tuple[str, str, str],
                   (item["provider"], item["kind"], item["name"]))
        if key in requested_by_key:
            _reject("INTENT_NOT_READY")
        requested_by_key[key] = item
    if set(cost_by_key) != set(requested_by_key):
        _reject("COST_EVIDENCE_MISSING")
    if not set(existing) <= set(requested_by_key):
        _reject("UNREVIEWED_DESTRUCTIVE_DIFF")
    estimate, cap = Decimal(0), Decimal(0)
    currencies: set[str] = set()
    price_sources: set[str] = set()
    price_evidence: set[tuple[str, str]] = set()
    diff: list[str] = []
    r2_holds: list[str] = []
    for key in sorted(requested_by_key):
        item = requested_by_key[key]
        quoted = cost_by_key[key]
        declared = item["cost"]
        if (
            quoted.currency != declared["currency"]
            or quoted.monthly_cap != _money(Decimal(declared["monthly_cap"]),
                                            "COST_CAP_INVALID")
            or quoted.price_source != declared["price_source"]
            or quoted.retrieved_on.isoformat() != declared["retrieved_on"]
        ):
            _reject("COST_EVIDENCE_MISMATCH")
        days = (now.date() - quoted.retrieved_on).days
        if days < 0 or days > min(policy.max_price_age_days, 30):
            _reject("PRICE_EVIDENCE_STALE")
        amount = _money(quoted.monthly_estimate, "COST_ESTIMATE_INVALID")
        limit = _money(quoted.monthly_cap, "COST_CAP_INVALID")
        if amount < 0 or limit <= 0 or amount > limit:
            _reject("COST_CAP_EXCEEDED")
        try:
            estimate = exact_add(estimate, amount)
            cap = exact_add(cap, limit)
        except NumericError:
            _reject("COST_TOTAL_INVALID")
        currencies.add(quoted.currency)
        price_sources.add(quoted.price_source)
        price_evidence.add((quoted.price_source, quoted.retrieved_on.isoformat()))
        live = existing.get(key)
        if live is not None:
            retention = item.get("retention")
            expected_days = retention["days"] if retention else None
            expected_hold = retention["legal_hold"] if retention else False
            if (
                live.spec_digest != resource_spec_digest(item)
                or live.owner != item["owner"]
                or live.retention_days != expected_days
                or live.legal_hold != expected_hold
            ):
                _reject("UNREVIEWED_DESTRUCTIVE_DIFF")
            if live.kind == "r2" and live.legal_hold:
                r2_holds.append(live.provider_resource_id)
        symbol = "UNCHANGED" if live else "CREATE"
        diff.append(f"{symbol} {key[0]} {key[1]} resource#{resource_spec_digest(item)[:12]}")
    if len(currencies) != 1:
        _reject("CURRENCY_MISMATCH")
    if _hash(intent) != intent_hash:
        _reject("INTENT_CHANGED_DURING_REVIEW")
    if inventory.inventory_digest != inventory_digest_for(
        inventory.project, inventory.environment, inventory.captured_utc_ns,
        inventory.resources,
    ):
        _reject("INVENTORY_CHANGED_DURING_REVIEW")
    cost_rows = [cost_by_key[key].model_dump(mode="json") for key in sorted(cost_by_key)]
    return {
        "version": 1, "project": project, "environment": environment,
        "intent_hash": intent_hash, "inventory_digest": inventory.inventory_digest,
        "inventory_captured_utc_ns": inventory.captured_utc_ns,
        "cost_digest": _hash(cost_rows), "created_utc_ns": created_utc_ns,
        "change_ticket": change_ticket, "artifact_digest": artifact_digest,
        "required_roles": ("Reviewer", "Release Manager") if environment == "live"
        else ("Reviewer",),
        "provider_resource_ids": tuple(sorted(resource.provider_resource_id
                                              for resource in existing.values())),
        "r2_hold_ids": tuple(sorted(r2_holds)),
        "monthly_estimate": estimate, "monthly_cap": cap,
        "currency": next(iter(currencies)),
        "price_sources": tuple(sorted(price_sources)),
        "price_evidence": tuple(sorted(price_evidence)),
        "redacted_diff": tuple(diff),
    }


def build_apply_plan(
    intent: object, *, registries: ResourceIntentRegistries | None,
    environment: str, inventory: InventorySnapshotV1,
    costs: tuple[CostEvidenceV1, ...], freshness: FreshnessPolicyV1 | None,
    now_utc_ns: int, change_ticket: str, artifact_digest: str,
    freeze_window: bool = False,
) -> ApplyPlanV1:
    """Issue a redacted plan after complete offline validation."""
    payload = _plan_payload(
        intent, registries=registries, environment=environment, inventory=inventory,
        costs=costs, freshness=freshness, now_utc_ns=now_utc_ns,
        created_utc_ns=now_utc_ns, change_ticket=change_ticket,
        artifact_digest=artifact_digest, freeze_window=freeze_window,
    )
    plan_hash = _hash(payload)
    payload["plan_hash"] = plan_hash
    payload["idempotency_key"] = _hash({"plan_hash": plan_hash, "environment": environment})
    return _PLAN_ISSUER.issue(ApplyPlanV1(**payload))


def evaluate_apply(
    plan: ApplyPlanV1, *, intent: object,
    registries: ResourceIntentRegistries | None, inventory: InventorySnapshotV1,
    costs: tuple[CostEvidenceV1, ...], approvals: tuple[ApprovalEvidenceV1, ...],
    freshness: FreshnessPolicyV1 | None, now_utc_ns: int, idempotency_key: str,
    freeze_window: bool = False, fake_receipt: FakeApplyReceiptV1 | None = None,
    previous_result: ApplyResultV1 | None = None,
) -> ApplyResultV1:
    """Evaluate fake approval/inventory evidence; never call a cloud provider."""
    try:
        require(plan, _PLAN_ISSUER.tag)
    except SealError:
        _reject("PLAN_UNTRUSTED")
    policy = _freshness(freshness)
    _age(now_utc_ns, plan.created_utc_ns, policy.max_plan_age_ns, "PLAN_STALE")
    _inventory(inventory, project=plan.project, environment=plan.environment,
               now_utc_ns=now_utc_ns, freshness=policy)
    if inventory.captured_utc_ns < plan.created_utc_ns:
        _reject("INVENTORY_BEFORE_PLAN")
    if inventory.inventory_digest != plan.inventory_digest:
        _reject("INVENTORY_DRIFT")
    payload = _plan_payload(
        intent, registries=registries, environment=plan.environment,
        inventory=inventory, costs=costs, freshness=policy, now_utc_ns=now_utc_ns,
        created_utc_ns=plan.created_utc_ns, change_ticket=plan.change_ticket,
        artifact_digest=plan.artifact_digest, freeze_window=freeze_window,
    )
    payload["inventory_captured_utc_ns"] = plan.inventory_captured_utc_ns
    if _hash(payload) != plan.plan_hash:
        _reject("PLAN_OR_INVENTORY_CHANGED")
    if idempotency_key != plan.idempotency_key or idempotency_key != _hash(
        {"plan_hash": plan.plan_hash, "environment": plan.environment}
    ):
        _reject("IDEMPOTENCY_KEY_MISMATCH")
    if type(approvals) is not tuple:
        _reject("APPROVAL_MISSING")
    by_role: dict[str, ApprovalEvidenceV1] = {}
    actor_ids: set[str] = set()
    for approval in approvals:
        if type(approval) is not ApprovalEvidenceV1:
            _reject("APPROVAL_INVALID")
        if (
            approval.plan_hash != plan.plan_hash
            or approval.environment != plan.environment
            or approval.change_ticket != plan.change_ticket
            or approval.artifact_digest != plan.artifact_digest
            or not _safe_id(approval.actor_id)
            or approval.actor_id in actor_ids or approval.role in by_role
            or approval.principal_kind != "human"
        ):
            _reject("APPROVAL_INVALID")
        _age(now_utc_ns, approval.approved_utc_ns, policy.max_approval_age_ns,
             "APPROVAL_STALE")
        if approval.approved_utc_ns < plan.created_utc_ns:
            _reject("APPROVAL_BEFORE_PLAN")
        by_role[approval.role] = approval
        actor_ids.add(approval.actor_id)
    if not set(plan.required_roles) <= set(by_role):
        _reject("APPROVAL_MISSING")
    if plan.environment == "live" and len(actor_ids) < 2:
        _reject("LIVE_TWO_PERSON_REQUIRED")
    if previous_result is not None:
        try:
            require(previous_result, _RESULT_ISSUER.tag)
        except SealError:
            _reject("RESULT_UNTRUSTED")
        if (
            previous_result.plan_hash != plan.plan_hash
            or previous_result.environment != plan.environment
            or previous_result.idempotency_key != idempotency_key
        ):
            _reject("IDEMPOTENCY_KEY_CONFLICT")
        return previous_result
    status: Literal["ELIGIBLE", "UNKNOWN"] = "ELIGIBLE"
    ids: tuple[str, ...] = ()
    if fake_receipt is not None:
        if type(fake_receipt) is not FakeApplyReceiptV1:
            _reject("FAKE_RECEIPT_INVALID")
        if (
            fake_receipt.observed_utc_ns < plan.created_utc_ns
            or fake_receipt.observed_utc_ns > now_utc_ns
            or any(not _safe_id(value) for value in fake_receipt.provider_ids)
        ):
            _reject("FAKE_RECEIPT_INVALID")
        status = "UNKNOWN"
        ids = fake_receipt.provider_ids
    result = ApplyResultV1(
        project=plan.project, environment=plan.environment, plan_hash=plan.plan_hash,
        inventory_digest=plan.inventory_digest,
        inventory_captured_utc_ns=inventory.captured_utc_ns,
        idempotency_key=plan.idempotency_key, status=status, event_utc_ns=now_utc_ns,
        actor_ids=tuple(sorted(actor_ids)), artifact_digest=plan.artifact_digest,
        provider_ids=ids, r2_hold_ids=plan.r2_hold_ids,
    )
    return _RESULT_ISSUER.issue(result)


def build_rollback_plan(
    result: ApplyResultV1, *, inventory: InventorySnapshotV1,
    freshness: FreshnessPolicyV1 | None, now_utc_ns: int,
    known_good_revision: str, known_good_artifact_digest: str,
) -> RollbackPlanV1:
    """Issue a review-only rollback proposal against a fresh fake inventory."""
    try:
        require(result, _RESULT_ISSUER.tag)
    except SealError:
        _reject("RESULT_UNTRUSTED")
    _now_date(now_utc_ns)
    policy = _freshness(freshness)
    existing = _inventory(inventory, project=result.project,
                          environment=result.environment, now_utc_ns=now_utc_ns,
                          freshness=policy)
    if inventory.captured_utc_ns <= result.event_utc_ns:
        _reject("ROLLBACK_INVENTORY_NOT_FRESH")
    if not _safe_id(known_good_revision) or not _hex(known_good_artifact_digest):
        _reject("KNOWN_GOOD_INVALID")
    retained = {resource.provider_resource_id for resource in existing.values()
                if resource.kind == "r2" and resource.legal_hold}
    if not set(result.r2_hold_ids) <= retained:
        _reject("R2_LEGAL_HOLD_MISSING")
    diff = tuple(f"PRESERVE r2 resource#{_hash(item)[:12]}" for item in sorted(retained))
    payload: dict[str, Any] = {
        "project": result.project, "environment": result.environment,
        "source_plan_hash": result.plan_hash,
        "inventory_digest": inventory.inventory_digest,
        "inventory_captured_utc_ns": inventory.captured_utc_ns,
        "known_good_revision": known_good_revision,
        "known_good_artifact_digest": known_good_artifact_digest,
        "created_utc_ns": now_utc_ns,
        "required_roles": ("Reviewer", "Release Manager") if result.environment == "live"
        else ("Reviewer",),
        "preserved_r2_holds": tuple(sorted(retained)), "redacted_diff": diff,
    }
    payload["plan_hash"] = _hash(payload)
    return _ROLLBACK_ISSUER.issue(RollbackPlanV1(**payload))
