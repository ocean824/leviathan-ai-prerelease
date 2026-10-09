"""Versioned, nonsecret records for the offline reviewed apply gate."""

from __future__ import annotations

from datetime import date
from decimal import Decimal
from typing import Literal

from pydantic import Field

from leviathan_core.seal import SealedModel

Environment = Literal["development", "staging", "live"]
Provider = Literal["neon", "cloudflare"]
ResourceKind = Literal["database", "worker", "queue", "r2"]


class GateError(Exception):
    """Content-free policy failure; only a stable code may be displayed."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class InventoryResourceV1(SealedModel):
    provider: Provider
    kind: ResourceKind
    name: str
    provider_resource_id: str
    owner: str
    spec_digest: str
    retention_days: int | None = None
    legal_hold: bool = False


class InventorySnapshotV1(SealedModel):
    version: Literal[1] = 1
    project: str
    environment: Environment
    captured_utc_ns: int
    resources: tuple[InventoryResourceV1, ...]
    inventory_digest: str


class CostEvidenceV1(SealedModel):
    provider: Provider
    kind: ResourceKind
    name: str
    currency: str
    monthly_estimate: Decimal
    monthly_cap: Decimal
    price_source: str
    retrieved_on: date


class FreshnessPolicyV1(SealedModel):
    max_inventory_age_ns: int = Field(gt=0)
    max_price_age_days: int = Field(gt=0)
    max_approval_age_ns: int = Field(gt=0)
    max_plan_age_ns: int = Field(gt=0)


class ApprovalEvidenceV1(SealedModel):
    version: Literal[1] = 1
    plan_hash: str
    environment: Environment
    actor_id: str
    role: Literal["Reviewer", "Release Manager"]
    approved_utc_ns: int
    change_ticket: str
    artifact_digest: str
    principal_kind: Literal["human"] = "human"


class FakeApplyReceiptV1(SealedModel):
    """Synthetic provider-port observation; never an authorization or success proof."""

    outcome: Literal["partial", "uncertain", "failed", "reported_success"]
    observed_utc_ns: int
    provider_ids: tuple[str, ...] = ()


class ApplyPlanV1(SealedModel):
    version: Literal[1] = 1
    project: str
    environment: Environment
    intent_hash: str
    inventory_digest: str
    inventory_captured_utc_ns: int
    cost_digest: str
    created_utc_ns: int
    plan_hash: str
    idempotency_key: str
    change_ticket: str
    artifact_digest: str
    required_roles: tuple[str, ...]
    provider_resource_ids: tuple[str, ...]
    r2_hold_ids: tuple[str, ...]
    monthly_estimate: Decimal
    monthly_cap: Decimal
    currency: str
    price_sources: tuple[str, ...]
    price_evidence: tuple[tuple[str, str], ...]
    redacted_diff: tuple[str, ...]


class ApplyResultV1(SealedModel):
    version: Literal[1] = 1
    project: str
    environment: Environment
    plan_hash: str
    inventory_digest: str
    inventory_captured_utc_ns: int
    idempotency_key: str
    status: Literal["ELIGIBLE", "UNKNOWN"]
    event_utc_ns: int
    actor_ids: tuple[str, ...]
    artifact_digest: str
    provider_ids: tuple[str, ...]
    r2_hold_ids: tuple[str, ...]


class RollbackPlanV1(SealedModel):
    version: Literal[1] = 1
    project: str
    environment: Environment
    source_plan_hash: str
    inventory_digest: str
    inventory_captured_utc_ns: int
    known_good_revision: str
    known_good_artifact_digest: str
    created_utc_ns: int
    plan_hash: str
    required_roles: tuple[str, ...]
    preserved_r2_holds: tuple[str, ...]
    redacted_diff: tuple[str, ...]
    status: Literal["PENDING_REVIEW"] = "PENDING_REVIEW"
