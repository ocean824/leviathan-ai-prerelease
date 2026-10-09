"""Offline, per-target MT deployment preflight plans.

This module emits sealed intent records only. It has no bridge, terminal,
network, storage, deployment, or trading integration.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal

from pydantic import model_validator

from leviathan_core.mt_export_bridge_artifacts import MtPlatformV1
from leviathan_core.seal import Issuer, SealedModel, SealError, require

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII)
_INT64_MAX = (1 << 63) - 1
_MAX_TARGETS = 256
_MAX_CAPABILITIES = 64
_PLAN_TAG = "mtbr.deployment_plan.v1"
_PLAN_ISSUER = Issuer(_PLAN_TAG)
_PLAN_MARKER = object()
_BlockCode = Literal[
    "LIVE_ACCOUNT_OPERATOR_SWITCH_REQUIRED",
    "PLATFORM_MISMATCH",
    "CAPABILITY_MISSING",
    "HEALTH_FAILED",
    "HEALTH_STALE",
    "HEALTH_TIMESTAMP_INVALID",
]
_PlanDecision = Literal["DOWNLOAD_ONLY", "STAGED", "ACTIVATE", "PLAN_BLOCKED"]
_CanaryPartition = Literal["CANARY", "REMAINDER", "BLOCKED"]


class DeploymentPlanError(ValueError):
    """Content-free deployment-plan failure with a closed code set."""

    _CODES = frozenset(
        {
            "INVALID_INPUT",
            "DUPLICATE_TARGET",
            "INVALID_CANARY_PERCENTAGE",
            "PLAN_SEAL_INVALID",
        }
    )

    def __init__(self, code: str) -> None:
        self.code = code if type(code) is str and code in self._CODES else "INVALID_INPUT"
        super().__init__(self.code)


class DeploymentActionV1(StrEnum):
    DOWNLOAD_ONLY = "DOWNLOAD_ONLY"
    STAGED = "STAGED"
    ACTIVATE = "ACTIVATE"


class DeploymentAccountKindV1(StrEnum):
    PAPER = "PAPER"
    DEMO = "DEMO"
    LIVE = "LIVE"


class DeploymentHealthV1(StrEnum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"


@dataclass(frozen=True, slots=True)
class DeploymentArtifactSnapshotV1:
    """Synthetic artifact identity and platform; contains no artifact bytes."""

    artifact_id: str
    platform: MtPlatformV1


@dataclass(frozen=True, slots=True)
class DeploymentTargetSnapshotV1:
    """Synthetic target readiness snapshot with no account credential material."""

    target_id: str
    platform: MtPlatformV1
    account_kind: DeploymentAccountKindV1
    capabilities: tuple[str, ...]
    health: DeploymentHealthV1
    observed_at_ns: int


@dataclass(frozen=True, slots=True)
class DeploymentPlanRequestV1:
    """Pure planner inputs, including explicit evaluation and freshness bounds."""

    artifact: DeploymentArtifactSnapshotV1
    targets: tuple[DeploymentTargetSnapshotV1, ...]
    action: DeploymentActionV1
    required_capabilities: tuple[str, ...]
    now_ns: int
    maximum_health_age_ns: int
    canary_percentage: int


@dataclass(frozen=True, slots=True)
class DeploymentTargetDecisionV1:
    """One immutable target decision covered by the parent plan seal."""

    target_id: str
    decision: _PlanDecision
    block_code: _BlockCode | None
    canary_partition: _CanaryPartition
    operator_switch_required: bool
    execution_permitted: bool

class DeploymentPlanV1(SealedModel):
    """Sealed plan proposal; it cannot authorize or invoke deployment."""

    schema_version: Literal["mtbr.deployment-plan/1"]
    artifact_id: str
    action: DeploymentActionV1
    evaluated_at_ns: int
    target_decisions: tuple[DeploymentTargetDecisionV1, ...]
    canary_target_ids: tuple[str, ...]
    remainder_target_ids: tuple[str, ...]
    blocked_target_ids: tuple[str, ...]
    execution_permitted: bool

    def __init__(self, /, *, _marker: object | None = None, **data: object) -> None:
        if _marker is not _PLAN_MARKER:
            raise DeploymentPlanError("PLAN_SEAL_INVALID")
        super().__init__(**data)

    @model_validator(mode="after")
    def _validate_plan(self) -> DeploymentPlanV1:
        decisions = self.target_decisions
        ids = tuple(item.target_id for item in decisions)
        if (
            self.schema_version != "mtbr.deployment-plan/1"
            or not _identifier(self.artifact_id)
            or type(self.action) is not DeploymentActionV1
            or type(self.evaluated_at_ns) is not int
            or not 0 <= self.evaluated_at_ns <= _INT64_MAX
            or not 1 <= len(decisions) <= _MAX_TARGETS
            or any(type(item) is not DeploymentTargetDecisionV1 for item in decisions)
            or len(set(ids)) != len(ids)
            or self.execution_permitted is not False
            or any(
                not _identifier(item.target_id)
                or item.decision not in {"DOWNLOAD_ONLY", "STAGED", "ACTIVATE", "PLAN_BLOCKED"}
                or (
                    item.block_code
                    not in {
                        None,
                        "LIVE_ACCOUNT_OPERATOR_SWITCH_REQUIRED",
                        "PLATFORM_MISMATCH",
                        "CAPABILITY_MISSING",
                        "HEALTH_FAILED",
                        "HEALTH_STALE",
                        "HEALTH_TIMESTAMP_INVALID",
                    }
                )
                or item.canary_partition not in {"CANARY", "REMAINDER", "BLOCKED"}
                or type(item.operator_switch_required) is not bool
                or type(item.execution_permitted) is not bool
                or item.execution_permitted is not False
                or (item.decision == "PLAN_BLOCKED") != (item.block_code is not None)
                or (item.decision == "PLAN_BLOCKED") != (item.canary_partition == "BLOCKED")
                or (
                    item.operator_switch_required
                    != (item.block_code == "LIVE_ACCOUNT_OPERATOR_SWITCH_REQUIRED")
                )
                for item in decisions
            )
        ):
            raise ValueError("PLAN_SEAL_INVALID")
        canary = tuple(item.target_id for item in decisions if item.canary_partition == "CANARY")
        remainder = tuple(
            item.target_id for item in decisions if item.canary_partition == "REMAINDER"
        )
        blocked = tuple(item.target_id for item in decisions if item.canary_partition == "BLOCKED")
        if (
            self.canary_target_ids != canary
            or self.remainder_target_ids != remainder
            or self.blocked_target_ids != blocked
            or len(set((*canary, *remainder, *blocked))) != len(ids)
        ):
            raise ValueError("PLAN_SEAL_INVALID")
        return self


def _identifier(value: object) -> bool:
    return type(value) is str and _IDENTIFIER.fullmatch(value) is not None


def _valid_timestamp(value: object) -> bool:
    return type(value) is int and 0 <= value <= _INT64_MAX


def _validate_request(request: object) -> DeploymentPlanRequestV1:
    if type(request) is not DeploymentPlanRequestV1:
        raise DeploymentPlanError("INVALID_INPUT")
    if (
        type(request.artifact) is not DeploymentArtifactSnapshotV1
        or not _identifier(request.artifact.artifact_id)
        or type(request.artifact.platform) is not MtPlatformV1
        or type(request.action) is not DeploymentActionV1
        or type(request.targets) is not tuple
        or not 1 <= len(request.targets) <= _MAX_TARGETS
        or type(request.required_capabilities) is not tuple
        or len(request.required_capabilities) > _MAX_CAPABILITIES
        or any(not _identifier(value) for value in request.required_capabilities)
        or len(set(request.required_capabilities)) != len(request.required_capabilities)
        or not _valid_timestamp(request.now_ns)
        or not _valid_timestamp(request.maximum_health_age_ns)
    ):
        raise DeploymentPlanError("INVALID_INPUT")
    if type(request.canary_percentage) is not int or not 0 <= request.canary_percentage <= 100:
        raise DeploymentPlanError("INVALID_CANARY_PERCENTAGE")
    if any(
        type(target) is not DeploymentTargetSnapshotV1
        or not _identifier(target.target_id)
        or type(target.platform) is not MtPlatformV1
        or type(target.account_kind) is not DeploymentAccountKindV1
        or type(target.capabilities) is not tuple
        or len(target.capabilities) > _MAX_CAPABILITIES
        or any(not _identifier(value) for value in target.capabilities)
        or len(set(target.capabilities)) != len(target.capabilities)
        or type(target.health) is not DeploymentHealthV1
        or not _valid_timestamp(target.observed_at_ns)
        for target in request.targets
    ):
        raise DeploymentPlanError("INVALID_INPUT")
    target_ids = tuple(target.target_id for target in request.targets)
    if len(set(target_ids)) != len(target_ids):
        raise DeploymentPlanError("DUPLICATE_TARGET")
    return request


def plan_deployment(request: DeploymentPlanRequestV1) -> DeploymentPlanV1:
    """Create a sealed per-target deployment plan from synthetic evidence only."""

    request = _validate_request(request)
    capability_set = set(request.required_capabilities)
    codes: dict[str, _BlockCode | None] = {}
    for target in request.targets:
        code: _BlockCode | None = None
        if target.account_kind is DeploymentAccountKindV1.LIVE:
            code = "LIVE_ACCOUNT_OPERATOR_SWITCH_REQUIRED"
        elif target.platform is not request.artifact.platform:
            code = "PLATFORM_MISMATCH"
        elif not capability_set.issubset(target.capabilities):
            code = "CAPABILITY_MISSING"
        elif target.observed_at_ns > request.now_ns:
            code = "HEALTH_TIMESTAMP_INVALID"
        elif request.now_ns - target.observed_at_ns > request.maximum_health_age_ns:
            code = "HEALTH_STALE"
        elif target.health is not DeploymentHealthV1.HEALTHY:
            code = "HEALTH_FAILED"
        codes[target.target_id] = code

    eligible_ids = sorted(target_id for target_id, code in codes.items() if code is None)
    if request.canary_percentage == 0:
        canary_count = 0
    else:
        canary_count = (len(eligible_ids) * request.canary_percentage + 99) // 100
    canary_ids = set(eligible_ids[:canary_count])
    decisions: list[DeploymentTargetDecisionV1] = []
    for target in request.targets:
        code = codes[target.target_id]
        if code is None:
            decision: _PlanDecision = request.action.value
            partition: _CanaryPartition = (
                "CANARY" if target.target_id in canary_ids else "REMAINDER"
            )
        else:
            decision = "PLAN_BLOCKED"
            partition = "BLOCKED"
        decisions.append(
            DeploymentTargetDecisionV1(
                target_id=target.target_id,
                decision=decision,
                block_code=code,
                canary_partition=partition,
                operator_switch_required=(
                    code == "LIVE_ACCOUNT_OPERATOR_SWITCH_REQUIRED"
                ),
                execution_permitted=False,
            )
        )
    canary_target_ids = tuple(
        item.target_id for item in decisions if item.canary_partition == "CANARY"
    )
    remainder_target_ids = tuple(
        item.target_id for item in decisions if item.canary_partition == "REMAINDER"
    )
    blocked_target_ids = tuple(
        item.target_id for item in decisions if item.canary_partition == "BLOCKED"
    )
    try:
        result = DeploymentPlanV1(
            _marker=_PLAN_MARKER,
            schema_version="mtbr.deployment-plan/1",
            artifact_id=request.artifact.artifact_id,
            action=request.action,
            evaluated_at_ns=request.now_ns,
            target_decisions=tuple(decisions),
            canary_target_ids=canary_target_ids,
            remainder_target_ids=remainder_target_ids,
            blocked_target_ids=blocked_target_ids,
            execution_permitted=False,
        )
        return _PLAN_ISSUER.issue(result)
    except (SealError, TypeError, ValueError):
        raise DeploymentPlanError("PLAN_SEAL_INVALID") from None


def require_deployment_plan(value: object) -> DeploymentPlanV1:
    """Verify issuance and invariants before a plan is consumed or serialized."""

    if type(value) is not DeploymentPlanV1:
        raise DeploymentPlanError("PLAN_SEAL_INVALID")
    try:
        plan = require(value, _PLAN_TAG)
        if plan.execution_permitted is not False:
            raise ValueError("PLAN_SEAL_INVALID")
        return plan
    except (SealError, TypeError, ValueError):
        raise DeploymentPlanError("PLAN_SEAL_INVALID") from None


__all__ = [
    "DeploymentAccountKindV1",
    "DeploymentActionV1",
    "DeploymentArtifactSnapshotV1",
    "DeploymentHealthV1",
    "DeploymentPlanError",
    "DeploymentPlanRequestV1",
    "DeploymentPlanV1",
    "DeploymentTargetDecisionV1",
    "DeploymentTargetSnapshotV1",
    "plan_deployment",
    "require_deployment_plan",
]
