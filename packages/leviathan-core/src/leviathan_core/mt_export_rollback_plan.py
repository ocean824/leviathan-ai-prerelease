"""Offline validation for a non-executable MT export rollback proposal."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import ClassVar, Literal, NoReturn, SupportsIndex, TypeVar, cast

from leviathan_core.mt_export_bridge_artifacts import DeploymentModeV1, MtPlatformV1
from leviathan_core.seal import Issuer, SealError, require

_TARGET_TAG = "mtbr.rollback_target.v1"
_ARTIFACT_TAG = "mtbr.rollback_artifact.v1"
_PROPOSAL_TAG = "mtbr.rollback_proposal.v1"
_PLAN_TAG = "mtbr.rollback_plan.v1"
_TARGET_ISSUER = Issuer(_TARGET_TAG)
_ARTIFACT_ISSUER = Issuer(_ARTIFACT_TAG)
_PROPOSAL_ISSUER = Issuer(_PROPOSAL_TAG)
_PLAN_ISSUER = Issuer(_PLAN_TAG)
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z", re.ASCII)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_INT64_MAX = (1 << 63) - 1


class RollbackPlanError(ValueError):
    """Content-free rollback proposal validation failure."""

    _CODES = frozenset(
        {
            "INVALID_INPUT",
            "PROVENANCE_INVALID",
            "PRIOR_NOT_EARLIER",
            "ARTIFACT_NOT_DISTINCT",
            "TARGET_MISMATCH",
            "PLATFORM_MISMATCH",
        }
    )

    def __init__(self, code: str) -> None:
        self.code = code if type(code) is str and code in self._CODES else "INVALID_INPUT"
        super().__init__(self.code)


class RollbackPlanStatusV1(StrEnum):
    READY = "READY"
    BLOCKED = "BLOCKED"


class _SealedRecord:
    """Shared SEAL assertion exposed on frozen records for callers."""

    __slots__ = ()
    _seal_tag: ClassVar[str]

    def assert_sealed(self) -> None:
        try:
            require(self, self._seal_tag)
        except SealError:
            raise RollbackPlanError("PROVENANCE_INVALID") from None

    def __copy__(self) -> NoReturn:
        raise SealError("SEAL_FORBIDDEN_OPERATION")

    def __deepcopy__(self, _memo: dict[int, object] | None = None) -> NoReturn:
        raise SealError("SEAL_FORBIDDEN_OPERATION")

    def __reduce__(self) -> NoReturn:
        raise SealError("SEAL_FORBIDDEN_OPERATION")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> NoReturn:
        raise SealError("SEAL_FORBIDDEN_OPERATION")

    def __getstate__(self) -> NoReturn:
        raise SealError("SEAL_FORBIDDEN_OPERATION")


_Record = TypeVar("_Record", bound=_SealedRecord)


def _guard_reinitialization(
    seal_tag: str,
) -> Callable[[type[_Record]], type[_Record]]:
    """Reject initialization of an issued identity before dataclass writes fields."""

    def decorate(record_type: type[_Record]) -> type[_Record]:
        original_init = cast(Callable[..., None], record_type.__init__)

        def guarded_init(self: object, *args: object, **kwargs: object) -> None:
            try:
                require(self, seal_tag)
            except SealError as exc:
                if exc.code != "SEAL_NOT_ISSUED":
                    raise
            else:
                raise SealError("SEAL_FORBIDDEN_OPERATION")
            original_init(self, *args, **kwargs)

        type.__setattr__(record_type, "__init__", guarded_init)
        return record_type

    return decorate


def _identifier(value: object) -> bool:
    return type(value) is str and _IDENTIFIER.fullmatch(value) is not None


def _sha256(value: object) -> bool:
    return type(value) is str and _SHA256.fullmatch(value) is not None


@_guard_reinitialization(_TARGET_TAG)
@dataclass(frozen=True, slots=True, weakref_slot=True)
class RollbackTargetV1(_SealedRecord):
    """Declared terminal target and account mode; contains no connection data."""

    _seal_tag: ClassVar[str] = _TARGET_TAG
    target_id: str
    platform: MtPlatformV1
    mode: DeploymentModeV1

    def __post_init__(self) -> None:
        if (
            not _identifier(self.target_id)
            or type(self.platform) is not MtPlatformV1
            or type(self.mode) is not DeploymentModeV1
        ):
            raise RollbackPlanError("INVALID_INPUT")


@_guard_reinitialization(_ARTIFACT_TAG)
@dataclass(frozen=True, slots=True, weakref_slot=True)
class RollbackArtifactV1(_SealedRecord):
    """Locally supplied artifact facts bound to their declared provenance digest."""

    _seal_tag: ClassVar[str] = _ARTIFACT_TAG
    artifact_id: str
    target_id: str
    platform: MtPlatformV1
    created_at_ns: int
    artifact_sha256: str
    provenance_sha256: str

    def __post_init__(self) -> None:
        if (
            not _identifier(self.artifact_id)
            or not _identifier(self.target_id)
            or type(self.platform) is not MtPlatformV1
            or type(self.created_at_ns) is not int
            or not 0 <= self.created_at_ns <= _INT64_MAX
            or not _sha256(self.artifact_sha256)
            or not _sha256(self.provenance_sha256)
        ):
            raise RollbackPlanError("INVALID_INPUT")


@_guard_reinitialization(_PROPOSAL_TAG)
@dataclass(frozen=True, slots=True, weakref_slot=True)
class RollbackProposalV1(_SealedRecord):
    """Offline input facts for validating one rollback proposal."""

    _seal_tag: ClassVar[str] = _PROPOSAL_TAG
    target: RollbackTargetV1
    current_artifact: RollbackArtifactV1
    prior_artifact: RollbackArtifactV1 | None
    forward_deployment_id: str

    def __post_init__(self) -> None:
        if (
            type(self.target) is not RollbackTargetV1
            or type(self.current_artifact) is not RollbackArtifactV1
            or (
                self.prior_artifact is not None
                and type(self.prior_artifact) is not RollbackArtifactV1
            )
            or not _identifier(self.forward_deployment_id)
        ):
            raise RollbackPlanError("INVALID_INPUT")


@_guard_reinitialization(_PLAN_TAG)
@dataclass(frozen=True, slots=True, weakref_slot=True)
class RollbackPlanV1(_SealedRecord):
    """Sealed plan data. It intentionally carries no action or execution handle."""

    _seal_tag: ClassVar[str] = _PLAN_TAG
    status: RollbackPlanStatusV1
    target_id: str
    platform: MtPlatformV1
    mode: DeploymentModeV1
    current_artifact_id: str
    prior_artifact_id: str | None
    forward_deployment_id: str
    block_code: Literal["NO_PRIOR_ARTIFACT", "LIVE_OPERATOR_SWITCH"] | None
    executable: Literal[False] = False

    def __post_init__(self) -> None:
        if (
            type(self.status) is not RollbackPlanStatusV1
            or not _identifier(self.target_id)
            or type(self.platform) is not MtPlatformV1
            or type(self.mode) is not DeploymentModeV1
            or not _identifier(self.current_artifact_id)
            or (self.prior_artifact_id is not None and not _identifier(self.prior_artifact_id))
            or not _identifier(self.forward_deployment_id)
            or self.block_code not in {None, "NO_PRIOR_ARTIFACT", "LIVE_OPERATOR_SWITCH"}
            or self.executable is not False
        ):
            raise RollbackPlanError("INVALID_INPUT")
        if self.status is RollbackPlanStatusV1.READY and (
            self.prior_artifact_id is None or self.block_code is not None
        ):
            raise RollbackPlanError("INVALID_INPUT")
        if self.status is RollbackPlanStatusV1.BLOCKED and self.block_code is None:
            raise RollbackPlanError("INVALID_INPUT")


def _issue_rollback_target(
    *, target_id: str, platform: MtPlatformV1, mode: DeploymentModeV1
) -> RollbackTargetV1:
    try:
        return _TARGET_ISSUER.issue(RollbackTargetV1(target_id, platform, mode))
    except RollbackPlanError:
        raise
    except Exception:
        raise RollbackPlanError("INVALID_INPUT") from None


def _issue_rollback_artifact(
    *,
    artifact_id: str,
    target_id: str,
    platform: MtPlatformV1,
    created_at_ns: int,
    artifact_sha256: str,
    provenance_sha256: str,
) -> RollbackArtifactV1:
    try:
        value = RollbackArtifactV1(
            artifact_id,
            target_id,
            platform,
            created_at_ns,
            artifact_sha256,
            provenance_sha256,
        )
        return _ARTIFACT_ISSUER.issue(value)
    except RollbackPlanError:
        raise
    except Exception:
        raise RollbackPlanError("INVALID_INPUT") from None


def _issue_rollback_proposal(
    *,
    target: RollbackTargetV1,
    current_artifact: RollbackArtifactV1,
    prior_artifact: RollbackArtifactV1 | None,
    forward_deployment_id: str,
) -> RollbackProposalV1:
    try:
        require(target, _TARGET_TAG)
        require(current_artifact, _ARTIFACT_TAG)
        if prior_artifact is not None:
            require(prior_artifact, _ARTIFACT_TAG)
        proposal = RollbackProposalV1(
            target, current_artifact, prior_artifact, forward_deployment_id
        )
        return _PROPOSAL_ISSUER.issue(proposal)
    except RollbackPlanError:
        raise
    except Exception:
        raise RollbackPlanError("PROVENANCE_INVALID") from None


def _issue_plan(
    *,
    proposal: RollbackProposalV1,
    status: RollbackPlanStatusV1,
    prior_artifact_id: str | None,
    block_code: Literal["NO_PRIOR_ARTIFACT", "LIVE_OPERATOR_SWITCH"] | None,
) -> RollbackPlanV1:
    target = proposal.target
    current = proposal.current_artifact
    plan = RollbackPlanV1(
        status=status,
        target_id=target.target_id,
        platform=target.platform,
        mode=target.mode,
        current_artifact_id=current.artifact_id,
        prior_artifact_id=prior_artifact_id,
        forward_deployment_id=proposal.forward_deployment_id,
        block_code=block_code,
    )
    return _PLAN_ISSUER.issue(plan)


def validate_rollback_proposal(proposal: RollbackProposalV1) -> RollbackPlanV1:
    """Validate only supplied offline facts; never perform a rollback action."""

    if type(proposal) is not RollbackProposalV1:
        raise RollbackPlanError("INVALID_INPUT")
    try:
        require(proposal, _PROPOSAL_TAG)
    except SealError as exc:
        raise RollbackPlanError(
            "PROVENANCE_INVALID" if exc.code == "SEAL_TAMPERED" else "INVALID_INPUT"
        ) from None

    target = proposal.target
    current = proposal.current_artifact
    prior = proposal.prior_artifact
    try:
        require(target, _TARGET_TAG)
        require(current, _ARTIFACT_TAG)
        if prior is not None:
            require(prior, _ARTIFACT_TAG)
    except SealError as exc:
        raise RollbackPlanError(
            "PROVENANCE_INVALID" if exc.code == "SEAL_TAMPERED" else "INVALID_INPUT"
        ) from None

    if target.mode is DeploymentModeV1.LIVE:
        return _issue_plan(
            proposal=proposal,
            status=RollbackPlanStatusV1.BLOCKED,
            prior_artifact_id=None if prior is None else prior.artifact_id,
            block_code="LIVE_OPERATOR_SWITCH",
        )

    if current.target_id != target.target_id:
        raise RollbackPlanError("TARGET_MISMATCH")
    if current.platform is not target.platform:
        raise RollbackPlanError("PLATFORM_MISMATCH")
    if prior is None:
        return _issue_plan(
            proposal=proposal,
            status=RollbackPlanStatusV1.BLOCKED,
            prior_artifact_id=None,
            block_code="NO_PRIOR_ARTIFACT",
        )
    if prior.target_id != target.target_id:
        raise RollbackPlanError("TARGET_MISMATCH")
    if prior.platform is not target.platform:
        raise RollbackPlanError("PLATFORM_MISMATCH")
    if prior.artifact_id == current.artifact_id or prior.artifact_sha256 == current.artifact_sha256:
        raise RollbackPlanError("ARTIFACT_NOT_DISTINCT")
    if prior.created_at_ns >= current.created_at_ns:
        raise RollbackPlanError("PRIOR_NOT_EARLIER")
    return _issue_plan(
        proposal=proposal,
        status=RollbackPlanStatusV1.READY,
        prior_artifact_id=prior.artifact_id,
        block_code=None,
    )


__all__ = [
    "RollbackArtifactV1",
    "RollbackPlanError",
    "RollbackPlanStatusV1",
    "RollbackPlanV1",
    "RollbackProposalV1",
    "RollbackTargetV1",
    "validate_rollback_proposal",
]
