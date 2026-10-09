"""Authenticated, evidence-bound operator resolution for venue conflicts.

This module contains request and result contracts only. The actor owns the
broker read and delegates durable evidence/clear operations to the ledger.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, NoReturn, SupportsIndex

from pydantic import model_validator

from leviathan_core.seal import Issuer, SealedModel, require
from leviathan_core.security.principal_verifier import VerifiedPrincipalV1

_ISSUER = Issuer("oms.venue_conflict_resolution.v1")
_PRINCIPAL_TAG = "sec003.verified_principal.v1"
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}\Z", re.ASCII)
_DIGEST = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_IDEMPOTENCY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z", re.ASCII)


class VenueConflictResolutionCode(StrEnum):
    INVALID_REQUEST = "INVALID_RESOLUTION_REQUEST"
    OPERATOR_REQUIRED = "OPERATOR_AUTH_REQUIRED"
    CONFIRMATION_REQUIRED = "HUMAN_CONFIRMATION_REQUIRED"
    CONFLICT_NOT_FOUND = "VENUE_CONFLICT_NOT_FOUND"
    LEGACY_CONFLICT_UNWAIVABLE = "LEGACY_CONFLICT_UNWAIVABLE"
    STALE_REVISION = "STALE_LEDGER_REVISION"
    STALE_CONFLICT = "STALE_VENUE_CONFLICT"
    BROKER_EVIDENCE_UNAVAILABLE = "BROKER_EVIDENCE_UNAVAILABLE"
    BROKER_EVIDENCE_INCOMPLETE = "BROKER_EVIDENCE_INCOMPLETE"
    BROKER_EVIDENCE_MISMATCH = "BROKER_EVIDENCE_MISMATCH"
    UNRESOLVED_EVIDENCE = "UNRESOLVED_EVIDENCE"
    RESOLUTION_ALREADY_USED = "RESOLUTION_IDEMPOTENCY_CONFLICT"


class VenueConflictResolutionError(RuntimeError):
    """Closed, input-free failure; caller values are never echoed."""

    def __init__(self, code: VenueConflictResolutionCode) -> None:
        if type(code) is not VenueConflictResolutionCode:
            raise ValueError("INVALID_RESOLUTION_ERROR")
        self.code = code.value
        super().__init__(code.value)


@dataclass(frozen=True, slots=True, weakref_slot=True)
class VenueConflictResolutionRequest:
    """Typed actor request retaining the exact SEC-003 principal instance."""

    environment: str
    account_id: str
    conflict_id: str
    expected_ledger_revision: int
    principal: VerifiedPrincipalV1
    human_confirmed: bool
    reason_code: str
    idempotency_key: str

    def __post_init__(self) -> None:
        allowed_reasons = {
            "BINDING_VERIFIED",
            "BROKER_STATE_RECONCILED",
            "OPERATOR_CORRECTION_CONFIRMED",
        }
        try:
            if (
                type(self.environment) is not str
                or self.environment not in {"paper", "demo", "live"}
                or type(self.account_id) is not str
                or _IDENTIFIER.fullmatch(self.account_id) is None
                or type(self.conflict_id) is not str
                or _DIGEST.fullmatch(self.conflict_id) is None
                or type(self.expected_ledger_revision) is not int
                or not 0 <= self.expected_ledger_revision <= 2**63 - 1
                or type(self.principal) is not VerifiedPrincipalV1
                or type(self.human_confirmed) is not bool
                or type(self.reason_code) is not str
                or self.reason_code not in allowed_reasons
                or type(self.idempotency_key) is not str
                or _IDEMPOTENCY.fullmatch(self.idempotency_key) is None
            ):
                raise ValueError()
            require(self.principal, _PRINCIPAL_TAG)
            if (
                self.principal.role != "operator"
                or "oms:venue-conflict:resolve" not in self.principal.scopes
            ):
                raise ValueError()
        except Exception:
            raise VenueConflictResolutionError(
                VenueConflictResolutionCode.INVALID_REQUEST
            ) from None

    def __copy__(self) -> NoReturn:
        raise VenueConflictResolutionError(VenueConflictResolutionCode.INVALID_REQUEST)

    def __deepcopy__(self, _memo: object) -> NoReturn:
        raise VenueConflictResolutionError(VenueConflictResolutionCode.INVALID_REQUEST)

    def __reduce_ex__(self, _protocol: SupportsIndex) -> NoReturn:
        raise VenueConflictResolutionError(VenueConflictResolutionCode.INVALID_REQUEST)


class VenueConflictReview(SealedModel):
    environment: str
    account_id: str
    conflict_id: str
    ledger_revision: int
    affected_order_ids: tuple[str, ...]
    binding_venue: str
    binding_environment: str
    observation_ids: tuple[str, ...]
    identity_digest: str

    @model_validator(mode="after")
    def _valid_review(self) -> VenueConflictReview:
        if (
            self.environment not in {"paper", "demo", "live"}
            or _IDENTIFIER.fullmatch(self.account_id) is None
            or _DIGEST.fullmatch(self.conflict_id) is None
            or type(self.ledger_revision) is not int
            or not 0 <= self.ledger_revision <= 2**63 - 1
            or type(self.affected_order_ids) is not tuple
            or not self.affected_order_ids
            or any(_IDENTIFIER.fullmatch(item) is None for item in self.affected_order_ids)
            or self.affected_order_ids != tuple(sorted(set(self.affected_order_ids)))
            or _IDENTIFIER.fullmatch(self.binding_venue) is None
            or self.binding_environment not in {"paper", "demo", "live"}
            or type(self.observation_ids) is not tuple
            or not self.observation_ids
            or any(_IDENTIFIER.fullmatch(item) is None for item in self.observation_ids)
            or self.observation_ids != tuple(sorted(set(self.observation_ids)))
            or _DIGEST.fullmatch(self.identity_digest) is None
        ):
            raise ValueError("INVALID_RESOLUTION_REVIEW")
        return self


class VenueConflictResolutionResult(SealedModel):
    resolution_id: str
    environment: str
    account_id: str
    conflict_id: str
    operator_principal_id: str
    broker_revision: int
    broker_evidence_digest: str
    prior_ledger_revision: int
    resolved_ledger_revision: int
    affected_order_ids: tuple[str, ...]
    resolved_at_ns: int

    @model_validator(mode="after")
    def _valid_result(self) -> VenueConflictResolutionResult:
        if (
            _DIGEST.fullmatch(self.resolution_id) is None
            or self.environment not in {"paper", "demo", "live"}
            or _IDENTIFIER.fullmatch(self.account_id) is None
            or _DIGEST.fullmatch(self.conflict_id) is None
            or _IDENTIFIER.fullmatch(self.operator_principal_id) is None
            or type(self.broker_revision) is not int
            or not 0 <= self.broker_revision <= 2**63 - 1
            or _DIGEST.fullmatch(self.broker_evidence_digest) is None
            or type(self.prior_ledger_revision) is not int
            or type(self.resolved_ledger_revision) is not int
            or self.resolved_ledger_revision < self.prior_ledger_revision
            or type(self.affected_order_ids) is not tuple
            or any(_IDENTIFIER.fullmatch(item) is None for item in self.affected_order_ids)
            or type(self.resolved_at_ns) is not int
            or self.resolved_at_ns < 0
        ):
            raise ValueError("INVALID_RESOLUTION_RESULT")
        return self


def issue_venue_conflict_resolution_request(
    *,
    environment: str,
    account_id: str,
    conflict_id: str,
    expected_ledger_revision: int,
    principal: VerifiedPrincipalV1,
    human_confirmed: bool,
    reason_code: str,
    idempotency_key: str,
) -> VenueConflictResolutionRequest:
    """Validate and seal one explicit authenticated operator command."""
    try:
        request = VenueConflictResolutionRequest(
            environment=environment,
            account_id=account_id,
            conflict_id=conflict_id,
            expected_ledger_revision=expected_ledger_revision,
            principal=principal,
            human_confirmed=human_confirmed,
            reason_code=reason_code,
            idempotency_key=idempotency_key,
        )
        return _ISSUER.issue(request)
    except Exception:
        raise VenueConflictResolutionError(
            VenueConflictResolutionCode.INVALID_REQUEST
        ) from None


def require_venue_conflict_resolution_request(
    request: VenueConflictResolutionRequest,
) -> VenueConflictResolutionRequest:
    if type(request) is not VenueConflictResolutionRequest:
        raise VenueConflictResolutionError(VenueConflictResolutionCode.INVALID_REQUEST)
    try:
        require(request, _ISSUER.tag)
        require(request.principal, _PRINCIPAL_TAG)
    except Exception:
        raise VenueConflictResolutionError(
            VenueConflictResolutionCode.INVALID_REQUEST
        ) from None
    return request


def issue_venue_conflict_review(
    *,
    environment: str,
    account_id: str,
    conflict_id: str,
    ledger_revision: int,
    affected_order_ids: tuple[str, ...],
    binding_venue: str,
    binding_environment: str,
    observation_ids: tuple[str, ...],
    identity_digest: str,
) -> VenueConflictReview:
    return _ISSUER.issue(VenueConflictReview(
        environment=environment,
        account_id=account_id,
        conflict_id=conflict_id,
        ledger_revision=ledger_revision,
        affected_order_ids=affected_order_ids,
        binding_venue=binding_venue,
        binding_environment=binding_environment,
        observation_ids=observation_ids,
        identity_digest=identity_digest,
    ))


def issue_venue_conflict_resolution_result(**values: Any) -> VenueConflictResolutionResult:
    try:
        return _ISSUER.issue(VenueConflictResolutionResult(**values))
    except Exception:
        raise VenueConflictResolutionError(
            VenueConflictResolutionCode.INVALID_REQUEST
        ) from None
