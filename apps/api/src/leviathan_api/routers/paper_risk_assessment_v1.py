"""Injection-only, read-only PAPER risk-limit preview endpoint."""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from decimal import Decimal
from typing import Final, Literal, Protocol

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from leviathan_core.risk_limits.kernel import assess_limits
from leviathan_core.risk_limits.models import (
    ProjectedOrderV1,
    RiskStateV1,
    VerifiedHardLimitsV1,
)
from leviathan_core.security.authz_models import (
    AuthorizationModelError,
    TrustedPrincipalV1,
    require_trusted_principal,
)

_ROUTER_PREFIX: Final = "/paper/risk/assessment/v1"
_PRINCIPAL_REQUIRED: Final = "PRINCIPAL_REQUIRED"
_PAPER_SCOPE_REQUIRED: Final = "PAPER_SCOPE_REQUIRED"
_INVALID_REQUEST: Final = "INVALID_REQUEST"
_ASSESSMENT_UNAVAILABLE: Final = "ASSESSMENT_UNAVAILABLE"
_DECIMAL_TEXT: Final = re.compile(r"(?:0|[1-9][0-9]*)(?:\.[0-9]+)?\Z", re.ASCII)
_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_REASON_CODES: Final = frozenset(
    {
        "within_hard_limits",
        "as_of_invalid",
        "policy_unverified",
        "policy_tampered",
        "order_invalid",
        "state_missing",
        "PRECISION_EXCEEDED",
        "account_mismatch",
        "environment_mismatch",
        "account_inactive",
        "state_invalid",
        "policy_missing",
        "policy_invalid",
        "policy_ambiguous",
        "policy_stale",
        "scope_not_allowed",
        "instrument_not_allowed",
        "state_stale",
        "price_stale",
        "state_incomplete",
        "state_oversized",
        "fx_ambiguous",
        "rate_state_invalid",
        "rate_counter_stale",
        "rate_ambiguous",
        "fx_missing",
        "fx_invalid",
        "fx_stale",
        "currency_mismatch",
        "price_invalid",
        "state_ambiguous",
        "state_inconsistent",
        "order_duplicate",
        "buying_power_exceeded",
        "max_order_quantity_exceeded",
        "max_order_notional_exceeded",
        "max_projected_position_exceeded",
        "max_gross_exposure_exceeded",
        "max_net_exposure_exceeded",
        "max_leverage_exceeded",
        "max_daily_loss_exceeded",
        "rate_state_missing",
        "order_rate_exceeded",
        "input_invalid",
    }
)
_MAX_REASON_CODES: Final = 16
_MAX_REASON_LENGTH: Final = 32
_MAX_POLICY_REVISIONS: Final = 32
_MAX_POLICY_REVISION_LENGTH: Final = 128


class PaperRiskAssessmentRequestV1(BaseModel):
    """Strict preview request. Environment is fixed to PAPER by the route."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    scope: Literal["paper"]
    account_id: str
    request_id: str
    attempt_id: str
    strategy_id: str
    venue_id: str
    instrument_id: str
    side: Literal["BUY", "SELL"]
    quantity: str = Field(pattern=r"^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$")
    price: str = Field(pattern=r"^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$")
    contract_multiplier: str = Field(pattern=r"^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$")
    currency: str
    price_source_ns: int
    price_ingest_ns: int
    price_source_id: str


@dataclass(frozen=True, slots=True)
class PaperRiskAssessmentInputsV1:
    """Read-only risk inputs resolved for the authenticated PAPER principal."""

    policies: VerifiedHardLimitsV1 | None
    state: RiskStateV1 | None


class PaperRiskAssessmentReadPort(Protocol):
    """Injected read-only boundary; implementations must not mutate or submit orders."""

    def read_inputs(
        self,
        *,
        principal: TrustedPrincipalV1,
        order: ProjectedOrderV1,
        as_of_ns: int,
    ) -> PaperRiskAssessmentInputsV1 | None: ...


def _error(status_code: int, code: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"detail": code},
        headers={"Cache-Control": "no-store"},
    )


def _order_from_request(body: PaperRiskAssessmentRequestV1) -> ProjectedOrderV1:
    decimal_values: dict[str, Decimal] = {}
    for field_name in ("quantity", "price", "contract_multiplier"):
        raw_value = getattr(body, field_name)
        if _DECIMAL_TEXT.fullmatch(raw_value) is None:
            raise ValueError(_INVALID_REQUEST)
        decimal_values[field_name] = Decimal(raw_value)
    return ProjectedOrderV1(
        environment="paper",
        account_id=body.account_id,
        request_id=body.request_id,
        attempt_id=body.attempt_id,
        strategy_id=body.strategy_id,
        venue_id=body.venue_id,
        instrument_id=body.instrument_id,
        side=body.side,
        quantity=decimal_values["quantity"],
        price=decimal_values["price"],
        contract_multiplier=decimal_values["contract_multiplier"],
        currency=body.currency,
        price_source_ns=body.price_source_ns,
        price_ingest_ns=body.price_ingest_ns,
        price_source_id=body.price_source_id,
    )


def _principal_for_request(request: Request) -> TrustedPrincipalV1 | None:
    try:
        principal = require_trusted_principal(getattr(request.state, "trusted_principal", None))
    except AuthorizationModelError:
        return None
    return principal


def build_paper_risk_assessment_router(
    read_port: PaperRiskAssessmentReadPort,
    *,
    clock_ns: Callable[[], int] = time.time_ns,
) -> APIRouter:
    """Build a router from injected dependencies; mounting remains coordinator-owned."""

    if not callable(getattr(read_port, "read_inputs", None)) or not callable(clock_ns):
        raise ValueError("INVALID_CONFIGURATION")

    router = APIRouter(prefix=_ROUTER_PREFIX, tags=["paper-risk-assessment"])

    @router.post("/preview", response_model=None)
    async def preview(request: Request) -> JSONResponse:
        principal = _principal_for_request(request)
        if principal is None:
            return _error(401, _PRINCIPAL_REQUIRED)
        try:
            raw_body = await request.json()
        except Exception:
            return _error(422, _INVALID_REQUEST)
        if not isinstance(raw_body, dict):
            return _error(422, _INVALID_REQUEST)
        if raw_body.get("scope") != "paper":
            return _error(403, _PAPER_SCOPE_REQUIRED)
        if principal.env != "paper" or "operator" not in principal.roles:
            return _error(403, _PAPER_SCOPE_REQUIRED)
        try:
            body = PaperRiskAssessmentRequestV1.model_validate(raw_body)
            order = _order_from_request(body)
        except (ValidationError, TypeError, ValueError):
            return _error(422, _INVALID_REQUEST)
        if (principal.venue is not None and principal.venue != order.venue_id) or (
            principal.strategy is not None and principal.strategy != order.strategy_id
        ):
            return _error(403, _PAPER_SCOPE_REQUIRED)
        try:
            as_of_ns = clock_ns()
            if type(as_of_ns) is not int or as_of_ns < 0:
                return _error(503, _ASSESSMENT_UNAVAILABLE)
            inputs = read_port.read_inputs(
                principal=principal,
                order=order,
                as_of_ns=as_of_ns,
            )
            if (
                type(inputs) is not PaperRiskAssessmentInputsV1
                or type(inputs.policies) is not VerifiedHardLimitsV1
                or type(inputs.state) is not RiskStateV1
            ):
                return _error(503, _ASSESSMENT_UNAVAILABLE)
            policy_digest = inputs.policies.verification.policy_digest
            if type(policy_digest) is not str or _SHA256.fullmatch(policy_digest) is None:
                return _error(503, _ASSESSMENT_UNAVAILABLE)
            assessment = assess_limits(order, inputs.policies, inputs.state, as_of_ns)
            if (
                type(assessment.decision) is not str
                or assessment.decision not in ("ALLOW", "DENY")
                or type(assessment.reason_codes) is not tuple
                or not assessment.reason_codes
                or len(assessment.reason_codes) > _MAX_REASON_CODES
                or any(
                    type(code) is not str
                    or code not in _REASON_CODES
                    or len(code) > _MAX_REASON_LENGTH
                    for code in assessment.reason_codes
                )
                or type(assessment.matched_policy_revisions) is not tuple
                or len(assessment.matched_policy_revisions) > _MAX_POLICY_REVISIONS
                or any(
                    type(revision) is not str
                    or not revision.isascii()
                    or not 1 <= len(revision) <= _MAX_POLICY_REVISION_LENGTH
                    for revision in assessment.matched_policy_revisions
                )
                or type(assessment.evidence_digest) is not str
                or _SHA256.fullmatch(assessment.evidence_digest) is None
            ):
                return _error(503, _ASSESSMENT_UNAVAILABLE)
        except Exception:
            return _error(503, _ASSESSMENT_UNAVAILABLE)
        return JSONResponse(
            status_code=200,
            content={
                "scope": "paper",
                "assessment_kind": "preview",
                "decision": assessment.decision,
                "assessment_time_ns": as_of_ns,
                "policy_version": 1,
                "policy_revisions": list(assessment.matched_policy_revisions),
                "policy_digest": policy_digest,
                "reason_codes": list(assessment.reason_codes),
                "evidence_digest": assessment.evidence_digest,
                "approval_issued": False,
                "order_submitted": False,
            },
            headers={"Cache-Control": "no-store"},
        )

    return router


__all__ = [
    "PaperRiskAssessmentInputsV1",
    "PaperRiskAssessmentReadPort",
    "PaperRiskAssessmentRequestV1",
    "build_paper_risk_assessment_router",
]
