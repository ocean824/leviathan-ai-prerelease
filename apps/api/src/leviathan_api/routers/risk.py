"""Sovereign risk surface.

Read status, engage a halt, lift a halt. Engaging is open to any
subsystem (petition model); lifting requires the exact named reason.
RBAC arrives with the admin console phase — until then this surface is
local-operator only.
"""

import structlog
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, model_validator

from leviathan_core.agent_council.publication_models import is_safe_display_label
from leviathan_core.risk.halt_reasons import is_known_halt_reason, is_static_halt_reason
from leviathan_core.security.authz_models import require_trusted_principal

router = APIRouter(prefix="/risk", tags=["risk"])
log = structlog.get_logger(__name__)


class HaltRequest(BaseModel):
    reason: str
    note: str | None = None

    @model_validator(mode="before")
    @classmethod
    def discard_non_text_values(cls, value: object) -> object:
        if not isinstance(value, dict):
            return {"reason": ""}
        reason = value.get("reason", "")
        sanitized: dict[str, object] = {"reason": reason if type(reason) is str else ""}
        if "note" in value:
            note = value["note"]
            sanitized["note"] = note if note is None or type(note) is str else ""
        return sanitized


def _validate_halt_request(body: HaltRequest, *, allow_patterns: bool) -> None:
    valid_reason = (
        is_known_halt_reason(body.reason) if allow_patterns else is_static_halt_reason(body.reason)
    )
    if not valid_reason:
        raise HTTPException(status_code=422, detail="INVALID_HALT_REASON")
    if body.note is not None and not is_safe_display_label(body.note):
        raise HTTPException(status_code=422, detail="INVALID_HALT_NOTE")


@router.get("/status")
def risk_status(request: Request) -> dict[str, object]:
    state = request.app.state.leviathan
    return {
        "halted": state.halts.halted,
        "active_halts": list(state.halts.active),
        "fault_code": state.halts.fault_code,
        "operating_mode": state.settings.operating_mode.value,
        "policy": {
            "max_daily_dd_pct": str(state.policy.drawdown.max_daily_pct),
            "max_open_heat_pct": str(state.policy.heat.max_open_pct),
            "max_leverage_x": str(state.policy.leverage.max_gross_notional_x),
            "loss_streak_trigger": state.policy.loss_streak.consecutive_losers,
        },
        "lock_file": state.lock_path.name,
    }


@router.post("/halt")
def engage_halt(request: Request, body: HaltRequest) -> dict[str, object]:
    _validate_halt_request(body, allow_patterns=False)
    state = request.app.state.leviathan
    try:
        state.halts.engage(body.reason)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="INVALID_HALT_REASON") from exc
    return {"halted": True, "active_halts": list(state.halts.active)}


@router.post("/halt/lift")
def lift_halt(request: Request, body: HaltRequest) -> dict[str, object]:
    # The local shell middleware is the only issuer on this path. A caller must
    # have a principal bound to this desktop instance before it can lift HALT.
    try:
        principal = require_trusted_principal(getattr(request.state, "trusted_principal", None))
    except (TypeError, ValueError):
        raise HTTPException(status_code=401, detail="TRUSTED_PRINCIPAL_REQUIRED") from None
    if getattr(request.state, "trusted_instance_principal_id", None) != principal.principal_id:
        raise HTTPException(status_code=401, detail="TRUSTED_PRINCIPAL_REQUIRED")
    features: object = getattr(request.state, "trusted_instance_features", frozenset())
    if type(features) is not frozenset or "live_trading" not in features:
        raise HTTPException(status_code=403, detail="LIVE_TRADING_ENTITLEMENT_REQUIRED")
    state = request.app.state.leviathan
    if body.note is not None and not is_safe_display_label(body.note):
        raise HTTPException(status_code=422, detail="INVALID_HALT_NOTE")
    legacy_reason = False
    try:
        known_reason = is_known_halt_reason(body.reason)
        if not known_reason:
            # Keep the active check and committed lift under the authority lock
            # so inactive legacy strings cannot race into a different response.
            with state.halts.route_interlock():
                legacy_reason = body.reason in state.halts.active
                if not legacy_reason:
                    raise HTTPException(status_code=422, detail="INVALID_HALT_REASON")
                changed = state.halts.lift_committed(body.reason)
        else:
            changed = state.halts.lift_committed(body.reason)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="INVALID_HALT_REASON") from exc
    if not changed:
        if legacy_reason:
            raise HTTPException(status_code=422, detail="INVALID_HALT_REASON")
        raise HTTPException(status_code=409, detail="HALT_REASON_NOT_ACTIVE")
    if legacy_reason:
        log.info("halt_legacy_reason_lift", code="LEGACY_REASON_LIFT")
    return {"halted": state.halts.halted, "active_halts": list(state.halts.active)}
