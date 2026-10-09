"""Fail-closed eligibility checks over attested account and stream evidence.

This module does not activate an account or dispatch an order. It is an
eligibility kernel; the dispatch-site permit/recheck remains a separate gate.
That composition root must source the sealed, versioned per-account
``VerifiedHardLimitsV1`` policy and canonical HALT authority before building
the input. Every dispatch attempt must recheck this guard immediately before
its single-use permit claim.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from contextlib import suppress
from datetime import UTC, datetime, timezone
from decimal import Decimal
from typing import Any, Literal, cast

from leviathan_core.execution.broker_port_v1 import (
    AccountViewV1,
    BrokerEnvironment,
    BrokerPortError,
    EquityEvidenceKindV1,
    EquityEvidenceV1,
    VenueIdentityV1,
)
from leviathan_core.execution.reconciliation import (
    ReconcileResultV1,
    ReconcileStatus,
    VerificationStatus,
    build_broker_snapshot,
)
from leviathan_core.numeric import NumericError, canonical_json
from leviathan_core.risk.halt_store import HaltStore, HaltStoreError
from leviathan_core.risk.policy import RiskPolicy
from leviathan_core.risk.route_guard import RouteGuard
from leviathan_core.risk_limits.kernel import assess_limits
from leviathan_core.risk_limits.live_models import (
    LiveGuardInputError,
    LiveGuardInputV1,
    LiveGuardPolicyV1,
)
from leviathan_core.risk_limits.models import ProjectedOrderV1, RiskStateV1, VerifiedHardLimitsV1
from leviathan_core.risk_limits.portfolio_sizing import size_portfolio
from leviathan_core.risk_limits.sizing_models import SizingEvidenceV1
from leviathan_core.schemas.risk import RiskGateContext
from leviathan_core.seal import Issuer, SealedModel, SealError, require
from leviathan_core.seal import digest as seal_digest

_RECONCILIATION_TAG = "execution.reconciliation"
_FRESHNESS_TAG = "md004.freshness_verdict.v1"
_DECISION_TAG = "risk003.live_guard_decision.v1"
_DECISION_ISSUER = Issuer(_DECISION_TAG)


class LiveGuardDecisionV1(SealedModel):
    """Issued, content-bound result; a decision is never a dispatch permit."""

    schema_version: Literal["risk003.live-guard-decision/1"] = "risk003.live-guard-decision/1"
    decision: Literal["ALLOW", "DENY"]
    reason_codes: tuple[str, ...]
    evidence_digest: str


def _deny(code: str, digest: str) -> LiveGuardDecisionV1:
    return _DECISION_ISSUER.issue(
        LiveGuardDecisionV1(decision="DENY", reason_codes=(code,), evidence_digest=digest)
    )


def _allow(digest: str) -> LiveGuardDecisionV1:
    return _DECISION_ISSUER.issue(
        LiveGuardDecisionV1(decision="ALLOW", reason_codes=("ELIGIBLE",), evidence_digest=digest)
    )


def _digest(value: LiveGuardInputV1, as_of_ns: int | None) -> str:
    """Hash all immutable decision evidence plus public HALT/C-101 observations."""
    try:
        if (
            type(value.policy) is not LiveGuardPolicyV1
            or type(value.order) is not ProjectedOrderV1
            or type(value.state) is not RiskStateV1
            or type(value.hard_limits) is not VerifiedHardLimitsV1
            or type(value.sizing_evidence) is not SizingEvidenceV1
            or type(value.account_view) is not AccountViewV1
            or type(value.reconciliation) is not ReconcileResultV1
        ):
            raise TypeError("evidence type")
        if type(value.halt_store) is not HaltStore:
            raise TypeError("halt type")
        halt_state = {
            "generation": value.halt_store.generation,
            "reasons": value.halt_store.load(integrity=True),
        }
        if type(value.route_guard) is not RouteGuard or type(value.route_policy) is not RiskPolicy:
            raise TypeError("route policy type")
        if type(value.route_context) is not RiskGateContext:
            raise TypeError("route context type")
        route_state = {
            "policy_matches_lock": value.route_guard.proves_policy(value.route_policy),
            "findings": tuple(
                finding.value for finding in value.route_guard.check(value.route_context)
            ),
        }
        payload = {
            "as_of_ns": as_of_ns,
            "policy": seal_digest(value.policy),
            "order": seal_digest(value.order),
            "state": seal_digest(value.state),
            "hard_limits": seal_digest(
                (value.hard_limits.policies, value.hard_limits.verification)
            ),
            "sizing_evidence": seal_digest(value.sizing_evidence),
            "account_view": seal_digest(value.account_view),
            "venue_identity": seal_digest(value.venue_identity),
            "reconciliation": seal_digest(value.reconciliation),
            "market_verdicts": seal_digest(value.market_verdicts),
            "binding": seal_digest(value.binding),
            "binding_request": seal_digest(value.binding_request),
            "credential_status": (
                None if value.credential_status is None else seal_digest(value.credential_status)
            ),
            "halt_state": halt_state,
            "route_policy": seal_digest(value.route_policy),
            "route_context": seal_digest(value.route_context),
            "route_state": route_state,
        }
        return hashlib.sha256(canonical_json(payload)).hexdigest()
    except Exception:
        # Invalid input still yields a content-free stable digest; the guard denies.
        fallback = {
            "schema": "risk003-invalid-evidence-v1",
            "input_type": f"{type(value).__module__}.{type(value).__qualname__}",
        }
        return hashlib.sha256(canonical_json(fallback)).hexdigest()


def _datetime_ns(value: object) -> int | None:
    if type(value) is not datetime or type(value.tzinfo) is not timezone:
        return None
    try:
        utc_value = value.astimezone(UTC)
        epoch = datetime(1970, 1, 1, tzinfo=UTC)
        delta = utc_value - epoch
        return ((delta.days * 86_400 + delta.seconds) * 1_000_000 + delta.microseconds) * 1_000
    except (OverflowError, ValueError):
        return None


def _environment(value: str) -> BrokerEnvironment:
    return {
        "PAPER": BrokerEnvironment.PAPER,
        "DEMO": BrokerEnvironment.DEMO,
        "LIVE": BrokerEnvironment.LIVE,
    }[value]


def _verification_statuses_allow(
    environment: str,
    balances_status: VerificationStatus,
    session_status: VerificationStatus,
) -> bool:
    if (
        type(balances_status) is not VerificationStatus
        or type(session_status) is not VerificationStatus
    ):
        return False
    if environment == "LIVE":
        return (
            balances_status is VerificationStatus.VERIFIED
            and session_status is VerificationStatus.VERIFIED
        )
    return balances_status in {
        VerificationStatus.UNVERIFIED,
        VerificationStatus.VERIFIED,
    } and session_status in {
        VerificationStatus.UNVERIFIED,
        VerificationStatus.VERIFIED,
    }


def _equity_evidence_error(environment: str) -> str | None:
    # ACCOUNT-VIEW-V13 gives balances no aggregate-equity semantics.
    return "EQUITY_EVIDENCE_UNAVAILABLE" if environment == "LIVE" else None


def _unissued_equity_evidence_error(value: LiveGuardInputV1) -> str | None:
    """Map an invalid nested equity issuance to the LIVE evidence denial."""
    if value.policy.environment != "LIVE":
        return None
    evidence = getattr(value.account_view, "equity", None)
    if evidence is None:
        return None
    if type(evidence) is not EquityEvidenceV1:
        return "EQUITY_EVIDENCE_UNAVAILABLE"
    try:
        evidence.assert_sealed()
    except BrokerPortError:
        return "EQUITY_EVIDENCE_UNAVAILABLE"
    return None


def _validate_equity_evidence(value: LiveGuardInputV1, observed_at_ns: int) -> str | None:
    """Require issued base-currency equity bound to the reconciled snapshot."""
    if value.policy.environment != "LIVE":
        return None
    evidence = getattr(value.account_view, "equity", None)
    if type(evidence) is not EquityEvidenceV1:
        return _equity_evidence_error(value.policy.environment)
    try:
        evidence.assert_sealed()
    except BrokerPortError:
        return _equity_evidence_error(value.policy.environment)
    if (
        type(evidence.kind) is not EquityEvidenceKindV1
        or evidence.kind
        not in {
            EquityEvidenceKindV1.NET_LIQUIDATION,
            EquityEvidenceKindV1.TOTAL_EQUITY,
        }
        or evidence.currency != value.state.base_currency
        or type(evidence.broker_observed_at_ns) is not int
        or evidence.broker_observed_at_ns != observed_at_ns
    ):
        return _equity_evidence_error(value.policy.environment)
    if type(value.state.equity) is not Decimal:
        return _equity_evidence_error(value.policy.environment)
    if evidence.amount != value.state.equity:
        return "EQUITY_MISMATCH"
    return None


def _validate_binding(value: LiveGuardInputV1, as_of_ns: int) -> bool:
    # Import lazily: the core stays importable without the optional vault package.
    from leviathan_vault.trading_bindings import validate_binding

    request = value.binding_request
    binding = value.binding
    if getattr(request, "want_submit", None) is not False:
        return False
    if getattr(request, "checked_at", None) is None:
        return False
    checked_ns = _datetime_ns(getattr(request, "checked_at", None))
    if checked_ns != as_of_ns:
        return False
    result = validate_binding(
        cast(Any, binding),
        cast(Any, request),
        credential_status=cast(Any, value.credential_status),
    )
    if type(result.metadata_valid) is not bool or not result.metadata_valid:
        return False
    order = value.order
    expected_binding_env = "live" if value.policy.environment == "LIVE" else "development"
    expected_mode = value.policy.environment.lower()
    return (
        getattr(binding, "environment", None) == expected_binding_env
        and getattr(binding, "session_mode", None) == expected_mode
        and getattr(binding, "can_read", None) is True
        and getattr(binding, "can_submit", None) is False
        and getattr(binding, "broker", None) == value.policy.broker_venue.value
        and getattr(binding, "hard_risk_limit_revision", None) == value.policy.policy_revision
        and getattr(request, "account_ref", None) == getattr(binding, "account_ref", None)
        and getattr(request, "venue", None) == getattr(order, "venue_id", None)
        and getattr(request, "instrument", None) == getattr(order, "instrument_id", None)
        and getattr(request, "strategy_id", None) == getattr(order, "strategy_id", None)
    )


def _validate_halt(value: LiveGuardInputV1) -> bool:
    store = value.halt_store
    if type(store) is not HaltStore:
        return False
    # These are the durable HALT store's public, integrity-checking reads.
    reasons = store.load(integrity=True)
    generation = store.generation
    return type(reasons) is dict and not reasons and type(generation) is int and generation >= 0


def _validate_streams(value: LiveGuardInputV1, as_of_ns: int) -> bool:
    try:
        from leviathan_market_data.live.models import FreshnessVerdictV1
    except ImportError:
        return False
    seen: set[tuple[str, str, str, str, str, str]] = set()
    for verdict in value.market_verdicts:
        if type(verdict) is not FreshnessVerdictV1:
            return False
        require(verdict, _FRESHNESS_TAG)
        key = verdict.stream_key
        if (
            type(key) is not tuple
            or len(key) != 6
            or key in seen
            or verdict.state != "HEALTHY"
            or verdict.publication_allowed is not True
            or verdict.execution_eligible is not False
            or type(verdict.evaluated_utc_ns) is not int
            or verdict.evaluated_utc_ns > as_of_ns
            or as_of_ns - verdict.evaluated_utc_ns > value.policy.max_stream_age_ns
            or type(verdict.heartbeat_age_ns) is not int
            or verdict.heartbeat_age_ns < 0
            or verdict.heartbeat_age_ns > value.policy.max_stream_age_ns
        ):
            return False
        if (
            verdict.node_drift_ms is not None
            and verdict.node_drift_ms * 1_000_000 > value.policy.max_clock_skew_ns
        ):
            return False
        seen.add(key)
    return seen == set(value.policy.required_stream_keys)


def _validate_reconciliation(value: LiveGuardInputV1, as_of_ns: int) -> str | None:
    result = value.reconciliation
    if type(result) is not ReconcileResultV1:
        return "ACCOUNT_RECONCILIATION_INVALID"
    try:
        require(result, _RECONCILIATION_TAG)
    except SealError:
        return "ACCOUNT_RECONCILIATION_INVALID"
    if not _verification_statuses_allow(
        value.policy.environment,
        result.balances_status,
        result.session_status,
    ):
        return "ACCOUNT_V13_UNVERIFIED"
    order = value.order
    state = value.state
    equity_source_ns = getattr(state, "equity_source_ns", None)
    if (
        type(result.observed_at_ns) is int
        and type(equity_source_ns) is int
        and equity_source_ns == result.observed_at_ns
        and result.observed_at_ns <= as_of_ns
        and as_of_ns - equity_source_ns > value.policy.max_equity_age_ns
    ):
        return "ACCOUNT_EQUITY_STALE"
    if (
        result.environment is not _environment(value.policy.environment)
        or result.account_id != value.policy.account_id
        or result.account_id != getattr(order, "account_id", None)
        or result.observed_environment is not _environment(value.policy.environment)
        or result.observed_account_id != value.policy.account_id
        or result.venue is not value.policy.broker_venue
        or result.observed_venue is not value.policy.broker_venue
        or type(value.venue_identity) is not VenueIdentityV1
        or value.venue_identity.venue is not value.policy.broker_venue
        or value.venue_identity.environment is not _environment(value.policy.environment)
        or value.venue_identity.account_id != value.policy.account_id
        or result.account_status is not ReconcileStatus.MATCHED
        or result.divergence_codes
        or result.submission_blocked is not False
        or type(result.snapshot_digest) is not str
        or type(result.observed_at_ns) is not int
        or result.observed_at_ns > as_of_ns
        or as_of_ns - result.observed_at_ns > value.policy.max_account_age_ns
        or result.ledger_revision < 0
        or result.broker_revision is None
    ):
        return "ACCOUNT_RECONCILIATION_DENIED"
    try:
        recomputed_snapshot = build_broker_snapshot(
            value.account_view,
            value.venue_identity,
            observed_at_ns=result.observed_at_ns,
        )
    except Exception:
        return "ACCOUNT_RECONCILIATION_DENIED"
    if seal_digest(recomputed_snapshot) != result.snapshot_digest:
        return "ACCOUNT_SNAPSHOT_MISMATCH"
    observed_ns = _datetime_ns(value.account_view.broker_observed_at)
    if (
        observed_ns is None
        or observed_ns > as_of_ns
        or as_of_ns - observed_ns > value.policy.max_account_age_ns
    ):
        return "ACCOUNT_SNAPSHOT_STALE"
    if (
        type(equity_source_ns) is not int
        or equity_source_ns != result.observed_at_ns
        or equity_source_ns > as_of_ns
        or as_of_ns - equity_source_ns > value.policy.max_equity_age_ns
    ):
        return "ACCOUNT_EQUITY_STALE"
    if value.account_view.positions != tuple(
        (position.instrument_id, position.quantity) for position in state.positions or ()
    ):
        return "ACCOUNT_POSITION_MISMATCH"
    return _validate_equity_evidence(value, result.observed_at_ns)


def validate_live_guard(
    value: LiveGuardInputV1, *, clock_ns: Callable[[], int]
) -> LiveGuardDecisionV1:
    """Assess once against trusted composition-root time and evidence.

    This is not a permit claim. The dispatch site must provide its canonical
    policy/HALT authorities and recheck the decision for every attempt.
    """
    clock_value: object = None
    with suppress(Exception):
        clock_value = clock_ns()
    as_of_ns = clock_value if type(clock_value) is int else None
    evidence_digest = (
        _digest(value, as_of_ns)
        if type(value) is LiveGuardInputV1
        else hashlib.sha256(b"invalid").hexdigest()
    )
    if type(value) is not LiveGuardInputV1:
        return _deny("INPUT_INVALID", evidence_digest)
    if type(as_of_ns) is not int or not 1 <= as_of_ns <= (1 << 63) - 1:
        return _deny("CLOCK_INVALID", evidence_digest)
    try:
        policy = value.policy
        order = value.order
        state = value.state
        value.__post_init__()
        policy.__post_init__()
        if type(order) is ProjectedOrderV1:
            order.__post_init__()
        if type(state) is RiskStateV1:
            state.__post_init__()
        if (
            type(policy) is not LiveGuardPolicyV1
            or type(order) is not ProjectedOrderV1
            or type(state) is not RiskStateV1
            or type(value.sizing_evidence) is not SizingEvidenceV1
            or type(value.venue_identity) is not VenueIdentityV1
            or policy.account_id != getattr(order, "account_id", None)
            or policy.environment.lower() != getattr(order, "environment", None)
            or policy.venue_id != getattr(order, "venue_id", None)
            or policy.strategy_id != getattr(order, "strategy_id", None)
            or policy.instrument_id != getattr(order, "instrument_id", None)
            or policy.account_id != getattr(state, "account_id", None)
            or policy.environment.lower() != getattr(state, "environment", None)
            or policy.account_id != getattr(value.account_view, "account_id", None)
            or type(value.account_view) is not AccountViewV1
        ):
            return _deny("ACCOUNT_SCOPE_MISMATCH", evidence_digest)
        if getattr(order, "is_manual", None) is not False:
            return _deny("MANUAL_ROUTE_DENIED", evidence_digest)
        if (
            getattr(order, "agent_instruction", None) is not None
            or getattr(order, "role", None) is not None
        ):
            return _deny("AGENT_ROUTE_DENIED", evidence_digest)
        equity_issuance_failure = _unissued_equity_evidence_error(value)
        if equity_issuance_failure is not None:
            return _deny(equity_issuance_failure, evidence_digest)
        value.account_view.assert_sealed()
        if policy.environment == "LIVE" and policy.live_switch_enabled is not True:
            return _deny("LIVE_SWITCH_DISABLED", evidence_digest)
        if not _validate_binding(value, as_of_ns):
            return _deny("BINDING_DENIED", evidence_digest)
        if not _validate_halt(value):
            return _deny("HALT_ACTIVE_OR_UNKNOWN", evidence_digest)
        if not _validate_streams(value, as_of_ns):
            return _deny("STREAM_EVIDENCE_DENIED", evidence_digest)
        reconciliation_failure = _validate_reconciliation(value, as_of_ns)
        if reconciliation_failure is not None:
            return _deny(reconciliation_failure, evidence_digest)
        if type(value.hard_limits) is not VerifiedHardLimitsV1:
            return _deny("HARD_POLICY_MISSING", evidence_digest)
        if not any(
            policy.scope == "ACCOUNT"
            and policy.account_id == value.policy.account_id
            and policy.revision == value.policy.policy_revision
            and policy.environment == value.policy.environment.lower()
            for policy in value.hard_limits.policies
        ):
            return _deny("HARD_POLICY_MISMATCH", evidence_digest)
        hard_assessment = assess_limits(order, value.hard_limits, state, as_of_ns)
        if hard_assessment.decision != "ALLOW":
            return _deny("HARD_LIMIT_DENIED", evidence_digest)
        sizing = size_portfolio(value.sizing_evidence, value.hard_limits, as_of_ns)
        if type(sizing.reason_codes) is tuple and "EQUITY_STALE" in sizing.reason_codes:
            return _deny("ACCOUNT_EQUITY_STALE", evidence_digest)
        if (
            sizing.status != "SIZE"
            or sizing.max_quantity < order.quantity
            or value.sizing_evidence.order != order
            or value.sizing_evidence.state != state
        ):
            return _deny("PORTFOLIO_SIZE_DENIED", evidence_digest)
        if type(value.route_guard) is not RouteGuard or type(value.route_policy) is not RiskPolicy:
            return _deny("C101_POLICY_DENIED", evidence_digest)
        if type(value.route_context) is not RiskGateContext:
            return _deny("C101_CONTEXT_MISSING", evidence_digest)
        if (
            _datetime_ns(value.route_context.as_of) != as_of_ns
            or type(value.route_context.required) is not tuple
            or not value.route_context.required
            or type(value.route_context.max_staleness_ms) is not int
            or type(value.route_context.max_clock_skew_ms) is not int
            or value.route_context.max_staleness_ms * 1_000_000 > value.policy.max_stream_age_ns
            or value.route_context.max_clock_skew_ms * 1_000_000 > value.policy.max_clock_skew_ns
        ):
            return _deny("C101_CONTEXT_MISMATCH", evidence_digest)
        if not value.route_guard.proves_policy(value.route_policy):
            return _deny("C101_POLICY_DENIED", evidence_digest)
        if value.route_guard.check(value.route_context):
            return _deny("C101_ROUTE_DENIED", evidence_digest)
        return _allow(evidence_digest)
    except (
        LiveGuardInputError,
        NumericError,
        SealError,
        HaltStoreError,
        ValueError,
        TypeError,
        AttributeError,
        KeyError,
        OSError,
    ):
        return _deny("EVIDENCE_INVALID", evidence_digest)


__all__ = ["LiveGuardDecisionV1", "validate_live_guard"]
