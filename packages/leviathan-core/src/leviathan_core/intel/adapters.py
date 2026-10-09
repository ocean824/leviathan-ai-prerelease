"""Reference adapters from existing SIG-001 and FLOW-001 outputs."""

from __future__ import annotations

from typing import Protocol, TypeVar

from leviathan_core.flow_radar.filters import FlowEvaluation
from leviathan_core.flow_radar.models import Entitlement, TradeSide
from leviathan_core.numeric import canonical_str
from leviathan_core.signal.signal_models import StructureSignalV1

from .models import (
    AbstentionReason,
    AsOfContextV1,
    EvidenceRefV1,
    FactorAbstentionV1,
    FactorFamily,
    FactorFreshnessPolicyV1,
    FactorOutcomeV1,
    FactorScoreV1,
    Freshness,
    evidence_from_payload,
    require_as_of_context,
    unix_ns,
)

SnapshotT = TypeVar("SnapshotT", contravariant=True)


class FactorAdapter(Protocol[SnapshotT]):
    """Adapter contract for a typed kernel snapshot and issued point-in-time context."""

    def evaluate(
        self,
        snapshot: SnapshotT,
        context: AsOfContextV1,
        policy: FactorFreshnessPolicyV1 | None = None,
    ) -> FactorOutcomeV1: ...


class FactorAdapterError(ValueError):
    code = "FACTOR_ADAPTER_INPUT_INVALID"

    def __init__(self) -> None:
        super().__init__(self.code)


def _abstain(
    *,
    factor_id: str,
    family: FactorFamily,
    instrument: str,
    venue: str,
    context: AsOfContextV1,
    policy: FactorFreshnessPolicyV1,
    source_event_ns: int,
    reason: AbstentionReason,
    method: str,
    method_version: str,
) -> FactorAbstentionV1:
    return FactorAbstentionV1(
        factor_id=factor_id,
        family=family,
        instrument=instrument,
        venue=venue,
        as_of_ns=context.decision_as_of_ns,
        source_event_ns=source_event_ns,
        freshness=context.freshness,
        unknown_freshness_allowed=(
            policy.allow_unknown_freshness and context.freshness == "unknown"
        ),
        freshness_policy_version=policy.policy_version,
        freshness_policy=policy if policy.allow_unknown_freshness else None,
        method=method,
        method_version=method_version,
        evidence_refs=context.evidence_refs,
        reason=reason,
    )


def _freshness_reason(
    context: AsOfContextV1, policy: FactorFreshnessPolicyV1
) -> AbstentionReason | None:
    if not context.evidence_refs:
        return "MISSING_EVIDENCE"
    if context.freshness == "stale":
        return "STALE_EVIDENCE"
    if context.freshness == "unknown" and not policy.allow_unknown_freshness:
        return "UNKNOWN_FRESHNESS"
    return None


def _policy_for(factor_id: str, policy: FactorFreshnessPolicyV1 | None) -> FactorFreshnessPolicyV1:
    selected = policy or FactorFreshnessPolicyV1(
        factor_id=factor_id,
        policy_version="default/1",
        allow_unknown_freshness=False,
    )
    if type(selected) is not FactorFreshnessPolicyV1 or selected.factor_id != factor_id:
        raise FactorAdapterError()
    return selected


def _context_for(
    *,
    source: str,
    payload: object,
    source_event_ns: int,
    as_of_ns: int,
    decision_as_of_ns: int,
    freshness: Freshness,
) -> AsOfContextV1:
    from .models import issue_as_of_context

    reference = evidence_from_payload(
        source=source,
        payload=payload,
        source_event_ns=source_event_ns,
        as_of_ns=as_of_ns,
    )
    return issue_as_of_context(
        decision_as_of_ns=decision_as_of_ns,
        freshness=freshness,
        evidence_refs=(reference,),
    )


def structure_context_for(
    snapshot: StructureSignalV1, *, decision_as_of_ns: int, freshness: Freshness = "fresh"
) -> AsOfContextV1:
    """Build context for an unsealed SIG snapshot, binding its full canonical content."""
    if type(snapshot) is not StructureSignalV1:
        raise FactorAdapterError()
    return _context_for(
        source="sig001.structure",
        payload=snapshot.model_dump(mode="json"),
        source_event_ns=unix_ns(snapshot.ts_event),
        as_of_ns=unix_ns(snapshot.ts_ingest),
        decision_as_of_ns=decision_as_of_ns,
        freshness=freshness,
    )


def _verify_context_snapshot(context: AsOfContextV1, expected: EvidenceRefV1) -> None:
    if not context.evidence_refs:
        return
    if expected not in context.evidence_refs:
        raise FactorAdapterError()
    if (
        expected.source_event_ns > context.decision_as_of_ns
        or expected.as_of_ns > context.decision_as_of_ns
    ):
        # Explicit hard failure: look-ahead leakage is not an abstention.
        raise ValueError("FUTURE_EVIDENCE")


class StructureFactorAdapter:
    """Map SIG-001 structure direction/confidence and quality without re-scoring it."""

    factor_id = "sig001.structure.break.v1"
    method = "sig001.structure-confidence"
    method_version = "1"

    def evaluate(
        self,
        snapshot: StructureSignalV1,
        context: AsOfContextV1,
        policy: FactorFreshnessPolicyV1 | None = None,
    ) -> FactorOutcomeV1:
        if type(snapshot) is not StructureSignalV1:
            raise FactorAdapterError()
        issued_context = require_as_of_context(context)
        selected_policy = _policy_for(self.factor_id, policy)
        source_event_ns = unix_ns(snapshot.ts_event)
        as_of_ns = unix_ns(snapshot.ts_ingest)
        expected = evidence_from_payload(
            source="sig001.structure",
            payload=snapshot.model_dump(mode="json"),
            source_event_ns=source_event_ns,
            as_of_ns=as_of_ns,
        )
        _verify_context_snapshot(issued_context, expected)
        reason = _freshness_reason(issued_context, selected_policy)
        if reason is not None:
            return _abstain(
                factor_id=self.factor_id,
                family="structure",
                instrument=snapshot.symbol,
                venue=snapshot.venue,
                context=issued_context,
                policy=selected_policy,
                source_event_ns=source_event_ns,
                reason=reason,
                method=self.method,
                method_version=self.method_version,
            )
        if snapshot.kind == "TOMBSTONE" or snapshot.quality.gap or snapshot.quality.stale_input:
            return _abstain(
                factor_id=self.factor_id,
                family="structure",
                instrument=snapshot.symbol,
                venue=snapshot.venue,
                context=issued_context,
                policy=selected_policy,
                source_event_ns=source_event_ns,
                reason=(
                    "STALE_EVIDENCE" if snapshot.quality.stale_input else "INSUFFICIENT_EVIDENCE"
                ),
                method=self.method,
                method_version=self.method_version,
            )
        return FactorScoreV1(
            factor_id=self.factor_id,
            family="structure",
            instrument=snapshot.symbol,
            venue=snapshot.venue,
            as_of_ns=issued_context.decision_as_of_ns,
            source_event_ns=source_event_ns,
            freshness=issued_context.freshness,
            unknown_freshness_allowed=(
                selected_policy.allow_unknown_freshness and issued_context.freshness == "unknown"
            ),
            freshness_policy_version=selected_policy.policy_version,
            freshness_policy=(selected_policy if selected_policy.allow_unknown_freshness else None),
            method=self.method,
            method_version=self.method_version,
            evidence_refs=issued_context.evidence_refs,
            direction="long" if snapshot.direction == "bull" else "short",
            strength=canonical_str(snapshot.confidence),
            # SIG quality is a pass/fail eligibility gate, not a calibrated probability.
            reliability="1",
        )


def _flow_snapshot_payload(value: FlowEvaluation) -> dict[str, object]:
    trade = value.print
    stamp = trade.stamp
    return {
        "source_key": stamp.source_key,
        "provider": stamp.provider,
        "dataset": stamp.dataset,
        "session": stamp.session,
        "venue": stamp.venue,
        "native_record_key": stamp.native_record_key,
        "event_ns": stamp.event_ns,
        "available_ns": stamp.available_ns,
        "entitlement": stamp.entitlement.value,
        "ingest_ns": stamp.ingest_ns,
        "request_id": stamp.request_id,
        "correction_of": stamp.correction_of,
        "ticker": trade.ticker,
        "expiry": trade.expiry.isoformat(),
        "strike": trade.strike,
        "side": trade.trade_side.value,
        "option_side": trade.cp.value,
        "size": trade.size,
        "price": trade.price,
        "multiplier": trade.multiplier,
        "aggression_score": trade.aggression_score,
        "flags": tuple(sorted(flag.value for flag in trade.flags)),
        "common_order_id": trade.common_order_id,
        "original_strike": trade.original_strike,
        "original_size": trade.original_size,
        "adjustment_version": trade.adjustment_version,
        "premium": value.premium,
        "integrity_ok": value.integrity_ok,
        "accepted": value.accepted,
        "reasons": value.reasons,
    }


def flow_context_for(
    snapshot: FlowEvaluation, *, decision_as_of_ns: int, freshness: Freshness = "fresh"
) -> AsOfContextV1:
    """Build context for a FLOW snapshot, binding its native source key and contents."""
    if type(snapshot) is not FlowEvaluation:
        raise FactorAdapterError()
    trade = snapshot.print
    return _context_for(
        source="flow001.option-print",
        payload=_flow_snapshot_payload(snapshot),
        source_event_ns=trade.stamp.event_ns,
        as_of_ns=trade.stamp.available_ns,
        decision_as_of_ns=decision_as_of_ns,
        freshness=freshness,
    )


class FlowFactorAdapter:
    """Map accepted FLOW-001 aggression to direction and bounded strength."""

    factor_id = "flow001.option-aggression.v1"
    method = "flow001.accepted-aggression"
    method_version = "1"

    def evaluate(
        self,
        snapshot: FlowEvaluation,
        context: AsOfContextV1,
        policy: FactorFreshnessPolicyV1 | None = None,
    ) -> FactorOutcomeV1:
        if type(snapshot) is not FlowEvaluation:
            raise FactorAdapterError()
        issued_context = require_as_of_context(context)
        selected_policy = _policy_for(self.factor_id, policy)
        trade = snapshot.print
        source_event_ns = trade.stamp.event_ns
        expected = evidence_from_payload(
            source="flow001.option-print",
            payload=_flow_snapshot_payload(snapshot),
            source_event_ns=source_event_ns,
            as_of_ns=trade.stamp.available_ns,
        )
        _verify_context_snapshot(issued_context, expected)
        reason = _freshness_reason(issued_context, selected_policy)
        if reason is not None:
            return _abstain(
                factor_id=self.factor_id,
                family="order_flow",
                instrument=trade.ticker,
                venue=trade.stamp.venue,
                context=issued_context,
                policy=selected_policy,
                source_event_ns=source_event_ns,
                reason=reason,
                method=self.method,
                method_version=self.method_version,
            )
        if not snapshot.accepted or not snapshot.integrity_ok:
            return _abstain(
                factor_id=self.factor_id,
                family="order_flow",
                instrument=trade.ticker,
                venue=trade.stamp.venue,
                context=issued_context,
                policy=selected_policy,
                source_event_ns=source_event_ns,
                reason="KERNEL_REJECTED",
                method=self.method,
                method_version=self.method_version,
            )
        if trade.stamp.entitlement is not Entitlement.ENTITLED or trade.aggression_score is None:
            return _abstain(
                factor_id=self.factor_id,
                family="order_flow",
                instrument=trade.ticker,
                venue=trade.stamp.venue,
                context=issued_context,
                policy=selected_policy,
                source_event_ns=source_event_ns,
                reason="INSUFFICIENT_EVIDENCE",
                method=self.method,
                method_version=self.method_version,
            )
        return FactorScoreV1(
            factor_id=self.factor_id,
            family="order_flow",
            instrument=trade.ticker,
            venue=trade.stamp.venue,
            as_of_ns=issued_context.decision_as_of_ns,
            source_event_ns=source_event_ns,
            freshness=issued_context.freshness,
            unknown_freshness_allowed=(
                selected_policy.allow_unknown_freshness and issued_context.freshness == "unknown"
            ),
            freshness_policy_version=selected_policy.policy_version,
            freshness_policy=(selected_policy if selected_policy.allow_unknown_freshness else None),
            method=self.method,
            method_version=self.method_version,
            evidence_refs=issued_context.evidence_refs,
            direction="long" if trade.trade_side is TradeSide.BUY else "short",
            strength=canonical_str(trade.aggression_score),
            # Entitlement plus FLOW integrity is eligibility evidence, not calibration.
            reliability="1",
        )
