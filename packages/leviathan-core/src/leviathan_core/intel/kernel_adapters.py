"""Thin, deterministic projections from issued kernel results to FactorScoreV1.

These adapters do not re-score kernels. Their explicit projection scale maps an
already-computed signed value into the factor contract's bounded strength.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import fields
from decimal import Decimal
from typing import Literal

from pydantic import Field, field_validator

from leviathan_core.dark_pool.models import DarkLensResultV1, _result_hash
from leviathan_core.dealer_gamma.models import GammaEstimateV1, semantic_digest
from leviathan_core.decision_fusion.models import FusionModelV1
from leviathan_core.feature_store.models import FeatureResultV1, require_feature_result
from leviathan_core.indicator_state.models import IndicatorResultV1, require_indicator_result
from leviathan_core.intel.adapters import _abstain, _freshness_reason, _policy_for
from leviathan_core.intel.models import (
    AbstentionReason,
    AsOfContextV1,
    EvidenceRefV1,
    FactorFamily,
    FactorFreshnessPolicyV1,
    FactorOutcomeV1,
    FactorScoreV1,
    Freshness,
    evidence_from_feature_result,
    evidence_from_normalized_event,
    evidence_from_payload,
    issue_as_of_context,
    require_as_of_context,
)
from leviathan_core.macro_cot.models import COTResultV1
from leviathan_core.numeric import (
    canonical_str,
    exact_sub,
    exact_sum,
    parse_decimal,
    quotient_final,
)
from leviathan_core.regime.models import RegimeResultV1, _result_content
from leviathan_market_data.live.book_cache import (
    BookKeyV1,
    BookSnapshotReceiptV1,
    is_issued_book_snapshot_receipt,
)
from leviathan_market_data.schema import NormalizedMarketEventV1

from .models import FutureEvidenceError


class FactorProjectionPolicyV1(FusionModelV1):
    """Versioned numeric projection; scale is explicit to avoid hidden calibration."""

    factor_id: str
    family: FactorFamily
    method: str
    method_version: str
    scale: Decimal = Field(gt=0)

    @field_validator("scale", mode="before")
    @classmethod
    def _scale(cls, value: object) -> Decimal:
        if type(value) not in (str, Decimal):
            raise ValueError("INVALID_FACTOR_SCALE")
        return parse_decimal(value, field="factor_scale")


class FactorAdapterInputError(ValueError):
    code = "FACTOR_ADAPTER_INPUT_INVALID"

    def __init__(self) -> None:
        super().__init__(self.code)


def _projection(
    *,
    factor_id: str,
    family: FactorFamily,
    method: str,
    method_version: str,
    instrument: str,
    venue: str,
    value: Decimal | None,
    scale: Decimal,
    reliability: Decimal,
    source_event_ns: int,
    context: AsOfContextV1,
    policy: FactorFreshnessPolicyV1 | None,
    ineligible: bool = False,
    direction_override: Literal["long", "short", "neutral"] | None = None,
    strength_override: Decimal | None = None,
    missing_reason: AbstentionReason = "INSUFFICIENT_EVIDENCE",
) -> FactorOutcomeV1:
    context = require_as_of_context(context)
    selected = _policy_for(factor_id, policy)
    reason = _freshness_reason(context, selected)
    if reason is None and ineligible:
        reason = "KERNEL_REJECTED"
    if reason is None and value is None:
        reason = missing_reason
    if reason is not None:
        return _abstain(
            factor_id=factor_id,
            family=family,
            instrument=instrument,
            venue=venue,
            context=context,
            policy=selected,
            source_event_ns=source_event_ns,
            reason=reason,
            method=method,
            method_version=method_version,
        )
    assert value is not None
    if source_event_ns > context.decision_as_of_ns or any(
        ref.source_event_ns > context.decision_as_of_ns or ref.as_of_ns > context.decision_as_of_ns
        for ref in context.evidence_refs
    ):
        raise FutureEvidenceError()
    signed = value
    direction: Literal["long", "short", "neutral"] = direction_override or (
        "long" if signed > 0 else "short" if signed < 0 else "neutral"
    )
    projected_strength = (
        strength_override if strength_override is not None else quotient_final(abs(signed), scale)
    )
    strength = min(Decimal(1), projected_strength)
    return FactorScoreV1(
        factor_id=factor_id,
        family=family,
        instrument=instrument,
        venue=venue,
        as_of_ns=context.decision_as_of_ns,
        source_event_ns=source_event_ns,
        freshness=context.freshness,
        unknown_freshness_allowed=(
            selected.allow_unknown_freshness and context.freshness == "unknown"
        ),
        freshness_policy_version=selected.policy_version,
        freshness_policy=(selected if selected.allow_unknown_freshness else None),
        method=method,
        method_version=method_version,
        evidence_refs=context.evidence_refs,
        direction=direction,
        strength=canonical_str(strength),
        reliability=canonical_str(reliability),
    )


def _context_for_result(
    *,
    source: str,
    payload: object,
    event_ns: int,
    available_ns: int,
    decision_as_of_ns: int,
    freshness: Freshness,
) -> AsOfContextV1:
    ref = evidence_from_payload(
        source=source, payload=payload, source_event_ns=event_ns, as_of_ns=available_ns
    )
    return issue_as_of_context(
        decision_as_of_ns=decision_as_of_ns, freshness=freshness, evidence_refs=(ref,)
    )


def _require_exact_evidence(
    context: AsOfContextV1, expected: tuple[EvidenceRefV1, ...]
) -> AsOfContextV1:
    """Bind an adapter call to precisely the source refs it verified."""
    issued = require_as_of_context(context)
    if issued.evidence_refs != tuple(
        sorted(expected, key=lambda ref: (ref.source, ref.record_digest))
    ):
        raise FactorAdapterInputError()
    return issued


def _regime_digest(snapshot: RegimeResultV1) -> str:
    payload = {
        item.name: _result_content(getattr(snapshot, item.name))
        for item in fields(snapshot)
        if item.name != "content_digest"
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _regime_provenance(snapshot: RegimeResultV1) -> tuple[dict[str, object], ...]:
    """Expose sealed input lineage in the adapter evidence digest."""
    return tuple(
        {
            "source": str(factor.source),
            "source_version": factor.source_version,
            "semantic_digest": factor.semantic_digest,
            "event_ns": factor.event_ns,
            "available_ns": factor.available_ns,
            "baseline_available_ns": factor.baseline_available_ns,
            "feature_available_ns": factor.feature_available_ns,
        }
        for factor in snapshot.factor_provenance
    )


def _regime_input_times(snapshot: RegimeResultV1) -> tuple[int | None, int | None]:
    events: list[int] = []
    available: list[int] = []
    for factor in snapshot.factor_provenance:
        events.append(factor.event_ns)
        available.extend((factor.available_ns, factor.baseline_available_ns))
        if factor.feature_available_ns is not None:
            available.append(factor.feature_available_ns)
    return (max(events) if events else None, max(available) if available else None)


class MarketBookFactorAdapter:
    """Project a coherent MD-006 book snapshot's top-of-book depth imbalance."""

    factor_id = "md006.book-imbalance.v1"
    method = "md006.bid-ask-depth-imbalance"
    method_version = "1"

    @staticmethod
    def context_for(
        key: BookKeyV1,
        receipt: BookSnapshotReceiptV1,
        source_event: NormalizedMarketEventV1,
        *,
        decision_as_of_ns: int,
        freshness: Freshness = "fresh",
    ) -> AsOfContextV1:
        if not is_issued_book_snapshot_receipt(receipt):
            raise FactorAdapterInputError()
        if (
            type(source_event) is not NormalizedMarketEventV1
            or source_event.event_type != "book_snapshot"
            or (
                source_event.provider,
                source_event.dataset,
                source_event.venue,
                source_event.instrument_id,
            )
            != (key.provider, key.dataset, key.venue, key.instrument_id)
            or receipt.updated_time_ns != source_event.event_time_ns
        ):
            raise FactorAdapterInputError()
        return issue_as_of_context(
            decision_as_of_ns=decision_as_of_ns,
            freshness=freshness,
            evidence_refs=(evidence_from_normalized_event(source_event),),
        )

    def evaluate(
        self,
        key: BookKeyV1,
        receipt: BookSnapshotReceiptV1,
        source_event: NormalizedMarketEventV1,
        context: AsOfContextV1,
        policy: FactorFreshnessPolicyV1 | None = None,
    ) -> FactorOutcomeV1:
        if not is_issued_book_snapshot_receipt(receipt):
            raise FactorAdapterInputError()
        expected = evidence_from_normalized_event(source_event)
        context = _require_exact_evidence(context, (expected,))
        if source_event.event_time_ns != receipt.updated_time_ns or (
            source_event.provider,
            source_event.dataset,
            source_event.venue,
            source_event.instrument_id,
        ) != (key.provider, key.dataset, key.venue, key.instrument_id):
            raise FactorAdapterInputError()
        if not receipt.coherent or receipt.snapshot is None or receipt.reason != "HEALTHY":
            return _projection(
                factor_id=self.factor_id,
                family="book_l2_l3",
                method=self.method,
                method_version=self.method_version,
                instrument=key.instrument_id,
                venue=key.venue,
                value=None,
                scale=Decimal(1),
                reliability=Decimal(0),
                source_event_ns=source_event.event_time_ns,
                context=context,
                policy=policy,
                ineligible=True,
            )
        bid = exact_sum(
            parse_decimal(level.size, field="book_size")
            for level in receipt.snapshot.levels
            if level.side == "bid"
        )
        ask = exact_sum(
            parse_decimal(level.size, field="book_size")
            for level in receipt.snapshot.levels
            if level.side == "ask"
        )
        total = exact_sum((bid, ask))
        value = quotient_final(exact_sub(bid, ask), total) if total else None
        return _projection(
            factor_id=self.factor_id,
            family="book_l2_l3",
            method=self.method,
            method_version=self.method_version,
            instrument=key.instrument_id,
            venue=key.venue,
            value=value,
            scale=Decimal(1),
            reliability=Decimal(1),
            source_event_ns=source_event.event_time_ns,
            context=context,
            policy=policy,
        )


class FeatureFactorAdapter:
    """Map an issued FEAT-001 scalar feature through an explicit scale."""

    def __init__(self, mapping: FactorProjectionPolicyV1) -> None:
        self.mapping = mapping

    def evaluate(
        self,
        snapshot: FeatureResultV1,
        context: AsOfContextV1,
        policy: FactorFreshnessPolicyV1 | None = None,
    ) -> FactorOutcomeV1:
        result = require_feature_result(snapshot)
        if not result.found:
            value = None
        elif result.value_decimal is not None:
            value = result.value_decimal
        else:
            value = None
        ref = evidence_from_feature_result(result)
        context = require_as_of_context(context)
        context = _require_exact_evidence(context, (ref,) if ref is not None else ())
        if result.event_time_ns is not None and result.event_time_ns > context.decision_as_of_ns:
            raise FutureEvidenceError()
        return _projection(
            factor_id=self.mapping.factor_id,
            family=self.mapping.family,
            method=self.mapping.method,
            method_version=self.mapping.method_version,
            instrument=result.instrument_id,
            venue="FEATURE_STORE",
            value=value,
            scale=self.mapping.scale,
            reliability=Decimal(1),
            source_event_ns=result.event_time_ns or result.asof_ns,
            context=context,
            policy=policy,
        )

    def context_for(
        self,
        snapshot: FeatureResultV1,
        *,
        decision_as_of_ns: int,
        freshness: Freshness = "fresh",
    ) -> AsOfContextV1:
        result = require_feature_result(snapshot)
        ref = evidence_from_feature_result(result)
        return issue_as_of_context(
            decision_as_of_ns=decision_as_of_ns,
            freshness=freshness,
            evidence_refs=(ref,) if ref is not None else (),
        )


class GammaFactorAdapter:
    """Project the issued GEX sign regime as a neutral volatility-regime factor."""

    factor_id = "gex001.dealer-gamma.v1"
    method = "gex001.confidence-regime"
    method_version = "1"

    @staticmethod
    def evidence_reference(snapshot: GammaEstimateV1) -> EvidenceRefV1:
        semantic_digest(snapshot)
        horizon = snapshot.live or snapshot.settled
        assert horizon is not None
        return evidence_from_payload(
            source="gex001.gamma",
            payload={
                "semantic_digest": snapshot.semantic_digest,
                "snapshot_id": horizon.snapshot_id,
                "aggregate_gamma": horizon.aggregate_gamma,
            },
            source_event_ns=horizon.observed_ns,
            as_of_ns=horizon.available_ns,
        )

    @staticmethod
    def context_for(
        snapshot: GammaEstimateV1,
        *,
        venue: str,
        decision_as_of_ns: int,
        freshness: Freshness = "fresh",
    ) -> AsOfContextV1:
        ref = GammaFactorAdapter.evidence_reference(snapshot)
        horizon = snapshot.live or snapshot.settled
        assert horizon is not None
        return _context_for_result(
            source=ref.source,
            payload={
                "semantic_digest": snapshot.semantic_digest,
                "snapshot_id": horizon.snapshot_id,
                "aggregate_gamma": horizon.aggregate_gamma,
            },
            event_ns=horizon.observed_ns,
            available_ns=horizon.available_ns,
            decision_as_of_ns=decision_as_of_ns,
            freshness=freshness,
        )

    def evaluate(
        self,
        snapshot: GammaEstimateV1,
        venue: str,
        context: AsOfContextV1,
        policy: FactorFreshnessPolicyV1 | None = None,
    ) -> FactorOutcomeV1:
        semantic_digest(snapshot)
        horizon = snapshot.live or snapshot.settled
        assert horizon is not None
        context = _require_exact_evidence(context, (self.evidence_reference(snapshot),))
        return _projection(
            factor_id=self.factor_id,
            family="gex",
            method=self.method,
            method_version=self.method_version,
            instrument=snapshot.underlier,
            venue=venue,
            value=horizon.confidence,
            scale=Decimal(1),
            reliability=horizon.confidence,
            source_event_ns=horizon.observed_ns,
            context=context,
            policy=policy,
            ineligible=(horizon.status != "OK" or horizon.aggregate_gamma is None),
            direction_override="neutral",
        )


class DarkPoolFactorAdapter:
    """Project verified FINRA dark-pool buy/sell imbalance without re-ranking prints."""

    factor_id = "dp001.dark-pool-imbalance.v1"
    method = "dp001.buy-sell-imbalance"
    method_version = "1"

    @staticmethod
    def context_for(
        snapshot: DarkLensResultV1,
        *,
        venue: str,
        decision_as_of_ns: int,
        freshness: Freshness = "fresh",
    ) -> AsOfContextV1:
        if type(snapshot) is not DarkLensResultV1 or snapshot.digest != _result_hash(snapshot):
            raise FactorAdapterInputError()
        event_ns = (
            snapshot.latest_contributing_event_ns
            if snapshot.latest_contributing_event_ns is not None
            else snapshot.window_end_ns
        )
        return _context_for_result(
            source="dp001.dark-pool",
            payload={
                "digest": snapshot.digest,
                "window_id": snapshot.window_id,
                "source_ids": snapshot.source_ids,
                "source_event_ids": snapshot.source_event_ids,
                "aggregate_context_ids": snapshot.aggregate_context_ids,
                "adjustment_versions": snapshot.adjustment_versions,
            },
            event_ns=event_ns,
            available_ns=snapshot.asof_ns,
            decision_as_of_ns=decision_as_of_ns,
            freshness=freshness,
        )

    def evaluate(
        self,
        snapshot: DarkLensResultV1,
        venue: str,
        context: AsOfContextV1,
        policy: FactorFreshnessPolicyV1 | None = None,
    ) -> FactorOutcomeV1:
        if type(snapshot) is not DarkLensResultV1 or snapshot.digest != _result_hash(snapshot):
            raise FactorAdapterInputError()
        event_ns = (
            snapshot.latest_contributing_event_ns
            if snapshot.latest_contributing_event_ns is not None
            else snapshot.window_end_ns
        )
        expected = evidence_from_payload(
            source="dp001.dark-pool",
            payload={
                "digest": snapshot.digest,
                "window_id": snapshot.window_id,
                "source_ids": snapshot.source_ids,
                "source_event_ids": snapshot.source_event_ids,
                "aggregate_context_ids": snapshot.aggregate_context_ids,
                "adjustment_versions": snapshot.adjustment_versions,
            },
            source_event_ns=event_ns,
            as_of_ns=snapshot.asof_ns,
        )
        context = _require_exact_evidence(context, (expected,))
        value = (
            quotient_final(snapshot.buy_sell_imbalance_bp, Decimal("10000"))
            if snapshot.buy_sell_imbalance_bp is not None
            else None
        )
        return _projection(
            factor_id=self.factor_id,
            family="dark_pool",
            method=self.method,
            method_version=self.method_version,
            instrument=snapshot.instrument_id,
            venue=venue,
            value=value,
            scale=Decimal(1),
            reliability=Decimal(1 if snapshot.valid else 0),
            source_event_ns=event_ns,
            context=context,
            policy=policy,
            ineligible=(not snapshot.valid or snapshot.recompute_pending),
        )


class RegimeFactorAdapter:
    """Map the sealed REG-001 discrete composite direction and confidence."""

    factor_id = "reg001.composite-regime.v1"
    method = "reg001.discrete-composite"
    method_version = "1"

    @staticmethod
    def context_for(
        snapshot: RegimeResultV1,
        *,
        instrument: str,
        venue: str,
        decision_as_of_ns: int,
        freshness: Freshness = "fresh",
    ) -> AsOfContextV1:
        if type(snapshot) is not RegimeResultV1 or snapshot.content_digest != _regime_digest(
            snapshot
        ):
            raise FactorAdapterInputError()
        event_ns, available_ns = _regime_input_times(snapshot)
        if event_ns is None or available_ns is None:
            return issue_as_of_context(
                decision_as_of_ns=decision_as_of_ns,
                freshness=freshness,
                evidence_refs=(),
            )
        return _context_for_result(
            source="reg001.result",
            payload={
                "content_digest": snapshot.content_digest,
                "inputs_hash": snapshot.inputs_hash,
                "revision": snapshot.revision,
                "factor_provenance": _regime_provenance(snapshot),
            },
            event_ns=event_ns,
            available_ns=available_ns,
            decision_as_of_ns=decision_as_of_ns,
            freshness=freshness,
        )

    def evaluate(
        self,
        snapshot: RegimeResultV1,
        instrument: str,
        venue: str,
        context: AsOfContextV1,
        policy: FactorFreshnessPolicyV1 | None = None,
    ) -> FactorOutcomeV1:
        if type(snapshot) is not RegimeResultV1 or snapshot.content_digest != _regime_digest(
            snapshot
        ):
            raise FactorAdapterInputError()
        event_ns, available_ns = _regime_input_times(snapshot)
        if event_ns is None or available_ns is None:
            return _projection(
                factor_id=self.factor_id,
                family="regime",
                method=self.method,
                method_version=self.method_version,
                instrument=instrument,
                venue=venue,
                value=None,
                scale=Decimal(1),
                reliability=snapshot.confidence,
                source_event_ns=0,
                context=require_as_of_context(context),
                policy=policy,
                missing_reason="MISSING_EVIDENCE",
            )
        expected = evidence_from_payload(
            source="reg001.result",
            payload={
                "content_digest": snapshot.content_digest,
                "inputs_hash": snapshot.inputs_hash,
                "revision": snapshot.revision,
                "factor_provenance": _regime_provenance(snapshot),
            },
            source_event_ns=event_ns,
            as_of_ns=available_ns,
        )
        context = _require_exact_evidence(context, (expected,))
        value = Decimal(snapshot.composite_regime or 0) / Decimal(2)
        return _projection(
            factor_id=self.factor_id,
            family="regime",
            method=self.method,
            method_version=self.method_version,
            instrument=instrument,
            venue=venue,
            value=value,
            scale=Decimal(1),
            reliability=snapshot.confidence,
            source_event_ns=event_ns,
            context=context,
            policy=policy,
            ineligible=(
                not snapshot.publish_current or snapshot.status not in {"SCORED", "PARTIAL"}
            ),
        )


class IndicatorFactorAdapter:
    """Project an issued IND-001 finalized value with explicit scale."""

    def __init__(self, mapping: FactorProjectionPolicyV1) -> None:
        self.mapping = mapping

    @staticmethod
    def context_for(
        snapshot: IndicatorResultV1,
        *,
        instrument: str,
        venue: str,
        available_ns: int,
        decision_as_of_ns: int,
        freshness: Freshness = "fresh",
    ) -> AsOfContextV1:
        result = require_indicator_result(snapshot)
        ref = evidence_from_payload(
            source=f"ind001.indicator:{instrument}",
            payload=result.canonical_bytes().hex(),
            source_event_ns=result.bar_end_ns,
            as_of_ns=available_ns,
        )
        return issue_as_of_context(
            decision_as_of_ns=decision_as_of_ns, freshness=freshness, evidence_refs=(ref,)
        )

    def evaluate(
        self,
        snapshot: IndicatorResultV1,
        instrument: str,
        venue: str,
        context: AsOfContextV1,
        policy: FactorFreshnessPolicyV1 | None = None,
    ) -> FactorOutcomeV1:
        result = require_indicator_result(snapshot)
        context = require_as_of_context(context)
        if not context.evidence_refs:
            raise FactorAdapterInputError()
        ref = evidence_from_payload(
            source=f"ind001.indicator:{instrument}",
            payload=result.canonical_bytes().hex(),
            source_event_ns=result.bar_end_ns,
            as_of_ns=context.evidence_refs[0].as_of_ns if context.evidence_refs else 0,
        )
        context = _require_exact_evidence(context, (ref,))
        value = result.value
        eligible = not (result.warmup or result.gap or result.late or result.invalid)
        return _projection(
            factor_id=self.mapping.factor_id,
            family="indicator",
            method=self.mapping.method,
            method_version=self.mapping.method_version,
            instrument=instrument,
            venue=venue,
            value=value,
            scale=self.mapping.scale,
            reliability=Decimal(1 if eligible else 0),
            source_event_ns=result.bar_end_ns,
            context=context,
            policy=policy,
            ineligible=not eligible,
        )


class COTFactorAdapter:
    """Map an issued COT contrarian posture; it is not a prediction or trade order."""

    factor_id = "cot001.positioning.v1"
    method = "cot001.extreme-positioning-contrarian"
    method_version = "1"

    @staticmethod
    def _payload(result: COTResultV1) -> dict[str, object]:
        return {
            "market_id": result.market_id,
            "asof_ns": result.asof_ns,
            "report_date": result.report_date.isoformat() if result.report_date else None,
            "latest_published_ns": result.latest_published_ns,
            "latest_available_ns": result.latest_available_ns,
            "net_mm_pct_oi": str(result.net_mm_pct_oi)
            if result.net_mm_pct_oi is not None
            else None,
            "percentile": str(result.percentile) if result.percentile is not None else None,
            "contrarian_tag": result.contrarian_tag,
            "status": result.status,
            "policy_version": result.policy_version,
            "selected_revision_ids": result.selected_revision_ids,
            "selected_vintages": tuple(
                {
                    "source": row.source,
                    "constituent_id": row.constituent_id,
                    "revision": row.revision,
                    "published_ns": row.published_ns,
                    "received_ns": row.received_ns,
                    "available_ns": row.available_ns,
                }
                for row in result.selected_vintages
            ),
        }

    @staticmethod
    def _input_times(snapshot: COTResultV1) -> tuple[int | None, int | None]:
        events = []
        available = []
        if snapshot.latest_published_ns is not None:
            events.append(snapshot.latest_published_ns)
        if snapshot.latest_available_ns is not None:
            available.append(snapshot.latest_available_ns)
        for vintage in snapshot.selected_vintages:
            if vintage.published_ns is not None:
                events.append(vintage.published_ns)
            if vintage.available_ns is not None:
                available.append(vintage.available_ns)
            if vintage.received_ns is not None:
                available.append(vintage.received_ns)
        return (max(events) if events else None, max(available) if available else None)

    @classmethod
    def context_for(
        cls,
        snapshot: COTResultV1,
        *,
        decision_as_of_ns: int,
        freshness: Freshness = "fresh",
    ) -> AsOfContextV1:
        event, available = cls._input_times(snapshot)
        if event is None or available is None:
            return issue_as_of_context(
                decision_as_of_ns=decision_as_of_ns,
                freshness=freshness,
                evidence_refs=(),
            )
        return _context_for_result(
            source=f"cftc.cot:{snapshot.market_id}",
            payload=cls._payload(snapshot),
            event_ns=event,
            available_ns=available,
            decision_as_of_ns=decision_as_of_ns,
            freshness=freshness,
        )

    def evaluate(
        self,
        snapshot: COTResultV1,
        instrument: str,
        venue: str,
        context: AsOfContextV1,
        policy: FactorFreshnessPolicyV1 | None = None,
    ) -> FactorOutcomeV1:
        if type(snapshot) is not COTResultV1:
            raise FactorAdapterInputError()
        event_ns, available_ns = self._input_times(snapshot)
        if event_ns is None or available_ns is None:
            return _projection(
                factor_id=self.factor_id,
                family="macro",
                method=self.method,
                method_version=self.method_version,
                instrument=instrument,
                venue=venue,
                value=None,
                scale=Decimal(1),
                reliability=Decimal("0.5") if snapshot.low_confidence else Decimal(1),
                source_event_ns=0,
                context=require_as_of_context(context),
                policy=policy,
                missing_reason="MISSING_EVIDENCE",
            )
        expected = evidence_from_payload(
            source=f"cftc.cot:{snapshot.market_id}",
            payload=self._payload(snapshot),
            source_event_ns=event_ns,
            as_of_ns=available_ns,
        )
        context = _require_exact_evidence(context, (expected,))
        if snapshot.contrarian_tag == "contrarian_long":
            percentile = snapshot.percentile
            value = exact_sub(Decimal(1), percentile) if percentile is not None else None
        elif snapshot.contrarian_tag == "contrarian_short":
            percentile = snapshot.percentile
            value = exact_sub(Decimal(0), percentile) if percentile is not None else None
        else:
            value = Decimal(0)
        return _projection(
            factor_id=self.factor_id,
            family="macro",
            method=self.method,
            method_version=self.method_version,
            instrument=instrument,
            venue=venue,
            value=value,
            scale=Decimal(1),
            reliability=Decimal("0.5") if snapshot.low_confidence else Decimal(1),
            source_event_ns=event_ns,
            context=context,
            policy=policy,
            ineligible=(snapshot.status != "OK" or snapshot.contrarian_tag is None),
        )


class MacroFeatureFactorAdapter(FeatureFactorAdapter):
    """FEAT-backed FRED/BEA/EIA macro projection; source identity stays in FEAT refs."""

    _SOURCE_PREFIXES = ("fred", "bea", "eia")

    def __init__(self, mapping: FactorProjectionPolicyV1) -> None:
        if mapping.family != "macro":
            raise FactorAdapterInputError()
        super().__init__(mapping)

    @classmethod
    def _validate_source(cls, snapshot: FeatureResultV1) -> None:
        if not snapshot.found:
            return
        source = (snapshot.source_dataset or "").casefold()
        if not any(
            source == prefix
            or source.startswith((f"{prefix}.", f"{prefix}:", f"{prefix}/", f"{prefix}_"))
            for prefix in cls._SOURCE_PREFIXES
        ):
            raise FactorAdapterInputError()

    def context_for(
        self,
        snapshot: FeatureResultV1,
        *,
        decision_as_of_ns: int,
        freshness: Freshness = "fresh",
    ) -> AsOfContextV1:
        self._validate_source(require_feature_result(snapshot))
        return super().context_for(
            snapshot, decision_as_of_ns=decision_as_of_ns, freshness=freshness
        )

    def evaluate(
        self,
        snapshot: FeatureResultV1,
        context: AsOfContextV1,
        policy: FactorFreshnessPolicyV1 | None = None,
    ) -> FactorOutcomeV1:
        self._validate_source(require_feature_result(snapshot))
        return super().evaluate(snapshot, context, policy)


__all__ = [
    "COTFactorAdapter",
    "DarkPoolFactorAdapter",
    "FactorAdapterInputError",
    "FactorProjectionPolicyV1",
    "FeatureFactorAdapter",
    "GammaFactorAdapter",
    "IndicatorFactorAdapter",
    "MacroFeatureFactorAdapter",
    "MarketBookFactorAdapter",
    "RegimeFactorAdapter",
]
