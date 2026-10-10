"""Per-record public-source normalizers for the INTEL FactorScoreV1 boundary."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Literal

from leviathan_core.intel.models import (
    FactorAbstentionV1,
    FactorFamily,
    FactorFreshnessPolicyV1,
    FactorOutcomeV1,
    Freshness,
    unix_ns,
)
from leviathan_core.numeric import canonical_str
from leviathan_market_data.public_sources import PublicEvidenceV1, PublicSourceError

from .public_sources_intel import (
    NormalizedPublicFactorV1,
    PublicFactorScoreAdapterV1,
    issue_public_as_of_context,
)


@dataclass(frozen=True, slots=True)
class _Rule:
    factor_id: str
    family: FactorFamily
    factor_tag: str
    method: str


_RULES: dict[str, _Rule] = {
    "sec.edgar.form4": _Rule(
        "public.sec.edgar.form4.insider_activity.v1",
        "insider",
        "insider_activity",
        "form4.open-market-notional",
    ),
    "sec.edgar.13f": _Rule(
        "public.sec.edgar.13f.insider_activity.v1",
        "insider",
        "insider_activity",
        "sec.filing-metadata-only",
    ),
    "sec.edgar.13dg": _Rule(
        "public.sec.edgar.13dg.insider_activity.v1",
        "insider",
        "insider_activity",
        "sec.filing-metadata-only",
    ),
    "house.ptr.bulk": _Rule(
        "public.house.ptr.bulk.insider_activity.v1",
        "insider",
        "insider_activity",
        "house.ptr-index-only",
    ),
    "finra.ats_weekly": _Rule(
        "public.finra.ats_weekly.dark_pool.v1",
        "dark_pool",
        "dark_pool",
        "finra.ats-aggregate-only",
    ),
    "finra.otc.weekly": _Rule(
        "public.finra.otc_weekly.dark_pool.v1",
        "dark_pool",
        "dark_pool",
        "finra.otc-aggregate-only",
    ),
    "finra.regsho.daily": _Rule(
        "public.finra.regsho.daily.short_activity.v1",
        "volume",
        "short_activity",
        "finra.regsho-short-volume-ratio",
    ),
    "finra.short_interest": _Rule(
        "public.finra.short_interest.short_activity.v1",
        "volume",
        "short_activity",
        "finra.short-interest-change-ratio",
    ),
    "cftc.cot.legacy": _Rule(
        "public.cftc.cot.legacy.positioning.v1",
        "macro",
        "positioning",
        "cftc.commercial-net-open-interest-ratio",
    ),
    "treasury.yield_curve": _Rule(
        "public.treasury.yield_curve.rates_macro.v1",
        "macro",
        "rates_macro",
        "treasury.curve-observation-no-baseline",
    ),
    "treasury.fiscal_data": _Rule(
        "public.treasury.fiscal_data.rates_macro.v1",
        "macro",
        "rates_macro",
        "treasury.fiscal-observation-no-baseline",
    ),
    "nyfed.markets": _Rule(
        "public.nyfed.markets.rates_macro.v1",
        "macro",
        "rates_macro",
        "nyfed.observation-no-baseline",
    ),
    "bls.public_api": _Rule(
        "public.bls.public_api.rates_macro.v1",
        "macro",
        "rates_macro",
        "bls.release-no-instrument-mapping",
    ),
    "fed.fomc": _Rule(
        "public.fed.fomc.rates_macro.v1",
        "macro",
        "rates_macro",
        "fed.calendar-event-only",
    ),
    "coinbase.derivatives_us": _Rule(
        "public.coinbase.derivatives_us.crypto_funding.v1",
        "macro",
        "positioning",
        "coinbase.derivatives-funding-rate",
    ),
}


def _values(record: PublicEvidenceV1) -> dict[str, str]:
    return {key.casefold(): value for key, value in record.values}


def _number(values: dict[str, str], *names: str) -> Decimal | None:
    raw = next((values[name.casefold()] for name in names if values.get(name.casefold())), None)
    if raw is None:
        return None
    try:
        value = Decimal(raw)
    except InvalidOperation:
        raise PublicSourceError("MALFORMED_NUMERIC_EVIDENCE") from None
    if not value.is_finite():
        raise PublicSourceError("MALFORMED_NUMERIC_EVIDENCE")
    return value


def _identifier(values: dict[str, str], record: PublicEvidenceV1) -> str:
    symbol = next(
        (
            values[key]
            for key in ("symbol", "issuesymbolidentifier", "symbolcode", "product_code")
            if values.get(key)
        ),
        None,
    )
    if symbol is not None:
        return symbol.upper()
    cik = values.get("cik")
    if cik:
        return f"CIK:{cik}"
    contract = values.get("contract_code") or values.get("cftc_contract_market_code")
    if contract:
        return f"CFTC:{contract}"
    return f"source-record:{record.record_id[:80]}"


def _outcome_abstention(
    *,
    rule: _Rule,
    record: PublicEvidenceV1,
    decision_as_of_ns: int,
    freshness: Freshness,
    reason: Literal[
        "MISSING_EVIDENCE", "STALE_EVIDENCE", "UNKNOWN_FRESHNESS", "INSUFFICIENT_EVIDENCE"
    ],
    instrument: str,
    policy: FactorFreshnessPolicyV1 | None,
) -> FactorAbstentionV1:
    context = issue_public_as_of_context(
        (record,), decision_as_of_ns=decision_as_of_ns, freshness=freshness
    )
    actual_reason = reason
    if not context.evidence_refs:
        actual_reason = (
            "UNKNOWN_FRESHNESS" if context.freshness == "unknown" else "MISSING_EVIDENCE"
        )
    elif context.freshness == "stale":
        actual_reason = "STALE_EVIDENCE"
    elif context.freshness == "unknown" and not (
        policy is not None and policy.allow_unknown_freshness
    ):
        actual_reason = "UNKNOWN_FRESHNESS"
    selected_policy = policy or FactorFreshnessPolicyV1(
        factor_id=rule.factor_id,
        policy_version="public-source/1",
        allow_unknown_freshness=False,
    )
    return FactorAbstentionV1(
        factor_id=rule.factor_id,
        family=rule.family,
        instrument=instrument,
        venue=record.source_id,
        as_of_ns=decision_as_of_ns,
        source_event_ns=unix_ns(record.as_of),
        freshness=context.freshness,
        method=rule.method,
        method_version="1",
        evidence_refs=context.evidence_refs,
        reason=actual_reason,
        freshness_policy_version=selected_policy.policy_version,
        freshness_policy=selected_policy if selected_policy.allow_unknown_freshness else None,
        unknown_freshness_allowed=selected_policy.allow_unknown_freshness
        and context.freshness == "unknown",
    )


class PublicSourceFactorAdapterV1:
    """Normalize one evidence record at a time; never blends unrelated source rows."""

    def __init__(self) -> None:
        self._scorer = PublicFactorScoreAdapterV1()

    def evaluate_record(
        self,
        record: PublicEvidenceV1,
        *,
        decision_as_of_ns: int,
        freshness: Freshness,
        instrument: str | None = None,
        policy: FactorFreshnessPolicyV1 | None = None,
    ) -> FactorOutcomeV1:
        if type(record) is not PublicEvidenceV1 or record.redistribution is not False:
            raise PublicSourceError("INVALID_PUBLIC_EVIDENCE")
        if type(decision_as_of_ns) is not int or decision_as_of_ns < 0:
            raise PublicSourceError("INVALID_DECISION_ASOF")
        rule = _RULES.get(record.source_id)
        if rule is None:
            raise PublicSourceError("UNMAPPED_PUBLIC_SOURCE")
        if policy is not None and (
            type(policy) is not FactorFreshnessPolicyV1 or policy.factor_id != rule.factor_id
        ):
            raise PublicSourceError("FACTOR_FRESHNESS_POLICY_MISMATCH")
        if rule.factor_tag not in record.factor_tags:
            raise PublicSourceError("FACTOR_TAG_MISMATCH")
        values = _values(record)
        symbol = instrument or _identifier(values, record)

        # Signed, source-native signals with a fixed, inspectable normalization.
        if record.source_id == "sec.edgar.form4":
            code = values.get("transaction_code", "").upper()
            shares = _number(values, "shares", "transactionshares")
            price = _number(values, "price", "transactionpricepershare")
            if (
                code not in {"P", "S"}
                or shares is None
                or price is None
                or shares <= 0
                or price <= 0
            ):
                return _outcome_abstention(
                    rule=rule,
                    record=record,
                    decision_as_of_ns=decision_as_of_ns,
                    freshness=freshness,
                    reason="INSUFFICIENT_EVIDENCE",
                    instrument=symbol,
                    policy=policy,
                )
            notional = shares * price
            direction: Literal["long", "short", "neutral"] = "long" if code == "P" else "short"
            strength = notional / (notional + Decimal("1000000"))
            reliability = Decimal("0.7")
        elif record.source_id == "finra.regsho.daily":
            short = _number(values, "short_volume")
            total = _number(values, "total_volume")
            if short is None or total is None or total <= 0 or short > total:
                return _outcome_abstention(
                    rule=rule,
                    record=record,
                    decision_as_of_ns=decision_as_of_ns,
                    freshness=freshness,
                    reason="INSUFFICIENT_EVIDENCE",
                    instrument=symbol,
                    policy=policy,
                )
            direction = "neutral"
            strength = short / total
            reliability = Decimal("0.5")
        elif record.source_id == "finra.short_interest":
            current = _number(
                values, "currentshortpositionquantity", "shortpositionquantity", "shortinterest"
            )
            previous = _number(values, "previousshortpositionquantity", "previousshortinterest")
            if current is None or previous is None or min(current, previous) < 0:
                return _outcome_abstention(
                    rule=rule,
                    record=record,
                    decision_as_of_ns=decision_as_of_ns,
                    freshness=freshness,
                    reason="INSUFFICIENT_EVIDENCE",
                    instrument=symbol,
                    policy=policy,
                )
            change = current - previous
            denom = current + previous
            if denom <= 0 or change == 0:
                return _outcome_abstention(
                    rule=rule,
                    record=record,
                    decision_as_of_ns=decision_as_of_ns,
                    freshness=freshness,
                    reason="INSUFFICIENT_EVIDENCE",
                    instrument=symbol,
                    policy=policy,
                )
            direction = "short" if change > 0 else "long"
            strength = abs(change) / denom
            reliability = Decimal("0.6")
        elif record.source_id == "cftc.cot.legacy":
            long = _number(values, "commercial_long")
            short = _number(values, "commercial_short")
            open_interest = _number(values, "open_interest")
            if (
                long is None
                or short is None
                or open_interest is None
                or min(long, short) < 0
                or open_interest <= 0
                or long == short
            ):
                return _outcome_abstention(
                    rule=rule,
                    record=record,
                    decision_as_of_ns=decision_as_of_ns,
                    freshness=freshness,
                    reason="INSUFFICIENT_EVIDENCE",
                    instrument=symbol,
                    policy=policy,
                )
            net = long - short
            direction = "long" if net > 0 else "short"
            strength = min(abs(net) / open_interest, Decimal(1))
            reliability = Decimal("0.6")
        elif record.source_id == "coinbase.derivatives_us":
            funding = _number(values, "funding_rate")
            if funding is None or funding == 0:
                return _outcome_abstention(
                    rule=rule,
                    record=record,
                    decision_as_of_ns=decision_as_of_ns,
                    freshness=freshness,
                    reason="INSUFFICIENT_EVIDENCE",
                    instrument=symbol,
                    policy=policy,
                )
            # Positive funding means longs pay shorts; negative means shorts pay longs.
            direction = "short" if funding > 0 else "long"
            strength = min(abs(funding), Decimal(1))
            reliability = Decimal("0.5")
        else:
            # Filing indexes, dark-pool totals, one-point rates/macro observations, and
            # calendars do not by themselves establish a signed, comparable factor.
            return _outcome_abstention(
                rule=rule,
                record=record,
                decision_as_of_ns=decision_as_of_ns,
                freshness=freshness,
                reason="INSUFFICIENT_EVIDENCE",
                instrument=symbol,
                policy=policy,
            )

        context = issue_public_as_of_context(
            (record,), decision_as_of_ns=decision_as_of_ns, freshness=freshness
        )
        normalized = NormalizedPublicFactorV1(
            factor_id=rule.factor_id,
            family=rule.family,
            instrument=symbol,
            venue=record.source_id,
            decision_as_of_ns=decision_as_of_ns,
            source_event_ns=unix_ns(record.as_of),
            direction=direction,
            strength=canonical_str(strength),
            reliability=canonical_str(reliability),
            method=rule.method,
            method_version="1",
            evidence=(record,),
            freshness=context.freshness,
        )
        return self._scorer.evaluate(normalized, context, policy)

    def evaluate_records(
        self,
        records: tuple[PublicEvidenceV1, ...],
        *,
        decision_as_of_ns: int,
        freshness: Freshness,
        policy: FactorFreshnessPolicyV1 | None = None,
    ) -> tuple[FactorOutcomeV1, ...]:
        """Return one typed outcome per source row; no cross-source aggregation occurs."""
        if type(records) is not tuple or len(records) > 128:
            raise PublicSourceError("TOO_MANY_EVIDENCE_REFS")
        outcomes = tuple(
            self.evaluate_record(
                record,
                decision_as_of_ns=decision_as_of_ns,
                freshness=freshness,
                policy=policy,
            )
            for record in records
        )
        return outcomes


__all__ = ["PublicSourceFactorAdapterV1"]
