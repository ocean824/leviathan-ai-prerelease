"""Pure, point-in-time normalization of recorded prediction-market quotes."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import fields, replace
from decimal import Decimal
from fractions import Fraction
from itertools import islice

from leviathan_core.numeric import NumericError, Ratio, canonical_json, quotient_final
from leviathan_core.seal import SealError, require

from .models import (
    _RESOLUTION_ISSUER,
    FXRateV1,
    NormalizedPriorV1,
    OutcomeProbabilityV1,
    PredictionError,
    PredictionSourceRecordV1,
    ResolutionEventV1,
    SourceReferenceV1,
    _fx_identity,
    _issue_prior,
    _ns,
    _token,
)

_STALE_NS = 30_000_000_000
_DEPTH_SCALE = Fraction(5_000)


def _record_key(row: PredictionSourceRecordV1) -> bytes:
    return canonical_json({field.name: getattr(row, field.name) for field in fields(row)})


def _resolution_identity(event: ResolutionEventV1) -> str:
    content = {field.name: getattr(event, field.name) for field in fields(event)}
    return hashlib.sha256(canonical_json(content)).hexdigest()


def _selected_fx(
    currency: str, quote_ns: int, asof_ns: int, rates: tuple[FXRateV1, ...]
) -> FXRateV1 | None:
    if currency == "USD":
        return None
    eligible = [
        rate
        for rate in rates
        if rate.from_currency == currency
        and rate.to_currency == "USD"
        and rate.observed_ns <= quote_ns
        and rate.available_ns <= quote_ns
        and rate.available_ns <= asof_ns
    ]
    if not eligible:
        return None
    latest = max((rate.observed_ns, rate.available_ns) for rate in eligible)
    tied = [rate for rate in eligible if (rate.observed_ns, rate.available_ns) == latest]
    if len({(rate.rate, rate.version, rate.source_id) for rate in tied}) > 1:
        raise PredictionError("FX_CONFLICT", "fx_rates")
    return tied[0]


def _final_fraction(value: Fraction) -> Decimal:
    try:
        return quotient_final(Ratio(value.numerator, value.denominator), 1)
    except NumericError as exc:
        raise PredictionError(exc.code, "probability") from None


def normalize(
    records: Iterable[PredictionSourceRecordV1],
    *,
    outcome_ids: tuple[str, ...],
    asof_ns: int,
    fx_rates: tuple[FXRateV1, ...] = (),
    calibration_id: str = "IDENTITY",
    calibration_revision: str = "identity-v1",
    mapping_revision: str = "unmapped-v1",
    resolution: ResolutionEventV1 | None = None,
) -> NormalizedPriorV1:
    """Return one sealed research prior. This never grants hedge permission."""
    _ns(asof_ns, "asof_ns")
    if type(outcome_ids) is not tuple or not 2 <= len(outcome_ids) <= 32:
        raise PredictionError("OUTCOME_VECTOR_INVALID", "outcome_ids")
    for outcome_id in outcome_ids:
        _token(outcome_id, "outcome_ids")
    if len(set(outcome_ids)) != len(outcome_ids):
        raise PredictionError("OUTCOME_VECTOR_INVALID", "outcome_ids")
    if (
        type(fx_rates) is not tuple
        or len(fx_rates) > 256
        or any(type(rate) is not FXRateV1 for rate in fx_rates)
    ):
        raise PredictionError("FX_INPUT_INVALID", "fx_rates")
    fx_rates = tuple(replace(rate) for rate in fx_rates)
    _token(calibration_id, "calibration_id")
    if not calibration_revision:
        raise PredictionError("CALIBRATION_VERSION_MISSING", "calibration_revision")
    _token(calibration_revision, "calibration_revision")
    _token(mapping_revision, "mapping_revision")
    if calibration_id != "IDENTITY":
        raise PredictionError("CALIBRATION_UNSUPPORTED", "calibration_id")
    if calibration_revision != "identity-v1":
        raise PredictionError("CALIBRATION_VERSION_UNSUPPORTED", "calibration_revision")
    try:
        rows = tuple(islice(iter(records), 257))
    except Exception:
        raise PredictionError("SOURCE_INPUT_INVALID", "records") from None
    if (
        not rows
        or len(rows) > 256
        or any(type(row) is not PredictionSourceRecordV1 for row in rows)
    ):
        raise PredictionError("SOURCE_INPUT_INVALID", "records")
    rows = tuple(replace(row) for row in rows)
    # The requested snapshot cannot be affected by future rows, even malformed
    # market identities or extra outcomes learned after as-of.
    visible = [row for row in rows if row.available_ns <= asof_ns]
    if not visible:
        raise PredictionError("OUTCOME_MISSING", "records")
    first = visible[0]
    if any((row.venue, row.contract_id) != (first.venue, first.contract_id) for row in visible):
        raise PredictionError("MARKET_IDENTITY_MISMATCH", "records")
    expected = set(outcome_ids)
    if any(row.outcome_id not in expected for row in visible):
        raise PredictionError("UNEXPECTED_OUTCOME", "records")
    chosen: list[PredictionSourceRecordV1] = []
    flags: set[str] = set()
    for outcome_id in sorted(expected):
        candidates = [row for row in visible if row.outcome_id == outcome_id]
        if not candidates:
            raise PredictionError("OUTCOME_MISSING", "records")
        latest = max((row.event_ns, row.received_ns, row.available_ns) for row in candidates)
        tied = [
            row for row in candidates if (row.event_ns, row.received_ns, row.available_ns) == latest
        ]
        if len({_record_key(row) for row in tied}) > 1:
            raise PredictionError("QUOTE_CONFLICT", "records")
        selected = tied[0]
        chosen.append(selected)
        if any(
            row.received_ns > selected.received_ns and row.event_ns < selected.event_ns
            for row in candidates
        ):
            flags.add("LATE_QUOTE")

    statuses = {row.market_status for row in chosen}
    if len(statuses) != 1:
        raise PredictionError("STATUS_CONFLICT", "records")
    status = chosen[0].market_status
    if len({row.resolution_version for row in chosen}) > 1:
        raise PredictionError("RESOLUTION_VERSION_CONFLICT", "records")
    ages = [asof_ns - row.event_ns for row in chosen]
    age = max(ages)
    if age > _STALE_NS:
        flags.add("STALE_QUOTE")
    access_classes = {row.access_class for row in chosen}
    if len(access_classes) > 1:
        flags.add("MIXED_ACCESS")
    if any(row.raw_quote_digest is None for row in chosen):
        flags.add("QUOTE_PROVENANCE_MISSING")
    if any(row.depth_1pct is None or row.depth_2pct is None for row in chosen):
        flags.add("MISSING_LIQUIDITY")
    if any(row.depth_2pct == 0 for row in chosen):
        flags.add("ZERO_LIQUIDITY")
    if status != "ACTIVE":
        flags.add("MARKET_" + status)

    effective: list[Fraction] = []
    for row in chosen:
        midpoint = (Fraction(row.bid) + Fraction(row.ask)) / 2
        effective.append(midpoint * (1 + Fraction(row.fee_rate)))
    total = sum(effective, Fraction(0))
    if total <= 0:
        raise PredictionError("ZERO_MARKET_PRICE", "records")
    probabilities = tuple(
        OutcomeProbabilityV1(row.outcome_id, _final_fraction(price / total))
        for row, price in zip(chosen, effective, strict=True)
    )

    conversion_versions: set[str] = set()
    conversion_by_outcome: dict[str, FXRateV1 | None] = {}
    liquidity = Fraction(0)
    missing_fx = False
    for row in chosen:
        if row.currency == "USD":
            rate = Fraction(1)
            conversion_by_outcome[row.outcome_id] = None
        else:
            fx = _selected_fx(row.currency, row.event_ns, asof_ns, fx_rates)
            if fx is None:
                missing_fx = True
                conversion_by_outcome[row.outcome_id] = None
                continue
            conversion_by_outcome[row.outcome_id] = fx
            conversion_versions.add(_fx_identity(fx))
            rate = Fraction(fx.rate)
        if row.depth_1pct is None or row.depth_2pct is None:
            continue
        liquidity += (Fraction(row.depth_1pct) + Fraction(row.depth_2pct)) * rate / 2
    if missing_fx:
        flags.add("FX_MISSING")
    spread = max(Fraction(row.ask) - Fraction(row.bid) for row in chosen)
    volatility = max(Fraction(row.volatility) for row in chosen)
    reliability = min(Fraction(row.source_reliability) for row in chosen)
    confidence_ratio = (
        liquidity
        / (liquidity + _DEPTH_SCALE)
        * (1 - spread)
        * Fraction(_STALE_NS, _STALE_NS + age)
        * Fraction(1, 1)
        / (1 + volatility)
        * reliability
    )
    if "MISSING_LIQUIDITY" in flags or "ZERO_LIQUIDITY" in flags:
        confidence_ratio = min(confidence_ratio, Fraction(19, 100))
    if "FX_MISSING" in flags:
        confidence_ratio = min(confidence_ratio, Fraction(1, 10))
    if "QUOTE_PROVENANCE_MISSING" in flags:
        confidence_ratio = Fraction(0)
    if "STALE_QUOTE" in flags or status != "ACTIVE":
        confidence_ratio = Fraction(0)

    resolution_identity: str | None = None
    if resolution is not None:
        if type(resolution) is not ResolutionEventV1:
            raise PredictionError("UNVERIFIED_RESOLUTION", "resolution")
        if resolution.available_ns <= asof_ns:
            try:
                require(resolution, _RESOLUTION_ISSUER.tag)
            except SealError:
                raise PredictionError("UNVERIFIED_RESOLUTION", "resolution") from None
            if (resolution.venue, resolution.contract_id) != (first.venue, first.contract_id):
                raise PredictionError("RESOLUTION_IDENTITY_MISMATCH", "resolution")
            if status != "RESOLVED" or resolution.version != chosen[0].resolution_version:
                raise PredictionError("RESOLUTION_VERSION_MISMATCH", "resolution")
            resolution_identity = _resolution_identity(resolution)
            if resolution.disputed:
                flags.add("RESOLUTION_DISPUTED")
            elif resolution.winning_outcome_id not in expected:
                raise PredictionError("RESOLUTION_WINNER_UNKNOWN", "resolution")
    if status == "RESOLVED":
        flags.add("RESOLUTION_UNVERIFIED")
        confidence_ratio = Fraction(0)

    return _issue_prior(
        venue=first.venue,
        contract_id=first.contract_id,
        outcomes=probabilities,
        source_refs=tuple(
            SourceReferenceV1(
                outcome_id=row.outcome_id,
                source_id=row.source_id,
                raw_quote_digest=row.raw_quote_digest,
                access_class=row.access_class,
                entitlement_ref=row.entitlement_ref,
                account_ref=row.account_ref,
                event_ns=row.event_ns,
                available_ns=row.available_ns,
                currency=row.currency,
                conversion_ref=conversion_by_outcome.get(row.outcome_id),
            )
            for row in chosen
        ),
        confidence=_final_fraction(confidence_ratio),
        source_ids=tuple(sorted({row.source_id for row in chosen})),
        raw_quote_digests=tuple(
            sorted({row.raw_quote_digest for row in chosen if row.raw_quote_digest is not None})
        ),
        access_classes=tuple(sorted(access_classes)),
        quote_age_ns=age,
        conversion_versions=tuple(sorted(conversion_versions)),
        resolution_identity=resolution_identity,
        calibration_id=calibration_id,
        calibration_revision=calibration_revision,
        mapping_revision=mapping_revision,
        quality_flags=tuple(sorted(flags)),
        market_status=status,
        asof_ns=asof_ns,
        hedge_eligible=False,
    )
