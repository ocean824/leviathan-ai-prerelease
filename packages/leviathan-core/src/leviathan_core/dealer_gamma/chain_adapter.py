"""GEX-002: pure translation of an entitled option-chain envelope into GEX-001 inputs.

No provider, network or credential is touched. A reviewed provider manifest
(``OptionChainSourcePortV1``) and a recorded envelope (``ChainEnvelopeV1``) are the
only inputs, and the clock is the explicit ``asof_ns`` argument.

Conventions (versioned, never inferred):

* Greek: ``GAMMA_PER_UNDERLYING_UNIT_V1``, gamma as the change of delta per one
  underlying price unit. Any other, or an unverified, convention is UNAVAILABLE.
* Units: spot in quote currency per underlying unit, IV as an annualized decimal
  fraction (not a percentage), open interest in contracts.
* Open interest is the official prior-close figure and is labelled with that
  date and its official close timestamp. An intraday OI family is UNAVAILABLE.
* Entitlement is proven by the manifest and by each row's Greek entitlement. An
  API key is never evidence of entitlement.

The adapter infers no dealer position or sign and produces no pin probability.
LIVE and SETTLED horizons carry separate provenance. A settled horizon is mapped
only from independent settled evidence with an official settlement timestamp and
is never copied from live. Non-finite Decimals are rejected when an envelope is
built, so every accepted gamma is finite.
"""

from __future__ import annotations

from datetime import date
from decimal import Decimal, localcontext
from fractions import Fraction
from itertools import pairwise
from typing import Annotated, Final, Literal

from pydantic import Field, StringConstraints, model_validator

from leviathan_core.seal import MAX_DIGEST_NODES_CEILING, Issuer, SealedModel, require, verify

from .models import (
    KERNEL_CONTEXT,
    MAX_GREEK_AGE_NS,
    MAX_IV_AGE_NS,
    MAX_OI_AGE_NS,
    MAX_QUOTE_AGE_NS,
    MAX_SPOT_AGE_NS,
    ChainSnapshotV1,
    DeliverableLegV1,
    ExchangeCalendarV1,
    GammaSnapshotV1,
    OptionSeriesEvidenceV1,
    exact_fraction_decimal,
)

ADAPTER_VERSION: Final = "gex002.chain_adapter.v1"
ADAPTATION_TAG: Final = "gex002.chain_adaptation.v1"
GREEK_CONVENTION_V1: Final = "GAMMA_PER_UNDERLYING_UNIT_V1"
SUPPORTED_GREEK_CONVENTIONS: Final = frozenset({GREEK_CONVENTION_V1})
GAMMA_UNIT: Final = "PER_UNDERLYING_UNIT"
SPOT_UNIT: Final = "QUOTE_CURRENCY_PER_UNDERLYING_UNIT"
IV_UNIT: Final = "DECIMAL_ANNUALIZED"
OI_UNIT: Final = "CONTRACTS"
OI_FAMILY_OFFICIAL_PRIOR_CLOSE: Final = "OFFICIAL_PRIOR_CLOSE"
UNDERLIER_BASES: Final = frozenset({"CASH_INDEX", "ETF_SPOT", "EQUITY_SPOT", "FUTURES_ADJUSTED"})
SUPPORTED_EXPIRY_KINDS: Final = frozenset({"WEEKLY", "MONTHLY"})
SUPPORTED_SETTLEMENTS: Final = frozenset({"AM", "PM"})

_MAX_NS: Final = 2**63 - 1
_ZERO: Final = Decimal("0")
_ONE: Final = Decimal("1")
_MIN_COVERAGE: Final = Fraction(4, 5)
_STATUS_ORDER: Final = {"OK": 0, "DEGRADED": 1, "STALE": 2, "UNAVAILABLE": 3}

_Id = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")]
_Ns = Annotated[int, Field(ge=0, le=_MAX_NS)]
_Currency = Annotated[str, StringConstraints(pattern=r"^[A-Z]{3}$")]
Entitlement = Literal["ENTITLED", "DENIED", "UNKNOWN"]
AdaptStatus = Literal["OK", "DEGRADED", "STALE", "UNAVAILABLE"]
DataState = Literal["LIVE", "SETTLED"]


class ChainAdapterError(ValueError):
    """Content-free argument error; no source value is ever echoed."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class _Model(SealedModel):
    """Base of every adapter record: frozen, strict and extra-forbidding."""


class OptionChainSourcePortV1(_Model):
    """Reviewed provider manifest: entitlement, conventions and timestamped coverage."""

    manifest_id: _Id
    manifest_version: _Id
    provider_id: _Id
    source_id: _Id
    dataset_id: _Id
    chain_entitlement_status: Entitlement
    chain_entitlement_id: _Id | None
    api_key_present: bool  # never evidence of entitlement
    entitled_underliers: tuple[_Id, ...]
    coverage_start_ns: _Ns  # entitlement and source validity window, UTC ns
    coverage_end_ns: _Ns
    quote_source_id: _Id
    spot_source_id: _Id
    iv_source_id: _Id
    oi_source_id: _Id
    spot_unit: _Id
    iv_unit: _Id
    oi_unit: _Id
    gamma_unit: _Id
    greek_convention: _Id
    greek_convention_verified: bool
    oi_family: _Id
    supported_expiry_kinds: tuple[_Id, ...]
    supported_settlements: tuple[_Id, ...]
    corporate_action_version: _Id

    @model_validator(mode="after")
    def _window_ordered(self) -> OptionChainSourcePortV1:
        if self.coverage_end_ns < self.coverage_start_ns:
            raise ValueError("coverage window reversed")
        return self


class ChainDeliverableV1(_Model):
    kind: Literal["UNDERLIER", "CASH", "OTHER_ASSET"]
    asset_id: _Id
    units: Decimal
    currency: _Currency


class ChainSessionV1(_Model):
    """Complete market-session provenance for one horizon."""

    calendar_id: _Id
    calendar_version: _Id
    session_source: _Id
    trade_date: date
    session_open_ns: _Ns
    session_close_ns: _Ns
    early_close: bool
    trading_session: bool


class ChainRowV1(_Model):
    """One provider row for one option contract."""

    row_id: _Id
    row_revision: Annotated[int, Field(ge=0, le=2**31)]
    corrects_row_id: _Id | None
    correction_id: _Id | None
    contract_id: _Id
    venue: _Id
    underlier: _Id
    option_type: Literal["CALL", "PUT"]
    strike: Decimal
    expiry_date: date  # exchange-local
    expiry_kind: _Id
    settlement: _Id
    expiry_cutoff_ns: _Ns
    multiplier: Decimal
    currency: _Currency
    deliverable_units: tuple[ChainDeliverableV1, ...]
    open_interest: Decimal
    oi_family: _Id
    oi_asof_date: date  # official prior-close date
    oi_official_close_ns: _Ns
    spot: Decimal
    spot_observed_ns: _Ns
    spot_available_ns: _Ns
    bid: Decimal | None
    ask: Decimal | None
    quote_observed_ns: _Ns
    quote_available_ns: _Ns
    implied_vol: Decimal
    iv_observed_ns: _Ns
    iv_available_ns: _Ns
    gamma: Decimal
    gamma_units: _Id
    greek_observed_ns: _Ns
    greek_available_ns: _Ns
    greek_entitlement_status: Entitlement
    greek_entitlement_id: _Id | None
    published_ns: _Ns
    underlier_basis: _Id
    futures_basis_id: _Id | None
    corporate_action_version: _Id
    split_factor: Decimal
    multiplier_basis: Literal["PRE_ACTION", "POST_ACTION_ADJUSTED"] | None
    adjustment_version: _Id | None
    halted: bool


class ChainHorizonV1(_Model):
    """One independently timestamped LIVE or SETTLED chain."""

    data_state: DataState
    snapshot_id: _Id
    source_chain_id: _Id
    revision: Annotated[int, Field(ge=0, le=2**31)]
    venue: _Id
    observed_ns: _Ns
    published_ns: _Ns
    available_ns: _Ns
    official_settlement_ns: _Ns | None
    session: ChainSessionV1
    eligible_expiries: tuple[date, ...]
    eligible_oi_denominator: Decimal | None
    expected_series_count: Annotated[int, Field(ge=0, le=2**31)] | None
    chain_complete: bool
    rows: tuple[ChainRowV1, ...]

    @model_validator(mode="after")
    def _settlement_only_when_settled(self) -> ChainHorizonV1:
        if self.data_state == "LIVE" and self.official_settlement_ns is not None:
            raise ValueError("live horizon cannot carry a settlement timestamp")
        return self


class ChainEnvelopeV1(_Model):
    envelope_id: _Id
    manifest_id: _Id
    underlier: _Id
    live: ChainHorizonV1 | None
    settled: ChainHorizonV1 | None

    @model_validator(mode="after")
    def _horizon_states(self) -> ChainEnvelopeV1:
        if self.live is not None and self.live.data_state != "LIVE":
            raise ValueError("live horizon must be LIVE")
        if self.settled is not None and self.settled.data_state != "SETTLED":
            raise ValueError("settled horizon must be SETTLED")
        return self


class ChainExclusionV1(_Model):
    series_id: _Id
    reason: _Id


class ChainHorizonResultV1(_Model):
    """Per-horizon outcome with its own provenance; never shared across horizons."""

    data_state: DataState
    status: AdaptStatus
    reasons: tuple[_Id, ...]
    snapshot_id: _Id
    source_chain_id: _Id
    revision: int
    manifest_id: _Id
    source_id: _Id
    dataset_id: _Id
    observed_ns: int
    published_ns: int
    available_ns: int
    official_settlement_ns: int | None
    entitlement_ids: tuple[_Id, ...]
    correction_ids: tuple[_Id, ...]
    mapped_series_ids: tuple[_Id, ...]
    excluded: tuple[ChainExclusionV1, ...]
    oi_family: _Id | None
    oi_asof_dates: tuple[date, ...]
    coverage_numerator: Decimal | None
    coverage_denominator: Decimal | None
    coverage_exact: tuple[int, int] | None
    coverage_ratio: Decimal | None
    spot_age_ns: int | None
    iv_age_ns: int | None
    oi_age_ns: int | None
    has_0dte: bool


class ChainAdaptationV1(_Model):
    """Issued adapter result. ``snapshot`` omits any horizon that is UNAVAILABLE."""

    status: AdaptStatus  # worst status across present horizons
    reasons: tuple[_Id, ...]
    asof_ns: int
    adapter_version: _Id
    manifest_id: _Id
    live: ChainHorizonResultV1 | None
    settled: ChainHorizonResultV1 | None
    snapshot: GammaSnapshotV1 | None
    dealer_sign_inferred: Literal[False] = False
    pin_probability: None = None


_ISSUER = Issuer(ADAPTATION_TAG, max_digest_nodes=MAX_DIGEST_NODES_CEILING)


def verify_adaptation(value: object) -> bool:
    return type(value) is ChainAdaptationV1 and verify(value, _ISSUER.tag)


def require_adaptation(value: ChainAdaptationV1) -> ChainAdaptationV1:
    return require(value, _ISSUER.tag)


def _series_id(row: ChainRowV1) -> str:
    return f"{row.venue}:{row.contract_id}"


def _manifest_reasons(port: OptionChainSourcePortV1, envelope: ChainEnvelopeV1) -> list[str]:
    hard: list[str] = []
    if envelope.manifest_id != port.manifest_id:
        hard.append("MANIFEST_MISMATCH")
    if port.chain_entitlement_status != "ENTITLED" or port.chain_entitlement_id is None:
        hard.append("MISSING_CHAIN_ENTITLEMENT")
    elif envelope.underlier not in port.entitled_underliers:
        hard.append("UNENTITLED_UNDERLIER")
    if (port.greek_convention not in SUPPORTED_GREEK_CONVENTIONS
            or not port.greek_convention_verified or port.gamma_unit != GAMMA_UNIT):
        hard.append("UNVERIFIED_GREEK_CONVENTION")
    if (port.spot_unit, port.iv_unit, port.oi_unit) != (SPOT_UNIT, IV_UNIT, OI_UNIT):
        hard.append("UNVERIFIED_UNITS")
    if port.oi_family != OI_FAMILY_OFFICIAL_PRIOR_CLOSE:
        hard.append("OI_FAMILY_UNSUPPORTED")
    return hard


def _resolve_rows(
    rows: tuple[ChainRowV1, ...],
) -> tuple[list[ChainRowV1], list[str], list[ChainExclusionV1]]:
    """Collapse exact replays and corrections; conflicting duplicates fail closed."""
    groups: dict[tuple[str, str], list[ChainRowV1]] = {}
    for row in rows:
        groups.setdefault((row.venue, row.contract_id), []).append(row)
    kept: list[ChainRowV1] = []
    hard: list[str] = []
    excluded: list[ChainExclusionV1] = []
    for group in groups.values():
        unique: list[ChainRowV1] = []
        for row in group:
            if row not in unique:
                unique.append(row)
        if len(unique) == 1:
            kept.append(unique[0])
            continue
        ordered = sorted(unique, key=lambda item: item.row_revision)
        chained = all(
            later.row_revision > earlier.row_revision
            and later.corrects_row_id == earlier.row_id and later.correction_id is not None
            for earlier, later in pairwise(ordered)
        )
        if chained:
            kept.append(ordered[-1])
            excluded.extend(ChainExclusionV1(series_id=_series_id(row),
                                             reason="SUPERSEDED_BY_CORRECTION")
                            for row in ordered[:-1])
            continue
        hard.append("DUPLICATE_CONFLICTING_CONTRACT")
        excluded.extend(ChainExclusionV1(series_id=_series_id(row),
                                         reason="DUPLICATE_CONFLICTING_CONTRACT")
                        for row in ordered)
    return kept, hard, excluded


def _deliverable_problem(row: ChainRowV1, underlier: str) -> tuple[str, str] | None:
    if not row.deliverable_units:
        return ("hard", "DELIVERABLE_UNITS_MISSING")
    if any(leg.units < _ZERO for leg in row.deliverable_units):
        return ("degraded", "NEGATIVE_DELIVERABLE_UNITS")
    if any(leg.kind == "OTHER_ASSET" for leg in row.deliverable_units):
        return ("degraded", "NON_STANDARD_DELIVERABLE_OTHER_ASSET")
    legs = [leg for leg in row.deliverable_units if leg.kind == "UNDERLIER"]
    if any(leg.asset_id != underlier for leg in legs):
        return ("hard", "DELIVERABLE_UNDERLIER_MISMATCH")
    if any(leg.currency != row.currency for leg in legs):
        return ("hard", "DELIVERABLE_CURRENCY_MISMATCH")
    units = sum((Fraction(leg.units) for leg in legs), Fraction())
    expected = Fraction(row.multiplier) * (
        Fraction(row.split_factor) if row.multiplier_basis == "PRE_ACTION" else 1
    )
    if units != expected:
        return ("hard", "DELIVERABLE_MULTIPLIER_MISMATCH")
    return None


def _row_problem(
    row: ChainRowV1, port: OptionChainSourcePortV1, horizon: ChainHorizonV1,
    underlier: str, asof_ns: int, clock_ns: int,
) -> tuple[str, str] | None:
    """First failing check as (severity, reason); severity is hard, degraded or info."""
    session = horizon.session
    if row.underlier != underlier:
        return ("hard", "MIXED_UNDERLIER")
    if row.venue != horizon.venue:
        return ("hard", "MIXED_VENUE")
    if row.expiry_date < session.trade_date or row.expiry_cutoff_ns <= clock_ns:
        return ("info", "EXPIRED_SERIES")
    if row.expiry_date not in horizon.eligible_expiries:
        return ("info", "EXPIRY_NOT_ELIGIBLE")
    if (row.expiry_kind not in port.supported_expiry_kinds
            or row.expiry_kind not in SUPPORTED_EXPIRY_KINDS
            or row.settlement not in port.supported_settlements
            or row.settlement not in SUPPORTED_SETTLEMENTS):
        return ("hard", "UNSUPPORTED_EXPIRY")
    if row.halted:
        return ("degraded", "HALTED_SERIES")
    if row.oi_family != port.oi_family:
        return ("hard", "OI_FAMILY_MISMATCH")
    if (row.oi_asof_date >= session.trade_date
            or row.oi_official_close_ns > session.session_open_ns):
        return ("hard", "OI_NOT_OFFICIAL_PRIOR_CLOSE")
    if row.gamma_units != port.gamma_unit:
        return ("hard", "UNVERIFIED_GREEK_CONVENTION")
    if row.greek_entitlement_status != "ENTITLED" or row.greek_entitlement_id is None:
        return ("degraded", "MISSING_GREEK_ENTITLEMENT")
    if min(row.strike, row.multiplier, row.spot, row.implied_vol) <= _ZERO:
        return ("degraded", "NONPOSITIVE_INPUT")
    if row.gamma < _ZERO or row.open_interest < _ZERO:
        return ("degraded", "NEGATIVE_INPUT")
    if (row.bid is not None and row.bid < _ZERO) or (row.ask is not None and row.ask < _ZERO) \
            or (row.bid is not None and row.ask is not None and row.ask < row.bid):
        return ("degraded", "CROSSED_QUOTE")
    pairs = ((row.spot_observed_ns, row.spot_available_ns),
             (row.quote_observed_ns, row.quote_available_ns),
             (row.iv_observed_ns, row.iv_available_ns),
             (row.greek_observed_ns, row.greek_available_ns))
    if (any(available < observed for observed, available in pairs)
            or row.published_ns < max(observed for observed, _ in pairs)
            or row.published_ns > max(available for _, available in pairs)):
        return ("degraded", "PROVENANCE_INCONSISTENT")
    if row.underlier_basis not in UNDERLIER_BASES or (
            row.underlier_basis == "FUTURES_ADJUSTED" and row.futures_basis_id is None):
        return ("hard", "UNDERLYING_BASIS_UNVERIFIED")
    if row.corporate_action_version != port.corporate_action_version:
        return ("hard", "CORPORATE_ACTION_VERSION_MISMATCH")
    if row.multiplier_basis is None:
        return ("hard", "ADJUSTMENT_BASIS_UNKNOWN")
    if row.adjustment_version is None:
        return ("hard", "ADJUSTMENT_VERSION_MISSING")
    if row.split_factor <= _ZERO:
        return ("hard", "INVALID_SPLIT_FACTOR")
    deliverable = _deliverable_problem(row, underlier)
    if deliverable is not None:
        return deliverable
    if max(row.spot_available_ns, row.quote_available_ns, row.iv_available_ns,
           row.greek_available_ns) > asof_ns:
        return ("degraded", "EVIDENCE_NOT_AVAILABLE")
    if row.oi_official_close_ns > clock_ns:
        return ("degraded", "FUTURE_OI")
    return None


def _series_evidence(
    row: ChainRowV1, port: OptionChainSourcePortV1, horizon: ChainHorizonV1,
) -> OptionSeriesEvidenceV1:
    return OptionSeriesEvidenceV1(
        series_id=_series_id(row), underlier=row.underlier, contract=row.contract_id,
        venue=row.venue, option_type=row.option_type, strike=row.strike,
        expiry_date=row.expiry_date, expiry_kind=row.expiry_kind, settlement=row.settlement,
        expiry_cutoff_ns=row.expiry_cutoff_ns, multiplier=row.multiplier,
        currency=row.currency, open_interest=row.open_interest,
        oi_asof_ns=row.oi_official_close_ns, spot=row.spot,
        spot_observed_ns=row.spot_observed_ns, spot_available_ns=row.spot_available_ns,
        bid=row.bid, ask=row.ask, quote_observed_ns=row.quote_observed_ns,
        quote_available_ns=row.quote_available_ns, implied_vol=row.implied_vol,
        iv_observed_ns=row.iv_observed_ns, iv_available_ns=row.iv_available_ns,
        gamma=row.gamma, gamma_units=row.gamma_units,
        greek_observed_ns=row.greek_observed_ns, greek_available_ns=row.greek_available_ns,
        source_id=port.source_id, dataset_id=port.dataset_id,
        entitlement_id=row.greek_entitlement_id or "", entitlement_status="ENTITLED",
        corporate_action_version=row.corporate_action_version, split_factor=row.split_factor,
        halted=False, chain_complete=horizon.chain_complete,
        expected_series_count=horizon.expected_series_count,
        multiplier_basis=row.multiplier_basis, adjustment_version=row.adjustment_version,
        deliverable_units=tuple(
            DeliverableLegV1(leg.kind, leg.asset_id, leg.units, leg.currency)
            for leg in row.deliverable_units
        ),
    )


def _unique(items: list[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(items))


def _settled_copies_live(settled: ChainHorizonV1, live: ChainHorizonV1) -> bool:
    live_rows = {row.row_id for row in live.rows}
    return (settled.source_chain_id == live.source_chain_id
            or settled.snapshot_id == live.snapshot_id
            or any(row.row_id in live_rows for row in settled.rows))


def _adapt_horizon(
    port: OptionChainSourcePortV1, envelope: ChainEnvelopeV1, horizon: ChainHorizonV1,
    other: ChainHorizonV1 | None, asof_ns: int, manifest_hard: list[str],
) -> tuple[ChainHorizonResultV1, ChainSnapshotV1 | None]:
    session = horizon.session
    settled = horizon.data_state == "SETTLED"
    hard: list[str] = list(manifest_hard)
    stale: list[str] = []
    degraded: list[str] = []
    excluded: list[ChainExclusionV1] = []
    if not port.coverage_start_ns <= horizon.available_ns <= port.coverage_end_ns:
        hard.append("OUTSIDE_SOURCE_COVERAGE")
    if horizon.available_ns > asof_ns:
        hard.append("SNAPSHOT_NOT_AVAILABLE")
    if horizon.published_ns > horizon.available_ns or horizon.observed_ns > horizon.published_ns:
        hard.append("SNAPSHOT_PROVENANCE_INCONSISTENT")
    if session.session_close_ns <= session.session_open_ns:
        hard.append("INVALID_SESSION")
    elif not session.trading_session:
        hard.append("NOT_TRADING_SESSION")
    if settled:
        official = horizon.official_settlement_ns
        if official is None:
            hard.append("MISSING_SETTLEMENT_TIMESTAMP")
        else:
            if official < session.session_close_ns:
                hard.append("SETTLEMENT_BEFORE_CLOSE")
            if horizon.observed_ns != official:
                hard.append("SETTLEMENT_OBSERVATION_MISMATCH")
            if horizon.available_ns < official:
                hard.append("SETTLEMENT_NOT_AVAILABLE")
        if other is not None and _settled_copies_live(horizon, other):
            hard.append("SETTLED_COPIES_LIVE")
        clock_ns = horizon.observed_ns
    else:
        if not session.session_open_ns <= horizon.observed_ns <= session.session_close_ns:
            hard.append("OUTSIDE_SESSION")
        clock_ns = asof_ns

    # A manifest-level failure makes every row untrustworthy: report it alone.
    resolved, duplicate_hard, superseded = (
        ([], [], []) if manifest_hard else _resolve_rows(horizon.rows))
    hard.extend(duplicate_hard)
    excluded.extend(superseded)
    eligible: list[ChainRowV1] = []
    for row in resolved:
        problem = _row_problem(row, port, horizon, envelope.underlier, asof_ns, clock_ns)
        if problem is None:
            eligible.append(row)
            continue
        severity, reason = problem
        excluded.append(ChainExclusionV1(series_id=_series_id(row), reason=reason))
        if severity == "hard":
            hard.append(reason)
        elif severity == "degraded":
            degraded.append(reason)
    if not horizon.rows:
        hard.append("MISSING_CHAIN")
    elif not eligible and not manifest_hard:
        hard.append("NO_ELIGIBLE_ENTITLED_SERIES")
    if not horizon.eligible_expiries:
        hard.append("NO_ELIGIBLE_EXPIRIES")
    if len({row.spot for row in eligible}) > 1:
        hard.append("SPOT_MISMATCH")
    if any(max(row.spot_available_ns, row.quote_available_ns, row.iv_available_ns,
               row.greek_available_ns) > horizon.available_ns for row in eligible):
        hard.append("SNAPSHOT_AVAILABILITY_INCONSISTENT")
    if any(max(row.spot_observed_ns, row.quote_observed_ns, row.iv_observed_ns,
               row.greek_observed_ns) > horizon.observed_ns for row in eligible):
        hard.append("SNAPSHOT_OBSERVATION_INCONSISTENT")

    spot_age = max((clock_ns - row.spot_observed_ns for row in eligible), default=None)
    iv_age = max((clock_ns - row.iv_observed_ns for row in eligible), default=None)
    oi_age = max((clock_ns - row.oi_official_close_ns for row in eligible), default=None)
    quote_age = max((clock_ns - row.quote_observed_ns for row in eligible), default=None)
    greek_age = max((clock_ns - row.greek_observed_ns for row in eligible), default=None)
    for name, age, limit in (("SPOT", spot_age, MAX_SPOT_AGE_NS), ("IV", iv_age, MAX_IV_AGE_NS),
                             ("QUOTE", quote_age, MAX_QUOTE_AGE_NS),
                             ("GREEK", greek_age, MAX_GREEK_AGE_NS),
                             ("OI", oi_age, MAX_OI_AGE_NS)):
        if age is not None and age > limit:
            stale.append(f"STALE_{name}")

    numerator = sum((Fraction(row.open_interest) for row in eligible), Fraction())
    denominator = horizon.eligible_oi_denominator
    coverage_exact: tuple[int, int] | None = None
    coverage_ratio: Decimal | None = None
    numerator_decimal: Decimal | None = None
    if denominator is None or denominator <= _ZERO:
        hard.append("UNKNOWN_OI_DENOMINATOR")
    elif manifest_hard:
        pass
    else:
        ratio = numerator / Fraction(denominator)
        coverage_exact = (ratio.numerator, ratio.denominator)
        with localcontext(KERNEL_CONTEXT):
            coverage_ratio = Decimal(ratio.numerator) / Decimal(ratio.denominator)
        if ratio > 1:
            hard.append("OI_DENOMINATOR_UNDERCOUNTS")
        elif ratio < _MIN_COVERAGE:
            degraded.append("LOW_OI_COVERAGE")
    try:
        numerator_decimal = exact_fraction_decimal(numerator)
    except ValueError:
        numerator_decimal = None
        hard.append("COVERAGE_NOT_REPRESENTABLE")
    if not manifest_hard:
        if horizon.expected_series_count is None:
            degraded.append("UNKNOWN_SERIES_COUNT")
        elif len(eligible) < horizon.expected_series_count:
            degraded.append("INCOMPLETE_SERIES_COUNT")
        if not horizon.chain_complete:
            degraded.append("INCOMPLETE_CHAIN")

    snapshot: ChainSnapshotV1 | None = None
    if not hard:
        try:
            snapshot = ChainSnapshotV1(
                snapshot_id=horizon.snapshot_id, data_state=horizon.data_state,
                underlier=envelope.underlier, venue=horizon.venue,
                observed_ns=horizon.observed_ns, available_ns=horizon.available_ns,
                revision=horizon.revision, source_id=port.source_id,
                dataset_id=port.dataset_id,
                calendar=ExchangeCalendarV1(
                    session.calendar_id, session.calendar_version, session.trade_date,
                    session.session_open_ns, session.session_close_ns,
                    session.early_close, session.trading_session),
                eligible_expiries=tuple(sorted(horizon.eligible_expiries)),
                eligible_oi_denominator=denominator,
                chain_complete=horizon.chain_complete,
                expected_series_count=horizon.expected_series_count,
                series=tuple(sorted((_series_evidence(row, port, horizon) for row in eligible),
                                    key=lambda item: item.series_id)),
            )
        except ValueError:
            hard.append("INVALID_SNAPSHOT_EVIDENCE")
            # Nothing was mapped, so no series or coverage is claimed.
            eligible = []
            coverage_exact = coverage_ratio = numerator_decimal = None
    status: AdaptStatus = ("UNAVAILABLE" if hard else "STALE" if stale
                           else "DEGRADED" if degraded else "OK")
    if status == "UNAVAILABLE":
        snapshot = None
    result = ChainHorizonResultV1(
        data_state=horizon.data_state, status=status,
        reasons=_unique(hard + stale + degraded), snapshot_id=horizon.snapshot_id,
        source_chain_id=horizon.source_chain_id, revision=horizon.revision,
        manifest_id=port.manifest_id, source_id=port.source_id, dataset_id=port.dataset_id,
        observed_ns=horizon.observed_ns, published_ns=horizon.published_ns,
        available_ns=horizon.available_ns,
        official_settlement_ns=horizon.official_settlement_ns,
        entitlement_ids=tuple(sorted({row.greek_entitlement_id for row in eligible
                                      if row.greek_entitlement_id is not None}
                                     | ({port.chain_entitlement_id}
                                        if port.chain_entitlement_id is not None else set()))),
        correction_ids=tuple(sorted({row.correction_id for row in eligible
                                     if row.correction_id is not None})),
        mapped_series_ids=tuple(sorted(_series_id(row) for row in eligible)),
        excluded=tuple(sorted(excluded, key=lambda item: (item.series_id, item.reason))),
        oi_family=port.oi_family if eligible else None,
        oi_asof_dates=tuple(sorted({row.oi_asof_date for row in eligible})),
        coverage_numerator=numerator_decimal, coverage_denominator=denominator,
        coverage_exact=coverage_exact, coverage_ratio=coverage_ratio,
        spot_age_ns=spot_age, iv_age_ns=iv_age, oi_age_ns=oi_age,
        has_0dte=any(row.expiry_date == session.trade_date for row in eligible),
    )
    return result, snapshot


def translate_chain(
    port: OptionChainSourcePortV1, envelope: ChainEnvelopeV1, *, asof_ns: int
) -> ChainAdaptationV1:
    """Translate ``envelope`` into an issued result holding a GEX-001 ``GammaSnapshotV1``.

    Pure and deterministic: replaying the same inputs yields an equal result.
    """
    if (not isinstance(port, OptionChainSourcePortV1)
            or not isinstance(envelope, ChainEnvelopeV1)):
        raise ChainAdapterError("INVALID_INPUT")
    if type(asof_ns) is not int or not 0 <= asof_ns <= _MAX_NS:
        raise ChainAdapterError("INVALID_ASOF")
    manifest_hard = _manifest_reasons(port, envelope)
    live_result = settled_result = None
    live_snapshot = settled_snapshot = None
    if envelope.live is not None:
        live_result, live_snapshot = _adapt_horizon(
            port, envelope, envelope.live, None, asof_ns, manifest_hard)
    if envelope.settled is not None:
        settled_result, settled_snapshot = _adapt_horizon(
            port, envelope, envelope.settled, envelope.live, asof_ns, manifest_hard)
    results = [item for item in (live_result, settled_result) if item is not None]
    reasons: list[str] = []
    for item in results:
        reasons.extend(item.reasons)
    snapshot = None
    if live_snapshot is not None or settled_snapshot is not None:
        snapshot = GammaSnapshotV1(live=live_snapshot, settled=settled_snapshot)
    if not results:
        status: AdaptStatus = "UNAVAILABLE"
        reasons.append("NO_HORIZON")
    else:
        status = max((item.status for item in results), key=lambda s: _STATUS_ORDER[s])
    return _ISSUER.issue(ChainAdaptationV1(
        status=status, reasons=_unique(reasons), asof_ns=asof_ns,
        adapter_version=ADAPTER_VERSION, manifest_id=port.manifest_id,
        live=live_result, settled=settled_result, snapshot=snapshot,
    ))


__all__ = [
    "ADAPTER_VERSION",
    "GREEK_CONVENTION_V1",
    "ChainAdaptationV1",
    "ChainAdapterError",
    "ChainDeliverableV1",
    "ChainEnvelopeV1",
    "ChainExclusionV1",
    "ChainHorizonResultV1",
    "ChainHorizonV1",
    "ChainRowV1",
    "ChainSessionV1",
    "OptionChainSourcePortV1",
    "require_adaptation",
    "translate_chain",
    "verify_adaptation",
]
