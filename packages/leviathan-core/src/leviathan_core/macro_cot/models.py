"""Immutable, I/O-free contracts for point-in-time CFTC positioning."""

from dataclasses import InitVar, dataclass, field
from datetime import date
from decimal import ROUND_HALF_EVEN, Context, Decimal
from typing import Literal, NoReturn, SupportsIndex


class COTValidationError(ValueError):
    """A COT input or policy cannot produce an unambiguous result."""

    def __init__(self, message: str, *, reason_code: str = "INVALID_COT_INPUT") -> None:
        super().__init__(message)
        self.reason_code = reason_code


def canonical_decimal(value: object, name: str) -> Decimal:
    """Bound and normalize a Decimal without using the caller's context."""
    if not isinstance(value, Decimal) or not value.is_finite():
        raise COTValidationError(
            f"{name} must be a finite Decimal", reason_code="DECIMAL_OUT_OF_BOUNDS"
        )
    if abs(value.adjusted()) > 38:
        raise COTValidationError(
            f"{name} exceeds Decimal bounds", reason_code="DECIMAL_OUT_OF_BOUNDS"
        )
    if value.is_zero():
        return Decimal(0)
    sign, digits, exponent = value.as_tuple()
    assert isinstance(exponent, int)
    canonical_digits = list(digits)
    while len(canonical_digits) > 1 and canonical_digits[-1] == 0:
        canonical_digits.pop()
        exponent += 1
    if len(canonical_digits) > 34:
        raise COTValidationError(
            f"{name} exceeds working precision", reason_code="PRECISION_EXCEEDED"
        )
    return Decimal((sign, tuple(canonical_digits), exponent))


class _NoClone:
    """Disallow reconstruction paths that skip an explicit validated constructor."""

    def __copy__(self) -> NoReturn:
        raise TypeError("COT models cannot be copied")

    def __deepcopy__(self, memo: object) -> NoReturn:
        raise TypeError("COT models cannot be copied")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise TypeError("COT models cannot be pickled")


_COT_RESULT_ISSUE_TOKEN = object()


@dataclass(frozen=True, slots=True)
class COTReportVintageV1(_NoClone):
    """One source vintage for one constituent and CFTC report date.

    ``published_ns`` is the actual CFTC release timestamp. ``None`` means the
    release is unverified and the vintage is never visible to replay.
    """

    cftc_market_code: str
    constituent_id: str
    report_date: date
    report_family: str
    source: str
    revision: int
    is_preliminary: bool
    published_ns: int | None
    received_ns: int | None
    available_ns: int | None
    mm_long: Decimal | None
    mm_short: Decimal | None
    open_interest: Decimal
    mm_spreading: Decimal = Decimal("0")
    units: str = "contracts"

    def __post_init__(self) -> None:
        if any(
            not isinstance(getattr(self, name), str)
            for name in ("cftc_market_code", "constituent_id", "report_family", "source", "units")
        ) or not isinstance(self.report_date, date):
            raise COTValidationError("invalid vintage identity")
        if type(self.revision) is not int or type(self.is_preliminary) is not bool:
            raise COTValidationError("invalid vintage revision")
        if any(
            stamp is not None and type(stamp) is not int
            for stamp in (self.published_ns, self.received_ns, self.available_ns)
        ):
            raise COTValidationError("invalid vintage timestamps")
        for name in ("mm_long", "mm_short", "open_interest", "mm_spreading"):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, canonical_decimal(value, name))


@dataclass(frozen=True, slots=True)
class COTMarketMapV1(_NoClone):
    """Effective-dated constituent set and optional macro driver weights.

    ``effective_to`` is exclusive. Changes to constituent membership require
    a new version; the same version must not be used for a different set.
    """

    market_id: str
    version: str
    constituent_ids: tuple[str, ...]
    effective_from: date
    constituent_codes: tuple[tuple[str, str], ...] = field(kw_only=True)
    effective_to: date | None = None
    driver_weights: tuple[tuple[str, Decimal], ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.market_id, str) or not isinstance(self.version, str):
            raise COTValidationError(
                "invalid market mapping identity", reason_code="MAPPING_AMBIGUOUS"
            )
        if not isinstance(self.effective_from, date) or (
            self.effective_to is not None and not isinstance(self.effective_to, date)
        ):
            raise COTValidationError("invalid mapping dates", reason_code="MAPPING_AMBIGUOUS")
        if isinstance(self.constituent_ids, (str, bytes)):
            raise COTValidationError("invalid constituent IDs", reason_code="MAPPING_AMBIGUOUS")
        identifiers = tuple(self.constituent_ids)
        if any(not isinstance(ident, str) for ident in identifiers):
            raise COTValidationError("invalid constituent IDs", reason_code="MAPPING_AMBIGUOUS")
        object.__setattr__(self, "constituent_ids", tuple(sorted(identifiers)))
        if isinstance(self.constituent_codes, (str, bytes)):
            raise COTValidationError("invalid constituent codes", reason_code="MAPPING_AMBIGUOUS")
        codes = tuple(tuple(pair) for pair in self.constituent_codes)
        if any(len(pair) != 2 or any(not isinstance(part, str) for part in pair) for pair in codes):
            raise COTValidationError("invalid constituent codes", reason_code="MAPPING_AMBIGUOUS")
        object.__setattr__(
            self, "constituent_codes", tuple(sorted(codes))
        )
        if isinstance(self.driver_weights, (str, bytes)):
            raise COTValidationError("invalid driver weights")
        weights = tuple(tuple(pair) for pair in self.driver_weights)
        if any(len(pair) != 2 or not isinstance(pair[0], str) for pair in weights):
            raise COTValidationError("invalid driver IDs")
        object.__setattr__(
            self,
            "driver_weights",
            tuple(sorted(
                (driver, canonical_decimal(weight, "driver weight"))
                for driver, weight in weights
            )),
        )


@dataclass(frozen=True, slots=True)
class COTPolicyV1(_NoClone):
    """Versioned backend computation defaults and source precedence."""

    min_lookback_samples: int
    version: str = "backend-prd-v1"
    lookback_reports: int = 156
    low_confidence_min_samples: int = 104
    percentile_method: str = "inclusive_empirical_cdf_upper_ties"
    contrarian_long_max: Decimal = Decimal("10")
    contrarian_short_min: Decimal = Decimal("90")
    confirmation_short_cover_max: Decimal = Decimal("35")
    confirmation_trend_follow_long_min: Decimal = Decimal("65")
    weight_tolerance: Decimal = Decimal("0.01")
    source_priority: tuple[str, ...] = ("CFTC",)

    def __post_init__(self) -> None:
        if not isinstance(self.version, str) or not isinstance(self.percentile_method, str):
            raise COTValidationError("invalid policy identity", reason_code="POLICY_OUT_OF_BOUNDS")
        if any(
            type(getattr(self, name)) is not int
            for name in ("lookback_reports", "low_confidence_min_samples", "min_lookback_samples")
        ):
            raise COTValidationError(
                "invalid policy sample counts", reason_code="POLICY_OUT_OF_BOUNDS"
            )
        for name in (
            "contrarian_long_max", "contrarian_short_min", "confirmation_short_cover_max",
            "confirmation_trend_follow_long_min", "weight_tolerance",
        ):
            try:
                object.__setattr__(self, name, canonical_decimal(getattr(self, name), name))
            except COTValidationError as exc:
                raise COTValidationError(str(exc), reason_code="POLICY_OUT_OF_BOUNDS") from exc
        if isinstance(self.source_priority, (str, bytes)):
            raise COTValidationError("invalid source priority", reason_code="POLICY_OUT_OF_BOUNDS")
        priority = tuple(self.source_priority)
        if any(not isinstance(source, str) for source in priority):
            raise COTValidationError("invalid source priority", reason_code="POLICY_OUT_OF_BOUNDS")
        object.__setattr__(self, "source_priority", priority)
        validate_policy_bounds(self)


def validate_policy_bounds(policy: COTPolicyV1) -> None:
    """Enforce backend v1 bounds during construction and replay."""
    def reject(message: str) -> NoReturn:
        raise COTValidationError(message, reason_code="POLICY_OUT_OF_BOUNDS")

    if not policy.version:
        reject("policy version is required")
    if policy.lookback_reports != 156:
        reject("backend-prd-v1 requires a 156-report window")
    if not 104 <= policy.low_confidence_min_samples <= policy.lookback_reports:
        reject("low_confidence_min_samples must be at least 104")
    if not 104 <= policy.min_lookback_samples <= policy.lookback_reports:
        reject("min_lookback_samples must be between 104 and 156")
    if policy.percentile_method != "inclusive_empirical_cdf_upper_ties":
        reject("unsupported percentile_method")
    thresholds = (
        policy.contrarian_long_max,
        policy.confirmation_short_cover_max,
        policy.confirmation_trend_follow_long_min,
        policy.contrarian_short_min,
    )
    if not Decimal(0) <= thresholds[0] < thresholds[1] < thresholds[2] < thresholds[3] <= 100:
        reject("tag thresholds must be ordered within [0, 100]")
    if thresholds[0] > 10 or thresholds[1] > 35 or thresholds[2] < 65 or thresholds[3] < 90:
        reject("tag thresholds cannot loosen backend-prd-v1")
    if not Decimal(0) <= policy.weight_tolerance <= Decimal("0.01"):
        reject("weight_tolerance must be between 0 and 0.01")
    if (
        not policy.source_priority
        or len(set(policy.source_priority)) != len(policy.source_priority)
    ):
        reject("source_priority must be nonempty and unique")
    if any(not source or source != source.strip() for source in policy.source_priority):
        reject("source_priority contains an invalid source")


@dataclass(frozen=True, slots=True)
class COTSnapshotV1(_NoClone):
    """One mapped market's replay input, including future revisions."""

    market_map: COTMarketMapV1
    vintages: tuple[COTReportVintageV1, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.market_map, COTMarketMapV1):
            raise COTValidationError("snapshot requires a market map")
        if isinstance(self.vintages, (str, bytes)):
            raise COTValidationError("invalid vintages")
        rows = tuple(self.vintages)
        if any(not isinstance(row, COTReportVintageV1) for row in rows):
            raise COTValidationError("snapshot requires COT vintages")
        object.__setattr__(self, "vintages", rows)


@dataclass(frozen=True, slots=True)
class COTResultV1(_NoClone):
    """Point-in-time positioning with explicit completeness and provenance."""

    market_id: str
    status: Literal["OK", "DEGRADED", "UNAVAILABLE"]
    asof_ns: int
    mapping_version: str
    policy_version: str
    percentile_method: str = "inclusive_empirical_cdf_upper_ties"
    driver_weights: tuple[tuple[str, Decimal], ...] = field(default_factory=tuple)
    report_date: date | None = None
    previous_report_date: date | None = None
    gap: bool = False
    net_mm: Decimal | None = None
    net_mm_pct_oi: Decimal | None = None
    wow_delta_mm: Decimal | None = None
    wow_delta_pct_oi: Decimal | None = None
    percentile: Decimal | None = None
    percentile_display: Decimal | None = None
    sample_count: int = 0
    lookback_samples_used: int = 0
    lookback_samples_requested: int = 0
    min_lookback_samples: int = 104
    window_start: date | None = None
    low_confidence: bool = True
    contrarian_tag: Literal["contrarian_long", "contrarian_short", "none"] | None = None
    confirmation_bias: Literal[
        "bias_short_cover", "bias_trend_follow_long", "neutral"
    ] | None = None
    selected_vintages: tuple[COTReportVintageV1, ...] = field(default_factory=tuple)
    warnings: tuple[str, ...] = field(default_factory=tuple)
    latest_published_ns: int | None = None
    latest_received_ns: int | None = None
    latest_available_ns: int | None = None
    is_preliminary: bool = False
    is_revised: bool = False
    selected_revision_ids: tuple[tuple[str, int], ...] = field(default_factory=tuple)
    newer_preliminary_not_selected: bool = False
    reason_codes: tuple[str, ...] = field(default_factory=tuple)
    _issue_token: InitVar[object | None] = field(default=None, kw_only=True)

    def __post_init__(self, _issue_token: object | None) -> None:
        if any(
            not isinstance(getattr(self, name), str)
            for name in (
                "market_id", "status", "mapping_version", "policy_version", "percentile_method"
            )
        ):
            raise COTValidationError("invalid result identity")
        if any(
            value is not None and not isinstance(value, date)
            for value in (self.report_date, self.previous_report_date, self.window_start)
        ):
            raise COTValidationError("invalid result dates")
        if any(
            type(getattr(self, name)) is not int
            for name in (
                "asof_ns", "sample_count", "lookback_samples_used", "lookback_samples_requested",
                "min_lookback_samples",
            )
        ) or any(
            value is not None and type(value) is not int
            for value in (
                self.latest_published_ns, self.latest_received_ns, self.latest_available_ns
            )
        ):
            raise COTValidationError("invalid result timestamps or counts")
        if any(
            type(getattr(self, name)) is not bool
            for name in (
                "gap", "low_confidence", "is_preliminary", "is_revised",
                "newer_preliminary_not_selected",
            )
        ):
            raise COTValidationError("invalid result flags")
        if self.status not in ("OK", "DEGRADED", "UNAVAILABLE"):
            raise COTValidationError("invalid result status", reason_code="INVALID_RESULT_STATE")
        if self.contrarian_tag not in (None, "contrarian_long", "contrarian_short", "none"):
            raise COTValidationError("invalid result tag", reason_code="INVALID_RESULT_STATE")
        if self.confirmation_bias not in (
            None, "bias_short_cover", "bias_trend_follow_long", "neutral"
        ):
            raise COTValidationError("invalid result bias", reason_code="INVALID_RESULT_STATE")
        weights = tuple(tuple(pair) for pair in self.driver_weights)
        if any(len(pair) != 2 or not isinstance(pair[0], str) for pair in weights):
            raise COTValidationError("invalid result driver IDs")
        for name in (
            "net_mm", "net_mm_pct_oi", "wow_delta_mm", "wow_delta_pct_oi", "percentile",
        ):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, canonical_decimal(value, name))
        if self.percentile_display is not None:
            display = canonical_decimal(self.percentile_display, "percentile_display")
            object.__setattr__(
                self, "percentile_display",
                display.quantize(
                    Decimal("0.1"), rounding=ROUND_HALF_EVEN, context=Context(prec=34)
                ),
            )
        object.__setattr__(
            self,
            "driver_weights",
            tuple(sorted(
                (driver, canonical_decimal(weight, "driver weight"))
                for driver, weight in weights
            )),
        )
        selected = tuple(self.selected_vintages)
        if any(not isinstance(row, COTReportVintageV1) for row in selected):
            raise COTValidationError("invalid result vintage")
        object.__setattr__(self, "selected_vintages", selected)
        warnings = tuple(self.warnings)
        reasons = tuple(self.reason_codes)
        if any(not isinstance(value, str) for value in (*warnings, *reasons)):
            raise COTValidationError("invalid result reasons")
        object.__setattr__(self, "warnings", warnings)
        object.__setattr__(self, "reason_codes", reasons)
        revisions = tuple(tuple(pair) for pair in self.selected_revision_ids)
        if any(
            len(pair) != 2 or not isinstance(pair[0], str) or type(pair[1]) is not int
            for pair in revisions
        ):
            raise COTValidationError("invalid result revisions")
        object.__setattr__(
            self, "selected_revision_ids", revisions
        )
        degrading = {"INSUFFICIENT_HISTORY", "MISSING_CONSTITUENTS", "NO_PUBLISHED_VINTAGE"}
        if not 104 <= self.min_lookback_samples <= 156 or any(
            count < 0 for count in (
                self.sample_count, self.lookback_samples_used, self.lookback_samples_requested
            )
        ):
            raise COTValidationError(
                "invalid result sample bounds", reason_code="INVALID_RESULT_STATE"
            )
        if self.status == "OK" and (
            self.report_date is None
            or self.sample_count < self.min_lookback_samples
            or self.lookback_samples_used != self.sample_count
            or self.net_mm is None
            or self.net_mm_pct_oi is None
            or self.percentile is None
            or self.percentile_display is None
            or self.contrarian_tag is None
            or self.confirmation_bias is None
            or degrading.intersection(reasons)
        ):
            raise COTValidationError("inconsistent OK result", reason_code="INVALID_RESULT_STATE")
        if self.status == "DEGRADED" and (
            not reasons
            or self.percentile is not None
            or self.percentile_display is not None
            or self.contrarian_tag is not None
            or self.confirmation_bias is not None
        ):
            raise COTValidationError(
                "inconsistent DEGRADED result", reason_code="INVALID_RESULT_STATE"
            )
        if self.status == "UNAVAILABLE" and (
            self.sample_count != 0
            or self.percentile is not None
            or self.contrarian_tag is not None
            or self.confirmation_bias is not None
        ):
            raise COTValidationError(
                "inconsistent UNAVAILABLE result", reason_code="INVALID_RESULT_STATE"
            )
        if _issue_token is not _COT_RESULT_ISSUE_TOKEN:
            raise COTValidationError(
                "result was not issued by kernel", reason_code="RESULT_NOT_ISSUED"
            )
