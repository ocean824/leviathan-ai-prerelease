"""Pure finalized-bar and feature-observation bridge for offline indicators.

The port mirrors MD-001 bar content. A later integration boundary must populate
it from a normalized market event and trusted calendar/finality metadata.
"""

from __future__ import annotations

import hashlib
import re
from decimal import ROUND_HALF_EVEN, Context, Decimal, localcontext
from typing import NoReturn, Self

from pydantic import ValidationError, field_validator, model_validator

from leviathan_core.feature_store import FeatureDefinitionV1, FeatureObservationV1
from leviathan_core.indicator_state.models import (
    FinalBarV1,
    IndicatorDefinitionV1,
    IndicatorResultV1,
    require_indicator_result,
)
from leviathan_core.numeric import NumericError, canonical_json, parse_decimal
from leviathan_core.seal import Issuer, SealedModel, SealError, require

_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z", re.ASCII)
_FLAG = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,63}\Z", re.ASCII)
_DIGEST = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_CONTEXT = Context(prec=34, rounding=ROUND_HALF_EVEN)
_BAR_ISSUER = Issuer("ind002.bar_port.v1")
_ERROR_CODES = frozenset(
    {
        "INVALID_BAR_PORT",
        "UNISSUED_BAR_PORT",
        "PROVISIONAL_BAR",
        "UNAVAILABLE_BAR",
        "LINEAGE_MISMATCH",
        "RESULT_MISMATCH",
        "SEAL_NOT_ISSUED",
        "SEAL_TAMPERED",
        "SEAL_WRONG_ISSUER",
        "CONFLICTING_INDICATOR_RESULT",
        "INVALID_TIME",
        "FEATURE_VALUE_OUT_OF_DOMAIN",
        "INVALID_FEATURE_OBSERVATION",
    }
)


class IndicatorAdapterError(ValueError):
    """Fixed, content-free failure at the IND-002 public boundary."""

    def __init__(self, code: str) -> None:
        self.code = code if code in _ERROR_CODES else "INVALID_BAR_PORT"
        super().__init__(self.code)


def _fail(code: str) -> NoReturn:
    raise IndicatorAdapterError(code)


def _time(value: object) -> int:
    if type(value) is not int or not 0 < value <= (1 << 63) - 1:
        _fail("INVALID_TIME")
    return value


def _key(payload: dict[str, object], prefix: str) -> str:
    try:
        return prefix + hashlib.sha256(canonical_json(payload)).hexdigest()
    except NumericError:
        _fail("INVALID_BAR_PORT")


class NormalizedBarPortV1(SealedModel):
    """MD-shaped bar plus explicit finality, source and calendar evidence.

    Every field is required. Direct construction validates shape but does not
    confer issuance; only issue_normalized_bar_port can issue a usable port.
    """

    provider: str
    source_dataset: str
    source_record_key: str
    source_payload_sha256: str
    instrument_id: str
    venue: str
    timeframe: str
    source_version: str
    adjustment_basis: str
    adjustment_version: str
    calendar_version: str
    calendar_session_id: str
    auction_session_id: str
    bar_start_ns: int
    bar_end_ns: int
    event_time_ns: int
    availability_ns: int
    watermark_ns: int
    finalized_at_ns: int | None
    open: Decimal
    high: Decimal
    low: Decimal
    close: Decimal
    volume: Decimal | None
    finalized: bool
    gap: bool
    quality_flags: tuple[str, ...]
    revision: int
    correction_id: str | None

    @field_validator("open", "high", "low", "close", "volume", mode="before")
    @classmethod
    def _exact_input(cls, value: object) -> Decimal | None:
        if value is None:
            return None
        return parse_decimal(value, field="bar")

    @model_validator(mode="after")
    def _validate_port(self) -> Self:
        for name in (
            "provider",
            "source_dataset",
            "source_record_key",
            "instrument_id",
            "venue",
            "timeframe",
            "source_version",
            "adjustment_basis",
            "adjustment_version",
            "calendar_version",
            "calendar_session_id",
            "auction_session_id",
        ):
            if _TOKEN.fullmatch(getattr(self, name)) is None:
                raise ValueError("INVALID_BAR_PORT")
        if _DIGEST.fullmatch(self.source_payload_sha256) is None:
            raise ValueError("INVALID_BAR_PORT")
        for name in (
            "bar_start_ns",
            "bar_end_ns",
            "event_time_ns",
            "availability_ns",
            "watermark_ns",
        ):
            _time(getattr(self, name))
        if self.finalized_at_ns is not None:
            _time(self.finalized_at_ns)
        if not (self.bar_start_ns < self.bar_end_ns <= self.event_time_ns <= self.availability_ns):
            raise ValueError("INVALID_TIME")
        if self.watermark_ns > self.availability_ns:
            raise ValueError("INVALID_TIME")
        if type(self.finalized) is not bool or type(self.gap) is not bool:
            raise ValueError("INVALID_BAR_PORT")
        if type(self.revision) is not int or self.revision < 0:
            raise ValueError("INVALID_BAR_PORT")
        if self.revision == 0 and self.correction_id is not None:
            raise ValueError("INVALID_BAR_PORT")
        if self.revision > 0 and (
            self.correction_id is None or _TOKEN.fullmatch(self.correction_id) is None
        ):
            raise ValueError("INVALID_BAR_PORT")
        if (
            type(self.quality_flags) is not tuple
            or any(_FLAG.fullmatch(flag) is None for flag in self.quality_flags)
            or len(set(self.quality_flags)) != len(self.quality_flags)
        ):
            raise ValueError("INVALID_BAR_PORT")
        if "GAP" in (flag.upper() for flag in self.quality_flags) and not self.gap:
            raise ValueError("INVALID_BAR_PORT")
        with localcontext(_CONTEXT):
            if (
                self.open <= 0
                or self.high <= 0
                or self.low <= 0
                or self.close <= 0
                or self.low > min(self.open, self.close)
                or self.high < max(self.open, self.close)
                or (self.volume is not None and self.volume < 0)
            ):
                raise ValueError("INVALID_BAR_PORT")
        if self.finalized and (
            self.finalized_at_ns is None
            or self.watermark_ns < self.bar_end_ns
            or not self.bar_end_ns <= self.finalized_at_ns <= self.availability_ns
        ):
            raise ValueError("INVALID_BAR_PORT")
        if not self.finalized and self.finalized_at_ns is not None:
            raise ValueError("INVALID_BAR_PORT")
        return self


def issue_normalized_bar_port(candidate: NormalizedBarPortV1) -> NormalizedBarPortV1:
    """Revalidate and issue a fresh port; MD attestation remains a gate."""
    if type(candidate) is not NormalizedBarPortV1:
        _fail("INVALID_BAR_PORT")
    try:
        # Never issue the caller's object: object.__setattr__ can bypass the
        # model's frozen surface, so rebuild from primitives and validate again.
        payload = candidate.model_dump(mode="python")
        fresh = NormalizedBarPortV1.model_validate(payload)
        return _BAR_ISSUER.issue(fresh)
    except (SealError, ValidationError, NumericError, TypeError, ValueError):
        _fail("INVALID_BAR_PORT")


def _issued(port: NormalizedBarPortV1) -> NormalizedBarPortV1:
    if type(port) is not NormalizedBarPortV1:
        _fail("INVALID_BAR_PORT")
    try:
        return require(port, _BAR_ISSUER.tag)
    except SealError:
        _fail("UNISSUED_BAR_PORT")


def _lineage(port: NormalizedBarPortV1, definition: IndicatorDefinitionV1) -> None:
    if type(definition) is not IndicatorDefinitionV1:
        _fail("LINEAGE_MISMATCH")
    if (
        definition.instrument_id != port.instrument_id
        or definition.venue != port.venue
        or definition.timeframe != port.timeframe
        or definition.source_version != port.source_version
        or definition.adjustment_version != port.adjustment_basis + ":" + port.adjustment_version
        or definition.calendar_version != port.calendar_version
    ):
        _fail("LINEAGE_MISMATCH")


def _bar_id(port: NormalizedBarPortV1) -> str:
    return _key(
        {
            "provider": port.provider,
            "source_dataset": port.source_dataset,
            "instrument_id": port.instrument_id,
            "venue": port.venue,
            "timeframe": port.timeframe,
            "bar_end_ns": port.bar_end_ns,
            "source_version": port.source_version,
            "adjustment_basis": port.adjustment_basis,
            "adjustment_version": port.adjustment_version,
            "calendar_version": port.calendar_version,
        },
        "bar:",
    )


def to_final_bar(
    port: NormalizedBarPortV1,
    definition: IndicatorDefinitionV1,
    *,
    asof_ns: int,
) -> FinalBarV1:
    """Reject non-final or future input before entering IND-001."""
    port = _issued(port)
    _lineage(port, definition)
    asof_ns = _time(asof_ns)
    if not port.finalized:
        _fail("PROVISIONAL_BAR")
    if port.availability_ns > asof_ns or (
        port.finalized_at_ns is not None and port.finalized_at_ns > asof_ns
    ):
        _fail("UNAVAILABLE_BAR")
    session_key = _key(
        {
            "calendar": port.calendar_session_id,
            "auction": port.auction_session_id,
        },
        "sess:",
    )
    try:
        return FinalBarV1(
            bar_id=_bar_id(port),
            instrument_id=port.instrument_id,
            venue=port.venue,
            timeframe=port.timeframe,
            session_key=session_key,
            source_version=port.source_version,
            adjustment_version=definition.adjustment_version,
            calendar_version=port.calendar_version,
            bar_end_ns=port.bar_end_ns,
            event_time_ns=port.event_time_ns,
            availability_ns=port.availability_ns,
            open=port.open,
            high=port.high,
            low=port.low,
            close=port.close,
            volume=port.volume,
            finalized=True,
            gap=port.gap,
        )
    except ValueError:
        _fail("INVALID_BAR_PORT")


def _feature_fields(
    port: NormalizedBarPortV1, definition: IndicatorDefinitionV1
) -> tuple[str, str]:
    name = "indicator." + definition.kind.lower()
    version = _key(
        {
            "formula_version": definition.formula_version,
            "kind": definition.kind,
            "period": definition.period,
            "parameter_version": definition.parameter_version,
            "provider": port.provider,
            "source_dataset": port.source_dataset,
            "source_version": port.source_version,
            "timeframe": port.timeframe,
            "venue": port.venue,
            "adjustment_basis": port.adjustment_basis,
            "adjustment_version": port.adjustment_version,
            "calendar_version": port.calendar_version,
        },
        "ind1.",
    )
    return name, version


def feature_definition(
    port: NormalizedBarPortV1,
    definition: IndicatorDefinitionV1,
    *,
    published: bool,
) -> FeatureDefinitionV1:
    """Deterministic FEAT-001 definition for one source/formula lineage."""
    port = _issued(port)
    _lineage(port, definition)
    if type(published) is not bool:
        _fail("INVALID_BAR_PORT")
    name, version = _feature_fields(port, definition)
    try:
        return FeatureDefinitionV1(
            feature_name=name,
            feature_version=version,
            value_kind="decimal",
            published=published,
        )
    except (ValidationError, ValueError, TypeError):
        _fail("INVALID_FEATURE_OBSERVATION")


def to_feature_observation(
    port: NormalizedBarPortV1,
    definition: IndicatorDefinitionV1,
    result: IndicatorResultV1,
    *,
    availability_ns: int,
) -> FeatureObservationV1:
    """Map one IND result through the conflict-checking plural boundary."""
    return to_feature_observations(port, definition, (result,), availability_ns=availability_ns)[0]


def _validated_result(result: IndicatorResultV1) -> IndicatorResultV1:
    try:
        return require_indicator_result(result)
    except SealError as exc:
        if exc.code in {"SEAL_NOT_ISSUED", "SEAL_TAMPERED", "SEAL_WRONG_ISSUER"}:
            _fail(exc.code)
        _fail("RESULT_MISMATCH")


def _result_digest(result: IndicatorResultV1) -> str:
    try:
        payload = {
            "bar_end_ns": result.bar_end_ns,
            "bar_id": result.bar_id,
            "definition_hash": result.definition_hash,
            "formula_version": result.formula_version,
            "gap": result.gap,
            "input_digest": result.input_digest,
            "invalid": result.invalid,
            "late": result.late,
            "quality_flags": result.quality_flags,
            "revision": result.revision,
            "sample_count": result.sample_count,
            "value": result.value,
            "warmup": result.warmup,
        }
        return hashlib.sha256(canonical_json(payload)).hexdigest()
    except NumericError:
        _fail("RESULT_MISMATCH")


def to_feature_observations(
    port: NormalizedBarPortV1,
    definition: IndicatorDefinitionV1,
    results: tuple[IndicatorResultV1, ...],
    *,
    availability_ns: int,
) -> tuple[FeatureObservationV1, ...]:
    """Preflight a result batch for identity conflicts before building any row."""
    availability_ns = _time(availability_ns)
    bar = to_final_bar(port, definition, asof_ns=availability_ns)
    if type(results) is not tuple:
        _fail("RESULT_MISMATCH")

    validated: list[tuple[IndicatorResultV1, str]] = []
    contents: dict[tuple[str, str, int, str], str] = {}
    for raw_result in results:
        result = _validated_result(raw_result)
        if (
            result.definition_hash != definition.semantic_hash
            or result.bar_id != bar.bar_id
            or result.bar_end_ns != bar.bar_end_ns
            or result.formula_version != definition.formula_version
        ):
            _fail("RESULT_MISMATCH")
        if result.value is None and not (result.warmup or result.invalid or result.gap):
            _fail("RESULT_MISMATCH")
        if result.value is not None and (result.warmup or result.invalid):
            _fail("RESULT_MISMATCH")
        if result.value is not None:
            try:
                parse_decimal(result.value, field="value")
            except NumericError:
                _fail("FEATURE_VALUE_OUT_OF_DOMAIN")
        result_digest = _result_digest(result)
        identity = (
            result.bar_id,
            result.definition_hash,
            result.revision,
            result.input_digest,
        )
        previous = contents.get(identity)
        if previous is not None and previous != result_digest:
            _fail("CONFLICTING_INDICATOR_RESULT")
        contents[identity] = result_digest
        validated.append((result, result_digest))

    # All result rows have passed identity and content checks before any FEAT
    # value is constructed. The digest also distinguishes independent calls.
    return tuple(
        _feature_observation(port, definition, result, result_digest, availability_ns)
        for result, result_digest in validated
    )


def _feature_observation(
    port: NormalizedBarPortV1,
    definition: IndicatorDefinitionV1,
    result: IndicatorResultV1,
    result_digest: str,
    availability_ns: int,
) -> FeatureObservationV1:
    name, version = _feature_fields(port, definition)
    source_key = _key(
        {
            "feature_name": name,
            "feature_version": version,
            "instrument_id": port.instrument_id,
            "source_dataset": port.source_dataset,
            "source_record_key": port.source_record_key,
            "source_payload_sha256": port.source_payload_sha256,
            "bar_end_ns": port.bar_end_ns,
            "availability_ns": availability_ns,
            "source_revision": port.revision,
            "correction_id": port.correction_id,
            "indicator_revision": result.revision,
            "indicator_input_digest": result.input_digest,
            "indicator_result_digest": result_digest,
        },
        "indobs:",
    )
    flags = {flag.upper() for flag in port.quality_flags}
    flags.update(result.quality_flags)
    if result.warmup:
        flags.add("WARMUP")
    if result.invalid:
        flags.add("INVALID")
    if result.gap:
        flags.add("GAP")
    if result.late:
        flags.add("LATE")
    quality = "|".join(sorted(flags)) or None
    try:
        return FeatureObservationV1(
            feature_name=name,
            feature_version=version,
            instrument_id=port.instrument_id,
            source_dataset=port.provider + ":" + port.source_dataset,
            source_record_key=source_key,
            event_time_ns=result.bar_end_ns,
            availability_ns=availability_ns,
            value_decimal=result.value,
            quality=quality,
            is_null=result.value is None,
            local_receipt_ns=None,
        )
    except (ValidationError, ValueError, TypeError):
        _fail("INVALID_FEATURE_OBSERVATION")
