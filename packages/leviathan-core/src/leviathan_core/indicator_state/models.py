"""Immutable input, output, and checkpoint contracts for offline indicators."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import InitVar, dataclass, field
from decimal import (
    ROUND_HALF_EVEN,
    Context,
    Decimal,
    DivisionByZero,
    InvalidOperation,
    localcontext,
)
from typing import Literal, NoReturn, SupportsIndex

from leviathan_core.seal import Issuer, SealError, require


class IndicatorValidationError(ValueError):
    """An indicator definition or finalized bar is invalid."""


class IndicatorConflictError(IndicatorValidationError):
    """Two different bars claim one logical slot and revision."""


class IndicatorCheckpointError(IndicatorValidationError):
    """A checkpoint does not match a verified source prefix."""


class IndicatorAvailabilityError(IndicatorValidationError):
    """A bar is not finalized and available at the requested cutoff."""


class IndicatorPrecisionExceededError(IndicatorValidationError):
    """An exact input needs more significant digits than IND-FORMULA-v1 allows."""


class _NoCopyOrPickle:
    """Value objects cannot acquire a second identity by copy or serialization."""

    __slots__ = ()

    def __copy__(self) -> None:
        raise IndicatorValidationError("indicator object cannot be copied")

    def __deepcopy__(self, memo: object) -> None:
        raise IndicatorValidationError("indicator object cannot be copied")

    def __reduce__(self) -> NoReturn:
        raise IndicatorValidationError("indicator object cannot be serialized")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise IndicatorValidationError("indicator object cannot be serialized")

    def __getstate__(self) -> None:
        raise IndicatorValidationError("indicator object cannot be serialized")


_STATE_TOKEN = object()
_RESULT_ISSUER = Issuer("ind001.indicator_result.v1")
_CONTEXT = Context(prec=34, rounding=ROUND_HALF_EVEN)
_CONTEXT.traps[InvalidOperation] = True
_CONTEXT.traps[DivisionByZero] = True


_IDENTITY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z", re.ASCII)
_TIMEFRAME = re.compile(r"[1-9][0-9]{0,8}(?:ns|us|ms|s|m|h|d|w)\Z", re.ASCII)
_DECIMAL = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?\Z", re.ASCII)
_HASH = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_MAX_DERIVED_ADJUSTED_EXPONENT = 128
_MAX_RESULT_VALUE_TEXT_LENGTH = 192


def _identity(value: object) -> str:
    if not isinstance(value, str) or _IDENTITY.fullmatch(value) is None:
        raise IndicatorValidationError("invalid indicator identity")
    return value


def _timeframe(value: object) -> str:
    if not isinstance(value, str) or _TIMEFRAME.fullmatch(value) is None:
        raise IndicatorValidationError("invalid indicator timeframe")
    return value


def _nanoseconds(value: object) -> int:
    if type(value) is not int or value < 0 or value > 2**63 - 1:
        raise IndicatorValidationError("invalid indicator timestamp")
    return value


def _canonical_decimal(value: Decimal) -> str:
    plain = format(value, "f")
    if value.is_zero():
        return "0"
    return plain.rstrip("0").rstrip(".") if "." in plain else plain


def _validated_decimal(
    value: object, *, nullable: bool = False, input_range: bool
) -> Decimal | None:
    if value is None and nullable:
        return None
    if isinstance(value, (bool, float)):
        raise IndicatorValidationError("indicator number must be exact")
    if not isinstance(value, (Decimal, str, int)):
        raise IndicatorValidationError("indicator number must be exact")
    if isinstance(value, Decimal):
        number = value
    else:
        if isinstance(value, int) and value.bit_length() > 130:
            raise IndicatorValidationError("indicator number out of range")
        raw = str(value)
        if isinstance(value, str) and _DECIMAL.fullmatch(value) is None:
            raise IndicatorValidationError("invalid indicator number")
        try:
            number = Decimal(raw)
        except InvalidOperation as exc:
            raise IndicatorValidationError("invalid indicator number") from exc
    if not number.is_finite():
        raise IndicatorValidationError("indicator number out of range")
    if input_range and abs(number.adjusted()) > 38:
        raise IndicatorValidationError("indicator number out of range")
    if not input_range and abs(number.adjusted()) > _MAX_DERIVED_ADJUSTED_EXPONENT:
        raise IndicatorValidationError("indicator number out of range")
    digits = number.as_tuple().digits
    significant = len(digits)
    while significant > 1 and digits[significant - 1] == 0:
        significant -= 1
    if significant > 34:
        raise IndicatorPrecisionExceededError("PRECISION_EXCEEDED")
    return Decimal(_canonical_decimal(number))


def _exact_decimal(value: object, *, nullable: bool = False) -> Decimal | None:
    """Validate an input number, including the source magnitude bound."""
    return _validated_decimal(value, nullable=nullable, input_range=True)


def _derived_decimal(value: object, *, nullable: bool = False) -> Decimal | None:
    """Validate a finite derived output without imposing the input magnitude bound."""
    return _validated_decimal(value, nullable=nullable, input_range=False)


def _hash_payload(payload: object) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("ascii")).hexdigest()


@dataclass(frozen=True, slots=True)
class IndicatorDefinitionV1(_NoCopyOrPickle):
    """A versioned formula bound to one instrument and one input lineage."""

    kind: Literal["EMA", "RSI", "ATR", "VWAP"]
    period: int | None
    formula_version: str
    parameter_version: str
    instrument_id: str
    venue: str
    timeframe: str
    source_version: str
    adjustment_version: str
    calendar_version: str

    def __post_init__(self) -> None:
        if self.formula_version != "IND-FORMULA-v1":
            raise IndicatorValidationError("unsupported indicator formula version")
        if self.kind not in ("EMA", "RSI", "ATR", "VWAP"):
            raise IndicatorValidationError("unknown indicator formula")
        if self.kind == "VWAP":
            if self.period is not None:
                raise IndicatorValidationError("VWAP has no period")
        elif type(self.period) is not int or not 2 <= self.period <= 10000:
            raise IndicatorValidationError("period must be 2..10000")
        for name in (
            "formula_version",
            "parameter_version",
            "instrument_id",
            "venue",
            "source_version",
            "adjustment_version",
            "calendar_version",
        ):
            _identity(getattr(self, name))
        _timeframe(self.timeframe)

    @property
    def semantic_hash(self) -> str:
        return _hash_payload({name: getattr(self, name) for name in self.__dataclass_fields__})


@dataclass(frozen=True, slots=True)
class FinalBarV1(_NoCopyOrPickle):
    """One finalized source revision; session_key comes from a venue calendar."""

    bar_id: str
    instrument_id: str
    venue: str
    timeframe: str
    session_key: str
    source_version: str
    adjustment_version: str
    calendar_version: str
    bar_end_ns: int
    event_time_ns: int
    availability_ns: int
    open: Decimal
    high: Decimal | None
    low: Decimal | None
    close: Decimal
    volume: Decimal | None = None
    finalized: bool = True
    gap: bool = False

    def __post_init__(self) -> None:
        for name in (
            "bar_id",
            "instrument_id",
            "venue",
            "session_key",
            "source_version",
            "adjustment_version",
            "calendar_version",
        ):
            _identity(getattr(self, name))
        _timeframe(self.timeframe)
        for name in ("bar_end_ns", "event_time_ns", "availability_ns"):
            _nanoseconds(getattr(self, name))
        if self.bar_end_ns > self.event_time_ns or self.event_time_ns > self.availability_ns:
            raise IndicatorValidationError("invalid indicator bar clocks")
        if type(self.finalized) is not bool or type(self.gap) is not bool:
            raise IndicatorValidationError("invalid indicator bar flags")
        for name in ("open", "high", "low", "close", "volume"):
            value = _exact_decimal(getattr(self, name), nullable=name in ("high", "low", "volume"))
            object.__setattr__(self, name, value)
        with localcontext(_CONTEXT):
            if self.open <= 0 or self.close <= 0:
                raise IndicatorValidationError("indicator prices must be positive")
            if self.high is not None and self.high <= 0:
                raise IndicatorValidationError("indicator prices must be positive")
            if self.low is not None and self.low <= 0:
                raise IndicatorValidationError("indicator prices must be positive")
            if self.high is not None and self.low is not None and self.high < self.low:
                raise IndicatorValidationError("indicator high is below low")
            if self.volume is not None and self.volume < 0:
                raise IndicatorValidationError("indicator volume is negative")

    @property
    def semantic_hash(self) -> str:
        payload = {
            name: (_canonical_decimal(value) if isinstance(value, Decimal) else value)
            for name in self.__dataclass_fields__
            if (value := getattr(self, name)) is not None
        }
        return _hash_payload(payload)


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False)
class IndicatorResultV1(_NoCopyOrPickle):
    """One finalized indicator point with explicit null and quality semantics."""

    warmup: bool
    gap: bool
    late: bool
    invalid: bool
    sample_count: int
    bar_end_ns: int
    bar_id: str
    input_digest: str
    revision: int
    definition_hash: str
    formula_version: str = "IND-FORMULA-v1"
    quality_flags: tuple[str, ...] = ()
    _value_text: str | None = field(init=False, repr=False)

    def __init__(
        self,
        value: Decimal | None,
        warmup: bool,
        gap: bool,
        late: bool,
        invalid: bool,
        sample_count: int,
        bar_end_ns: int,
        bar_id: str,
        input_digest: str,
        revision: int,
        definition_hash: str,
        formula_version: str = "IND-FORMULA-v1",
        quality_flags: tuple[str, ...] = (),
    ) -> None:
        try:
            require(self, _RESULT_ISSUER.tag)
        except SealError as exc:
            if exc.code != "SEAL_NOT_ISSUED":
                raise
        else:
            raise SealError("SEAL_FORBIDDEN_OPERATION")
        normalized = _derived_decimal(value, nullable=True)
        value_text = None if normalized is None else _canonical_decimal(normalized)
        if value_text is not None and len(value_text) > _MAX_RESULT_VALUE_TEXT_LENGTH:
            raise IndicatorValidationError("indicator number out of range")
        object.__setattr__(self, "_value_text", value_text)
        for name, item in (
            ("warmup", warmup),
            ("gap", gap),
            ("late", late),
            ("invalid", invalid),
            ("sample_count", sample_count),
            ("bar_end_ns", bar_end_ns),
            ("bar_id", bar_id),
            ("input_digest", input_digest),
            ("revision", revision),
            ("definition_hash", definition_hash),
            ("formula_version", formula_version),
            ("quality_flags", quality_flags),
        ):
            object.__setattr__(self, name, item)
        self.__post_init__()

    @property
    def value(self) -> Decimal | None:
        value_text = object.__getattribute__(self, "_value_text")
        return None if value_text is None else Decimal(value_text)

    def __post_init__(self) -> None:
        if self.formula_version != "IND-FORMULA-v1":
            raise IndicatorValidationError("unsupported indicator formula version")
        for name in ("warmup", "gap", "late", "invalid"):
            if type(getattr(self, name)) is not bool:
                raise IndicatorValidationError("invalid indicator quality flag")
        if type(self.sample_count) is not int or self.sample_count < 0:
            raise IndicatorValidationError("invalid indicator sample count")
        if type(self.revision) is not int or self.revision < 0:
            raise IndicatorValidationError("invalid indicator revision")
        _nanoseconds(self.bar_end_ns)
        _identity(self.bar_id)
        if not _is_digest(self.input_digest) or not _is_digest(self.definition_hash):
            raise IndicatorValidationError("invalid indicator digest")
        if type(self.quality_flags) is not tuple or any(
            not isinstance(flag, str) or _IDENTITY.fullmatch(flag) is None
            for flag in self.quality_flags
        ):
            raise IndicatorValidationError("invalid indicator quality flags")

    def canonical_bytes(self) -> bytes:
        """Stable UTF-8 wire form for parity and golden-vector assertions."""
        payload = {
            "bar_end_ns": self.bar_end_ns,
            "bar_id": self.bar_id,
            "definition_hash": self.definition_hash,
            "formula_version": self.formula_version,
            "gap": self.gap,
            "input_digest": self.input_digest,
            "invalid": self.invalid,
            "late": self.late,
            "revision": self.revision,
            "quality_flags": self.quality_flags,
            "sample_count": self.sample_count,
            "value": _canonical_decimal(self.value) if self.value is not None else None,
            "warmup": self.warmup,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
            "ascii"
        )

    def __repr__(self) -> str:
        return (
            f"IndicatorResultV1(value={self.value!r}, warmup={self.warmup!r}, "
            f"gap={self.gap!r}, late={self.late!r}, invalid={self.invalid!r}, "
            f"sample_count={self.sample_count!r}, bar_end_ns={self.bar_end_ns!r}, "
            f"bar_id={self.bar_id!r}, input_digest={self.input_digest!r}, "
            f"revision={self.revision!r}, definition_hash={self.definition_hash!r}, "
            f"formula_version={self.formula_version!r}, quality_flags={self.quality_flags!r})"
        )


def require_indicator_result(value: object) -> IndicatorResultV1:
    """Require an unchanged IND-001 kernel-issued result."""
    issued = require(value, _RESULT_ISSUER.tag)
    if type(issued) is not IndicatorResultV1:
        raise IndicatorValidationError("invalid indicator result issuer type")
    return issued


@dataclass(frozen=True, slots=True)
class _Snapshot(_NoCopyOrPickle):
    count: int = 0
    prev_close: Decimal | None = None
    seed_sum: Decimal = Decimal(0)
    value: Decimal | None = None
    gain_sum: Decimal = Decimal(0)
    loss_sum: Decimal = Decimal(0)
    avg_gain: Decimal | None = None
    avg_loss: Decimal | None = None
    vwap_num: Decimal = Decimal(0)
    vwap_den: Decimal = Decimal(0)
    session_key: str | None = None
    gap_active: bool = False


@dataclass(frozen=True, slots=True)
class IndicatorStateV1(_NoCopyOrPickle):
    """Immutable selected bars, results, and replay checkpoints."""

    bars: tuple[FinalBarV1, ...]
    results: tuple[IndicatorResultV1, ...]
    input_digest: str
    definition_hash: str
    last_bar_id: str | None
    revision: int
    asof_ns: int
    _token: InitVar[object | None] = None
    _snapshots: tuple[_Snapshot, ...] = field(default=(), repr=False, compare=False)
    _checkpoint_start: int = field(default=0, repr=False, compare=False)
    _base_snapshot: _Snapshot | None = field(default=None, repr=False, compare=False)

    def __post_init__(self, _token: object | None) -> None:
        if _token is not _STATE_TOKEN:
            raise IndicatorCheckpointError("indicator checkpoint must come from kernel")
        if type(self.bars) is not tuple or any(
            not isinstance(item, FinalBarV1) for item in self.bars
        ):
            raise IndicatorValidationError("indicator state bars must be immutable")
        if type(self.results) is not tuple or any(
            not isinstance(item, IndicatorResultV1) for item in self.results
        ):
            raise IndicatorValidationError("indicator state results must be immutable")
        if type(self._snapshots) is not tuple or any(
            not isinstance(item, _Snapshot) for item in self._snapshots
        ):
            raise IndicatorValidationError("indicator checkpoints must be immutable")
        if self._base_snapshot is not None and not isinstance(self._base_snapshot, _Snapshot):
            raise IndicatorValidationError("indicator checkpoint invalid")
        if len(self.bars) != len(self.results):
            raise IndicatorValidationError("indicator state length mismatch")
        if type(self.revision) is not int or self.revision < 0:
            raise IndicatorValidationError("invalid indicator revision")
        if type(self._checkpoint_start) is not int or not 0 <= self._checkpoint_start <= len(
            self.bars
        ):
            raise IndicatorValidationError("invalid indicator checkpoint index")
        if self._snapshots and len(self._snapshots) != len(self.bars) - self._checkpoint_start:
            raise IndicatorValidationError("indicator checkpoint length mismatch")
        _nanoseconds(self.asof_ns)
        if self.last_bar_id is not None:
            _identity(self.last_bar_id)
        if not _is_digest(self.input_digest) or not _is_digest(self.definition_hash):
            raise IndicatorValidationError("invalid indicator digest")

    @property
    def checkpoint_digest(self) -> str:
        return self.input_digest


def _is_digest(value: object) -> bool:
    return isinstance(value, str) and _HASH.fullmatch(value) is not None
