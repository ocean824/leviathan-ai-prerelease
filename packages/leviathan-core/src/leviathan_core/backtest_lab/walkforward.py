"""Deterministic, fixture-only walk-forward folds over BT-002 coverage."""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from decimal import Decimal
from typing import Literal, NoReturn, SupportsIndex, TypeVar

from leviathan_core.feature_store.models import FeatureResultV1
from leviathan_core.numeric import canonical_json, parse_decimal
from leviathan_core.seal import MAX_DIGEST_NODES_CEILING, Issuer, SealError, require
from leviathan_core.seal import digest as seal_digest

from .events import (
    CoverageGapV1,
    CoverageReportV1,
    DatasetManifestV1,
    SequenceGapV1,
)

WalkForwardScheme = Literal["fixed", "rolling", "expanding", "anchored"]
WarmStartPolicy = Literal["reset", "checkpoint"]
FeatureKey = tuple[str, str]
ParameterScalar = str | int | bool | Decimal

_MAX_UTC_NS = 253_402_300_799_999_999_999
MAX_FOLDS = 4096
MAX_FEATURE_ROWS = 4096
_MAX_FOLDS = MAX_FOLDS
_SHA256_LEN = 64
_RecordT = TypeVar("_RecordT")


class WalkForwardError(ValueError):
    """Base for content-free deterministic walk-forward rejections."""

    code = "WALK_FORWARD_INVALID"

    def __init__(self) -> None:
        super().__init__(self.code)


class WalkForwardSpecError(WalkForwardError):
    code = "WALK_FORWARD_SPEC_INVALID"


class DatasetCoverageError(WalkForwardError):
    code = "DATASET_COVERAGE_INVALID"


class CalendarInvalidError(WalkForwardError):
    code = "CALENDAR_INVALID"


class EmptyFoldError(WalkForwardError):
    code = "NO_VALID_FOLDS"


class InputTooLargeError(WalkForwardError):
    code = "INPUT_TOO_LARGE"


class FoldOverlapError(WalkForwardSpecError):
    code = "OOS_WINDOWS_OVERLAP"


class CoverageInsufficientError(WalkForwardError):
    code = "COVERAGE_INSUFFICIENT"


class FeatureUnavailableError(WalkForwardError):
    code = "FEATURE_UNAVAILABLE_AT_CUTOFF"


class FoldNotFoundError(WalkForwardError):
    code = "FOLD_NOT_FOUND"


class SelectorError(WalkForwardError):
    code = "SELECTOR_INVALID"


class OOSSelectionAccessError(SelectorError):
    code = "OOS_READ_BLOCKED"


class SelectorExecutionError(WalkForwardError):
    code = "SELECTOR_FAILED"


class _FrozenRecord:
    """Value objects cannot be copied, deep-copied or reconstructed by pickle."""

    def __copy__(self) -> NoReturn:
        raise TypeError("walk-forward records cannot be copied")

    def __deepcopy__(self, memo: object) -> NoReturn:
        raise TypeError("walk-forward records cannot be copied")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise TypeError("walk-forward records cannot be pickled")


def _digest(value: object) -> str:
    try:
        return seal_digest(value, max_nodes=MAX_DIGEST_NODES_CEILING)
    except SealError:
        raise InputTooLargeError() from None


def _issue(issuer: Issuer, value: _RecordT) -> _RecordT:
    try:
        return issuer.issue(value)
    except SealError:
        raise InputTooLargeError() from None


def _require_issued(value: _RecordT, tag: str) -> _RecordT:
    try:
        return require(value, tag)
    except SealError:
        raise InputTooLargeError() from None


def _token(value: object) -> str:
    if (
        type(value) is not str
        or not value
        or not value.isascii()
        or any(ord(char) < 33 or ord(char) > 126 for char in value)
    ):
        raise WalkForwardSpecError()
    return value


def _timestamp(value: object) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_UTC_NS:
        raise WalkForwardSpecError()
    return value


def _sha256(value: object) -> str:
    if (
        type(value) is not str
        or len(value) != _SHA256_LEN
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise DatasetCoverageError()
    return value


def _feature_key(value: object) -> FeatureKey:
    if type(value) is not tuple or len(value) != 2:
        raise WalkForwardSpecError()
    return (_token(value[0]), _token(value[1]))


def _feature_row_key(row: FeatureResultV1) -> tuple[int, str, str, str, str]:
    return (
        row.asof_ns,
        row.instrument_id,
        row.feature_name,
        row.feature_version,
        row.source_record_key or "",
    )


@dataclass(frozen=True, slots=True)
class WalkForwardSpecV1(_FrozenRecord):
    """Immutable UTC-ns window policy. Anchored mode requires ``anchor_ns``."""

    scheme: WalkForwardScheme
    is_length_ns: int
    oos_length_ns: int
    step_ns: int
    embargo_ns: int
    warm_start_policy: WarmStartPolicy = "reset"
    min_oos_fraction: Decimal = Decimal("1")
    feature_allowlist: tuple[FeatureKey, ...] = ()
    anchor_ns: int | None = None

    def __post_init__(self) -> None:
        if type(self.scheme) is not str or self.scheme not in (
            "fixed",
            "rolling",
            "expanding",
            "anchored",
        ):
            raise WalkForwardSpecError()
        for name in ("is_length_ns", "oos_length_ns", "step_ns"):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise WalkForwardSpecError()
        if type(self.embargo_ns) is not int or self.embargo_ns < 0:
            raise WalkForwardSpecError()
        if type(self.warm_start_policy) is not str or self.warm_start_policy not in (
            "reset",
            "checkpoint",
        ):
            raise WalkForwardSpecError()
        if self.scheme != "fixed" and self.step_ns < self.oos_length_ns:
            raise FoldOverlapError()
        if self.scheme == "anchored":
            _timestamp(self.anchor_ns)
        elif self.anchor_ns is not None:
            raise WalkForwardSpecError()
        try:
            fraction = parse_decimal(self.min_oos_fraction, field="min_oos_fraction")
        except (TypeError, ValueError):
            raise WalkForwardSpecError() from None
        if fraction < 0 or fraction > 1:
            raise WalkForwardSpecError()
        try:
            feature_keys = tuple(_feature_key(value) for value in self.feature_allowlist)
        except (TypeError, ValueError, IndexError):
            raise WalkForwardSpecError() from None
        if len(set(feature_keys)) != len(feature_keys):
            raise WalkForwardSpecError()
        object.__setattr__(self, "min_oos_fraction", fraction)
        object.__setattr__(self, "feature_allowlist", tuple(sorted(feature_keys)))


@dataclass(frozen=True, slots=True)
class DatasetCoverageV1(_FrozenRecord):
    """BT-002 dataset/coverage evidence plus an immutable FEAT-001 as-of snapshot."""

    dataset_manifest: DatasetManifestV1
    coverage_report: CoverageReportV1
    feature_rows: tuple[FeatureResultV1, ...] = ()

    def __post_init__(self) -> None:
        if type(self.dataset_manifest) is not DatasetManifestV1:
            raise DatasetCoverageError()
        if type(self.coverage_report) is not CoverageReportV1:
            raise DatasetCoverageError()
        try:
            rows = tuple(self.feature_rows)
        except (TypeError, ValueError):
            raise DatasetCoverageError() from None
        if len(rows) > MAX_FEATURE_ROWS:
            raise InputTooLargeError()
        if any(type(row) is not FeatureResultV1 for row in rows):
            raise DatasetCoverageError()
        keys = [_feature_row_key(row) for row in rows]
        if len(keys) != len(set(keys)):
            raise DatasetCoverageError()
        for row in rows:
            _token(row.feature_name)
            _token(row.feature_version)
            _token(row.instrument_id)
            _timestamp(row.asof_ns)
            if row.found and (
                type(row.event_time_ns) is not int
                or type(row.availability_ns) is not int
                or row.event_time_ns > row.asof_ns
                or row.availability_ns > row.asof_ns
            ):
                raise FeatureUnavailableError()
        sessions = {
            (session.venue, session.session_date) for session in self.dataset_manifest.sessions
        }
        if (
            type(self.coverage_report.complete) is not bool
            or type(self.coverage_report.skipped_unavailable) is not int
            or self.coverage_report.skipped_unavailable < 0
            or any(type(gap) is not SequenceGapV1 for gap in self.coverage_report.observed_gaps)
            or any(type(gap) is not CoverageGapV1 for gap in self.coverage_report.gaps)
        ):
            raise DatasetCoverageError()
        covered = tuple(self.coverage_report.covered_sessions)
        uncovered = tuple(self.coverage_report.uncovered_sessions)
        if (
            len(covered) != len(set(covered))
            or len(uncovered) != len(set(uncovered))
            or set(covered) & set(uncovered)
            or not (set(covered) | set(uncovered)) <= sessions
        ):
            raise DatasetCoverageError()
        if self.coverage_report.complete and (
            set(covered) != sessions
            or uncovered
            or self.coverage_report.observed_gaps
            or self.coverage_report.gaps
            or self.coverage_report.skipped_unavailable
        ):
            raise DatasetCoverageError()
        stream_ids = {stream.stream_id for stream in self.dataset_manifest.streams}
        if any(
            gap.stream_id not in stream_ids for gap in self.coverage_report.observed_gaps
        ) or any(gap.stream_id not in stream_ids for gap in self.coverage_report.gaps):
            raise DatasetCoverageError()
        members = {member.instrument: member for member in self.dataset_manifest.universe}
        for row in rows:
            member = members.get(row.instrument_id)
            if (
                member is None
                or row.asof_ns < member.listed_ns
                or (member.delisted_ns is not None and row.asof_ns >= member.delisted_ns)
            ):
                raise FeatureUnavailableError()
        object.__setattr__(self, "feature_rows", tuple(sorted(rows, key=_feature_row_key)))

    @property
    def dataset_snapshot_sha256(self) -> str:
        return _digest(self.dataset_manifest)

    @property
    def coverage_snapshot_sha256(self) -> str:
        return _digest(self.coverage_report)

    @property
    def universe_snapshot_sha256(self) -> str:
        return _digest(self.dataset_manifest.universe)

    @property
    def feature_snapshot_sha256(self) -> str:
        return _digest(self.feature_rows)


@dataclass(frozen=True, slots=True, weakref_slot=True)
class FoldV1(_FrozenRecord):
    fold_id: str
    index: int
    is_start_ns: int
    is_end_ns: int
    oos_start_ns: int
    oos_end_ns: int
    embargo_ns: int
    warm_start_policy: WarmStartPolicy
    feature_allowlist: tuple[FeatureKey, ...]
    is_coverage: tuple[int, int]
    oos_coverage: tuple[int, int]

    def __post_init__(self) -> None:
        _token(self.fold_id)
        for value in (self.is_start_ns, self.is_end_ns, self.oos_start_ns, self.oos_end_ns):
            _timestamp(value)
        if (
            type(self.index) is not int
            or self.index < 1
            or type(self.embargo_ns) is not int
            or self.embargo_ns < 0
            or self.is_start_ns >= self.is_end_ns
            or self.oos_start_ns >= self.oos_end_ns
            or self.is_end_ns + self.embargo_ns > self.oos_start_ns
            or type(self.warm_start_policy) is not str
            or self.warm_start_policy not in ("reset", "checkpoint")
        ):
            raise WalkForwardSpecError()
        try:
            feature_keys = tuple(_feature_key(value) for value in self.feature_allowlist)
        except (TypeError, ValueError, IndexError):
            raise WalkForwardSpecError() from None
        if len(feature_keys) != len(set(feature_keys)):
            raise WalkForwardSpecError()
        for fraction in (self.is_coverage, self.oos_coverage):
            if (
                type(fraction) is not tuple
                or len(fraction) != 2
                or any(type(value) is not int or value < 0 for value in fraction)
                or fraction[1] <= 0
                or fraction[0] > fraction[1]
            ):
                raise WalkForwardSpecError()
        object.__setattr__(self, "feature_allowlist", tuple(sorted(feature_keys)))


@dataclass(frozen=True, slots=True)
class DroppedFoldV1(_FrozenRecord):
    """A candidate omitted rather than silently shortened or snapped."""

    index: int
    is_start_ns: int
    is_end_ns: int
    oos_start_ns: int
    oos_end_ns: int
    reason: Literal["PARTIAL_TAIL", "BOUNDARY_OUTSIDE_SESSION"]

    def __post_init__(self) -> None:
        if type(self.index) is not int or self.index < 1:
            raise WalkForwardSpecError()
        for value in (self.is_start_ns, self.is_end_ns, self.oos_start_ns, self.oos_end_ns):
            _timestamp(value)
        if (
            self.is_start_ns >= self.is_end_ns
            or self.oos_start_ns > self.oos_end_ns
            or type(self.reason) is not str
            or self.reason not in ("PARTIAL_TAIL", "BOUNDARY_OUTSIDE_SESSION")
        ):
            raise WalkForwardSpecError()


@dataclass(frozen=True, slots=True, weakref_slot=True)
class FoldManifestV1(_FrozenRecord):
    dataset_id: str
    dataset_version: str
    universe_version: str
    calendar_id: str
    calendar_version: str
    dataset_snapshot_sha256: str
    coverage_snapshot_sha256: str
    universe_snapshot_sha256: str
    feature_snapshot_sha256: str
    spec_sha256: str
    folds: tuple[FoldV1, ...]
    manifest_sha256: str
    dropped_folds: tuple[DroppedFoldV1, ...] = ()

    def __post_init__(self) -> None:
        for value in (
            self.dataset_id,
            self.dataset_version,
            self.universe_version,
            self.calendar_id,
            self.calendar_version,
        ):
            _token(value)
        for value in (
            self.dataset_snapshot_sha256,
            self.coverage_snapshot_sha256,
            self.universe_snapshot_sha256,
            self.feature_snapshot_sha256,
            self.spec_sha256,
            self.manifest_sha256,
        ):
            _sha256(value)
        try:
            folds = tuple(self.folds)
            dropped_folds = tuple(self.dropped_folds)
        except (TypeError, ValueError):
            raise WalkForwardSpecError() from None
        if (
            not folds
            or len(folds) > _MAX_FOLDS
            or any(type(fold) is not FoldV1 for fold in folds)
            or tuple(fold.index for fold in folds) != tuple(sorted(fold.index for fold in folds))
            or len({fold.index for fold in folds}) != len(folds)
            or len({fold.fold_id for fold in folds}) != len(folds)
            or len(dropped_folds) > _MAX_FOLDS
            or any(type(fold) is not DroppedFoldV1 for fold in dropped_folds)
            or tuple(fold.index for fold in dropped_folds)
            != tuple(sorted(fold.index for fold in dropped_folds))
            or len({fold.index for fold in dropped_folds}) != len(dropped_folds)
            or {fold.index for fold in folds} & {fold.index for fold in dropped_folds}
        ):
            raise WalkForwardSpecError()
        previous_oos_end: int | None = None
        for fold in folds:
            if previous_oos_end is not None and fold.oos_start_ns < previous_oos_end:
                raise FoldOverlapError()
            previous_oos_end = fold.oos_end_ns
        object.__setattr__(self, "folds", folds)
        object.__setattr__(self, "dropped_folds", dropped_folds)
        stable = (
            self.dataset_id,
            self.dataset_version,
            self.universe_version,
            self.calendar_id,
            self.calendar_version,
            self.dataset_snapshot_sha256,
            self.coverage_snapshot_sha256,
            self.universe_snapshot_sha256,
            self.feature_snapshot_sha256,
            self.spec_sha256,
            folds,
            dropped_folds,
        )
        if _digest(stable) != self.manifest_sha256:
            raise WalkForwardSpecError()


@dataclass(frozen=True, slots=True, weakref_slot=True)
class TrainingFoldViewV1(_FrozenRecord):
    """Selection input intentionally contains training rows and no OOS field."""

    fold_id: str
    is_start_ns: int
    is_end_ns: int
    warm_start_policy: WarmStartPolicy
    feature_allowlist: tuple[FeatureKey, ...]
    training_features: tuple[FeatureResultV1, ...]
    dataset_snapshot_sha256: str
    feature_snapshot_sha256: str
    training_snapshot_sha256: str

    def __post_init__(self) -> None:
        _token(self.fold_id)
        _timestamp(self.is_start_ns)
        _timestamp(self.is_end_ns)
        if self.is_start_ns >= self.is_end_ns:
            raise WalkForwardSpecError()
        for value in (
            self.dataset_snapshot_sha256,
            self.feature_snapshot_sha256,
            self.training_snapshot_sha256,
        ):
            _sha256(value)
        if type(self.warm_start_policy) is not str or self.warm_start_policy not in (
            "reset",
            "checkpoint",
        ):
            raise WalkForwardSpecError()
        try:
            feature_keys = tuple(_feature_key(value) for value in self.feature_allowlist)
            training_features = tuple(self.training_features)
        except (TypeError, ValueError, IndexError):
            raise DatasetCoverageError() from None
        if len(feature_keys) != len(set(feature_keys)) or any(
            type(row) is not FeatureResultV1 for row in training_features
        ):
            raise DatasetCoverageError()
        if any(not self.is_start_ns <= row.asof_ns < self.is_end_ns for row in training_features):
            raise FeatureUnavailableError()
        training_features = tuple(sorted(training_features, key=_feature_row_key))
        object.__setattr__(self, "feature_allowlist", tuple(sorted(feature_keys)))
        object.__setattr__(self, "training_features", training_features)
        if (
            _digest((self.fold_id, self.is_start_ns, self.is_end_ns, training_features))
            != self.training_snapshot_sha256
        ):
            raise DatasetCoverageError()

    def __getattr__(self, name: str) -> object:
        if type(name) is str and (
            name.startswith("oos_") or name in ("oos", "out_of_sample", "test_features")
        ):
            raise OOSSelectionAccessError()
        raise AttributeError(name)


@dataclass(frozen=True, slots=True, weakref_slot=True)
class SelectedParametersV1(_FrozenRecord):
    fold_id: str
    training_snapshot_sha256: str
    parameters: tuple[tuple[str, ParameterScalar], ...]
    parameters_sha256: str

    def __post_init__(self) -> None:
        _token(self.fold_id)
        _sha256(self.training_snapshot_sha256)
        _sha256(self.parameters_sha256)
        try:
            parameters = tuple(
                (_token(key), _parameter_value(value)) for key, value in self.parameters
            )
        except (TypeError, ValueError):
            raise SelectorError() from None
        if not parameters or len({key for key, _ in parameters}) != len(parameters):
            raise SelectorError()
        parameters = tuple(sorted(parameters, key=lambda item: item[0]))
        encoded = canonical_json(
            {
                "fold_id": self.fold_id,
                "parameters": parameters,
                "training_snapshot_sha256": self.training_snapshot_sha256,
            }
        )
        if hashlib.sha256(encoded).hexdigest() != self.parameters_sha256:
            raise SelectorError()
        object.__setattr__(self, "parameters", parameters)


_FOLD_ISSUER = Issuer("bt004.fold_manifest.v1", max_digest_nodes=MAX_DIGEST_NODES_CEILING)
_TRAINING_VIEW_ISSUER = Issuer("bt004.training_view.v1", max_digest_nodes=MAX_DIGEST_NODES_CEILING)
_PARAMETER_ISSUER = Issuer(
    "bt004.selected_parameters.v1", max_digest_nodes=MAX_DIGEST_NODES_CEILING
)


def _require_manifest(manifest: FoldManifestV1) -> FoldManifestV1:
    if type(manifest) is not FoldManifestV1:
        raise WalkForwardSpecError()
    return _require_issued(manifest, _FOLD_ISSUER.tag)


def _coverage_ns(
    start_ns: int,
    end_ns: int,
    coverage: DatasetCoverageV1,
) -> tuple[int, int]:
    expected = covered = 0
    report = coverage.coverage_report
    manifest = coverage.dataset_manifest
    covered_keys = set(report.covered_sessions)
    bad_streams = {gap.stream_id for gap in report.observed_gaps}
    bad_streams.update(gap.stream_id for gap in report.gaps)
    bad_venues = {stream.venue for stream in manifest.streams if stream.stream_id in bad_streams}
    if report.skipped_unavailable:
        return 0, 1
    for session in manifest.sessions:
        overlap = max(0, min(end_ns, session.close_ns) - max(start_ns, session.open_ns))
        if not overlap:
            continue
        expected += overlap
        key = (session.venue, session.session_date)
        if key in covered_keys and session.venue not in bad_venues:
            covered += overlap
    return covered, expected


def _ratio_at_least(actual: tuple[int, int], minimum: Decimal) -> bool:
    covered, expected = actual
    if expected <= 0:
        return False
    from leviathan_core.numeric import Ratio

    return Ratio(covered, expected).ge(Ratio.from_decimals(minimum, 1))


def _window_coverage(
    start_ns: int,
    end_ns: int,
    coverage: DatasetCoverageV1,
    *,
    minimum: Decimal,
) -> tuple[int, int]:
    result = _coverage_ns(start_ns, end_ns, coverage)
    if result[1] <= 0:
        raise CalendarInvalidError()
    if not _ratio_at_least(result, minimum):
        raise CoverageInsufficientError()
    return result


def _inside_session_start(timestamp_ns: int, coverage: DatasetCoverageV1) -> bool:
    return any(
        session.open_ns <= timestamp_ns < session.close_ns
        for session in coverage.dataset_manifest.sessions
    )


def _inside_session_end(timestamp_ns: int, coverage: DatasetCoverageV1) -> bool:
    return any(
        session.open_ns < timestamp_ns <= session.close_ns
        for session in coverage.dataset_manifest.sessions
    )


def _make_manifest(
    spec: WalkForwardSpecV1,
    coverage: DatasetCoverageV1,
    folds: tuple[FoldV1, ...],
    dropped_folds: tuple[DroppedFoldV1, ...],
) -> FoldManifestV1:
    dataset = coverage.dataset_manifest
    dataset_hash = coverage.dataset_snapshot_sha256
    coverage_hash = coverage.coverage_snapshot_sha256
    universe_hash = coverage.universe_snapshot_sha256
    feature_hash = coverage.feature_snapshot_sha256
    spec_hash = _digest(spec)
    stable = (
        dataset.dataset_id,
        dataset.dataset_version,
        dataset.universe_version,
        dataset.calendar_id,
        dataset.calendar_version,
        dataset_hash,
        coverage_hash,
        universe_hash,
        feature_hash,
        spec_hash,
        folds,
        dropped_folds,
    )
    manifest_hash = _digest(stable)
    return _issue(
        _FOLD_ISSUER,
        FoldManifestV1(
            dataset_id=dataset.dataset_id,
            dataset_version=dataset.dataset_version,
            universe_version=dataset.universe_version,
            calendar_id=dataset.calendar_id,
            calendar_version=dataset.calendar_version,
            dataset_snapshot_sha256=dataset_hash,
            coverage_snapshot_sha256=coverage_hash,
            universe_snapshot_sha256=universe_hash,
            feature_snapshot_sha256=feature_hash,
            spec_sha256=spec_hash,
            folds=folds,
            manifest_sha256=manifest_hash,
            dropped_folds=dropped_folds,
        ),
    )


def split(spec: WalkForwardSpecV1, coverage: DatasetCoverageV1) -> FoldManifestV1:
    """Build UTC-ns half-open folds from an exact dataset and coverage snapshot."""
    if type(spec) is not WalkForwardSpecV1 or type(coverage) is not DatasetCoverageV1:
        raise WalkForwardSpecError()
    dataset = coverage.dataset_manifest
    start = spec.anchor_ns if spec.scheme == "anchored" else dataset.start_ns
    if start is None or start < dataset.start_ns or start >= dataset.end_ns:
        raise CalendarInvalidError()
    if not dataset.sessions:
        raise CalendarInvalidError()
    is_start = start
    is_end = is_start + spec.is_length_ns
    folds: list[FoldV1] = []
    dropped_folds: list[DroppedFoldV1] = []
    candidate_index = 0
    previous_oos_end: int | None = None
    while candidate_index < _MAX_FOLDS + 1:
        candidate_index += 1
        oos_start = is_end + spec.embargo_ns
        oos_end = oos_start + spec.oos_length_ns
        if is_end > dataset.end_ns or oos_end > dataset.end_ns:
            dropped_folds.append(
                DroppedFoldV1(
                    index=candidate_index,
                    is_start_ns=is_start,
                    is_end_ns=is_end,
                    oos_start_ns=min(oos_start, dataset.end_ns),
                    oos_end_ns=min(oos_end, dataset.end_ns),
                    reason="PARTIAL_TAIL",
                )
            )
            break
        if candidate_index > _MAX_FOLDS:
            raise InputTooLargeError()
        if is_start >= is_end or is_end + spec.embargo_ns > oos_start:
            raise WalkForwardSpecError()
        if (
            not _inside_session_start(is_start, coverage)
            or not _inside_session_end(is_end, coverage)
            or not _inside_session_start(oos_start, coverage)
            or not _inside_session_end(oos_end, coverage)
            or (spec.scheme == "anchored" and not _inside_session_start(start, coverage))
        ):
            dropped_folds.append(
                DroppedFoldV1(
                    index=candidate_index,
                    is_start_ns=is_start,
                    is_end_ns=is_end,
                    oos_start_ns=oos_start,
                    oos_end_ns=oos_end,
                    reason="BOUNDARY_OUTSIDE_SESSION",
                )
            )
            if spec.scheme == "fixed":
                break
            if spec.scheme == "rolling":
                is_start += spec.step_ns
                is_end += spec.step_ns
            else:
                is_end += spec.step_ns
            continue
        if previous_oos_end is not None and oos_start < previous_oos_end:
            raise FoldOverlapError()
        is_coverage = _window_coverage(is_start, is_end, coverage, minimum=Decimal("1"))
        oos_coverage = _window_coverage(oos_start, oos_end, coverage, minimum=spec.min_oos_fraction)
        fold = FoldV1(
            fold_id=f"fold-{candidate_index:06d}",
            index=candidate_index,
            is_start_ns=is_start,
            is_end_ns=is_end,
            oos_start_ns=oos_start,
            oos_end_ns=oos_end,
            embargo_ns=spec.embargo_ns,
            warm_start_policy=spec.warm_start_policy,
            feature_allowlist=spec.feature_allowlist,
            is_coverage=is_coverage,
            oos_coverage=oos_coverage,
        )
        folds.append(fold)
        previous_oos_end = oos_end
        if spec.scheme == "fixed":
            break
        if spec.scheme == "rolling":
            is_start += spec.step_ns
            is_end += spec.step_ns
        else:
            is_end += spec.step_ns
    if not folds:
        raise EmptyFoldError()
    return _make_manifest(spec, coverage, tuple(folds), tuple(dropped_folds))


def training_view(
    manifest: FoldManifestV1,
    fold_id: str,
    coverage: DatasetCoverageV1,
) -> TrainingFoldViewV1:
    """Return a sealed training-only feature view for one manifest fold."""
    _require_issued(manifest, _FOLD_ISSUER.tag)
    if type(coverage) is not DatasetCoverageV1:
        raise DatasetCoverageError()
    if (
        coverage.dataset_snapshot_sha256 != manifest.dataset_snapshot_sha256
        or coverage.coverage_snapshot_sha256 != manifest.coverage_snapshot_sha256
        or coverage.universe_snapshot_sha256 != manifest.universe_snapshot_sha256
        or coverage.feature_snapshot_sha256 != manifest.feature_snapshot_sha256
    ):
        raise DatasetCoverageError()
    if type(fold_id) is not str:
        raise FoldNotFoundError()
    fold = next((item for item in manifest.folds if item.fold_id == fold_id), None)
    if fold is None:
        raise FoldNotFoundError()
    allowlist = set(fold.feature_allowlist)
    training_features = tuple(
        row
        for row in coverage.feature_rows
        if (row.feature_name, row.feature_version) in allowlist
        and fold.is_start_ns <= row.asof_ns < fold.is_end_ns
    )
    for row in training_features:
        if row.found and (
            row.event_time_ns is None
            or row.availability_ns is None
            or row.event_time_ns > row.asof_ns
            or row.availability_ns > row.asof_ns
        ):
            raise FeatureUnavailableError()
    training_hash = _digest((fold.fold_id, fold.is_start_ns, fold.is_end_ns, training_features))
    view = TrainingFoldViewV1(
        fold_id=fold.fold_id,
        is_start_ns=fold.is_start_ns,
        is_end_ns=fold.is_end_ns,
        warm_start_policy=fold.warm_start_policy,
        feature_allowlist=fold.feature_allowlist,
        training_features=training_features,
        dataset_snapshot_sha256=manifest.dataset_snapshot_sha256,
        feature_snapshot_sha256=manifest.feature_snapshot_sha256,
        training_snapshot_sha256=training_hash,
    )
    return _issue(_TRAINING_VIEW_ISSUER, view)


def _parameter_value(value: object) -> ParameterScalar:
    if type(value) in (str, int, bool):
        return value  # type: ignore[return-value]
    if type(value) is Decimal:
        try:
            return parse_decimal(value, field="parameter")
        except (TypeError, ValueError):
            raise SelectorError() from None
    raise SelectorError()


def select_parameters(
    view: TrainingFoldViewV1,
    selector: Callable[[TrainingFoldViewV1], Mapping[str, ParameterScalar]],
) -> SelectedParametersV1:
    """Call a selector with only sealed IS rows and bind its output to that view."""
    _require_issued(view, _TRAINING_VIEW_ISSUER.tag)
    if not callable(selector):
        raise SelectorError()
    try:
        raw = selector(view)
    except OOSSelectionAccessError:
        raise
    except Exception:
        raise SelectorExecutionError() from None
    _require_issued(view, _TRAINING_VIEW_ISSUER.tag)
    if not isinstance(raw, Mapping):
        raise SelectorError()
    parameters: list[tuple[str, ParameterScalar]] = []
    try:
        for key, value in raw.items():
            parameters.append((_token(key), _parameter_value(value)))
    except (TypeError, ValueError):
        raise SelectorError() from None
    parameters.sort(key=lambda item: item[0])
    if not parameters or len({key for key, _ in parameters}) != len(parameters):
        raise SelectorError()
    values = tuple(parameters)
    encoded = canonical_json(
        {
            "fold_id": view.fold_id,
            "parameters": values,
            "training_snapshot_sha256": view.training_snapshot_sha256,
        }
    )
    result = SelectedParametersV1(
        fold_id=view.fold_id,
        training_snapshot_sha256=view.training_snapshot_sha256,
        parameters=values,
        parameters_sha256=hashlib.sha256(encoded).hexdigest(),
    )
    return _issue(_PARAMETER_ISSUER, result)


__all__ = [
    "MAX_FEATURE_ROWS",
    "MAX_FOLDS",
    "CalendarInvalidError",
    "CoverageInsufficientError",
    "DatasetCoverageError",
    "DatasetCoverageV1",
    "DroppedFoldV1",
    "EmptyFoldError",
    "FeatureUnavailableError",
    "FoldManifestV1",
    "FoldNotFoundError",
    "FoldOverlapError",
    "FoldV1",
    "InputTooLargeError",
    "OOSSelectionAccessError",
    "SelectedParametersV1",
    "SelectorError",
    "SelectorExecutionError",
    "TrainingFoldViewV1",
    "WalkForwardError",
    "WalkForwardScheme",
    "WalkForwardSpecError",
    "WalkForwardSpecV1",
    "WarmStartPolicy",
    "select_parameters",
    "split",
    "training_view",
]
