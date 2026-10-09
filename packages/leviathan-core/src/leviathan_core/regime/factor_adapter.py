"""Pure, fixture-gated projections of reviewed analytics into regime factors.

The injected mapping and source registries are trusted configuration ports. Source
records, feature results, signals and truth verdicts are untrusted evidence and
are checked again at the requested point in time. No learned weights or routes
are activated here.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import InitVar, dataclass, field, fields, replace
from decimal import Decimal
from typing import Any, Literal
from weakref import ReferenceType, finalize, ref

from leviathan_core.feature_store.models import FeatureResultV1
from leviathan_core.numeric import NumericError, canonical_json, parse_decimal, parse_int
from leviathan_core.regime.models import (
    DEFAULT_WEIGHT_VERSION,
    FACTOR_KINDS,
    RELEASE_LAGS_NS,
    FactorKind,
    RegimeClockV1,
    RegimeFactorV1,
    RegimeSnapshotV1,
    RegimeSourceIdV1,
    RegimeSourceRegistryV1,
)

SourceFamily = Literal["GEX", "FLOW", "DP", "COT"]
DatabaseScope = Literal["global", "book", "sector", "instrument"]
RegimeScope = Literal["global", "class", "symbol"]
Entitlement = Literal["LICENSED", "SYNTHETIC", "UNENTITLED"]
Quality = Literal["GOOD", "BAD", "UNKNOWN"]
SignalStatus = Literal["FINALIZED", "PROVISIONAL", "UNKNOWN"]
TruthStatus = Literal["PASS", "SOFT_FAIL", "HARD_FAIL", "UNKNOWN"]

_FAMILY_KIND: dict[SourceFamily, FactorKind] = {
    "GEX": "dealer", "FLOW": "flow", "DP": "dp", "COT": "macro",
}
_SCOPE_PRIORITY: dict[DatabaseScope, int] = {
    "global": 0, "book": 1, "sector": 2, "instrument": 3,
}
_IDENTIFIER = re.compile(r"[A-Za-z0-9._:/-]{1,128}\Z", re.ASCII)
_REASON = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z", re.ASCII)
_ISSUER = object()
_MAX_NS = 2**63 - 1


class RegimeAdapterError(ValueError):
    """Content-free error at the public adapter boundary."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class _NoCopy:
    __slots__ = ()

    def __copy__(self) -> None:
        raise RegimeAdapterError("IMMUTABLE_COPY")

    def __deepcopy__(self, memo: object) -> None:
        raise RegimeAdapterError("IMMUTABLE_COPY")

    def __reduce_ex__(self, protocol: object) -> str | tuple[Any, ...]:
        raise RegimeAdapterError("IMMUTABLE_COPY")


def _id(value: object) -> bool:
    return type(value) is str and _IDENTIFIER.fullmatch(value) is not None


def _integer(value: object, name: str, *, maximum: int = _MAX_NS) -> int:
    try:
        return parse_int(value, field=name, min_value=0, max_value=maximum)
    except NumericError as error:
        raise RegimeAdapterError(error.code) from None


def _decimal(value: object, name: str) -> Decimal:
    if not isinstance(value, Decimal):
        raise RegimeAdapterError("INVALID_DECIMAL")
    try:
        return parse_decimal(value, field=name)
    except NumericError as error:
        raise RegimeAdapterError(error.code) from None


def _digest(value: object) -> str:
    try:
        return hashlib.sha256(canonical_json(value)).hexdigest()
    except NumericError:
        raise RegimeAdapterError("AUDIT_INVALID") from None


@dataclass(frozen=True, slots=True)
class RegimeFactorSourcePortV1(_NoCopy):
    """One versioned upstream source row and its FEAT as-of normalization pin."""

    kind: FactorKind
    family: SourceFamily
    source_id: RegimeSourceIdV1
    source_version: str
    record_id: str
    revision: int
    correction_of: str | None
    event_ns: int
    available_ns: int
    fresh_until_ns: int
    scope_type: DatabaseScope
    scope_id: str | None
    raw_value: Decimal | None
    raw_unit: str
    entitlement: Entitlement
    quality: Quality
    feature: FeatureResultV1 | None
    upstream_interface_id: str | None = None

    def __post_init__(self) -> None:
        if type(self.family) is not str or self.family not in _FAMILY_KIND or (
            self.kind != _FAMILY_KIND[self.family]
        ):
            raise RegimeAdapterError("SOURCE_FAMILY_INVALID")
        if not isinstance(self.source_id, RegimeSourceIdV1) or not all(
            _id(value) for value in (self.source_version, self.record_id, self.raw_unit)
        ):
            raise RegimeAdapterError("SOURCE_IDENTITY_INVALID")
        _integer(self.revision, "revision", maximum=2**31 - 1)
        for name in ("event_ns", "available_ns", "fresh_until_ns"):
            _integer(getattr(self, name), name)
        if self.available_ns < self.event_ns or self.fresh_until_ns < self.available_ns:
            raise RegimeAdapterError("SOURCE_CLOCK_INVALID")
        if (self.revision == 0) != (self.correction_of is None):
            raise RegimeAdapterError("CORRECTION_INVALID")
        if self.correction_of is not None and not _id(self.correction_of):
            raise RegimeAdapterError("CORRECTION_INVALID")
        if type(self.scope_type) is not str or self.scope_type not in _SCOPE_PRIORITY or (
            (self.scope_type == "global") != (self.scope_id is None)
        ) or (self.scope_id is not None and not _id(self.scope_id)):
            raise RegimeAdapterError("SCOPE_INVALID")
        if self.raw_value is not None:
            object.__setattr__(self, "raw_value", _decimal(self.raw_value, "raw_value"))
        if self.entitlement not in ("LICENSED", "SYNTHETIC", "UNENTITLED"):
            raise RegimeAdapterError("ENTITLEMENT_INVALID")
        if self.quality not in ("GOOD", "BAD", "UNKNOWN"):
            raise RegimeAdapterError("QUALITY_INVALID")
        if self.feature is not None and not isinstance(self.feature, FeatureResultV1):
            raise RegimeAdapterError("FEATURE_INVALID")
        if self.feature is not None:
            try:
                original_payload = self.feature.model_dump(
                    mode="python", round_trip=True, warnings=False
                )
                validated_feature = FeatureResultV1.model_validate(original_payload)
                if original_payload != validated_feature.model_dump(
                    mode="python", round_trip=True, warnings=False
                ):
                    raise RegimeAdapterError("FEATURE_INVALID")
            except Exception:
                raise RegimeAdapterError("FEATURE_INVALID") from None
            object.__setattr__(self, "feature", validated_feature)
        if self.upstream_interface_id is not None and not _id(self.upstream_interface_id):
            raise RegimeAdapterError("INTERFACE_INVALID")


@dataclass(frozen=True, slots=True)
class RegimeFactorMappingV1(_NoCopy):
    """Injected standardization definition; no raw signal formula is invented."""

    kind: FactorKind
    family: SourceFamily
    source_id: RegimeSourceIdV1
    source_version: str
    raw_unit: str
    feature_name: str
    feature_version: str
    definition_hash: str
    baseline_version: str
    training_start_ns: int
    training_end_ns: int
    baseline_available_ns: int
    release_lag: str
    release_lag_ns: int
    window_sec: int
    horizon_sec: int
    max_age_ns: int

    def __post_init__(self) -> None:
        if type(self.family) is not str or self.family not in _FAMILY_KIND or (
            self.kind != _FAMILY_KIND[self.family]
        ):
            raise RegimeAdapterError("MAPPING_INVALID")
        if not isinstance(self.source_id, RegimeSourceIdV1) or not all(_id(value) for value in (
            self.source_version, self.raw_unit, self.feature_name,
            self.feature_version, self.definition_hash, self.baseline_version,
        )):
            raise RegimeAdapterError("MAPPING_INVALID")
        for name in ("training_start_ns", "training_end_ns", "baseline_available_ns",
                     "release_lag_ns"):
            _integer(getattr(self, name), name)
        if self.training_start_ns > self.training_end_ns or (
            self.baseline_available_ns < self.training_end_ns
        ):
            raise RegimeAdapterError("MAPPING_CLOCK_INVALID")
        if type(self.release_lag) is not str or self.release_lag not in RELEASE_LAGS_NS or (
            self.release_lag_ns != RELEASE_LAGS_NS[self.release_lag]
        ):
            raise RegimeAdapterError("RELEASE_LAG_INVALID")
        _integer(self.window_sec, "window_sec", maximum=2**31 - 1)
        _integer(self.horizon_sec, "horizon_sec", maximum=2**31 - 1)
        _integer(self.max_age_ns, "max_age_ns")
        if self.window_sec == 0 or self.horizon_sec == 0 or self.max_age_ns == 0:
            raise RegimeAdapterError("WINDOW_INVALID")


@dataclass(frozen=True, slots=True)
class RegimeFeatureBaselineBindingV1(_NoCopy):
    """Reviewed identity binding between a FEAT observation and its baseline."""

    feature_name: str
    feature_version: str
    definition_hash: str
    observation_hash: str
    baseline_version: str
    training_start_ns: int
    training_end_ns: int
    baseline_available_ns: int

    def __post_init__(self) -> None:
        if not all(_id(value) for value in (
            self.feature_name, self.feature_version, self.definition_hash,
            self.observation_hash, self.baseline_version,
        )):
            raise RegimeAdapterError("BASELINE_BINDING_INVALID")
        for name in ("training_start_ns", "training_end_ns", "baseline_available_ns"):
            _integer(getattr(self, name), name)
        if self.training_start_ns > self.training_end_ns or (
            self.baseline_available_ns < self.training_end_ns
        ):
            raise RegimeAdapterError("BASELINE_BINDING_INVALID")


@dataclass(frozen=True, slots=True)
class RegimeScopeBindingV1(_NoCopy):
    """One exact mapping from database scope into REG-001 scope."""

    scope_type: DatabaseScope
    scope_id: str | None
    target_scope: RegimeScope
    target_scope_key: str | None

    def __post_init__(self) -> None:
        expected: dict[DatabaseScope, RegimeScope] = {
            "global": "global", "book": "class", "sector": "class",
            "instrument": "symbol",
        }
        if type(self.scope_type) is not str or self.scope_type not in expected or (
            self.target_scope != expected[self.scope_type]
        ):
            raise RegimeAdapterError("SCOPE_MAPPING_INVALID")
        if (self.scope_type == "global") != (self.scope_id is None) or (
            (self.target_scope == "global") != (self.target_scope_key is None)
        ):
            raise RegimeAdapterError("SCOPE_MAPPING_INVALID")
        if self.scope_id is not None and not _id(self.scope_id):
            raise RegimeAdapterError("SCOPE_MAPPING_INVALID")
        if self.target_scope_key is not None and not _id(self.target_scope_key):
            raise RegimeAdapterError("SCOPE_MAPPING_INVALID")


@dataclass(frozen=True, slots=True)
class RegimeFactorAdapterPolicyV1(_NoCopy):
    version: str
    mappings: tuple[RegimeFactorMappingV1, ...]
    scope_bindings: tuple[RegimeScopeBindingV1, ...]
    status: Literal["FIXTURE_ONLY", "APPROVED"]
    approval_ref: str | None = None
    baseline_bindings: tuple[RegimeFeatureBaselineBindingV1, ...] = ()
    truth_policy_id: str | None = None
    truth_policy_version: str | None = None

    def __post_init__(self) -> None:
        if not _id(self.version) or self.status not in ("FIXTURE_ONLY", "APPROVED"):
            raise RegimeAdapterError("POLICY_INVALID")
        if self.status == "APPROVED" and not _id(self.approval_ref):
            raise RegimeAdapterError("POLICY_UNAPPROVED")
        if self.status == "FIXTURE_ONLY" and self.approval_ref is not None:
            raise RegimeAdapterError("POLICY_INVALID")
        if (self.truth_policy_id is None) != (self.truth_policy_version is None) or (
            self.truth_policy_id is not None and not all(_id(value) for value in (
                self.truth_policy_id, self.truth_policy_version,
            ))
        ):
            raise RegimeAdapterError("POLICY_INVALID")
        if type(self.mappings) is not tuple or any(
            not isinstance(item, RegimeFactorMappingV1) for item in self.mappings
        ) or type(self.scope_bindings) is not tuple or any(
            not isinstance(item, RegimeScopeBindingV1) for item in self.scope_bindings
        ) or type(self.baseline_bindings) is not tuple or any(
            not isinstance(item, RegimeFeatureBaselineBindingV1)
            for item in self.baseline_bindings
        ):
            raise RegimeAdapterError("POLICY_INVALID")
        map_keys = [(item.kind, item.source_id, item.source_version) for item in self.mappings]
        scope_keys = [(item.scope_type, item.scope_id) for item in self.scope_bindings]
        if len(map_keys) != len(set(map_keys)) or len(scope_keys) != len(set(scope_keys)):
            raise RegimeAdapterError("POLICY_CONFLICT")
        baseline_keys = [
            (item.feature_name, item.feature_version, item.definition_hash,
             item.observation_hash) for item in self.baseline_bindings
        ]
        if len(baseline_keys) != len(set(baseline_keys)):
            raise RegimeAdapterError("POLICY_CONFLICT")


@dataclass(frozen=True, slots=True)
class RegimeSignalPortV1(_NoCopy):
    signal_id: str
    bar_id: str
    session_id: str
    symbol: str
    event_ns: int
    available_ns: int
    status: SignalStatus
    revision: int

    def __post_init__(self) -> None:
        if not all(_id(value) for value in (
            self.signal_id, self.bar_id, self.session_id, self.symbol,
        )):
            raise RegimeAdapterError("SIGNAL_INVALID")
        _integer(self.event_ns, "event_ns")
        _integer(self.available_ns, "available_ns")
        _integer(self.revision, "revision", maximum=2**31 - 1)
        if self.available_ns < self.event_ns or self.status not in (
            "FINALIZED", "PROVISIONAL", "UNKNOWN",
        ):
            raise RegimeAdapterError("SIGNAL_INVALID")


@dataclass(frozen=True, slots=True)
class RegimeTruthPortV1(_NoCopy):
    verdict: TruthStatus
    evaluation_ns: int
    available_ns: int
    trace_id: str
    policy_version: str
    target_symbol: str
    target_bar_id: str
    target_session_id: str
    target_asof_ns: int
    policy_id: str

    def __post_init__(self) -> None:
        if self.verdict not in ("PASS", "SOFT_FAIL", "HARD_FAIL", "UNKNOWN") or not all(
            _id(value) for value in (
                self.trace_id, self.policy_version, self.target_symbol,
                self.target_bar_id, self.target_session_id, self.policy_id,
            )
        ):
            raise RegimeAdapterError("TRUTH_INVALID")
        _integer(self.evaluation_ns, "evaluation_ns")
        _integer(self.available_ns, "available_ns")
        _integer(self.target_asof_ns, "target_asof_ns")
        if self.available_ns < self.evaluation_ns:
            raise RegimeAdapterError("TRUTH_INVALID")


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False)
class RegimeFactorAdapterResultV1(_NoCopy):
    snapshot: RegimeSnapshotV1
    exclusions: tuple[tuple[FactorKind, str], ...]
    activation_gates: tuple[str, ...]
    policy_version: str
    inputs_hash: str = field(init=False)
    audit_digest: str = field(init=False)
    _input_payload: InitVar[object | None] = field(default=None, kw_only=True)
    _issue_token: InitVar[object | None] = field(default=None, kw_only=True)

    def __init__(
        self, snapshot: RegimeSnapshotV1,
        exclusions: tuple[tuple[FactorKind, str], ...],
        activation_gates: tuple[str, ...], policy_version: str,
        *, _input_payload: object | None = None, _issue_token: object | None = None,
    ) -> None:
        existing = _ISSUED.get(id(self))
        if existing is not None and existing[0]() is self:
            raise RegimeAdapterError("ADAPTER_RESULT_SEALED")
        if _issue_token is not _ISSUER:
            raise RegimeAdapterError("ADAPTER_RESULT_SEALED")
        object.__setattr__(self, "snapshot", snapshot)
        object.__setattr__(self, "exclusions", exclusions)
        object.__setattr__(self, "activation_gates", activation_gates)
        object.__setattr__(self, "policy_version", policy_version)
        self.__post_init__(_input_payload, _issue_token)

    def __setstate__(self, state: object) -> None:
        raise RegimeAdapterError("ADAPTER_RESULT_SEALED")

    def __post_init__(self, _input_payload: object | None, _issue_token: object | None) -> None:
        existing = _ISSUED.get(id(self))
        if existing is not None and existing[0]() is self:
            raise RegimeAdapterError("ADAPTER_RESULT_SEALED")
        if not isinstance(self.snapshot, RegimeSnapshotV1) or not _id(self.policy_version):
            raise RegimeAdapterError("ADAPTER_RESULT_INVALID")
        if type(self.exclusions) is not tuple or any(
            type(item) is not tuple or len(item) != 2 or item[0] not in FACTOR_KINDS
            or type(item[1]) is not str or _REASON.fullmatch(item[1]) is None
            for item in self.exclusions
        ) or type(self.activation_gates) is not tuple or any(
            type(item) is not str or _REASON.fullmatch(item) is None
            for item in self.activation_gates
        ):
            raise RegimeAdapterError("ADAPTER_RESULT_INVALID")
        if _issue_token is not _ISSUER:
            raise RegimeAdapterError("ADAPTER_RESULT_SEALED")
        if _input_payload is None:
            raise RegimeAdapterError("ADAPTER_RESULT_INVALID")
        object.__setattr__(self, "inputs_hash", _digest(_input_payload))
        content = {
            "schema": "regime-factor-adapter-v1",
            "inputs_hash": self.inputs_hash,
            "policy_version": self.policy_version,
            "snapshot": _snapshot_content(self.snapshot),
            "exclusions": self.exclusions,
            "activation_gates": self.activation_gates,
        }
        object.__setattr__(self, "audit_digest", _digest(content))
        reference = ref(self)
        _ISSUED[id(self)] = (reference, _digest(_issued_content(self)))
        finalize(self, _drop_issued, id(self), reference)

    def require_issued(self) -> None:
        entry = _ISSUED.get(id(self))
        if entry is None or entry[0]() is not self:
            raise RegimeAdapterError("ADAPTER_RESULT_SEALED")
        try:
            valid = entry[1] == _digest(_issued_content(self))
        except Exception:
            valid = False
        if not valid:
            raise RegimeAdapterError("ADAPTER_RESULT_SEALED")


_ISSUED: dict[int, tuple[ReferenceType[RegimeFactorAdapterResultV1], str]] = {}


def _drop_issued(
    identity: int, reference: ReferenceType[RegimeFactorAdapterResultV1],
) -> None:
    entry = _ISSUED.get(identity)
    if entry is not None and entry[0] is reference:
        _ISSUED.pop(identity, None)


def _snapshot_content(snapshot: RegimeSnapshotV1) -> dict[str, object]:
    content = {item.name: getattr(snapshot, item.name) for item in fields(snapshot)
               if item.name not in ("clock", "factors")}
    content["clock"] = {
        item.name: getattr(snapshot.clock, item.name) for item in fields(snapshot.clock)
    }
    content["factors"] = [
        {part.name: getattr(factor, part.name) for part in fields(factor)}
        for factor in snapshot.factors
    ]
    return content


def _issued_content(result: RegimeFactorAdapterResultV1) -> dict[str, object]:
    return {
        "snapshot": _snapshot_content(result.snapshot),
        "exclusions": result.exclusions,
        "activation_gates": result.activation_gates,
        "policy_version": result.policy_version,
        "inputs_hash": result.inputs_hash,
        "audit_digest": result.audit_digest,
    }


def _source_content(source: RegimeFactorSourcePortV1) -> dict[str, object]:
    feature = source.feature
    return {
        "kind": source.kind, "family": source.family, "source_id": source.source_id,
        "source_version": source.source_version, "record_id": source.record_id,
        "revision": source.revision, "correction_of": source.correction_of,
        "event_ns": source.event_ns, "available_ns": source.available_ns,
        "fresh_until_ns": source.fresh_until_ns, "scope_type": source.scope_type,
        "scope_id": source.scope_id, "raw_value": source.raw_value,
        "raw_unit": source.raw_unit, "entitlement": source.entitlement,
        "quality": source.quality, "upstream_interface_id": source.upstream_interface_id,
        "feature": None if feature is None else feature.model_dump(
            mode="python", round_trip=True, warnings=False
        ),
    }


def _reconcile(
    visible: tuple[RegimeFactorSourcePortV1, ...],
) -> tuple[tuple[RegimeFactorSourcePortV1, ...], tuple[tuple[FactorKind, str], ...]]:
    """Reconcile only records already visible at the requested as-of."""
    groups: dict[tuple[object, ...], list[RegimeFactorSourcePortV1]] = {}
    for source in visible:
        slot = (source.kind, source.source_id, source.source_version,
                source.scope_type, source.scope_id)
        groups.setdefault(slot, []).append(source)
    heads: list[RegimeFactorSourcePortV1] = []
    exclusions: list[tuple[FactorKind, str]] = []
    for group_key in sorted(groups, key=str):
        records: dict[str, RegimeFactorSourcePortV1] = {}
        for source in groups[group_key]:
            previous = records.get(source.record_id)
            if previous is not None and _digest(_source_content(previous)) != _digest(
                _source_content(source)
            ):
                raise RegimeAdapterError("SOURCE_CONFLICT")
            records[source.record_id] = source
        children: dict[str, list[RegimeFactorSourcePortV1]] = {}
        for source in records.values():
            if source.revision > 0:
                parent = records.get(source.correction_of or "")
                if parent is None or source.revision != parent.revision + 1:
                    exclusions.append((source.kind, "UNLINKED_CORRECTION"))
                    continue
                children.setdefault(parent.record_id, []).append(source)
        visited: set[str] = set()
        for root in sorted(
            (item for item in records.values() if item.revision == 0),
            key=lambda item: item.record_id,
        ):
            current = root
            while True:
                visited.add(current.record_id)
                successors = children.get(current.record_id, ())
                if not successors:
                    break
                if len(successors) != 1:
                    raise RegimeAdapterError("SOURCE_CONFLICT")
                current = successors[0]
            heads.append(current)
        for source in records.values():
            if source.revision > 0 and source.record_id not in visited:
                exclusions.append((source.kind, "UNLINKED_CORRECTION"))
    return tuple(heads), tuple(exclusions)


def _scope_binding(
    source: RegimeFactorSourcePortV1, policy: RegimeFactorAdapterPolicyV1,
    clock: RegimeClockV1,
) -> RegimeScopeBindingV1 | None:
    binding = next((item for item in policy.scope_bindings if (
        item.scope_type == source.scope_type and item.scope_id == source.scope_id
    )), None)
    if binding is None:
        return None
    if binding.target_scope == "symbol" and binding.target_scope_key != clock.symbol:
        return None
    if binding.target_scope == "class" and binding.target_scope_key != clock.universe:
        return None
    return binding


def _mapped_factor(
    source: RegimeFactorSourcePortV1, binding: RegimeScopeBindingV1,
    mapping: RegimeFactorMappingV1 | None, policy: RegimeFactorAdapterPolicyV1,
    registry: RegimeSourceRegistryV1, clock: RegimeClockV1, asof_ns: int,
) -> tuple[RegimeFactorV1 | None, str | None]:
    if mapping is None or mapping.family != source.family or mapping.raw_unit != source.raw_unit:
        return None, "MAPPING_UNAPPROVED"
    record = registry.lookup(source.source_id)
    if record is None or record.trust_class != "PIPELINE":
        return None, "UNTRUSTED_SOURCE"
    if source.entitlement == "UNENTITLED" or source.entitlement != record.entitlement:
        return None, "UNENTITLED"
    if source.upstream_interface_id is None or (
        source.upstream_interface_id not in record.allowed_interface_ids
    ):
        return None, "UNTRUSTED_INTERFACE"
    if source.raw_value is None:
        return None, "SOURCE_MISSING"
    if source.quality != "GOOD":
        return None, "SOURCE_QUALITY"
    effective_fresh_until = min(
        source.fresh_until_ns, source.event_ns + mapping.max_age_ns,
    )
    if effective_fresh_until < clock.asof_ns:
        return None, "SOURCE_STALE"
    if source.event_ns + mapping.release_lag_ns > asof_ns:
        return None, "RELEASE_LAG"
    if mapping.training_end_ns > clock.asof_ns or mapping.baseline_available_ns > asof_ns:
        return None, "NORMALIZATION_FUTURE"
    feature = source.feature
    if feature is None or feature.asof_ns > asof_ns or (
        feature.availability_ns is not None and feature.availability_ns > asof_ns
    ):
        return None, "FEATURE_MISSING"
    if not feature.found or feature.is_null or feature.value_decimal is None:
        return None, "FEATURE_MISSING"
    if feature.quality != "GOOD":
        return None, "FEATURE_QUALITY"
    if feature.event_time_ns is None or feature.event_time_ns > clock.asof_ns or (
        feature.availability_ns is None
    ) or feature.availability_ns > feature.asof_ns or (
        feature.event_time_ns > feature.asof_ns
    ):
        return None, "FEATURE_FUTURE"
    if feature.value_vector is not None:
        return None, "FEATURE_VALUE_CONFLICT"
    if (
        feature.lineage.definition_sha256 != feature.definition_hash
        or feature.lineage.observation_sha256 != feature.observation_hash
        or feature.lineage.source_dataset != feature.source_dataset
        or feature.lineage.source_record_key != feature.source_record_key
    ):
        raise RegimeAdapterError("LINEAGE_CONFLICT")
    if (
        feature.feature_name != mapping.feature_name
        or feature.feature_version != mapping.feature_version
        or feature.definition_hash != mapping.definition_hash
        or feature.observation_hash is None
        or feature.instrument_id != clock.symbol
        or feature.source_dataset != source.source_id
        or feature.source_record_key != source.record_id
        or source.record_id not in feature.source_keys
        or feature.asof_ns < source.event_ns
        or feature.availability_ns < source.available_ns
        or feature.availability_ns < mapping.baseline_available_ns
    ):
        return None, "FEATURE_LINEAGE"
    baseline = next((item for item in policy.baseline_bindings if (
        item.feature_name == feature.feature_name
        and item.feature_version == feature.feature_version
        and item.definition_hash == feature.definition_hash
        and item.observation_hash == feature.observation_hash
    )), None)
    if baseline is None or (
        baseline.baseline_version != mapping.baseline_version
        or baseline.training_start_ns != mapping.training_start_ns
        or baseline.training_end_ns != mapping.training_end_ns
        or baseline.baseline_available_ns != mapping.baseline_available_ns
    ):
        return None, "BASELINE_UNBOUND"
    value = _decimal(feature.value_decimal, "value")
    semantic_digest = _digest({
        "source": _source_content(source),
        "mapping": [policy.version, mapping.family, mapping.source_id,
                    mapping.source_version, mapping.raw_unit, mapping.feature_name,
                    mapping.feature_version, mapping.definition_hash,
                    mapping.baseline_version, mapping.training_start_ns,
                    mapping.training_end_ns, mapping.baseline_available_ns,
                    mapping.release_lag, mapping.release_lag_ns,
                    mapping.window_sec, mapping.horizon_sec, mapping.max_age_ns],
        "baseline_binding": {
            item.name: getattr(baseline, item.name) for item in fields(baseline)
        },
        "scope": [binding.scope_type, binding.scope_id,
                  binding.target_scope, binding.target_scope_key],
        "registry": [registry.version, record.source_id, record.trust_class,
                     record.entitlement, record.allowed_interface_ids],
    })
    return RegimeFactorV1(
        kind=source.kind, value=value, source=source.source_id,
        source_version=source.source_version, semantic_digest=semantic_digest,
        event_ns=source.event_ns, available_ns=source.available_ns,
        baseline_available_ns=mapping.baseline_available_ns, valid=True,
        fresh_until_ns=effective_fresh_until, scope=binding.target_scope,
        scope_key=binding.target_scope_key, window_sec=mapping.window_sec,
        horizon_sec=mapping.horizon_sec, entitlement=source.entitlement,
        release_lag=mapping.release_lag, release_lag_ns=mapping.release_lag_ns,
        feature_available_ns=feature.availability_ns,
        upstream_interface_id=source.upstream_interface_id,
        source_type="PIPELINE", quality="GOOD",
    ), None


def adapt_regime_factors(
    target_clock: RegimeClockV1,
    sources: tuple[RegimeFactorSourcePortV1, ...],
    signal: RegimeSignalPortV1 | None,
    truth: RegimeTruthPortV1 | None,
    policy: RegimeFactorAdapterPolicyV1,
    source_registry: RegimeSourceRegistryV1,
    asof_ns: int,
) -> RegimeFactorAdapterResultV1:
    """Build a REG-001 input snapshot and explicit source diagnostics, without I/O."""
    if not isinstance(target_clock, RegimeClockV1) or type(sources) is not tuple or any(
        not isinstance(item, RegimeFactorSourcePortV1) for item in sources
    ) or not isinstance(policy, RegimeFactorAdapterPolicyV1) or not isinstance(
        source_registry, RegimeSourceRegistryV1
    ) or (signal is not None and not isinstance(signal, RegimeSignalPortV1)) or (
        truth is not None and not isinstance(truth, RegimeTruthPortV1)
    ):
        raise RegimeAdapterError("ADAPTER_INPUT_INVALID")
    _integer(asof_ns, "asof_ns")
    if asof_ns < target_clock.asof_ns:
        raise RegimeAdapterError("ASOF_BEFORE_BAR")
    visible_signal = signal if signal is not None and (
        signal.event_ns <= target_clock.asof_ns and signal.available_ns <= asof_ns
    ) else None
    if visible_signal is not None and (
        visible_signal.bar_id != target_clock.bar_id
        or visible_signal.session_id != target_clock.session_id
        or visible_signal.symbol != target_clock.symbol
        or visible_signal.event_ns != target_clock.asof_ns
    ):
        raise RegimeAdapterError("SIGNAL_MISMATCH")
    finalized = bool(
        target_clock.finalized and visible_signal is not None
        and visible_signal.status == "FINALIZED"
    )
    clock = replace(target_clock, finalized=finalized)
    signal_status: SignalStatus = (
        "FINALIZED" if finalized else "PROVISIONAL"
        if visible_signal is not None else "UNKNOWN"
    )
    visible_truth = truth if truth is not None and (
        truth.evaluation_ns <= asof_ns and truth.available_ns <= asof_ns
        and truth.target_asof_ns <= asof_ns
    ) else None
    truth_status: TruthStatus = "UNKNOWN"
    gates: list[str] = []
    if policy.truth_policy_id is None or policy.truth_policy_version is None:
        gates.append("TRUTH_POLICY_UNBOUND")
    elif visible_truth is not None:
        if (
            visible_truth.target_symbol != target_clock.symbol
            or visible_truth.target_bar_id != target_clock.bar_id
            or visible_truth.target_session_id != target_clock.session_id
            or visible_truth.target_asof_ns != target_clock.asof_ns
            or visible_truth.policy_id != policy.truth_policy_id
            or visible_truth.policy_version != policy.truth_policy_version
        ):
            gates.append("TRUTH_MISMATCH")
        elif visible_truth.evaluation_ns < target_clock.asof_ns:
            gates.append("TRUTH_PREMATURE")
        else:
            truth_status = visible_truth.verdict
    if policy.status == "FIXTURE_ONLY":
        gates.append("SOURCE_MAPPING_UNAPPROVED")
        if truth_status == "PASS":
            truth_status = "UNKNOWN"

    # Filter future rows before any duplicate/revision reconciliation.
    visible_sources = tuple(
        source for source in sources
        if source.event_ns <= clock.asof_ns and source.available_ns <= asof_ns
        and (source.feature is None or (
            source.feature.asof_ns <= asof_ns
            and (source.feature.availability_ns is None
                 or source.feature.availability_ns <= asof_ns)
            and (source.feature.event_time_ns is None
                 or source.feature.event_time_ns <= clock.asof_ns)
        ))
    )
    heads, revision_exclusions = _reconcile(visible_sources)
    exclusions: list[tuple[FactorKind, str]] = list(revision_exclusions)
    factors: list[RegimeFactorV1] = []
    flow_source: str | None = None
    flow_quality: str | None = None
    latest_available = clock.asof_ns
    if visible_signal is not None:
        latest_available = max(latest_available, visible_signal.available_ns)
    if visible_truth is not None:
        latest_available = max(latest_available, visible_truth.available_ns)
    for visible_source in visible_sources:
        latest_available = max(latest_available, visible_source.available_ns)
        if visible_source.feature is not None and (
            visible_source.feature.availability_ns is not None
        ):
            latest_available = max(
                latest_available, visible_source.feature.availability_ns,
            )
    mapping_by_key = {
        (item.kind, item.source_id, item.source_version): item
        for item in policy.mappings
    }
    for kind in FACTOR_KINDS:
        matching = [
            (source, binding)
            for source in heads if source.kind == kind
            if (binding := _scope_binding(source, policy, clock)) is not None
        ]
        if not matching:
            exclusions.append((kind, "SOURCE_MISSING" if not any(
                source.kind == kind for source in heads
            ) else "SCOPE_UNMAPPED"))
            continue
        matching.sort(key=lambda item: (
            _SCOPE_PRIORITY[item[0].scope_type], item[0].event_ns,
        ), reverse=True)
        source, binding = matching[0]
        if len(matching) > 1 and (
            _SCOPE_PRIORITY[matching[1][0].scope_type] == _SCOPE_PRIORITY[source.scope_type]
            and matching[1][0].event_ns == source.event_ns
            and _digest(_source_content(matching[1][0])) != _digest(_source_content(source))
        ):
            raise RegimeAdapterError("SCOPE_CONFLICT")
        factor, reason = _mapped_factor(
            source, binding,
            mapping_by_key.get((source.kind, source.source_id, source.source_version)),
            policy, source_registry, clock, asof_ns,
        )
        if reason is not None:
            exclusions.append((kind, reason))
            continue
        assert factor is not None
        factors.append(factor)
        latest_available = max(latest_available, source.available_ns,
                               factor.feature_available_ns or 0)
        if kind == "flow":
            flow_source = str(source.source_id)
            flow_quality = "GOOD"
    snapshot = RegimeSnapshotV1(
        clock=clock, factors=tuple(factors), record_available_ns=latest_available,
        signal_status=signal_status, truth_status=truth_status,
        flow_source=flow_source, flow_quality=flow_quality,
        weight_version=DEFAULT_WEIGHT_VERSION,
    )
    input_payload = {
        "schema": "regime-factor-inputs-v1",
        "target_clock": {part.name: getattr(target_clock, part.name)
                         for part in fields(target_clock)},
        "asof_ns": asof_ns,
        "visible_sources": sorted({_digest(_source_content(item)) for item in visible_sources}),
        "visible_signal": None if visible_signal is None else {
            part.name: getattr(visible_signal, part.name) for part in fields(visible_signal)
        },
        "visible_truth": None if visible_truth is None else {
            part.name: getattr(visible_truth, part.name) for part in fields(visible_truth)
        },
        "mapping_policy": [
            policy.version, policy.status, policy.approval_ref,
            [{part.name: getattr(item, part.name) for part in fields(item)}
             for item in sorted(policy.mappings, key=lambda item: (
                 item.kind, item.source_id, item.source_version,
             ))],
            [{part.name: getattr(item, part.name) for part in fields(item)}
             for item in sorted(policy.scope_bindings, key=lambda item: (
                 item.scope_type, item.scope_id or "",
             ))],
            [{part.name: getattr(item, part.name) for part in fields(item)}
             for item in sorted(policy.baseline_bindings, key=lambda item: (
                 item.feature_name, item.feature_version, item.definition_hash,
                 item.observation_hash,
             ))],
            policy.truth_policy_id, policy.truth_policy_version,
        ],
        "source_registry": [
            source_registry.version,
            [{part.name: getattr(item, part.name) for part in fields(item)}
             for item in sorted(source_registry.records, key=lambda item: item.source_id)],
        ],
    }
    return RegimeFactorAdapterResultV1(
        snapshot=snapshot,
        exclusions=tuple(sorted(set(exclusions), key=lambda item: (FACTOR_KINDS.index(item[0]),
                                                               item[1]))),
        activation_gates=tuple(sorted(gates)), policy_version=policy.version,
        _input_payload=input_payload, _issue_token=_ISSUER,
    )
