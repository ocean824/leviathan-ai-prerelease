"""Fake-first Neon feature port with atomic writes and FEAT-001 as-of semantics."""

from __future__ import annotations

import hashlib
import re
import warnings
from collections.abc import Iterable
from contextlib import suppress
from threading import RLock

from leviathan_core.feature_store import (
    FeatureDefinitionV1,
    FeatureKernelV1,
    FeatureObservationV1,
    FeatureQueryV1,
    FeatureResultV1,
)
from leviathan_core.numeric import canonical_json
from leviathan_core.seal import Issuer, require

from .feature_models import (
    FeaturePersistenceError,
    FeatureWriteAckV1,
    _DefinitionRow,
    _ObservationRow,
)

_ACK_ISSUER = Issuer("stor001.fake_commit.v1")
_ACK_TAG = _ACK_ISSUER.tag
_DefinitionKey = tuple[str, str, str, str]
_ObservationKey = tuple[str, str, str, str, str, str, str]
_LineageKey = tuple[str, str, str, str, str, str, str]
_SCOPE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


def _text(value: object) -> str:
    if type(value) is not str or not value or value != value.strip() or "\x00" in value:
        raise FeaturePersistenceError("INVALID_IDENTITY")
    invalid = False
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        invalid = True
    if invalid:
        raise FeaturePersistenceError("INVALID_IDENTITY")
    return value


def _scope_id(value: object) -> str:
    if type(value) is not str or _SCOPE_ID.fullmatch(value) is None:
        raise FeaturePersistenceError("INVALID_IDENTITY")
    return value


def _ns(value: object) -> int:
    if type(value) is not int or value < 0 or value >= 2**63:
        raise FeaturePersistenceError("INVALID_UTC_NS")
    return value


def _definition(value: object) -> FeatureDefinitionV1:
    if not isinstance(value, FeatureDefinitionV1):
        raise FeaturePersistenceError("INVALID_DEFINITION")
    checked: FeatureDefinitionV1 | None = None
    with suppress(Exception):
        checked = FeatureDefinitionV1.model_validate(
            value.model_dump(mode="python", warnings=False)
        )
    if checked is None:
        raise FeaturePersistenceError("INVALID_DEFINITION")
    return checked


def _observation(value: object) -> FeatureObservationV1:
    if not isinstance(value, FeatureObservationV1):
        raise FeaturePersistenceError("INVALID_OBSERVATION")
    checked: FeatureObservationV1 | None = None
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        with suppress(Exception):
            checked = FeatureObservationV1.model_validate(
                value.model_dump(mode="python", warnings=False)
            )
    if checked is None:
        raise FeaturePersistenceError("INVALID_OBSERVATION")
    return checked


def _query(value: object) -> FeatureQueryV1:
    if not isinstance(value, FeatureQueryV1):
        raise FeaturePersistenceError("INVALID_QUERY")
    checked: FeatureQueryV1 | None = None
    with suppress(Exception):
        checked = FeatureQueryV1.model_validate(value.model_dump(mode="python", warnings=False))
    if checked is None:
        raise FeaturePersistenceError("INVALID_QUERY")
    return checked


class NeonFeatureRepositoryV1:
    """In-memory fake of a scoped Neon transaction boundary; no DB connection."""

    backend = "FAKE_NEON"

    def __init__(self) -> None:
        self._lock = RLock()
        self._orgs: set[str] = set()
        self._datasets: dict[tuple[str, str], str] = {}
        self._instruments: set[tuple[str, str]] = set()
        self._policies: dict[tuple[str, str, str], tuple[str, str, tuple[str, ...]]] = {}
        self._definitions: dict[_DefinitionKey, _DefinitionRow] = {}
        self._observations: dict[_ObservationKey, _ObservationRow] = {}
        self._lineage: set[_LineageKey] = set()
        self._transaction_sequence = 0

    def _ack(self, inserted: int, idempotent: int) -> FeatureWriteAckV1:
        self._transaction_sequence += 1
        return _ACK_ISSUER.issue(
            FeatureWriteAckV1(
                transaction_sequence=self._transaction_sequence,
                inserted_count=inserted,
                idempotent_count=idempotent,
            )
        )

    def register_org(self, org_id: str) -> None:
        org = _scope_id(org_id)
        with self._lock:
            self._orgs.add(org)

    def register_dataset(self, org_id: str, dataset_id: str, owner_id: str) -> None:
        org, dataset, owner = _scope_id(org_id), _scope_id(dataset_id), _scope_id(owner_id)
        with self._lock:
            if org not in self._orgs:
                raise FeaturePersistenceError("ORG_NOT_FOUND")
            key = (org, dataset)
            previous = self._datasets.get(key)
            if previous is not None and previous != owner:
                raise FeaturePersistenceError("DATASET_CONFLICT")
            self._datasets[key] = owner

    def register_instrument(self, org_id: str, instrument_id: str) -> None:
        org, instrument = _scope_id(org_id), _scope_id(instrument_id)
        with self._lock:
            if org not in self._orgs:
                raise FeaturePersistenceError("ORG_NOT_FOUND")
            self._instruments.add((org, instrument))

    def register_access_policy(
        self,
        org_id: str,
        dataset_id: str,
        policy_id: str,
        subject_type: str,
        subject_id: str,
        permissions: tuple[str, ...],
    ) -> None:
        org, dataset, policy = _scope_id(org_id), _scope_id(dataset_id), _scope_id(policy_id)
        subject = _scope_id(subject_id)
        if (
            type(subject_type) is not str
            or subject_type not in {"org", "user", "service", "role"}
            or type(permissions) is not tuple
            or not permissions
            or any(
                type(item) is not str or item not in {"read", "write", "admin"}
                for item in permissions
            )
            or len(set(permissions)) != len(permissions)
        ):
            raise FeaturePersistenceError("INVALID_POLICY")
        row = (subject_type, subject, tuple(sorted(permissions)))
        with self._lock:
            if (org, dataset) not in self._datasets:
                raise FeaturePersistenceError("DATASET_NOT_FOUND")
            key = (org, dataset, policy)
            previous = self._policies.get(key)
            if previous is not None and previous != row:
                raise FeaturePersistenceError("POLICY_CONFLICT")
            self._policies[key] = row

    def _require_dataset(self, org: str, dataset: str) -> None:
        if (org, dataset) not in self._datasets:
            raise FeaturePersistenceError("DATASET_NOT_FOUND")
        if not any(key[:2] == (org, dataset) for key in self._policies):
            raise FeaturePersistenceError("ACCESS_POLICY_NOT_FOUND")

    def register_upstream_lineage(
        self,
        org_id: str,
        dataset_id: str,
        feature_name: str,
        feature_version: str,
        upstream_dataset_id: str,
        job_id: str,
        run_id: str,
    ) -> FeatureWriteAckV1:
        org, dataset, upstream = (
            _scope_id(org_id),
            _scope_id(dataset_id),
            _scope_id(upstream_dataset_id),
        )
        name, version = _text(feature_name), _text(feature_version)
        job, run = _scope_id(job_id), _scope_id(run_id)
        with self._lock:
            self._require_dataset(org, dataset)
            if (org, upstream) not in self._datasets:
                raise FeaturePersistenceError("DATASET_NOT_FOUND")
            if (org, dataset, name, version) not in self._definitions:
                raise FeaturePersistenceError("DEFINITION_NOT_FOUND")
            key = (org, dataset, name, version, upstream, job, run)
            if key in self._lineage:
                return self._ack(0, 1)
            ack = self._ack(1, 0)
            self._lineage.add(key)
            return ack

    def get_upstream_lineage(
        self, org_id: str, dataset_id: str, feature_name: str, feature_version: str
    ) -> tuple[tuple[str, str, str], ...]:
        org, dataset = _scope_id(org_id), _scope_id(dataset_id)
        name, version = _text(feature_name), _text(feature_version)
        with self._lock:
            self._require_dataset(org, dataset)
            if (org, dataset, name, version) not in self._definitions:
                raise FeaturePersistenceError("DEFINITION_NOT_FOUND")
            return tuple(
                sorted(
                    (key[4], key[5], key[6])
                    for key in self._lineage
                    if key[:4] == (org, dataset, name, version)
                )
            )

    def publish_definition(
        self,
        org_id: str,
        dataset_id: str,
        definition: FeatureDefinitionV1,
        *,
        git_ref: str,
        data_interval_start_ns: int,
        data_interval_end_ns: int,
    ) -> FeatureWriteAckV1:
        org, dataset = _scope_id(org_id), _scope_id(dataset_id)
        saved = _definition(definition)
        start, end = _ns(data_interval_start_ns), _ns(data_interval_end_ns)
        if end < start:
            raise FeaturePersistenceError("INVALID_INTERVAL")
        git = _text(git_ref)
        metadata_sha256 = hashlib.sha256(
            canonical_json(
                {
                    "org_id": org,
                    "dataset_id": dataset,
                    "feature_name": saved.feature_name,
                    "feature_version": saved.feature_version,
                    "git_ref": git,
                    "data_interval_start_ns": start,
                    "data_interval_end_ns": end,
                }
            )
        ).hexdigest()
        row = _DefinitionRow(
            payload=saved.model_dump_json().encode("utf-8"),
            semantic_hash=saved.semantic_hash,
            metadata_sha256=metadata_sha256,
            git_ref=git,
            data_interval_start_ns=start,
            data_interval_end_ns=end,
        )
        key = (org, dataset, saved.feature_name, saved.feature_version)
        with self._lock:
            self._require_dataset(org, dataset)
            previous = self._definitions.get(key)
            if previous is not None:
                if previous != row:
                    raise FeaturePersistenceError("DEFINITION_CONFLICT")
                return self._ack(0, 1)
            ack = self._ack(1, 0)
            self._definitions[key] = row
            return ack

    def insert_observations(
        self,
        org_id: str,
        dataset_id: str,
        observations: Iterable[FeatureObservationV1],
        *,
        fail_before_commit: bool = False,
    ) -> FeatureWriteAckV1:
        org, dataset = _scope_id(org_id), _scope_id(dataset_id)
        if type(fail_before_commit) is not bool:
            raise FeaturePersistenceError("INVALID_FAILPOINT")
        incoming: tuple[FeatureObservationV1, ...] = ()
        invalid = False
        try:
            incoming = tuple(_observation(item) for item in observations)
        except Exception:
            invalid = True
        if invalid:
            raise FeaturePersistenceError("INVALID_OBSERVATION")
        if not incoming:
            raise FeaturePersistenceError("EMPTY_BATCH")
        with self._lock:
            self._require_dataset(org, dataset)
            staged = dict(self._observations)
            inserted = idempotent = 0
            for observation in incoming:
                definition_key = (
                    org,
                    dataset,
                    observation.feature_name,
                    observation.feature_version,
                )
                source = observation.source_dataset
                if source != dataset and (
                    (org, source) not in self._datasets
                    or not any(
                        link[:4] == definition_key and link[4] == source for link in self._lineage
                    )
                ):
                    raise FeaturePersistenceError("DATASET_SCOPE_MISMATCH")
                if (org, observation.instrument_id) not in self._instruments:
                    raise FeaturePersistenceError("INSTRUMENT_NOT_FOUND")
                definition_row = self._definitions.get(definition_key)
                if definition_row is None:
                    raise FeaturePersistenceError("DEFINITION_NOT_FOUND")
                definition = FeatureDefinitionV1.model_validate_json(definition_row.payload)
                if not definition.published:
                    raise FeaturePersistenceError("UNPUBLISHED_VERSION")
                if not observation.is_null and (
                    (definition.value_kind == "decimal" and observation.value_decimal is None)
                    or (definition.value_kind == "vector" and observation.value_vector is None)
                ):
                    raise FeaturePersistenceError("VALUE_KIND_MISMATCH")
                _ns(observation.event_time_ns)
                _ns(observation.availability_ns)
                key = (
                    org,
                    dataset,
                    observation.feature_name,
                    observation.feature_version,
                    observation.instrument_id,
                    observation.source_dataset,
                    observation.source_record_key,
                )
                row = _ObservationRow(
                    payload=observation.model_dump_json().encode("utf-8"),
                    semantic_hash=observation.semantic_hash,
                )
                previous = staged.get(key)
                if previous is not None:
                    if previous.semantic_hash != row.semantic_hash:
                        raise FeaturePersistenceError("OBSERVATION_CONFLICT")
                    idempotent += 1
                    continue
                staged[key] = row
                inserted += 1
            if fail_before_commit:
                raise FeaturePersistenceError("FAKE_TRANSACTION_ABORTED")
            ack = self._ack(inserted, idempotent)
            self._observations = staged
            return ack

    def get_definition(
        self, org_id: str, dataset_id: str, feature_name: str, feature_version: str
    ) -> FeatureDefinitionV1:
        key = (
            _scope_id(org_id),
            _scope_id(dataset_id),
            _text(feature_name),
            _text(feature_version),
        )
        with self._lock:
            self._require_dataset(key[0], key[1])
            row = self._definitions.get(key)
            if row is None:
                raise FeaturePersistenceError("DEFINITION_NOT_FOUND")
            return FeatureDefinitionV1.model_validate_json(row.payload)

    def get_lineage(
        self, org_id: str, dataset_id: str, feature_name: str, feature_version: str
    ) -> tuple[str, int, int, str]:
        key = (
            _scope_id(org_id),
            _scope_id(dataset_id),
            _text(feature_name),
            _text(feature_version),
        )
        with self._lock:
            self._require_dataset(key[0], key[1])
            row = self._definitions.get(key)
            if row is None:
                raise FeaturePersistenceError("DEFINITION_NOT_FOUND")
            return (
                row.git_ref,
                row.data_interval_start_ns,
                row.data_interval_end_ns,
                row.semantic_hash,
            )

    def query_asof(self, org_id: str, dataset_id: str, query: FeatureQueryV1) -> FeatureResultV1:
        org, dataset = _scope_id(org_id), _scope_id(dataset_id)
        checked = _query(query)
        _ns(checked.asof_ns)
        key = (org, dataset, checked.feature_name, checked.feature_version)
        with self._lock:
            self._require_dataset(org, dataset)
            definition_row = self._definitions.get(key)
            if definition_row is None:
                raise FeaturePersistenceError("DEFINITION_NOT_FOUND")
            if (org, checked.instrument_id) not in self._instruments:
                raise FeaturePersistenceError("INSTRUMENT_NOT_FOUND")
            definitions = [FeatureDefinitionV1.model_validate_json(definition_row.payload)]
            observations = [
                FeatureObservationV1.model_validate_json(row.payload)
                for obs_key, row in self._observations.items()
                if obs_key[:4] == key and obs_key[4] == checked.instrument_id
            ]
            result: FeatureResultV1 | None = None
            with suppress(Exception):
                result = FeatureKernelV1(definitions, observations).query(checked)
            if result is None:
                raise FeaturePersistenceError("QUERY_FAILED")
            return result

    def observations_in_range(
        self,
        org_id: str,
        dataset_id: str,
        feature_name: str,
        feature_version: str,
        instrument_id: str,
        *,
        start_ns: int,
        end_ns: int,
        asof_ns: int,
    ) -> tuple[FeatureObservationV1, ...]:
        org, dataset = _scope_id(org_id), _scope_id(dataset_id)
        name, version, instrument = (
            _text(feature_name),
            _text(feature_version),
            _scope_id(instrument_id),
        )
        start, end, asof = _ns(start_ns), _ns(end_ns), _ns(asof_ns)
        if end < start:
            raise FeaturePersistenceError("INVALID_INTERVAL")
        with self._lock:
            self._require_dataset(org, dataset)
            if (org, dataset, name, version) not in self._definitions:
                raise FeaturePersistenceError("DEFINITION_NOT_FOUND")
            if (org, instrument) not in self._instruments:
                raise FeaturePersistenceError("INSTRUMENT_NOT_FOUND")
            visible = [
                FeatureObservationV1.model_validate_json(row.payload)
                for key, row in self._observations.items()
                if key[:5] == (org, dataset, name, version, instrument)
            ]
            visible = [
                item
                for item in visible
                if start <= item.event_time_ns <= end
                and item.event_time_ns <= asof
                and item.availability_ns <= asof
            ]
            visible.sort(
                key=lambda item: (
                    item.event_time_ns,
                    item.availability_ns,
                    item.source_record_key,
                )
            )
            return tuple(visible)


def require_feature_write_ack(ack: FeatureWriteAckV1) -> FeatureWriteAckV1:
    """Verify the exact issued ACK and its unchanged content."""
    return require(ack, _ACK_TAG)
