"""Deterministic in-memory as-of feature selection."""

from __future__ import annotations

from collections.abc import Iterable

from leviathan_core.feature_store.models import (
    FeatureDefinitionV1,
    FeatureLineageV1,
    FeatureObservationV1,
    FeatureQueryV1,
    FeatureResultV1,
    _issue_feature_result,
)


class FeatureVersionNotFoundError(LookupError):
    """The requested name/version has no published definition."""


class FeatureDefinitionConflictError(ValueError):
    """A feature name/version was redefined with different semantic content."""


class FeatureObservationCollisionError(ValueError):
    """Two observations occupy the same ordered source slot with different content."""


class FeatureKernelV1:
    """Frozen local inputs and deterministic historical lookups, with no I/O."""

    def __init__(
        self,
        definitions: Iterable[FeatureDefinitionV1],
        observations: Iterable[FeatureObservationV1],
    ) -> None:
        by_version: dict[tuple[str, str], FeatureDefinitionV1] = {}
        for definition in definitions:
            key = (definition.feature_name, definition.feature_version)
            previous = by_version.get(key)
            if previous is not None and previous.semantic_hash != definition.semantic_hash:
                raise FeatureDefinitionConflictError(f"conflicting feature definition: {key!r}")
            by_version[key] = definition
        self._definitions = by_version
        self._observations = tuple(observations)

    def query(self, query: FeatureQueryV1) -> FeatureResultV1:
        definition = self._definitions.get((query.feature_name, query.feature_version))
        if definition is None or not definition.published:
            raise FeatureVersionNotFoundError(
                f"no published feature version: {query.feature_name}/{query.feature_version}"
            )

        selected: dict[tuple[int, int, str], FeatureObservationV1] = {}
        for observation in self._observations:
            if (
                observation.feature_name != query.feature_name
                or observation.feature_version != query.feature_version
                or observation.instrument_id != query.instrument_id
                or observation.event_time_ns > query.asof_ns
                or observation.availability_ns > query.asof_ns
            ):
                continue
            if not observation.is_null and (
                (definition.value_kind == "decimal" and observation.value_decimal is None)
                or (definition.value_kind == "vector" and observation.value_vector is None)
            ):
                raise ValueError("observation value kind differs from published definition")
            order = (
                observation.availability_ns,
                observation.event_time_ns,
                observation.source_record_key,
            )
            previous = selected.get(order)
            if previous is not None and previous.semantic_hash != observation.semantic_hash:
                raise FeatureObservationCollisionError(
                    f"conflicting feature observation: {order!r}"
                )
            selected[order] = observation

        winner = selected[max(selected)] if selected else None
        definition_hash = definition.semantic_hash
        if winner is None:
            return _issue_feature_result(
                found=False,
                feature_name=query.feature_name,
                feature_version=query.feature_version,
                instrument_id=query.instrument_id,
                asof_ns=query.asof_ns,
                definition_hash=definition_hash,
                lineage=FeatureLineageV1(definition_sha256=definition_hash),
            )

        observation_hash = winner.semantic_hash
        return _issue_feature_result(
            found=True,
            feature_name=query.feature_name,
            feature_version=query.feature_version,
            instrument_id=query.instrument_id,
            asof_ns=query.asof_ns,
            value_decimal=winner.value_decimal,
            value_vector=winner.value_vector,
            quality=winner.quality,
            is_null=winner.is_null,
            source_dataset=winner.source_dataset,
            source_record_key=winner.source_record_key,
            event_time_ns=winner.event_time_ns,
            availability_ns=winner.availability_ns,
            source_keys=(winner.source_record_key,),
            definition_hash=definition_hash,
            observation_hash=observation_hash,
            lineage=FeatureLineageV1(
                definition_sha256=definition_hash,
                observation_sha256=observation_hash,
                source_dataset=winner.source_dataset,
                source_record_key=winner.source_record_key,
            ),
        )


def query_asof(
    query: FeatureQueryV1,
    definitions: Iterable[FeatureDefinitionV1],
    observations: Iterable[FeatureObservationV1],
) -> FeatureResultV1:
    """Run one query over injected, in-memory definitions and observations."""
    return FeatureKernelV1(definitions, observations).query(query)
