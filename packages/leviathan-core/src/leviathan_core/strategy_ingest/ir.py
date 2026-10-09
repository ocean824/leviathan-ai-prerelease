"""Closed, typed intermediate representation for reviewed strategy codegen."""

from __future__ import annotations

import re
from decimal import Decimal
from enum import Enum
from typing import Any, Literal

from pydantic import field_validator, model_validator

from leviathan_core.ea_builder.graph import GraphV1
from leviathan_core.seal import SealedModel
from leviathan_core.strategy_ingest.models import (
    ClaimConflictV1,
    ExtractedEvidenceV1,
    LineageEdgeV1,
    ReviewerActionV1,
    SourceRecordV1,
    StrategyIngestError,
    digest,
)

_IDENT = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,63}\Z", re.ASCII)
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z", re.ASCII)
_SHA = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)


class CodegenTargetV1(Enum):
    PYTHON = "PYTHON"
    PINE_V5 = "PINE_V5"
    EA_GRAPH = "EA_GRAPH"


class OperatorKindV1(Enum):
    SMA = "sma"
    CROSS_ABOVE = "cross_above"
    CROSS_BELOW = "cross_below"
    STOP_DISTANCE = "stop_distance"
    TARGET_DISTANCE = "target_distance"
    POSITION_CAP = "position_cap"


class OperatorV1(SealedModel):
    node_id: str
    kind: OperatorKindV1
    action: Literal["entry", "exit"] | None
    inputs: tuple[str, ...]
    period: int | None
    value: Decimal | None
    unit: Literal["bars", "pips", "positions"] | None
    evidence_id: str

    @field_validator("node_id", "evidence_id")
    @classmethod
    def _identity(cls, value: str) -> str:
        if not _IDENT.fullmatch(value):
            raise ValueError
        return value

    @model_validator(mode="after")
    def _shape(self) -> OperatorV1:
        if self.kind == OperatorKindV1.SMA:
            if (
                type(self.period) is not int
                or not 1 <= self.period <= 100_000
                or self.action is not None
                or self.inputs
                or self.value is not None
            ):
                raise ValueError
        elif self.kind in {OperatorKindV1.CROSS_ABOVE, OperatorKindV1.CROSS_BELOW}:
            if (
                len(self.inputs) != 2
                or self.action not in {"entry", "exit"}
                or self.period is not None
                or self.value is not None
                or self.unit is not None
            ):
                raise ValueError
        else:
            if (
                self.action is not None
                or self.inputs
                or self.period is not None
                or self.value is None
                or self.unit not in {"pips", "positions"}
            ):
                raise ValueError
            if self.value <= 0 or (
                self.kind == OperatorKindV1.POSITION_CAP and self.unit != "positions"
            ):
                raise ValueError
        return self


class StrategyIRV1(SealedModel):
    schema_version: Literal["1"]
    symbol: str
    timeframe: str
    session: str
    decision_asof_ns: int
    operators: tuple[OperatorV1, ...]

    @field_validator("symbol", "timeframe", "session")
    @classmethod
    def _scope(cls, value: str) -> str:
        if not _IDENT.fullmatch(value):
            raise ValueError
        return value

    @field_validator("decision_asof_ns")
    @classmethod
    def _clock(cls, value: int) -> int:
        if type(value) is not int or value < 0:
            raise ValueError
        return value

    @model_validator(mode="after")
    def _references(self) -> StrategyIRV1:
        ids = [op.node_id for op in self.operators]
        if len(ids) != len(set(ids)) or len(ids) > 256:
            raise ValueError
        known = set(ids)
        if any(ref not in known for op in self.operators for ref in op.inputs):
            raise ValueError
        return self


class TargetTemplateV1(SealedModel):
    target: CodegenTargetV1
    template_id: str
    template_version: str
    template_sha256: str

    @field_validator("template_id", "template_version")
    @classmethod
    def _token(cls, value: str, info: Any) -> str:
        pattern = _VERSION if info.field_name == "template_version" else _IDENT
        if not pattern.fullmatch(value):
            raise ValueError
        return value

    @field_validator("template_sha256")
    @classmethod
    def _hash(cls, value: str) -> str:
        if not _SHA.fullmatch(value):
            raise ValueError
        return value


class TemplateCatalogV1(SealedModel):
    schema_version: Literal["1"]
    catalog_id: str
    catalog_version: int
    templates: tuple[TargetTemplateV1, ...]

    @field_validator("catalog_id")
    @classmethod
    def _id(cls, value: str) -> str:
        if not _IDENT.fullmatch(value):
            raise ValueError
        return value

    @field_validator("catalog_version")
    @classmethod
    def _version(cls, value: int) -> int:
        if type(value) is not int or value < 1:
            raise ValueError
        return value

    @model_validator(mode="after")
    def _unique_targets(self) -> TemplateCatalogV1:
        targets = [template.target for template in self.templates]
        if not targets or len(targets) != len(set(targets)):
            raise ValueError
        return self

    def template_for(self, target: CodegenTargetV1) -> TargetTemplateV1:
        for template in self.templates:
            if template.target == target:
                return template
        raise StrategyIngestError("TEMPLATE_TARGET_MISSING")

    def canonical_sha256(self) -> str:
        rows = sorted(
            (item.model_dump(mode="json") for item in self.templates),
            key=lambda item: str(item["target"]),
        )
        return digest(
            {
                "schema_version": self.schema_version,
                "catalog_id": self.catalog_id,
                "catalog_version": self.catalog_version,
                "templates": rows,
            }
        )


class CodeArtifactV1(SealedModel):
    schema_version: Literal["1"]
    target: CodegenTargetV1
    template_id: str
    template_version: str
    template_sha256: str
    catalog_id: str
    catalog_version: int
    catalog_sha256: str
    strategy_ir: StrategyIRV1
    source_provenance: SourceRecordV1
    source_id: str
    source_sha256: str
    packet_sha256: str
    spec_sha256: str
    reviewer_ids: tuple[str, ...]
    claim_ids: tuple[str, ...]
    reviewer_actions: tuple[ReviewerActionV1, ...]
    accepted_claims: tuple[ExtractedEvidenceV1, ...]
    rejected_claims: tuple[ExtractedEvidenceV1, ...]
    lineage_edges: tuple[LineageEdgeV1, ...]
    conflicts: tuple[ClaimConflictV1, ...]
    promotion_status: Literal["BLOCKED_UNVERIFIED_SOURCE"]
    promotable: Literal[False]
    parameter_schema: tuple[tuple[str, str, str], ...]
    dependency_manifest: tuple[str, ...]
    python_source: str | None
    pine_source: str | None
    ea_graph: GraphV1 | None
    unsupported_nodes: tuple[str, ...]
    canonical_sha256: str

    @model_validator(mode="after")
    def _content(self) -> CodeArtifactV1:
        outputs = (
            self.python_source is not None,
            self.pine_source is not None,
            self.ea_graph is not None,
        )
        expected = {
            CodegenTargetV1.PYTHON: (True, False, False),
            CodegenTargetV1.PINE_V5: (False, True, False),
            CodegenTargetV1.EA_GRAPH: (False, False, True),
        }[self.target]
        if outputs != expected or self.unsupported_nodes:
            raise ValueError
        return self

    def calculate_sha256(self) -> str:
        payload = self.model_dump(mode="json", exclude={"canonical_sha256"})
        return digest(payload)


__all__ = [
    "CodeArtifactV1",
    "CodegenTargetV1",
    "OperatorKindV1",
    "OperatorV1",
    "StrategyIRV1",
    "TargetTemplateV1",
    "TemplateCatalogV1",
]
