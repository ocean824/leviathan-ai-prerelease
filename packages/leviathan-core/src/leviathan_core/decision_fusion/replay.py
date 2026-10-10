"""Deterministic fixture replay of advisory decision proposals."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import InitVar, dataclass, fields
from typing import Literal, NoReturn, SupportsIndex

from leviathan_core.decision_fusion.models import FusionResultV1
from leviathan_core.decision_fusion.proposal import (
    DecisionContextV1,
    DecisionFrozenError,
    DecisionInputError,
    DecisionProposalV1,
    _content_free_frozen,
    compose,
)
from leviathan_core.numeric import canonical_json
from leviathan_core.portfolio.models import SizingResultV1
from leviathan_core.portfolio.overlap import PortfolioCheckV1
from leviathan_core.seal import Issuer, SealError, require

TRACE_TAG = "dec002.trace.v1"
_TRACE_ISSUER = Issuer(TRACE_TAG)
_TRACE_CONSTRUCTION = object()
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII)
_DIGEST = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)


class _FrozenRecord:
    def __copy__(self) -> NoReturn:
        raise DecisionFrozenError

    def __deepcopy__(self, memo: dict[int, object]) -> NoReturn:
        raise DecisionFrozenError

    def __reduce__(self) -> NoReturn:
        raise DecisionFrozenError

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise DecisionFrozenError


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise DecisionInputError(code)


def _guard_new_trace(record: object) -> None:
    try:
        require(record, TRACE_TAG)
    except SealError as exc:
        if exc.code == "SEAL_NOT_ISSUED":
            return
    raise DecisionInputError("UNISSUED_TRACE")


@_content_free_frozen
@dataclass(frozen=True, slots=True)
class DecisionFixtureV1(_FrozenRecord):
    fixture_id: str
    c102_bars_sha256: str
    c102_lock_sha256: str
    fusion: FusionResultV1
    sizing: SizingResultV1
    portfolio: PortfolioCheckV1
    context: DecisionContextV1
    schema_version: Literal["1.0.0"] = "1.0.0"

    def __post_init__(self) -> None:
        _require(type(self.fixture_id) is str and _ID.fullmatch(self.fixture_id) is not None,
                 "INVALID_FIXTURE")
        for value in (self.c102_bars_sha256, self.c102_lock_sha256):
            _require(type(value) is str and _DIGEST.fullmatch(value) is not None,
                     "INVALID_DIGEST")
        _require(type(self.fusion) is FusionResultV1 and type(self.sizing) is SizingResultV1
                 and type(self.portfolio) is PortfolioCheckV1
                 and type(self.context) is DecisionContextV1, "INVALID_FIXTURE")
        _require(type(self.schema_version) is str and self.schema_version == "1.0.0",
                 "INVALID_VERSION")


@_content_free_frozen
@dataclass(frozen=True, slots=True, weakref_slot=True, init=False)
class DecisionTraceV1(_FrozenRecord):
    fixture_id: str
    fixture_hash: str
    c102_bars_sha256: str
    c102_lock_sha256: str
    proposal: DecisionProposalV1
    schema_version: Literal["1.0.0"] = "1.0.0"
    _issuer: InitVar[object | None] = None

    def __init__(self, *, _issuer: object | None = None, **values: object) -> None:
        _guard_new_trace(self)
        _require(_issuer is _TRACE_CONSTRUCTION, "UNISSUED_TRACE")
        values.setdefault("schema_version", "1.0.0")
        declared = {field.name for field in fields(type(self))}
        _require(set(values) == declared, "INVALID_TRACE")
        for field in fields(type(self)):
            object.__setattr__(self, field.name, values[field.name])
        self.__post_init__(_issuer)

    def __post_init__(self, _issuer: object | None) -> None:
        _require(_issuer is _TRACE_CONSTRUCTION, "UNISSUED_TRACE")
        _require(not _TRACE_ISSUER.issued_here(self), "ALREADY_ISSUED")
        _require(type(self.fixture_id) is str and _ID.fullmatch(self.fixture_id) is not None,
                 "INVALID_TRACE")
        for value in (self.fixture_hash, self.c102_bars_sha256, self.c102_lock_sha256):
            _require(type(value) is str and _DIGEST.fullmatch(value) is not None,
                     "INVALID_DIGEST")
        _require(type(self.proposal) is DecisionProposalV1, "INVALID_TRACE")
        _require(type(self.schema_version) is str and self.schema_version == "1.0.0",
                 "INVALID_VERSION")

    def canonical_bytes(self) -> bytes:
        require(self, TRACE_TAG)
        proposal = json.loads(self.proposal.canonical_bytes())
        return canonical_json({
            "schema_version": self.schema_version,
            "fixture_id": self.fixture_id,
            "fixture_hash": self.fixture_hash,
            "c102_bars_sha256": self.c102_bars_sha256,
            "c102_lock_sha256": self.c102_lock_sha256,
            "proposal": proposal,
        })


def replay(fixture: DecisionFixtureV1) -> DecisionTraceV1:
    """Pin C-102 fixture digests and recompute a byte-stable proposal trace."""
    _require(type(fixture) is DecisionFixtureV1, "INVALID_FIXTURE")
    fixture.__post_init__()
    proposal = compose(fixture.fusion, fixture.sizing, fixture.portfolio, fixture.context)
    fixture_hash = hashlib.sha256(canonical_json({
        "schema_version": fixture.schema_version,
        "fixture_id": fixture.fixture_id,
        "c102_bars_sha256": fixture.c102_bars_sha256,
        "c102_lock_sha256": fixture.c102_lock_sha256,
        "proposal_input_hash": proposal.input_hash,
    })).hexdigest()
    trace = DecisionTraceV1(
        fixture_id=fixture.fixture_id,
        fixture_hash=fixture_hash,
        c102_bars_sha256=fixture.c102_bars_sha256,
        c102_lock_sha256=fixture.c102_lock_sha256,
        proposal=proposal,
        _issuer=_TRACE_CONSTRUCTION,
    )
    return _TRACE_ISSUER.issue(trace)


__all__ = ["DecisionFixtureV1", "DecisionTraceV1", "replay"]
