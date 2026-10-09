"""Typed fake-Neon feature persistence results and internal stored rows."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from leviathan_core.seal import SealedModel


class FeaturePersistenceError(ValueError):
    """Content-free error at the repository boundary."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class FeatureWriteAckV1(SealedModel):
    """Issued proof of one atomic fake transaction, with no durability claim."""

    backend: Literal["FAKE_NEON"] = "FAKE_NEON"
    boundary: Literal["fake_transaction_commit"] = "fake_transaction_commit"
    committed: Literal[True] = True
    transaction_sequence: int
    inserted_count: int
    idempotent_count: int


@dataclass(frozen=True, slots=True)
class _DefinitionRow:
    payload: bytes
    semantic_hash: str
    metadata_sha256: str
    git_ref: str
    data_interval_start_ns: int
    data_interval_end_ns: int


@dataclass(frozen=True, slots=True)
class _ObservationRow:
    payload: bytes
    semantic_hash: str
