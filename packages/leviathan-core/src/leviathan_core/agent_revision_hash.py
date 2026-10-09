"""Domain-separated revision digests for the existing agent council profiles."""

from __future__ import annotations

import hashlib
import re
from enum import StrEnum
from typing import Literal

from pydantic import field_validator

from leviathan_core.agent_council.runner_models import CouncilRunCommandV1
from leviathan_core.agent_council.state_models import HypothesisV1
from leviathan_core.numeric import canonical_json
from leviathan_core.seal import Issuer, SealedModel

_HASH = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_SEMANTIC_ISSUER = Issuer("agent.revision_hash.semantic.v1")
_FULL_ISSUER = Issuer("agent.revision_hash.full.v1")


class RevisionHashCode(StrEnum):
    INVALID_INPUT = "INVALID_INPUT"


class RevisionHashError(ValueError):
    """Content-free error for unsupported revision-hash inputs."""

    def __init__(self, code: RevisionHashCode) -> None:
        self.code = code
        super().__init__(code.value)


class _RevisionDigestV1(SealedModel):
    """Shared immutable representation; the concrete class pins its profile."""

    schema_version: Literal["1"]
    sha256_hex: str

    @field_validator("sha256_hex")
    @classmethod
    def _validate_digest(cls, value: str) -> str:
        if type(value) is not str or _HASH.fullmatch(value) is None:
            raise ValueError("INVALID_DIGEST")
        return value

    def __eq__(self, other: object) -> bool:
        if isinstance(other, _RevisionDigestV1) and type(self) is not type(other):
            raise TypeError("PROFILE_MISMATCH")
        return super().__eq__(other)


class CouncilStateSemanticDigestV1(_RevisionDigestV1):
    """Digest for AGENT-001 semantic state identity."""

    profile: Literal["council_state_semantic"]


class HypothesisFullRevisionDigestV1(_RevisionDigestV1):
    """Digest for AGENT-004 full hypothesis revision binding."""

    profile: Literal["hypothesis_full_revision"]


def council_state_semantic(hypothesis: HypothesisV1) -> CouncilStateSemanticDigestV1:
    """Return the legacy semantic hash, excluding identity/version and sorting refs."""
    if type(hypothesis) is not HypothesisV1:
        raise RevisionHashError(RevisionHashCode.INVALID_INPUT)
    try:
        payload = hypothesis.model_dump(mode="json", exclude={"hypothesis_id", "version"})
        payload["signal_refs"] = sorted(
            payload["signal_refs"],
            key=lambda ref: (ref["signal_id"], ref["version"]),
        )
        digest = hashlib.sha256(canonical_json(payload)).hexdigest()
        result = CouncilStateSemanticDigestV1(
            schema_version="1",
            profile="council_state_semantic",
            sha256_hex=digest,
        )
        return _SEMANTIC_ISSUER.issue(result)
    except Exception:
        raise RevisionHashError(RevisionHashCode.INVALID_INPUT) from None


def hypothesis_full_revision(
    command: CouncilRunCommandV1,
) -> HypothesisFullRevisionDigestV1:
    """Return the legacy full revision hash over the command hypothesis JSON."""
    if type(command) is not CouncilRunCommandV1:
        raise RevisionHashError(RevisionHashCode.INVALID_INPUT)
    return hypothesis_full_revision_from_hypothesis(command.hypothesis)


def hypothesis_full_revision_from_hypothesis(
    hypothesis: HypothesisV1,
) -> HypothesisFullRevisionDigestV1:
    """Return the full revision profile for an exact hypothesis value."""
    if type(hypothesis) is not HypothesisV1:
        raise RevisionHashError(RevisionHashCode.INVALID_INPUT)
    try:
        payload = hypothesis.model_dump(mode="json")
        digest = hashlib.sha256(canonical_json(payload)).hexdigest()
        result = HypothesisFullRevisionDigestV1(
            schema_version="1",
            profile="hypothesis_full_revision",
            sha256_hex=digest,
        )
        return _FULL_ISSUER.issue(result)
    except Exception:
        raise RevisionHashError(RevisionHashCode.INVALID_INPUT) from None


__all__ = [
    "CouncilStateSemanticDigestV1",
    "HypothesisFullRevisionDigestV1",
    "RevisionHashCode",
    "RevisionHashError",
    "council_state_semantic",
    "hypothesis_full_revision",
    "hypothesis_full_revision_from_hypothesis",
]
