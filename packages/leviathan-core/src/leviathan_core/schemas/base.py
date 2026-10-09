"""Base model and identity helpers for all LEVIATHAN contracts."""

from datetime import UTC, datetime
from uuid import uuid4

from pydantic import BaseModel, ConfigDict


class LeviathanModel(BaseModel):
    """Frozen, strict base for every Layer-1 contract.

    - frozen: contract objects are immutable value objects; downstream
      layers may not mutate upstream evidence.
    - extra="forbid": unknown fields are a schema violation, not noise.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")


def utcnow() -> datetime:
    return datetime.now(UTC)


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex[:12]}"
