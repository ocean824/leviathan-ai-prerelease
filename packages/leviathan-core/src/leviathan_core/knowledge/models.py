"""Knowledge Domain models — ConceptChunk and SourceProvenance.

All knowledge artefacts carry cryptographic provenance so the lineage of
every insight can be traced to its origin document. Knowledge NEVER flows
directly to live execution — it must pass the Research Domain first.
"""

from datetime import datetime

from pydantic import Field

from leviathan_core.schemas.base import LeviathanModel

# Allowed source types for ConceptChunk.
SourceType = str  # literal "pdf" | "markdown" | "note" | "transcript"


class SourceProvenance(LeviathanModel):
    """Cryptographic lineage record for an ingested source.

    Every ConceptChunk embeds one SourceProvenance so that downstream
    consumers can always verify what was ingested and when.
    """

    source_id: str
    origin_path: str
    ingested_at: datetime
    sha256: str = Field(min_length=64, max_length=64)


class ConceptChunk(LeviathanModel):
    """A structured knowledge fragment extracted from a source document.

    ``chunk_id``      — unique identifier for this chunk.
    ``source_id``     — identifier for the source document.
    ``source_type``   — one of: "pdf", "markdown", "note", "transcript".
    ``title``         — section heading or derived title.
    ``content``       — full text of this chunk.
    ``tags``          — zero or more classification tags.
    ``methodology``   — optional methodology label (e.g. "ict_concepts").
    ``provenance``    — cryptographic lineage of the originating source.
    """

    chunk_id: str
    source_id: str
    source_type: str = Field(pattern=r"^(pdf|markdown|note|transcript)$")
    title: str
    content: str
    tags: tuple[str, ...] = Field(default=())
    methodology: str | None = None
    provenance: SourceProvenance
