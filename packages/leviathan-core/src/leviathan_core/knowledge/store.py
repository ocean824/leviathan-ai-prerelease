"""InMemoryKnowledgeStore — volatile knowledge chunk repository.

Provides add/get/search-by-tag/search-by-methodology operations. All
stored objects are immutable ConceptChunks (frozen Pydantic models).
This store is intentionally ephemeral: it is used for testing and
in-process research sessions. Knowledge NEVER flows directly to live
execution — it must pass the Research Domain validation gate first.
"""

from leviathan_core.knowledge.models import ConceptChunk


class InMemoryKnowledgeStore:
    """Thread-unsafe in-memory store for ConceptChunks.

    All mutation methods accept a single ConceptChunk; the store is
    keyed by chunk_id and duplicate ids are silently replaced.
    """

    def __init__(self) -> None:
        self._chunks: dict[str, ConceptChunk] = {}

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def add(self, chunk: ConceptChunk) -> None:
        """Insert or replace a chunk by chunk_id."""
        self._chunks[chunk.chunk_id] = chunk

    def add_many(self, chunks: list[ConceptChunk]) -> None:
        """Bulk insert."""
        for chunk in chunks:
            self.add(chunk)

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def get(self, chunk_id: str) -> ConceptChunk | None:
        """Return the chunk with the given id, or None."""
        return self._chunks.get(chunk_id)

    def all(self) -> list[ConceptChunk]:
        """Return all stored chunks in insertion order."""
        return list(self._chunks.values())

    # ------------------------------------------------------------------
    # Search
    # ------------------------------------------------------------------

    def search_by_tag(self, tag: str) -> list[ConceptChunk]:
        """Return all chunks that carry the given tag (exact match)."""
        return [c for c in self._chunks.values() if tag in c.tags]

    def search_by_methodology(self, methodology: str) -> list[ConceptChunk]:
        """Return all chunks whose methodology matches the given string."""
        return [c for c in self._chunks.values() if c.methodology == methodology]

    def __len__(self) -> int:
        return len(self._chunks)
