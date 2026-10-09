"""Knowledge Domain — document/vault ingestion contracts (TRITON).

Phase 1 implementation target. Parses PDFs/notes/vault content into
structured intelligence with provenance. Knowledge NEVER flows directly
to live execution — it must pass the Research Domain first.
"""

from leviathan_core.knowledge.ingest import MarkdownIngestor
from leviathan_core.knowledge.models import ConceptChunk, SourceProvenance
from leviathan_core.knowledge.store import InMemoryKnowledgeStore

__all__ = [
    "ConceptChunk",
    "InMemoryKnowledgeStore",
    "MarkdownIngestor",
    "SourceProvenance",
]
