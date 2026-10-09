"""MarkdownIngestor — parse markdown text into ConceptChunks.

Chunking rules:
- Each ## heading starts a new chunk; the heading text becomes the title.
- Content is everything between this heading and the next ## heading.
- A line matching ``tags: a, b, c`` (case-insensitive) within a section
  populates the tags tuple; the line itself is stripped from the content.
- A line matching ``methodology: <value>`` within a section populates the
  methodology field; the line itself is stripped from the content.
- The preamble before the first ## heading is discarded (no chunk emitted
  for header-only or empty preamble text).
- sha256 is computed over the full source text (not per-chunk), so all
  chunks from the same source carry the same digest.
- ``ingested_at`` is set to utcnow() at call time; for deterministic tests
  pass ``ingested_at`` explicitly.

Pure function: no I/O, no side effects.
"""

import hashlib
import re
from datetime import datetime

from leviathan_core.knowledge.models import ConceptChunk, SourceProvenance
from leviathan_core.schemas.base import new_id, utcnow

_HEADING_RE = re.compile(r"^##\s+(.+)$", re.MULTILINE)
_TAGS_RE = re.compile(r"^\s*tags\s*:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
_METHODOLOGY_RE = re.compile(r"^\s*methodology\s*:\s*(.+)$", re.IGNORECASE | re.MULTILINE)


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _parse_tags(block: str) -> tuple[str, ...]:
    m = _TAGS_RE.search(block)
    if not m:
        return ()
    return tuple(tag.strip() for tag in m.group(1).split(",") if tag.strip())


def _parse_methodology(block: str) -> str | None:
    m = _METHODOLOGY_RE.search(block)
    return m.group(1).strip() if m else None


def _strip_meta_lines(block: str) -> str:
    """Remove tags: and methodology: lines from content."""
    block = _TAGS_RE.sub("", block)
    block = _METHODOLOGY_RE.sub("", block)
    return block.strip()


class MarkdownIngestor:
    """Parse a markdown string into ConceptChunks, one per ## section.

    Args:
        source_type: one of "pdf", "markdown", "note", "transcript".
                     Defaults to "markdown".
    """

    def __init__(self, source_type: str = "markdown") -> None:
        self._source_type = source_type

    def ingest(
        self,
        text: str,
        origin_path: str,
        *,
        source_id: str | None = None,
        ingested_at: datetime | None = None,
    ) -> list[ConceptChunk]:
        """Parse *text* into ConceptChunks.

        Args:
            text:         Raw markdown source text.
            origin_path:  File path or URI identifying the source document.
            source_id:    Optional explicit source identifier; auto-generated
                          if omitted.
            ingested_at:  Explicit ingestion timestamp (tz-aware). Defaults
                          to utcnow().

        Returns:
            List of ConceptChunks, one per ## section found in *text*.
            Returns an empty list if no ## headings exist.
        """
        if source_id is None:
            source_id = new_id("src")
        if ingested_at is None:
            ingested_at = utcnow()

        sha = _sha256_hex(text)
        provenance = SourceProvenance(
            source_id=source_id,
            origin_path=origin_path,
            ingested_at=ingested_at,
            sha256=sha,
        )

        # Split by ## headings.
        matches = list(_HEADING_RE.finditer(text))
        if not matches:
            return []

        chunks: list[ConceptChunk] = []
        for i, match in enumerate(matches):
            title = match.group(1).strip()
            start = match.end()
            end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
            raw_block = text[start:end]

            tags = _parse_tags(raw_block)
            methodology = _parse_methodology(raw_block)
            content = _strip_meta_lines(raw_block)

            chunk = ConceptChunk(
                chunk_id=new_id("chunk"),
                source_id=source_id,
                source_type=self._source_type,
                title=title,
                content=content,
                tags=tags,
                methodology=methodology,
                provenance=provenance,
            )
            chunks.append(chunk)

        return chunks
