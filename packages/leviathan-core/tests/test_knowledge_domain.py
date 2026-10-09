"""Tests for Knowledge Domain: MarkdownIngestor, ConceptChunk, InMemoryKnowledgeStore."""

import hashlib
from datetime import UTC, datetime

import pytest

from leviathan_core.knowledge import (
    ConceptChunk,
    InMemoryKnowledgeStore,
    MarkdownIngestor,
    SourceProvenance,
)

_INGESTED_AT = datetime(2026, 4, 15, 12, 0, 0, tzinfo=UTC)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# MarkdownIngestor — chunking
# ---------------------------------------------------------------------------

_MARKDOWN_TWO_SECTIONS = """\
# Document Title

Some preamble text that should be discarded.

## Fair Value Gaps

tags: ict, fvg, imbalance
methodology: ict_concepts

A fair value gap is a three-candle imbalance where price moves so quickly
that an inefficiency is left behind in the chart.

## Order Blocks

tags: ict, order_block

An order block is the last opposing candle before a strong directional move.
"""

_MARKDOWN_NO_HEADINGS = """\
Just a plain document with no ## headings at all.
"""

_MARKDOWN_SINGLE_SECTION = """\
## Liquidity Sweeps

tags: ict, liquidity
methodology: smart_money

Equal highs and equal lows act as liquidity pools.
"""


def test_ingest_two_sections_produces_two_chunks() -> None:
    ingestor = MarkdownIngestor()
    chunks = ingestor.ingest(
        _MARKDOWN_TWO_SECTIONS, origin_path="/vault/concepts.md", ingested_at=_INGESTED_AT
    )
    assert len(chunks) == 2


def test_chunk_titles_match_headings() -> None:
    ingestor = MarkdownIngestor()
    chunks = ingestor.ingest(
        _MARKDOWN_TWO_SECTIONS, origin_path="/vault/concepts.md", ingested_at=_INGESTED_AT
    )
    assert chunks[0].title == "Fair Value Gaps"
    assert chunks[1].title == "Order Blocks"


def test_chunk_tags_parsed_correctly() -> None:
    ingestor = MarkdownIngestor()
    chunks = ingestor.ingest(
        _MARKDOWN_TWO_SECTIONS, origin_path="/vault/concepts.md", ingested_at=_INGESTED_AT
    )
    assert chunks[0].tags == ("ict", "fvg", "imbalance")
    assert chunks[1].tags == ("ict", "order_block")


def test_chunk_methodology_parsed_on_first_section() -> None:
    ingestor = MarkdownIngestor()
    chunks = ingestor.ingest(
        _MARKDOWN_TWO_SECTIONS, origin_path="/vault/concepts.md", ingested_at=_INGESTED_AT
    )
    assert chunks[0].methodology == "ict_concepts"


def test_chunk_methodology_none_when_absent() -> None:
    ingestor = MarkdownIngestor()
    chunks = ingestor.ingest(
        _MARKDOWN_TWO_SECTIONS, origin_path="/vault/concepts.md", ingested_at=_INGESTED_AT
    )
    assert chunks[1].methodology is None


def test_tags_and_methodology_lines_stripped_from_content() -> None:
    ingestor = MarkdownIngestor()
    chunks = ingestor.ingest(
        _MARKDOWN_TWO_SECTIONS, origin_path="/vault/concepts.md", ingested_at=_INGESTED_AT
    )
    content = chunks[0].content
    assert "tags:" not in content.lower()
    assert "methodology:" not in content.lower()
    assert "fair value gap" in content.lower()


def test_no_headings_returns_empty_list() -> None:
    ingestor = MarkdownIngestor()
    chunks = ingestor.ingest(
        _MARKDOWN_NO_HEADINGS, origin_path="/vault/plain.md", ingested_at=_INGESTED_AT
    )
    assert chunks == []


def test_single_section_returns_one_chunk() -> None:
    ingestor = MarkdownIngestor()
    chunks = ingestor.ingest(
        _MARKDOWN_SINGLE_SECTION, origin_path="/vault/liq.md", ingested_at=_INGESTED_AT
    )
    assert len(chunks) == 1
    assert chunks[0].title == "Liquidity Sweeps"
    assert chunks[0].methodology == "smart_money"
    assert "ict" in chunks[0].tags


# ---------------------------------------------------------------------------
# MarkdownIngestor — provenance and sha256
# ---------------------------------------------------------------------------


def test_all_chunks_share_same_provenance_sha256() -> None:
    ingestor = MarkdownIngestor()
    chunks = ingestor.ingest(
        _MARKDOWN_TWO_SECTIONS, origin_path="/vault/concepts.md", ingested_at=_INGESTED_AT
    )
    expected_sha = _sha256(_MARKDOWN_TWO_SECTIONS)
    for chunk in chunks:
        assert chunk.provenance.sha256 == expected_sha


def test_provenance_origin_path_is_preserved() -> None:
    ingestor = MarkdownIngestor()
    chunks = ingestor.ingest(
        _MARKDOWN_SINGLE_SECTION,
        origin_path="/research/notes/liq.md",
        ingested_at=_INGESTED_AT,
    )
    assert chunks[0].provenance.origin_path == "/research/notes/liq.md"


def test_provenance_ingested_at_is_preserved() -> None:
    ingestor = MarkdownIngestor()
    chunks = ingestor.ingest(
        _MARKDOWN_SINGLE_SECTION, origin_path="/vault/liq.md", ingested_at=_INGESTED_AT
    )
    assert chunks[0].provenance.ingested_at == _INGESTED_AT


def test_all_chunks_share_same_source_id() -> None:
    ingestor = MarkdownIngestor()
    chunks = ingestor.ingest(
        _MARKDOWN_TWO_SECTIONS,
        origin_path="/vault/concepts.md",
        source_id="src_fixed_001",
        ingested_at=_INGESTED_AT,
    )
    for chunk in chunks:
        assert chunk.source_id == "src_fixed_001"
        assert chunk.provenance.source_id == "src_fixed_001"


def test_explicit_source_id_propagated() -> None:
    ingestor = MarkdownIngestor()
    chunks = ingestor.ingest(
        _MARKDOWN_SINGLE_SECTION,
        origin_path="/vault/liq.md",
        source_id="src_explicit_42",
        ingested_at=_INGESTED_AT,
    )
    assert chunks[0].provenance.source_id == "src_explicit_42"


def test_sha256_changes_when_content_changes() -> None:
    ingestor = MarkdownIngestor()
    text_a = "## Section A\n\nContent A."
    text_b = "## Section A\n\nContent B."
    chunks_a = ingestor.ingest(text_a, origin_path="/f.md", ingested_at=_INGESTED_AT)
    chunks_b = ingestor.ingest(text_b, origin_path="/f.md", ingested_at=_INGESTED_AT)
    assert chunks_a[0].provenance.sha256 != chunks_b[0].provenance.sha256


# ---------------------------------------------------------------------------
# MarkdownIngestor — source_type
# ---------------------------------------------------------------------------


def test_default_source_type_is_markdown() -> None:
    ingestor = MarkdownIngestor()
    chunks = ingestor.ingest(
        _MARKDOWN_SINGLE_SECTION, origin_path="/f.md", ingested_at=_INGESTED_AT
    )
    assert chunks[0].source_type == "markdown"


def test_custom_source_type_note() -> None:
    ingestor = MarkdownIngestor(source_type="note")
    chunks = ingestor.ingest(
        _MARKDOWN_SINGLE_SECTION, origin_path="/f.md", ingested_at=_INGESTED_AT
    )
    assert chunks[0].source_type == "note"


def test_invalid_source_type_raises() -> None:
    from pydantic import ValidationError

    ingestor = MarkdownIngestor(source_type="invalid_type")
    with pytest.raises(ValidationError):
        ingestor.ingest(
            _MARKDOWN_SINGLE_SECTION, origin_path="/f.md", ingested_at=_INGESTED_AT
        )


# ---------------------------------------------------------------------------
# MarkdownIngestor — frozen models
# ---------------------------------------------------------------------------


def test_concept_chunk_is_frozen() -> None:
    from pydantic import ValidationError

    ingestor = MarkdownIngestor()
    chunks = ingestor.ingest(
        _MARKDOWN_SINGLE_SECTION, origin_path="/f.md", ingested_at=_INGESTED_AT
    )
    chunk = chunks[0]
    with pytest.raises((ValidationError, TypeError)):
        chunk.title = "modified"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# InMemoryKnowledgeStore
# ---------------------------------------------------------------------------


def _make_chunk(
    chunk_id: str,
    tags: tuple[str, ...] = (),
    methodology: str | None = None,
) -> ConceptChunk:
    prov = SourceProvenance(
        source_id="src_test",
        origin_path="/test.md",
        ingested_at=_INGESTED_AT,
        sha256="a" * 64,
    )
    return ConceptChunk(
        chunk_id=chunk_id,
        source_id="src_test",
        source_type="markdown",
        title=f"Title {chunk_id}",
        content=f"Content for {chunk_id}",
        tags=tags,
        methodology=methodology,
        provenance=prov,
    )


def test_store_add_and_get() -> None:
    store = InMemoryKnowledgeStore()
    chunk = _make_chunk("chunk_001")
    store.add(chunk)
    assert store.get("chunk_001") is chunk


def test_store_get_unknown_returns_none() -> None:
    store = InMemoryKnowledgeStore()
    assert store.get("nonexistent") is None


def test_store_add_many() -> None:
    store = InMemoryKnowledgeStore()
    chunks = [_make_chunk(f"chunk_{i:03d}") for i in range(5)]
    store.add_many(chunks)
    assert len(store) == 5


def test_store_search_by_tag() -> None:
    store = InMemoryKnowledgeStore()
    store.add(_make_chunk("c1", tags=("ict", "fvg")))
    store.add(_make_chunk("c2", tags=("ict", "ob")))
    store.add(_make_chunk("c3", tags=("smc",)))
    results = store.search_by_tag("ict")
    assert len(results) == 2
    ids = {r.chunk_id for r in results}
    assert ids == {"c1", "c2"}


def test_store_search_by_tag_no_match() -> None:
    store = InMemoryKnowledgeStore()
    store.add(_make_chunk("c1", tags=("ict",)))
    assert store.search_by_tag("wyckoff") == []


def test_store_search_by_methodology() -> None:
    store = InMemoryKnowledgeStore()
    store.add(_make_chunk("c1", methodology="ict_concepts"))
    store.add(_make_chunk("c2", methodology="ict_concepts"))
    store.add(_make_chunk("c3", methodology="smart_money"))
    store.add(_make_chunk("c4"))
    results = store.search_by_methodology("ict_concepts")
    assert len(results) == 2
    assert all(r.methodology == "ict_concepts" for r in results)


def test_store_replace_on_duplicate_id() -> None:
    store = InMemoryKnowledgeStore()
    store.add(_make_chunk("c1", tags=("a",)))
    store.add(_make_chunk("c1", tags=("b",)))
    assert len(store) == 1
    assert store.get("c1").tags == ("b",)  # type: ignore[union-attr]


def test_store_all_returns_all_chunks() -> None:
    store = InMemoryKnowledgeStore()
    chunks = [_make_chunk(f"c{i}") for i in range(3)]
    store.add_many(chunks)
    assert len(store.all()) == 3


# ---------------------------------------------------------------------------
# SourceProvenance sha256 field validation
# ---------------------------------------------------------------------------


def test_provenance_sha256_must_be_64_chars() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        SourceProvenance(
            source_id="s1",
            origin_path="/f.md",
            ingested_at=_INGESTED_AT,
            sha256="tooshort",
        )
