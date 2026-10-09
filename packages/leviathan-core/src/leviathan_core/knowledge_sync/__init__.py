"""Offline Obsidian Markdown parsing contracts; no source fetching or persistence."""

from leviathan_core.knowledge_sync.markdown_parser import parse_markdown
from leviathan_core.knowledge_sync.parser_models import (
    ChunkSpecV1,
    FolderTagRuleV1,
    ParsedChunkV1,
    ParseFailureV1,
    ParseResultV1,
    ParserModelError,
    SourceEnvelopeV1,
    TagRulesV1,
    TagSetV1,
    VaultPathIndexV1,
)

__all__ = [
    "ChunkSpecV1",
    "FolderTagRuleV1",
    "ParseFailureV1",
    "ParseResultV1",
    "ParsedChunkV1",
    "ParserModelError",
    "SourceEnvelopeV1",
    "TagRulesV1",
    "TagSetV1",
    "VaultPathIndexV1",
    "parse_markdown",
]
