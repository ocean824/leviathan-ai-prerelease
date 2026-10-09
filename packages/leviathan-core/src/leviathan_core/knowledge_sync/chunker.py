"""Pure, deterministic Markdown chunking with protected code and quote blocks."""

import re
from collections.abc import Sequence
from dataclasses import dataclass
from itertools import pairwise

from markdown_it.token import Token

from leviathan_core.knowledge_sync.parser_models import MAX_PARSER_CHUNKS, ChunkSpecV1

_TOKEN = re.compile(r"\S+")
_MAX_TOKEN_CHARS = 64
MAX_LINES = 100_000
MAX_TOKENS = 262_144
MAX_CHUNKS_PER_DOCUMENT = MAX_PARSER_CHUNKS
MAX_HEADING_CHARS = 256


class ResourceLimitError(ValueError):
    pass


@dataclass(frozen=True)
class _TokenSpan:
    start: int
    end: int


@dataclass(frozen=True)
class _FenceInfo:
    opener: str
    marker: str
    content_start: int
    content_end: int


@dataclass(frozen=True)
class _Block:
    start: int
    end: int
    kind: str
    heading: str | None
    heading_path: tuple[str, ...]
    tokens: tuple[_TokenSpan, ...]
    fence: _FenceInfo | None = None


@dataclass(frozen=True)
class ChunkWindow:
    char_start: int
    char_end: int
    heading: str | None
    heading_path: tuple[str, ...]
    token_count: int
    text: str
    continuation_part: int | None = None
    continuation_total: int | None = None
    synthetic_fence: bool = False


def _fence_info(text: str, line_offsets: list[int], token: Token) -> _FenceInfo:
    if token.map is None:
        raise ResourceLimitError("fence has no source map")
    first, last = token.map
    opener = text[line_offsets[first] : line_offsets[first + 1]].lstrip(" \t").rstrip("\r\n")
    marker = token.markup
    if not opener.startswith(marker):
        raise ResourceLimitError("invalid fence source map")
    closer = text[line_offsets[last - 1] : line_offsets[last]].lstrip(" \t").rstrip("\r\n")
    run = len(closer) - len(closer.lstrip(marker[0]))
    explicitly_closed = last - first >= 2 and run >= len(marker) and not closer[run:].strip()
    content_end = line_offsets[last - 1] if explicitly_closed else line_offsets[last]
    return _FenceInfo(opener, marker, line_offsets[first + 1], content_end)


def _make_block(
    text: str,
    start: int,
    end: int,
    kind: str,
    heading_path: tuple[str, ...],
    fence: _FenceInfo | None = None,
) -> _Block | None:
    token_list = _token_spans(text, start, end)
    if not token_list:
        return None
    if kind in ("code", "quote"):
        token_list[0] = _TokenSpan(start, token_list[0].end)
    return _Block(
        start,
        end,
        kind,
        heading_path[-1] if heading_path else None,
        heading_path,
        tuple(token_list),
        fence,
    )


def _blocks(text: str, body_start: int, markdown_tokens: Sequence[Token]) -> list[_Block]:
    """Use CommonMark block spans; no independent Markdown grammar lives here."""

    line_offsets = [body_start]
    for line in text[body_start:].splitlines(keepends=True):
        line_offsets.append(line_offsets[-1] + len(line))
    blocks: list[_Block] = []
    index = 0
    headings: list[tuple[int, str]] = []

    def enter_heading(heading_token: Token, inline_token: Token) -> tuple[str, ...]:
        level = int(heading_token.tag[1:])
        heading = inline_token.content.strip().rstrip("# ").strip()
        if len(heading) > MAX_HEADING_CHARS:
            raise ResourceLimitError("heading limit")
        while headings and headings[-1][0] >= level:
            headings.pop()
        headings.append((level, heading))
        return tuple(title for _, title in headings)

    while index < len(markdown_tokens):
        token = markdown_tokens[index]
        if token.map is None or token.type == "definition" or token.nesting < 0:
            index += 1
            continue
        if token.nesting == 1:
            depth = 1
            following = index + 1
            while following < len(markdown_tokens) and depth:
                depth += markdown_tokens[following].nesting
                following += 1
            if depth:
                raise ResourceLimitError("unclosed Markdown token")
        else:
            following = index + 1
        start_line, end_line = token.map
        if end_line > len(line_offsets) - 1:
            raise ResourceLimitError("invalid Markdown source map")
        start, end = line_offsets[start_line], line_offsets[end_line]
        kind = "code" if token.type in ("fence", "code_block") else "prose"
        if token.type == "heading_open":
            heading_path = enter_heading(token, markdown_tokens[index + 1])
            kind = "heading"
        else:
            heading_path = tuple(title for _, title in headings)
        if token.type == "blockquote_open":
            kind = "quote"
        if kind in ("heading", "quote", "code"):
            fence = _fence_info(text, line_offsets, token) if token.type == "fence" else None
            block = _make_block(text, start, end, kind, heading_path, fence)
            if block is not None:
                blocks.append(block)
            if kind == "quote":
                for nested_index in range(index + 1, following):
                    nested = markdown_tokens[nested_index]
                    if nested.type == "heading_open":
                        enter_heading(nested, markdown_tokens[nested_index + 1])
        else:
            protected: list[tuple[int, int, str, Token, int]] = []
            for nested_index in range(index + 1, following):
                nested = markdown_tokens[nested_index]
                if nested.map is None or nested.type not in (
                    "fence", "code_block", "blockquote_open", "heading_open"
                ):
                    continue
                nested_start, nested_end = nested.map
                protected.append(
                    (
                        line_offsets[nested_start],
                        line_offsets[nested_end],
                        (
                            "quote"
                            if nested.type == "blockquote_open"
                            else "heading"
                            if nested.type == "heading_open"
                            else "code"
                        ),
                        nested,
                        nested_index,
                    )
                )
            protected.sort(key=lambda item: (item[0], -item[1]))
            cursor = start
            for protected_start, protected_end, protected_kind, nested, nested_index in protected:
                if protected_start < cursor:
                    if protected_kind == "heading" and protected_end <= cursor:
                        heading_path = enter_heading(nested, markdown_tokens[nested_index + 1])
                    continue
                if protected_end > end:
                    continue
                before = _make_block(text, cursor, protected_start, "prose", heading_path)
                if before is not None:
                    blocks.append(before)
                if protected_kind == "heading":
                    heading_path = enter_heading(nested, markdown_tokens[nested_index + 1])
                fence = _fence_info(text, line_offsets, nested) if nested.type == "fence" else None
                protected_block = _make_block(
                    text, protected_start, protected_end, protected_kind, heading_path, fence
                )
                if protected_block is not None:
                    blocks.append(protected_block)
                cursor = protected_end
            after = _make_block(text, cursor, end, "prose", heading_path)
            if after is not None:
                blocks.append(after)
        index = following
    return blocks


def _token_spans(text: str, start: int, end: int) -> list[_TokenSpan]:
    """Whitespace tokens, with bounded pieces for unbroken text and CJK runs."""

    spans: list[_TokenSpan] = []
    for match in _TOKEN.finditer(text[start:end]):
        token_start = start + match.start()
        token_end = start + match.end()
        for piece_start in range(token_start, token_end, _MAX_TOKEN_CHARS):
            spans.append(_TokenSpan(piece_start, min(piece_start + _MAX_TOKEN_CHARS, token_end)))
    return spans


def _window(
    text: str, tokens: tuple[_TokenSpan, ...], heading_path: tuple[str, ...]
) -> ChunkWindow:
    start, end = tokens[0].start, tokens[-1].end
    return ChunkWindow(
        start,
        end,
        heading_path[-1] if heading_path else None,
        heading_path,
        len(tokens),
        text[start:end],
    )


def _fence_parts(text: str, block: _Block, spec: ChunkSpecV1) -> list[ChunkWindow]:
    fence = block.fence
    if fence is None:
        raise ResourceLimitError("missing fence metadata")
    wrapper_tokens = len(_token_spans(fence.opener, 0, len(fence.opener))) + 1
    capacity = spec.target_tokens - wrapper_tokens
    if capacity < 1:
        raise ResourceLimitError("fence information exceeds chunk target")
    content_tokens = _token_spans(text, fence.content_start, fence.content_end)
    if not content_tokens:
        return [_window(text, block.tokens, block.heading_path)]
    boundaries = [fence.content_start]
    boundaries.extend(
        content_tokens[index].start for index in range(capacity, len(content_tokens), capacity)
    )
    boundaries.append(fence.content_end)
    if len(boundaries) == 2:
        return [_window(text, block.tokens, block.heading_path)]
    total = len(boundaries) - 1
    windows: list[ChunkWindow] = []
    for index, (start, end) in enumerate(pairwise(boundaries), start=1):
        original = text[start:end]
        fence_open = fence.opener + "\n"
        fence_close = "\n" + fence.marker
        windows.append(
            ChunkWindow(
                char_start=start,
                char_end=end,
                heading=block.heading,
                heading_path=block.heading_path,
                token_count=len(_token_spans(text, start, end)) + wrapper_tokens,
                text=fence_open + original + fence_close,
                continuation_part=index,
                continuation_total=total,
                synthetic_fence=True,
            )
        )
    return windows


def _trailing_overlap(blocks: list[_Block], limit: int) -> list[_Block]:
    kept: list[_Block] = []
    count = 0
    for block in reversed(blocks):
        if count + len(block.tokens) > limit:
            break
        kept.insert(0, block)
        count += len(block.tokens)
    return kept


def chunk_markdown(
    text: str, body_start: int, spec: ChunkSpecV1, markdown_tokens: Sequence[Token]
) -> tuple[ChunkWindow, ...]:
    """Keep code/quote blocks whole and overlap only complete blocks."""

    if text.count("\n") + text.count("\r") > MAX_LINES:
        raise ResourceLimitError("line limit")
    token_count = 0
    for match in _TOKEN.finditer(text[body_start:]):
        token_count += (len(match.group()) + _MAX_TOKEN_CHARS - 1) // _MAX_TOKEN_CHARS
        if token_count > MAX_TOKENS:
            raise ResourceLimitError("token limit")

    output: list[ChunkWindow] = []
    pending: list[_Block] = []
    pending_count = 0

    def emit_window(window: ChunkWindow) -> None:
        if len(output) >= MAX_CHUNKS_PER_DOCUMENT:
            raise ResourceLimitError("chunk limit")
        output.append(window)

    def emit(tokens: tuple[_TokenSpan, ...], heading_path: tuple[str, ...]) -> None:
        emit_window(_window(text, tokens, heading_path))

    for block in _blocks(text, body_start, markdown_tokens):
        block_count = len(block.tokens)
        if pending and (
            block.kind == "heading" or block.heading_path != pending[0].heading_path
        ):
            tokens = tuple(token for part in pending for token in part.tokens)
            emit(tokens, pending[0].heading_path)
            pending = []
            pending_count = 0
        if block_count > spec.target_tokens:
            if pending:
                tokens = tuple(token for part in pending for token in part.tokens)
                emit(tokens, pending[0].heading_path)
                pending = []
                pending_count = 0
            if block.fence is not None:
                for window in _fence_parts(text, block, spec):
                    emit_window(window)
                continue
            if block.kind in ("heading", "code", "quote"):
                emit(block.tokens, block.heading_path)
                continue
            step = spec.target_tokens - spec.overlap_tokens
            for offset in range(0, block_count, step):
                token_slice = block.tokens[offset : offset + spec.target_tokens]
                emit(token_slice, block.heading_path)
                if offset + spec.target_tokens >= block_count:
                    break
            continue
        if pending and pending_count + block_count > spec.target_tokens:
            tokens = tuple(token for part in pending for token in part.tokens)
            emit(tokens, pending[0].heading_path)
            pending = _trailing_overlap(pending, spec.overlap_tokens)
            pending_count = sum(len(part.tokens) for part in pending)
            if pending_count + block_count > spec.target_tokens:
                pending = []
                pending_count = 0
        pending.append(block)
        pending_count += block_count
    if pending:
        tokens = tuple(token for part in pending for token in part.tokens)
        emit(tokens, pending[0].heading_path)
    return tuple(output)
