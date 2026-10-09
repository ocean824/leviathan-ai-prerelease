"""Safe, pure Markdown source parsing. Source text is never executable authority."""

import hashlib
import html
import json
import posixpath
import re
import unicodedata
from collections.abc import Mapping
from typing import Any
from urllib.parse import unquote, urlsplit

import yaml
from markdown_it import MarkdownIt
from markdown_it.rules_inline.state_inline import StateInline
from markdown_it.token import Token
from yaml.events import AliasEvent, CollectionEndEvent, CollectionStartEvent, DocumentStartEvent

from leviathan_core.knowledge_sync.chunker import MAX_LINES, ResourceLimitError, chunk_markdown
from leviathan_core.knowledge_sync.parser_models import (
    MAX_PARSER_SOURCE_BYTES,
    ChunkSpecV1,
    ParsedChunkV1,
    ParseFailureV1,
    ParseResultV1,
    ParserModelError,
    SourceEnvelopeV1,
    TagRulesV1,
    _issue_model,
    _issue_result,
    _require_result,
)
from leviathan_core.knowledge_sync.tag_rules import TagRuleError, resolve_tags
from leviathan_core.seal import SealError

# A measured 1.5 AST tokens/source byte for dense CommonMark list/heading
# fixtures is rounded up to a 2-token/byte work allowance. Enforce this
# before Markdown or YAML parsing, rather than after token expansion.
MAX_MARKDOWN_BYTES = MAX_PARSER_SOURCE_BYTES
MAX_FRONTMATTER_BYTES = 64 * 1024
MAX_FRONTMATTER_DEPTH = 4
MAX_FRONTMATTER_EVENTS = 2048
MAX_PATH_DEPTH = 32
MAX_MARKDOWN_AST_TOKENS = 262_144
MAX_MARKDOWN_NESTING = 32
_WIKI_LINK = re.compile(r"\[\[([^\]\n]+)\]\]")
_DANGEROUS_PREFIX = re.compile(r"<\s*(script|style|iframe|object|embed|svg|form)\b", re.I)
_DEVICE = re.compile(
    r"^(?:con|prn|aux|nul|conin\$|conout\$|clock\$|com[1-9¹²³]|lpt[1-9¹²³])(?:\..*)?$",
    re.I,
)
_SHORT_NAME = re.compile(r"~[1-9](?:\.|$)", re.I)
_BACKSLASH_ESCAPE = re.compile(r"\\([!\"#$%&'()*+,./:;<=>?@\[\]^_`{|}~-])")


class _UniqueSafeLoader(yaml.SafeLoader):
    def construct_mapping(self, node: yaml.nodes.MappingNode, deep: bool = False) -> dict[Any, Any]:
        result: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, (str, int, float, bool)):
                raise yaml.constructor.ConstructorError(
                    None, None, "invalid YAML key", key_node.start_mark
                )
            if key in result:
                raise yaml.constructor.ConstructorError(
                    None, None, "duplicate YAML key", key_node.start_mark
                )
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def _failure(
    code: str,
    message: str,
    path: str,
    *,
    detail_code: str | None = None,
    line: int | None = None,
    column: int | None = None,
) -> ParseFailureV1:
    return _issue_result(
        ParseFailureV1,
        code=code, message=message, path=path, detail_code=detail_code, line=line, column=column
    )


def _hash_parts(*parts: object) -> str:
    canonical = json.dumps(
        parts, ensure_ascii=False, sort_keys=True, allow_nan=False, separators=(",", ":")
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _safe_path(path: str) -> str | None:
    try:
        path.encode("utf-8")
    except UnicodeEncodeError:
        return None
    if not path or len(path) > 1024 or path != unicodedata.normalize("NFC", path):
        return None
    if "\\" in path or path.startswith("/") or path.endswith("/") or "//" in path:
        return None
    if any(ord(character) < 32 or ord(character) == 127 for character in path):
        return None
    if ":" in path or unquote(path) != path:
        return None
    parts = path.split("/")
    if len(parts) > MAX_PATH_DEPTH:
        return None
    for part in parts:
        if (
            part in ("", ".", "..")
            or part.rstrip(" .") != part
            or _DEVICE.fullmatch(part)
            or _SHORT_NAME.search(part)
        ):
            return None
    return path


def _decoded_destination(value: str) -> str | None:
    if not value or len(value) > 2048:
        return None
    decoded = value
    for _ in range(4):
        next_value = html.unescape(decoded)
        if next_value == decoded:
            break
        decoded = next_value
    if html.unescape(decoded) != decoded:
        return None
    decoded = _BACKSLASH_ESCAPE.sub(r"\1", decoded)
    for _ in range(4):
        next_value = unquote(decoded)
        if next_value == decoded:
            break
        decoded = next_value
    if re.search(r"%[0-9a-fA-F]{2}", decoded):
        return None
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in decoded) or "\\" in decoded:
        return None
    try:
        decoded.encode("utf-8")
    except UnicodeEncodeError:
        return None
    return decoded


def _link_destination(value: str, source_path: str) -> tuple[str, str] | None:
    decoded = _decoded_destination(value)
    if decoded is None or decoded.startswith(("/", "\\")):
        return None
    try:
        parsed = urlsplit(decoded)
    except ValueError:
        return None
    if parsed.scheme:
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            return None
        return ("external", parsed.geturl())
    if parsed.netloc or ":" in decoded:
        return None
    relative = parsed.path or source_path.rpartition("/")[2]
    if any(part == ".." for part in relative.split("/")):
        return None
    resolved = posixpath.normpath(posixpath.join(posixpath.dirname(source_path), relative))
    if _safe_path(resolved) is None:
        return None
    return ("vault", resolved)


class _InspectingMarkdownIt(MarkdownIt):
    """Expose parsed destinations so this kernel can apply its stricter allowlist."""

    def validateLink(self, url: str) -> bool:  # noqa: N802
        # markdown-it otherwise converts dangerous links into plain text before
        # the security walk can inspect them. The walk rejects them below.
        return True


def _inspect_wiki(state: StateInline, silent: bool) -> bool:
    """Record raw wiki targets before CommonMark splits formatted aliases."""

    if silent or not state.src.startswith("[[", state.pos):
        return False
    cache: dict[str, dict[int, str]] = state.env.setdefault("_wiki_match_cache", {})
    if state.src not in cache:
        cache[state.src] = {
            match.start(): match.group(1) for match in _WIKI_LINK.finditer(state.src)
        }
    state.env.setdefault("_wiki_targets", []).append(cache[state.src].get(state.pos))
    return False


def _blank_span(buffer: list[str], start: int, end: int) -> None:
    for index in range(start, end):
        if buffer[index] not in ("\r", "\n"):
            buffer[index] = " "


def _parse_commonmark(
    text: str, body_start: int, source_path: str
) -> tuple[list[Token], tuple[str, ...], str] | ParseFailureV1:
    """Validate CommonMark tokens and retain original source offsets."""

    parser = _InspectingMarkdownIt(
        "commonmark",
        {
            "html": True,
            "linkify": False,
            "inline_definitions": True,
            "maxNesting": MAX_MARKDOWN_NESTING,
        },
    )
    parser.inline.ruler.before("link", "inspect_wiki", _inspect_wiki)
    body = text[body_start:]
    environment: dict[str, Any] = {}
    tokens = parser.parse(body, environment)
    external: list[str] = []
    external_seen: set[str] = set()
    for raw_target in environment.get("_wiki_targets", ()):
        if raw_target is None:
            return _failure("invalid_link", "Markdown contains an unsafe link", source_path)
        wiki_target = raw_target.split("|", 1)[0]
        target = _link_destination(wiki_target, source_path)
        if target is None:
            return _failure("invalid_link", "Markdown contains an unsafe link", source_path)
        if target[0] == "external" and target[1] not in external_seen:
            external_seen.add(target[1])
            external.append(target[1])
    line_offsets = [body_start]
    for line in body.splitlines(keepends=True):
        line_offsets.append(line_offsets[-1] + len(line))

    depth = 0
    for token in tokens:
        depth += token.nesting
        if depth >= MAX_MARKDOWN_NESTING:
            return _failure(
                "resource_limit_exceeded", "Markdown nesting limit exceeded", source_path
            )
    if depth:
        return _failure("invalid_source", "Markdown token nesting is unbalanced", source_path)

    count = 0
    sanitized = list(text)
    html_cursors: dict[int, int] = {}
    stack: list[tuple[Token, Token | None]] = [(token, None) for token in reversed(tokens)]
    while stack:
        token, parent = stack.pop()
        count += 1
        if count > MAX_MARKDOWN_AST_TOKENS:
            return _failure("resource_limit_exceeded", "Markdown token limit exceeded", source_path)
        if token.children:
            stack.extend((child, token) for child in reversed(token.children))

        destination: str | None = None
        if token.type == "definition":
            destination = token.meta.get("url")
        elif token.type in ("link_open", "image"):
            value = token.attrGet("href" if token.type == "link_open" else "src")
            if not isinstance(value, str):
                return _failure("invalid_link", "Markdown contains an unsafe link", source_path)
            destination = value
        if destination is not None:
            target = _link_destination(destination, source_path)
            if target is None:
                return _failure("invalid_link", "Markdown contains an unsafe link", source_path)
            if target[0] == "external" and target[1] not in external_seen:
                external_seen.add(target[1])
                external.append(target[1])

        if token.type == "html_block":
            return _failure("unsafe_html", "active HTML is not allowed", source_path)
        if token.type == "html_inline":
            markup = token.content
            if _DANGEROUS_PREFIX.search(markup) or re.search(
                r"\bon[a-z]+\s*=|javascript\s*:", markup, re.I
            ):
                return _failure("unsafe_html", "active HTML is not allowed", source_path)
            if parent is None or parent.map is None:
                return _failure("unsafe_html", "HTML source span is unavailable", source_path)
            if any(
                child.type == "code_inline" and markup in child.content
                for child in parent.children or []
            ):
                return _failure("unsafe_html", "ambiguous HTML source span", source_path)
            start_line, end_line = parent.map
            start, end = line_offsets[start_line], line_offsets[end_line]
            cursor = html_cursors.get(id(parent), start)
            while True:
                position = text.find(markup, cursor, end)
                if position < 0:
                    return _failure("unsafe_html", "HTML source span is unavailable", source_path)
                cursor = position + len(markup)
                if position == 0 or text[position - 1] != "\\":
                    _blank_span(sanitized, position, cursor)
                    html_cursors[id(parent)] = cursor
                    break
    return tokens, tuple(external), "".join(sanitized)


def _collision_detail(envelope: SourceEnvelopeV1, path: str) -> str | None:
    canonical = unicodedata.normalize("NFC", path).casefold()
    batch = (path, *envelope.batch_paths)
    seen: dict[str, str] = {}
    for candidate in batch:
        if _safe_path(candidate) is None:
            return "INVALID_BATCH_PATH"
        identity = unicodedata.normalize("NFC", candidate).casefold()
        prior = seen.setdefault(identity, candidate)
        if prior != candidate:
            return "CASE_COLLISION"
    if envelope.vault_path_index is not None:
        index_seen: dict[str, str] = {}
        for candidate in envelope.vault_path_index.paths:
            if _safe_path(candidate) is None:
                return "INVALID_INDEX_PATH"
            identity = unicodedata.normalize("NFC", candidate).casefold()
            prior = index_seen.setdefault(identity, candidate)
            if prior != candidate:
                return "CASE_COLLISION"
            if (
                identity == canonical and candidate != path
            ):
                return "CASE_COLLISION"
    return None


def _frontmatter(text: str) -> tuple[Mapping[str, Any], int]:
    if not text.startswith("---\n") and not text.startswith("---\r\n"):
        return {}, 0
    lines = text.splitlines(keepends=True)
    end = len(lines[0])
    byte_count = len(lines[0].encode("utf-8"))
    closing_found = False
    for line in lines[1:]:
        end += len(line)
        byte_count += len(line.encode("utf-8"))
        if byte_count > MAX_FRONTMATTER_BYTES:
            raise ValueError("frontmatter exceeds 64 KiB")
        if line.rstrip("\r\n") == "---":
            closing_found = True
            break
    if not closing_found:
        raise ValueError("frontmatter is not closed")
    document = text[len(lines[0]) : end - len(line)]
    depth = 0
    documents = 0
    for events, event in enumerate(yaml.parse(document), start=1):
        if events > MAX_FRONTMATTER_EVENTS:
            raise ValueError("frontmatter has too many nodes")
        if isinstance(event, AliasEvent):
            raise ValueError("YAML aliases are not allowed")
        if isinstance(event, DocumentStartEvent):
            documents += 1
            if documents > 1:
                raise ValueError("multiple frontmatter documents are not allowed")
        if isinstance(event, CollectionStartEvent):
            depth += 1
            if depth > MAX_FRONTMATTER_DEPTH:
                raise ValueError("frontmatter is too deeply nested")
        elif isinstance(event, CollectionEndEvent):
            depth -= 1
    parsed = yaml.load(document, Loader=_UniqueSafeLoader)
    if parsed is None:
        return {}, end
    if not isinstance(parsed, dict) or any(not isinstance(key, str) for key in parsed):
        raise ValueError("frontmatter must be a string-keyed mapping")
    return parsed, end


def _byte_offsets(text: str, positions: set[int]) -> dict[int, int]:
    result: dict[int, int] = {}
    previous_char = 0
    previous_byte = 0
    for position in sorted(positions):
        previous_byte += len(text[previous_char:position].encode("utf-8"))
        result[position] = previous_byte
        previous_char = position
    return result


def parse_markdown(
    envelope: SourceEnvelopeV1,
    *,
    tag_rules: TagRulesV1 | None = None,
    chunk_spec: ChunkSpecV1 | None = None,
) -> ParseResultV1 | ParseFailureV1:
    """Parse a bounded Markdown payload without I/O, clocks, model calls or execution."""

    rules = tag_rules if tag_rules is not None else TagRulesV1()
    spec = chunk_spec if chunk_spec is not None else ChunkSpecV1()
    path = _safe_path(envelope.path)
    if path is None:
        return _failure("invalid_path", "path is not canonical and vault-relative", "")
    collision = _collision_detail(envelope, path)
    if collision is not None:
        return _failure("invalid_path", "vault path identity is invalid", "", detail_code=collision)
    if envelope.content_type.lower() not in ("md", "markdown", "text/markdown"):
        return _failure("unsupported_format", "only Markdown is supported", path)
    if spec.tokenizer_version != "whitespace-v1":
        return _failure("unsupported_tokenizer", "tokenizer version is not installed", path)
    try:
        source = (
            envelope.source_bytes
            if envelope.source_bytes is not None
            else envelope.source_text.encode("utf-8")  # type: ignore[union-attr]
        )
    except UnicodeEncodeError:
        return _failure("invalid_source", "source text is not valid UTF-8", path)
    if len(source) > MAX_MARKDOWN_BYTES:
        return _failure("payload_too_large", "Markdown exceeds parser work budget", path)
    try:
        text = source.decode("utf-8")
    except UnicodeDecodeError:
        return _failure("invalid_source", "source bytes are not valid UTF-8", path)
    if "\x00" in text:
        return _failure("invalid_source", "NUL is not valid Markdown text", path)
    if text.count("\n") + text.count("\r") > MAX_LINES:
        return _failure("resource_limit_exceeded", "document line limit exceeded", path)
    try:
        frontmatter, body_start = _frontmatter(text)
    except (ValueError, yaml.YAMLError) as exc:
        mark = getattr(exc, "problem_mark", None)
        return _failure(
            "invalid_frontmatter",
            "frontmatter is invalid",
            "",
            line=mark.line + 2 if mark is not None else None,
            column=mark.column + 1 if mark is not None else None,
        )
    commonmark = _parse_commonmark(text, body_start, path)
    if isinstance(commonmark, ParseFailureV1):
        return commonmark
    markdown_tokens, external_references, sanitized = commonmark
    try:
        tags = resolve_tags(frontmatter, envelope.event_tags, path, rules)
    except TagRuleError as exc:
        return _failure(exc.code, str(exc), path)
    except (SealError, ParserModelError):
        return _failure("invalid_tag", "event tags are invalid", path)
    source_hash = hashlib.sha256(source).hexdigest()
    dedupe_key = _hash_parts(envelope.org_id, envelope.vault_id, path, source_hash)
    try:
        windows = chunk_markdown(sanitized, body_start, spec, markdown_tokens)
    except ResourceLimitError:
        return _failure("resource_limit_exceeded", "document resource limit exceeded", path)
    output_bytes = sum(len(window.text.encode("utf-8")) for window in windows)
    if output_bytes > 2 * len(source) + 1024 * len(windows) + 4096:
        return _failure("resource_limit_exceeded", "document output limit exceeded", path)
    offsets = _byte_offsets(
        text, {p for window in windows for p in (window.char_start, window.char_end)}
    )
    chunks: list[ParsedChunkV1] = []
    for sequence, window in enumerate(windows):
        content_for_identity = (
            text[window.char_start : window.char_end] if window.synthetic_fence else window.text
        )
        normalized = unicodedata.normalize(
            "NFC", content_for_identity.replace("\r\n", "\n").replace("\r", "\n")
        )
        chunk_hash = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
        chunk_id = _hash_parts(
            envelope.version_id,
            sequence,
            window.char_start,
            window.char_end,
            normalized,
        )
        chunks.append(
            ParsedChunkV1(
                chunk_id=chunk_id,
                chunk_hash=chunk_hash,
                sequence=sequence,
                text=window.text,
                continuation_part=window.continuation_part,
                continuation_total=window.continuation_total,
                synthetic_fence=window.synthetic_fence,
                token_count=window.token_count,
                char_start=window.char_start,
                char_end=window.char_end,
                byte_start=offsets[window.char_start],
                byte_end=offsets[window.char_end],
                heading=window.heading,
                heading_path=window.heading_path,
                org_id=envelope.org_id,
                vault_id=envelope.vault_id,
                doc_id=envelope.doc_id,
                version_id=envelope.version_id,
                path=path,
                source_hash=source_hash,
                parser_version=envelope.parser_version,
                chunker_version=envelope.chunker_version,
                tokenizer_version=spec.tokenizer_version,
                source_trust_label="untrusted_vault",
                created_at_ns=envelope.created_at_ns,
                tags=tags,
            )
        )
    draft = ParseResultV1(
        org_id=envelope.org_id,
        vault_id=envelope.vault_id,
        doc_id=envelope.doc_id,
        version_id=envelope.version_id,
        path=path,
        source_hash=source_hash,
        dedupe_key=dedupe_key,
        parser_version=envelope.parser_version,
        chunker_version=envelope.chunker_version,
        created_at_ns=envelope.created_at_ns,
        tags=tags,
        chunks=tuple(chunks),
        external_references=external_references,
        collision_check="PASSED" if envelope.vault_path_index is not None else "NOT_PERFORMED",
    )
    if len(draft.model_dump_json().encode("utf-8")) > (
        2 * len(source) + 1024 * len(chunks) + 4096
    ):
        return _failure("resource_limit_exceeded", "document output limit exceeded", path)
    try:
        result = _issue_model(draft)
    except SealError as error:
        code = "resource_limit_exceeded" if error.code == "SEAL_DIGEST_LIMIT" else "invalid_source"
        return _failure(code, "document cannot be sealed", path)
    return _require_result(result)
