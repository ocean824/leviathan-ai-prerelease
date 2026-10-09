"""Contract-level tests for the pure source parser."""

import hashlib
import pickle
import warnings
from copy import copy, deepcopy
from cProfile import Profile

import pytest
from pydantic import BaseModel, TypeAdapter

from leviathan_core.knowledge_sync import (
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
    parse_markdown,
)
from leviathan_core.knowledge_sync.parser_models import (
    _ISSUER,
    MAX_PARSER_CHUNK_SEAL_NODES,
    MAX_PARSER_CHUNKS,
    MAX_PARSER_RESULT_SEAL_NODES,
    MAX_PARSER_SEAL_NODES,
    MAX_PARSER_SOURCE_BYTES,
)
from leviathan_core.knowledge_sync.tag_rules import resolve_tags
from leviathan_core.seal import MAX_DIGEST_NODES_CEILING, SealError, digest, require, verify


def _source(source_text: str, **changes: object) -> SourceEnvelopeV1:
    values: dict[str, object] = {
        "org_id": "org-a",
        "vault_id": "vault-a",
        "doc_id": "doc-a",
        "version_id": "version-a",
        "path": "research/methods/note.md",
        "content_type": "md",
        "source_text": source_text,
        "parser_version": "markdown-v1",
        "chunker_version": "block-v1",
        "created_at_ns": 1_800_000_000_000_000_000,
    }
    values.update(changes)
    return SourceEnvelopeV1.model_validate(values)


def test_frontmatter_priority_unresolved_and_tenant_allowlist() -> None:
    document = "---\nmethodology: [Smart Money]\nasset: BTC\n---\n# Heading\nQuoted content."
    rules = TagRulesV1(
        methodology_allowlist=("smart-money",),
        asset_allowlist=("btc",),
        folder_rules=(
            FolderTagRuleV1(
                prefix="research/methods",
                tags=TagSetV1(methodology=("folder-method",), regime=("risk-on",)),
            ),
        ),
    )
    parsed = parse_markdown(
        _source(document, event_tags=TagSetV1(methodology=("event-method",))),
        tag_rules=rules,
    )
    assert isinstance(parsed, ParseResultV1)
    assert parsed.tags.methodology == ("smart-money",)
    assert parsed.tags.methodology_source == "frontmatter"
    assert parsed.tags.asset == ("btc",)
    assert parsed.tags.regime == ("risk-on",)
    assert parsed.tags.regime_source == "folder"
    assert parsed.tags.unresolved_required == ()
    assert parsed.chunks[0].tags == parsed.tags


def test_missing_taxonomy_is_explicit_and_disallowed_value_fails_atomically() -> None:
    unresolved = parse_markdown(_source("# A\nText"))
    assert isinstance(unresolved, ParseResultV1)
    assert unresolved.tags.unresolved_required == ("methodology", "asset", "regime")
    denied = parse_markdown(
        _source("---\nasset: ETH\n---\n# A\nText"),
        tag_rules=TagRulesV1(asset_allowlist=("btc",)),
    )
    assert isinstance(denied, ParseFailureV1)
    assert denied.code == "tag_not_allowed"


@pytest.mark.parametrize(
    ("path", "body", "code"),
    [
        ("../private.md", "# Safe", "invalid_path"),
        ("research/%252e%252e/private.md", "# Safe", "invalid_path"),
        ("research/note.md", "[read](../private.md)", "invalid_link"),
        ("research/note.md", "[[..\\private.md]]", "invalid_link"),
        ("research/note.md", "[run](javascript:alert)", "invalid_link"),
    ],
)
def test_unsafe_paths_and_links_fail(path: str, body: str, code: str) -> None:
    parsed = parse_markdown(_source(body, path=path))
    assert isinstance(parsed, ParseFailureV1)
    assert parsed.code == code


def test_html_never_passes_through_and_offsets_refer_to_original_utf8() -> None:
    text = "# Café\nhello <b>world</b> done"
    parsed = parse_markdown(_source(text))
    assert isinstance(parsed, ParseResultV1)
    assert parsed.source_hash == hashlib.sha256(text.encode()).hexdigest()
    content = " ".join(chunk.text for chunk in parsed.chunks)
    assert "<b>" not in content
    assert "world" in content
    assert parsed.chunks[0].byte_end > parsed.chunks[0].char_end
    assert parsed.chunks[0].source_trust_label == "untrusted_vault"
    active = parse_markdown(_source("# Heading\n<script>steal()</script>"))
    assert isinstance(active, ParseFailureV1)
    assert active.code == "unsafe_html"


def test_malicious_frontmatter_rejected_without_execution() -> None:
    unsafe = "---\nasset: !!python/object/apply:os.system ['echo unsafe']\n---\n# Text"
    parsed = parse_markdown(_source(unsafe))
    assert isinstance(parsed, ParseFailureV1)
    assert parsed.code == "invalid_frontmatter"
    alias = "---\nasset: &a BTC\nregime: *a\n---\n# Text"
    parsed_alias = parse_markdown(_source(alias))
    assert isinstance(parsed_alias, ParseFailureV1)
    assert parsed_alias.code == "invalid_frontmatter"


def test_frontmatter_byte_cap_and_unclosed_script_are_fail_closed() -> None:
    oversized_unicode = "---\nauthor: " + "é" * 33_000 + "\n---\n# Body"
    large = parse_markdown(_source(oversized_unicode))
    assert isinstance(large, ParseFailureV1)
    assert large.code == "invalid_frontmatter"
    script = parse_markdown(_source("# Body\n<script"))
    assert isinstance(script, ParseFailureV1)
    assert script.code == "unsafe_html"


def test_size_boundary_and_deterministic_lineage() -> None:
    source = _source("# Head\nText")
    first = parse_markdown(source)
    second = parse_markdown(source)
    assert isinstance(first, ParseResultV1)
    assert first == second
    changed = parse_markdown(_source("# Head\nTexts"))
    assert isinstance(changed, ParseResultV1)
    assert first.dedupe_key != changed.dedupe_key
    assert first.chunks[0].chunk_id != changed.chunks[0].chunk_id
    at_limit = parse_markdown(_source("a" * (128 * 1024)))
    assert isinstance(at_limit, ParseResultV1)
    over_limit = parse_markdown(_source("a" * (128 * 1024 + 1)))
    assert isinstance(over_limit, ParseFailureV1)
    assert over_limit.code == "payload_too_large"


def test_shared_seal_node_budget_covers_declared_parser_caps() -> None:
    assert MAX_PARSER_SEAL_NODES == (
        MAX_PARSER_CHUNKS * MAX_PARSER_CHUNK_SEAL_NODES
        + MAX_PARSER_RESULT_SEAL_NODES
        + MAX_PARSER_SOURCE_BYTES
    )
    assert MAX_PARSER_SEAL_NODES == 880_787
    assert MAX_PARSER_SEAL_NODES <= MAX_DIGEST_NODES_CEILING
    assert _ISSUER.max_digest_nodes == MAX_PARSER_SEAL_NODES

    result = parse_markdown(
        _source(" ".join(f"token{i}" for i in range(4_096))),
        chunk_spec=ChunkSpecV1(target_tokens=64, overlap_tokens=31),
    )
    assert isinstance(result, ParseResultV1)
    assert require(result, "knowledge.parser.v1") is result
    assert len(digest(result, max_nodes=MAX_PARSER_SEAL_NODES)) == 64

    # These shape probes make the numeric per-chunk and root bounds fail CI
    # if a future model field changes the declared issuer budget.
    small = parse_markdown(_source("# heading\nbody"))
    assert isinstance(small, ParseResultV1)
    labels = tuple(f"tag{i}" for i in range(32))
    max_tags = TagSetV1(
        methodology=labels,
        asset=labels,
        regime=labels,
        unresolved_required=(),
        methodology_source="frontmatter",
        asset_source="frontmatter",
        regime_source="frontmatter",
    )
    chunk_data = small.chunks[0].model_dump(mode="python")
    chunk_data["tags"] = max_tags
    chunk_data["heading_path"] = tuple(f"H{i}" for i in range(6))
    max_chunk = ParsedChunkV1.model_validate(chunk_data)
    assert len(digest(max_chunk, max_nodes=MAX_PARSER_CHUNK_SEAL_NODES)) == 64
    with pytest.raises(SealError) as chunk_over_budget:
        digest(max_chunk, max_nodes=MAX_PARSER_CHUNK_SEAL_NODES - 1)
    assert chunk_over_budget.value.code == "SEAL_DIGEST_LIMIT"

    root_data = small.model_dump(mode="python")
    root_data["chunks"] = ()
    root_data["tags"] = max_tags
    root_data["external_references"] = ()
    max_root = ParseResultV1.model_validate(root_data)
    assert len(digest(max_root, max_nodes=MAX_PARSER_RESULT_SEAL_NODES)) == 64
    with pytest.raises(SealError) as root_over_budget:
        digest(max_root, max_nodes=MAX_PARSER_RESULT_SEAL_NODES - 1)
    assert root_over_budget.value.code == "SEAL_DIGEST_LIMIT"


def test_block_aware_chunking_records_configured_tokenizer() -> None:
    text = (
        "# H\n"
        + " ".join(f"w{i}" for i in range(100))
        + "\n\n```py\na = 1\nb = 2\n```\n\n> quoted line\n> another line"
    )
    result = parse_markdown(
        _source(text), chunk_spec=ChunkSpecV1(target_tokens=64, overlap_tokens=10)
    )
    assert isinstance(result, ParseResultV1)
    assert len(result.chunks) >= 2
    assert all(chunk.token_count <= 64 for chunk in result.chunks)
    assert all(chunk.tokenizer_version == "whitespace-v1" for chunk in result.chunks)
    assert "a = 1\nb = 2" in " ".join(chunk.text for chunk in result.chunks)


@pytest.mark.parametrize(
    "body",
    [
        "[x](javascript&#58;alert(1))",
        "[x](javascript&amp;#58;alert(1))",
        "[x](&#46;&#46;/private.md)",
        "[x](safe(foo)/../private.md)",
        "[x]:\n javascript:alert(1)\n\n[x]",
        "[x](http://example.com)",
        "[x](file:///private.md)",
        "[x](//example.com/a)",
    ],
)
def test_decoded_active_links_fail_closed(body: str) -> None:
    result = parse_markdown(_source(body))
    assert isinstance(result, ParseFailureV1)
    assert result.code == "invalid_link"


def test_commonmark_code_span_with_backslash_is_inert() -> None:
    body = "`[x](javascript:alert)\\`"
    result = parse_markdown(_source(body))
    assert isinstance(result, ParseResultV1)
    assert body in result.chunks[0].text


@pytest.mark.parametrize(
    "body",
    [
        '[Foo\n bar]: javascript:alert(1) "title"\n\n[Baz][Foo bar]',
        "[x]\n\n> [x]: javascript:alert(1)\n",
        r"[foo\]]: javascript:alert(1)" + "\n\n" + r"[foo\]]",
        "- [x][item]\n\n  [item]: javascript:alert(1)\n",
    ],
)
def test_commonmark_reference_definitions_are_validated(body: str) -> None:
    result = parse_markdown(_source(body))
    assert isinstance(result, ParseFailureV1)
    assert result.code == "invalid_link"


@pytest.mark.parametrize(
    "body",
    ["[[../private.md|*alias*]]", "[[javascript:alert(1)|*alias*]]"],
)
def test_raw_wiki_target_is_validated_before_alias_formatting(body: str) -> None:
    result = parse_markdown(_source(body))
    assert isinstance(result, ParseFailureV1)
    assert result.code == "invalid_link"


def test_wiki_syntax_inside_code_span_is_inert() -> None:
    result = parse_markdown(_source("`[[../private.md|*alias*]]`"))
    assert isinstance(result, ParseResultV1)


@pytest.mark.parametrize(
    ("body", "code"),
    [
        ("- item\n\n    [x](javascript:alert(1))\n", "invalid_link"),
        ("- item\n\n    <script>alert(1)</script>\n", "unsafe_html"),
    ],
)
def test_list_continuation_is_active_markdown(body: str, code: str) -> None:
    result = parse_markdown(_source(body))
    assert isinstance(result, ParseFailureV1)
    assert result.code == code


def test_backtick_span_parser_has_linear_scan_steps() -> None:
    def scan_steps(size: int) -> int:
        body = "a`a`" * (size // 4)
        profile = Profile()
        profile.enable()
        result = parse_markdown(_source(body))
        profile.disable()
        assert isinstance(result, ParseResultV1)
        return sum(
            entry.callcount
            for entry in profile.getstats()
            if hasattr(entry.code, "co_filename")
            and "markdown_it" in entry.code.co_filename.replace("\\", "/")
        )

    small, middle, large = (scan_steps(size) for size in (32_768, 65_536, 131_072))
    assert 0 < small < middle < large
    assert middle < 2.2 * small
    assert large < 2.2 * middle
    assert large < 4.5 * small


def test_parser_work_cap_precedes_frontmatter_and_tokenization() -> None:
    invalid_yaml = "---\nasset: [\n---\n"
    body = invalid_yaml + "x" * (128 * 1024 + 1 - len(invalid_yaml))
    result = parse_markdown(_source(body))
    assert isinstance(result, ParseFailureV1)
    assert result.code == "payload_too_large"


def test_commonmark_nesting_cap_is_typed_and_fail_closed() -> None:
    result = parse_markdown(_source("> " * 32 + "[x](javascript:alert(1))"))
    assert isinstance(result, ParseFailureV1)
    assert result.code == "resource_limit_exceeded"


@pytest.mark.parametrize("marker", ["```", "~~~"])
def test_nested_oversize_fence_is_refenced_with_source_spans(marker: str) -> None:
    body = f"- item\n\n  {marker}python\n  " + "word " * 100 + f"\n  {marker}\n\n- after\n"
    result = parse_markdown(
        _source(body), chunk_spec=ChunkSpecV1(target_tokens=64, overlap_tokens=20)
    )
    assert isinstance(result, ParseResultV1)
    parts = [chunk for chunk in result.chunks if chunk.synthetic_fence]
    assert len(parts) == 2
    for part_number, chunk in enumerate(parts, start=1):
        original = body[chunk.char_start : chunk.char_end]
        fence_open = f"{marker}python\n"
        fence_close = "\n" + marker
        assert chunk.text == fence_open + original + fence_close
        assert chunk.text.count(marker) == 2
        assert chunk.continuation_part == part_number
        assert chunk.continuation_total == len(parts)
        assert chunk.chunk_hash == hashlib.sha256(original.encode()).hexdigest()
        assert chunk.token_count <= 64
    assert all(chunk.text.count(marker) in (0, 2) for chunk in result.chunks)
    with pytest.raises(ParserModelError):
        parts[0].model_copy(update={"continuation_part": True})
    with pytest.raises(ParserModelError):
        parts[0].model_copy(update={"continuation_part": 3})
    with pytest.raises(ParserModelError):
        parts[0].model_copy(update={"synthetic_fence": False})


def test_parser_models_reject_copy_pickle_and_unchecked_construction() -> None:
    envelope = _source("# Note")
    parsed = parse_markdown(envelope)
    assert isinstance(parsed, ParseResultV1)
    for model in (envelope, ChunkSpecV1(), parsed, parsed.chunks[0], parsed.tags):
        with pytest.raises(SealError, match="SEAL_FORBIDDEN_OPERATION"):
            copy(model)
        with pytest.raises(SealError, match="SEAL_FORBIDDEN_OPERATION"):
            deepcopy(model)
        with pytest.raises(SealError, match="SEAL_FORBIDDEN_OPERATION"):
            pickle.dumps(model)
        with pytest.raises(SealError, match="SEAL_FORBIDDEN_OPERATION"):
            type(model).model_construct(**model.model_dump())
    with pytest.raises(ParserModelError):
        envelope.model_copy(update={"created_at_ns": True})
    with pytest.raises(ParserModelError):
        parsed.chunks[0].model_copy(update={"source_trust_label": "trusted_instruction"})
    assert envelope.model_copy(update={"version_id": "v2"}).version_id == "v2"


def test_boolean_integer_fields_are_rejected() -> None:
    with pytest.raises(ParserModelError):
        _source("body", created_at_ns=True)
    with pytest.raises(ParserModelError):
        ChunkSpecV1(target_tokens=True)
    with pytest.raises(ParserModelError):
        ChunkSpecV1(overlap_tokens=False)


def test_public_model_errors_are_typed_and_content_free() -> None:
    canary = "SYNTHETIC_PRIVATE_CANARY"
    envelope = _source("body")
    operations = (
        lambda: _source("body", created_at_ns=canary),
        lambda: envelope.model_copy(update={"created_at_ns": canary}),
        lambda: SourceEnvelopeV1.model_validate(
            {**envelope.model_dump(), "created_at_ns": canary}
        ),
        lambda: SourceEnvelopeV1.model_validate_json(
            '{"created_at_ns":"SYNTHETIC_PRIVATE_CANARY"}'
        ),
        lambda: SourceEnvelopeV1.model_validate_json("{SYNTHETIC_PRIVATE_CANARY"),
        lambda: SourceEnvelopeV1.model_validate_strings({"created_at_ns": canary}),
        lambda: TypeAdapter(SourceEnvelopeV1).validate_python(
            {**envelope.model_dump(), "created_at_ns": canary}
        ),
    )
    for operation in operations:
        with pytest.raises(ParserModelError) as caught:
            operation()
        error = caught.value
        assert error.code == "MODEL_VALIDATION"
        assert error.__context__ is None
        for view in (str(error), repr(error.args), repr(error.errors()), error.json()):
            assert canary not in view
        assert all(set(item) == {"code", "loc", "type"} for item in error.errors())


def test_frozen_models_and_shared_issuer_contract() -> None:
    envelope = _source("body")
    result = parse_markdown(envelope)
    failure = parse_markdown(_source("[x](javascript:alert(1))"))
    assert isinstance(result, ParseResultV1)
    assert isinstance(failure, ParseFailureV1)
    canary = "SYNTHETIC_PRIVATE_CANARY"
    for model, field in ((envelope, "path"), (result, "path"), (result.chunks[0], "text")):
        for operation in (
            lambda model=model, field=field: setattr(model, field, canary),
            lambda model=model, field=field: delattr(model, field),
        ):
            with pytest.raises(SealError) as caught:
                operation()
            assert caught.value.code == "SEAL_FORBIDDEN_OPERATION"
            assert canary not in str(caught.value)
    for issued in (result, result.chunks[0], result.tags, result.chunks[0].tags, failure):
        assert verify(issued, "knowledge.parser.v1")
        assert require(issued, "knowledge.parser.v1") is issued
        before = issued.model_dump()
        with pytest.raises(SealError, match="SEAL_FORBIDDEN_OPERATION"):
            BaseModel.__init__(issued, **before)
        assert issued.model_dump() == before
        with pytest.raises(SealError, match="SEAL_FORBIDDEN_OPERATION"):
            issued.__setstate__({"__dict__": before})
        assert issued.model_dump() == before
        validated = type(issued).model_validate(issued)
        assert validated is not issued
        with pytest.raises(SealError, match="SEAL_NOT_ISSUED"):
            require(validated, "knowledge.parser.v1")
        copied = issued.model_copy()
        with pytest.raises(SealError, match="SEAL_NOT_ISSUED"):
            require(copied, "knowledge.parser.v1")
        assert issued.model_dump() == before


def test_event_tags_are_revalidated_data_and_issued_afresh() -> None:
    first = parse_markdown(_source("---\nasset: btc\n---\nbody"))
    assert isinstance(first, ParseResultV1)
    issued_tags = first.tags

    fresh_input = resolve_tags({}, issued_tags, "research/methods/note.md", TagRulesV1())
    assert fresh_input.asset == ("btc",)
    assert fresh_input is not issued_tags
    with pytest.raises(SealError, match="SEAL_NOT_ISSUED"):
        require(fresh_input, "knowledge.parser.v1")

    second = parse_markdown(_source("body", event_tags=issued_tags))
    assert isinstance(second, ParseResultV1)
    assert second.tags.asset == ("btc",)
    assert second.tags is not issued_tags
    assert require(second.tags, "knowledge.parser.v1") is second.tags

    raw_tags = BaseModel.__dict__["__dict__"].__get__(issued_tags, type(issued_tags))
    raw_tags["asset"] = ("forged",)
    with pytest.raises(SealError, match="SEAL_TAMPERED"):
        resolve_tags({}, issued_tags, "research/methods/note.md", TagRulesV1())


def test_issued_results_and_nested_tags_detect_low_level_tampering() -> None:
    canary = "SYNTHETIC_PRIVATE_CANARY"

    def assert_tampered(model: ParseResultV1 | ParsedChunkV1 | TagSetV1) -> None:
        for operation in (
            lambda: require(model, "knowledge.parser.v1"),
            lambda: model.model_dump(),
            lambda: model.model_dump_json(),
            lambda: BaseModel.model_dump(model),
            lambda: type(model).model_validate(model),
        ):
            with pytest.raises(SealError) as caught:
                operation()
            assert caught.value.code == "SEAL_TAMPERED"
            assert canary not in str(caught.value)

    result = parse_markdown(_source("# Note\nBody"))
    assert isinstance(result, ParseResultV1)
    raw = BaseModel.__dict__["__dict__"].__get__(result, type(result))
    raw["collision_check"] = "PASSED"
    assert_tampered(result)

    result = parse_markdown(_source("# Note\nBody"))
    assert isinstance(result, ParseResultV1)
    chunk = result.chunks[0]
    raw_chunk = BaseModel.__dict__["__dict__"].__get__(chunk, type(chunk))
    raw_chunk["text"] = canary
    assert_tampered(chunk)
    assert_tampered(result)

    result = parse_markdown(_source("# Note\nBody"))
    assert isinstance(result, ParseResultV1)
    tags = result.tags
    assert verify(tags, "knowledge.parser.v1")
    tags.__dict__["asset"] = (canary,)
    assert_tampered(tags)
    assert_tampered(result)


def test_seal_preserves_runtime_container_types_and_field_set() -> None:
    result = parse_markdown(_source("# Note\nBody"))
    assert isinstance(result, ParseResultV1)
    raw = BaseModel.__dict__["__dict__"].__get__(result, type(result))
    raw["chunks"] = list(raw["chunks"])
    with pytest.raises(SealError, match="SEAL_TAMPERED"):
        result.model_dump_json()

    result = parse_markdown(_source("# Note\nBody"))
    assert isinstance(result, ParseResultV1)
    tags = result.tags
    tags.__dict__["asset"] = list(tags.asset)
    with pytest.raises(SealError, match="SEAL_TAMPERED"):
        tags.model_dump()
    with pytest.raises(SealError, match="SEAL_TAMPERED"):
        result.model_dump()

    result = parse_markdown(_source("# Note\nBody"))
    assert isinstance(result, ParseResultV1)
    result.__pydantic_fields_set__.clear()
    for operation in (
        lambda: result.model_dump(exclude_unset=True),
        lambda: result.model_dump_json(exclude_unset=True),
    ):
        with pytest.raises(SealError, match="SEAL_TAMPERED"):
            operation()

    result = parse_markdown(_source("# Note\nBody"))
    assert isinstance(result, ParseResultV1)
    tags = result.tags
    tags.__pydantic_fields_set__.clear()
    with pytest.raises(SealError, match="SEAL_TAMPERED"):
        tags.model_dump(exclude_unset=True)
    with pytest.raises(SealError, match="SEAL_TAMPERED"):
        result.model_dump(exclude_unset=True)


def test_nested_tamper_emits_no_caller_content_in_warnings() -> None:
    result = parse_markdown(_source("# Note\nBody"))
    assert isinstance(result, ParseResultV1)
    canary = "SYNTHETIC_PRIVATE_CANARY"
    tags = result.tags
    tags.__dict__["asset"] = [canary]
    with warnings.catch_warnings(record=True) as captured:
        warnings.simplefilter("always")
        for operation in (tags.model_dump, tags.model_dump_json, result.model_dump):
            with pytest.raises(SealError) as caught:
                operation()
            assert caught.value.code == "SEAL_TAMPERED"
    assert not captured
    assert canary not in caught.value.args


def test_tag_policy_bounds_validate_on_construction_and_copy() -> None:
    with pytest.raises(ParserModelError):
        FolderTagRuleV1(prefix="../escape", tags=TagSetV1())
    with pytest.raises(ParserModelError):
        FolderTagRuleV1(prefix="notes/CON", tags=TagSetV1())
    with pytest.raises(ParserModelError):
        TagRulesV1(methodology_allowlist=("x" * 65,))
    with pytest.raises(ParserModelError):
        TagRulesV1().model_copy(update={"asset_allowlist": ("x" * 65,)})


def test_https_reference_is_recorded_and_never_fetched() -> None:
    result = parse_markdown(_source("[x][ref]\n\n[ref]:\n https://example.com/a"))
    assert isinstance(result, ParseResultV1)
    assert result.external_references == ("https://example.com/a",)
    assert result.collision_check == "NOT_PERFORMED"


def test_https_wiki_reference_is_recorded_once() -> None:
    result = parse_markdown(
        _source("[[https://example.test/a#part|*alias*]] [[https://example.test/a#part|again]]")
    )
    assert isinstance(result, ParseResultV1)
    assert result.external_references == ("https://example.test/a#part",)


def test_list_heading_updates_chunk_lineage() -> None:
    body = "# Outer\n\n- intro\n\n  ## Inner\n\n  " + "fact " * 100
    result = parse_markdown(
        _source(body), chunk_spec=ChunkSpecV1(target_tokens=64, overlap_tokens=0)
    )
    assert isinstance(result, ParseResultV1)
    fact_chunks = [chunk for chunk in result.chunks if "fact" in chunk.text]
    assert len(fact_chunks) >= 2
    assert all(chunk.heading_path == ("Outer", "Inner") for chunk in fact_chunks)


def test_blockquote_heading_updates_later_chunk_lineage() -> None:
    result = parse_markdown(_source("# Outer\n\n> ## Inner\n> quote\n\nafter\n"))
    assert isinstance(result, ParseResultV1)
    after_chunk = next(chunk for chunk in result.chunks if "after" in chunk.text)
    assert after_chunk.heading_path == ("Outer", "Inner")


def test_unclosed_eof_fence_is_valid_commonmark_code() -> None:
    source = "```python\nprint(1)\n"
    result = parse_markdown(_source(source))
    assert isinstance(result, ParseResultV1)
    assert result.chunks[0].text == source.rstrip()
    oversized = parse_markdown(
        _source("```python\n" + "word " * 100 + "\n"),
        chunk_spec=ChunkSpecV1(target_tokens=64, overlap_tokens=0),
    )
    assert isinstance(oversized, ParseResultV1)
    assert len(oversized.chunks) == 2
    assert all(chunk.synthetic_fence and chunk.text.count("```") == 2 for chunk in oversized.chunks)


def test_yaml_error_contains_no_source_excerpt() -> None:
    secret = "SYNTHETIC_SECRET_ABC123"
    result = parse_markdown(_source(f"---\nasset: [{secret}\n---\ntext"))
    assert isinstance(result, ParseFailureV1)
    assert result.code == "invalid_frontmatter"
    assert result.line is not None and result.column is not None
    assert secret not in result.message
    assert secret not in str(result)
    assert secret not in repr(result)


def test_chunk_bounds_and_output_work_limit() -> None:
    with pytest.raises(ParserModelError):
        ChunkSpecV1(target_tokens=1, overlap_tokens=0)
    with pytest.raises(ParserModelError):
        ChunkSpecV1(target_tokens=64, overlap_tokens=32)
    with pytest.raises(ParserModelError):
        ChunkSpecV1(target_tokens=8193, overlap_tokens=0)
    too_many_lines = parse_markdown(_source("\n" * 100_001))
    assert isinstance(too_many_lines, ParseFailureV1)
    assert too_many_lines.code == "resource_limit_exceeded"
    too_many_chunks = parse_markdown(_source("# H\n" * 4_100))
    assert isinstance(too_many_chunks, ParseFailureV1)
    assert too_many_chunks.code == "resource_limit_exceeded"


def test_protected_overlap_and_heading_path_at_first_byte() -> None:
    code = "```txt\n" + " ".join(f"w{i}" for i in range(80)) + "\n```"
    text = "# Alpha\nfirst facts\n\n## Child\n" + code + "\nafter words\n\n# Beta\nsecond facts"
    result = parse_markdown(
        _source(text), chunk_spec=ChunkSpecV1(target_tokens=64, overlap_tokens=10)
    )
    assert isinstance(result, ParseResultV1)
    assert any(chunk.heading_path == ("Alpha", "Child") for chunk in result.chunks)
    assert any(chunk.heading_path == ("Beta",) for chunk in result.chunks)
    assert all(
        chunk.heading_path != ("Beta",) for chunk in result.chunks if "first facts" in chunk.text
    )
    assert all(chunk.text.count("```") == 2 for chunk in result.chunks if "```" in chunk.text)


@pytest.mark.parametrize(
    "path",
    [
        "notes/.. /private.md",
        "notes/CON.md",
        "notes/file~1.md",
        "notes/x. ",
        "C:/a.md",
        "a:stream",
        "notes/\ud800.md",
    ],
)
def test_windows_aliases_and_surrogate_are_typed_path_failures(path: str) -> None:
    result = parse_markdown(_source("# Note", path=path))
    assert isinstance(result, ParseFailureV1)
    assert result.code == "invalid_path"


def test_collision_index_and_batch_are_explicit() -> None:
    index = VaultPathIndexV1(snapshot_id="snapshot-1", paths=("research/methods/NOTE.md",))
    collision = parse_markdown(_source("# Note", vault_path_index=index))
    assert isinstance(collision, ParseFailureV1)
    assert collision.detail_code == "CASE_COLLISION"
    batch = parse_markdown(_source("# Note", batch_paths=("research/methods/NOTE.md",)))
    assert isinstance(batch, ParseFailureV1)
    assert batch.detail_code == "CASE_COLLISION"
    clear = parse_markdown(
        _source("# Note", vault_path_index=VaultPathIndexV1(snapshot_id="s2", paths=()))
    )
    assert isinstance(clear, ParseResultV1)
    assert clear.collision_check == "PASSED"


def test_trust_label_cannot_be_supplied_and_code_examples_remain_inert() -> None:
    with pytest.raises(ParserModelError):
        _source("# Note", source_trust_label="trusted_instruction")
    example = (
        "```html\n<script>sample</script>\n[x](javascript:alert)\n```\n\n"
        "    <script>indented</script>"
    )
    result = parse_markdown(_source(example))
    assert isinstance(result, ParseResultV1)
    content = "\n".join(chunk.text for chunk in result.chunks)
    assert "<script>sample</script>" in content
    assert "[x](javascript:alert)" in content
    assert "<script>indented</script>" in content
    assert all(chunk.source_trust_label == "untrusted_vault" for chunk in result.chunks)


def test_long_fence_closer_and_indented_code_remain_inert_and_exact() -> None:
    text = (
        "````html\n"
        "<script>sample</script>\n"
        "[x](javascript:alert)\n"
        "`````\n\n"
        "    <script>indented</script>\n"
        "    [x](javascript:alert)\n"
    )
    result = parse_markdown(_source(text))
    assert isinstance(result, ParseResultV1)
    combined = "\n".join(chunk.text for chunk in result.chunks)
    assert "`````" in combined
    assert "    <script>indented</script>" in combined
    assert "    [x](javascript:alert)" in combined
