"""Immutable contracts for the offline, untrusted-source Markdown parser.

Before trusting fields of a parser-issued result, chunk, failure or nested tag
set, consumers must call ``require(value, "knowledge.parser.v1")``. Ordinary
attribute reads are not trust boundaries. Caller-supplied envelope/event tags
are unissued input data and are normalized by the parser without such a claim.
"""

import hashlib
import json
import re
import unicodedata
from collections.abc import Mapping
from typing import Any, Literal, Self, TypeVar

from pydantic import Field, StrictBool, StrictInt, model_validator

from leviathan_core.seal import Issuer, SealedModel, SealError, require

Taxon = Literal["methodology", "asset", "regime"]
MAX_PARSER_SOURCE_BYTES = 128 * 1024
MAX_PARSER_CHUNKS = 4_096
# The source cap bounds external-reference entries by one per input byte.
# A fully populated chunk walks at most 183 SEAL nodes (96 tag labels and
# six headings included); the root without chunks/references walks 147.
MAX_PARSER_CHUNK_SEAL_NODES = 183
MAX_PARSER_RESULT_SEAL_NODES = 147
MAX_PARSER_SEAL_NODES = (
    MAX_PARSER_CHUNKS * MAX_PARSER_CHUNK_SEAL_NODES
    + MAX_PARSER_RESULT_SEAL_NODES
    + MAX_PARSER_SOURCE_BYTES
)
FailureCode = Literal[
    "invalid_source",
    "invalid_path",
    "invalid_link",
    "payload_too_large",
    "unsupported_format",
    "unsupported_tokenizer",
    "invalid_frontmatter",
    "unsafe_html",
    "invalid_tag",
    "tag_not_allowed",
    "resource_limit_exceeded",
]
_CONFIG_SLUG = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
_WINDOWS_DEVICE = re.compile(
    r"(?:con|prn|aux|nul|conin\$|conout\$|clock\$|com[1-9¹²³]|lpt[1-9¹²³])(?:\..*)?\Z",
    re.I,
)
_WINDOWS_SHORT_NAME = re.compile(r"~[1-9](?:\.|$)", re.I)

class ParserModelError(Exception):
    """Typed parser-contract error with no caller data in any public view."""

    def __init__(
        self, code: str, issues: tuple[tuple[tuple[str | int, ...], str], ...] = ()
    ) -> None:
        self.code = code
        self.issues = issues
        super().__init__(code)

    def errors(self) -> list[dict[str, object]]:
        return [
            {"code": self.code, "loc": list(location), "type": kind}
            for location, kind in self.issues
        ]

    def json(self) -> str:
        return json.dumps(self.errors(), ensure_ascii=True, separators=(",", ":"))


def _validate_config_tags(tags: "TagSetV1") -> None:
    for taxon in ("methodology", "asset", "regime"):
        values: tuple[str, ...] = getattr(tags, taxon)
        if len(values) > 32:
            raise ValueError("too many configured tag values")
        for value in values:
            label = unicodedata.normalize("NFKC", value).strip().casefold()
            label = re.sub(r"[\s_]+", "-", label).strip("-")
            if label and (len(label) > 64 or not _CONFIG_SLUG.fullmatch(label)):
                raise ValueError("configured tag is not lowercase kebab-case")


def _validate_folder_prefix(prefix: str) -> None:
    if prefix in ("", "."):
        return
    try:
        prefix.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("invalid folder rule prefix") from exc
    if (
        len(prefix) > 1024
        or prefix != unicodedata.normalize("NFC", prefix)
        or "\\" in prefix
        or ":" in prefix
        or prefix.startswith("/")
        or prefix.endswith("/")
        or "//" in prefix
        or any(ord(char) < 32 or ord(char) == 127 for char in prefix)
    ):
        raise ValueError("invalid folder rule prefix")
    if len(prefix.split("/")) > 32 or any(
        part in ("", ".", "..")
        or part.rstrip(" .") != part
        or _WINDOWS_DEVICE.fullmatch(part)
        or _WINDOWS_SHORT_NAME.search(part)
        for part in prefix.split("/")
    ):
        raise ValueError("invalid folder rule prefix")


class _ParserModel(SealedModel):
    """Parser models use SEAL-001; input validation retains a redacted parser error."""

    def __init__(self, **data: Any) -> None:
        invalid = False
        try:
            super().__init__(**data)
        except SealError as error:
            if error.code != "SEAL_INVALID_MODEL":
                raise
            invalid = True
        if invalid:
            raise ParserModelError("MODEL_VALIDATION")

    @classmethod
    def model_validate(cls, obj: Any, **kwargs: Any) -> Self:
        invalid = False
        try:
            return super().model_validate(obj, **kwargs)
        except SealError as error:
            if error.code != "SEAL_INVALID_MODEL":
                raise
            invalid = True
        if invalid:
            raise ParserModelError("MODEL_VALIDATION")
        raise AssertionError("model validation did not return")

    @classmethod
    def model_validate_json(cls, json_data: str | bytes | bytearray, **kwargs: Any) -> Self:
        invalid = False
        try:
            return super().model_validate_json(json_data, **kwargs)
        except SealError as error:
            if error.code != "SEAL_INVALID_MODEL":
                raise
            invalid = True
        if invalid:
            raise ParserModelError("MODEL_VALIDATION")
        raise AssertionError("JSON model validation did not return")

    @classmethod
    def model_validate_strings(cls, obj: Any, **kwargs: Any) -> Self:
        invalid = False
        try:
            return super().model_validate_strings(obj, **kwargs)
        except SealError as error:
            if error.code != "SEAL_INVALID_MODEL":
                raise
            invalid = True
        if invalid:
            raise ParserModelError("MODEL_VALIDATION")
        raise AssertionError("string model validation did not return")

    def model_copy(self, *, update: Mapping[str, Any] | None = None, deep: bool = False) -> Self:
        invalid = False
        try:
            return super().model_copy(update=update, deep=deep)
        except SealError as error:
            if error.code != "SEAL_INVALID_MODEL":
                raise
            invalid = True
        if invalid:
            raise ParserModelError("MODEL_VALIDATION")
        raise AssertionError("model copy did not return")


_ISSUER = Issuer("knowledge.parser.v1", max_digest_nodes=MAX_PARSER_SEAL_NODES)
_IssuedT = TypeVar("_IssuedT", bound=_ParserModel)


def _issue_result(model: type[_IssuedT], **data: Any) -> _IssuedT:
    """Issue the completed output tree through the shared digest domain."""

    return _require_result(_issue_model(model(**data)))


def _issue_model(result: _IssuedT) -> _IssuedT:
    """Issue an internally validated model after output bounds are checked."""

    return _ISSUER.issue(result)


def _require_result(result: _IssuedT) -> _IssuedT:
    """Verify identity and content whenever a parser result is consumed."""

    return require(result, _ISSUER.tag)


class TagSetV1(_ParserModel):
    """Resolved taxonomy values and required taxons still needing operator review."""

    methodology: tuple[str, ...] = ()
    asset: tuple[str, ...] = ()
    regime: tuple[str, ...] = ()
    unresolved_required: tuple[Taxon, ...] = ()
    methodology_source: str = "unresolved"
    asset_source: str = "unresolved"
    regime_source: str = "unresolved"


class FolderTagRuleV1(_ParserModel):
    """A vault-relative directory prefix and its configured taxonomy values."""

    prefix: str
    tags: TagSetV1

    @model_validator(mode="after")
    def validate_rule(self) -> "FolderTagRuleV1":
        _validate_folder_prefix(self.prefix)
        _validate_config_tags(self.tags)
        return self


class TagRulesV1(_ParserModel):
    """Tenant-provided allowlists and vault folder mapping; empty allowlist is open."""

    methodology_allowlist: tuple[str, ...] = ()
    asset_allowlist: tuple[str, ...] = ()
    regime_allowlist: tuple[str, ...] = ()
    folder_rules: tuple[FolderTagRuleV1, ...] = ()

    @model_validator(mode="after")
    def validate_rules(self) -> "TagRulesV1":
        if len(self.folder_rules) > 1024:
            raise ValueError("too many folder rules")
        _validate_config_tags(
            TagSetV1(
                methodology=self.methodology_allowlist,
                asset=self.asset_allowlist,
                regime=self.regime_allowlist,
            )
        )
        return self


class VaultPathIndexV1(_ParserModel):
    """Caller-supplied immutable vault snapshot for casefold collision detection."""

    snapshot_id: str = Field(min_length=1)
    paths: tuple[str, ...]
    canonical_identities: frozenset[str] = Field(default_factory=frozenset)
    digest: str = ""

    @model_validator(mode="after")
    def bind_snapshot(self) -> "VaultPathIndexV1":
        identities = frozenset(unicodedata.normalize("NFC", path).casefold() for path in self.paths)
        payload = json.dumps(
            sorted(self.paths), ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )
        try:
            digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        except UnicodeEncodeError as exc:
            raise ValueError("vault snapshot path is not UTF-8") from exc
        if self.canonical_identities and self.canonical_identities != identities:
            raise ValueError("vault snapshot identities do not match paths")
        if self.digest and self.digest != digest:
            raise ValueError("vault snapshot digest does not match paths")
        object.__setattr__(self, "canonical_identities", identities)
        object.__setattr__(self, "digest", digest)
        return self


class SourceEnvelopeV1(_ParserModel):
    """Authenticated caller context plus exactly one raw UTF-8 source representation.

    IDs, versions, event tags and timestamp are supplied by trusted caller code.
    This model does not authenticate them; the parser never grants source text authority.
    """

    org_id: str = Field(min_length=1)
    vault_id: str = Field(min_length=1)
    doc_id: str = Field(min_length=1)
    version_id: str = Field(min_length=1)
    path: str
    content_type: str
    source_bytes: bytes | None = None
    source_text: str | None = None
    event_tags: TagSetV1 = Field(default_factory=TagSetV1)
    vault_path_index: VaultPathIndexV1 | None = None
    batch_paths: tuple[str, ...] = ()
    parser_version: str = Field(min_length=1)
    chunker_version: str = Field(min_length=1)
    created_at_ns: StrictInt = Field(ge=0)

    @model_validator(mode="after")
    def one_source(self) -> "SourceEnvelopeV1":
        if (self.source_bytes is None) == (self.source_text is None):
            raise ValueError("supply exactly one of source_bytes or source_text")
        return self


class ChunkSpecV1(_ParserModel):
    target_tokens: StrictInt = Field(default=400, ge=64, le=8192)
    overlap_tokens: StrictInt = Field(default=60, ge=0)
    tokenizer_version: str = "whitespace-v1"

    @model_validator(mode="after")
    def valid_overlap(self) -> "ChunkSpecV1":
        if self.overlap_tokens * 2 >= self.target_tokens:
            raise ValueError("overlap_tokens must be less than half target_tokens")
        return self


class ParsedChunkV1(_ParserModel):
    chunk_id: str
    chunk_hash: str
    sequence: StrictInt
    text: str
    continuation_part: StrictInt | None = None
    continuation_total: StrictInt | None = None
    synthetic_fence: StrictBool = False
    token_count: StrictInt
    char_start: StrictInt
    char_end: StrictInt
    byte_start: StrictInt
    byte_end: StrictInt
    heading: str | None
    heading_path: tuple[str, ...] = ()
    page_number: StrictInt | None = None
    timestamp_start_ms: StrictInt | None = None
    timestamp_end_ms: StrictInt | None = None
    org_id: str
    vault_id: str
    doc_id: str
    version_id: str
    path: str
    source_hash: str
    parser_version: str
    chunker_version: str
    tokenizer_version: str
    source_trust_label: Literal["untrusted_vault", "untrusted_external"]
    created_at_ns: StrictInt
    tags: TagSetV1

    @model_validator(mode="after")
    def valid_continuation(self) -> "ParsedChunkV1":
        part, total = self.continuation_part, self.continuation_total
        if (part is None) != (total is None) or self.synthetic_fence != (part is not None):
            raise ValueError("invalid continuation metadata")
        if part is not None and total is not None and (part < 1 or total < 1 or part > total):
            raise ValueError("invalid continuation part")
        return self


class ParseResultV1(_ParserModel):
    org_id: str
    vault_id: str
    doc_id: str
    version_id: str
    path: str
    source_hash: str
    dedupe_key: str
    parser_version: str
    chunker_version: str
    created_at_ns: StrictInt
    tags: TagSetV1
    chunks: tuple[ParsedChunkV1, ...]
    external_references: tuple[str, ...] = ()
    collision_check: Literal["NOT_PERFORMED", "PASSED"] = "NOT_PERFORMED"


class ParseFailureV1(_ParserModel):
    code: FailureCode
    message: str
    path: str
    detail_code: str | None = None
    line: StrictInt | None = None
    column: StrictInt | None = None
