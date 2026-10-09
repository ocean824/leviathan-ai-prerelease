"""Deterministic tenant-scoped taxonomy resolution for untrusted Markdown."""

import re
import unicodedata
from collections.abc import Mapping
from typing import Any

from leviathan_core.knowledge_sync.parser_models import TagRulesV1, TagSetV1, Taxon

_TAXONS: tuple[Taxon, ...] = ("methodology", "asset", "regime")
_SLUG = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")


class TagRuleError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _normalize_values(raw: Any) -> tuple[str, ...]:
    if raw is None or raw == "":
        return ()
    values: list[Any]
    if isinstance(raw, str):
        values = raw.split(",")
    elif isinstance(raw, (list, tuple)):
        values = list(raw)
    else:
        raise TagRuleError("invalid_tag", "tag values must be strings or arrays of strings")
    if len(values) > 32:
        raise TagRuleError("invalid_tag", "too many values for one taxon")
    normalized: list[str] = []
    for value in values:
        if not isinstance(value, str):
            raise TagRuleError("invalid_tag", "tag values must be strings")
        label = unicodedata.normalize("NFKC", value).strip().casefold()
        label = re.sub(r"[\s_]+", "-", label).strip("-")
        if not label:
            continue
        if len(label) > 64 or not _SLUG.fullmatch(label):
            raise TagRuleError("invalid_tag", "tag is not lowercase kebab-case")
        if label not in normalized:
            normalized.append(label)
    return tuple(normalized)


def _folder_tags(path: str, rules: TagRulesV1) -> TagSetV1:
    directory = path.rpartition("/")[0]
    matching: list[tuple[int, int, TagSetV1]] = []
    for index, rule in enumerate(rules.folder_rules):
        prefix = rule.prefix.replace("\\", "/").strip("/")
        if (not prefix or prefix == ".") and rule.prefix in ("", "."):
            matching.append((0, index, rule.tags))
            continue
        parts = prefix.split("/")
        if any(part in ("", ".", "..") for part in parts) or ":" in prefix:
            raise TagRuleError("invalid_tag", "invalid folder rule prefix")
        if directory == prefix or directory.startswith(prefix + "/"):
            matching.append((len(prefix), index, rule.tags))
    if not matching:
        return TagSetV1()
    matching.sort(key=lambda item: (-item[0], item[1]))
    return matching[0][2]


def resolve_tags(
    frontmatter: Mapping[str, Any], event_tags: TagSetV1, path: str, rules: TagRulesV1
) -> TagSetV1:
    """Normalize event tags as input data, copying them before any resolution.

    Shared validation checks an issued input's seal before making an unissued
    copy. The returned tag set is fresh and gains authority only with the
    parser-issued result that contains it.
    """

    event_input = TagSetV1.model_validate(event_tags)
    folder_tags = _folder_tags(path, rules)
    resolved: dict[str, Any] = {}
    unresolved: list[Taxon] = []
    for taxon in _TAXONS:
        candidates = (
            ("frontmatter", frontmatter.get(taxon)),
            ("event", getattr(event_input, taxon)),
            ("folder", getattr(folder_tags, taxon)),
        )
        values: tuple[str, ...] = ()
        source = "unresolved"
        for candidate_source, raw in candidates:
            values = _normalize_values(raw)
            if values:
                source = candidate_source
                break
        allowlist = _normalize_values(getattr(rules, f"{taxon}_allowlist"))
        if allowlist and any(value not in allowlist for value in values):
            raise TagRuleError("tag_not_allowed", f"{taxon} value is outside tenant allowlist")
        resolved[taxon] = values
        resolved[f"{taxon}_source"] = source
        if not values:
            unresolved.append(taxon)
    return TagSetV1(**resolved, unresolved_required=tuple(unresolved))
