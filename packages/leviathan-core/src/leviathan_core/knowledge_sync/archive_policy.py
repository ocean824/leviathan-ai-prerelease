"""Pure archived-knowledge read and 410 decisions; no route or data access."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from email.utils import format_datetime
from types import MappingProxyType
from typing import Final, Literal, cast

from leviathan_core.numeric import canonical_json
from leviathan_core.seal import Issuer
from leviathan_core.security.authz_models import (
    AuthorizationModelError,
    require_trusted_principal,
)

from .archive_models import (
    ArchivedQueryV1,
    ArchivedReadDecisionV1,
    ArchivedRecordV1,
    ArchivedWriteDenialV1,
    ArchivePolicyError,
    load_payload,
    valid_id,
    valid_ns,
)

SYNTHETIC_MARKET_DATA_DOC = "https://docs.example.invalid/market-data-pipeline"
SYNTHETIC_EA_BUILDER_DOC = "https://docs.example.invalid/ea-builder-knowledge"
_READ_ISSUER = Issuer("know_legacy001.read.v1")
_DENIAL_ISSUER = Issuer("know_legacy001.denial.v1")
_READ_ROLES = frozenset(
    {
        "admin",
        "operator",
        "audit",
        "strategy",
        "research",
        "readonly-market",
    }
)
_QUERY_KEYS = frozenset(
    {
        "cursor",
        "limit",
        "source_type",
        "created_after",
        "created_before",
        "tag",
    }
)
_MASK = "****"
_VISIBLE_PAYLOAD_PATHS: Final[Mapping[str, frozenset[tuple[str, ...]]]] = MappingProxyType(
    {
        "web": frozenset(),
        "file": frozenset(),
        "api": frozenset(),
        "custom": frozenset(),
    }
)
_ETAG_ITEM = re.compile(r'[ \t]*(\*|(?:W/)?"[\x21\x23-\x7e]*")[ \t]*(,|$)', re.ASCII)


def _ns_param(value: object, code: str) -> int:
    if type(value) is not str or not value.isascii() or not value.isdecimal():
        raise ArchivePolicyError(code)
    try:
        return valid_ns(int(value))
    except (ValueError, ArchivePolicyError):
        raise ArchivePolicyError(code) from None


def parse_archived_query(params: Mapping[str, object]) -> ArchivedQueryV1:
    """Normalize HTTP query strings; unknown names yield a generic warning."""
    if not isinstance(params, Mapping) or len(params) > 64:
        raise ArchivePolicyError("INVALID_QUERY")
    if any(type(key) is not str for key in params):
        raise ArchivePolicyError("INVALID_QUERY")
    known: dict[str, str] = {}
    for key in _QUERY_KEYS:
        if key in params:
            value = params[key]
            if type(value) is not str:
                raise ArchivePolicyError("INVALID_QUERY")
            known[key] = value
    limit = 50
    if "limit" in known:
        raw_limit = known["limit"]
        if not raw_limit.isascii() or not raw_limit.isdecimal() or len(raw_limit) > 3:
            raise ArchivePolicyError("INVALID_LIMIT")
        limit = int(raw_limit)
    return ArchivedQueryV1(
        schema_version="1",
        cursor=known.get("cursor"),
        limit=limit,
        source_type=cast(Literal["web", "file", "api", "custom"] | None, known.get("source_type")),
        created_after_ns=(
            _ns_param(known["created_after"], "INVALID_TIME") if "created_after" in known else None
        ),
        created_before_ns=(
            _ns_param(known["created_before"], "INVALID_TIME")
            if "created_before" in known
            else None
        ),
        tag=known.get("tag"),
        warnings=("IGNORED_UNKNOWN_FILTER",) if set(params) - _QUERY_KEYS else (),
    )


def _headers(sunset_at_ns: int) -> tuple[tuple[str, str], ...]:
    sunset = datetime.fromtimestamp(valid_ns(sunset_at_ns) // 1_000_000_000, UTC)
    return (
        ("Deprecation", "true"),
        ("Sunset", format_datetime(sunset, usegmt=True)),
        (
            "Link",
            f'<{SYNTHETIC_MARKET_DATA_DOC}>; rel="successor-version", '
            f'<{SYNTHETIC_EA_BUILDER_DOC}>; rel="successor-version"',
        ),
    )


def _replacements() -> dict[str, str]:
    return {
        "market_data_doc": SYNTHETIC_MARKET_DATA_DOC,
        "ea_builder_doc": SYNTHETIC_EA_BUILDER_DOC,
    }


def _json(value: object) -> str:
    try:
        return canonical_json(value).decode("ascii")
    except Exception:
        raise ArchivePolicyError("INVALID_SNAPSHOT") from None


def _read_decision(
    status: Literal[200, 304, 401, 403, 404],
    *,
    body: object | None,
    etag: str | None,
    next_cursor: str | None,
    warnings: tuple[Literal["IGNORED_UNKNOWN_FILTER"], ...],
    headers: tuple[tuple[str, str], ...],
    record_count: int,
) -> ArchivedReadDecisionV1:
    result = ArchivedReadDecisionV1(
        schema_version="1",
        status_code=status,
        body_json=None if body is None else _json(body),
        etag=etag,
        next_cursor=next_cursor,
        warnings=warnings,
        headers=headers,
        record_count=record_count,
    )
    return _READ_ISSUER.issue(result)


def _error_decision(
    status: Literal[401, 403, 404], headers: tuple[tuple[str, str], ...]
) -> ArchivedReadDecisionV1:
    codes = {401: "UNAUTHENTICATED", 403: "FORBIDDEN", 404: "NOT_FOUND"}
    return _read_decision(
        status,
        body={"error": {"code": codes[status]}, "replacement": _replacements()},
        etag=None,
        next_cursor=None,
        warnings=(),
        headers=headers,
        record_count=0,
    )


def _principal_status(principal: object, org_id: str) -> Literal[401, 403, 404] | None:
    # SEC-002 issuance first: an unissued, copied, subclassed or altered principal is
    # the same 401 as no principal, so a forgery learns nothing new.
    try:
        trusted = require_trusted_principal(principal)
    except AuthorizationModelError:
        return 401
    try:
        project_id, roles = trusted.project_id, trusted.roles
        if type(project_id) is not str or type(roles) is not tuple:
            return 401
        if any(type(role) is not str for role in roles):
            return 401
    except (AttributeError, TypeError):
        return 401
    # The synthetic dataset uses the SEC-002 project scope as its org scope.
    if project_id != org_id:
        return 404
    if not _READ_ROLES.intersection(roles):
        return 403
    return None


def _query(value: object) -> ArchivedQueryV1:
    if type(value) is not ArchivedQueryV1:
        raise ArchivePolicyError("INVALID_QUERY")
    try:
        return ArchivedQueryV1(**value.model_dump())
    except Exception:
        raise ArchivePolicyError("INVALID_QUERY") from None


def _record(value: object) -> ArchivedRecordV1:
    if type(value) is not ArchivedRecordV1:
        raise ArchivePolicyError("INVALID_RECORD")
    try:
        return ArchivedRecordV1(**value.model_dump())
    except Exception:
        raise ArchivePolicyError("INVALID_RECORD") from None


def _redact(value: object, source_type: str, path: tuple[str, ...] = ()) -> object:
    if isinstance(value, dict):
        return {key: _redact(item, source_type, (*path, key)) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact(item, source_type, (*path, "*")) for item in value]
    return value if path in _VISIBLE_PAYLOAD_PATHS[source_type] else _MASK


def _visible_record(record: ArchivedRecordV1) -> dict[str, object]:
    return {
        "id": record.record_id,
        "source_type": record.source_type,
        "created_at_ns": record.created_at_ns,
        "updated_at_ns": record.updated_at_ns,
        "tags": record.tags,
        "status": record.status,
        "data": _redact(load_payload(record.payload_json), record.source_type),
    }


def _matches(record: ArchivedRecordV1, query: ArchivedQueryV1, org_id: str, now_ns: int) -> bool:
    return (
        record.org_id == org_id
        and record.created_at_ns <= now_ns
        and record.updated_at_ns <= now_ns
        and (query.source_type is None or record.source_type == query.source_type)
        and (query.created_after_ns is None or record.created_at_ns >= query.created_after_ns)
        and (query.created_before_ns is None or record.created_at_ns <= query.created_before_ns)
        and (query.tag is None or query.tag in record.tags)
    )


def _etag(body: object) -> str:
    return '"' + hashlib.sha256(_json(body).encode("ascii")).hexdigest() + '"'


def _etag_matches(header: str | None, tag: str) -> bool:
    if header is None:
        return False
    if type(header) is not str or not header or len(header) > 8192 or not header.isascii():
        raise ArchivePolicyError("INVALID_ETAG")
    matched = False
    offset = 0
    while offset < len(header):
        item = _ETAG_ITEM.match(header, offset)
        if item is None:
            raise ArchivePolicyError("INVALID_ETAG")
        candidate, separator = item.groups()
        matched = matched or candidate == "*" or candidate.removeprefix("W/") == tag
        offset = item.end()
        if separator == "," and offset == len(header):
            raise ArchivePolicyError("INVALID_ETAG")
    return matched


def _conditional(
    body: object,
    *,
    if_none_match: str | None,
    next_cursor: str | None,
    warnings: tuple[Literal["IGNORED_UNKNOWN_FILTER"], ...],
    headers: tuple[tuple[str, str], ...],
    record_count: int,
) -> ArchivedReadDecisionV1:
    tag = _etag(body)
    not_modified = _etag_matches(if_none_match, tag)
    return _read_decision(
        304 if not_modified else 200,
        body=None if not_modified else body,
        etag=tag,
        next_cursor=next_cursor,
        warnings=warnings,
        headers=headers,
        record_count=record_count,
    )


def read_archived_list(
    principal: object,
    org_id: str,
    records: tuple[ArchivedRecordV1, ...],
    query: ArchivedQueryV1,
    *,
    now_ns: int,
    sunset_at_ns: int,
    if_none_match: str | None = None,
) -> ArchivedReadDecisionV1:
    """Decide one deterministic page from an injected immutable snapshot."""
    valid_id(org_id, code="INVALID_ORG_ID")
    valid_ns(now_ns)
    headers = _headers(sunset_at_ns)
    auth_status = _principal_status(principal, org_id)
    if auth_status is not None:
        return _error_decision(auth_status, headers)
    parsed_query = _query(query)
    if type(records) is not tuple or len(records) > 10000:
        raise ArchivePolicyError("INVALID_SNAPSHOT")
    if any(type(item) is not ArchivedRecordV1 for item in records):
        raise ArchivePolicyError("INVALID_RECORD")
    try:
        selected = [item for item in records if _matches(item, parsed_query, org_id, now_ns)]
        selected.sort(key=lambda item: (item.created_at_ns, item.record_id))
    except (AttributeError, TypeError, ValueError):
        raise ArchivePolicyError("INVALID_RECORD") from None
    offset = int(parsed_query.cursor or "0")
    if offset > len(selected):
        raise ArchivePolicyError("INVALID_CURSOR")
    page = tuple(_record(item) for item in selected[offset : offset + parsed_query.limit])
    end = offset + len(page)
    next_cursor = str(end) if end < len(selected) else None
    body = {
        "data": [_visible_record(item) for item in page],
        "meta": {
            "cursor": next_cursor,
            "warnings": parsed_query.warnings,
            "replacement": _replacements(),
        },
    }
    return _conditional(
        body,
        if_none_match=if_none_match,
        next_cursor=next_cursor,
        warnings=parsed_query.warnings,
        headers=headers,
        record_count=len(page),
    )


def read_archived_detail(
    principal: object,
    org_id: str,
    record: ArchivedRecordV1 | None,
    *,
    now_ns: int,
    sunset_at_ns: int,
    if_none_match: str | None = None,
) -> ArchivedReadDecisionV1:
    """Return an authorized historical record or the same 404 for missing/foreign."""
    valid_id(org_id, code="INVALID_ORG_ID")
    valid_ns(now_ns)
    headers = _headers(sunset_at_ns)
    auth_status = _principal_status(principal, org_id)
    if auth_status is not None:
        return _error_decision(auth_status, headers)
    if record is None:
        return _error_decision(404, headers)
    safe_record = _record(record)
    if (
        safe_record.org_id != org_id
        or safe_record.created_at_ns > now_ns
        or safe_record.updated_at_ns > now_ns
    ):
        return _error_decision(404, headers)
    body = {
        "data": _visible_record(safe_record),
        "meta": {"replacement": _replacements()},
    }
    return _conditional(
        body,
        if_none_match=if_none_match,
        next_cursor=None,
        warnings=(),
        headers=headers,
        record_count=1,
    )


def deny_archived_write(method: str, *, now_ns: int, sunset_at_ns: int) -> ArchivedWriteDenialV1:
    """Translate every legacy mutation/execute intent to a side-effect-free 410."""
    if type(method) is not str or not method or len(method) > 64 or not method.isascii():
        raise ArchivePolicyError("INVALID_METHOD")
    valid_ns(now_ns)
    result = ArchivedWriteDenialV1(
        schema_version="1",
        status_code=410,
        code="LEGACY_ARCHIVED",
        body_json=_json(
            {
                "error": {
                    "code": "LEGACY_ARCHIVED",
                    "message": "Archived knowledge ingestion is read-only.",
                    "replacements": _replacements(),
                },
            }
        ),
        headers=_headers(sunset_at_ns),
    )
    return _DENIAL_ISSUER.issue(result)
