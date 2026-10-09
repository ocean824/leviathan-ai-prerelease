"""Writer tests for the pure archived knowledge policy."""

from __future__ import annotations

import json
import pickle
from copy import copy, deepcopy
from email.utils import parsedate_to_datetime

import pytest
from pydantic import BaseModel

from leviathan_core.knowledge_sync import archive_models, archive_policy
from leviathan_core.knowledge_sync.archive_models import (
    ArchivedQueryV1,
    ArchivedRecordV1,
    ArchivePolicyError,
)
from leviathan_core.knowledge_sync.archive_policy import (
    deny_archived_write,
    parse_archived_query,
    read_archived_detail,
    read_archived_list,
)
from leviathan_core.seal import SealError, require, verify
from leviathan_core.security.authz_models import (
    _VERIFIER_MARKER,
    PrincipalV1,
    TrustedPrincipalAdapterV1,
)

_ORG = "org-a"
_NOW = 1_700_000_000_000_000_000
_SUNSET = 1_690_000_000_000_000_000


def _principal(*, org: str = _ORG, roles: tuple[str, ...] = ("audit",)) -> object:
    claims = PrincipalV1(principal_id="auditor-1", project_id=org, roles=roles, env="paper")
    return TrustedPrincipalAdapterV1.from_verified_claims(claims, verifier_marker=_VERIFIER_MARKER)


def _record(
    record_id: str = "00000000-0000-0000-0000-000000000001",
    *,
    org: str = _ORG,
    created: int = 100,
    payload: str = (
        '{"api_key":"secret","nested":{"connection_string":"db://secret",'
        '"db_conn":"host=hidden","ok":1}}'
    ),
) -> ArchivedRecordV1:
    return ArchivedRecordV1(
        schema_version="1",
        org_id=org,
        record_id=record_id,
        source_type="api",
        created_at_ns=created,
        updated_at_ns=created,
        tags=("legacy",),
        payload_json=payload,
        status="archived",
    )


def _query(**kwargs: object) -> ArchivedQueryV1:
    return ArchivedQueryV1(schema_version="1", **kwargs)


def _read(
    records: tuple[ArchivedRecordV1, ...],
    *,
    query: ArchivedQueryV1 | None = None,
    principal: object | None = None,
    if_none_match: str | None = None,
) -> object:
    return read_archived_list(
        _principal() if principal is None else principal,
        _ORG,
        records,
        _query() if query is None else query,
        now_ns=_NOW,
        sunset_at_ns=_SUNSET,
        if_none_match=if_none_match,
    )


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "START_RUN", "QUEUE_RUN"])
def test_all_legacy_writes_are_issued_410(method: str) -> None:
    decision = deny_archived_write(method, now_ns=_NOW, sunset_at_ns=_SUNSET)
    assert decision.status_code == 410
    assert decision.code == "LEGACY_ARCHIVED"
    assert verify(decision, "know_legacy001.denial.v1")
    assert "docs.example.invalid" in decision.body_json
    assert {name for name, _ in decision.headers} == {"Deprecation", "Sunset", "Link"}


def test_unknown_query_filter_warns_and_defaults_to_fifty() -> None:
    query = parse_archived_query({"unknown": "ignored"})
    assert query.limit == 50
    assert query.warnings == ("IGNORED_UNKNOWN_FILTER",)


@pytest.mark.parametrize("limit", ["0", "201", "1.5", "true"])
def test_bad_limit_fails_closed(limit: str) -> None:
    with pytest.raises((ArchivePolicyError, SealError)):
        parse_archived_query({"limit": limit})


def test_list_paginates_and_masks_nested_secrets() -> None:
    records = tuple(_record(f"00000000-0000-0000-0000-{i:012d}", created=i) for i in range(1, 4))
    first = _read(records, query=_query(limit=1))
    assert first.status_code == 200
    assert first.next_cursor == "1"
    body = json.loads(first.body_json)
    assert len(body["data"]) == 1
    assert body["data"][0]["data"]["api_key"] == "****"
    assert body["data"][0]["data"]["nested"]["connection_string"] == "****"
    assert body["data"][0]["data"]["nested"]["db_conn"] == "****"
    assert "db://secret" not in first.body_json
    second = _read(records, query=_query(limit=1, cursor=first.next_cursor))
    assert second.next_cursor == "2"
    assert json.loads(second.body_json)["data"][0]["id"].endswith("000000000002")


def test_authorized_matching_etag_returns_304() -> None:
    first = _read((_record(),))
    second = _read((_record(),), if_none_match=first.etag)
    assert first.status_code == 200
    assert second.status_code == 304
    assert second.body_json is None
    assert second.etag == first.etag
    assert verify(second, "know_legacy001.read.v1")


def test_missing_and_foreign_detail_are_indistinguishable() -> None:
    kwargs = {"now_ns": _NOW, "sunset_at_ns": _SUNSET}
    missing = read_archived_detail(_principal(), _ORG, None, **kwargs)
    foreign = read_archived_detail(_principal(), _ORG, _record(org="org-b"), **kwargs)
    assert missing.status_code == foreign.status_code == 404
    assert missing.body_json == foreign.body_json
    assert foreign.etag is None


def test_future_snapshot_rows_are_invisible_before_pagination() -> None:
    past = _record(created=100)
    future = _record("00000000-0000-0000-0000-000000000002", created=_NOW + 1)
    listed = _read((future, past), query=_query(limit=1))
    assert listed.status_code == 200
    assert listed.record_count == 1
    assert listed.next_cursor is None
    assert json.loads(listed.body_json)["data"][0]["id"] == past.record_id
    hidden = read_archived_detail(_principal(), _ORG, future, now_ns=_NOW, sunset_at_ns=_SUNSET)
    assert hidden.status_code == 404


def test_untrusted_denied_and_verified_role_denied() -> None:
    assert _read((_record(),), principal=object()).status_code == 401
    assert _read((_record(),), principal=_principal(roles=("trader",))).status_code == 403
    assert _read((_record(),), principal=_principal(org="org-b")).status_code == 404


def test_issued_result_is_immutable_and_tamper_detected() -> None:
    result = _read((_record(),))
    with pytest.raises(SealError) as frozen:
        result.body_json = "canary-secret"
    assert "canary-secret" not in str(frozen.value)
    assert "canary-secret" not in repr(frozen.value.args)
    with pytest.raises(SealError):
        copy(result)
    with pytest.raises(SealError):
        deepcopy(result)
    with pytest.raises(SealError):
        pickle.dumps(result)
    with pytest.raises(SealError):
        BaseModel.__init__(result, body_json="canary-secret")
    clone = type(result).model_validate(result)
    assert clone is not result
    assert not verify(clone, "know_legacy001.read.v1")
    with pytest.raises(SealError, match="SEAL_FORBIDDEN_OPERATION"):
        BaseModel.__setstate__(result, {})
    assert verify(result, "know_legacy001.read.v1")
    require(result, "know_legacy001.read.v1")
    result = _read((_record(),))
    object.__setattr__(result, "body_json", "{}")
    assert not verify(result, "know_legacy001.read.v1")
    with pytest.raises(SealError):
        result.model_dump()


def test_base_state_restore_is_blocked_for_issued_and_detected_for_unissued() -> None:
    result = _read((_record(),))
    with pytest.raises(SealError, match="SEAL_FORBIDDEN_OPERATION") as failure:
        BaseModel.__setstate__(result, {"__dict__": {"body_json": "canary-secret"}})
    assert "canary-secret" not in str(failure.value)
    assert verify(result, "know_legacy001.read.v1")
    assert "canary-secret" not in result.model_dump_json()

    record = _record()
    BaseModel.__setstate__(record, {"__dict__": {"payload_json": "canary-secret"}})
    with pytest.raises(ArchivePolicyError, match="INVALID_RECORD") as denied:
        read_archived_detail(_principal(), _ORG, record, now_ns=_NOW, sunset_at_ns=_SUNSET)
    assert "canary-secret" not in str(denied.value)


def test_record_rejects_non_object_json_and_secret_is_not_in_etag() -> None:
    with pytest.raises(SealError):
        _record(payload='["not an object"]')
    one = _read((_record(payload='{"token":"first","public":1}'),))
    two = _read((_record(payload='{"token":"second","public":1}'),))
    assert one.etag == two.etag


def test_payload_is_structure_only_even_for_credential_values_under_plain_keys() -> None:
    canaries = tuple(f"SYNTHETIC_CANARY_{index}" for index in range(12))
    payload = {
        "auth": {"pass": canaries[0]},
        "passwd": canaries[1],
        "pw": canaries[2],
        "db": f"postgresql://admin:{canaries[3]}@db.invalid/prod",
        "url": f"https://example.invalid/?api_key={canaries[4]}",
        "headers": [["Authorization", f"Bearer {canaries[5]}"]],
        "keys": [canaries[6]],
        "signature": canaries[7],
        "cookie": canaries[8],
        "jwt": canaries[9],
        "p\u0430ssword": canaries[10],
        "notes": f"free text {canaries[11]}",
        "public": 42,
    }
    decision = read_archived_detail(
        _principal(roles=("research",)),
        _ORG,
        _record(payload=json.dumps(payload)),
        now_ns=_NOW,
        sunset_at_ns=_SUNSET,
    )
    assert decision.status_code == 200
    assert all(canary not in decision.body_json for canary in canaries)
    visible = json.loads(decision.body_json)["data"]["data"]
    assert visible["public"] == "****"
    assert visible["headers"] == [["****", "****"]]
    assert visible["keys"] == ["****"]


@pytest.mark.parametrize("header", ["W/{etag}", '"other", {etag}', "*"])
def test_conditional_read_accepts_weak_list_and_wildcard(header: str) -> None:
    first = _read((_record(),))
    conditional = _read((_record(),), if_none_match=header.format(etag=first.etag))
    assert conditional.status_code == 304
    assert conditional.body_json is None


def test_sunset_is_imf_fixdate_and_unlisted_writes_are_denied() -> None:
    for method in ("RETRY_RUN", "UPLOAD", "post"):
        denial = deny_archived_write(method, now_ns=_NOW, sunset_at_ns=_SUNSET)
        assert denial.status_code == 410
        assert denial.code == "LEGACY_ARCHIVED"
        sunset = dict(denial.headers)["Sunset"]
        assert sunset.endswith(" GMT")
        assert parsedate_to_datetime(sunset).utcoffset().total_seconds() == 0


def test_list_parse_cost_is_bounded_to_selected_page(monkeypatch: pytest.MonkeyPatch) -> None:
    records = (
        _record(created=100),
        *(
            _record(f"00000000-0000-0000-0000-{index:012d}", created=_NOW + index)
            for index in range(2, 12)
        ),
    )
    calls = 0
    original = archive_models.load_payload

    def counted(value: object) -> dict[str, object]:
        nonlocal calls
        calls += 1
        return original(value)

    monkeypatch.setattr(archive_models, "load_payload", counted)
    monkeypatch.setattr(archive_policy, "load_payload", counted)
    decision = _read(records, query=_query(limit=1))
    assert decision.record_count == 1
    assert calls <= 2
