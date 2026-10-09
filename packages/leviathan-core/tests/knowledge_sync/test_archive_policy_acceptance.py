"""Independent acceptance tests for the KNOW-LEGACY-001 archived read boundary."""

from __future__ import annotations

import copy
import json
import pickle
from datetime import UTC, datetime
from decimal import Decimal, localcontext
from email.utils import format_datetime

import pytest
from pydantic import BaseModel

import leviathan_core.knowledge_sync.archive_models as archive_models
import leviathan_core.knowledge_sync.archive_policy as archive_policy
from leviathan_core.knowledge_sync.archive_models import (
    ArchivedQueryV1,
    ArchivedReadDecisionV1,
    ArchivedRecordV1,
    ArchivePolicyError,
)
from leviathan_core.knowledge_sync.archive_policy import (
    deny_archived_write,
    parse_archived_query,
    read_archived_detail,
    read_archived_list,
)
from leviathan_core.seal import SealError, verify
from leviathan_core.security.authz_models import (
    _VERIFIER_MARKER,
    PrincipalV1,
    TrustedPrincipalAdapterV1,
    TrustedPrincipalV1,
)

ORG = "synthetic-org-a"
OTHER_ORG = "synthetic-org-b"
NOW_NS = 1_800_000_000_000_000_000
SUNSET_NS = 1_850_000_000_000_000_000
READ_TAG = "know_legacy001.read.v1"
DENIAL_TAG = "know_legacy001.denial.v1"


def principal(*, org: str = ORG, roles: tuple[str, ...] = ("audit",)) -> TrustedPrincipalV1:
    claims = PrincipalV1(
        principal_id="synthetic-auditor",
        project_id=org,
        roles=roles,
        env="paper",
    )
    return TrustedPrincipalAdapterV1.from_verified_claims(
        claims,
        verifier_marker=_VERIFIER_MARKER,
    )


def record(
    sequence: int,
    *,
    org: str = ORG,
    created_ns: int | None = None,
    updated_ns: int | None = None,
    payload_json: str | None = None,
    tags: tuple[str, ...] = ("legacy",),
) -> ArchivedRecordV1:
    instant = sequence if created_ns is None else created_ns
    payload = (
        '{"public":"visible","api_key":"SYNTHETIC_SECRET_CANARY",'
        '"nested":{"connection_string":"SYNTHETIC_DSN_CANARY","db_conn":"SYNTHETIC_DB_CONN_CANARY","db_uri":"SYNTHETIC_DB_URI_CANARY","db_url":"SYNTHETIC_DB_URL_CANARY",'
        '"Auth":{"token":"SYNTHETIC_TOKEN_CANARY"},"count":3}}'
        if payload_json is None
        else payload_json
    )
    return ArchivedRecordV1(
        schema_version="1",
        org_id=org,
        record_id=f"00000000-0000-0000-0000-{sequence:012d}",
        source_type="api",
        created_at_ns=instant,
        updated_at_ns=instant if updated_ns is None else updated_ns,
        tags=tags,
        payload_json=payload,
        status="archived",
    )


def query(**fields: object) -> ArchivedQueryV1:
    return ArchivedQueryV1(schema_version="1", **fields)


def read_list(
    records: tuple[ArchivedRecordV1, ...],
    *,
    who: object | None = None,
    org: str = ORG,
    q: ArchivedQueryV1 | None = None,
    etag: str | None = None,
    now_ns: int = NOW_NS,
) -> object:
    return read_archived_list(
        principal() if who is None else who,
        org,
        records,
        query() if q is None else q,
        now_ns=now_ns,
        sunset_at_ns=SUNSET_NS,
        if_none_match=etag,
    )


def headers_map(decision: object) -> dict[str, str]:
    return dict(decision.headers)  # type: ignore[attr-defined]


def test_all_write_and_execute_verbs_are_archived_410_with_successors() -> None:
    verbs = (
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "START_RUN",
        "QUEUE_RUN",
        "RETRY_RUN",
        "UPLOAD",
        "post",
    )

    for method in verbs:
        denial = deny_archived_write(method, now_ns=NOW_NS, sunset_at_ns=SUNSET_NS)
        headers = headers_map(denial)
        assert denial.status_code == 410
        assert denial.code == "LEGACY_ARCHIVED"
        assert verify(denial, DENIAL_TAG)
        assert set(headers) == {"Deprecation", "Sunset", "Link"}
        assert headers["Deprecation"] == "true"
        expected_sunset = format_datetime(
            datetime.fromtimestamp(SUNSET_NS // 1_000_000_000, UTC),
            usegmt=True,
        )
        assert headers["Sunset"] == expected_sunset
        assert headers["Sunset"].endswith("GMT")
        assert headers["Link"].count('rel="successor-version"') == 2
        assert headers["Link"].count(".invalid") == 2
        assert "SYNTHETIC" not in denial.body_json


def test_only_verified_read_roles_are_allowed_and_headers_cover_error_results() -> None:
    accepted = ("admin", "operator", "audit", "strategy", "research", "readonly-market")

    for role in accepted:
        result = read_list((record(1),), who=principal(roles=(role,)))
        assert result.status_code == 200
        assert set(headers_map(result)) == {"Deprecation", "Sunset", "Link"}

    assert read_list((record(1),), who=object()).status_code == 401
    denied = read_list((record(1),), who=principal(roles=("trader",)))
    assert denied.status_code == 403
    assert set(headers_map(denied)) == {"Deprecation", "Sunset", "Link"}


def test_unissued_or_equal_subclass_principal_cannot_borrow_verified_identity() -> None:
    class EqualPrincipal(TrustedPrincipalV1):
        def __eq__(self, other: object) -> bool:
            return True

        def __hash__(self) -> int:
            return 1

    forged = object.__new__(EqualPrincipal)
    object.__setattr__(forged, "principal_id", "synthetic-auditor")
    object.__setattr__(forged, "project_id", ORG)
    object.__setattr__(forged, "roles", ("audit",))
    object.__setattr__(forged, "env", "paper")
    object.__setattr__(forged, "venue", None)
    object.__setattr__(forged, "portfolio", None)
    object.__setattr__(forged, "strategy", None)
    object.__setattr__(forged, "break_glass", False)

    assert forged == principal()
    assert read_list((record(1),), who=forged).status_code == 401


def test_foreign_tenant_and_missing_detail_are_indistinguishable() -> None:
    options = {"now_ns": NOW_NS, "sunset_at_ns": SUNSET_NS}
    missing = read_archived_detail(principal(), ORG, None, **options)
    foreign = read_archived_detail(
        principal(),
        ORG,
        record(2, org=OTHER_ORG),
        **options,
    )
    other_principal = read_archived_detail(
        principal(org=OTHER_ORG),
        ORG,
        record(2, org=OTHER_ORG),
        **options,
    )

    assert missing.status_code == foreign.status_code == other_principal.status_code == 404
    assert missing.body_json == foreign.body_json
    assert foreign.etag is None
    assert OTHER_ORG not in foreign.body_json


def test_list_never_exposes_foreign_records_or_foreign_existence() -> None:
    own = record(1)
    foreign = record(2, org=OTHER_ORG)
    decision = read_list((own, foreign))

    assert decision.status_code == 200
    assert decision.record_count == 1
    assert "000000000001" in decision.body_json
    assert "000000000002" not in decision.body_json
    assert OTHER_ORG not in decision.body_json


def test_nested_credentials_are_redacted_before_body_and_etag() -> None:
    first = record(
        1,
        payload_json=(
            '{"public":"keep","api_key":"FIRST_SECRET_MARKER",'
            '"nested":{"connection_string":"FIRST_DSN_MARKER","db_conn":"FIRST_DB_CONN_MARKER","db_uri":"FIRST_DB_URI_MARKER","db_url":"FIRST_DB_URL_MARKER",'
            '"Auth":{"token":"FIRST_TOKEN_MARKER"},"safe":7}}'
        ),
    )
    second = record(
        1,
        payload_json=(
            '{"public":"keep","api_key":"SECOND_SECRET_MARKER",'
            '"nested":{"connection_string":"SECOND_DSN_MARKER","db_conn":"SECOND_DB_CONN_MARKER","db_uri":"SECOND_DB_URI_MARKER","db_url":"SECOND_DB_URL_MARKER",'
            '"Auth":{"token":"SECOND_TOKEN_MARKER"},"safe":7}}'
        ),
    )
    one = read_list((first,))
    two = read_list((second,))

    assert one.status_code == 200
    assert one.etag == two.etag
    parsed = json.loads(one.body_json)
    visible = parsed["data"][0]["data"]
    _assert_masked_leaf_values(visible)
    for marker in (
        "FIRST_SECRET_MARKER",
        "FIRST_DSN_MARKER",
        "FIRST_TOKEN_MARKER",
        "FIRST_DB_CONN_MARKER",
        "FIRST_DB_URI_MARKER",
        "FIRST_DB_URL_MARKER",
        "SECOND_SECRET_MARKER",
        "SECOND_DSN_MARKER",
        "SECOND_TOKEN_MARKER",
        "SECOND_DB_CONN_MARKER",
        "SECOND_DB_URI_MARKER",
        "SECOND_DB_URL_MARKER",
    ):
        assert marker not in one.body_json
        assert marker not in one.etag


def _assert_masked_leaf_values(value: object) -> None:
    if isinstance(value, dict):
        for child in value.values():
            _assert_masked_leaf_values(child)
    elif isinstance(value, list):
        for child in value:
            _assert_masked_leaf_values(child)
    else:
        assert value == "****"


def test_empty_allowlist_masks_every_leaf_and_all_reviewer_canaries() -> None:
    canaries = (
        "CANARY_PASS",
        "CANARY_PASSWD",
        "CANARY_PW",
        "postgresql://admin:CANARY_DBPASS@db.internal:5432/prod",
        "https://example.invalid/config?api_key=CANARY_QS_KEY",
        "Bearer CANARY_BEARER",
        "CANARY_KEYS_LIST",
        "CANARY_SIG",
        "session=CANARY_COOKIE",
        "eyJ_CANARY_JWT",
        "CANARY_HOMOGLYPH",
        "notes contain password CANARY_NOTE_PASS",
    )
    # The key contains Cyrillic small a (U+0430) in the attempted password key.
    payload_json = json.dumps(
        {
            "auth": {"pass": canaries[0]},
            "passwd": canaries[1],
            "pw": canaries[2],
            "db": canaries[3],
            "url": canaries[4],
            "headers": [["Authorization", canaries[5]]],
            "keys": [canaries[6]],
            "signature": canaries[7],
            "cookie": canaries[8],
            "jwt": canaries[9],
            "p\u0430ssword": canaries[10],
            "notes": canaries[11],
            "ordinary": {"count": 7, "enabled": False, "missing": None},
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )
    result = read_list((record(1, payload_json=payload_json),))

    assert result.status_code == 200
    payload_view = json.loads(result.body_json)["data"][0]["data"]
    _assert_masked_leaf_values(payload_view)
    assert "ordinary" in payload_view and "missing" in payload_view["ordinary"]
    for canary in canaries:
        assert canary not in result.body_json
        assert canary not in result.etag


@pytest.mark.parametrize("form", ["weak", "list", "star"])
def test_if_none_match_weak_list_and_star_forms_return_authorized_304(form: str) -> None:
    item = record(1, payload_json='{"status":"synthetic"}')
    strong = read_list((item,))
    if form == "weak":
        condition = "W/" + strong.etag
    elif form == "list":
        condition = '"different", ' + strong.etag + ', "another"'
    else:
        condition = "*"

    result = read_list((item,), etag=condition)

    assert result.status_code == 304
    assert result.body_json is None
    assert result.etag == strong.etag
    assert verify(result, READ_TAG)

    unauthorized = read_list((item,), who=principal(roles=("trader",)), etag="*")
    assert unauthorized.status_code == 403
    assert unauthorized.body_json is not None


def test_list_filters_and_paginates_before_parsing_payloads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = record(1, created_ns=100, payload_json='{"visible":"page"}')
    later_page = record(2, created_ns=200, payload_json='{"visible":"later"}')
    foreign = record(3, org=OTHER_ORG, created_ns=150, payload_json='{"foreign":1}')
    future = record(4, created_ns=600, payload_json='{"future":1}')
    tag_mismatch = record(
        5,
        created_ns=125,
        payload_json='{"filtered":"tag"}',
        tags=("other",),
    )
    parsed: list[object] = []
    original_load_payload = archive_models.load_payload

    def track_payload(value: object) -> dict[str, object]:
        parsed.append(value)
        return original_load_payload(value)

    monkeypatch.setattr(archive_models, "load_payload", track_payload)
    monkeypatch.setattr(archive_policy, "load_payload", track_payload)
    result = read_list(
        (later_page, foreign, future, tag_mismatch, selected),
        q=query(limit=1, tag="legacy"),
        now_ns=500,
    )

    assert result.record_count == 1
    assert "000000000001" in result.body_json
    assert set(parsed) == {selected.payload_json}
    assert len(parsed) <= 2


def test_unknown_filters_are_ignored_with_generic_warning_and_no_name_leak() -> None:
    canary_filter = "customer_secret_filter"
    parsed = parse_archived_query({canary_filter: "value"})
    result = read_list((record(1),), q=parsed)

    assert parsed.limit == 50
    assert parsed.warnings == ("IGNORED_UNKNOWN_FILTER",)
    assert result.warnings == ("IGNORED_UNKNOWN_FILTER",)
    assert canary_filter not in result.body_json
    assert canary_filter not in result.etag


def test_cursor_limits_default_one_and_two_hundred() -> None:
    default = parse_archived_query({})
    assert default.limit == 50

    one = parse_archived_query({"limit": "1"})
    two_hundred = parse_archived_query({"limit": "200"})
    rows = tuple(record(index, created_ns=index) for index in range(1, 202))

    first_page = read_list(rows, q=one)
    assert first_page.record_count == 1
    assert first_page.next_cursor == "1"

    max_page = read_list(rows, q=two_hundred)
    assert max_page.record_count == 200
    assert max_page.next_cursor == "200"

    next_page = read_list(rows, q=query(limit=1, cursor=max_page.next_cursor))
    assert next_page.record_count == 1
    assert next_page.next_cursor is None


@pytest.mark.parametrize("limit", ["0", "201", "1.5", "true", "-1", "0001"])
def test_out_of_range_or_noncanonical_limit_is_rejected(limit: str) -> None:
    with pytest.raises((ArchivePolicyError, SealError)) as caught:
        parse_archived_query({"limit": limit})
    assert caught.value.code in {"INVALID_LIMIT", "SEAL_INVALID_MODEL"}
    assert limit not in str(caught.value)


def test_created_time_filters_apply_to_the_immutable_snapshot() -> None:
    snapshot = (
        record(1, created_ns=100),
        record(2, created_ns=200),
        record(3, created_ns=300),
    )
    before = tuple(item.model_dump() for item in snapshot)
    q = parse_archived_query({"created_after": "150", "created_before": "250"})
    decision = read_list(snapshot, q=q, now_ns=250)

    assert decision.record_count == 1
    assert "000000000002" in decision.body_json
    assert "000000000001" not in decision.body_json
    assert "000000000003" not in decision.body_json
    assert tuple(item.model_dump() for item in snapshot) == before


def test_future_created_or_updated_records_are_hidden_before_pagination() -> None:
    now = 500
    snapshot = (
        record(1, created_ns=100, updated_ns=200),
        record(2, created_ns=600, updated_ns=600),
        record(3, created_ns=300, updated_ns=600),
    )
    before = tuple(item.model_dump() for item in snapshot)

    decision = read_list(snapshot, q=query(limit=1), now_ns=now)

    assert decision.status_code == 200
    assert decision.record_count == 1
    assert "000000000001" in decision.body_json
    assert "000000000002" not in decision.body_json
    assert "000000000003" not in decision.body_json
    assert decision.next_cursor is None
    assert tuple(item.model_dump() for item in snapshot) == before


def test_matching_etag_is_304_and_body_change_changes_etag() -> None:
    first = read_list((record(1, payload_json='{"public":1,"token":"one"}'),))
    same = read_list((record(1, payload_json='{"public":1,"token":"another"}'),))
    changed = read_list((record(1, payload_json='{"public":2,"token":"another","extra":true}'),))
    not_modified = read_list(
        (record(1, payload_json='{"public":1,"token":"other-secret"}'),),
        etag=first.etag,
    )

    assert first.etag == same.etag
    assert first.etag != changed.etag
    assert not_modified.status_code == 304
    assert not_modified.body_json is None
    assert not_modified.etag == first.etag
    assert verify(not_modified, READ_TAG)
    assert set(headers_map(not_modified)) == {"Deprecation", "Sunset", "Link"}


def test_etag_is_stable_under_decimal_context_and_exact_json_numbers() -> None:
    exact_json = '{"amount":0.100000000000000000000000000001,"description":"synthetic"}'
    item = record(1, payload_json=exact_json)

    with localcontext() as context:
        context.prec = 6
        low_precision = read_list((item,))
    with localcontext() as context:
        context.prec = 60
        high_precision = read_list((item,))

    exact_input = archive_models.load_payload(exact_json)
    assert exact_input["amount"] == Decimal("0.100000000000000000000000000001")
    assert low_precision.etag == high_precision.etag
    visible = json.loads(low_precision.body_json, parse_float=Decimal)
    assert visible["data"][0]["data"]["amount"] == "****"
    assert "0.100000000000000000000000000001" not in low_precision.body_json


def test_bad_versions_types_times_and_snapshots_fail_with_safe_codes() -> None:
    with pytest.raises(SealError):
        ArchivedQueryV1(limit=50)  # schema_version is mandatory
    with pytest.raises(SealError) as caught:
        ArchivedQueryV1(schema_version="1", limit=True)
    assert caught.value.code == "SEAL_INVALID_MODEL"

    with pytest.raises(SealError) as caught:
        record(4, created_ns=True)
    assert caught.value.code == "SEAL_INVALID_MODEL"

    with pytest.raises(ArchivePolicyError) as caught:
        read_archived_list(
            principal(),
            ORG,
            (None,),  # type: ignore[arg-type]
            query(),
            now_ns=NOW_NS,
            sunset_at_ns=SUNSET_NS,
        )
    assert caught.value.code == "INVALID_RECORD"

    with pytest.raises(ArchivePolicyError) as caught:
        read_archived_list(
            principal(),
            ORG,
            (record(1),),
            None,  # type: ignore[arg-type]
            now_ns=NOW_NS,
            sunset_at_ns=SUNSET_NS,
        )
    assert caught.value.code == "INVALID_QUERY"

    for hostile_json in (
        "[]",
        '{"value":NaN}',
        '{"value":Infinity}',
        '{"nested":' + "[" * 1500 + "0" + "]" * 1500 + "}",
        '{"amount":' + "9" * 100 + "}",
    ):
        with pytest.raises((ArchivePolicyError, SealError)):
            record(5, payload_json=hostile_json)


def test_public_input_records_cannot_be_mutated_or_copied_to_bypass_validation() -> None:
    item = record(1)

    with pytest.raises(SealError):
        item.org_id = OTHER_ORG
    with pytest.raises(SealError):
        del item.status
    with pytest.raises(SealError):
        copy.copy(item)
    with pytest.raises(SealError):
        copy.deepcopy(item)
    with pytest.raises(SealError):
        pickle.dumps(item)
    with pytest.raises(SealError):
        item.copy(update={"status": "active"})
    with pytest.raises(SealError):
        item.model_copy(update={"status": "active"})
    with pytest.raises(SealError):
        ArchivedRecordV1.model_construct(
            schema_version="1",
            org_id=ORG,
            record_id="00000000-0000-0000-0000-000000000001",
            source_type="api",
            created_at_ns=1,
            updated_at_ns=1,
            tags=(),
            payload_json="{}",
            status="archived",
        )


def test_issued_decisions_reject_reinitialization_state_and_copy_paths() -> None:
    decision = read_list((record(1),))
    original_body = decision.body_json

    with pytest.raises(SealError):
        BaseModel.__init__(
            decision,
            schema_version="1",
            status_code=401,
            body_json=None,
            etag=None,
            next_cursor=None,
            warnings=(),
            headers=decision.headers,
            record_count=0,
        )
    with pytest.raises(SealError):
        copy.copy(decision)
    with pytest.raises(SealError):
        copy.deepcopy(decision)
    with pytest.raises(SealError):
        pickle.dumps(decision)
    with pytest.raises(SealError):
        decision.copy(update={"status_code": 401})
    with pytest.raises(SealError):
        decision.model_construct(status_code=401)

    assert decision.body_json == original_body
    assert verify(decision, READ_TAG)


def test_issued_result_tampering_is_detected_on_every_export() -> None:
    decision = read_list((record(1),))
    object.__setattr__(decision, "body_json", '{"tampered":"SYNTHETIC_CANARY"}')

    assert not verify(decision, READ_TAG)
    with pytest.raises(SealError):
        decision.model_dump()


def test_write_denial_input_and_successor_output_are_not_mutable() -> None:
    denial = deny_archived_write("POST", now_ns=NOW_NS, sunset_at_ns=SUNSET_NS)

    with pytest.raises(SealError):
        denial.status_code = 200
    with pytest.raises(SealError) as caught:
        object.__setattr__(denial, "__dict__", {"status_code": 200})
    assert caught.value.code == "SEAL_FORBIDDEN_OPERATION"
    assert verify(denial, DENIAL_TAG)
    assert denial.status_code == 410


def test_wrong_public_types_fail_with_safe_errors() -> None:
    with pytest.raises(ArchivePolicyError) as caught:
        parse_archived_query(None)  # type: ignore[arg-type]
    assert caught.value.code == "INVALID_QUERY"
    assert (
        read_archived_list(
            None, ORG, (record(1),), query(), now_ns=NOW_NS, sunset_at_ns=SUNSET_NS
        ).status_code
        == 401
    )
    with pytest.raises(ArchivePolicyError) as caught:
        deny_archived_write(None, now_ns=NOW_NS, sunset_at_ns=SUNSET_NS)  # type: ignore[arg-type]
    assert caught.value.code == "INVALID_METHOD"


def test_direct_unissued_read_decision_does_not_acquire_policy_authority() -> None:
    forged = ArchivedReadDecisionV1(
        schema_version="1",
        status_code=200,
        body_json="{}",
        etag='"' + "a" * 64 + '"',
        next_cursor=None,
        warnings=(),
        headers=(),
        record_count=0,
    )
    assert not verify(forged, READ_TAG)


def test_base_setstate_tampering_is_rejected_immediately() -> None:
    decision = read_list((record(1),))
    with pytest.raises(SealError) as caught:
        BaseModel.__setstate__(decision, {"status_code": 401})
    assert caught.value.code == "SEAL_FORBIDDEN_OPERATION"
    assert "401" not in str(caught.value)
    assert verify(decision, READ_TAG)
    assert decision.status_code == 200

    empty_state = read_list((record(2),))
    with pytest.raises(SealError) as caught:
        BaseModel.__setstate__(empty_state, {})
    assert caught.value.code == "SEAL_FORBIDDEN_OPERATION"
    assert verify(empty_state, READ_TAG)
    assert json.loads(empty_state.model_dump_json())["status_code"] == 200
