from __future__ import annotations

import copy
import pickle
from dataclasses import replace

import pytest

from leviathan_core.knowledge_sync.archive_models import ArchivedQueryV1, ArchivedRecordV1
from leviathan_core.knowledge_sync.archive_policy import (
    read_archived_detail,
    read_archived_list,
)
from leviathan_core.security.authz_models import (
    _VERIFIER_MARKER,
    PrincipalV1,
    TrustedPrincipalAdapterV1,
    TrustedPrincipalV1,
)

ORG = "synthetic-knowlegacy-org"
NOW_NS = 1_791_288_000_000_000_000
SUNSET_NS = 1_800_000_000_000_000_000
RECORD_ID = "00000000-0000-0000-0000-000000000001"


def _issued_principal() -> TrustedPrincipalV1:
    claims = PrincipalV1(
        principal_id="synthetic-archive-reader",
        project_id=ORG,
        roles=("audit",),
        env="paper",
    )
    return TrustedPrincipalAdapterV1.from_verified_claims(
        claims,
        verifier_marker=_VERIFIER_MARKER,
    )


def _hand_built_principal() -> TrustedPrincipalV1:
    forged = object.__new__(TrustedPrincipalV1)
    for name, value in (
        ("principal_id", "synthetic-archive-reader"),
        ("project_id", ORG),
        ("roles", ("audit",)),
        ("env", "paper"),
        ("venue", None),
        ("portfolio", None),
        ("strategy", None),
        ("break_glass", False),
    ):
        object.__setattr__(forged, name, value)
    return forged


def _record() -> ArchivedRecordV1:
    return ArchivedRecordV1(
        schema_version="1",
        org_id=ORG,
        record_id=RECORD_ID,
        source_type="api",
        created_at_ns=NOW_NS - 2,
        updated_at_ns=NOW_NS - 1,
        tags=("synthetic", "legacy"),
        payload_json='{"summary":"synthetic archived result"}',
        status="archived",
    )


def _decision(principal: object) -> object:
    return read_archived_list(
        principal,
        ORG,
        (_record(),),
        ArchivedQueryV1(schema_version="1"),
        now_ns=NOW_NS,
        sunset_at_ns=SUNSET_NS,
    )


def _detail_decision(principal: object) -> object:
    return read_archived_detail(
        principal,
        ORG,
        _record(),
        now_ns=NOW_NS,
        sunset_at_ns=SUNSET_NS,
    )


def _shape(decision: object) -> tuple[object, ...]:
    return (
        decision.status_code,  # type: ignore[attr-defined]
        decision.body_json,  # type: ignore[attr-defined]
        decision.etag,  # type: ignore[attr-defined]
        decision.next_cursor,  # type: ignore[attr-defined]
        decision.warnings,  # type: ignore[attr-defined]
        decision.headers,  # type: ignore[attr-defined]
        decision.record_count,  # type: ignore[attr-defined]
    )


def test_issued_auditor_principal_keeps_archive_read_access() -> None:
    decision = _decision(_issued_principal())
    detail = _detail_decision(_issued_principal())

    assert decision.status_code == 200  # type: ignore[attr-defined]
    assert decision.record_count == 1  # type: ignore[attr-defined]
    assert RECORD_ID in decision.body_json  # type: ignore[attr-defined]
    assert detail.status_code == 200  # type: ignore[attr-defined]
    assert RECORD_ID in detail.body_json  # type: ignore[attr-defined]


@pytest.mark.parametrize("forgery", ["object_new", "tamper_after_issue"])
def test_unissued_or_tampered_principal_gets_uniform_archive_denial(
    forgery: str,
) -> None:
    if forgery == "object_new":
        candidate = _hand_built_principal()
    else:
        candidate = _issued_principal()
        object.__setattr__(candidate, "roles", ("audit", "admin"))

    anonymous = _decision(None)
    denied = _decision(candidate)
    anonymous_detail = _detail_decision(None)
    denied_detail = _detail_decision(candidate)

    assert anonymous.status_code == 401  # type: ignore[attr-defined]
    assert _shape(denied) == _shape(anonymous)
    assert ORG not in (denied.body_json or "")  # type: ignore[attr-defined]
    assert _shape(denied_detail) == _shape(anonymous_detail)


def test_constructor_and_dataclass_replace_cannot_mint_a_principal() -> None:
    issued = _issued_principal()

    with pytest.raises(TypeError):
        TrustedPrincipalV1(
            principal_id="synthetic-archive-reader",
            project_id=ORG,
            roles=("audit",),
            env="paper",
            venue=None,
            portfolio=None,
            strategy=None,
            break_glass=False,
        )
    with pytest.raises(TypeError):
        replace(issued, roles=("audit", "admin"))


def test_copy_and_pickle_cannot_create_a_usable_principal() -> None:
    issued = _issued_principal()

    with pytest.raises(TypeError):
        copy.copy(issued)
    with pytest.raises(TypeError):
        copy.deepcopy(issued)
    with pytest.raises(TypeError):
        pickle.loads(pickle.dumps(issued))
