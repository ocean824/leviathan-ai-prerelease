"""CL-KNOWLEGACY-SEAL: archive policy decides access only for issued principals."""

from __future__ import annotations

import copy
import pickle
from dataclasses import replace

import pytest

from leviathan_core.knowledge_sync.archive_models import ArchivedQueryV1, ArchivedRecordV1
from leviathan_core.knowledge_sync.archive_policy import read_archived_list
from leviathan_core.security.authz_models import (
    _VERIFIER_MARKER,
    PrincipalV1,
    TrustedPrincipalAdapterV1,
    TrustedPrincipalV1,
    is_trusted_principal,
)

ORG = "synthetic-org-a"
NOW_NS = 1_800_000_000_000_000_000
SUNSET_NS = 1_850_000_000_000_000_000
_FIELDS = ("principal_id", "project_id", "roles", "env", "venue", "portfolio", "strategy",
           "break_glass")


def _claims(*, org: str = ORG, roles: tuple[str, ...] = ("audit",)) -> PrincipalV1:
    return PrincipalV1(principal_id="synthetic-auditor", project_id=org, roles=roles, env="paper")


def _issued(**kwargs: object) -> TrustedPrincipalV1:
    return TrustedPrincipalAdapterV1.from_verified_claims(
        _claims(**kwargs), verifier_marker=_VERIFIER_MARKER  # type: ignore[arg-type]
    )


def _hand_built(**kwargs: object) -> TrustedPrincipalV1:
    claims = _claims(**kwargs)  # type: ignore[arg-type]
    principal = object.__new__(TrustedPrincipalV1)
    for name in _FIELDS:
        object.__setattr__(principal, name, getattr(claims, name))
    return principal


def _records() -> tuple[ArchivedRecordV1, ...]:
    return (ArchivedRecordV1(
        schema_version="1", org_id=ORG, record_id="00000000-0000-0000-0000-000000000001",
        source_type="api", created_at_ns=1, updated_at_ns=1, tags=("legacy",),
        payload_json='{"public":"visible"}', status="archived",
    ),)


def _read(principal: object, org: str = ORG) -> tuple[int, str | None, int]:
    decision = read_archived_list(
        principal, org, _records(), ArchivedQueryV1(schema_version="1"),
        now_ns=NOW_NS, sunset_at_ns=SUNSET_NS,
    )
    return decision.status_code, decision.body_json, decision.record_count


def test_issued_principals_keep_their_existing_results() -> None:
    status, body, count = _read(_issued())
    assert (status, count) == (200, 1)
    assert body is not None and "00000000-0000-0000-0000-000000000001" in body
    assert _read(_issued(roles=("viewer",)))[0] == 403  # no read role
    assert _read(_issued(org="synthetic-org-b"))[0] == 404  # other org's scope


def test_forged_principals_get_the_same_denial_as_no_principal() -> None:
    expected = _read(None)
    assert expected[0] == 401 and expected[2] == 0
    forged = _hand_built()  # right org and a read role: would be allowed if trusted
    assert not is_trusted_principal(forged)
    assert _read(forged) == expected
    # No distinguishing leak: wrong-org and role-less forgeries answer the same way.
    assert _read(_hand_built(org="synthetic-org-b")) == expected
    assert _read(_hand_built(roles=("viewer",))) == expected


def test_a_subclass_instance_cannot_borrow_issued_standing() -> None:
    class Twin(TrustedPrincipalV1):
        def __eq__(self, other: object) -> bool:
            return True

        def __hash__(self) -> int:
            return 1

    twin = object.__new__(Twin)
    for name in _FIELDS:
        object.__setattr__(twin, name, getattr(_issued(), name))
    assert _read(twin) == _read(None)


def test_tampering_after_issue_denies_even_with_a_matching_role() -> None:
    weak = _issued(roles=("viewer",))
    assert _read(weak)[0] == 403
    object.__setattr__(weak, "roles", ("audit",))  # escalate after issuance
    assert _read(weak) == _read(None)
    moved = _issued()
    object.__setattr__(moved, "project_id", "synthetic-org-b")
    assert _read(moved, "synthetic-org-b") == _read(None)
    retuple = _issued()
    object.__setattr__(retuple, "roles", list(retuple.roles))  # tuple -> list swap
    assert _read(retuple) == _read(None)


def test_copy_replace_and_pickle_cannot_mint_a_principal() -> None:
    principal = _issued()
    with pytest.raises(TypeError):
        copy.copy(principal)
    with pytest.raises(TypeError):
        copy.deepcopy(principal)
    with pytest.raises(TypeError):
        pickle.dumps(principal)
    with pytest.raises(TypeError):
        replace(principal, roles=("admin",))
    with pytest.raises(TypeError):
        TrustedPrincipalV1(**{name: "x" for name in _FIELDS})  # type: ignore[arg-type]
    assert _read(principal)[0] == 200  # the original is untouched
