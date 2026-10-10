from __future__ import annotations

import ast
import os
from pathlib import Path
from runpy import run_path
from typing import Any

import pytest

WORKTREE = Path(__file__).resolve().parents[3]
SOURCE_ROOT = Path(os.environ.get("CREDENTIAL_ACCEPTANCE_SOURCE_ROOT", str(WORKTREE))).resolve()
API = SOURCE_ROOT / "apps/api/src/leviathan_api"
CORE_TESTS = SOURCE_ROOT / "packages/leviathan-core/tests/security/test_principal_verifier.py"
WORKER = SOURCE_ROOT / "workers/licensing/src/worker/compose.ts"
LIVE_ACCEPTANCE = SOURCE_ROOT / "apps/api/tests/test_live_activation_acceptance.py"


@pytest.fixture(scope="module")
def verifier_helpers() -> dict[str, Any]:
    return run_path(str(CORE_TESTS))


@pytest.fixture(scope="module")
def synthetic_key(verifier_helpers: dict[str, Any]) -> tuple[Any, int]:
    fixture = verifier_helpers["synthetic_key"]
    return fixture.__wrapped__()


def test_import_origin_matches_requested_worktree_when_configured() -> None:
    expected_worktree = os.environ.get("LEVIATHAN_ACCEPTANCE_WORKTREE")
    if not expected_worktree:
        pytest.skip("set LEVIATHAN_ACCEPTANCE_WORKTREE to verify import origin")

    import leviathan_api.routers.live_activation as activation
    import leviathan_core.security.principal_verifier as verifier

    expected_root = Path(expected_worktree).resolve()
    assert Path(activation.__file__).resolve().is_relative_to(expected_root), activation.__file__
    assert Path(verifier.__file__).resolve().is_relative_to(expected_root), verifier.__file__


def test_signed_device_claim_is_the_only_principal_device_source(
    verifier_helpers: dict[str, Any], synthetic_key: tuple[Any, int]
) -> None:
    verifier = verifier_helpers["_verifier"](synthetic_key[0])
    token = verifier_helpers["_token"](
        synthetic_key,
        claims=verifier_helpers["_claims"]() | {"device_id": "device.signed"},
    )
    verified = verifier.verify(token)
    trusted = verifier.to_trusted_principal(verified)
    assert verified.device_id == "device.signed"
    assert trusted.device_id == "device.signed"

    no_claim = verifier.verify(verifier_helpers["_token"](synthetic_key))
    assert no_claim.device_id is None
    assert verifier.to_trusted_principal(no_claim).device_id is None

    forged_claim = verifier_helpers["_token"](
        synthetic_key,
        claims=verifier_helpers["_claims"]() | {"device_id": "device.signed"},
        bad_signature=True,
    )
    from leviathan_core.security.principal_verifier import PrincipalVerificationError

    with pytest.raises(PrincipalVerificationError, match=r"^TOKEN_REJECTED$"):
        verifier.verify(forged_claim)


def test_expired_device_claim_is_rejected_by_verifier(
    verifier_helpers: dict[str, Any], synthetic_key: tuple[Any, int]
) -> None:
    claims = verifier_helpers["_claims"]() | {
        "device_id": "device.signed",
        "iat": verifier_helpers["NOW_SECONDS"] - 900,
        "nbf": verifier_helpers["NOW_SECONDS"] - 900,
        "exp": verifier_helpers["NOW_SECONDS"] - 61,
    }
    token = verifier_helpers["_token"](synthetic_key, claims=claims)
    from leviathan_core.security.principal_verifier import PrincipalVerificationError

    with pytest.raises(PrincipalVerificationError, match=r"^TOKEN_REJECTED$"):
        verifier_helpers["_verifier"](synthetic_key[0]).verify(token)


def test_missing_or_mismatched_device_denies_before_live_preconditions_or_events(
    verifier_helpers: dict[str, Any], synthetic_key: tuple[Any, int]
) -> None:
    helpers = run_path(str(LIVE_ACCEPTANCE))
    make_client = helpers["make_client"]
    enable = helpers["enable"]
    verifier = verifier_helpers["_verifier"](synthetic_key[0])
    owner_claims = verifier_helpers["_claims"]() | {"sub": "owner-1"}
    signed_principals = (
        verifier.to_trusted_principal(
            verifier.verify(verifier_helpers["_token"](synthetic_key, claims=owner_claims))
        ),
        verifier.to_trusted_principal(
            verifier.verify(
                verifier_helpers["_token"](
                    synthetic_key,
                    claims=owner_claims | {"device_id": "device-other"},
                )
            )
        ),
    )
    for trusted in signed_principals:
        client, evidence, log = make_client(trusted=trusted)
        response = enable(client)
        assert response.status_code == 404
        assert response.json() == {"error": {"code": "ACCOUNT_NOT_FOUND"}}
        assert evidence.open_orders_calls == []
        assert log.events == []


def test_forged_request_device_is_rejected_before_any_activation_side_effect() -> None:
    helpers = run_path(str(LIVE_ACCEPTANCE))
    client, evidence, log = helpers["make_client"](trusted=helpers["principal"]())
    response = helpers["enable"](
        client,
        {
            "account_id": helpers["ACCOUNT"],
            "confirmation": f"ENABLE LIVE {helpers['ACCOUNT']}",
            "device_id": "device.forged",
        },
    )
    assert response.status_code == 422
    assert response.json() == {"error": {"code": "INVALID_REQUEST"}}
    assert evidence.open_orders_calls == []
    assert log.events == []


def test_entitled_non_admin_can_activate_own_device_bound_account() -> None:
    helpers = run_path(str(LIVE_ACCEPTANCE))
    user = helpers["principal"](("user",), device_id="device-1")
    client, _, log = helpers["make_client"](trusted=user)
    response = helpers["enable"](client)
    assert response.status_code == 200
    assert response.json()["effective_state"] == "LIVE"
    assert [event.event_type for event in log.events] == ["ACTIVATION_REQUESTED", "ENABLED"]


def test_live_activation_policy_has_no_owner_or_admin_role_gate() -> None:
    tree = ast.parse(API.joinpath("routers/live_activation.py").read_text(encoding="utf-8"))
    blockers = next(
        node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "_blockers"
    )
    assert not any(
        isinstance(node, ast.FunctionDef) and node.name == "_is_owner" for node in tree.body
    )
    assert "_is_owner" not in ast.unparse(blockers)


def test_worker_enforces_device_signature_expiry_and_active_records() -> None:
    source = WORKER.read_text(encoding="utf-8")
    verifier = source.split("async function verifyInternalDeviceToken", maxsplit=1)[1].split(
        "/** Build all production ports", maxsplit=1
    )[0]
    assert "crypto.subtle.verify" in verifier
    assert "BigInt(claims.exp_utc_ns) <= BigInt(utcNs())" in verifier
    assert "d.status='ACTIVE'" in verifier
    assert "o.active=TRUE" in verifier and "s.status='ACTIVE'" in verifier
    assert "device_id: claims.device_id" in verifier


def test_worker_source_is_the_writer_worktree() -> None:
    assert WORKER.resolve().is_relative_to(WORKTREE), WORKER
