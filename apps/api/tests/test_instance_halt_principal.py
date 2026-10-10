"""The desktop shell session is the sole principal source for HALT lift."""

from __future__ import annotations

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from starlette.requests import Request

from leviathan_api.auth import make_local_operator_profile
from leviathan_api.main import create_app
from leviathan_api.routers.risk import HaltRequest, lift_halt
from leviathan_core.security.authz_models import (
    _VERIFIER_MARKER,
    PrincipalV1,
    TrustedPrincipalAdapterV1,
)

_PORT = 46221
_CAPABILITY = "a" * 64
_HEADERS = {
    "Host": f"127.0.0.1:{_PORT}",
    "Origin": f"http://127.0.0.1:{_PORT}",
    "X-Leviathan-Capability": _CAPABILITY,
}


def _desktop_app(*, profile: object | None, features: frozenset[str]):
    return create_app(
        desktop_operator_capability=_CAPABILITY,
        desktop_operator_port=_PORT,
        desktop_operator_profile=profile,
        desktop_operator_features=features,
    )


def test_entitled_non_admin_session_can_lift_its_instance_halt() -> None:
    app = _desktop_app(
        profile=make_local_operator_profile(
            principal_id="paid-user-1", project_id="leviathan-ai", env="paper"
        ),
        features=frozenset({"live_trading"}),
    )
    with TestClient(app) as client:
        assert client.post("/risk/halt", json={"reason": "operator_hold"}).status_code == 200
        response = client.post(
            "/risk/halt/lift", json={"reason": "operator_hold"}, headers=_HEADERS
        )
        assert response.status_code == 200
        assert response.json() == {"halted": False, "active_halts": []}


@pytest.mark.parametrize("license_state", ["EXPIRED", "INACTIVE"])
def test_halt_engage_succeeds_with_expired_or_inactive_license_without_live_feature(
    monkeypatch: pytest.MonkeyPatch, license_state: str
) -> None:
    monkeypatch.setenv("LEVIATHAN_LICENSE_STATE", license_state)
    monkeypatch.setenv("LEVIATHAN_LICENSE_FEATURES", "")
    from leviathan_api.settings import get_settings

    get_settings.cache_clear()
    try:
        app = create_app()
        with TestClient(app) as client:
            response = client.post("/risk/halt", json={"reason": "operator_hold"})
        assert response.status_code == 200
        assert response.json()["halted"] is True
    finally:
        get_settings.cache_clear()


def test_missing_shell_session_fails_closed_even_with_forged_identity_headers() -> None:
    app = _desktop_app(profile=None, features=frozenset())
    with TestClient(app) as client:
        assert client.post("/risk/halt", json={"reason": "operator_hold"}).status_code == 200
        response = client.post(
            "/risk/halt/lift",
            json={"reason": "operator_hold"},
            headers={**_HEADERS, "X-Principal-ID": "attacker", "Authorization": "Bearer forged"},
        )
        assert response.status_code == 401
        assert response.json() == {"detail": "TRUSTED_PRINCIPAL_REQUIRED"}


def test_shell_session_without_live_trading_entitlement_is_denied() -> None:
    app = _desktop_app(
        profile=make_local_operator_profile(
            principal_id="paper-user-1", project_id="leviathan-ai", env="paper"
        ),
        features=frozenset({"paper_trading"}),
    )
    with TestClient(app) as client:
        client.post("/risk/halt", json={"reason": "operator_hold"})
        response = client.post(
            "/risk/halt/lift", json={"reason": "operator_hold"}, headers=_HEADERS
        )
        assert response.status_code == 403
        assert response.json() == {"detail": "LIVE_TRADING_ENTITLEMENT_REQUIRED"}


def test_principal_not_bound_to_this_instance_cannot_lift() -> None:
    principal = TrustedPrincipalAdapterV1.from_verified_claims(
        PrincipalV1(
            principal_id="some-other-user",
            project_id="leviathan-ai",
            roles=("operator",),
            env="paper",
        ),
        verifier_marker=_VERIFIER_MARKER,
    )
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/risk/halt/lift",
        "headers": [],
        "query_string": b"",
        "state": {
            "trusted_principal": principal,
            "trusted_instance_principal_id": "signed-in-user",
            "trusted_instance_features": frozenset({"live_trading"}),
        },
        "app": type("App", (), {"state": object()})(),
    }
    request = Request(scope)
    try:
        lift_halt(request, HaltRequest(reason="operator_hold"))
    except Exception as exc:
        assert isinstance(exc, HTTPException)
        assert exc.status_code == 401
        assert exc.detail == "TRUSTED_PRINCIPAL_REQUIRED"
    else:
        raise AssertionError("mismatched instance principal unexpectedly lifted HALT")
