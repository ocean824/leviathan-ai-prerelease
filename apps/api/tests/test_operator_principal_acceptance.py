"""Independent acceptance for per-launch local operator principal middleware."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import pytest
from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient

from leviathan_api.auth import (
    LocalOperatorProfileV1,
    OperatorAuthError,
    OperatorPrincipalMiddleware,
    make_local_operator_profile,
)
from leviathan_core.seal import SealError
from leviathan_core.security.authz_models import (
    AuthorizationModelError,
    require_trusted_principal,
)

PORT = 43127
BASE_URL = f"http://127.0.0.1:{PORT}"
CAPABILITY = "a" * 64
OTHER_LAUNCH_CAPABILITY = "b" * 64
PRINCIPAL_ID = "acceptance-operator-007"
PROJECT_ID = "acceptance-project-002"
ORIGIN = BASE_URL


def _profile(**overrides: Any) -> LocalOperatorProfileV1:
    values: dict[str, Any] = {
        "principal_id": PRINCIPAL_ID,
        "project_id": PROJECT_ID,
        "env": "test",
    }
    values.update(overrides)
    return make_local_operator_profile(**values)


def _app(
    profile: object | None = None,
    *,
    capability: str = CAPABILITY,
    port: int = PORT,
    seed_existing_principal: object | None = None,
) -> tuple[Any, list[object]]:
    accepted: list[object] = []
    api = FastAPI()

    def payload(request: Request) -> dict[str, object]:
        try:
            principal = require_trusted_principal(
                getattr(request.state, "trusted_principal", None)
            )
        except AuthorizationModelError:
            raise HTTPException(status_code=401, detail="Unauthorized") from None
        accepted.append(principal)
        return {
            "principal_id": principal.principal_id,
            "project_id": principal.project_id,
            "env": principal.env,
            "roles": list(principal.roles),
            "venue": principal.venue,
            "portfolio": principal.portfolio,
            "strategy": principal.strategy,
        }

    @api.get("/private")
    async def private_get(request: Request) -> dict[str, object]:
        return payload(request)

    @api.post("/private")
    async def private_post(request: Request) -> dict[str, object]:
        # The handler deliberately ignores body claims. It authenticates only
        # the request-local adapter-issued principal.
        await request.body()
        return payload(request)

    @api.head("/private")
    async def private_head(request: Request) -> dict[str, object]:
        return payload(request)

    @api.options("/private")
    async def private_options(request: Request) -> dict[str, object]:
        return payload(request)

    api.add_middleware(
        OperatorPrincipalMiddleware,
        capability=capability,
        port=port,
        profile=_profile() if profile is None else profile,
    )

    if seed_existing_principal is None:
        return api, accepted

    class SeedStaleState:
        def __init__(self, app: Any) -> None:
            self.app = app

        async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
            if scope.get("type") == "http":
                scope.setdefault("state", {})["trusted_principal"] = seed_existing_principal
            await self.app(scope, receive, send)

    return SeedStaleState(api), accepted


def _headers(*, capability: str = CAPABILITY, origin: str | None = None) -> dict[str, str]:
    headers = {"X-Leviathan-Capability": capability}
    if origin is not None:
        headers["Origin"] = origin
    return headers


def _unauthorized(client: TestClient, *, capability: str | None = None) -> tuple[int, str]:
    headers = {} if capability is None else {"X-Leviathan-Capability": capability}
    response = client.get("/private", headers=headers)
    return response.status_code, response.text


def test_valid_per_launch_evidence_yields_fresh_issued_principal_each_request() -> None:
    api, accepted = _app()

    with TestClient(api, base_url=BASE_URL) as client:
        first = client.get("/private", headers=_headers())
        second = client.get("/private", headers=_headers())
        head = client.head("/private", headers=_headers())
        options = client.options("/private", headers=_headers())

    assert first.status_code == second.status_code == 200
    assert head.status_code == options.status_code == 200
    assert first.json()["principal_id"] == PRINCIPAL_ID
    assert first.json()["project_id"] == PROJECT_ID
    assert first.json()["env"] == "test"
    assert first.json()["roles"] == ["operator"]
    assert len(accepted) == 4
    assert accepted[0] is not accepted[1]
    assert require_trusted_principal(accepted[0]) is accepted[0]
    assert require_trusted_principal(accepted[1]) is accepted[1]


@pytest.mark.parametrize(
    "provided_capability",
    (None, "not-a-capability", OTHER_LAUNCH_CAPABILITY, "c" * 64),
    ids=("missing", "invalid", "other-launch", "tampered"),
)
def test_missing_invalid_other_launch_and_tampered_evidence_have_uniform_401(
    provided_capability: str | None,
) -> None:
    api, accepted = _app()

    with TestClient(api, base_url=BASE_URL) as client:
        status, body = _unauthorized(client, capability=provided_capability)

    assert status == 401
    assert body == '{"detail":"Unauthorized"}'
    assert accepted == []


def test_failure_removes_any_preexisting_request_principal() -> None:
    stale = object()
    api, accepted = _app(seed_existing_principal=stale)

    with TestClient(api, base_url=BASE_URL) as client:
        response = client.get("/private")

    assert response.status_code == 401
    assert response.text == '{"detail":"Unauthorized"}'
    assert accepted == []


def test_request_claim_injection_cannot_change_profile_roles_or_scope() -> None:
    api, accepted = _app()
    with TestClient(api, base_url=BASE_URL) as client:
        get_response = client.get(
            "/private?role=admin&principal_id=forged",
            headers={
                **_headers(),
                "X-Role": "admin",
                "X-Principal-Id": "forged-principal",
                "Cookie": "role=admin; principal_id=forged-principal",
            },
        )
        post_response = client.post(
            "/private",
            headers={**_headers(origin=ORIGIN), "X-Role": "administrator"},
            json={
                "role": "admin",
                "principal_id": "forged-principal",
                "project_id": "other-project",
                "env": "live",
                "scopes": ["*"],
            },
        )

    assert get_response.status_code == post_response.status_code == 200
    for response in (get_response, post_response):
        assert response.json() == {
            "principal_id": PRINCIPAL_ID,
            "project_id": PROJECT_ID,
            "env": "test",
            "roles": ["operator"],
            "venue": None,
            "portfolio": None,
            "strategy": None,
        }
    assert len(accepted) == 2


def test_host_origin_and_duplicate_capability_guards_fail_closed() -> None:
    api, accepted = _app()
    with TestClient(api, base_url=BASE_URL) as client:
        wrong_host = client.get("/private", headers={**_headers(), "Host": "127.0.0.1:43128"})
        wrong_origin = client.get("/private", headers=_headers(origin="http://evil.invalid"))
        missing_write_origin = client.post("/private", headers=_headers(), json={})
        correct_write_origin = client.post("/private", headers=_headers(origin=ORIGIN), json={})
        duplicate_capability = client.get(
            "/private",
            headers=[
                ("X-Leviathan-Capability", CAPABILITY),
                ("X-Leviathan-Capability", CAPABILITY),
            ],
        )
        duplicate_host = client.get(
            "/private",
            headers=[
                ("Host", f"127.0.0.1:{PORT}"),
                ("Host", f"127.0.0.1:{PORT}"),
                ("X-Leviathan-Capability", CAPABILITY),
            ],
        )
        duplicate_origin = client.post(
            "/private",
            headers=[
                ("Origin", ORIGIN),
                ("Origin", ORIGIN),
                ("X-Leviathan-Capability", CAPABILITY),
            ],
            json={},
        )

    for rejected in (
        wrong_host,
        wrong_origin,
        missing_write_origin,
        duplicate_capability,
        duplicate_host,
        duplicate_origin,
    ):
        assert rejected.status_code == 401
        assert rejected.text == '{"detail":"Unauthorized"}'
    assert correct_write_origin.status_code == 200
    assert len(accepted) == 1


def test_capability_is_absent_from_repr_errors_responses_and_logs(
    caplog: pytest.LogCaptureFixture,
) -> None:
    api, _ = _app()
    middleware = OperatorPrincipalMiddleware(
        api,
        capability=CAPABILITY,
        port=PORT,
        profile=_profile(),
    )
    assert CAPABILITY not in repr(middleware)

    with pytest.raises(OperatorAuthError) as caught:
        OperatorPrincipalMiddleware(
            api, capability="synthetic-token-value", port=PORT, profile=_profile()
        )
    assert caught.value.code == "INVALID_CAPABILITY"
    assert str(caught.value) == "INVALID_CAPABILITY"
    assert CAPABILITY not in repr(caught.value)
    assert "synthetic-token-value" not in repr(caught.value)
    assert "synthetic-token-value" not in str(caught.value)

    caplog.set_level(logging.DEBUG)
    with TestClient(api, base_url=BASE_URL) as client:
        response = client.get("/private", headers=_headers(capability=CAPABILITY))
        rejected = client.get("/private", headers=_headers(capability="d" * 64))
    assert response.status_code == 200
    assert CAPABILITY not in response.text
    assert rejected.status_code == 401
    assert "d" * 64 not in rejected.text
    assert CAPABILITY not in caplog.text
    assert "d" * 64 not in caplog.text


@pytest.mark.parametrize(
    "profile_values",
    (
        {"env": "live"},
        {"env": "production"},
        {"roles": ()},
        {"roles": ("operator", "operator")},
        {"roles": ("*",)},
        {"roles": ("live-trader",)},
        {"strategy": "funded-strategy"},
    ),
)
def test_profile_cannot_carry_live_authority(profile_values: dict[str, object]) -> None:
    with pytest.raises(SealError):
        _profile(**profile_values)


def test_tampered_profile_is_rejected_when_middleware_is_constructed() -> None:
    profile = _profile()
    try:
        object.__setattr__(profile, "principal_id", "tampered-principal")
    except (AttributeError, TypeError, ValueError):
        # A write-time refusal is fail-closed as well; an issued profile remains
        # usable because no state was changed.
        return

    with pytest.raises(OperatorAuthError) as caught:
        OperatorPrincipalMiddleware(
            FastAPI(), capability=CAPABILITY, port=PORT, profile=profile
        )
    assert caught.value.code == "INVALID_PROFILE"
    assert "tampered-principal" not in str(caught.value)


def test_directly_constructed_but_unissued_profile_is_rejected() -> None:
    profile = LocalOperatorProfileV1(
        principal_id=PRINCIPAL_ID,
        project_id=PROJECT_ID,
        env="test",
        roles=("operator",),
        venue=None,
        portfolio=None,
        strategy=None,
    )

    with pytest.raises(OperatorAuthError) as caught:
        OperatorPrincipalMiddleware(FastAPI(), capability=CAPABILITY, port=PORT, profile=profile)
    assert caught.value.code == "INVALID_PROFILE"


def test_non_http_asgi_scope_passes_through_untouched() -> None:
    observed: list[dict[str, Any]] = []

    async def downstream(scope: dict[str, Any], _receive: Any, _send: Any) -> None:
        observed.append(scope)

    async def unused_receive() -> dict[str, str]:
        return {"type": "lifespan.startup"}

    async def unused_send(_message: dict[str, Any]) -> None:
        return None

    scope: dict[str, Any] = {"type": "lifespan", "state": {"trusted_principal": "sentinel"}}
    middleware = OperatorPrincipalMiddleware(
        downstream, capability=CAPABILITY, port=PORT, profile=_profile()
    )
    asyncio.run(middleware(scope, unused_receive, unused_send))

    assert observed == [scope]
    assert scope["state"]["trusted_principal"] == "sentinel"
