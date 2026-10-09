"""AUTH-MW-001: the local operator principal middleware."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from leviathan_api.auth import (
    ALLOWED_ENVS,
    DEFAULT_ROLES,
    LocalOperatorProfileV1,
    OperatorAuthError,
    OperatorPrincipalMiddleware,
    make_local_operator_profile,
    require_local_operator_profile,
)
from leviathan_api.routers.knowledge_archive import KnowledgeArchiveRuntime, router
from leviathan_core.knowledge_sync.archive_models import ArchivedRecordV1
from leviathan_core.seal import SealError, verify
from leviathan_core.security.authz_models import (
    _VERIFIER_MARKER,
    TRUSTED_PRINCIPAL_TAG,
    AuthorizationModelError,
    PrincipalV1,
    TrustedPrincipalAdapterV1,
    TrustedPrincipalV1,
    is_trusted_principal,
    require_trusted_principal,
)

PORT = 49321
CAPABILITY = "ab" * 32
OTHER_LAUNCH = "cd" * 32
ORG = "local-operator-project"
BASE = f"http://127.0.0.1:{PORT}"
GOOD = {"x-leviathan-capability": CAPABILITY}
POST_GOOD = {**GOOD, "origin": BASE}
SENTINEL = "SYNTHETIC-SENTINEL-NOT-A-ROLE"


def _profile(**changes: object):
    values = dict(principal_id="local-operator", project_id=ORG, env="paper")
    values.update(changes)
    return make_local_operator_profile(**values)  # type: ignore[arg-type]


def _forged() -> TrustedPrincipalV1:
    claims = PrincipalV1(principal_id="forged", project_id=ORG, roles=("admin",), env="paper")
    principal = object.__new__(TrustedPrincipalV1)
    for name in (
        "principal_id",
        "project_id",
        "roles",
        "env",
        "venue",
        "portfolio",
        "strategy",
        "break_glass",
    ):
        object.__setattr__(principal, name, getattr(claims, name))
    return principal


class _Preset:
    """Outermost wrapper that plants a hand-built principal before the middleware runs."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            scope.setdefault("state", {})["trusted_principal"] = _forged()
        await self.app(scope, receive, send)


def _app(*, preset: bool = False, profile=None) -> FastAPI:
    app = FastAPI()

    @app.api_route("/whoami", methods=["GET", "POST"])
    async def whoami(request: Request) -> JSONResponse:
        principal = getattr(request.state, "trusted_principal", None)
        try:
            trusted = require_trusted_principal(principal)
        except AuthorizationModelError:
            return JSONResponse({"error": "unauthenticated"}, status_code=401)
        return JSONResponse(
            {
                "principal_id": trusted.principal_id,
                "project_id": trusted.project_id,
                "roles": list(trusted.roles),
                "env": trusted.env,
                "id": id(trusted),
            }
        )

    app.add_middleware(
        OperatorPrincipalMiddleware,
        capability=CAPABILITY,
        port=PORT,
        profile=profile if profile is not None else _profile(),
    )
    if preset:
        app.add_middleware(_Preset)
    return app


@pytest.fixture
def client():
    with TestClient(_app(), base_url=BASE) as test_client:
        yield test_client


def test_valid_session_yields_an_issued_principal(client) -> None:
    response = client.get("/whoami", headers=GOOD)
    assert response.status_code == 200
    assert response.json() | {"id": 0} == {
        "principal_id": "local-operator",
        "project_id": ORG,
        "roles": ["operator"],
        "env": "paper",
        "id": 0,
    }
    assert DEFAULT_ROLES == ("operator",)
    assert client.post("/whoami", headers=POST_GOOD).status_code == 200


def test_principal_is_issued_by_the_adapter_and_fresh_per_request() -> None:
    seen: list[TrustedPrincipalV1] = []
    app = _app()

    @app.get("/capture")
    async def capture(request: Request) -> JSONResponse:
        seen.append(request.state.trusted_principal)
        return JSONResponse({})

    with TestClient(app, base_url=BASE) as test_client:
        for _ in range(2):
            assert test_client.get("/capture", headers=GOOD).status_code == 200
    first, second = seen
    assert first is not second
    for principal in (first, second):
        assert type(principal) is TrustedPrincipalV1
        assert verify(principal, TRUSTED_PRINCIPAL_TAG) and is_trusted_principal(principal)
        assert require_trusted_principal(principal) is principal


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"x-leviathan-capability": OTHER_LAUNCH},  # another launch's capability
        {"x-leviathan-capability": CAPABILITY.upper()},
        {"x-leviathan-capability": CAPABILITY[:-1]},
        {"x-leviathan-capability": CAPABILITY + "0"},
        {"x-leviathan-capability": ""},
    ],
)
def test_missing_or_wrong_evidence_yields_no_principal(client, headers) -> None:
    assert client.get("/whoami", headers=headers).status_code == 401


def test_duplicate_capability_header_is_refused(client) -> None:
    both = [("x-leviathan-capability", CAPABILITY), ("x-leviathan-capability", CAPABILITY)]
    assert client.get("/whoami", headers=both).status_code == 401
    mixed = [("x-leviathan-capability", CAPABILITY), ("x-leviathan-capability", OTHER_LAUNCH)]
    assert client.get("/whoami", headers=mixed).status_code == 401


def test_host_and_origin_are_rechecked_like_the_sidecar_guard() -> None:
    with TestClient(_app(), base_url=f"http://127.0.0.1:{PORT + 1}") as wrong_host:
        assert wrong_host.get("/whoami", headers=GOOD).status_code == 401
    with TestClient(_app(), base_url="http://localhost:49321") as other_name:
        assert other_name.get("/whoami", headers=GOOD).status_code == 401
    with TestClient(_app(), base_url=BASE) as local:
        assert (
            local.get("/whoami", headers={**GOOD, "origin": "http://evil.invalid"}).status_code
            == 401
        )
        assert local.get("/whoami", headers={**GOOD, "origin": BASE}).status_code == 200
        assert local.post("/whoami", headers=GOOD).status_code == 401  # origin required
        assert (
            local.post("/whoami", headers={**GOOD, "origin": "http://evil.invalid"}).status_code
            == 401
        )
        two_origins = [("origin", BASE), ("origin", BASE), ("x-leviathan-capability", CAPABILITY)]
        assert local.get("/whoami", headers=two_origins).status_code == 401


def test_request_supplied_roles_and_identity_are_ignored(client) -> None:
    injected = {
        **GOOD,
        "x-leviathan-roles": "admin,live-trader",
        "x-leviathan-principal": "attacker",
        "x-principal-id": "attacker",
        "x-roles": "admin",
        "authorization": "Bearer attacker-admin",
        "cookie": "roles=admin; principal=attacker; trusted_principal=1",
    }
    body = client.get("/whoami?roles=admin&principal_id=attacker", headers=injected).json()
    assert body["principal_id"] == "local-operator" and body["roles"] == ["operator"]
    # Injected identity without the evidence gets nothing.
    bare = {key: value for key, value in injected.items() if key != "x-leviathan-capability"}
    assert client.get("/whoami", headers=bare).status_code == 401
    wrong = {**bare, "x-leviathan-capability": OTHER_LAUNCH}
    assert client.get("/whoami", headers=wrong).status_code == 401


def test_a_preexisting_principal_is_cleared_and_never_trusted() -> None:
    with TestClient(_app(preset=True), base_url=BASE) as planted:
        assert planted.get("/whoami", headers={}).status_code == 401  # planted one removed
        assert (
            planted.get("/whoami", headers={"x-leviathan-capability": OTHER_LAUNCH}).status_code
            == 401
        )
        body = planted.get("/whoami", headers=GOOD).json()
        assert body["principal_id"] == "local-operator" and body["roles"] == ["operator"]


def test_no_secret_or_profile_value_leaks_anywhere() -> None:
    profile = _profile()
    middleware = OperatorPrincipalMiddleware(
        _app(), capability=CAPABILITY, port=PORT, profile=profile
    )
    for text in (
        repr(middleware),
        str(middleware),
        repr(profile),
        str(profile),
        profile.model_dump_json(),
        repr(type(middleware).__slots__),
    ):
        assert CAPABILITY not in text and OTHER_LAUNCH not in text
    for bad in (CAPABILITY.upper(), CAPABILITY[:-1], 12345, None):
        with pytest.raises(OperatorAuthError) as raised:
            OperatorPrincipalMiddleware(_app(), capability=bad, port=PORT, profile=profile)
        assert raised.value.code == "INVALID_CAPABILITY"
        assert CAPABILITY not in f"{raised.value!r} {raised.value}"
        assert raised.value.__cause__ is None
    for port in (0, 65536, True, "49321"):
        with pytest.raises(OperatorAuthError):
            OperatorPrincipalMiddleware(_app(), capability=CAPABILITY, port=port, profile=profile)  # type: ignore[arg-type]
    with TestClient(_app(), base_url=BASE) as test_client:
        for headers in ({}, GOOD, {"x-leviathan-capability": OTHER_LAUNCH}):
            response = test_client.get("/whoami", headers=headers)
            blob = response.text + json.dumps(dict(response.headers))
            assert CAPABILITY not in blob and OTHER_LAUNCH not in blob


def test_profile_is_sealed_minimal_and_never_live() -> None:
    profile = _profile()
    assert require_local_operator_profile(profile) is profile
    assert profile.roles == ("operator",)
    assert (profile.venue, profile.portfolio, profile.strategy) == (None, None, None)
    assert {"development", "test", "paper", "demo"} == ALLOWED_ENVS
    scoped = _profile(venue="XNYS", portfolio="book.1", strategy="alpha.1", roles=("audit",))
    assert (scoped.venue, scoped.portfolio, scoped.strategy) == ("XNYS", "book.1", "alpha.1")
    for env in ("live", "LIVE", "production", "prod", "staging", "", "paper-live"):
        with pytest.raises(SealError):
            _profile(env=env)
    for roles in (
        ("live-trader",),
        ("operator", "LIVE"),
        ("prod-admin",),
        (),
        ("a", "a"),
        ("*",),
        ("real-money",),
    ):
        with pytest.raises(SealError):
            _profile(roles=roles)
    for scope in ("venue", "portfolio", "strategy"):
        with pytest.raises(SealError):
            _profile(**{scope: "live-book"})
    with pytest.raises(TypeError):
        make_local_operator_profile(principal_id="x", project_id=ORG)  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        make_local_operator_profile(project_id=ORG, env="paper")  # type: ignore[call-arg]


def test_only_an_issued_unmodified_profile_is_accepted() -> None:
    unissued = LocalOperatorProfileV1(
        principal_id="local-operator",
        project_id=ORG,
        env="paper",
        roles=("operator",),
        venue=None,
        portfolio=None,
        strategy=None,
    )
    for bad in (unissued, None, "profile", {"roles": ["admin"]}, object()):
        with pytest.raises(OperatorAuthError) as raised:
            OperatorPrincipalMiddleware(_app(), capability=CAPABILITY, port=PORT, profile=bad)
        assert raised.value.code == "INVALID_PROFILE"
    tampered = _profile()
    object.__getattribute__(tampered, "__dict__")["roles"] = ("operator", "admin")
    with pytest.raises(OperatorAuthError):
        OperatorPrincipalMiddleware(_app(), capability=CAPABILITY, port=PORT, profile=tampered)


def test_a_profile_tampered_after_construction_fails_closed() -> None:
    profile = _profile()
    app = _app(profile=profile)
    with TestClient(app, base_url=BASE) as test_client:
        assert test_client.get("/whoami", headers=GOOD).status_code == 200  # stack is built
        object.__getattribute__(profile, "__dict__")["roles"] = ("operator", "admin")
        assert test_client.get("/whoami", headers=GOOD).status_code == 401


def test_non_http_scopes_pass_through_without_a_principal() -> None:
    seen: list[tuple[str, object]] = []

    async def inner(scope, receive, send):
        del receive, send
        state = scope.get("state", {})
        seen.append((scope["type"], state.get("trusted_principal")))

    middleware = OperatorPrincipalMiddleware(
        inner, capability=CAPABILITY, port=PORT, profile=_profile()
    )

    import asyncio

    asyncio.run(middleware({"type": "lifespan"}, None, None))  # type: ignore[arg-type]
    sent = []
    asyncio.run(
        middleware(
            {
                "type": "websocket",
                "headers": [
                    (b"host", f"127.0.0.1:{PORT}".encode()),
                    (b"x-leviathan-capability", CAPABILITY.encode()),
                    (b"origin", f"http://127.0.0.1:{PORT}".encode()),
                ],
            },
            None,
            sent.append,
        )
    )  # type: ignore[arg-type]
    assert [kind for kind, _ in seen] == ["lifespan", "websocket"]
    assert seen[0][1] is None
    assert type(seen[1][1]) is TrustedPrincipalV1
    assert sent == []


def test_principal_gated_archive_route_works_with_a_valid_session() -> None:
    record = ArchivedRecordV1(
        schema_version="1",
        org_id=ORG,
        record_id="00000000-0000-0000-0000-000000000001",
        source_type="api",
        created_at_ns=1_791_288_000_000_000_000 - 2,
        updated_at_ns=1_791_288_000_000_000_000 - 1,
        tags=("synthetic",),
        payload_json='{"ordinary":{"count":3}}',
        status="archived",
    )

    class Repository:
        def list_archived_records(self, org_id: str):
            return (record,)

        def get_archived_record(self, org_id: str, ingestion_id: str):
            return record

        def list_archived_runs(self, org_id: str, ingestion_id: str):
            return (record,)

    class Sink:
        def record(self, event: object) -> None:
            return None

        def increment(self, name: str, *, labels: dict[str, str]) -> None:
            return None

        def emit(self, alert: object) -> None:
            return None

    app = FastAPI()
    app.include_router(router)
    app.state.knowledge_archive = KnowledgeArchiveRuntime(
        repository=Repository(),
        audit=Sink(),
        metrics=Sink(),
        alerts=Sink(),
        clock=lambda: datetime(2026, 10, 6, 12, 0, tzinfo=UTC),
        sunset_at_ns=1_800_000_000_000_000_000,
        daily_threshold=100,
    )
    app.add_middleware(
        OperatorPrincipalMiddleware, capability=CAPABILITY, port=PORT, profile=_profile()
    )
    with TestClient(app, base_url=BASE) as test_client:
        assert test_client.get("/v1/knowledge/ingestions", headers=GOOD).status_code == 200
        denied = test_client.get("/v1/knowledge/ingestions", headers={})
        assert denied.status_code == 401
        other = test_client.get(
            "/v1/knowledge/ingestions", headers={"x-leviathan-capability": OTHER_LAUNCH}
        )
        assert (other.status_code, other.text) == (denied.status_code, denied.text)


def test_adapter_is_still_the_only_issuer_of_principals() -> None:
    assert not is_trusted_principal(_forged())
    claims = PrincipalV1(principal_id="p", project_id=ORG, roles=("operator",), env="paper")
    issued = TrustedPrincipalAdapterV1.from_verified_claims(
        claims, verifier_marker=_VERIFIER_MARKER
    )
    assert is_trusted_principal(issued)
