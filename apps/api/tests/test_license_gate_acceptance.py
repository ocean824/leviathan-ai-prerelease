"""Independent acceptance probes for the API license gate."""

from __future__ import annotations

import logging
import re
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.requests import Request

from leviathan_api.main import create_app
from leviathan_api.middleware.license_gate import (
    FEATURE_KEYS_V1,
    FEATURE_ROUTE_FAMILIES_V1,
    ROUTE_FEATURES_V1,
    LicenseGateMiddleware,
    feature_for_path,
)

_STATE = "LEVIATHAN_LICENSE_STATE"
_FEATURES = "LEVIATHAN_LICENSE_FEATURES"
_ALL_FEATURES = ",".join(sorted(FEATURE_KEYS_V1))


def _client(environ: dict[str, str]) -> tuple[TestClient, list[str]]:
    app = FastAPI()
    calls: list[str] = []

    async def endpoint(request: Request) -> dict[str, str]:
        calls.append(request.url.path)
        return {"path": request.url.path}

    for path, methods in (
        ("/orders", ["GET", "POST"]),
        ("/orders/activations", ["POST"]),
        ("/live-activation/enable", ["POST"]),
        ("/api/preferences/{namespace}", ["PUT"]),
        ("/risk/halt", ["POST"]),
        ("/health", ["GET"]),
        ("/desktop/update-readiness", ["GET"]),
        ("/live-activation/disable", ["POST"]),
        ("/unmapped/write", ["POST"]),
    ):
        app.add_api_route(
            path,
            endpoint,
            methods=methods,
            name=f"acceptance_{path.replace('/', '_').replace('{', '').replace('}', '')}",
        )

    middleware = LicenseGateMiddleware(app, environ=environ)
    return TestClient(middleware), calls


def _grace(features: str = _ALL_FEATURES) -> dict[str, str]:
    return {_STATE: "GRACE_READ_ONLY", _FEATURES: features}


def test_grace_rejects_mutations_before_the_route_runs() -> None:
    client, calls = _client(_grace())
    with client:
        for method, path in (
            ("post", "/orders"),
            ("put", "/api/preferences/profile"),
            ("post", "/unmapped/write"),
        ):
            response = getattr(client, method)(path)
            assert response.status_code == 403
            assert response.json() == {"code": "LICENSE_READ_ONLY"}
    assert calls == []


def test_real_create_app_wires_grace_gate_and_preserves_unset_behavior(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exercise the production middleware registration, not a hand-built app."""
    monkeypatch.setenv(_STATE, "GRACE_READ_ONLY")
    monkeypatch.setenv(_FEATURES, _ALL_FEATURES)
    with TestClient(create_app()) as client:
        denied_order = client.post("/orders", json={})
        healthy = client.get("/health")

    assert denied_order.status_code == 403
    assert denied_order.json() == {"code": "LICENSE_READ_ONLY"}
    assert healthy.status_code == 200

    monkeypatch.delenv(_STATE, raising=False)
    monkeypatch.delenv(_FEATURES, raising=False)
    with TestClient(create_app()) as client:
        unset_order = client.post("/orders", json={})
        unset_health = client.get("/health")

    # The normal route may reject an incomplete order body; the key assertion
    # is that the inactive middleware does not turn it into LICENSE_READ_ONLY.
    assert unset_order.status_code != 403
    assert unset_order.json() != {"code": "LICENSE_READ_ONLY"}
    assert unset_health.status_code == 200


@pytest.mark.parametrize("path", ["/live-activation/enable", "/orders/activations"])
def test_grace_never_allows_live_enable_even_with_all_features(path: str) -> None:
    client, calls = _client(_grace())
    with client:
        response = client.post(path)
    assert response.status_code == 403
    assert response.json() == {"code": "LICENSE_READ_ONLY"}
    assert calls == []


def test_grace_allows_safe_reads_and_halt_engage() -> None:
    client, calls = _client(_grace())
    with client:
        read = client.get("/orders")
        readiness = client.get("/desktop/update-readiness")
        halt = client.post("/risk/halt")
        disable_live = client.post("/live-activation/disable")
    assert read.status_code == 200
    assert readiness.status_code == 200
    assert halt.status_code == 200
    assert disable_live.status_code == 200
    assert calls == [
        "/orders",
        "/desktop/update-readiness",
        "/risk/halt",
        "/live-activation/disable",
    ]


@pytest.mark.parametrize(
    "environ",
    [
        {_STATE: "GRACE_READ_ONLY"},
        {_FEATURES: _ALL_FEATURES},
        {_STATE: "GRACE_READ_ONLY", _FEATURES: f"{_ALL_FEATURES},unknown_feature"},
        {_STATE: "UNKNOWN_STATE", _FEATURES: _ALL_FEATURES},
    ],
)
def test_partial_or_invalid_configuration_fails_closed(environ: dict[str, str]) -> None:
    client, calls = _client(environ)
    with client:
        write = client.post("/orders")
        read = client.get("/orders")
    assert write.status_code == 403
    assert write.json() == {"code": "LICENSE_READ_ONLY"}
    assert read.status_code == 403
    assert read.json() == {"code": "FEATURE_NOT_ENTITLED", "feature": "paper_trading"}
    assert calls == []


def test_gate_is_inactive_only_when_both_environment_values_are_absent() -> None:
    client, calls = _client({})
    with client:
        response = client.post("/orders")
    assert response.status_code == 200
    assert calls == ["/orders"]


def test_online_feature_denial_uses_fixed_feature_response() -> None:
    client, calls = _client({_STATE: "VERIFIED_ONLINE", _FEATURES: "live_trading"})
    with client:
        denied = client.get("/orders")
        allowed = client.post("/orders/activations")
    assert denied.status_code == 403
    assert denied.json() == {"code": "FEATURE_NOT_ENTITLED", "feature": "paper_trading"}
    assert allowed.status_code == 200
    assert calls == ["/orders/activations"]


def test_route_feature_table_covers_catalog_exactly() -> None:
    catalog_path = (
        Path(__file__).resolve().parents[3] / "workers/licensing/src/entitlement/feature_catalog.ts"
    )
    catalog = catalog_path.read_text(encoding="utf-8")

    keys_match = re.search(
        r"export const FEATURE_KEYS_V1 = Object\.freeze\(\[(.*?)\] as const\);",
        catalog,
        re.DOTALL,
    )
    assert keys_match is not None
    catalog_features = set(re.findall(r'"([a-z][a-z0-9_]*)"', keys_match.group(1)))

    actions_match = re.search(
        r"export const API_FEATURE_ACTIONS_V1:.*?= Object\.freeze\(\(\[(.*?)\]"
        r"\s+satisfies ApiFeatureActionV1\[\]\)",
        catalog,
        re.DOTALL,
    )
    assert actions_match is not None
    catalog_routes = {
        path: feature
        for _action_id, _method, path, feature in re.findall(
            r'\{ action_id: "([^"]+)", method: "([A-Z]+)", path: "([^"]+)", '
            r'feature_key: "([a-z][a-z0-9_]*)"',
            actions_match.group(1),
        )
    }
    gate_routes = dict(ROUTE_FEATURES_V1)
    route_families = dict(FEATURE_ROUTE_FAMILIES_V1)

    assert catalog_features == set(FEATURE_KEYS_V1)
    assert gate_routes == catalog_routes
    assert set(route_families) == catalog_features
    assert route_families["charts"] == ()
    assert {feature: set(paths) for feature, paths in route_families.items()} == {
        feature: {path for path, bound_feature in gate_routes.items() if bound_feature == feature}
        for feature in catalog_features
    }


def test_route_templates_match_one_segment_and_bind_expected_feature() -> None:
    assert feature_for_path("/api/preferences/profile") == "user_settings"
    assert feature_for_path("/api/preferences/a/b") is None
    assert feature_for_path("/not-in-the-table") is None


def test_environment_values_are_not_written_to_gate_logs(caplog: pytest.LogCaptureFixture) -> None:
    marker = "synthetic-license-value-must-not-leak"
    logger = logging.getLogger("acceptance.license_gate")
    caplog.set_level(logging.WARNING, logger=logger.name)
    LicenseGateMiddleware(
        FastAPI(),
        environ={_STATE: marker},
        logger=logger,
    )
    assert "LICENSE_GATE_PARTIAL_CONFIG" in caplog.text
    assert marker not in caplog.text
