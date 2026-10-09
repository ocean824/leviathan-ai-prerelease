"""Unit tests for the unregistered desktop licence gate middleware."""

from __future__ import annotations

import asyncio
import logging
import re
from pathlib import Path
from typing import Any, cast

import pytest
from starlette.types import Message, Receive, Scope, Send

from leviathan_api.middleware.license_gate import (
    FEATURE_KEYS_V1,
    FEATURE_ROUTE_FAMILIES_V1,
    ROUTE_FEATURES_V1,
    LicenseGateMiddleware,
    feature_for_path,
)

_CATALOG = (
    Path(__file__).resolve().parents[3]
    / "workers"
    / "licensing"
    / "src"
    / "entitlement"
    / "feature_catalog.ts"
)
_CATALOG_FEATURES = re.compile(
    r"export const FEATURE_KEYS_V1\s*=\s*Object\.freeze\(\[(.*?)\]\s+as const\)",
    re.DOTALL,
)
_CATALOG_ACTIONS = re.compile(
    r'\{\s*action_id:\s*"[^"]+",\s*method:\s*"[A-Z]+",\s*'
    r'path:\s*"([^"]+)",\s*feature_key:\s*"([^"]+)"',
)


def _run_request(
    middleware: LicenseGateMiddleware,
    *,
    path: str,
    method: str,
) -> tuple[int | None, bytes, bool, int]:
    calls: dict[str, Any] = {"app": False, "receive": 0, "status": None, "body": b""}

    async def app(_scope: Scope, _receive: Receive, send: Send) -> None:
        calls["app"] = True
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    async def receive() -> Message:
        calls["receive"] += 1
        return {"type": "http.request", "body": b"synthetic", "more_body": False}

    async def send(message: Message) -> None:
        if message["type"] == "http.response.start":
            calls["status"] = message["status"]
        elif message["type"] == "http.response.body":
            calls["body"] += message.get("body", b"")

    scope: Scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("ascii"),
        "query_string": b"secret=query-not-read",
        "headers": [(b"content-type", b"application/json")],
        "client": ("127.0.0.1", 12345),
        "server": ("127.0.0.1", 8000),
        "state": {},
    }
    middleware.app = app
    asyncio.run(middleware(scope, receive, send))
    return calls["status"], calls["body"], calls["app"], calls["receive"]


def _body(result: tuple[int | None, bytes, bool, int]) -> dict[str, str]:
    import json

    return cast(dict[str, str], json.loads(result[1]))


def test_closed_route_table_covers_catalog_actions_and_only_known_feature_ids() -> None:
    source = _CATALOG.read_text(encoding="utf-8")
    feature_block = _CATALOG_FEATURES.search(source)
    assert feature_block is not None
    catalog_features = set(re.findall(r'"([a-z_]+)"', feature_block.group(1)))
    assert catalog_features == FEATURE_KEYS_V1

    actions = _CATALOG_ACTIONS.findall(source)
    action_ids = re.findall(r'action_id:\s*"([^"]+)"', source)
    assert len(actions) == len(action_ids) == 60
    assert set(FEATURE_ROUTE_FAMILIES_V1) == catalog_features
    assert FEATURE_ROUTE_FAMILIES_V1["charts"] == ()
    flattened = {
        (route_template, feature)
        for feature, route_templates in FEATURE_ROUTE_FAMILIES_V1.items()
        for route_template in route_templates
    }
    assert flattened == set(ROUTE_FEATURES_V1)
    for route_template, feature in actions:
        assert feature in catalog_features
        assert feature_for_path(route_template) == feature

    table_paths = [path for path, _feature in ROUTE_FEATURES_V1]
    assert len(table_paths) == len(set(table_paths))
    assert {feature for _path, feature in ROUTE_FEATURES_V1} <= catalog_features


def test_grace_denies_mutations_with_fixed_content_free_response_without_reading_body() -> None:
    middleware = LicenseGateMiddleware(
        _unused_app,
        environ={
            "LEVIATHAN_LICENSE_STATE": "GRACE_READ_ONLY",
            "LEVIATHAN_LICENSE_FEATURES": "paper_trading",
        },
    )
    result = _run_request(middleware, path="/orders", method="POST")
    assert result[0] == 403
    assert _body(result) == {"code": "LICENSE_READ_ONLY"}
    assert result[2] is False
    assert result[3] == 0


def test_grace_allows_safe_methods_but_still_applies_feature_gate() -> None:
    middleware = LicenseGateMiddleware(
        _unused_app,
        environ={
            "LEVIATHAN_LICENSE_STATE": "GRACE_READ_ONLY",
            "LEVIATHAN_LICENSE_FEATURES": "",
        },
    )
    health = _run_request(middleware, path="/health", method="GET")
    assert health[0] == 204 and health[2] is True
    missing_feature = _run_request(middleware, path="/orders", method="GET")
    assert missing_feature[0] == 403
    assert _body(missing_feature) == {
        "code": "FEATURE_NOT_ENTITLED",
        "feature": "paper_trading",
    }


@pytest.mark.parametrize(
    "path",
    ["/risk/halt", "/mcp/halts", "/omega/kill", "/live-activation/disable"],
)
def test_grace_allows_halt_and_live_disable_safety_actions(path: str) -> None:
    middleware = LicenseGateMiddleware(
        _unused_app,
        environ={
            "LEVIATHAN_LICENSE_STATE": "GRACE_READ_ONLY",
            "LEVIATHAN_LICENSE_FEATURES": "live_trading",
        },
    )
    result = _run_request(middleware, path=path, method="POST")
    assert result[0] == 204 and result[2] is True


@pytest.mark.parametrize("method", ["GET", "POST", "OPTIONS"])
@pytest.mark.parametrize("path", ["/live-activation/enable", "/orders/activations"])
def test_grace_never_allows_live_enable_even_when_route_is_safe_method(
    path: str, method: str
) -> None:
    middleware = LicenseGateMiddleware(
        _unused_app,
        environ={
            "LEVIATHAN_LICENSE_STATE": "GRACE_READ_ONLY",
            "LEVIATHAN_LICENSE_FEATURES": "live_trading",
        },
    )
    result = _run_request(middleware, path=path, method=method)
    assert result[0] == 403
    assert _body(result) == {"code": "LICENSE_READ_ONLY"}
    assert result[2] is False


def test_online_feature_denial_and_entitled_route() -> None:
    denied = LicenseGateMiddleware(
        _unused_app,
        environ={
            "LEVIATHAN_LICENSE_STATE": "VERIFIED_ONLINE",
            "LEVIATHAN_LICENSE_FEATURES": "chat_terminal",
        },
    )
    denied_result = _run_request(denied, path="/orders", method="GET")
    assert denied_result[0] == 403
    assert _body(denied_result) == {
        "code": "FEATURE_NOT_ENTITLED",
        "feature": "paper_trading",
    }

    allowed = LicenseGateMiddleware(
        _unused_app,
        environ={
            "LEVIATHAN_LICENSE_STATE": "VERIFIED_ONLINE",
            "LEVIATHAN_LICENSE_FEATURES": "paper_trading,chat_terminal",
        },
    )
    allowed_result = _run_request(allowed, path="/orders", method="POST")
    assert allowed_result[0] == 204 and allowed_result[2] is True


def test_unmapped_routes_pass_and_inactive_config_logs_only_one_fixed_marker(
    caplog: pytest.LogCaptureFixture,
) -> None:
    logger_name = "leviathan_api.middleware.license_gate"
    with caplog.at_level(logging.WARNING, logger=logger_name):
        middleware = LicenseGateMiddleware(_unused_app, environ={})
    assert [record.message for record in caplog.records] == ["LICENSE_GATE_INACTIVE"]
    result = _run_request(middleware, path="/synthetic/unmapped", method="POST")
    assert result[0] == 204 and result[2] is True


def test_partial_and_malformed_configuration_fail_closed_without_echoing_values(
    caplog: pytest.LogCaptureFixture,
) -> None:
    logger_name = "leviathan_api.middleware.license_gate"
    with caplog.at_level(logging.WARNING, logger=logger_name):
        partial = LicenseGateMiddleware(
            _unused_app,
            environ={"LEVIATHAN_LICENSE_STATE": "VERIFIED_ONLINE"},
        )
        malformed = LicenseGateMiddleware(
            _unused_app,
            environ={
                "LEVIATHAN_LICENSE_STATE": "VERIFIED_ONLINE",
                "LEVIATHAN_LICENSE_FEATURES": "paper_trading,secret-unknown-id",
            },
        )
    assert [record.message for record in caplog.records] == [
        "LICENSE_GATE_PARTIAL_CONFIG",
        "LICENSE_GATE_PARTIAL_CONFIG",
    ]
    assert all("secret-unknown-id" not in record.message for record in caplog.records)

    for middleware in (partial, malformed):
        denied_write = _run_request(middleware, path="/synthetic/unmapped", method="POST")
        assert denied_write[0] == 403
        assert _body(denied_write) == {"code": "LICENSE_READ_ONLY"}
        denied_feature = _run_request(middleware, path="/orders", method="GET")
        assert denied_feature[0] == 403
        assert _body(denied_feature) == {
            "code": "FEATURE_NOT_ENTITLED",
            "feature": "paper_trading",
        }


async def _unused_app(_scope: Scope, _receive: Receive, _send: Send) -> None:
    raise AssertionError("test app should be replaced by _run_request")
