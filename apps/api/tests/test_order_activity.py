"""Local API boundary tests for the unmounted read-only activity router."""

from fastapi import FastAPI
from fastapi.testclient import TestClient

from leviathan_api.routers.order_activity import (
    _issue_cursor,
    _read_cursor,
    _scope_digest,
    create_order_activity_router,
)


def test_activity_router_disabled_and_unlisted_method_are_no_store() -> None:
    app = FastAPI()
    app.include_router(create_order_activity_router())
    client = TestClient(app)

    disabled = client.get("/orders/activity")
    assert disabled.status_code == 503
    assert disabled.json() == {"error": {"code": "PAPER_ACTIVITY_UNAVAILABLE"}}
    assert disabled.headers["cache-control"] == "no-store"

    unsupported = client.post("/orders/activity")
    assert unsupported.status_code == 405
    assert unsupported.headers["cache-control"] == "no-store"


def test_activity_cursor_is_authenticated_and_scope_bound() -> None:
    key = b"activity-cursor-unit-key" * 2
    scope = _scope_digest("paper", "paper-1")
    token = _issue_cursor(key, scope=scope, high_water=12, last_sequence=7)

    assert _read_cursor(token, key, expected_scope=scope) == (12, 7)
    assert _read_cursor(token, key, expected_scope=_scope_digest("paper", "paper-2")) is None
    assert _read_cursor(token + "x", key, expected_scope=scope) is None
