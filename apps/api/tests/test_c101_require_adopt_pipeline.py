"""C-101 API response and reload boundaries."""

from __future__ import annotations

from typing import Never

import pytest
from fastapi.testclient import TestClient
from leviathan_store.risk_txn import RouteAttemptStore


def test_post_uses_issued_in_process_result_without_reload(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    client.app.state.leviathan.ledger_integrity_key = None

    async def forbidden_reload(self: RouteAttemptStore, decision_id: str) -> Never:
        raise AssertionError("POST must not reload its terminal row")

    monkeypatch.setattr(RouteAttemptStore, "read_view", forbidden_reload)
    response = client.post("/pipeline/replay")
    body = response.json()

    assert response.status_code == 200
    assert body["status"] == "completed" and body["final"] is True
    assert body["final_verdict"] is not None
    assert body["journal_record"] is not None


def test_keyless_later_read_is_explicitly_unverified(client: TestClient) -> None:
    client.app.state.leviathan.ledger_integrity_key = None
    response = client.post("/pipeline/replay")
    decision_id = response.json()["decision"]["decision_id"]

    later = client.get(f"/pipeline/attempts/{decision_id}")

    assert response.status_code == 200
    assert later.status_code == 200
    assert later.json()["status"] == "unverified"
    assert later.json()["verification"] == "UNVERIFIED"
    assert later.json()["final"] is False
    assert later.json()["final_verdict"] is None
    assert later.json()["journal_record"] is None


def test_keyed_later_read_of_keyless_row_is_http_200_unverified(
    client: TestClient,
) -> None:
    state = client.app.state.leviathan
    available_key = state.ledger_integrity_key
    assert available_key is not None
    state.ledger_integrity_key = None
    response = client.post("/pipeline/replay")
    decision_id = response.json()["decision"]["decision_id"]

    state.ledger_integrity_key = available_key
    later = client.get(f"/pipeline/attempts/{decision_id}")
    body = later.json()

    assert response.status_code == 200
    assert later.status_code == 200
    assert body["status"] == "unverified"
    assert body["verification"] == "UNVERIFIED"
    assert body["reason"] == "UNISSUED_PERSISTED"
    assert body["final"] is False
    assert body["final_verdict"] is None
    assert body["journal_record"] is None
    assert body["audit_sink_failure"] is False


def test_keyed_later_read_uses_authoritative_reload(client: TestClient) -> None:
    response = client.post("/pipeline/replay")
    body = response.json()
    decision_id = body["decision"]["decision_id"]

    later = client.get(f"/pipeline/attempts/{decision_id}")

    assert response.status_code == 200
    assert later.status_code == 200
    assert later.json()["status"] == "completed"
    assert later.json()["final"] is True
    assert later.json()["final_verdict"] == body["final_verdict"]
    assert later.json()["journal_record"] == body["journal_record"]
