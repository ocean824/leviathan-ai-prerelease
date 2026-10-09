"""C-101 journal egress distinguishes verified from historical rows."""

from __future__ import annotations

from datetime import UTC, datetime

import anyio
from fastapi.testclient import TestClient
from leviathan_store.tables import JournalRow, RouteAttemptRow


def test_keyless_journal_rows_are_historical_and_excluded_from_stats(
    client: TestClient,
) -> None:
    client.app.state.leviathan.ledger_integrity_key = None
    replay = client.post("/pipeline/replay")
    assert replay.status_code == 200

    response = client.get("/journal/records")
    body = response.json()

    assert response.status_code == 200
    assert body["provenance"] == "unverified"
    assert body["stats"] == {}
    assert body["unverified_count"] == 1
    assert len(body["records"]) == 1
    assert body["records"][0]["provenance"] == "route_attempt_terminal_unverified"
    assert body["records"][0]["decision_id"] == replay.json()["decision"]["decision_id"]
    assert "proof" not in body["records"][0]


def test_keyed_journal_rows_are_verified_and_counted(client: TestClient) -> None:
    replay = client.post("/pipeline/replay")
    assert replay.status_code == 200

    response = client.get("/journal/records")
    body = response.json()

    assert response.status_code == 200
    assert body["provenance"] == "verified"
    assert body["stats"] == {"win": 1}
    assert body["unverified_count"] == 0
    assert len(body["records"]) == 1
    assert body["records"][0]["provenance"] == "route_attempt_terminal_verified"
    assert body["records"][0]["decision_id"] == replay.json()["decision"]["decision_id"]
    assert "proof" not in body["records"][0]


def test_keyed_reader_returns_proofless_terminal_as_historical(
    client: TestClient,
) -> None:
    replay = client.post("/pipeline/replay")
    decision_id = replay.json()["decision"]["decision_id"]

    async def remove_proof() -> None:
        async with client.app.state.sessionmaker() as session:
            row = await session.get(RouteAttemptRow, decision_id)
            assert row is not None and isinstance(row.outcome, dict)
            row.outcome = {key: value for key, value in row.outcome.items() if key != "proof"}
            await session.commit()

    anyio.run(remove_proof)
    response = client.get("/journal/records")
    body = response.json()

    assert response.status_code == 200
    assert body["provenance"] == "unverified"
    assert body["stats"] == {}
    assert body["unverified_count"] == 1
    assert body["records"][0]["provenance"] == "route_attempt_terminal_unverified"


def test_forged_duplicate_trade_id_payload_is_not_verified(client: TestClient) -> None:
    replay = client.post("/pipeline/replay")
    assert replay.status_code == 200
    verified = replay.json()["journal_record"]
    payload = {**verified, "post_trade_notes": "forged duplicate trade id"}

    async def insert_forged_row() -> None:
        async with client.app.state.sessionmaker() as session:
            session.add(
                JournalRow(
                    trade_id="different_database_primary_key",
                    setup_id=payload["setup_id"],
                    decision_id="different_forged_decision",
                    outcome=payload["outcome"],
                    entry=payload["entry"],
                    exit=payload["exit"],
                    mae=payload["mae"],
                    mfe=payload["mfe"],
                    notes=payload["post_trade_notes"],
                    payload=payload,
                    created_at=datetime.now(UTC),
                )
            )
            await session.commit()

    anyio.run(insert_forged_row)
    response = client.get("/journal/records")
    body = response.json()

    assert response.status_code == 200
    assert body["provenance"] == "mixed"
    assert body["stats"] == {"win": 1}
    assert body["unverified_count"] == 1
    by_notes = {record["post_trade_notes"]: record for record in body["records"]}
    assert by_notes[verified["post_trade_notes"]]["provenance"] == (
        "route_attempt_terminal_verified"
    )
    assert by_notes["forged duplicate trade id"]["provenance"] == (
        "route_attempt_terminal_unverified"
    )


def test_empty_journal_has_none_provenance(client: TestClient) -> None:
    response = client.get("/journal/records")

    assert response.status_code == 200
    assert response.json() == {
        "records": [],
        "stats": {},
        "unverified_count": 0,
        "provenance": "none",
    }


def test_malformed_legacy_rows_are_skipped_and_counted_unverified(
    client: TestClient,
) -> None:
    valid_payload = {
        "trade_id": "malformed-source",
        "setup_id": "setup-legacy",
        "decision_id": "decision-legacy",
        "outcome": "win",
        "entry": "10",
        "exit": "12",
        "mae": None,
        "mfe": None,
        "post_trade_notes": "legacy",
    }
    malformed_payloads: list[object] = [
        {**valid_payload, "unknown_field": "not accepted"},
        {"trade_id": "older-schema", "outcome": "win"},
        ["not", "an", "object"],
        {**valid_payload, "outcome": "not-an-outcome"},
    ]

    async def insert_malformed_rows() -> None:
        async with client.app.state.sessionmaker() as session:
            for index, payload in enumerate(malformed_payloads):
                session.add(
                    JournalRow(
                        trade_id=f"malformed-{index}",
                        setup_id="legacy-setup",
                        decision_id=f"legacy-decision-{index}",
                        outcome="invalid" if index == 3 else "win",
                        entry=None,
                        exit=None,
                        mae=None,
                        mfe=None,
                        notes="legacy payload",
                        payload=payload,  # type: ignore[arg-type]
                        created_at=datetime.now(UTC),
                    )
                )
            await session.commit()

    anyio.run(insert_malformed_rows)
    response = client.get("/journal/records")
    body = response.json()

    assert response.status_code == 200
    assert body["records"] == []
    assert body["stats"] == {}
    assert body["unverified_count"] == 4
    assert body["unverified_reasons"] == {"UNDECODABLE_ROW": 4}
    assert body["provenance"] == "unverified"
