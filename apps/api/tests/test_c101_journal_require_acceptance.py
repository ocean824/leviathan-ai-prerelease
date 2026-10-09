"""Independent acceptance for verified and historical journal API rows."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import anyio
import pytest
from fastapi.testclient import TestClient
from leviathan_store.tables import JournalRow, RouteAttemptRow

from leviathan_core.execution.order_models import LedgerIntegrityKey
from leviathan_core.schemas import TradeJournalRecord, TradeOutcome

_SYNTHETIC_KEY = b"journal-acceptance-synthetic-key-0000000001"
_KEY = LedgerIntegrityKey(_SYNTHETIC_KEY)
_VERIFIED_PROVENANCE = "route_attempt_terminal_verified"
_UNVERIFIED_PROVENANCE = "route_attempt_terminal_unverified"
_TOP_VERIFIED_PROVENANCE = "verified"
_TOP_UNVERIFIED_PROVENANCE = "unverified"
_TOP_MIXED_PROVENANCE = "mixed"


def _create_terminal(client: TestClient, *, key: LedgerIntegrityKey | None) -> dict[str, Any]:
    client.app.state.leviathan.ledger_integrity_key = key
    response = client.post("/pipeline/replay")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] in {"completed", "blocked"} and body["final"] is True
    return body


def _fetch_journal(client: TestClient, *, has_undecodable_rows: bool = False) -> dict[str, Any]:
    response = client.get("/journal/records")
    assert response.status_code == 200
    report = response.json()
    expected_keys = {"records", "stats", "provenance", "unverified_count"}
    if has_undecodable_rows:
        expected_keys.add("unverified_reasons")
    assert set(report) == expected_keys
    return report


def _forbid_private_material(payload: object) -> None:
    forbidden_keys = {"proof", "mac", "integrity_key", "traceback", "exception"}

    def visit(value: object) -> None:
        if isinstance(value, dict):
            assert not forbidden_keys.intersection(str(key).lower() for key in value)
            for nested in value.values():
                visit(nested)
        elif isinstance(value, list):
            for nested in value:
                visit(nested)

    visit(payload)
    rendered = json.dumps(payload, sort_keys=True).lower()
    assert _SYNTHETIC_KEY.decode() not in rendered
    assert "traceback" not in rendered


def _record_for(report: dict[str, Any], decision_id: str) -> dict[str, Any] | None:
    return next(
        (row for row in report["records"] if row.get("decision_id") == decision_id),
        None,
    )


def _assert_explicitly_untrusted(report: dict[str, Any], record: dict[str, Any]) -> None:
    assert record["provenance"] == _UNVERIFIED_PROVENANCE
    assert report["unverified_count"] >= 1


async def _seed_legacy_journal(client: TestClient) -> str:
    record = TradeJournalRecord(
        trade_id="acceptance_legacy_trade",
        setup_id="acceptance_legacy_setup",
        decision_id="acceptance_legacy_decision",
        outcome=TradeOutcome.BLOCKED,
        post_trade_notes="synthetic proofless historical journal",
    )
    async with client.app.state.sessionmaker() as session:
        session.add(
            JournalRow(
                trade_id=record.trade_id,
                setup_id=record.setup_id,
                decision_id=record.decision_id,
                outcome=record.outcome.value,
                entry=None,
                exit=None,
                mae=None,
                mfe=None,
                notes=record.post_trade_notes,
                payload=record.model_dump(mode="json"),
                created_at=datetime(2026, 10, 6, tzinfo=UTC),
            )
        )
        await session.commit()
    return record.decision_id


async def _seed_trade_id_laundering_row(
    client: TestClient, verified_payload: dict[str, Any]
) -> str:
    forged_decision_id = "acceptance_forged_decision"
    payload = {
        **verified_payload,
        "setup_id": "acceptance_forged_setup",
        "decision_id": forged_decision_id,
        "post_trade_notes": "forged content copied under a different database key",
    }
    async with client.app.state.sessionmaker() as session:
        session.add(
            JournalRow(
                trade_id="acceptance_forged_database_trade",
                setup_id="acceptance_forged_setup",
                decision_id=forged_decision_id,
                outcome=payload["outcome"],
                entry=payload.get("entry"),
                exit=payload.get("exit"),
                mae=payload.get("mae"),
                mfe=payload.get("mfe"),
                notes=payload["post_trade_notes"],
                payload=payload,
                created_at=datetime(2026, 10, 6, tzinfo=UTC),
            )
        )
        await session.commit()
    return forged_decision_id


async def _seed_malformed_journal_payload(client: TestClient, payload: object) -> None:
    async with client.app.state.sessionmaker() as session:
        session.add(
            JournalRow(
                trade_id="acceptance_malformed_database_trade",
                setup_id="acceptance_malformed_database_setup",
                decision_id="acceptance_malformed_database_decision",
                outcome=TradeOutcome.BLOCKED.value,
                entry=None,
                exit=None,
                mae=None,
                mfe=None,
                notes="synthetic raw row with malformed payload",
                payload=payload,
                created_at=datetime(2026, 10, 6, tzinfo=UTC),
            )
        )
        await session.commit()


async def _tamper_proof(
    client: TestClient, decision_id: str, copied_from: str | None = None
) -> None:
    async with client.app.state.sessionmaker() as session:
        row = await session.get(RouteAttemptRow, decision_id)
        assert row is not None and isinstance(row.outcome, dict)
        proof = row.outcome.get("proof")
        assert isinstance(proof, dict)
        if copied_from is None:
            proof = {**proof, "mac": "0" * 64}
        else:
            source = await session.get(RouteAttemptRow, copied_from)
            assert source is not None and isinstance(source.outcome, dict)
            proof = source.outcome.get("proof")
            assert isinstance(proof, dict)
        row.outcome = {**row.outcome, "proof": proof}
        await session.commit()


def test_keyed_terminal_journal_is_verified_and_response_shape_is_stable(
    client: TestClient,
) -> None:
    result = _create_terminal(client, key=_KEY)
    decision_id = result["decision"]["decision_id"]

    response = _fetch_journal(client)
    assert response["provenance"] == _TOP_VERIFIED_PROVENANCE
    record = _record_for(response, decision_id)
    assert record is not None
    assert record["trade_id"] == result["journal_record"]["trade_id"]
    assert record["outcome"] == result["journal_record"]["outcome"]
    assert record["provenance"] == _VERIFIED_PROVENANCE
    assert response["stats"] == {record["outcome"]: 1}
    assert response["unverified_count"] == 0
    _forbid_private_material(response)


def test_duplicate_payload_trade_id_does_not_launder_a_forged_row(
    client: TestClient,
) -> None:
    result = _create_terminal(client, key=_KEY)
    verified_payload = result["journal_record"]
    verified_decision_id = result["decision"]["decision_id"]
    forged_decision_id = anyio.run(_seed_trade_id_laundering_row, client, verified_payload)

    response = _fetch_journal(client)
    verified = _record_for(response, verified_decision_id)
    forged = _record_for(response, forged_decision_id)

    assert verified is not None and forged is not None
    assert verified["trade_id"] == verified_payload["trade_id"]
    assert forged["trade_id"] == verified["trade_id"]
    assert forged["post_trade_notes"] != verified["post_trade_notes"]
    assert verified["provenance"] == _VERIFIED_PROVENANCE
    _assert_explicitly_untrusted(response, forged)
    assert response["unverified_count"] == 1
    assert response["stats"] == {verified["outcome"]: 1}
    assert response["provenance"] == _TOP_MIXED_PROVENANCE
    _forbid_private_material(response)


@pytest.mark.parametrize(
    "malformation",
    ["unknown_extra_key", "older_missing_required_field", "non_object", "invalid_outcome"],
)
def test_undecodable_legacy_journal_rows_are_counted_and_omitted(
    client: TestClient, malformation: str
) -> None:
    payload: Any = {
        "trade_id": "acceptance_malformed_payload_trade",
        "setup_id": "acceptance_malformed_payload_setup",
        "decision_id": "acceptance_malformed_payload_decision",
        "entry": None,
        "exit": None,
        "mae": None,
        "mfe": None,
        "outcome": TradeOutcome.BLOCKED.value,
        "post_trade_notes": "synthetic malformed historical payload",
    }
    if malformation == "unknown_extra_key":
        payload["unrecognized_field"] = "must be rejected"
    elif malformation == "older_missing_required_field":
        payload.pop("setup_id")
    elif malformation == "non_object":
        payload = ["not", "a", "journal-object"]
    else:
        payload["outcome"] = "not-a-valid-trade-outcome"

    anyio.run(_seed_malformed_journal_payload, client, payload)
    response = _fetch_journal(client, has_undecodable_rows=True)

    assert response["records"] == []
    assert response["stats"] == {}
    assert response["provenance"] == _TOP_UNVERIFIED_PROVENANCE
    assert response["unverified_count"] == 1
    assert response["unverified_reasons"] == {"UNDECODABLE_ROW": 1}
    _forbid_private_material(response)


@pytest.mark.parametrize("mode", ["keyless", "proofless"])
def test_keyless_or_proofless_terminal_is_returned_as_unverified_not_verified(
    client: TestClient, mode: str
) -> None:
    if mode == "keyless":
        result = _create_terminal(client, key=None)
        decision_id = result["decision"]["decision_id"]
        expected_trade_id = result["journal_record"]["trade_id"]
    else:
        client.app.state.leviathan.ledger_integrity_key = _KEY
        decision_id = anyio.run(_seed_legacy_journal, client)
        expected_trade_id = "acceptance_legacy_trade"

    response = _fetch_journal(client)
    record = _record_for(response, decision_id)
    assert record is not None, "unverified historical journal row must still be returned"
    assert record["trade_id"] == expected_trade_id
    _assert_explicitly_untrusted(response, record)
    assert record["outcome"] not in response["stats"]
    assert response["provenance"] == _TOP_UNVERIFIED_PROVENANCE
    _forbid_private_material(response)


@pytest.mark.parametrize("case", ["tampered", "cross_decision"])
def test_tampered_or_cross_decision_proof_is_never_returned_as_verified(
    client: TestClient, case: str
) -> None:
    first = _create_terminal(client, key=_KEY)
    first_id = first["decision"]["decision_id"]
    expected_verified_count = 0
    if case == "tampered":
        target_id = first_id
        anyio.run(_tamper_proof, client, target_id)
    else:
        second = _create_terminal(client, key=_KEY)
        target_id = second["decision"]["decision_id"]
        anyio.run(_tamper_proof, client, target_id, first_id)
        expected_verified_count = 1

    response = _fetch_journal(client)
    target = _record_for(response, target_id)
    assert target is not None
    _assert_explicitly_untrusted(response, target)
    assert response["stats"].get(target["outcome"], 0) == expected_verified_count
    expected_top_provenance = (
        _TOP_UNVERIFIED_PROVENANCE if case == "tampered" else _TOP_MIXED_PROVENANCE
    )
    assert response["provenance"] == expected_top_provenance
    _forbid_private_material(response)
