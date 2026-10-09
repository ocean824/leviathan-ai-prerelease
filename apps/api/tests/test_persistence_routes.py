"""Journal and genome surfaces backed by the store package."""

import pytest
from fastapi.testclient import TestClient

from leviathan_api.main import app


@pytest.fixture
def client() -> TestClient:
    with TestClient(app) as c:
        yield c


def test_replay_persists_full_decision_trail(client: TestClient) -> None:
    client.post("/pipeline/replay")

    journal = client.get("/journal/records").json()
    assert journal["stats"] == {"win": 1}
    record = journal["records"][0]
    assert record["outcome"] == "win"
    assert record["entry"] is not None
    assert record["decision_id"].startswith("dec_")


def test_blocked_replay_is_journaled_too(client: TestClient) -> None:
    client.post("/risk/halt", json={"reason": "operator_halt"})
    body = client.post("/pipeline/replay").json()
    assert body["verdict"]["action"] == "halt_all_trading"

    journal = client.get("/journal/records").json()
    assert journal["stats"] == {"blocked": 1}
    assert "operator_halt" in journal["records"][0]["post_trade_notes"]
    client.post("/risk/halt/lift", json={"reason": "operator_halt"})


def test_genomes_lists_seeded_demo_genome_fresh(client: TestClient) -> None:
    body = client.get("/genomes").json()
    ids = {g["strategy_id"]: g for g in body["genomes"]}
    demo = ids["genome_nq_opening_range_break_v1"]
    assert demo["family"] == "opening_range_break"
    assert demo["stale"] is False
