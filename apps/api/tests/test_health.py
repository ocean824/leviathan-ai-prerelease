from fastapi.testclient import TestClient


def test_health_reports_ok_and_operating_mode(client: TestClient) -> None:
    resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["service"] == "leviathan-api"
    assert body["operating_mode"] in {
        "research", "advisory", "semi_auto", "full_auto",
        "prop_firm", "recovery", "signal_only",
    }
