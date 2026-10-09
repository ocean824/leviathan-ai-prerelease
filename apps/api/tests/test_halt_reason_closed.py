from fastapi.testclient import TestClient

from leviathan_api.main import app
from leviathan_api.routers import risk
from leviathan_core.risk.halt_reasons import (
    HaltReasonPatternV1,
    HaltReasonV1,
    is_known_halt_reason,
)


def test_closed_reason_vocabulary_accepts_only_declared_codes_and_patterns() -> None:
    assert all(is_known_halt_reason(reason) for reason in HaltReasonV1)
    assert is_known_halt_reason("omega_kill:" + "a" * 64)
    assert is_known_halt_reason("omega_bridge_disconnected:" + "0" * 64)
    assert is_known_halt_reason("omega_bridge_degraded:" + "f" * 64)
    assert {pattern.value for pattern in HaltReasonPatternV1} == {
        "omega_kill",
        "omega_bridge_disconnected",
        "omega_bridge_degraded",
    }


def test_reason_validation_rejects_free_text_without_engaging() -> None:
    with TestClient(app) as client:
        for body in (
            {"reason": "PRIVATE_MARKER operator requested halt"},
            {"reason": {"secret": "PRIVATE_MARKER"}},
            {"note": "PRIVATE_MARKER without a reason"},
        ):
            response = client.post("/risk/halt", json=body)
            assert response.status_code == 422
            assert response.json() == {"detail": "INVALID_HALT_REASON"}
            assert "PRIVATE_MARKER" not in response.text
        assert client.get("/risk/status").json()["active_halts"] == []


def test_reason_validation_rejects_unknown_lift_without_mutation() -> None:
    with TestClient(app) as client:
        engaged = client.post("/risk/halt", json={"reason": "operator_hold"})
        assert engaged.status_code == 200
        response = client.post(
            "/risk/halt/lift", json={"reason": "PRIVATE_MARKER arbitrary reason"}
        )
        assert response.status_code == 422
        assert response.json() == {"detail": "INVALID_HALT_REASON"}
        assert "PRIVATE_MARKER" not in response.text
        assert client.get("/risk/status").json()["active_halts"] == ["operator_hold"]


def test_operator_note_uses_safe_label_grammar_and_is_not_persisted() -> None:
    with TestClient(app) as client:
        response = client.post(
            "/risk/halt", json={"reason": "operator_hold", "note": "Desk Review2"}
        )
        assert response.status_code == 200
        assert client.get("/risk/status").json()["active_halts"] == ["operator_hold"]

        rejected = client.post(
            "/risk/halt/lift",
            json={"reason": "operator_hold", "note": "token=PRIVATE_MARKER"},
        )
        assert rejected.status_code == 422
        assert rejected.json() == {"detail": "INVALID_HALT_NOTE"}
        assert "PRIVATE_MARKER" not in rejected.text
        malformed = client.post(
            "/risk/halt/lift", json={"reason": "operator_hold", "note": {"x": "PRIVATE_MARKER"}}
        )
        assert malformed.status_code == 422
        assert malformed.json() == {"detail": "INVALID_HALT_NOTE"}
        assert "PRIVATE_MARKER" not in malformed.text
        assert client.get("/risk/status").json()["active_halts"] == ["operator_hold"]


def test_dynamic_reason_requires_exact_known_prefix_and_sha256() -> None:
    assert is_known_halt_reason("omega_kill:" + "a" * 64)
    assert not is_known_halt_reason("omega_kill:" + "A" * 64)
    assert not is_known_halt_reason("omega_kill:" + "a" * 63)
    assert not is_known_halt_reason("omega_unknown:" + "a" * 64)
    assert not is_known_halt_reason("omega_kill:" + "a" * 64 + ":extra")
    assert not is_known_halt_reason("operator hold")
    assert not is_known_halt_reason(None)


def test_public_engage_rejects_dynamic_omega_keys() -> None:
    with TestClient(app) as client:
        for reason in (
            "omega_kill:" + "a" * 64,
            "omega_bridge_disconnected:" + "b" * 64,
            "omega_bridge_degraded:" + "c" * 64,
        ):
            response = client.post("/risk/halt", json={"reason": reason})
            assert response.status_code == 422
            assert response.json() == {"detail": "INVALID_HALT_REASON"}
            assert reason not in response.text
        assert client.get("/risk/status").json()["active_halts"] == []


def test_active_legacy_reason_can_only_be_lifted_and_is_logged_without_reason(
    monkeypatch,
) -> None:
    legacy_reasons = (
        "operator_test",
        "operator_drill",
        "test_fault",
        "review_hold",
    )
    observed: list[tuple[str, dict[str, str]]] = []
    monkeypatch.setattr(
        risk.log,
        "info",
        lambda event, **fields: observed.append((event, fields)),
    )

    with TestClient(app) as client:
        halts = client.app.state.leviathan.halts
        for reason in legacy_reasons:
            # Simulate a reason already present in the durable authority before
            # the closed vocabulary was deployed.
            halts.engage(reason)
            rejected_engage = client.post("/risk/halt", json={"reason": reason})
            assert rejected_engage.status_code == 422
            assert rejected_engage.json() == {"detail": "INVALID_HALT_REASON"}
            assert client.get("/risk/status").json()["active_halts"] == [reason]

            lifted = client.post("/risk/halt/lift", json={"reason": reason})
            assert lifted.status_code == 200
            assert lifted.json() == {"halted": False, "active_halts": []}
            assert reason not in lifted.text

        assert observed == [
            ("halt_legacy_reason_lift", {"code": "LEGACY_REASON_LIFT"})
        ] * len(legacy_reasons)


def test_inactive_legacy_lift_has_same_fixed_error_as_unknown_lift() -> None:
    with TestClient(app) as client:
        unknown = client.post(
            "/risk/halt/lift", json={"reason": "unknown legacy value"}
        )
        assert unknown.status_code == 422
        assert unknown.json() == {"detail": "INVALID_HALT_REASON"}

        client.app.state.leviathan.halts.engage("inactive legacy value")
        client.app.state.leviathan.halts.lift_committed("inactive legacy value")
        inactive = client.post(
            "/risk/halt/lift", json={"reason": "inactive legacy value"}
        )
        assert inactive.status_code == unknown.status_code
        assert inactive.json() == unknown.json()
        assert client.app.state.leviathan.halts.active == ()
