"""Independent acceptance for the closed HALT reason boundary."""

from __future__ import annotations

from typing import Any, cast

import pytest
from fastapi.testclient import TestClient
from structlog.testing import capture_logs

from leviathan_core.risk.halt_reasons import HaltReasonPatternV1, HaltReasonV1

STATIC_REASONS = tuple(reason.value for reason in HaltReasonV1)
DYNAMIC_DIGEST = "a" * 64
DYNAMIC_REASONS = tuple(f"{pattern.value}:{DYNAMIC_DIGEST}" for pattern in HaltReasonPatternV1)
INVALID_REASONS = (
    "my password is x",
    "operator_test",
    "omega_kill:" + "a" * 63,
    "omega_kill:" + "A" * 64,
    "omega_unknown:" + DYNAMIC_DIGEST,
    "operator_hold:" + DYNAMIC_DIGEST,
)
NON_TEXT_VALUES: tuple[object, ...] = (
    7,
    {"password": "synthetic-caller-content"},
    ["synthetic caller content"],
)


@pytest.mark.parametrize("reason", STATIC_REASONS)
def test_known_static_and_dynamic_reasons_engage_and_lift(
    entitled_desktop_lift_client, reason: str
) -> None:
    client, headers = entitled_desktop_lift_client
    engaged = client.post("/risk/halt", json={"reason": reason})
    assert engaged.status_code == 200
    assert engaged.json() == {"halted": True, "active_halts": [reason]}

    status = client.get("/risk/status")
    assert status.status_code == 200
    assert status.json()["active_halts"] == [reason]

    lifted = client.post("/risk/halt/lift", json={"reason": reason}, headers=headers)
    assert lifted.status_code == 200
    assert lifted.json() == {"halted": False, "active_halts": []}


@pytest.mark.parametrize("reason", DYNAMIC_REASONS)
def test_public_engage_rejects_omega_pattern_reasons_without_mutation(
    client: TestClient, reason: str
) -> None:
    response = client.post("/risk/halt", json={"reason": reason})
    assert response.status_code == 422
    assert response.json() == {"detail": "INVALID_HALT_REASON"}
    assert reason not in response.text
    assert client.get("/risk/status").json()["active_halts"] == []


@pytest.mark.parametrize("reason", DYNAMIC_REASONS)
def test_active_omega_pattern_reason_can_be_lifted(
    entitled_desktop_lift_client, reason: str
) -> None:
    client, headers = entitled_desktop_lift_client
    cast(Any, client.app).state.leviathan.halts.engage(reason)
    assert client.get("/risk/status").json()["active_halts"] == [reason]

    response = client.post("/risk/halt/lift", json={"reason": reason}, headers=headers)
    assert response.status_code == 200
    assert response.json() == {"halted": False, "active_halts": []}
    assert reason not in response.text


LEGACY_FREE_TEXT_REASONS = (
    "operator_test",
    "operator_drill",
    "test_fault",
    "review_hold",
)


@pytest.mark.parametrize("reason", LEGACY_FREE_TEXT_REASONS)
def test_public_engage_rejects_legacy_free_text_reasons_without_mutation(
    client: TestClient, reason: str
) -> None:
    response = client.post("/risk/halt", json={"reason": reason})
    assert response.status_code == 422
    assert response.json() == {"detail": "INVALID_HALT_REASON"}
    assert reason not in response.text
    assert client.get("/risk/status").json()["active_halts"] == []


@pytest.mark.parametrize("reason", LEGACY_FREE_TEXT_REASONS)
def test_active_legacy_reason_can_be_lifted_with_fixed_audit_code(
    entitled_desktop_lift_client, reason: str
) -> None:
    client, headers = entitled_desktop_lift_client
    cast(Any, client.app).state.leviathan.halts.engage(reason)

    with capture_logs() as logs:
        response = client.post("/risk/halt/lift", json={"reason": reason}, headers=headers)

    assert response.status_code == 200
    assert response.json() == {"halted": False, "active_halts": []}
    assert reason not in response.text
    assert any(
        event.get("event") == "halt_legacy_reason_lift"
        and event.get("code") == "LEGACY_REASON_LIFT"
        for event in logs
    )
    assert reason not in repr(logs)
    assert client.get("/risk/status").json()["active_halts"] == []


@pytest.mark.parametrize("inactive_reason", LEGACY_FREE_TEXT_REASONS)
def test_unknown_and_inactive_legacy_lifts_return_identical_422(
    entitled_desktop_lift_client, inactive_reason: str
) -> None:
    client, headers = entitled_desktop_lift_client
    unknown = "unrecognized_legacy_reason"
    unknown_response = client.post("/risk/halt/lift", json={"reason": unknown}, headers=headers)
    inactive_response = client.post(
        "/risk/halt/lift", json={"reason": inactive_reason}, headers=headers
    )

    assert unknown_response.status_code == inactive_response.status_code == 422
    assert unknown_response.json() == inactive_response.json() == {"detail": "INVALID_HALT_REASON"}
    assert unknown not in unknown_response.text
    assert inactive_reason not in inactive_response.text
    assert client.get("/risk/status").json()["active_halts"] == []


@pytest.mark.parametrize("endpoint", ("/risk/halt", "/risk/halt/lift"))
@pytest.mark.parametrize("reason", INVALID_REASONS)
def test_unknown_reasons_are_content_free_422_and_do_not_mutate_halts(
    entitled_desktop_lift_client, endpoint: str, reason: str
) -> None:
    client, headers = entitled_desktop_lift_client
    if endpoint == "/risk/halt/lift":
        seed = client.post("/risk/halt", json={"reason": HaltReasonV1.OPERATOR_HOLD.value})
        assert seed.status_code == 200
        expected_active = [HaltReasonV1.OPERATOR_HOLD.value]
    else:
        expected_active = []

    response = client.post(endpoint, json={"reason": reason}, headers=headers)
    assert response.status_code == 422
    assert response.json() == {"detail": "INVALID_HALT_REASON"}
    assert reason not in response.text
    assert client.get("/risk/status").json()["active_halts"] == expected_active


@pytest.mark.parametrize("endpoint", ("/risk/halt", "/risk/halt/lift"))
@pytest.mark.parametrize("reason", NON_TEXT_VALUES)
def test_non_text_reasons_are_content_free_422_and_do_not_mutate_halts(
    entitled_desktop_lift_client, endpoint: str, reason: object
) -> None:
    client, headers = entitled_desktop_lift_client
    if endpoint == "/risk/halt/lift":
        seed = client.post("/risk/halt", json={"reason": HaltReasonV1.OPERATOR_HOLD.value})
        assert seed.status_code == 200
        expected_active = [HaltReasonV1.OPERATOR_HOLD.value]
    else:
        expected_active = []

    response = client.post(endpoint, json={"reason": reason}, headers=headers)
    assert response.status_code == 422
    assert response.json() == {"detail": "INVALID_HALT_REASON"}
    assert repr(reason) not in response.text
    assert client.get("/risk/status").json()["active_halts"] == expected_active


@pytest.mark.parametrize("endpoint", ("/risk/halt", "/risk/halt/lift"))
def test_operator_note_outside_closed_grammar_is_rejected_without_mutation(
    entitled_desktop_lift_client, endpoint: str
) -> None:
    client, headers = entitled_desktop_lift_client
    active_reason = HaltReasonV1.OPERATOR_HOLD.value
    assert client.post("/risk/halt", json={"reason": active_reason}).status_code == 200
    reason = HaltReasonV1.RISK_LIMIT_BREACH.value if endpoint == "/risk/halt" else active_reason
    caller_text = "my password is x"

    response = client.post(endpoint, json={"reason": reason, "note": caller_text}, headers=headers)
    assert response.status_code == 422
    assert response.json() == {"detail": "INVALID_HALT_NOTE"}
    assert caller_text not in response.text
    status = client.get("/risk/status")
    assert status.json()["active_halts"] == [active_reason]
    assert caller_text not in status.text


@pytest.mark.parametrize("endpoint", ("/risk/halt", "/risk/halt/lift"))
@pytest.mark.parametrize("note", NON_TEXT_VALUES)
def test_non_text_operator_notes_are_content_free_422_without_mutation(
    entitled_desktop_lift_client, endpoint: str, note: object
) -> None:
    client, headers = entitled_desktop_lift_client
    active_reason = HaltReasonV1.OPERATOR_HOLD.value
    seed = client.post("/risk/halt", json={"reason": active_reason})
    assert seed.status_code == 200
    reason = HaltReasonV1.RISK_LIMIT_BREACH.value if endpoint == "/risk/halt" else active_reason

    response = client.post(endpoint, json={"reason": reason, "note": note}, headers=headers)
    assert response.status_code == 422
    assert response.json() == {"detail": "INVALID_HALT_NOTE"}
    assert repr(note) not in response.text
    status = client.get("/risk/status")
    assert status.json()["active_halts"] == [active_reason]
    assert repr(note) not in status.text


def test_safe_operator_note_is_accepted_but_never_persisted_or_returned(
    entitled_desktop_lift_client,
) -> None:
    client, headers = entitled_desktop_lift_client
    reason = HaltReasonV1.OPERATOR_HALT.value
    note = "Manual review7"
    response = client.post("/risk/halt", json={"reason": reason, "note": note})
    assert response.status_code == 200
    assert note not in response.text

    status = client.get("/risk/status")
    assert status.json()["active_halts"] == [reason]
    assert note not in status.text

    lifted = client.post("/risk/halt/lift", json={"reason": reason, "note": note}, headers=headers)
    assert lifted.status_code == 200
    assert note not in lifted.text


def test_durable_halt_survives_api_lifespan_and_lifts_by_exact_reason(
    entitled_desktop_lift_client,
) -> None:
    reason = HaltReasonV1.OPERATOR_HOLD.value
    client, headers = entitled_desktop_lift_client
    assert client.post("/risk/halt", json={"reason": reason}).status_code == 200
    # Re-enter the same TestClient to run two real app lifespans sequentially
    # without opening two writers on the exclusive HALT store lock.
    client.__exit__(None, None, None)
    client.__enter__()
    status = client.get("/risk/status").json()
    assert status["halted"] is True
    assert status["active_halts"] == [reason]

    lifted = client.post("/risk/halt/lift", json={"reason": reason}, headers=headers)
    assert lifted.status_code == 200
    assert lifted.json() == {"halted": False, "active_halts": []}
