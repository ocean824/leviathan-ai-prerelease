from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from leviathan_market_data.public_sources.api_anything_client import (
    MAX_EVIDENCE_REFS,
    CollectorNotificationV1,
    CollectorSupervisor,
    OperationStatus,
    PublicOperationError,
    PublicOperationErrorCode,
    PublicOperationResultV1,
    SidecarReply,
    parse_operation_result,
)
from leviathan_market_data.public_sources.api_anything_registry import intel_evidence_payload

FIXTURE = Path(__file__).parent / "fixtures" / "api_anything_fear_greed.json"


def _result(payload: dict[str, object] | None = None) -> PublicOperationResultV1:
    raw = json.loads(FIXTURE.read_text(encoding="utf-8"))
    if payload:
        raw.update(payload)
    return parse_operation_result(SidecarReply.model_validate_json(json.dumps(raw)))


def test_recorded_fixture_preserves_provenance_and_future_scheduled_event() -> None:
    result = _result()
    record = result.records[0]
    assert result.source_tier == 3
    assert result.redistribution is False
    assert record.record_id == "cnn-fg-20261009"
    assert record.factor_tags == ("sentiment",)
    assert len(record.record_digest) == 64
    assert record.knowable_at is not None
    # A target event may be future-dated relative to decision time when already knowable.
    future = datetime(2026, 10, 9, 14, 0, tzinfo=UTC)
    assert record.event_at > future


def test_intel_payload_preserves_full_operation_record() -> None:
    record = _result().records[0]
    payload = intel_evidence_payload(record)
    assert payload["operation_id"] == "cnn.fear_greed"
    assert payload["template_version"] == "fixture-1"
    assert payload["source_tier"] == 3
    assert payload["record_id"] == "cnn-fg-20261009"
    assert payload["first_seen_at"] == record.first_seen_at.astimezone(UTC).isoformat()
    assert payload["status"] == "OK"
    assert payload["quality"] == "source_timestamped"
    assert payload["template_sha256"] == record.template_sha256
    assert payload["approval_id"] == record.approval_id
    assert payload["approval_deadline"] == record.approval_deadline.astimezone(UTC).isoformat()
    assert payload["freshness_deadline"] == record.freshness_deadline.astimezone(UTC).isoformat()
    assert payload["redistribution"] is False
    assert payload["record_digest"] == record.record_digest
    assert payload["typed_values"] == record.data.model_dump(mode="json")


def test_available_timestamp_can_establish_source_timestamped_quality() -> None:
    raw = json.loads(FIXTURE.read_text(encoding="utf-8"))
    raw["records"][0]["published_at"] = None
    raw["records"][0]["available_at"] = "2026-10-09T14:59:00Z"
    record = parse_operation_result(SidecarReply.model_validate_json(json.dumps(raw))).records[0]
    assert record.quality == "source_timestamped"
    assert record.knowable_at == datetime(2026, 10, 9, 14, 59, tzinfo=UTC)


def test_learn_validates_both_examples_before_private_stdio_request() -> None:
    supervisor = CollectorSupervisor("node", "sidecar.js")
    sent: dict[str, object] = {}

    def fake_request(
        method: str,
        operation_id: str | None = None,
        args: object = None,
        examples: object = None,
        ) -> SidecarReply:
            sent.update(method=method, operation_id=operation_id, args=args, examples=examples)
            raw = json.loads(FIXTURE.read_text(encoding="utf-8"))
            raw["candidate_only"] = True
            raw["records"] = []
            return SidecarReply.model_validate_json(json.dumps(raw))

    supervisor._request = fake_request  # type: ignore[method-assign]
    version = supervisor.learn("cnn.fear_greed", ({}, {}))
    assert version == "fixture-1"
    assert sent["method"] == "learn"
    assert sent["operation_id"] == "cnn.fear_greed"
    assert sent["examples"] == ({}, {})


def test_learn_rejects_invalid_examples_before_launch() -> None:
    supervisor = CollectorSupervisor("node", "sidecar.js")
    with pytest.raises(PublicOperationError) as exc:
        supervisor.learn("calendar.fed", ({"year": 2026}, {"year": "2027"}))
    assert exc.value.code is PublicOperationErrorCode.SCHEMA_INVALID


def test_sidecar_requires_an_app_owned_data_directory() -> None:
    supervisor = CollectorSupervisor("node", "sidecar.js")
    with pytest.raises(PublicOperationError) as exc:
        supervisor.health()
    assert exc.value.code is PublicOperationErrorCode.COLLECTOR_UNAVAILABLE


def test_missing_knowable_at_is_abstained_from_evidence() -> None:
    raw = json.loads(FIXTURE.read_text(encoding="utf-8"))
    raw["records"][0]["knowable_at"] = None
    raw["records"][0]["quality"] = "availability_unknown"
    raw["knowable_at"] = None
    result = parse_operation_result(SidecarReply.model_validate_json(json.dumps(raw)))
    assert result.evidence_records(datetime(2026, 10, 9, 15, 1, tzinfo=UTC)) == ()


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (OperationStatus.DEGRADED, PublicOperationErrorCode.OPERATION_DEGRADED),
        (OperationStatus.USER_ACTION_REQUIRED, PublicOperationErrorCode.USER_ACTION_REQUIRED),
        (OperationStatus.USER_ACTION_DECLINED, PublicOperationErrorCode.USER_ACTION_DECLINED),
        (OperationStatus.TIMEOUT, PublicOperationErrorCode.TIMEOUT),
    ],
)
def test_unhealthy_operation_status_abstains(
    status: OperationStatus, expected: PublicOperationErrorCode
) -> None:
    result = _result({"status": status.value})
    with pytest.raises(PublicOperationError) as exc:
        result.evidence_records(datetime(2026, 10, 9, 15, 1, tzinfo=UTC))
    assert exc.value.code is expected


@pytest.mark.parametrize("field", ["as_of", "knowable_at"])
def test_future_evidence_hard_fails(field: str) -> None:
    raw = json.loads(FIXTURE.read_text(encoding="utf-8"))
    raw[field] = "2026-10-09T15:02:00Z"
    with pytest.raises(PublicOperationError) as exc:
        parse_operation_result(SidecarReply.model_validate_json(json.dumps(raw)))
    assert exc.value.code is PublicOperationErrorCode.SCHEMA_INVALID


def test_record_bound_is_explicit_and_never_silently_truncated() -> None:
    raw = json.loads(FIXTURE.read_text(encoding="utf-8"))
    raw["records"] *= MAX_EVIDENCE_REFS + 1
    raw["records"] = [
        dict(item, record_id=f"record-{index}") for index, item in enumerate(raw["records"])
    ]
    result = parse_operation_result(SidecarReply.model_validate_json(json.dumps(raw)))
    with pytest.raises(PublicOperationError) as exc:
        result.evidence_records(datetime(2026, 10, 9, 15, 1, tzinfo=UTC))
    assert exc.value.code is PublicOperationErrorCode.SCHEMA_INVALID


def test_future_record_knowability_hard_fails() -> None:
    raw = json.loads(FIXTURE.read_text(encoding="utf-8"))
    raw["records"][0]["knowable_at"] = "2026-10-09T15:02:00Z"
    raw["knowable_at"] = "2026-10-09T15:02:00Z"
    # Keep timestamps within fetched time, then make the decision cutoff earlier.
    raw["fetched_at"] = "2026-10-09T15:05:00Z"
    result = parse_operation_result(SidecarReply.model_validate_json(json.dumps(raw)))
    with pytest.raises(PublicOperationError) as exc:
        result.evidence_records(datetime(2026, 10, 9, 15, 1, tzinfo=UTC))
    assert exc.value.code is PublicOperationErrorCode.SCHEMA_INVALID


def test_redistribution_true_is_rejected() -> None:
    raw = json.loads(FIXTURE.read_text(encoding="utf-8"))
    raw["redistribution"] = True
    with pytest.raises(ValueError):
        SidecarReply.model_validate_json(json.dumps(raw))


def test_user_action_notification_is_typed_and_allowlisted() -> None:
    event = CollectorNotificationV1.model_validate_json(
        json.dumps(
            {
                "type": "notification",
                "request_id": "95c8cf46-15bc-4509-9961-59d6dbe44144",
                "status": "USER_ACTION_REQUIRED",
                "source_id": "api_anything.cnn.fear_greed",
                "operation_id": "cnn.fear_greed",
                "message": "Leviathan needs you to complete a check on cnn-fear-greed.",
            }
        )
    )
    assert event.status == "USER_ACTION_REQUIRED"
    assert event.operation_id == "cnn.fear_greed"


def test_big_sur_replay_mode_disables_learning(monkeypatch: pytest.MonkeyPatch) -> None:
    import leviathan_market_data.public_sources.api_anything_client as client_module

    monkeypatch.setattr(client_module.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(client_module.platform, "mac_ver", lambda: ("11.7.10", ("", "", ""), ""))
    supervisor = CollectorSupervisor("node", "sidecar.js", data_dir="unused")
    assert supervisor._replay_only is True
    with pytest.raises(PublicOperationError) as exc:
        supervisor.learn("calendar.fed", ({"year": 2026}, {"year": 2027}))
    assert exc.value.code is PublicOperationErrorCode.BROWSER_UNAVAILABLE


def test_forced_close_clears_only_app_owned_chrome_profile_locks(tmp_path: Path) -> None:
    supervisor = CollectorSupervisor("node", "sidecar.js", data_dir=tmp_path)
    profile = tmp_path / "isolated" / "cnn-fear-greed"
    profile.mkdir(parents=True)
    lock_file = profile / "SingletonLock"
    lock_file.write_text("stale", encoding="utf-8")
    unrelated = profile / "Preferences"
    unrelated.write_text("keep", encoding="utf-8")

    class ExitedProcess:
        @staticmethod
        def poll() -> int:
            return 0

    supervisor._proc = ExitedProcess()  # type: ignore[assignment]
    supervisor.close(force=True)
    assert not lock_file.exists()
    assert unrelated.read_text(encoding="utf-8") == "keep"


def test_template_export_import_requires_committed_pin_and_rejects_cookie_material(
    tmp_path: Path,
) -> None:
    from leviathan_market_data.public_sources.api_anything_templates import (
        export_pinned_template,
        import_pinned_template,
    )

    raw = b'{"name":"cnn-fear-greed","request":{"url":"https://www.cnn.com/api"}}'
    digest = hashlib.sha256(raw).hexdigest()
    source_templates = tmp_path / "source" / "services" / "public-collector" / "templates"
    registry = source_templates / "PINNED.json"
    pin = {
        "version": "v1",
        "sha256": digest,
        "template_path": "cnn.fear_greed/v1.json",
        "tos_review_id": "fixture-review",
        "allowed_hosts": ["www.cnn.com"],
        "challenge_hosts": [],
        "review_note": "reviewed fixture pin",
    }
    registry.parent.mkdir(parents=True)
    registry.write_text(json.dumps({"operations": {"cnn.fear_greed": pin}}), encoding="utf-8")
    template_path = source_templates / pin["template_path"]
    template_path.parent.mkdir(parents=True)
    template_path.write_bytes(raw)
    bundle = tmp_path / "export.json"
    assert export_pinned_template(
        "cnn.fear_greed",
        data_dir=tmp_path / "unused-data",
        registry_path=registry,
        destination=bundle,
    ) == digest

    destination_templates = tmp_path / "destination" / "services" / "public-collector" / "templates"
    destination_registry = destination_templates / "PINNED.json"
    destination_registry.parent.mkdir(parents=True)
    destination_registry.write_text(
        json.dumps({"operations": {"cnn.fear_greed": pin}}), encoding="utf-8"
    )
    assert import_pinned_template(
        bundle,
        registry_path=destination_registry,
        data_dir=tmp_path / "unused-replay-data",
    ) == digest
    assert (destination_templates / pin["template_path"]).read_bytes() == raw

    exported = json.loads(bundle.read_text(encoding="utf-8"))
    exported["approval_id"] = "unreviewed"
    bundle.write_text(json.dumps(exported), encoding="utf-8")
    with pytest.raises(PublicOperationError) as exc:
        import_pinned_template(
            bundle,
            registry_path=destination_registry,
            data_dir=tmp_path / "unused-replay-data",
        )
    assert exc.value.code is PublicOperationErrorCode.SCHEMA_INVALID

    unsafe = b'{"headers":{"Cookie":"session=owner"}}'
    template_path.write_bytes(unsafe)
    registry_data = json.loads(registry.read_text(encoding="utf-8"))
    registry_data["operations"]["cnn.fear_greed"]["sha256"] = hashlib.sha256(unsafe).hexdigest()
    registry.write_text(json.dumps(registry_data), encoding="utf-8")
    with pytest.raises(PublicOperationError) as exc:
        export_pinned_template(
            "cnn.fear_greed",
            data_dir=tmp_path / "unused-data",
            registry_path=registry,
            destination=bundle,
        )
    assert exc.value.code is PublicOperationErrorCode.SCHEMA_INVALID
