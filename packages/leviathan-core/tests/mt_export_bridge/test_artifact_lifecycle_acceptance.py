"""Independent MTBR-DB-002 acceptance tests derived from wave24-refill §3."""

import hashlib
from datetime import UTC, datetime, timedelta, timezone

import pytest

from leviathan_core.mt_export_bridge_artifacts import (
    ArtifactLifecycleError,
    BridgeChannelStateV1,
    BridgeChannelV1,
    BridgeEventTypeV1,
    BridgeEventV1,
    BuildArtifactV1,
    DeploymentCandidateV1,
    DeploymentModeV1,
    DeploymentStatusV1,
    DeploymentTargetV1,
    ExportJobEvidenceV1,
    ExportJobStatusV1,
    MtPlatformV1,
    append_bridge_event,
    require_bridge_event,
    validate_bridge_channel,
    validate_build_artifact_binding,
    validate_deployment,
)
from leviathan_core.numeric import canonical_json
from leviathan_core.seal import SealError

NOW = datetime(2026, 10, 6, 12, 0, tzinfo=UTC)


def job(
    job_id: str = "job_a", status: ExportJobStatusV1 = ExportJobStatusV1.SUCCEEDED
) -> ExportJobEvidenceV1:
    return ExportJobEvidenceV1(export_job_id=job_id, status=status)


def artifact(
    artifact_id: str = "artifact_a",
    *,
    job_id: str = "job_a",
    platform: MtPlatformV1 = MtPlatformV1.MT5,
    signed: bool = False,
    signature_algo: str | None = None,
) -> BuildArtifactV1:
    return BuildArtifactV1(
        artifact_id=artifact_id,
        export_job_id=job_id,
        platform=platform,
        signed=signed,
        signature_algo=signature_algo,
    )


def target(
    target_id: str = "target_a", platform: MtPlatformV1 = MtPlatformV1.MT5
) -> DeploymentTargetV1:
    return DeploymentTargetV1(target_id=target_id, platform=platform)


def deployment(
    deployment_id: str = "deployment_a",
    *,
    artifact_id: str = "artifact_a",
    target_id: str = "target_a",
    account_id: str = "account_a",
    mode: DeploymentModeV1 = DeploymentModeV1.PAPER,
    magic_number: int = 123,
    status: DeploymentStatusV1 = DeploymentStatusV1.QUEUED,
) -> DeploymentCandidateV1:
    return DeploymentCandidateV1(
        deployment_id=deployment_id,
        artifact_id=artifact_id,
        target_id=target_id,
        account_id=account_id,
        mode=mode,
        magic_number=magic_number,
        status=status,
    )


def assert_content_free_failure(call, canary: str | None = None) -> None:
    with pytest.raises(ArtifactLifecycleError) as caught:
        call()
    error = caught.value
    assert error.code
    assert error.args == (error.code,)
    with pytest.raises(ArtifactLifecycleError) as repeated:
        call()
    assert repeated.value.code == error.code
    rendered = f"{error!s} {error!r} {error.args!r}"
    assert canary is None or canary not in rendered


def test_artifact_requires_matching_successful_export_job():
    assert validate_build_artifact_binding(artifact(), job()) is None

    assert_content_free_failure(
        lambda: validate_build_artifact_binding(artifact(job_id="another_job"), job())
    )
    for status in (
        ExportJobStatusV1.QUEUED,
        ExportJobStatusV1.RUNNING,
        ExportJobStatusV1.FAILED,
        ExportJobStatusV1.CANCELLED,
    ):
        assert_content_free_failure(
            lambda status=status: validate_build_artifact_binding(artifact(), job(status=status))
        )


def test_signed_artifact_requires_a_signature_algorithm():
    assert (
        validate_build_artifact_binding(artifact(signed=True, signature_algo="ed25519"), job())
        is None
    )
    assert validate_build_artifact_binding(artifact(signed=False), job()) is None
    assert_content_free_failure(
        lambda: validate_build_artifact_binding(artifact(signed=True, signature_algo=None), job())
    )


def test_deployment_relations_require_artifact_and_target_identity_and_platform():
    valid = deployment()
    assert validate_deployment(valid, artifact=artifact(), target=target()) is None

    invalid_cases = (
        (deployment(artifact_id="foreign_artifact"), artifact(), target()),
        (deployment(target_id="foreign_target"), artifact(), target()),
        (
            deployment(),
            artifact(platform=MtPlatformV1.MT4),
            target(platform=MtPlatformV1.MT5),
        ),
    )
    for candidate, build, terminal in invalid_cases:
        assert_content_free_failure(
            lambda candidate=candidate, build=build, terminal=terminal: validate_deployment(
                candidate,
                artifact=build,
                target=terminal,
            )
        )


@pytest.mark.parametrize(
    ("proposed_status", "existing_status"),
    [
        (DeploymentStatusV1.QUEUED, DeploymentStatusV1.QUEUED),
        (DeploymentStatusV1.QUEUED, DeploymentStatusV1.DEPLOYED),
        (DeploymentStatusV1.DEPLOYED, DeploymentStatusV1.QUEUED),
        (DeploymentStatusV1.DEPLOYED, DeploymentStatusV1.DEPLOYED),
    ],
)
def test_magic_number_collision_is_unique_while_both_deployments_are_active(
    proposed_status: DeploymentStatusV1,
    existing_status: DeploymentStatusV1,
):
    proposed = deployment(status=proposed_status)
    active_peer = deployment("deployment_peer", status=existing_status)
    assert_content_free_failure(
        lambda: validate_deployment(
            proposed,
            artifact=artifact(),
            target=target(),
            existing_deployments=(active_peer,),
        )
    )

    for inactive in (DeploymentStatusV1.FAILED, DeploymentStatusV1.CANCELLED):
        inactive_peer = deployment(
            "inactive_peer", status=inactive, magic_number=proposed.magic_number
        )
        assert (
            validate_deployment(
                proposed,
                artifact=artifact(),
                target=target(),
                existing_deployments=(inactive_peer,),
            )
            is None
        )
        inactive_candidate = deployment(status=inactive)
        assert (
            validate_deployment(
                inactive_candidate,
                artifact=artifact(),
                target=target(),
                existing_deployments=(deployment("active_peer"),),
            )
            is None
        )


@pytest.mark.parametrize(
    "peer",
    [
        deployment("other_target", target_id="target_b"),
        deployment("other_account", account_id="account_b"),
        deployment("other_mode", mode=DeploymentModeV1.LIVE),
        deployment("other_magic", magic_number=124),
    ],
)
def test_magic_number_uniqueness_key_includes_target_account_mode_and_number(peer):
    assert (
        validate_deployment(
            deployment(),
            artifact=artifact(),
            target=target(),
            existing_deployments=(peer,),
        )
        is None
    )


def test_closed_bridge_channel_requires_closed_timestamp():
    assert (
        validate_bridge_channel(
            BridgeChannelV1(
                channel_id="channel_open", state=BridgeChannelStateV1.OPEN, closed_at=None
            )
        )
        is None
    )
    assert (
        validate_bridge_channel(
            BridgeChannelV1(
                channel_id="channel_error", state=BridgeChannelStateV1.ERROR, closed_at=None
            )
        )
        is None
    )
    assert (
        validate_bridge_channel(
            BridgeChannelV1(
                channel_id="channel_closed", state=BridgeChannelStateV1.CLOSED, closed_at=NOW
            )
        )
        is None
    )
    assert_content_free_failure(
        lambda: validate_bridge_channel(
            BridgeChannelV1(
                channel_id="channel_missing_close_time",
                state=BridgeChannelStateV1.CLOSED,
                closed_at=None,
            )
        )
    )


def test_bridge_event_append_returns_a_new_immutable_issued_chain_record():
    first = append_bridge_event(
        None,
        event_id="event_1",
        channel_id="channel_1",
        event_type=BridgeEventTypeV1.HEARTBEAT,
        event_time=NOW,
        payload_sha256="a" * 64,
    )
    second = append_bridge_event(
        first,
        event_id="event_2",
        channel_id="channel_1",
        event_type=BridgeEventTypeV1.EVENT,
        event_time=NOW + timedelta(seconds=1),
        payload_sha256="b" * 64,
    )

    assert first.event_id == "event_1"
    assert first.sequence == 1
    assert second.event_id == "event_2"
    assert second.sequence == 2
    assert require_bridge_event(second) is second
    assert first.previous_event_sha256 is None
    assert (
        second.previous_event_sha256
        == hashlib.sha256(canonical_json(first.model_dump(mode="json"))).hexdigest()
    )
    assert set(second.model_dump(mode="python")) == {
        "schema_version",
        "event_id",
        "channel_id",
        "sequence",
        "event_type",
        "event_time",
        "payload_sha256",
        "previous_event_sha256",
    }
    assert_content_free_failure(
        lambda: append_bridge_event(
            first,
            event_id="event_other_channel",
            channel_id="different_channel",
            event_type=BridgeEventTypeV1.LOG,
            event_time=NOW + timedelta(seconds=2),
            payload_sha256="c" * 64,
        )
    )

    with pytest.raises(SealError):
        first.event_id = "rewritten"  # type: ignore[misc]
    with pytest.raises(SealError):
        del first.event_id

    try:
        copy_candidate = first.model_copy()
    except SealError:
        pass
    else:
        with pytest.raises(ArtifactLifecycleError) as copied:
            require_bridge_event(copy_candidate)
        assert copied.value.code == "EVENT_INVALID"

    tampered = append_bridge_event(
        None,
        event_id="tamper_source_event",
        channel_id="channel_2",
        event_type=BridgeEventTypeV1.LOG,
        event_time=NOW,
        payload_sha256="d" * 64,
    )
    object.__setattr__(tampered, "event_id", "TAMPER_CANARY")
    with pytest.raises(ArtifactLifecycleError) as tamper_error:
        require_bridge_event(tampered)
    assert tamper_error.value.code == "EVENT_INVALID"
    assert "TAMPER_CANARY" not in str(tamper_error.value)


def test_bridge_events_cannot_be_constructed_without_the_issuer():
    assert_content_free_failure(lambda: BridgeEventV1())


def test_event_time_must_be_exact_utc_and_event_errors_are_content_free():
    local_timestamp = NOW.astimezone(timezone(timedelta(hours=1)))
    assert_content_free_failure(
        lambda: append_bridge_event(
            None,
            event_id="event_time_canary",
            channel_id="channel_1",
            event_type=BridgeEventTypeV1.LOG,
            event_time=local_timestamp,
            payload_sha256="c" * 64,
        ),
        "event_time_canary",
    )
