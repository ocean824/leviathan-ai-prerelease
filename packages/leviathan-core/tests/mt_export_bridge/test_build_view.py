from __future__ import annotations

import pytest

from leviathan_core.mt_export_bridge_build_view import (
    BUILD_VIEW_SEAL_TAG,
    BuildEventV1,
    BuildSeverityV1,
    BuildStatusV1,
    BuildViewError,
    BuildViewV1,
    project_build_events,
)
from leviathan_core.seal import SealError, require


def _event(
    status: BuildStatusV1,
    severity: BuildSeverityV1 = BuildSeverityV1.INFO,
    *,
    line: int | None = None,
    message: str = "synthetic build output",
) -> BuildEventV1:
    return BuildEventV1(
        status=status,
        severity=severity,
        source_line=line,
        message=message,
    )


def test_empty_stream_projects_to_idle_with_actions_disabled() -> None:
    view = project_build_events(())

    assert view.status is BuildStatusV1.IDLE
    assert view.logs == ()
    assert view.packaging_allowed is False
    assert view.deploy_allowed is False
    assert require(view, BUILD_VIEW_SEAL_TAG) is view


def test_successful_sequence_preserves_safe_metadata_and_order() -> None:
    secret_log = "C:\\Users\\trader\\secret\\token=synthetic-canary"
    events = (
        _event(BuildStatusV1.GENERATING, message=secret_log),
        _event(BuildStatusV1.COMPILING, BuildSeverityV1.WARNING, line=17, message=secret_log),
        _event(BuildStatusV1.PACKAGING, BuildSeverityV1.INFO, message=secret_log),
        _event(BuildStatusV1.READY, BuildSeverityV1.ERROR, line=42, message=secret_log),
    )

    view = project_build_events(events)

    assert view.status is BuildStatusV1.READY
    assert view.packaging_allowed is True
    assert view.deploy_allowed is False
    assert tuple(log.severity for log in view.logs) == (
        BuildSeverityV1.INFO,
        BuildSeverityV1.WARNING,
        BuildSeverityV1.INFO,
        BuildSeverityV1.ERROR,
    )
    assert tuple(log.source_line for log in view.logs) == (None, 17, None, 42)
    assert {log.message for log in view.logs} == {"[REDACTED]"}
    assert secret_log not in repr(view)
    assert require(view, BUILD_VIEW_SEAL_TAG) is view


@pytest.mark.parametrize(
    "events",
    [
        (_event(BuildStatusV1.GENERATING), _event(BuildStatusV1.FAILED)),
        (
            _event(BuildStatusV1.GENERATING),
            _event(BuildStatusV1.COMPILING),
            _event(BuildStatusV1.FAILED),
        ),
        (
            _event(BuildStatusV1.GENERATING),
            _event(BuildStatusV1.COMPILING),
            _event(BuildStatusV1.PACKAGING),
            _event(BuildStatusV1.FAILED),
        ),
    ],
)
def test_failure_is_terminal_and_never_enables_packaging(
    events: tuple[BuildEventV1, ...],
) -> None:
    view = project_build_events(events)

    assert view.status is BuildStatusV1.FAILED
    assert view.packaging_allowed is False
    assert view.deploy_allowed is False


@pytest.mark.parametrize(
    "events",
    [
        (_event(BuildStatusV1.COMPILING, message="private-marker"),),
        (_event(BuildStatusV1.GENERATING), _event(BuildStatusV1.PACKAGING)),
        (
            _event(BuildStatusV1.GENERATING),
            _event(BuildStatusV1.COMPILING),
            _event(BuildStatusV1.PACKAGING),
            _event(BuildStatusV1.READY),
            _event(BuildStatusV1.FAILED, message="private-marker"),
        ),
        (_event(BuildStatusV1.IDLE),),
    ],
)
def test_illegal_or_post_terminal_transitions_raise_content_free_error(
    events: tuple[BuildEventV1, ...],
) -> None:
    with pytest.raises(BuildViewError) as raised:
        project_build_events(events)

    assert raised.value.code == "INVALID_TRANSITION"
    assert "private-marker" not in str(raised.value)
    assert "private-marker" not in repr(raised.value)


def test_event_constructor_rejects_invalid_severity_and_line_without_echo() -> None:
    with pytest.raises(SealError) as raised:
        BuildEventV1(
            status=BuildStatusV1.COMPILING,
            severity="TRACE",
            source_line=0,
            message="private-marker",
        )

    assert "private-marker" not in str(raised.value)
    assert "private-marker" not in repr(raised.value)


def test_boolean_is_not_a_valid_source_line() -> None:
    with pytest.raises(SealError):
        BuildEventV1(
            status=BuildStatusV1.GENERATING,
            severity=BuildSeverityV1.INFO,
            source_line=True,
            message="safe synthetic text",
        )


def test_wrong_event_type_is_denied_without_echo() -> None:
    with pytest.raises(BuildViewError) as raised:
        project_build_events([{"status": "Ready", "message": "private-marker"}])  # type: ignore[list-item]

    assert raised.value.code == "INVALID_EVENTS"
    assert "private-marker" not in str(raised.value)


def test_raised_build_view_error_subclass_from_iterator_is_normalized() -> None:
    class LeakyBuildViewError(BuildViewError):
        def __str__(self) -> str:
            return "LEAKED: private-token-canary"

    def malicious_events():
        yield _event(BuildStatusV1.GENERATING)
        raise LeakyBuildViewError("private-token-canary")

    with pytest.raises(BuildViewError) as raised:
        project_build_events(malicious_events())

    assert type(raised.value) is BuildViewError
    assert raised.value.code == "INVALID_EVENTS"
    assert str(raised.value) == "INVALID_EVENTS"
    assert "private-token-canary" not in repr(raised.value)
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None


def test_build_view_is_sealed_and_raw_log_cannot_be_inserted() -> None:
    view = project_build_events((_event(BuildStatusV1.GENERATING),))
    assert require(view, BUILD_VIEW_SEAL_TAG) is view

    with pytest.raises(SealError):
        view.status = BuildStatusV1.READY  # type: ignore[misc]

    with pytest.raises(SealError):
        project_build_events((_event(BuildStatusV1.GENERATING),)).model_copy(
            update={"status": BuildStatusV1.READY, "packaging_allowed": True}
        )


def test_unissued_ready_view_cannot_enable_packaging() -> None:
    view = BuildViewV1(status=BuildStatusV1.READY, logs=())

    assert view.packaging_allowed is False
    with pytest.raises(SealError):
        require(view, BUILD_VIEW_SEAL_TAG)


def test_event_text_is_bounded_and_validation_errors_do_not_expose_it() -> None:
    with pytest.raises(SealError) as raised:
        BuildEventV1(
            status=BuildStatusV1.GENERATING,
            severity=BuildSeverityV1.INFO,
            message="secret" * 1000,
        )

    assert "secret" not in str(raised.value)
    assert "secret" not in repr(raised.value)
