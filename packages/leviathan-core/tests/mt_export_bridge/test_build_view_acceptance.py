from __future__ import annotations

import pytest

from leviathan_core.mt_export_bridge_build_view import (
    BuildEventV1,
    BuildSeverityV1,
    BuildStatusV1,
    BuildViewError,
    BuildViewV1,
    project_build_events,
)
from leviathan_core.seal import SealError


def _event(
    status: BuildStatusV1,
    severity: BuildSeverityV1 = BuildSeverityV1.INFO,
    *,
    line: int | None = None,
    message: str = "synthetic build message",
) -> BuildEventV1:
    return BuildEventV1(
        status=status,
        severity=severity,
        source_line=line,
        message=message,
    )


def _prefix(status: BuildStatusV1) -> tuple[BuildStatusV1, ...]:
    return {
        BuildStatusV1.IDLE: (),
        BuildStatusV1.GENERATING: (BuildStatusV1.GENERATING,),
        BuildStatusV1.COMPILING: (
            BuildStatusV1.GENERATING,
            BuildStatusV1.COMPILING,
        ),
        BuildStatusV1.PACKAGING: (
            BuildStatusV1.GENERATING,
            BuildStatusV1.COMPILING,
            BuildStatusV1.PACKAGING,
        ),
        BuildStatusV1.READY: (
            BuildStatusV1.GENERATING,
            BuildStatusV1.COMPILING,
            BuildStatusV1.PACKAGING,
            BuildStatusV1.READY,
        ),
        BuildStatusV1.FAILED: (
            BuildStatusV1.GENERATING,
            BuildStatusV1.FAILED,
        ),
    }[status]


_ALLOWED: dict[BuildStatusV1, frozenset[BuildStatusV1]] = {
    BuildStatusV1.IDLE: frozenset({BuildStatusV1.GENERATING}),
    BuildStatusV1.GENERATING: frozenset({BuildStatusV1.COMPILING, BuildStatusV1.FAILED}),
    BuildStatusV1.COMPILING: frozenset({BuildStatusV1.PACKAGING, BuildStatusV1.FAILED}),
    BuildStatusV1.PACKAGING: frozenset({BuildStatusV1.READY, BuildStatusV1.FAILED}),
    BuildStatusV1.READY: frozenset(),
    BuildStatusV1.FAILED: frozenset(),
}


def test_empty_input_is_idle_and_allows_no_actions() -> None:
    view = project_build_events(())

    assert view.status is BuildStatusV1.IDLE
    assert view.logs == ()
    assert view.packaging_allowed is False
    assert view.deploy_allowed is False


def test_full_success_path_preserves_ordered_severity_and_exact_line_refs() -> None:
    source_messages = (
        "generated token=ACCEPTANCE_SECRET_CANARY",
        "compiler warning at private/path.mq5",
        "packaging details ACCEPTANCE_SECRET_CANARY",
        "ready with account=synthetic-account",
    )
    events = (
        _event(BuildStatusV1.GENERATING, message=source_messages[0]),
        _event(
            BuildStatusV1.COMPILING,
            BuildSeverityV1.WARNING,
            line=17,
            message=source_messages[1],
        ),
        _event(
            BuildStatusV1.PACKAGING,
            BuildSeverityV1.INFO,
            message=source_messages[2],
        ),
        _event(
            BuildStatusV1.READY,
            line=43,
            message=source_messages[3],
        ),
    )

    view = project_build_events(events)

    assert view.status is BuildStatusV1.READY
    assert view.packaging_allowed is True
    assert view.deploy_allowed is False
    assert tuple(entry.severity for entry in view.logs) == (
        BuildSeverityV1.INFO,
        BuildSeverityV1.WARNING,
        BuildSeverityV1.INFO,
        BuildSeverityV1.INFO,
    )
    assert tuple(entry.source_line for entry in view.logs) == (
        None,
        17,
        None,
        43,
    )
    assert tuple(entry.message for entry in view.logs) == ("[REDACTED]",) * 4
    rendered = repr(view)
    for secret in source_messages:
        assert secret not in rendered


@pytest.mark.parametrize(
    ("status", "expected_packaging"),
    [
        (BuildStatusV1.IDLE, False),
        (BuildStatusV1.GENERATING, False),
        (BuildStatusV1.COMPILING, False),
        (BuildStatusV1.PACKAGING, False),
        (BuildStatusV1.READY, True),
        (BuildStatusV1.FAILED, False),
    ],
)
def test_packaging_is_enabled_only_for_issued_ready_view(
    status: BuildStatusV1, expected_packaging: bool
) -> None:
    view = project_build_events(tuple(_event(step) for step in _prefix(status)))

    assert view.status is status
    assert view.packaging_allowed is expected_packaging
    assert view.deploy_allowed is False


def test_hand_built_ready_view_does_not_enable_packaging() -> None:
    unissued = BuildViewV1(status=BuildStatusV1.READY, logs=())

    assert unissued.status is BuildStatusV1.READY
    assert unissued.packaging_allowed is False
    assert unissued.deploy_allowed is False


@pytest.mark.parametrize(
    ("current", "next_status"),
    [
        (current, next_status)
        for current in BuildStatusV1
        for next_status in BuildStatusV1
        if next_status not in _ALLOWED[current]
    ],
)
def test_every_undefined_transition_is_rejected_without_echo(
    current: BuildStatusV1, next_status: BuildStatusV1
) -> None:
    secret = "DO_NOT_ECHO_BUILD_SECRET"
    events = (*(_event(step) for step in _prefix(current)), _event(next_status, message=secret))

    with pytest.raises(BuildViewError) as raised:
        project_build_events(events)

    assert raised.value.code == "INVALID_TRANSITION"
    assert secret not in str(raised.value)
    assert secret not in repr(raised.value)


@pytest.mark.parametrize(
    "active_prefix",
    [
        (BuildStatusV1.GENERATING,),
        (BuildStatusV1.GENERATING, BuildStatusV1.COMPILING),
        (
            BuildStatusV1.GENERATING,
            BuildStatusV1.COMPILING,
            BuildStatusV1.PACKAGING,
        ),
    ],
)
def test_failure_is_legal_from_each_active_state_and_terminal(
    active_prefix: tuple[BuildStatusV1, ...],
) -> None:
    view = project_build_events(
        (
            *(_event(step) for step in active_prefix),
            _event(BuildStatusV1.FAILED, BuildSeverityV1.ERROR, line=91),
        )
    )

    assert view.status is BuildStatusV1.FAILED
    assert view.logs[-1].severity is BuildSeverityV1.ERROR
    assert view.logs[-1].source_line == 91
    assert view.packaging_allowed is False
    assert view.deploy_allowed is False


def test_severity_sequence_and_line_references_are_preserved_on_failure() -> None:
    events = (
        _event(BuildStatusV1.GENERATING, BuildSeverityV1.INFO),
        _event(BuildStatusV1.COMPILING, BuildSeverityV1.WARNING, line=17),
        _event(BuildStatusV1.FAILED, BuildSeverityV1.ERROR, line=42),
    )

    view = project_build_events(events)

    assert view.status is BuildStatusV1.FAILED
    assert tuple(entry.severity for entry in view.logs) == (
        BuildSeverityV1.INFO,
        BuildSeverityV1.WARNING,
        BuildSeverityV1.ERROR,
    )
    assert tuple(entry.source_line for entry in view.logs) == (None, 17, 42)


@pytest.mark.parametrize("line", [0, -1, True])
def test_invalid_line_reference_is_rejected_without_echo(line: object) -> None:
    with pytest.raises(SealError) as raised:
        _event(
            BuildStatusV1.GENERATING,
            line=line,  # type: ignore[arg-type]
            message="LINE_VALIDATION_SECRET",
        )

    assert "LINE_VALIDATION_SECRET" not in str(raised.value)
    assert "LINE_VALIDATION_SECRET" not in repr(raised.value)


def test_invalid_event_stream_is_content_free() -> None:
    with pytest.raises(BuildViewError) as raised:
        project_build_events(
            [_event(BuildStatusV1.GENERATING), object()]  # type: ignore[list-item]
        )

    assert raised.value.code == "INVALID_EVENTS"
    assert "synthetic build message" not in str(raised.value)
    assert "synthetic build message" not in repr(raised.value)


def test_generator_exception_subclass_cannot_leak_through_error_string() -> None:
    secret = "GENERATOR_EXCEPTION_SECRET_CANARY"

    class LeakyBuildViewError(BuildViewError):
        def __str__(self) -> str:
            return f"iterator failed: {secret}"

    def event_stream():
        yield _event(BuildStatusV1.GENERATING)
        raise LeakyBuildViewError("INVALID_EVENTS")

    with pytest.raises(BuildViewError) as raised:
        project_build_events(event_stream())

    assert type(raised.value) is BuildViewError
    assert raised.value.code == "INVALID_EVENTS"
    assert str(raised.value) == "INVALID_EVENTS"
    assert secret not in str(raised.value)
    assert secret not in repr(raised.value)
    assert raised.value.__cause__ is None


def test_event_message_bound_rejects_input_without_echo() -> None:
    message = "BUILD_LOG_SECRET_CANARY" * 300

    with pytest.raises(SealError) as raised:
        _event(BuildStatusV1.GENERATING, message=message)

    assert message not in str(raised.value)
    assert message not in repr(raised.value)
