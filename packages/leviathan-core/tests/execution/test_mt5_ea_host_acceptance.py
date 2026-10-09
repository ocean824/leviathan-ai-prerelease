"""Independent black-box acceptance for the demo-only EA hosting core."""

from __future__ import annotations

import hashlib
import os
from collections.abc import Callable
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import cast
from unittest.mock import patch

import pytest

from leviathan_core.execution import broker_port_v1 as broker
from leviathan_core.execution.mt5_ea_host import (
    MAX_EA_BYTES,
    MAX_SET_BYTES,
    CapStatus,
    EaCapAssessmentV1,
    EaCapEvaluatorPortV1,
    EaHostingError,
    EaHostingServiceV1,
    EaInstallRequestV1,
    LocalEaFileSystemV1,
    issue_ea_cap_assessment,
)
from leviathan_core.execution.order_models import BrokerObservation, OrderState
from leviathan_core.risk.halt import HaltAuthority

ACCOUNT = "synthetic-demo-account"
OPERATOR = "synthetic-operator"
ROOT = Path("C:/synthetic/mt5-data-root")
NOW_NS = 1_798_761_600_000_000_000
OBSERVED_AT = datetime(2026, 12, 31, 23, 59, 59, tzinfo=UTC)
SYNTHETIC_EA_BYTES = b"synthetic dummy compiled payload; never executed"
SYNTHETIC_SET_BYTES = b"synthetic preset values only"


class FakeFileSystem:
    def __init__(self) -> None:
        self.installs: list[dict[str, object]] = []

    def install_pair(
        self,
        *,
        root: Path,
        expert_relative_path: str,
        expert_bytes: bytes,
        preset_relative_path: str,
        preset_bytes: bytes,
    ) -> None:
        self.installs.append(
            {
                "root": root,
                "expert_relative_path": expert_relative_path,
                "expert_bytes": expert_bytes,
                "preset_relative_path": preset_relative_path,
                "preset_bytes": preset_bytes,
            }
        )


def _account_view() -> broker.AccountViewV1:
    order = BrokerObservation(
        observation_id="synthetic-observation-1",
        environment="demo",
        account_id=ACCOUNT,
        venue="MT5",
        client_order_id="synthetic-client-order-1",
        status=OrderState.WORKING,
        observed_at=OBSERVED_AT,
        venue_order_id="synthetic-venue-order-1",
    )
    return broker._issue_account_view(
        ACCOUNT,
        (order,),
        (("EURUSD", Decimal("0.25")),),
        1,
        (),
        OBSERVED_AT,
        complete=True,
        broker_observed_at=OBSERVED_AT,
    )


class FakeBridge:
    def __init__(
        self, *, environment: broker.BrokerEnvironment = broker.BrokerEnvironment.DEMO
    ) -> None:
        self.venue = broker._issue_venue_identity(broker.BrokerVenue.MT5, environment, ACCOUNT)
        self.view = _account_view()
        self.read_accounts: list[str] = []
        self.disabled: list[str] = []
        self.closed: list[str] = []
        self.disable_result = True
        self.close_result = True

    def read_account_view(self, account_id: str) -> broker.AccountViewV1:
        self.read_accounts.append(account_id)
        return self.view

    def disable_expert(self, session_id: str) -> bool:
        self.disabled.append(session_id)
        return self.disable_result

    def close_all(self, account_id: str) -> bool:
        self.closed.append(account_id)
        return self.close_result


class FakeCapEvaluator:
    def __init__(self, status: CapStatus = "WITHIN_CAPS") -> None:
        self.status = status
        self.calls: list[tuple[broker.AccountViewV1, int]] = []

    def assess(self, view: broker.AccountViewV1, *, as_of_ns: int) -> EaCapAssessmentV1:
        self.calls.append((view, as_of_ns))
        return issue_ea_cap_assessment(
            view,
            status=self.status,
            observed_at_ns=as_of_ns,
        )


class RaisedCapEvaluator:
    def assess(self, view: broker.AccountViewV1, *, as_of_ns: int) -> EaCapAssessmentV1:
        raise RuntimeError("synthetic evaluator failure text")


class InvalidCapEvaluator:
    def assess(self, view: broker.AccountViewV1, *, as_of_ns: int) -> EaCapAssessmentV1:
        return cast(EaCapAssessmentV1, object())


def _service(
    *,
    bridge: FakeBridge | None = None,
    filesystem: FakeFileSystem | None = None,
    cap_evaluator: EaCapEvaluatorPortV1 | None = None,
    halt: HaltAuthority | None = None,
    clock_ns: Callable[[], int] = lambda: NOW_NS,
) -> tuple[EaHostingServiceV1, FakeBridge, FakeFileSystem, HaltAuthority]:
    actual_bridge = bridge or FakeBridge()
    actual_filesystem = filesystem or FakeFileSystem()
    actual_halt = halt or HaltAuthority()
    return (
        EaHostingServiceV1(
            data_root=ROOT,
            bridge=actual_bridge,
            filesystem=actual_filesystem,
            cap_evaluator=cap_evaluator,
            halt=actual_halt,
            clock_ns=clock_ns,
        ),
        actual_bridge,
        actual_filesystem,
        actual_halt,
    )


def _request(**changes: object) -> EaInstallRequestV1:
    values: dict[str, object] = {
        "ea_filename": "SyntheticRisk.ex5",
        "ea_bytes": SYNTHETIC_EA_BYTES,
        "set_filename": "SyntheticRisk.set",
        "set_bytes": SYNTHETIC_SET_BYTES,
        "terminal_family": "MT5",
        "symbol": "EURUSD",
        "timeframe": "M5",
    }
    values.update(changes)
    return EaInstallRequestV1(**values)  # type: ignore[arg-type]


def test_install_validates_pair_and_records_demo_provenance_and_startup_config() -> None:
    service, bridge, filesystem, _ = _service()

    result = service.install(_request(), operator_id=OPERATOR)

    assert len(filesystem.installs) == 1
    installed = filesystem.installs[0]
    assert installed == {
        "root": ROOT,
        "expert_relative_path": "MQL5/Experts/SyntheticRisk.ex5",
        "expert_bytes": SYNTHETIC_EA_BYTES,
        "preset_relative_path": "MQL5/Presets/SyntheticRisk.set",
        "preset_bytes": SYNTHETIC_SET_BYTES,
    }
    assert result.environment == "DEMO"
    assert result.terminal_family == "MT5"
    assert result.expert_relative_path == "MQL5/Experts/SyntheticRisk.ex5"
    assert result.preset_relative_path == "MQL5/Presets/SyntheticRisk.set"
    assert result.ea_sha256 == hashlib.sha256(SYNTHETIC_EA_BYTES).hexdigest()
    assert result.set_sha256 == hashlib.sha256(SYNTHETIC_SET_BYTES).hexdigest()
    assert result.provenance.ea_filename == "SyntheticRisk.ex5"
    assert result.provenance.set_filename == "SyntheticRisk.set"
    assert result.provenance.operator_id == OPERATOR
    assert result.provenance.installed_at_ns == NOW_NS
    assert result.startup_config.model_dump() == {
        "terminal_family": "MT5",
        "expert_name": "SyntheticRisk.ex5",
        "set_file": "SyntheticRisk.set",
        "symbol": "EURUSD",
        "timeframe": "M5",
        "environment": "DEMO",
        "execution_allowed": False,
    }
    assert result.execution_allowed is False
    assert bridge.read_accounts == []
    assert bridge.disabled == []
    assert bridge.closed == []


@pytest.mark.parametrize(
    ("field", "value", "expected_code"),
    [
        ("ea_filename", "../Escape.ex5", "INVALID_EA_FILE"),
        ("ea_filename", "Nested\\Escape.ex5", "INVALID_EA_FILE"),
        ("ea_filename", "SyntheticRisk.mq5", "INVALID_EA_FILE"),
        ("set_filename", "../Escape.set", "INVALID_SET_FILE"),
        ("set_filename", "SyntheticRisk.ini", "INVALID_SET_FILE"),
    ],
)
def test_install_rejects_traversal_and_wrong_file_types_before_filesystem(
    field: str, value: str, expected_code: str
) -> None:
    service, _, filesystem, _ = _service()

    with pytest.raises(EaHostingError) as caught:
        service.install(_request(**{field: value}), operator_id=OPERATOR)

    assert caught.value.code == expected_code
    assert filesystem.installs == []


@pytest.mark.parametrize(
    ("field", "size"),
    [("ea_bytes", MAX_EA_BYTES + 1), ("set_bytes", MAX_SET_BYTES + 1)],
)
def test_install_enforces_file_size_before_any_filesystem_write(field: str, size: int) -> None:
    service, _, filesystem, _ = _service()

    with pytest.raises(EaHostingError) as caught:
        service.install(_request(**{field: b"x" * size}), operator_id=OPERATOR)

    assert caught.value.code == "FILE_TOO_LARGE"
    assert filesystem.installs == []


def test_real_filesystem_rejects_a_symlink_escape_without_writing_outside_root(
    tmp_path: Path,
) -> None:
    root = tmp_path / "terminal"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    link = root / "MQL5"
    try:
        os.symlink(outside, link, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlink creation unavailable: {type(exc).__name__}")

    with pytest.raises(EaHostingError) as caught:
        LocalEaFileSystemV1.install_pair(
            root=root,
            expert_relative_path="MQL5/Experts/SyntheticRisk.ex5",
            expert_bytes=SYNTHETIC_EA_BYTES,
            preset_relative_path="MQL5/Presets/SyntheticRisk.set",
            preset_bytes=SYNTHETIC_SET_BYTES,
        )

    assert caught.value.code == "FILESYSTEM_UNAVAILABLE"
    assert list(outside.rglob("*")) == []


def test_monitor_exposes_sealed_order_position_view_and_cap_status() -> None:
    evaluator = FakeCapEvaluator()
    service, bridge, _, halt = _service(cap_evaluator=evaluator)
    installed = service.install(_request(), operator_id=OPERATOR)

    result = service.monitor(installed.session_id, operator_id=OPERATOR)

    assert result.cap_status == "WITHIN_CAPS"
    assert result.state == "MONITORING"
    assert result.environment == "DEMO"
    assert result.account_id == ACCOUNT
    assert result.open_order_count == 1
    assert result.open_orders[0].venue_order_id == "synthetic-venue-order-1"
    assert result.open_orders[0].client_order_id == "synthetic-client-order-1"
    assert result.open_orders[0].venue == "MT5"
    assert result.open_orders[0].status == "WORKING"
    assert result.open_orders[0].observed_at_ns == NOW_NS - 1_000_000_000
    assert result.positions == (("EURUSD", "0.25"),)
    assert result.execution_allowed is False
    assert bridge.read_accounts == [ACCOUNT]
    assert evaluator.calls == [(bridge.view, NOW_NS)]
    assert halt.halted is False


@pytest.mark.parametrize(
    ("evaluator", "expected_status"),
    [
        (FakeCapEvaluator("BREACH"), "BREACH"),
        (None, "UNKNOWN"),
        (RaisedCapEvaluator(), "UNKNOWN"),
        (InvalidCapEvaluator(), "UNKNOWN"),
    ],
)
def test_missing_or_breached_caps_halt_and_stop_fail_closed(
    evaluator: EaCapEvaluatorPortV1 | None,
    expected_status: str,
) -> None:
    service, bridge, _, halt = _service(cap_evaluator=evaluator)
    installed = service.install(_request(), operator_id=OPERATOR)

    result = service.monitor(installed.session_id, operator_id=OPERATOR)

    assert result.cap_status == expected_status
    assert result.state == "HALT_REQUIRED"
    assert result.execution_allowed is False
    assert bridge.disabled == [installed.session_id]
    assert bridge.closed == [ACCOUNT]
    assert halt.halted is True


def test_kill_switch_disables_and_closes_and_never_claims_success_on_partial_failure() -> None:
    service, bridge, _, halt = _service()
    installed = service.install(_request(), operator_id=OPERATOR)

    success = service.kill(installed.session_id, operator_id=OPERATOR)
    assert success.state == "STOPPED"
    assert success.disabled is True
    assert success.close_attempted is True
    assert success.execution_allowed is False
    assert bridge.disabled == [installed.session_id]
    assert bridge.closed == [ACCOUNT]
    assert halt.halted is True

    second_service, second_bridge, _, _ = _service()
    second = second_service.install(_request(), operator_id=OPERATOR)
    second_bridge.close_result = False
    failed = second_service.kill(second.session_id, operator_id=OPERATOR)
    assert failed.state == "UNKNOWN"
    assert failed.execution_allowed is False


def test_kill_still_disables_and_closes_when_halt_recording_fails() -> None:
    service, bridge, _, halt = _service()
    installed = service.install(_request(), operator_id=OPERATOR)

    with patch.object(halt, "engage", side_effect=RuntimeError("synthetic halt-store failure")):
        result = service.kill(installed.session_id, operator_id=OPERATOR)

    assert result.state == "UNKNOWN"
    assert result.execution_allowed is False
    assert bridge.disabled == [installed.session_id]
    assert bridge.closed == [ACCOUNT]


def test_sessions_are_bound_to_the_installing_operator() -> None:
    service, bridge, _, _ = _service(cap_evaluator=FakeCapEvaluator())
    installed = service.install(_request(), operator_id=OPERATOR)

    for operation in (
        lambda: service.monitor(installed.session_id, operator_id="synthetic-other-operator"),
        lambda: service.kill(installed.session_id, operator_id="synthetic-other-operator"),
    ):
        with pytest.raises(EaHostingError) as caught:
            operation()
        assert caught.value.code == "SESSION_NOT_FOUND"
    assert bridge.read_accounts == []
    assert bridge.disabled == []
    assert bridge.closed == []


@pytest.mark.parametrize(
    "environment", [broker.BrokerEnvironment.PAPER, broker.BrokerEnvironment.LIVE]
)
def test_non_demo_bridge_identity_is_refused_before_install(
    environment: broker.BrokerEnvironment,
) -> None:
    bridge = FakeBridge(environment=environment)
    filesystem = FakeFileSystem()

    with pytest.raises(EaHostingError) as caught:
        _service(bridge=bridge, filesystem=filesystem)

    assert caught.value.code == "DEMO_IDENTITY_REQUIRED"
    assert filesystem.installs == []
