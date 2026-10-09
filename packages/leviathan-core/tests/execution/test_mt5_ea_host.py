from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest

from leviathan_core.execution.broker_port_v1 import (
    BrokerEnvironment,
    BrokerVenue,
    _issue_account_view,
    _issue_venue_identity,
)
from leviathan_core.execution.mt5_ea_host import (
    EaHostingError,
    EaHostingServiceV1,
    EaInstallRequestV1,
    LocalEaFileSystemV1,
    issue_ea_cap_assessment,
)
from leviathan_core.risk.halt import HaltAuthority

_NOW = datetime(2026, 10, 6, 12, 0, 10, tzinfo=UTC)
_FIXTURE = Path(__file__).resolve().parents[4] / "qa/ea_hosting/fixtures/trivial_ea.mq5"
_FIXTURE_BYTES = _FIXTURE.read_bytes()  # opaque fake payload; never compiled or executed


def _ns(value: datetime) -> int:
    delta = value - datetime(1970, 1, 1, tzinfo=UTC)
    return ((delta.days * 86_400 + delta.seconds) * 1_000_000_000) + delta.microseconds * 1_000


class FakeFileSystem:
    def __init__(self) -> None:
        self.calls: list[tuple[Path, str, bytes, str, bytes]] = []
        self.fail = False

    def install_pair(
        self,
        *,
        root: Path,
        expert_relative_path: str,
        expert_bytes: bytes,
        preset_relative_path: str,
        preset_bytes: bytes,
    ) -> None:
        if self.fail:
            raise OSError("private path must not escape")
        self.calls.append(
            (root, expert_relative_path, expert_bytes, preset_relative_path, preset_bytes)
        )


class FakeBridge:
    def __init__(self, *, mode: BrokerEnvironment = BrokerEnvironment.DEMO) -> None:
        self.venue = _issue_venue_identity(BrokerVenue.MT5, mode, "ACC-DEMO-1")
        self.view = _issue_account_view(
            "ACC-DEMO-1",
            (),
            (("EURUSD", Decimal("0")),),
            3,
            (),
            datetime(2026, 10, 6, 12, 0, 0, tzinfo=UTC),
            complete=True,
            broker_observed_at=datetime(2026, 10, 6, 12, 0, 0, tzinfo=UTC),
            session_id="mt5-session-demo",
        )
        self.disabled: list[str] = []
        self.closed: list[str] = []
        self.disable_ok = True
        self.close_ok = True
        self.fail_read = False

    def read_account_view(self, account_id: str):
        if self.fail_read or account_id != "ACC-DEMO-1":
            raise RuntimeError("canary path unavailable")
        return self.view

    def disable_expert(self, session_id: str) -> bool:
        self.disabled.append(session_id)
        return self.disable_ok

    def close_all(self, account_id: str) -> bool:
        self.closed.append(account_id)
        return self.close_ok


class FakeCaps:
    def __init__(self, status: str = "WITHIN_CAPS") -> None:
        self.status = status

    def assess(self, view, *, as_of_ns: int):
        return issue_ea_cap_assessment(view, status=self.status, observed_at_ns=as_of_ns)


def _request(**changes: object) -> EaInstallRequestV1:
    values: dict[str, object] = {
        "ea_filename": "TrivialExpert.ex5",
        "ea_bytes": _FIXTURE_BYTES,
        "set_filename": "TrivialExpert.set",
        "set_bytes": b"Lots=0.01\n",
        "terminal_family": "MT5",
        "symbol": "EURUSD",
        "timeframe": "M5",
    }
    values.update(changes)
    return EaInstallRequestV1(**values)  # type: ignore[arg-type]


def _service(
    tmp_path: Path,
    *,
    bridge: FakeBridge | None = None,
    filesystem: FakeFileSystem | None = None,
    caps: FakeCaps | None = None,
):
    return EaHostingServiceV1(
        data_root=tmp_path,
        bridge=bridge or FakeBridge(),
        filesystem=filesystem or FakeFileSystem(),
        cap_evaluator=caps,
        halt=HaltAuthority(),
        clock_ns=lambda: _ns(_NOW),
    )


def test_install_places_only_validated_pair_and_returns_hash_provenance(tmp_path: Path) -> None:
    fs = FakeFileSystem()
    service = _service(tmp_path, filesystem=fs)
    result = service.install(_request(), operator_id="operator-1")

    assert result.environment == "DEMO"
    assert result.execution_allowed is False
    assert result.expert_relative_path == "MQL5/Experts/TrivialExpert.ex5"
    assert result.preset_relative_path == "MQL5/Presets/TrivialExpert.set"
    assert result.provenance.ea_sha256 == result.ea_sha256
    assert result.provenance.set_sha256 == result.set_sha256
    assert result.provenance.operator_id == "operator-1"
    assert result.startup_config.symbol == "EURUSD"
    assert result.startup_config.timeframe == "M5"
    assert result.startup_config.execution_allowed is False
    assert len(fs.calls) == 1
    assert fs.calls[0][1:] == (
        "MQL5/Experts/TrivialExpert.ex5",
        _request().ea_bytes,
        "MQL5/Presets/TrivialExpert.set",
        _request().set_bytes,
    )


@pytest.mark.parametrize(
    ("change", "code"),
    [
        ({"ea_filename": "..\\outside.ex5"}, "INVALID_EA_FILE"),
        ({"ea_filename": "trick.ex4"}, "INVALID_EA_FILE"),
        ({"set_filename": "../outside.set"}, "INVALID_SET_FILE"),
        ({"terminal_family": "LIVE"}, "INVALID_EA_REQUEST"),
        ({"timeframe": "CUSTOM-FREE-TEXT"}, "INVALID_EA_REQUEST"),
        ({"symbol": "EURUSD\\.."}, "INVALID_EA_REQUEST"),
        ({"ea_bytes": b""}, "INVALID_EA_FILE"),
        ({"set_bytes": b""}, "INVALID_SET_FILE"),
    ],
)
def test_invalid_uploads_fail_before_filesystem_write(
    tmp_path: Path, change: dict[str, object], code: str
) -> None:
    fs = FakeFileSystem()
    with pytest.raises(EaHostingError) as error:
        _service(tmp_path, filesystem=fs).install(_request(**change), operator_id="operator-1")
    assert error.value.code == code
    assert str(error.value) == code
    assert fs.calls == []


def test_demo_identity_is_required_at_construction(tmp_path: Path) -> None:
    with pytest.raises(EaHostingError) as error:
        _service(tmp_path, bridge=FakeBridge(mode=BrokerEnvironment.LIVE))
    assert error.value.code == "DEMO_IDENTITY_REQUIRED"


def test_monitor_requires_bound_cap_evidence_and_halts_when_missing(tmp_path: Path) -> None:
    bridge = FakeBridge()
    service = _service(tmp_path, bridge=bridge, caps=None)
    installed = service.install(_request(), operator_id="operator-1")
    # Missing cap adapter is an UNKNOWN decision and synchronously engages HALT,
    # disables the expert, and attempts to close the exact demo account.
    result = service.monitor(installed.session_id, operator_id="operator-1")
    assert result.cap_status == "UNKNOWN"
    assert result.state == "HALT_REQUIRED"
    assert result.execution_allowed is False
    assert bridge.disabled == [installed.session_id]
    assert bridge.closed == ["ACC-DEMO-1"]


def test_verified_within_caps_monitor_returns_orders_positions_and_status(tmp_path: Path) -> None:
    service = _service(tmp_path, caps=FakeCaps("WITHIN_CAPS"))
    installed = service.install(_request(), operator_id="operator-1")
    result = service.monitor(installed.session_id, operator_id="operator-1")
    assert result.cap_status == "WITHIN_CAPS"
    assert result.state == "MONITORING"
    assert result.positions == (("EURUSD", "0"),)
    assert result.open_order_count == 0


def test_invalid_or_breached_cap_evidence_never_reports_monitoring(tmp_path: Path) -> None:
    bridge = FakeBridge()
    service = _service(tmp_path, bridge=bridge, caps=FakeCaps("BREACH"))
    installed = service.install(_request(), operator_id="operator-1")
    result = service.monitor(installed.session_id, operator_id="operator-1")
    assert result.cap_status == "BREACH"
    assert result.state == "HALT_REQUIRED"
    assert bridge.disabled == [installed.session_id]
    assert bridge.closed == ["ACC-DEMO-1"]


def test_kill_is_halt_first_and_unknown_if_any_action_is_unconfirmed(tmp_path: Path) -> None:
    bridge = FakeBridge()
    bridge.close_ok = False
    service = _service(tmp_path, bridge=bridge)
    installed = service.install(_request(), operator_id="operator-1")
    result = service.kill(installed.session_id, operator_id="operator-1")
    assert result.state == "UNKNOWN"
    assert result.disabled is True
    assert result.close_attempted is True
    assert bridge.disabled == [installed.session_id]
    assert bridge.closed == ["ACC-DEMO-1"]


def test_kill_still_attempts_disable_and_close_if_halt_recording_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bridge = FakeBridge()
    service = _service(tmp_path, bridge=bridge)
    installed = service.install(_request(), operator_id="operator-1")

    def fail_engage(_self: HaltAuthority, _reason: str) -> None:
        raise RuntimeError("synthetic halt-store failure")

    monkeypatch.setattr(HaltAuthority, "engage", fail_engage)
    result = service.kill(installed.session_id, operator_id="operator-1")

    assert result.state == "UNKNOWN"
    assert bridge.disabled == [installed.session_id]
    assert bridge.closed == ["ACC-DEMO-1"]


def test_sessions_are_bound_to_installing_operator(tmp_path: Path) -> None:
    bridge = FakeBridge()
    service = _service(tmp_path, bridge=bridge)
    installed = service.install(_request(), operator_id="operator-1")
    with pytest.raises(EaHostingError) as error:
        service.monitor(installed.session_id, operator_id="other-operator")
    assert error.value.code == "SESSION_NOT_FOUND"
    assert bridge.disabled == []
    assert bridge.closed == []


def test_real_filesystem_rejects_path_escape_and_never_follows_symlink(tmp_path: Path) -> None:
    root = tmp_path / "terminal"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    link = root / "MQL5"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is unavailable on this test host")
    with pytest.raises(EaHostingError) as error:
        LocalEaFileSystemV1.install_pair(
            root=root,
            expert_relative_path="MQL5/Experts/X.ex5",
            expert_bytes=b"opaque",
            preset_relative_path="MQL5/Presets/X.set",
            preset_bytes=b"safe",
        )
    assert error.value.code == "FILESYSTEM_UNAVAILABLE"
    assert list(outside.iterdir()) == []
