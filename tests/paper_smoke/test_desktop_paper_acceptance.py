from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import NoReturn

import desktop_harness
import pytest
from desktop_harness import (
    StepStatus,
    SyntheticCredentialResolver,
    _network_denied,
    run_fake_paper_api_smoke,
)


def _forbid_process_launch(*_args: object, **_kwargs: object) -> NoReturn:
    raise AssertionError("desktop and installer processes are forbidden in acceptance")


def test_fake_paper_smoke_stays_waiting_for_unintegrated_desktop_dependencies(
    tmp_path: Path,
    tmp_path_factory: pytest.TempPathFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process_attempts: list[str] = []

    def forbid_process(*_args: object, **_kwargs: object) -> NoReturn:
        process_attempts.append("process")
        _forbid_process_launch(*_args, **_kwargs)

    monkeypatch.setattr(subprocess, "Popen", forbid_process)
    monkeypatch.setattr(subprocess, "run", forbid_process)
    monkeypatch.setattr(subprocess, "call", forbid_process)
    monkeypatch.setattr(os, "system", forbid_process)
    monkeypatch.setattr(os, "startfile", forbid_process, raising=False)

    profile_environment_before = {
        name: os.environ.get(name) for name in ("LOCALAPPDATA", "APPDATA", "USERPROFILE")
    }
    isolated_root = tmp_path / "isolated-paper-profile"
    pytest_basetemp = tmp_path_factory.getbasetemp().resolve()
    assert pytest_basetemp in isolated_root.resolve().parents
    report = run_fake_paper_api_smoke(
        isolated_root,
        pytest_basetemp=tmp_path_factory.getbasetemp(),
    )

    assert report.status is StepStatus.WAITING_FOR_INTEGRATED_UI_OR_INSTALLER
    assert report.launch_mode == "FASTAPI_TESTCLIENT_IN_PROCESS"
    assert report.fake_broker_type == "FakeBrokerPort"
    assert report.fake_broker_submit_calls == 1
    assert report.live_enabled is False
    assert report.outbound_network_denied is True
    assert process_attempts == []
    assert {
        name: os.environ.get(name) for name in ("LOCALAPPDATA", "APPDATA", "USERPROFILE")
    } == profile_environment_before

    for name in (
        "paper_activity_read",
        "activation_ui",
        "terminal_navigation",
        "installed_desktop",
    ):
        assert report.step(name).status is StepStatus.WAITING_FOR_INTEGRATED_UI_OR_INSTALLER

    for name in (
        "api_health",
        "capability_boundary",
        "live_disabled",
        "paper_activation_api",
        "paper_fake_order_submit",
        "halt_visible",
        "test_launch_shutdown",
    ):
        assert report.step(name).status is StepStatus.PASS
    assert not isolated_root.exists()


def test_outbound_network_guard_denies_connection_attempts() -> None:
    with _network_denied():
        with pytest.raises(AssertionError, match="outbound network is disabled"):
            socket.create_connection(("198.51.100.1", 443), timeout=0.1)

        client = socket.socket()
        try:
            with pytest.raises(AssertionError, match="outbound network is disabled"):
                client.connect(("198.51.100.1", 443))
            with pytest.raises(AssertionError, match="outbound network is disabled"):
                client.connect_ex(("198.51.100.1", 443))
        finally:
            client.close()


def test_outbound_network_guard_denies_udp_sendto() -> None:
    with _network_denied():
        datagram = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            with pytest.raises(AssertionError, match="outbound network is disabled"):
                datagram.sendto(b"denied", ("198.51.100.1", 53))
        finally:
            datagram.close()


def test_outbound_network_guard_denies_udp_sendmsg_when_available() -> None:
    with _network_denied():
        datagram = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            if hasattr(datagram, "sendmsg"):
                with pytest.raises(AssertionError, match="outbound network is disabled"):
                    datagram.sendmsg([b"denied"], [], 0, ("198.51.100.1", 53))
            else:
                assert not hasattr(datagram, "sendmsg")
        finally:
            datagram.close()


def test_outbound_network_guard_denies_ipv6_connect_ex() -> None:
    if not socket.has_ipv6:
        pytest.skip("IPv6 is unavailable on this host")
    with _network_denied():
        if socket.has_ipv6:
            ipv6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            try:
                with pytest.raises(AssertionError, match="outbound network is disabled"):
                    ipv6.connect_ex(("2001:db8::1", 443, 0, 0))
            finally:
                ipv6.close()


def test_outbound_network_guard_denies_non_loopback_name_resolution() -> None:
    with _network_denied(), pytest.raises(AssertionError, match="outbound network is disabled"):
        socket.getaddrinfo("example.com", 443)


@pytest.mark.parametrize(
    ("protected_environment", "relative_root"),
    [
        ("LOCALAPPDATA", ""),
        ("LOCALAPPDATA", "LeviathanAI/state/cache"),
        ("LOCALAPPDATA", "Leviathan AI/state/cache"),
        ("APPDATA", ""),
        ("APPDATA", "LeviathanAI/state/cache"),
        ("APPDATA", "Leviathan AI/state/cache"),
        ("USERPROFILE", ""),
    ],
)
def test_local_app_data_roots_are_rejected_before_any_write(
    tmp_path: Path,
    tmp_path_factory: pytest.TempPathFactory,
    monkeypatch: pytest.MonkeyPatch,
    protected_environment: str,
    relative_root: str,
) -> None:
    original_environment = {
        name: os.environ.get(name) for name in ("LOCALAPPDATA", "APPDATA", "USERPROFILE")
    }
    synthetic_roots = {
        name: tmp_path / "synthetic-profile" / name.lower()
        for name in ("LOCALAPPDATA", "APPDATA", "USERPROFILE")
    }
    for path in synthetic_roots.values():
        path.mkdir(parents=True)

    before = {name: set(path.iterdir()) for name, path in synthetic_roots.items()}
    with monkeypatch.context() as environment_override:
        for name, path in synthetic_roots.items():
            environment_override.setenv(name, str(path))
        protected_root = synthetic_roots[protected_environment]
        root = protected_root / relative_root if relative_root else protected_root

        rejected = False
        try:
            run_fake_paper_api_smoke(
                root,
                pytest_basetemp=tmp_path_factory.getbasetemp(),
            )
        except ValueError:
            rejected = True

        after = {name: set(path.iterdir()) for name, path in synthetic_roots.items()}
        nested_root_exists = root.exists() if relative_root else None
        assert (rejected, after, nested_root_exists) == (
            True,
            before,
            False if relative_root else None,
        )

    assert {
        name: os.environ.get(name) for name in ("LOCALAPPDATA", "APPDATA", "USERPROFILE")
    } == original_environment


def test_root_outside_pytest_basetemp_is_refused_before_any_write(
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    pytest_basetemp = tmp_path_factory.getbasetemp().resolve()
    with tempfile.TemporaryDirectory(prefix="paper-smoke-outside-basetemp-") as outside:
        root = Path(outside).resolve()
        assert pytest_basetemp not in root.parents

        rejected = False
        try:
            run_fake_paper_api_smoke(root, pytest_basetemp=pytest_basetemp)
        except ValueError:
            rejected = True

        assert rejected and list(root.iterdir()) == []


def test_junction_root_is_refused_without_writing_through_it(
    tmp_path: Path,
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    if sys.platform != "win32":
        pytest.skip("Windows junction semantics are platform-specific")
    import _winapi

    target = tmp_path / "junction-target"
    target.mkdir()
    junction = tmp_path / "junction-root"
    _winapi.CreateJunction(str(target), str(junction))

    try:
        assert junction.is_junction()
        rejected = False
        try:
            run_fake_paper_api_smoke(
                junction,
                pytest_basetemp=tmp_path_factory.getbasetemp(),
            )
        except ValueError:
            rejected = True
        target_was_untouched = list(target.iterdir()) == []
    finally:
        junction.rmdir()
    assert rejected and target_was_untouched


def test_embedded_junction_is_refused_without_writing_through_it(
    tmp_path: Path,
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    if sys.platform != "win32":
        pytest.skip("Windows junction semantics are platform-specific")
    import _winapi

    isolated_root = tmp_path / "profile-with-junction"
    isolated_root.mkdir()
    target = tmp_path / "embedded-junction-target"
    target.mkdir()
    junction = isolated_root / "redirected-data"
    _winapi.CreateJunction(str(target), str(junction))

    assert junction.is_junction()
    with pytest.raises(ValueError):
        run_fake_paper_api_smoke(
            isolated_root,
            pytest_basetemp=tmp_path_factory.getbasetemp(),
        )
    assert list(target.iterdir()) == []


def test_temporary_profile_is_removed_after_failing_run(
    tmp_path: Path,
    tmp_path_factory: pytest.TempPathFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    isolated_root = tmp_path / "failing-isolated-paper-profile"
    local_app_data_before = os.environ.get("LOCALAPPDATA")

    def fail_app_creation(*_args: object, **_kwargs: object) -> NoReturn:
        raise RuntimeError("synthetic smoke failure")

    monkeypatch.setattr(desktop_harness, "create_app", fail_app_creation)
    with pytest.raises(RuntimeError, match="synthetic smoke failure"):
        run_fake_paper_api_smoke(
            isolated_root,
            pytest_basetemp=tmp_path_factory.getbasetemp(),
        )

    assert not isolated_root.exists()
    assert os.environ.get("LOCALAPPDATA") == local_app_data_before


def test_synthetic_credential_resolver_uses_only_fake_paper_values() -> None:
    resolver = SyntheticCredentialResolver()
    resolved = resolver.resolve(
        "ALPACA",
        "PAPER",
        "paper-smoke-synthetic",
    )

    assert resolved.profile.profile_id == "paper-smoke-synthetic"
    assert resolved.profile.environment == "PAPER"
    assert "synthetic-paper-secret-value" not in repr(resolved)
