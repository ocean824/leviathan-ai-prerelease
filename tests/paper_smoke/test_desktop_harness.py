"""Unit coverage for the offline paper desktop smoke harness."""

from __future__ import annotations

import os
import socket
import sys
from pathlib import Path
from unittest.mock import patch

import desktop_harness
import pytest

if sys.platform == "win32":
    import _winapi
from desktop_harness import (
    StepStatus,
    SyntheticCredentialResolver,
    _network_denied,
    run_fake_paper_api_smoke,
)


def test_fake_paper_api_smoke_reports_waiting_gates_and_cleans_profile(
    tmp_path: Path, tmp_path_factory: pytest.TempPathFactory
) -> None:
    profile = tmp_path / "isolated-profile"
    local_app_data_before = os.environ.get("LOCALAPPDATA")
    report = run_fake_paper_api_smoke(profile, pytest_basetemp=tmp_path_factory.getbasetemp())

    assert not profile.exists()
    assert os.environ.get("LOCALAPPDATA") == local_app_data_before
    assert report.status is StepStatus.WAITING_FOR_INTEGRATED_UI_OR_INSTALLER
    assert report.launch_mode == "FASTAPI_TESTCLIENT_IN_PROCESS"
    assert report.fake_broker_type == "FakeBrokerPort"
    assert report.fake_broker_submit_calls == 1
    assert report.live_enabled is False
    assert report.outbound_network_denied is True
    assert report.step("api_health").status is StepStatus.PASS
    assert report.step("capability_boundary").status is StepStatus.PASS
    assert report.step("paper_activation_api").status is StepStatus.PASS
    assert report.step("paper_fake_order_submit").status is StepStatus.PASS
    assert report.step("halt_visible").status is StepStatus.PASS
    assert report.step("test_launch_shutdown").status is StepStatus.PASS
    for name in (
        "paper_activity_read",
        "activation_ui",
        "terminal_navigation",
        "installed_desktop",
    ):
        assert report.step(name).status is StepStatus.WAITING_FOR_INTEGRATED_UI_OR_INSTALLER


def test_harness_cleans_profile_and_restores_localappdata_after_setup_failure(
    tmp_path: Path,
    tmp_path_factory: pytest.TempPathFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = tmp_path / "failed-profile"
    local_app_data_before = os.environ.get("LOCALAPPDATA")

    def fail_create_app(**_kwargs: object) -> None:
        raise RuntimeError("synthetic setup failure")

    monkeypatch.setattr(desktop_harness, "create_app", fail_create_app)
    with pytest.raises(RuntimeError, match="synthetic setup failure"):
        run_fake_paper_api_smoke(profile, pytest_basetemp=tmp_path_factory.getbasetemp())

    assert not profile.exists()
    assert os.environ.get("LOCALAPPDATA") == local_app_data_before


def test_synthetic_credential_resolver_never_contains_real_credentials() -> None:
    resolver = SyntheticCredentialResolver()
    resolved = resolver.resolve("ALPACA", "PAPER", "paper-smoke-synthetic")

    assert resolved.profile.profile_id == "paper-smoke-synthetic"
    assert resolved.profile.environment == "PAPER"
    assert "synthetic-paper-secret-value" not in repr(resolved)


def test_harness_refuses_real_profile_roots_before_writing(
    tmp_path: Path,
    tmp_path_factory: pytest.TempPathFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    basetemp = tmp_path_factory.getbasetemp()
    local_root = tmp_path / "local-app-data"
    monkeypatch.setenv("LOCALAPPDATA", str(local_root))
    exact_root = local_root
    with pytest.raises(ValueError, match="real user-data root"):
        run_fake_paper_api_smoke(exact_root, pytest_basetemp=basetemp)
    assert not exact_root.exists()

    product_root = local_root / "LeviathanAI" / "data" / "profile"
    with pytest.raises(ValueError, match="protected product"):
        run_fake_paper_api_smoke(product_root, pytest_basetemp=basetemp)
    assert not local_root.exists()


def test_harness_refuses_root_outside_pytest_basetemp(
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    basetemp = tmp_path_factory.getbasetemp()
    outside = basetemp.parent / "outside-paper-smoke-root"
    with pytest.raises(ValueError, match="strict child of pytest basetemp"):
        run_fake_paper_api_smoke(outside, pytest_basetemp=basetemp)
    assert not outside.exists()


def test_harness_refuses_nonempty_isolated_root(
    tmp_path: Path, tmp_path_factory: pytest.TempPathFactory
) -> None:
    root = tmp_path / "not-empty"
    root.mkdir()
    (root / "existing.txt").write_text("synthetic fixture", encoding="utf-8")

    with pytest.raises(ValueError, match="must be empty"):
        run_fake_paper_api_smoke(root, pytest_basetemp=tmp_path_factory.getbasetemp())
    assert root.exists()


@pytest.mark.skipif(
    sys.platform != "win32", reason="Windows junction semantics are platform-specific"
)
def test_harness_rejects_junction_root_without_touching_target(
    tmp_path: Path, tmp_path_factory: pytest.TempPathFactory
) -> None:
    target = tmp_path / "junction-target"
    target.mkdir()
    junction = tmp_path / "junction-root"
    _winapi.CreateJunction(str(target), str(junction))

    with pytest.raises(ValueError, match="reparse points"):
        run_fake_paper_api_smoke(junction, pytest_basetemp=tmp_path_factory.getbasetemp())
    assert list(target.iterdir()) == []


@pytest.mark.skipif(
    sys.platform != "win32", reason="Windows junction semantics are platform-specific"
)
def test_harness_rejects_junction_inside_root_without_touching_target(
    tmp_path: Path, tmp_path_factory: pytest.TempPathFactory
) -> None:
    root = tmp_path / "profile-with-junction"
    root.mkdir()
    target = tmp_path / "nested-junction-target"
    target.mkdir()
    junction = root / "redirected-data"
    _winapi.CreateJunction(str(target), str(junction))

    with pytest.raises(ValueError, match="reparse points"):
        run_fake_paper_api_smoke(root, pytest_basetemp=tmp_path_factory.getbasetemp())
    assert list(target.iterdir()) == []


def test_outbound_network_guard_intercepts_socket_egress_primitives() -> None:
    with _network_denied():
        for host in ("198.51.100.1", "2001:db8::1", "example.invalid"):
            with pytest.raises(AssertionError, match="outbound network is disabled"):
                socket.getaddrinfo(host, 443)

        with pytest.raises(AssertionError, match="outbound network is disabled"):
            socket.create_connection(("198.51.100.1", 443), timeout=0.1)

        for family, address in (
            (socket.AF_INET, ("198.51.100.1", 443)),
            (socket.AF_INET6, ("2001:db8::1", 443, 0, 0)),
        ):
            client = socket.socket(
                family, socket.SOCK_DGRAM if family == socket.AF_INET else socket.SOCK_STREAM
            )
            try:
                with pytest.raises(AssertionError, match="outbound network is disabled"):
                    client.connect(address)
                with pytest.raises(AssertionError, match="outbound network is disabled"):
                    client.connect_ex(address)
                with pytest.raises(AssertionError, match="outbound network is disabled"):
                    client.sendto(b"synthetic", address)
                sendmsg = getattr(client, "sendmsg", None)
                if sendmsg is not None:
                    with pytest.raises(AssertionError, match="outbound network is disabled"):
                        sendmsg([b"synthetic"], [], 0, address)
            finally:
                client.close()

        with pytest.raises(AssertionError, match="outbound network is disabled"):
            socket.socket().send(b"synthetic")

        assert socket.getaddrinfo("127.0.0.1", 43127)
        assert socket.getaddrinfo("::1", 43127)


def test_name_resolution_is_synthetic_for_loopback_without_os_resolver() -> None:
    def native_resolver_was_called(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("native name resolution must not be used")

    with (
        patch.object(socket, "getaddrinfo", native_resolver_was_called),
        patch.object(socket, "gethostbyname", native_resolver_was_called),
        patch.object(socket, "gethostbyname_ex", native_resolver_was_called),
        patch.object(socket, "gethostbyaddr", native_resolver_was_called),
        patch.object(socket, "getnameinfo", native_resolver_was_called),
        _network_denied(),
    ):
        ipv4_results = socket.getaddrinfo("localhost", 43127, socket.AF_INET)
        ipv6_results = socket.getaddrinfo("localhost", 43127, socket.AF_INET6)
        numeric_results = socket.getaddrinfo("127.0.0.1", 43127, socket.AF_INET)
        assert ipv4_results and all(item[4][0] == "127.0.0.1" for item in ipv4_results)
        assert ipv6_results and all(item[4][0] == "::1" for item in ipv6_results)
        assert numeric_results and all(item[4][0] == "127.0.0.1" for item in numeric_results)
        assert socket.gethostbyname("localhost") == "127.0.0.1"
        assert socket.gethostbyname_ex("localhost") == ("localhost", [], ["127.0.0.1"])
        assert socket.gethostbyaddr("127.0.0.1") == ("127.0.0.1", [], ["127.0.0.1"])
        assert socket.getnameinfo(("::1", 43127, 0, 0), socket.NI_NAMEREQD) == ("::1", "43127")


def test_name_resolution_blocks_non_loopback_for_every_socket_resolver() -> None:
    with _network_denied():
        unsafe_calls = (
            lambda: socket.getaddrinfo("example.invalid", 443),
            lambda: socket.gethostbyname("example.invalid"),
            lambda: socket.gethostbyname_ex("example.invalid"),
            lambda: socket.gethostbyaddr("198.51.100.1"),
            lambda: socket.getnameinfo(("2001:db8::1", 443, 0, 0), 0),
        )
        for resolve in unsafe_calls:
            with pytest.raises(AssertionError, match="outbound network is disabled"):
                resolve()
