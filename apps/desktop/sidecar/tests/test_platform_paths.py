from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from platform_paths import credential_root, data_root


def test_windows_data_roots_preserve_existing_locations(monkeypatch) -> None:
    monkeypatch.setenv("LOCALAPPDATA", r"C:\Users\operator\AppData\Local")

    assert data_root() == Path(r"C:\Users\operator\AppData\Local\LeviathanAI")
    assert credential_root() == Path(r"C:\Users\operator\AppData\Local\Leviathan AI\credentials")


def test_windows_data_root_fails_closed_without_local_app_data(monkeypatch) -> None:
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    with pytest.raises(RuntimeError, match="LOCALAPPDATA is required"):
        data_root()


@pytest.mark.parametrize("value", ["", "relative\\root", r"..\outside", r"C:\safe\..\outside"])
def test_windows_data_root_rejects_unsafe_bases(monkeypatch, value: str) -> None:
    monkeypatch.setenv("LOCALAPPDATA", value)
    with pytest.raises(RuntimeError, match="LOCALAPPDATA is required"):
        data_root()


@pytest.mark.parametrize("value", ["", "relative/root", "/tmp/../outside"])
def test_macos_data_root_rejects_unsafe_bases(monkeypatch, value: str) -> None:
    import os
    from pathlib import PurePosixPath

    class PosixOS:
        name = "posix"
        environ = os.environ

    monkeypatch.setattr("platform_paths.os", PosixOS())
    monkeypatch.setattr("platform_paths.sys", SimpleNamespace(platform="darwin"))
    monkeypatch.setattr("platform_paths.Path", PurePosixPath)
    monkeypatch.setenv("HOME", value)
    with pytest.raises(RuntimeError, match="HOME is required"):
        data_root()


def test_macos_data_root_preserves_valid_absolute_path(monkeypatch) -> None:
    import os
    from pathlib import PurePosixPath

    class PosixOS:
        name = "posix"
        environ = os.environ

    monkeypatch.setattr("platform_paths.os", PosixOS())
    monkeypatch.setattr("platform_paths.sys", SimpleNamespace(platform="darwin"))
    monkeypatch.setattr("platform_paths.Path", PurePosixPath)
    monkeypatch.setenv("HOME", "/Users/operator")
    assert data_root() == PurePosixPath("/Users/operator/Library/Application Support/LeviathanAI")


def test_data_root_base_validator_rejects_nul() -> None:
    from platform_paths import _validated_base

    with pytest.raises(RuntimeError, match="LOCALAPPDATA is required"):
        _validated_base("bad\x00root", windows=True, variable="LOCALAPPDATA")
    with pytest.raises(RuntimeError, match="HOME is required"):
        _validated_base("bad\x00root", windows=False, variable="HOME")


@pytest.mark.parametrize(
    ("os_name", "platform", "variable", "windows", "value"),
    [
        ("nt", "win32", "LOCALAPPDATA", True, ""),
        ("nt", "win32", "LOCALAPPDATA", True, "relative\\root"),
        ("nt", "win32", "LOCALAPPDATA", True, "bad\x00root"),
        ("nt", "win32", "LOCALAPPDATA", True, r"..\outside"),
        ("posix", "darwin", "HOME", False, ""),
        ("posix", "darwin", "HOME", False, "relative/root"),
        ("posix", "darwin", "HOME", False, "bad\x00root"),
        ("posix", "darwin", "HOME", False, "/Users/operator/../outside"),
    ],
)
def test_credential_root_rejects_unsafe_base_on_each_os(
    monkeypatch, os_name: str, platform: str, variable: str, windows: bool, value: str
) -> None:
    from pathlib import PurePosixPath, PureWindowsPath

    class Environment:
        def get(self, name: str) -> str | None:
            return value if name == variable else None

    class SimulatedOS:
        name = os_name
        environ = Environment()

    monkeypatch.setattr("platform_paths.os", SimulatedOS())
    monkeypatch.setattr("platform_paths.sys", SimpleNamespace(platform=platform))
    monkeypatch.setattr("platform_paths.Path", PureWindowsPath if windows else PurePosixPath)
    with pytest.raises(RuntimeError):
        credential_root()
