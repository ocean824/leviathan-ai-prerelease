"""Platform-specific user data paths for the desktop runtime."""

from __future__ import annotations

import os
import sys
from pathlib import Path, PurePosixPath, PureWindowsPath


def _validated_base(value: str, *, windows: bool, variable: str) -> Path:
    lexical_path = PureWindowsPath(value) if windows else PurePosixPath(value)
    if not value or "\0" in value or not lexical_path.is_absolute() or ".." in lexical_path.parts:
        raise RuntimeError(f"{variable} is required for the desktop app")
    return Path(value)


def data_root() -> Path:
    if os.name == "nt":
        local_app_data = os.environ.get("LOCALAPPDATA")
        if not local_app_data:
            raise RuntimeError("LOCALAPPDATA is required for the Windows desktop app")
        root = _validated_base(local_app_data, windows=True, variable="LOCALAPPDATA")
        return root / "LeviathanAI"
    if sys.platform == "darwin":
        home = os.environ.get("HOME")
        if not home:
            raise RuntimeError("HOME is required for the desktop app")
        root = _validated_base(home, windows=False, variable="HOME")
        return root / "Library" / "Application Support" / "LeviathanAI"
    raise RuntimeError("unsupported desktop platform")


def credential_root() -> Path:
    if os.name == "nt":
        local_app_data = os.environ.get("LOCALAPPDATA")
        if not local_app_data:
            raise RuntimeError("LOCALAPPDATA is required for the runtime credential store")
        root = _validated_base(local_app_data, windows=True, variable="LOCALAPPDATA")
        return root / "Leviathan AI" / "credentials"
    return data_root() / "credentials"
