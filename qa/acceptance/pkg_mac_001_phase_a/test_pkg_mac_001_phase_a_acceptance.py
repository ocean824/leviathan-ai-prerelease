from __future__ import annotations

import hashlib
import importlib.util
import json
import logging
import os
import sys
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from types import ModuleType, SimpleNamespace

import pytest
from pydantic import SecretStr

_TREE = Path(
    os.environ.get(
        "PKG_MAC_PHASE_A_TREE",
        str(Path(__file__).resolve().parents[3]),
    )
).resolve()
_STAMP = datetime(2026, 10, 7, 12, 0, tzinfo=UTC)
_CREDENTIALS: ModuleType | None = None


class _OSProxy:
    def __init__(self, name: str) -> None:
        self.name = name

    def __getattr__(self, name: str) -> object:
        return getattr(os, name)


def _load_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def test_windows_and_simulated_macos_data_roots(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _load_module(
        _TREE / "apps/desktop/sidecar/platform_paths.py", "pkg_mac_acceptance_platform_paths"
    )
    monkeypatch.setenv("LOCALAPPDATA", r"C:\Users\acceptance\AppData\Local")
    assert paths.data_root() == Path(r"C:\Users\acceptance\AppData\Local\LeviathanAI")

    monkeypatch.setattr(paths, "os", _OSProxy("posix"))
    monkeypatch.setattr(paths, "sys", SimpleNamespace(platform="darwin"))
    monkeypatch.setattr(paths, "Path", PurePosixPath)
    home = PurePosixPath("/Users/pkg-mac-acceptance")
    monkeypatch.setenv("HOME", str(home))
    assert paths.data_root() == home / "Library" / "Application Support" / "LeviathanAI"


@pytest.mark.parametrize(
    ("os_name", "platform", "variable"),
    [("nt", "win32", "LOCALAPPDATA"), ("posix", "darwin", "HOME")],
)
def test_data_roots_fail_closed_for_missing_and_hostile_environment(
    monkeypatch: pytest.MonkeyPatch,
    os_name: str,
    platform: str,
    variable: str,
) -> None:
    paths = _load_module(
        _TREE / "apps/desktop/sidecar/platform_paths.py",
        f"pkg_mac_acceptance_paths_{os_name}",
    )
    monkeypatch.setattr(paths, "os", _OSProxy(os_name))
    monkeypatch.setattr(paths, "sys", SimpleNamespace(platform=platform))
    if platform == "darwin":
        monkeypatch.setattr(paths, "Path", PurePosixPath)
    monkeypatch.delenv(variable, raising=False)
    with pytest.raises(RuntimeError):
        paths.data_root()

    hostile_value = r"..\outside" if platform == "win32" else "/tmp/../outside"
    monkeypatch.setenv(variable, hostile_value)
    with pytest.raises(RuntimeError):
        paths.data_root()


def _load_credentials() -> ModuleType:
    global _CREDENTIALS
    if _CREDENTIALS is None:
        import leviathan_vault.app_credentials as credentials

        _CREDENTIALS = credentials
    return _CREDENTIALS


def test_windows_credential_store_selection_remains_dpapi(tmp_path: Path) -> None:
    credentials = _load_credentials()
    store = credentials.credential_store_for_platform(tmp_path / "windows-credentials")
    assert type(store) is credentials.DPAPICredentialStore


def test_non_apple_keyring_is_rejected_without_plaintext_fallback(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    credentials = _load_credentials()
    monkeypatch.setattr(credentials, "os", _OSProxy("posix"))
    monkeypatch.setattr(credentials, "sys", SimpleNamespace(platform="darwin"))

    class NonAppleBackend:
        pass

    NonAppleBackend.__module__ = "keyring.backends.fail"
    backend_items: dict[tuple[str, str], str] = {}
    fake_keyring = SimpleNamespace(
        get_keyring=lambda: NonAppleBackend(),
        set_password=lambda service, account, value: backend_items.__setitem__(
            (service, account), value
        ),
        get_password=lambda service, account: backend_items.get((service, account)),
    )
    monkeypatch.setitem(sys.modules, "keyring", fake_keyring)

    secret = "PKG_MAC_ACCEPTANCE_SECRET_NON_APPLE_4f3c"
    root = tmp_path / "non-apple-store"
    store = credentials.credential_store_for_platform(root)
    assert type(store) is credentials.MacOSKeychainCredentialStore
    with caplog.at_level(logging.DEBUG), pytest.raises(credentials.CredentialError) as raised:
        store.put_profile("OPENAI", "PAPER", "synthetic-profile", {"api_key": SecretStr(secret)})
    assert raised.value.code == "UNAVAILABLE"
    assert not list(root.rglob("profile.json"))
    assert secret not in caplog.text
    assert all(secret.encode() not in path.read_bytes() for path in root.rglob("*.*"))


def test_apple_keyring_uses_interface_and_never_logs_or_writes_plaintext(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    capsys: pytest.CaptureFixture[str],
) -> None:
    credentials = _load_credentials()
    monkeypatch.setattr(credentials, "os", _OSProxy("posix"))
    monkeypatch.setattr(credentials, "sys", SimpleNamespace(platform="darwin"))
    stored: dict[tuple[str, str], str] = {}

    class AppleBackend:
        pass

    AppleBackend.__module__ = "keyring.backends.macOS.Keyring"
    fake_keyring = SimpleNamespace(
        get_keyring=lambda: AppleBackend(),
        set_password=lambda service, account, value: stored.__setitem__((service, account), value),
        get_password=lambda service, account: stored.get((service, account)),
    )
    monkeypatch.setitem(sys.modules, "keyring", fake_keyring)

    secret = "PKG_MAC_ACCEPTANCE_SECRET_APPLE_91d2"
    root = tmp_path / "apple-store"
    store = credentials.credential_store_for_platform(root)
    assert type(store) is credentials.MacOSKeychainCredentialStore
    store.put_profile("OPENAI", "PAPER", "synthetic-profile", {"api_key": SecretStr(secret)})
    resolved = store.resolve("OPENAI", "PAPER", "synthetic-profile")

    assert resolved.secret("api_key").get_secret_value() == secret
    assert stored
    assert all(value != secret for value in stored.values())
    assert all(secret.encode() not in path.read_bytes() for path in root.rglob("*.*"))
    assert secret not in repr(resolved)
    assert secret not in caplog.text
    captured = capsys.readouterr()
    assert secret not in captured.out + captured.err


def test_darwin_manifest_signatures_and_newer_only_publication(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    feed = _load_module(_TREE / "infra/release/feed_manifest.py", "pkg_mac_acceptance_feed")
    artifacts = {
        "darwin-aarch64": ("LeviathanAI_1.2.3_aarch64.app.tar.gz", "arm-signature"),
        "darwin-x86_64": ("LeviathanAI_1.2.3_x86_64.app.tar.gz", "intel-signature"),
    }
    payload = feed.build_latest_manifest(
        base_url="https://releases.invalid",
        version="1.2.3",
        notes="synthetic",
        pub_date=_STAMP,
        signature=None,
        require_signature=True,
        platform_artifacts=artifacts,
    )
    assert set(payload["platforms"]) == {"darwin-aarch64", "darwin-x86_64"}
    for label, entry in payload["platforms"].items():
        assert entry["signature"]
        assert label.split("-", 1)[0] in entry["url"]
        assert label.split("-", 1)[1] in entry["url"]

    for label, (artifact, _signature) in artifacts.items():
        incomplete = dict(artifacts)
        incomplete[label] = (artifact, None)
        with pytest.raises(feed.FeedManifestError, match="signature"):
            feed.build_latest_manifest(
                base_url="https://releases.invalid",
                version="1.2.3",
                notes="synthetic",
                pub_date=_STAMP,
                signature=None,
                require_signature=True,
                platform_artifacts=incomplete,
            )

    prior = tmp_path / "prior-latest.json"
    prior.write_text('{"version":"1.2.3"}', encoding="utf-8")
    base = {
        "bundle_dir": tmp_path / "bundle",
        "base_url": "https://releases.invalid",
        "notes": "synthetic",
        "pub_date": _STAMP,
        "signature": "windows-signature",
        "prior_latest": prior,
    }
    with pytest.raises(feed.FeedManifestError, match="newer"):
        feed.write_latest_manifest(version="1.2.3", **base)
    with pytest.raises(feed.FeedManifestError, match="newer"):
        feed.write_latest_manifest(version="1.2.2", **base)
    output = feed.write_latest_manifest(version="1.2.4", **base)
    assert json.loads(output.read_text(encoding="utf-8"))["version"] == "1.2.4"


def test_windows_feed_entry_matches_pinned_expectation() -> None:
    frozen = _load_module(_TREE / "infra/release/feed_manifest.py", "pkg_mac_frozen_feed")
    arguments = {
        "base_url": "https://releases.invalid",
        "version": "1.2.3",
        "notes": "synthetic",
        "pub_date": _STAMP,
        "signature": "synthetic-windows-signature",
        "require_signature": True,
    }
    payload = frozen.build_latest_manifest(**arguments)
    assert payload["platforms"] == {
        "windows-x86_64": {
            "signature": "synthetic-windows-signature",
            "url": (
                "https://releases.invalid/v1/updates/desktop/windows/x86_64/1.2.3/"
                "LeviathanAI_1.2.3_x64-setup.nsis.zip"
            ),
        }
    }


def _json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _contains_key(value: object, key: str) -> bool:
    if isinstance(value, dict):
        return any(str(item).casefold() == key.casefold() for item in value) or any(
            _contains_key(child, key) for child in value.values()
        )
    if isinstance(value, list):
        return any(_contains_key(child, key) for child in value)
    return False


def test_tauri_platform_configs_keep_macos_packaging_and_windows_semantics() -> None:
    mac_config = _json(_TREE / "apps/desktop/src-tauri/tauri.macos.conf.json")
    bundle = mac_config["bundle"]
    assert bundle["targets"] == ["app", "dmg"]
    assert bundle["createUpdaterArtifacts"] is True
    assert not _contains_key(mac_config, "nsis")
    assert not _contains_key(mac_config, "webviewInstallMode")

    windows_config_path = _TREE / "apps/desktop/src-tauri/tauri.conf.json"
    frozen_windows = _json(windows_config_path)
    assert hashlib.sha256(windows_config_path.read_bytes()).hexdigest() == (
        "9a55edc96e874f195af3f1f58191d13d3a1d58db81ce4cd2c6ca9f983e6b73ff"
    )
    assert frozen_windows["bundle"] == {
        "active": True,
        "createUpdaterArtifacts": False,
        "targets": ["nsis"],
        "icon": ["icons/icon.ico"],
        "resources": ["resources/sidecar/"],
        "windows": {
            "webviewInstallMode": {"type": "offlineInstaller"},
            "nsis": {"installMode": "currentUser"},
        },
    }
    assert "dmg" not in frozen_windows["bundle"]["targets"]
