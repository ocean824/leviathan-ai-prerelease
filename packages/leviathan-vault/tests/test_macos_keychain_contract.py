from __future__ import annotations

import base64
import sys
from types import SimpleNamespace

from leviathan_vault import app_credentials


def test_macos_credential_envelope_uses_keyring_and_never_returns_plaintext(
    monkeypatch,
) -> None:
    stored: dict[tuple[str, str], str] = {}

    class MacKeychainBackend:
        __module__ = "keyring.backends.macOS"

    fake_keyring = SimpleNamespace(
        get_keyring=lambda: MacKeychainBackend(),
        set_password=lambda service, account, value: stored.__setitem__((service, account), value),
        get_password=lambda service, account: stored.get((service, account)),
    )
    monkeypatch.setitem(sys.modules, "keyring", fake_keyring)
    monkeypatch.setattr(app_credentials.sys, "platform", "darwin")

    raw = bytearray(b"synthetic private fixture")
    entropy = bytearray(b"stable test profile entropy")
    reference = app_credentials._crypt(raw, entropy, decrypt=False)

    assert reference == b"keychain:v1"
    assert stored
    assert all(base64.b64decode(value) == bytes(raw) for value in stored.values())
    assert bytes(raw) not in reference
    assert app_credentials._crypt(reference, entropy, decrypt=True) == raw


def test_macos_keychain_backend_fails_closed_if_keyring_selects_non_keychain(
    monkeypatch,
) -> None:
    class UnsafeBackend:
        __module__ = "keyring.backends.fail"

    monkeypatch.setitem(
        sys.modules,
        "keyring",
        SimpleNamespace(get_keyring=lambda: UnsafeBackend()),
    )
    monkeypatch.setattr(app_credentials.sys, "platform", "darwin")
    try:
        app_credentials._crypt(bytearray(b"secret fixture"), bytearray(b"entropy"), decrypt=False)
    except app_credentials.CredentialError as error:
        assert error.code == "UNAVAILABLE"
    else:
        raise AssertionError("non-Keychain backend must fail closed")
