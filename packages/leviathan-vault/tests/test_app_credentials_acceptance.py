"""Contract-first acceptance for the runtime operator credential store."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import pickle
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr

from leviathan_core.seal import digest
from leviathan_core.seal.digest import canonical_json
from leviathan_vault.app_credentials import (
    CredentialError,
    DPAPICredentialStore,
    InMemoryCredentialStore,
)

SECRET_VALUE = "CRED_UI_SYNTHETIC_SECRET_" + "Q" * 220 + "_END"
SECOND_SECRET = "CRED_UI_SYNTHETIC_ROTATED_SECRET_" + "R" * 190 + "_END"
SYNTHETIC_KEY_ID = "CRED_UI_SYNTHETIC_KEY_ID_42"
ROTATED_KEY_ID = "CRED_UI_SYNTHETIC_KEY_ID_43"
PROFILE_ID = "default"
CANARY_SECRETS = (SECRET_VALUE, SECOND_SECRET, SYNTHETIC_KEY_ID, ROTATED_KEY_ID)


def _secret(value: str = SECRET_VALUE) -> SecretStr:
    return SecretStr(value)


def _alpaca_fields(
    *, key_id: str = SYNTHETIC_KEY_ID, secret: str = SECRET_VALUE
) -> dict[str, object]:
    return {"key_id": _secret(key_id), "secret_key": _secret(secret)}


def _fields(provider: str) -> dict[str, object]:
    if provider == "ALPACA":
        return _alpaca_fields()
    if provider == "IBKR":
        return {"host": "127.0.0.1", "port": 4002, "client_id": 7, "account_id": "SYNTH-ACCT"}
    if provider == "MT5":
        return {"server": "SYNTH-DEMO", "login": "synthetic-login", "password": _secret()}
    if provider == "MCP":
        return {"server_id": "synthetic-mcp", "token": _secret()}
    raise AssertionError(f"test fixture provider missing: {provider}")


def _markers(secret: str = SECRET_VALUE) -> tuple[str, ...]:
    encoded = base64.urlsafe_b64encode(secret.encode("utf-8")).decode("ascii")
    markers = [
        secret,
        secret[:13],
        secret[-13:],
        hashlib.sha256(secret.encode("utf-8")).hexdigest(),
        secret[::-1],
        encoded,
    ]
    return tuple(markers)


def _contains_exact_value(value: object, expected: object) -> bool:
    if isinstance(value, dict):
        return any(
            "length" in str(key).lower() or _contains_exact_value(item, expected)
            for key, item in value.items()
        )
    if isinstance(value, (list, tuple)):
        return any(_contains_exact_value(item, expected) for item in value)
    return value == expected


def _assert_absent(text: str, *secrets: str) -> None:
    for secret in secrets or CANARY_SECRETS:
        for marker in _markers(secret):
            assert marker not in text


def _assert_error(call: Callable[[], Any], code: str | None = None) -> CredentialError:
    with pytest.raises(CredentialError) as caught:
        call()
    error = caught.value
    if code is not None:
        assert error.code == code
    assert error.args == (error.code,)
    assert str(error) == error.code
    return error


def _error_surfaces(error: BaseException) -> str:
    return "\n".join(
        (
            str(error),
            repr(error),
            str(error.args),
            repr(error.args),
            repr(error.__cause__),
            repr(error.__context__),
        )
    )


def _profile_envelope(root: Path, profile_id: str) -> Path:
    envelope = root / "PAPER" / "ALPACA" / profile_id / "profile.json"
    assert envelope.is_file()
    return envelope


def _filesystem_snapshot(root: Path) -> tuple[tuple[str, bytes | None], ...]:
    entries = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        entries.append((relative, path.read_bytes() if path.is_file() else None))
    return tuple(entries)


def test_provider_environment_matrix_and_loopback_schema_are_enforced() -> None:
    store = InMemoryCredentialStore()
    for provider, environment in (
        ("ALPACA", "PAPER"),
        ("ALPACA", "LIVE"),
        ("IBKR", "PAPER"),
        ("IBKR", "LIVE"),
        ("MT5", "DEMO"),
        ("MT5", "LIVE"),
        ("MCP", "PAPER"),
    ):
        profile = store.put_profile(provider, environment, PROFILE_ID, _fields(provider))
        assert profile.provider == provider
        assert profile.environment == environment
        assert profile.profile_id == PROFILE_ID

    for provider, environment in (
        ("ALPACA", "DEMO"),
        ("IBKR", "DEMO"),
        ("MT5", "PAPER"),
        ("MCP", "LIVE"),
        ("UNKNOWN", "PAPER"),
    ):
        fields = _alpaca_fields() if provider == "UNKNOWN" else _fields(provider)
        _assert_error(
            lambda provider=provider, environment=environment, fields=fields: store.put_profile(
                provider, environment, "matrix-probe", fields
            )
        )

    non_loopback = {
        "host": "192.0.2.20",
        "port": 4002,
        "client_id": 8,
        "account_id": "SYNTH-ACCT",
    }
    _assert_error(lambda: store.put_profile("IBKR", "PAPER", "remote-host", non_loopback))


@pytest.mark.parametrize(
    "invalid_id",
    ("Upper", "..", "a.b", "con", "COM1", "x" * 65, "", 17),
    ids=(
        "uppercase",
        "traversal",
        "dot",
        "reserved-con",
        "reserved-com1",
        "too-long",
        "empty",
        "not-str",
    ),
)
def test_profile_id_uses_strict_closed_safe_syntax_and_content_free_errors(
    invalid_id: object,
) -> None:
    store = InMemoryCredentialStore()
    error = _assert_error(
        lambda: store.put_profile("ALPACA", "PAPER", invalid_id, _alpaca_fields()),
        "INVALID_ID",
    )
    _assert_absent(_error_surfaces(error))


@pytest.mark.parametrize(
    "invalid_server_id",
    ("Upper", "..", "a.b", "con", "COM1", "x" * 65, "", 17),
    ids=(
        "uppercase",
        "traversal",
        "dot",
        "reserved-con",
        "reserved-com1",
        "too-long",
        "empty",
        "not-str",
    ),
)
def test_mcp_server_id_uses_strict_closed_safe_syntax(
    invalid_server_id: object,
) -> None:
    store = InMemoryCredentialStore()
    error = _assert_error(
        lambda: store.put_profile(
            "MCP",
            "PAPER",
            PROFILE_ID,
            {"server_id": invalid_server_id, "token": _secret()},
        ),
        "INVALID_ID",
    )
    _assert_absent(_error_surfaces(error))


def test_partial_profile_is_not_resolvable_until_every_required_field_exists() -> None:
    store = InMemoryCredentialStore()
    partial = store.put_profile(
        "ALPACA", "PAPER", PROFILE_ID, {"key_id": _secret(SYNTHETIC_KEY_ID)}
    )
    assert partial.configured["key_id"] is True
    assert partial.configured["secret_key"] is False
    _assert_error(
        lambda: store.resolve("ALPACA", "PAPER", PROFILE_ID),
        "NOT_CONFIGURED",
    )

    complete = store.put_profile(
        "ALPACA", "PAPER", PROFILE_ID, {"secret_key": _secret(SECRET_VALUE)}
    )
    assert complete.configured["key_id"] is True
    assert complete.configured["secret_key"] is True
    resolved = store.resolve("ALPACA", "PAPER", PROFILE_ID)
    assert resolved.secret("secret_key").get_secret_value() == SECRET_VALUE


def test_partial_update_retains_omitted_secret_and_revision_stales_old_consumers() -> None:
    store = InMemoryCredentialStore()
    first = store.put_profile(
        "MT5",
        "DEMO",
        PROFILE_ID,
        {"server": "SYNTH-ONE", "login": "login-one", "password": _secret()},
    )
    old_resolved = store.resolve("MT5", "DEMO", PROFILE_ID)
    second = store.put_profile(
        "MT5", "DEMO", PROFILE_ID, {"server": "SYNTH-TWO", "login": "login-two"}
    )
    new_resolved = store.resolve("MT5", "DEMO", PROFILE_ID)

    assert second.revision > first.revision
    assert second.server == "SYNTH-TWO"
    assert second.login == "login-two"
    assert old_resolved.secret("password").get_secret_value() == SECRET_VALUE
    assert new_resolved.secret("password").get_secret_value() == SECRET_VALUE
    assert store.is_stale(first) is True
    assert store.is_stale(second) is False


def test_put_and_delete_bump_profile_revision_and_do_not_reuse_old_values() -> None:
    store = InMemoryCredentialStore()
    first = store.put_profile("ALPACA", "PAPER", PROFILE_ID, _alpaca_fields())
    store.delete_profile("ALPACA", "PAPER", PROFILE_ID)
    _assert_error(lambda: store.resolve("ALPACA", "PAPER", PROFILE_ID), "NOT_CONFIGURED")

    recreated = store.put_profile(
        "ALPACA", "PAPER", PROFILE_ID, _alpaca_fields(secret=SECOND_SECRET)
    )
    assert recreated.revision >= first.revision + 2
    assert (
        store.resolve("ALPACA", "PAPER", PROFILE_ID).secret("secret_key").get_secret_value()
        == SECOND_SECRET
    )
    assert store.is_stale(first) is True


def test_deleting_a_missing_profile_is_idempotent_and_creates_no_tombstone() -> None:
    store = InMemoryCredentialStore()
    store.put_profile("ALPACA", "PAPER", PROFILE_ID, _alpaca_fields())
    store.delete_profile("ALPACA", "PAPER", PROFILE_ID)
    before = store.status_all()

    for _ in range(8):
        store.delete_profile("ALPACA", "PAPER", PROFILE_ID)

    assert store.status_all() == before == ()


def test_oversize_secret_fails_with_a_content_free_store_error() -> None:
    store = InMemoryCredentialStore()
    oversized = "SYNTHETIC_OVERSIZE_SECRET_" + "V" * (1024 * 1024)
    error = _assert_error(
        lambda: store.put_profile(
            "ALPACA",
            "PAPER",
            PROFILE_ID,
            _alpaca_fields(secret=oversized),
        )
    )
    surface = _error_surfaces(error)
    _assert_absent(surface, oversized)
    assert len(surface) < 1024


def test_exact_provider_and_environment_resolution_never_falls_back() -> None:
    store = InMemoryCredentialStore()
    store.put_profile("ALPACA", "PAPER", "shared", _alpaca_fields(secret=SECRET_VALUE))
    store.put_profile("ALPACA", "LIVE", "shared", _alpaca_fields(secret=SECOND_SECRET))
    store.put_profile(
        "MT5",
        "DEMO",
        "shared",
        {"server": "DEMO-SERVER", "login": "demo-user", "password": _secret("DEMO-SECRET")},
    )
    store.put_profile(
        "MT5",
        "LIVE",
        "shared",
        {"server": "LIVE-SERVER", "login": "live-user", "password": _secret("LIVE-SECRET")},
    )
    store.put_profile(
        "MCP", "PAPER", "shared", {"server_id": "synthetic-mcp", "token": _secret("MCP-SECRET")}
    )

    assert (
        store.resolve("ALPACA", "PAPER", "shared").secret("secret_key").get_secret_value()
        == SECRET_VALUE
    )
    assert (
        store.resolve("ALPACA", "LIVE", "shared").secret("secret_key").get_secret_value()
        == SECOND_SECRET
    )
    assert (
        store.resolve("MT5", "DEMO", "shared").secret("password").get_secret_value()
        == "DEMO-SECRET"
    )
    assert (
        store.resolve("MT5", "LIVE", "shared").secret("password").get_secret_value()
        == "LIVE-SECRET"
    )
    assert (
        store.resolve("MCP", "PAPER", "shared").secret("token").get_secret_value() == "MCP-SECRET"
    )
    _assert_error(lambda: store.resolve("MT5", "PAPER", "shared"), "INVALID_ENVIRONMENT")
    _assert_error(lambda: store.resolve("IBKR", "PAPER", "shared"), "NOT_CONFIGURED")


def test_secret_values_and_derived_material_never_enter_sealed_profile_or_digest_input(
    caplog: pytest.LogCaptureFixture,
) -> None:
    store = InMemoryCredentialStore()
    profile = store.put_profile("ALPACA", "PAPER", PROFILE_ID, _alpaca_fields())

    computed_digest = digest(profile)
    canonical_profile = canonical_json(profile.model_dump(mode="json")).decode("utf-8")
    profile_surfaces = "\n".join(
        (
            repr(profile),
            str(profile),
            repr(profile.model_dump()),
            profile.model_dump_json(),
            computed_digest,
            canonical_profile,
            caplog.text,
        )
    )
    assert canonical_profile
    dumped_profile = profile.model_dump()
    assert not {"key_id", "secret_key", "password", "token"}.intersection(dumped_profile)
    json_profile = profile.model_dump(mode="json")
    for secret in CANARY_SECRETS:
        assert not _contains_exact_value(json_profile, len(secret))
        assert not _contains_exact_value(json_profile, str(len(secret)))
    _assert_absent(profile_surfaces)


def test_resolved_credential_is_redacted_and_refuses_serialization_or_copy() -> None:
    store = InMemoryCredentialStore()
    store.put_profile("ALPACA", "PAPER", PROFILE_ID, _alpaca_fields())
    resolved = store.resolve("ALPACA", "PAPER", PROFILE_ID)

    assert not hasattr(resolved, "__dict__")
    _assert_absent(repr(resolved))
    operations: tuple[Callable[[], object], ...] = (
        lambda: resolved.model_dump(),
        lambda: resolved.model_dump_json(),
        lambda: json.dumps(resolved),
        lambda: pickle.dumps(resolved),
        lambda: copy.copy(resolved),
        lambda: copy.deepcopy(resolved),
    )
    for operation in operations:
        with pytest.raises(Exception) as caught:
            operation()
        _assert_absent(_error_surfaces(caught.value))


@pytest.mark.skipif(os.name != "nt", reason="CryptProtectData is Windows-only")
def test_dpapi_round_trip_uses_only_tmp_path_and_keeps_plaintext_off_disk(tmp_path: Path) -> None:
    root = tmp_path / "runtime-credentials"
    store = DPAPICredentialStore(root)
    store.put_profile("ALPACA", "PAPER", PROFILE_ID, _alpaca_fields())
    resolved = DPAPICredentialStore(root).resolve("ALPACA", "PAPER", PROFILE_ID)
    assert resolved.secret("secret_key").get_secret_value() == SECRET_VALUE
    assert resolved.secret("key_id").get_secret_value() == SYNTHETIC_KEY_ID

    disk_bytes = b"".join(path.read_bytes() for path in root.rglob("*") if path.is_file())
    _assert_absent(disk_bytes.decode("latin-1"))


@pytest.mark.skipif(os.name != "nt", reason="DPAPI atomic-write behavior is Windows-only")
def test_failed_profile_envelope_replace_keeps_the_previous_complete_profile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "runtime-credentials"
    store = DPAPICredentialStore(root)
    initial = store.put_profile("ALPACA", "PAPER", PROFILE_ID, _alpaca_fields())
    original_replace = os.replace

    attempted: list[Path] = []

    def fail_replace(source: object, target: object) -> None:
        destination = Path(target)
        if destination.name == "profile.json":
            attempted.append(destination)
            raise OSError("synthetic disk write failure")
        original_replace(source, target)

    with monkeypatch.context() as patch_context:
        patch_context.setattr(os, "replace", fail_replace)
        failure = _assert_error(
            lambda: store.put_profile(
                "ALPACA",
                "PAPER",
                PROFILE_ID,
                _alpaca_fields(key_id=ROTATED_KEY_ID, secret=SECOND_SECRET),
            )
        )
        _assert_absent(_error_surfaces(failure))
    assert attempted

    resolved = DPAPICredentialStore(root).resolve("ALPACA", "PAPER", PROFILE_ID)
    assert resolved.revision == initial.revision
    assert resolved.secret("secret_key").get_secret_value() == SECRET_VALUE
    assert resolved.secret("key_id").get_secret_value() == SYNTHETIC_KEY_ID


@pytest.mark.skipif(os.name != "nt", reason="DPAPI envelope behavior is Windows-only")
def test_swapped_profile_envelope_is_rejected_as_content_free_corrupt(
    tmp_path: Path,
) -> None:
    root = tmp_path / "runtime-credentials"
    store = DPAPICredentialStore(root)
    store.put_profile("ALPACA", "PAPER", "alpha", _alpaca_fields(secret=SECRET_VALUE))
    store.put_profile("ALPACA", "PAPER", "bravo", _alpaca_fields(secret=SECOND_SECRET))
    alpha_file = _profile_envelope(root, "alpha")
    bravo_file = _profile_envelope(root, "bravo")
    alpha_file.write_bytes(bravo_file.read_bytes())

    error = _assert_error(
        lambda: DPAPICredentialStore(root).resolve("ALPACA", "PAPER", "alpha"),
        "CORRUPT",
    )
    _assert_absent(_error_surfaces(error))
    reopened = DPAPICredentialStore(root)
    assert reopened.resolve("ALPACA", "PAPER", "bravo").secret(
        "secret_key"
    ).get_secret_value() == SECOND_SECRET
    assert reopened.corrupt_profiles() == (("ALPACA", "PAPER", "alpha"),)


@pytest.mark.skipif(os.name != "nt", reason="DPAPI envelope behavior is Windows-only")
def test_one_corrupt_profile_does_not_block_store_startup_or_other_profiles(
    tmp_path: Path,
) -> None:
    root = tmp_path / "runtime-credentials"
    store = DPAPICredentialStore(root)
    store.put_profile("ALPACA", "PAPER", "alpha", _alpaca_fields(secret=SECRET_VALUE))
    store.put_profile("ALPACA", "PAPER", "bravo", _alpaca_fields(secret=SECOND_SECRET))
    _profile_envelope(root, "alpha").write_bytes(b"synthetic-corrupt-envelope")

    reopened = DPAPICredentialStore(root)
    resolved = reopened.resolve("ALPACA", "PAPER", "bravo")
    assert resolved.secret("secret_key").get_secret_value() == SECOND_SECRET
    assert reopened.corrupt_profiles() == (("ALPACA", "PAPER", "alpha"),)
    error = _assert_error(
        lambda: reopened.resolve("ALPACA", "PAPER", "alpha"),
        "CORRUPT",
    )
    _assert_absent(_error_surfaces(error))
    reopened.delete_profile("ALPACA", "PAPER", "alpha")
    assert reopened.corrupt_profiles() == ()
    assert reopened.resolve("ALPACA", "PAPER", "bravo").secret(
        "secret_key"
    ).get_secret_value() == SECOND_SECRET


@pytest.mark.skipif(os.name != "nt", reason="DPAPI missing-profile persistence is Windows-only")
def test_missing_profile_deletes_do_not_grow_disk_tombstones(tmp_path: Path) -> None:
    root = tmp_path / "runtime-credentials"
    store = DPAPICredentialStore(root)
    store.put_profile("ALPACA", "PAPER", PROFILE_ID, _alpaca_fields())
    store.delete_profile("ALPACA", "PAPER", PROFILE_ID)
    before = _filesystem_snapshot(root)

    for _ in range(8):
        store.delete_profile("ALPACA", "PAPER", PROFILE_ID)

    assert DPAPICredentialStore(root).status_all() == ()
    assert _filesystem_snapshot(root) == before


@pytest.mark.skipif(os.name != "nt", reason="DPAPI blob test is Windows-only")
def test_corrupt_dpapi_blob_fails_without_returning_other_secret_fields(tmp_path: Path) -> None:
    root = tmp_path / "runtime-credentials"
    store = DPAPICredentialStore(root)
    store.put_profile("ALPACA", "PAPER", PROFILE_ID, _alpaca_fields())
    _profile_envelope(root, PROFILE_ID).write_bytes(b"synthetic-corrupt-ciphertext")

    error = _assert_error(
        lambda: DPAPICredentialStore(root).resolve("ALPACA", "PAPER", PROFILE_ID),
        "CORRUPT",
    )
    _assert_absent(_error_surfaces(error))


@pytest.mark.skipif(os.name != "nt", reason="Windows reparse-point behavior")
def test_dpapi_store_rejects_reparse_directory_and_does_not_write_outside_root(
    tmp_path: Path,
) -> None:
    root = tmp_path / "runtime-credentials"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    try:
        (root / "PAPER").symlink_to(outside, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"cannot create synthetic directory reparse point here: {type(error).__name__}")

    store = DPAPICredentialStore(root)
    failure = _assert_error(
        lambda: store.put_profile("ALPACA", "PAPER", PROFILE_ID, _alpaca_fields())
    )
    _assert_absent(_error_surfaces(failure))
    assert not tuple(outside.rglob("*.bin"))


@pytest.mark.skipif(os.name == "nt", reason="non-Windows production backend is unavailable")
def test_dpapi_backend_is_unavailable_off_windows(tmp_path: Path) -> None:
    error = _assert_error(
        lambda: DPAPICredentialStore(tmp_path / "runtime-credentials").put_profile(
            "ALPACA", "PAPER", PROFILE_ID, _alpaca_fields()
        ),
        "UNAVAILABLE",
    )
    _assert_absent(_error_surfaces(error))
