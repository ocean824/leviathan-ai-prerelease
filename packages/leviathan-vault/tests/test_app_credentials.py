from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from importlib import import_module

import pytest
from pydantic import SecretStr

from leviathan_core.seal import digest as seal_digest
from leviathan_core.seal import require
from leviathan_vault.app_credentials import (
    CredentialError,
    DPAPICredentialStore,
    InMemoryCredentialStore,
    ResolvedCredentialV1,
)


def test_alpaca_partial_put_retains_secrets_and_bumps_revision() -> None:
    store = InMemoryCredentialStore()
    first = store.put_profile(
        "ALPACA",
        "PAPER",
        "default",
        {
            "key_id": SecretStr("SYNTHETIC-not-a-secret-0001"),
            "secret_key": SecretStr("SYNTHETIC-not-a-secret-0002"),
        },
    )
    second = store.put_profile(
        "ALPACA",
        "PAPER",
        "default",
        {
            "key_id": SecretStr("SYNTHETIC-not-a-secret-0003"),
        },
    )
    assert first.revision == 1
    assert second.revision == 2
    assert (
        store.resolve("ALPACA", "PAPER", "default").secret("secret_key").get_secret_value()
        == "SYNTHETIC-not-a-secret-0002"
    )
    assert store.is_stale(first)
    assert not store.is_stale(second)


def test_incomplete_and_cross_environment_profiles_do_not_resolve() -> None:
    store = InMemoryCredentialStore()
    store.put_profile(
        "ALPACA", "PAPER", "default", {"key_id": SecretStr("SYNTHETIC-not-a-secret-0001")}
    )
    with pytest.raises(CredentialError, match="NOT_CONFIGURED"):
        store.resolve("ALPACA", "PAPER", "default")
    with pytest.raises(CredentialError, match="NOT_CONFIGURED"):
        store.resolve("ALPACA", "LIVE", "default")
    with pytest.raises(CredentialError, match="NOT_CONFIGURED"):
        store.resolve("IBKR", "PAPER", "default")


def test_delete_bumps_revision_and_provider_environment_pairs_are_exact() -> None:
    store = InMemoryCredentialStore()
    profile = store.put_profile(
        "ALPACA",
        "PAPER",
        "default",
        {
            "key_id": SecretStr("SYNTHETIC-key-0001"),
            "secret_key": SecretStr("SYNTHETIC-secret-0001"),
        },
    )
    store.delete_profile("ALPACA", "PAPER", "default")
    recreated = store.put_profile(
        "ALPACA",
        "PAPER",
        "default",
        {
            "key_id": SecretStr("SYNTHETIC-key-0002"),
            "secret_key": SecretStr("SYNTHETIC-secret-0002"),
        },
    )
    assert recreated.revision == profile.revision + 2
    with pytest.raises(CredentialError, match="INVALID_ENVIRONMENT"):
        store.put_profile(
            "MCP",
            "LIVE",
            "default",
            {"server_id": "server-one", "token": SecretStr("SYNTHETIC-token-0001")},
        )


@pytest.mark.parametrize("value", ["UPPER", "..", "a.b", "con", "COM1", "x" * 65, "", 3, None])
def test_profile_id_rejects_invalid_syntax_without_echo(value: object) -> None:
    store = InMemoryCredentialStore()
    with pytest.raises(CredentialError) as caught:
        store.put_profile("ALPACA", "PAPER", value, {})  # type: ignore[arg-type]
    assert caught.value.code == "INVALID_ID"
    assert caught.value.loc == ("profile_id",)
    assert str(caught.value) == "INVALID_ID"


@pytest.mark.parametrize("value", ["UPPER", "..", "a.b", "con", "COM1", "x" * 65, "", 3, None])
def test_mcp_server_id_rejects_invalid_syntax(value: object) -> None:
    store = InMemoryCredentialStore()
    with pytest.raises(CredentialError) as caught:
        store.put_profile(
            "MCP",
            "PAPER",
            "default",
            {"server_id": value, "token": SecretStr("SYNTHETIC-token-0001")},
        )
    assert caught.value.code == "INVALID_ID"
    assert caught.value.loc == ("server_id",)


def test_sealed_profile_contains_no_secret_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    digest_module = import_module("leviathan_core.seal.digest")

    store = InMemoryCredentialStore()
    synthetic = "SYNTHETIC-digest-probe-24681357"
    profile = store.put_profile(
        "ALPACA",
        "PAPER",
        "default",
        {
            "key_id": SecretStr(synthetic),
            "secret_key": SecretStr("SYNTHETIC-secret-0002"),
        },
    )
    observed: list[object] = []
    original = digest_module.canonical_json

    def capture(value: object) -> bytes:
        observed.append(value)
        return original(value)

    monkeypatch.setattr(digest_module, "canonical_json", capture)
    seal_digest(profile)
    require(profile, "leviathan_vault.app_credentials.profile.v1")
    assert observed
    assert all(synthetic.encode() not in repr(value).encode() for value in observed)
    assert all(b"SYNTHETIC-secret-0002" not in repr(value).encode() for value in observed)


def test_resolved_value_redacts_and_denies_export_and_copy() -> None:
    store = InMemoryCredentialStore()
    store.put_profile(
        "ALPACA",
        "PAPER",
        "default",
        {
            "key_id": SecretStr("SYNTHETIC-not-a-secret-0001"),
            "secret_key": SecretStr("SYNTHETIC-not-a-secret-0002"),
        },
    )
    resolved = store.resolve("ALPACA", "PAPER", "default")
    assert isinstance(resolved, ResolvedCredentialV1)
    assert "SYNTHETIC" not in repr(resolved)
    for action in (
        resolved.model_dump,
        resolved.model_dump_json,
        resolved.__reduce__,
        resolved.__copy__,
    ):
        with pytest.raises(CredentialError, match="FORBIDDEN_OPERATION"):
            action()


@pytest.mark.skipif(__import__("os").name != "nt", reason="DPAPI CurrentUser is Windows only")
def test_dpapi_round_trip_under_test_directory(tmp_path) -> None:
    store = DPAPICredentialStore(tmp_path / "runtime-credentials")
    store.put_profile(
        "ALPACA",
        "PAPER",
        "default",
        {
            "key_id": SecretStr("SYNTHETIC-not-a-secret-0001"),
            "secret_key": SecretStr("SYNTHETIC-not-a-secret-0002"),
        },
    )
    loaded = DPAPICredentialStore(tmp_path / "runtime-credentials")
    assert (
        loaded.resolve("ALPACA", "PAPER", "default").secret("key_id").get_secret_value()
        == "SYNTHETIC-not-a-secret-0001"
    )
    assert (
        b"SYNTHETIC-not-a-secret-0001"
        not in (
            tmp_path / "runtime-credentials" / "PAPER" / "ALPACA" / "default" / "profile.json"
        ).read_bytes()
    )


def test_dpapi_fails_closed_off_windows(tmp_path) -> None:
    if __import__("os").name == "nt":
        pytest.skip("Windows exercises the real DPAPI backend")
    with pytest.raises(CredentialError, match="UNAVAILABLE"):
        DPAPICredentialStore(tmp_path / "runtime-credentials")


@pytest.mark.skipif(__import__("os").name != "nt", reason="DPAPI CurrentUser is Windows only")
def test_dpapi_corrupt_profile_isolated_and_deletable(tmp_path) -> None:
    root = tmp_path / "runtime-credentials"
    store = DPAPICredentialStore(root)
    store.put_profile(
        "ALPACA",
        "PAPER",
        "default",
        {
            "key_id": SecretStr("SYNTHETIC-key-0001"),
            "secret_key": SecretStr("SYNTHETIC-secret-0001"),
        },
    )
    store.put_profile(
        "ALPACA",
        "PAPER",
        "other",
        {
            "key_id": SecretStr("SYNTHETIC-other-key-0001"),
            "secret_key": SecretStr("SYNTHETIC-other-secret-0001"),
        },
    )
    (root / "PAPER" / "ALPACA" / "default" / "profile.json").write_bytes(
        b"corrupt synthetic record"
    )
    loaded = DPAPICredentialStore(root)
    assert loaded.corrupt_profiles() == (("ALPACA", "PAPER", "default"),)
    assert (
        loaded.resolve("ALPACA", "PAPER", "other").secret("key_id").get_secret_value()
        == "SYNTHETIC-other-key-0001"
    )
    with pytest.raises(CredentialError, match="CORRUPT"):
        loaded.resolve("ALPACA", "PAPER", "default")
    loaded.delete_profile("ALPACA", "PAPER", "default")
    assert loaded.corrupt_profiles() == ()


@pytest.mark.skipif(__import__("os").name != "nt", reason="DPAPI CurrentUser is Windows only")
def test_dpapi_failed_atomic_rotation_preserves_complete_old_record(tmp_path, monkeypatch) -> None:
    root = tmp_path / "runtime-credentials"
    store = DPAPICredentialStore(root)
    store.put_profile(
        "ALPACA",
        "PAPER",
        "default",
        {
            "key_id": SecretStr("SYNTHETIC-old-key-0001"),
            "secret_key": SecretStr("SYNTHETIC-old-secret-0001"),
        },
    )
    real_replace = __import__("os").replace

    def fail_profile_replace(source, destination):
        if __import__("pathlib").Path(destination).name == "profile.json":
            raise OSError("injected synthetic commit failure")
        real_replace(source, destination)

    monkeypatch.setattr("leviathan_vault.app_credentials.os.replace", fail_profile_replace)
    with pytest.raises(CredentialError, match="UNAVAILABLE"):
        store.put_profile(
            "ALPACA",
            "PAPER",
            "default",
            {
                "key_id": SecretStr("SYNTHETIC-new-key-0001"),
                "secret_key": SecretStr("SYNTHETIC-new-secret-0001"),
            },
        )
    assert (
        store.resolve("ALPACA", "PAPER", "default").secret("key_id").get_secret_value()
        == "SYNTHETIC-old-key-0001"
    )
    restarted = DPAPICredentialStore(root)
    resolved = restarted.resolve("ALPACA", "PAPER", "default")
    assert resolved.revision == 1
    assert resolved.secret("key_id").get_secret_value() == "SYNTHETIC-old-key-0001"
    assert resolved.secret("secret_key").get_secret_value() == "SYNTHETIC-old-secret-0001"


@pytest.mark.skipif(__import__("os").name != "nt", reason="DPAPI CurrentUser is Windows only")
def test_dpapi_swapped_profile_envelope_is_corrupt_and_other_record_loads(tmp_path) -> None:
    root = tmp_path / "runtime-credentials"
    store = DPAPICredentialStore(root)
    for profile_id in ("acct-a", "acct-b"):
        store.put_profile(
            "ALPACA",
            "PAPER",
            profile_id,
            {
                "key_id": SecretStr(f"SYNTHETIC-key-{profile_id}"),
                "secret_key": SecretStr(f"SYNTHETIC-secret-{profile_id}"),
            },
        )
    source = root / "PAPER" / "ALPACA" / "acct-a" / "profile.json"
    destination = root / "PAPER" / "ALPACA" / "acct-b" / "profile.json"
    destination.write_bytes(source.read_bytes())
    loaded = DPAPICredentialStore(root)
    assert loaded.corrupt_profiles() == (("ALPACA", "PAPER", "acct-b"),)
    assert (
        loaded.resolve("ALPACA", "PAPER", "acct-a").secret("secret_key").get_secret_value()
        == "SYNTHETIC-secret-acct-a"
    )


def test_delete_unknown_profile_is_idempotent_without_tombstone(tmp_path) -> None:
    store = InMemoryCredentialStore()
    store.delete_profile("ALPACA", "PAPER", "never-configured")
    assert store.status_all() == ()
    if __import__("os").name == "nt":
        disk_store = DPAPICredentialStore(tmp_path / "runtime-credentials")
        disk_store.delete_profile("ALPACA", "PAPER", "never-configured")
        assert not list((tmp_path / "runtime-credentials").glob("PAPER/ALPACA/.*.revision"))


@pytest.mark.skipif(__import__("os").name != "nt", reason="DPAPI CurrentUser is Windows only")
def test_entropy_first_run_race_produces_one_complete_value(tmp_path) -> None:
    root = tmp_path / "runtime-credentials"
    with ThreadPoolExecutor(max_workers=8) as executor:
        entropies = list(
            executor.map(lambda _: bytes(DPAPICredentialStore(root)._entropy), range(8))
        )
    assert len(set(entropies)) == 1
    assert len((root / ".entropy").read_bytes()) == 32


def test_profile_count_is_bounded_per_provider_environment() -> None:
    store = InMemoryCredentialStore()
    for index in range(256):
        server = f"server-{index}"
        store.put_profile("MCP", "PAPER", server, {"server_id": server})
    with pytest.raises(CredentialError, match="LIMIT_EXCEEDED"):
        store.put_profile("MCP", "PAPER", "server-over-limit", {"server_id": "server-over-limit"})
