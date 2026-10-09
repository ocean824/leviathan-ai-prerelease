from __future__ import annotations

import json
import os
import stat
import subprocess
from pathlib import Path

import pytest

from leviathan_vault import XyraVault, import_keys, transaction

SCOPE = "leviathan-ai"
ENV = "development"
OLD_VALUE = "N8qW4pL2vT7mR9xK"
NEW_VALUE = "Z6mP3vT8qL2xR7jW"


def _temp_factory(tmp_path: Path) -> tuple[Path, Path, Path]:
    source = os.environ.get("XYRA_BROKER_MODULE")
    if os.name != "nt" or not source or not Path(source).is_file():
        pytest.skip("real XYRA broker path required for temporary Windows store")
    root = tmp_path / "factory"
    (root / "registries").mkdir(parents=True)
    module = root / "tools" / "secrets" / "Xyra.Secrets.psm1"
    module.parent.mkdir(parents=True)
    module.write_bytes(Path(source).read_bytes())
    registry = root / "registries" / "SECRET_REGISTRY.yaml"
    registry.write_text(json.dumps({"schema_version": "1.0.0", "entries": [{
        "name": "UNRELATED_SECRET", "scope": "factory-admin",
        "environment": "administration", "inherit_to_projects": False,
        "store_reference": "dpapi-current-user://factory-admin--administration--UNRELATED_SECRET.dpapi",
        "custom": "preserve",
    }]}), encoding="utf-8")
    bindings = tmp_path / "SECRET_BINDINGS.yaml"
    bindings.write_text(json.dumps({"schema_version": "1.0.0", "bindings": [{
        "provider": "unrelated", "name": "UNRELATED_API_KEY", "scope": SCOPE,
        "environment": ENV, "state": "declared", "custom": "preserve",
    }], "aliases": []}), encoding="utf-8")
    return root, registry, bindings


def _acl(path: Path) -> str:
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
         "(Get-Acl -LiteralPath $env:XYRA_TEST_CIPHERTEXT).Sddl"],
        env={**os.environ, "XYRA_TEST_CIPHERTEXT": str(path)},
        capture_output=True, text=True, check=True,
    )
    return result.stdout.strip()


def _synthetic_target(root: Path) -> Path:
    target = root / ".local" / "secrets" / f"{SCOPE}--{ENV}--FRED_API_KEY.dpapi"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"synthetic-encrypted-old")
    return target


def _replace_bytes(target: Path, content: bytes) -> None:
    pending = target.with_name(f".{target.name}.synthetic-pending")
    pending.write_bytes(content)
    os.replace(pending, target)


@pytest.mark.parametrize("point", [
    "journal", "backup", "registry", "bindings", "secret", "applying",
])
def test_interrupted_preparation_recovers_without_orphan_snapshots(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, point: str,
) -> None:
    root, registry, bindings = _temp_factory(tmp_path)
    target = _synthetic_target(root)
    before = (registry.read_bytes(), bindings.read_bytes(), target.read_bytes())
    original_journal = transaction._atomic_journal
    original_link = transaction.os.link
    original_copy = transaction.shutil.copy2
    snapshot_links = 0

    def interrupted_journal(path: Path, document: dict[str, object], *,
                            create: bool = False) -> None:
        original_journal(path, document, create=create)
        if (point == "journal" and create) or (
            point == "applying" and document["phase"] == "applying"
        ):
            raise SystemExit("synthetic preparation interruption")

    def interrupted_link(source: Path, destination: Path) -> None:
        nonlocal snapshot_links
        original_link(source, destination)
        if str(destination).endswith(".snapshot"):
            snapshot_links += 1
            if point == ("registry", "bindings", "secret")[snapshot_links - 1]:
                raise SystemExit("synthetic snapshot interruption")

    def interrupted_copy(source: Path, destination: Path) -> Path:
        copied = original_copy(source, destination)
        if point == "backup":
            raise SystemExit("synthetic backup interruption")
        return copied

    monkeypatch.setattr(transaction, "_atomic_journal", interrupted_journal)
    monkeypatch.setattr(transaction.os, "link", interrupted_link)
    monkeypatch.setattr(transaction.shutil, "copy2", interrupted_copy)
    with transaction.import_lock(root) as backup_root:
        with pytest.raises(SystemExit, match="synthetic"):
            transaction.ImportTransaction.begin(root, bindings, backup_root,
                                                [("FRED_API_KEY", SCOPE, ENV)])
        assert len(list(backup_root.glob("tx-*.json"))) == 1
        monkeypatch.setattr(transaction, "_atomic_journal", original_journal)
        monkeypatch.setattr(transaction.os, "link", original_link)
        monkeypatch.setattr(transaction.shutil, "copy2", original_copy)
        transaction.recover_pending(root, bindings, backup_root)
        assert not list(backup_root.glob("tx-*.json"))
    assert (registry.read_bytes(), bindings.read_bytes(), target.read_bytes()) == before
    assert not list(root.rglob("*.snapshot"))


@pytest.mark.parametrize("position", [0, 1, 2])
def test_interrupted_restoration_retries_from_immutable_snapshots(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, position: int,
) -> None:
    root, registry, bindings = _temp_factory(tmp_path)
    target = _synthetic_target(root)
    before = (registry.read_bytes(), bindings.read_bytes(), target.read_bytes())
    with transaction.import_lock(root) as backup_root:
        transaction.ImportTransaction.begin(root, bindings, backup_root,
                                            [("FRED_API_KEY", SCOPE, ENV)])
        for path in (registry, bindings, target):
            _replace_bytes(path, b"synthetic-new")
        original_replace = transaction.os.replace
        restored = 0

        def interrupted_replace(source: Path, destination: Path) -> None:
            nonlocal restored
            original_replace(source, destination)
            if str(source).endswith(".restore"):
                restored += 1
                if restored == position + 1:
                    raise SystemExit("synthetic restoration interruption")

        monkeypatch.setattr(transaction.os, "replace", interrupted_replace)
        with pytest.raises(SystemExit, match="synthetic"):
            transaction.recover_pending(root, bindings, backup_root)
        assert len(list(backup_root.glob("tx-*.json"))) == 1
        monkeypatch.setattr(transaction.os, "replace", original_replace)
        transaction.recover_pending(root, bindings, backup_root)
        assert not list(backup_root.glob("tx-*.json"))
    assert (registry.read_bytes(), bindings.read_bytes(), target.read_bytes()) == before
    assert not list(root.rglob("*.snapshot"))


def test_interrupted_restore_link_is_recoverable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, registry, bindings = _temp_factory(tmp_path)
    target = _synthetic_target(root)
    before = (registry.read_bytes(), bindings.read_bytes(), target.read_bytes())
    with transaction.import_lock(root) as backup_root:
        transaction.ImportTransaction.begin(root, bindings, backup_root,
                                            [("FRED_API_KEY", SCOPE, ENV)])
        for path in (registry, bindings, target):
            _replace_bytes(path, b"synthetic-new")
        original_link = transaction.os.link

        def interrupted_link(source: Path, destination: Path) -> None:
            original_link(source, destination)
            if str(destination).endswith(".restore"):
                raise SystemExit("synthetic restore-link interruption")

        monkeypatch.setattr(transaction.os, "link", interrupted_link)
        with pytest.raises(SystemExit, match="synthetic"):
            transaction.recover_pending(root, bindings, backup_root)
        monkeypatch.setattr(transaction.os, "link", original_link)
        transaction.recover_pending(root, bindings, backup_root)
        assert not list(backup_root.glob("tx-*.json"))
    assert (registry.read_bytes(), bindings.read_bytes(), target.read_bytes()) == before
    assert not list(root.rglob("*.restore"))


def test_interrupted_new_ciphertext_removal_is_recoverable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, registry, bindings = _temp_factory(tmp_path)
    before = (registry.read_bytes(), bindings.read_bytes())
    with transaction.import_lock(root) as backup_root:
        transaction.ImportTransaction.begin(root, bindings, backup_root,
                                            [("FRED_API_KEY", SCOPE, ENV)])
        target = root / ".local" / "secrets" / f"{SCOPE}--{ENV}--FRED_API_KEY.dpapi"
        target.parent.mkdir(parents=True)
        target.write_bytes(b"synthetic-new")
        original_unlink = Path.unlink

        def interrupted_unlink(path: Path, *args: object, **kwargs: object) -> None:
            original_unlink(path, *args, **kwargs)  # type: ignore[arg-type]
            if path == target:
                raise SystemExit("synthetic new-ciphertext removal interruption")

        monkeypatch.setattr(Path, "unlink", interrupted_unlink)
        with pytest.raises(SystemExit, match="synthetic"):
            transaction.recover_pending(root, bindings, backup_root)
        monkeypatch.setattr(Path, "unlink", original_unlink)
        transaction.recover_pending(root, bindings, backup_root)
        assert not list(backup_root.glob("tx-*.json"))
    assert (registry.read_bytes(), bindings.read_bytes()) == before
    assert not target.exists()


@pytest.mark.parametrize("role", ["registry", "bindings"])
def test_impossible_journal_cannot_delete_protected_metadata(
    tmp_path: Path, role: str,
) -> None:
    root, registry, bindings = _temp_factory(tmp_path)
    before = (registry.read_bytes(), bindings.read_bytes())
    with transaction.import_lock(root) as backup_root:
        tx = transaction.ImportTransaction.begin(root, bindings, backup_root, [])
        document = json.loads(tx.path.read_text(encoding="utf-8"))
        item = next(item for item in document["items"] if item["role"] == role)
        item["existed"] = False
        item["original"] = None
        tx.path.write_text(json.dumps(document), encoding="utf-8")
        with pytest.raises(transaction.TransactionError, match=r"^IMPORT_RECOVERY_FAILED$"):
            transaction.recover_pending(root, bindings, backup_root)
        assert tx.path.is_file()
    assert (registry.read_bytes(), bindings.read_bytes()) == before


def test_missing_late_snapshot_cannot_delete_earlier_new_ciphertext(tmp_path: Path) -> None:
    root, registry, bindings = _temp_factory(tmp_path)
    before = (registry.read_bytes(), bindings.read_bytes())
    with transaction.import_lock(root) as backup_root:
        tx = transaction.ImportTransaction.begin(root, bindings, backup_root,
                                                 [("FRED_API_KEY", SCOPE, ENV)])
        target = root / ".local" / "secrets" / f"{SCOPE}--{ENV}--FRED_API_KEY.dpapi"
        target.parent.mkdir(parents=True)
        target.write_bytes(b"synthetic-new-ciphertext")
        registry_snapshot = transaction._snapshot_path(registry, tx.txid)
        registry_snapshot.unlink()
        with pytest.raises(transaction.TransactionError, match=r"^IMPORT_RECOVERY_FAILED$"):
            transaction.recover_pending(root, bindings, backup_root)
        assert tx.path.is_file()
    assert (registry.read_bytes(), bindings.read_bytes()) == before
    assert target.read_bytes() == b"synthetic-new-ciphertext"


@pytest.mark.parametrize("invalid", ["phase", "txid", "fingerprint", "duplicate"])
def test_invalid_journal_is_rejected_before_any_target_mutation(
    tmp_path: Path, invalid: str,
) -> None:
    root, registry, bindings = _temp_factory(tmp_path)
    target = _synthetic_target(root)
    before = (registry.read_bytes(), bindings.read_bytes(), target.read_bytes())
    with transaction.import_lock(root) as backup_root:
        tx = transaction.ImportTransaction.begin(root, bindings, backup_root,
                                                 [("FRED_API_KEY", SCOPE, ENV)])
        document = json.loads(tx.path.read_text(encoding="utf-8"))
        if invalid == "phase":
            document["phase"] = "unknown"
        elif invalid == "txid":
            document["txid"] = "b" * 32
        elif invalid == "fingerprint":
            document["items"][2]["original"]["sha256"] = "0" * 64
        else:
            document["items"].append(document["items"][2].copy())
        tx.path.write_text(json.dumps(document), encoding="utf-8")
        with pytest.raises(transaction.TransactionError, match=r"^IMPORT_RECOVERY_FAILED$"):
            transaction.recover_pending(root, bindings, backup_root)
        assert tx.path.is_file()
    assert (registry.read_bytes(), bindings.read_bytes(), target.read_bytes()) == before


@pytest.mark.parametrize("kind", ["journal", "snapshot"])
def test_preexisting_transaction_identity_collision_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str,
) -> None:
    root, registry, bindings = _temp_factory(tmp_path)
    before = (registry.read_bytes(), bindings.read_bytes())

    class FixedId:
        hex = "a" * 32

    monkeypatch.setattr(transaction.uuid, "uuid4", lambda: FixedId())
    with transaction.import_lock(root) as backup_root:
        collision = (backup_root / f"tx-{'a' * 32}.json" if kind == "journal" else
                     transaction._snapshot_path(registry, "a" * 32))
        collision.write_bytes(b"preserve-collision")
        with pytest.raises(transaction.TransactionError, match=r"^IMPORT_SNAPSHOT_FAILED$"):
            transaction.ImportTransaction.begin(root, bindings, backup_root, [])
        assert collision.read_bytes() == b"preserve-collision"
    assert (registry.read_bytes(), bindings.read_bytes()) == before


@pytest.mark.parametrize("phase", ["committed", "rolled_back"])
def test_terminal_phase_cleanup_retries_after_interruption(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, phase: str,
) -> None:
    root, registry, bindings = _temp_factory(tmp_path)
    target = _synthetic_target(root)
    before = (registry.read_bytes(), bindings.read_bytes(), target.read_bytes())
    with transaction.import_lock(root) as backup_root:
        tx = transaction.ImportTransaction.begin(root, bindings, backup_root,
                                                 [("FRED_API_KEY", SCOPE, ENV)])
        original_unlink = Path.unlink
        removed = 0

        def interrupted_unlink(path: Path, *args: object, **kwargs: object) -> None:
            nonlocal removed
            original_unlink(path, *args, **kwargs)  # type: ignore[arg-type]
            if str(path).endswith(".snapshot"):
                removed += 1
                if removed == 1:
                    raise SystemExit("synthetic cleanup interruption")

        monkeypatch.setattr(Path, "unlink", interrupted_unlink)
        with pytest.raises(SystemExit, match="synthetic"):
            if phase == "committed":
                tx.commit()
            else:
                tx.rollback()
        monkeypatch.setattr(Path, "unlink", original_unlink)
        assert json.loads(tx.path.read_text(encoding="utf-8"))["phase"] == phase
        transaction.recover_pending(root, bindings, backup_root)
        assert not list(backup_root.glob("tx-*.json"))
    assert (registry.read_bytes(), bindings.read_bytes(), target.read_bytes()) == before
    assert not list(root.rglob("*.snapshot"))


def test_later_broker_failure_rolls_back_whole_import(tmp_path: Path) -> None:
    root, registry, bindings = _temp_factory(tmp_path)
    before_registry, before_bindings = registry.read_bytes(), bindings.read_bytes()
    plan = import_keys.ImportPlan((
        import_keys.ParsedCredential("FRED", "FRED_API_KEY", ENV, OLD_VALUE),
        import_keys.ParsedCredential("DATABENTO", "DATABENTO_API_KEY", ENV, ""),
    ), (), (), ())
    with pytest.raises(import_keys.ImportErrorCode, match=r"^SECRET_WRITE_FAILED$"):
        import_keys.import_plan(root, plan, SCOPE, bindings=bindings)
    assert registry.read_bytes() == before_registry
    assert bindings.read_bytes() == before_bindings
    assert list((root / ".local" / "secrets").glob("*.dpapi")) == []


def test_readonly_bindings_preflight_never_calls_real_copied_broker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, registry, bindings = _temp_factory(tmp_path)
    before_registry, before_bindings = registry.read_bytes(), bindings.read_bytes()
    actual_broker = import_keys._broker_write
    calls = 0

    def counted_broker(*args: object) -> None:
        nonlocal calls
        calls += 1
        actual_broker(*args)  # type: ignore[arg-type]

    monkeypatch.setattr(import_keys, "_broker_write", counted_broker)
    bindings.chmod(stat.S_IREAD)
    try:
        plan = import_keys.ImportPlan((
            import_keys.ParsedCredential("FRED", "FRED_API_KEY", ENV, OLD_VALUE),
        ), (), (), ())
        dry = import_keys.import_plan(root, plan, SCOPE, bindings=bindings, dry_run=True)
        assert dry.dry_run and dry.imported == 0 and dry.would_import == 1
        assert not (root / ".local").exists()
        with pytest.raises(import_keys.ImportErrorCode, match=r"^IMPORT_BINDINGS_FAILED$"):
            import_keys.import_plan(root, plan, SCOPE, bindings=bindings)
        assert calls == 0
        assert (registry.read_bytes(), bindings.read_bytes()) == (
            before_registry, before_bindings
        )
        assert not list((root / ".local").rglob("*.dpapi"))
        assert not list((root / ".local").rglob("tx-*.json"))
        assert not list((root / ".local").rglob("*.snapshot"))
    finally:
        bindings.chmod(stat.S_IREAD | stat.S_IWRITE)


def test_parent_replace_denial_is_preflighted_without_broker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, registry, bindings = _temp_factory(tmp_path)
    before = (registry.read_bytes(), bindings.read_bytes())
    broker_calls: list[str] = []
    monkeypatch.setattr(import_keys, "_broker_write", lambda *args: broker_calls.append("call"))
    real_replace = os.replace

    def deny_binding_parent_probe(source: Path, destination: Path) -> None:
        if (Path(source).name.startswith(".xyra-replace-probe-")
                and Path(source).parent == bindings.parent):
            raise PermissionError("synthetic destination directory denial")
        real_replace(source, destination)

    monkeypatch.setattr(import_keys.os, "replace", deny_binding_parent_probe)
    plan = import_keys.ImportPlan((
        import_keys.ParsedCredential("FRED", "FRED_API_KEY", ENV, OLD_VALUE),
    ), (), (), ())
    with pytest.raises(import_keys.ImportErrorCode, match=r"^IMPORT_BINDINGS_FAILED$"):
        import_keys.import_plan(root, plan, SCOPE, bindings=bindings)
    assert not broker_calls
    assert (registry.read_bytes(), bindings.read_bytes()) == before
    assert not list((root / ".local").rglob("*.dpapi"))
    assert not list((root / ".local").rglob("tx-*.json"))
    assert not list(tmp_path.rglob(".xyra-replace-probe-*"))


def test_canonical_bindings_commit_with_real_broker(tmp_path: Path) -> None:
    root, registry, bindings = _temp_factory(tmp_path)
    document = json.loads(bindings.read_text(encoding="utf-8"))
    document["bindings"].extend([
        {"provider": "massive", "name": "MASSIVE_API_KEY", "scope": SCOPE,
         "environment": "development", "state": "pending_import"},
        {"provider": "kalshi", "name": "KALSHI_API_KEY", "scope": SCOPE,
         "environment": "live", "state": "pending_import"},
    ])
    bindings.write_text(json.dumps(document), encoding="utf-8")
    plan = import_keys.parse_key_text(
        f"POLYGON: synthetic data\nKEY: {OLD_VALUE}\n\n"
        f"KALSHI: synthetic authenticated\nHeader: {NEW_VALUE}\n"
    )
    result = import_keys.import_plan(root, plan, SCOPE, bindings=bindings)
    assert result.imported == 2 and not result.bindings_required
    entries = json.loads(registry.read_text(encoding="utf-8"))["entries"]
    assert {(item["name"], item["environment"]) for item in entries[1:]} == {
        ("MASSIVE_API_KEY", "development"), ("KALSHI_API_KEY", "live"),
    }
    assert all(item["validation"]["provider_authentication"] == "NOT_TESTED"
               for item in entries[1:])
    saved = json.loads(bindings.read_text(encoding="utf-8"))["bindings"]
    assert saved[0] == document["bindings"][0]
    assert [item["state"] for item in saved[1:]] == ["locally_stored", "locally_stored"]
    assert (XyraVault(root).get("MASSIVE_API_KEY", SCOPE, "development")
            .get_secret_value() == OLD_VALUE)
    assert XyraVault(root).get("KALSHI_API_KEY", SCOPE, "live").get_secret_value() == NEW_VALUE


def test_replace_snapshot_and_final_bindings_failure_restore_acl(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, registry, bindings = _temp_factory(tmp_path)
    old = import_keys.ParsedCredential("FRED", "FRED_API_KEY", ENV, OLD_VALUE)
    import_keys.import_plan(root, import_keys.ImportPlan((old,), (), (), ()),
                            SCOPE, bindings=bindings)
    target = root / ".local" / "secrets" / "leviathan-ai--development--FRED_API_KEY.dpapi"
    before_registry, before_bindings = registry.read_bytes(), bindings.read_bytes()
    old_ciphertext, old_acl = target.read_bytes(), _acl(target)
    registry_acl, bindings_acl = _acl(registry), _acl(bindings)
    snapshot = target.with_name("synthetic-old-hardlink.dpapi")
    os.link(target, snapshot)
    newer = import_keys.ParsedCredential("FRED", "FRED_API_KEY", ENV, NEW_VALUE)
    import_keys._broker_write(root, newer, SCOPE, True)
    assert snapshot.read_bytes() == old_ciphertext
    assert _acl(snapshot) == old_acl
    restore = target.with_name("synthetic-restore-hardlink.dpapi")
    os.link(snapshot, restore)
    os.replace(restore, target)
    assert os.path.samefile(snapshot, target)
    snapshot.unlink()
    original_atomic = import_keys._atomic_json

    def fail_final(path: Path, document: dict[str, object]) -> None:
        if path == bindings:
            raise OSError("synthetic bindings replace failure")
        original_atomic(path, document)

    monkeypatch.setattr(import_keys, "_atomic_json", fail_final)
    with pytest.raises(import_keys.ImportErrorCode, match=r"^IMPORT_BINDINGS_FAILED$"):
        import_keys.import_plan(root, import_keys.ImportPlan((newer,), (), (), ()),
                                SCOPE, bindings=bindings, replace=True)
    assert registry.read_bytes() == before_registry
    assert bindings.read_bytes() == before_bindings
    assert _acl(registry) == registry_acl
    assert _acl(bindings) == bindings_acl
    assert target.read_bytes() == old_ciphertext
    assert _acl(target) == old_acl
    assert XyraVault(root).get("FRED_API_KEY", SCOPE, ENV).get_secret_value() == OLD_VALUE


def test_registry_metadata_failure_after_broker_restores_all(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, registry, bindings = _temp_factory(tmp_path)
    before_registry, before_bindings = registry.read_bytes(), bindings.read_bytes()
    plan = import_keys.ImportPlan((
        import_keys.ParsedCredential("FRED", "FRED_API_KEY", ENV, OLD_VALUE),
    ), (), (), ())
    original_atomic = import_keys._atomic_json
    registry_writes = 0

    def fail_second_registry(path: Path, document: dict[str, object]) -> None:
        nonlocal registry_writes
        if path == registry:
            registry_writes += 1
            if registry_writes == 2:
                raise OSError("synthetic metadata failure")
        original_atomic(path, document)

    monkeypatch.setattr(import_keys, "_atomic_json", fail_second_registry)
    with pytest.raises(import_keys.ImportErrorCode, match=r"^IMPORT_REGISTRY_FAILED$"):
        import_keys.import_plan(root, plan, SCOPE, bindings=bindings)
    assert registry_writes == 2
    assert registry.read_bytes() == before_registry
    assert bindings.read_bytes() == before_bindings
    assert list((root / ".local" / "secrets").glob("*.dpapi")) == []


def test_snapshot_hardlink_failure_denies_before_broker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, registry, bindings = _temp_factory(tmp_path)
    before = registry.read_bytes()
    monkeypatch.setattr(transaction.os, "link", lambda *args: (_ for _ in ()).throw(OSError()))
    with pytest.raises(transaction.TransactionError, match=r"^IMPORT_SNAPSHOT_FAILED$"):
        import_keys.import_plan(root, import_keys.ImportPlan((
            import_keys.ParsedCredential("FRED", "FRED_API_KEY", ENV, OLD_VALUE),
        ), (), (), ()), SCOPE, bindings=bindings)
    assert registry.read_bytes() == before
    assert not (root / ".local" / "secrets").exists()


def test_import_lock_serializes_mutations(tmp_path: Path) -> None:
    root, registry, bindings = _temp_factory(tmp_path)
    before = registry.read_bytes()
    with transaction.import_lock(root), pytest.raises(
        transaction.TransactionError, match=r"^IMPORT_LOCKED$"
    ):
        import_keys.import_plan(root, import_keys.ImportPlan((
            import_keys.ParsedCredential("FRED", "FRED_API_KEY", ENV, OLD_VALUE),
        ), (), (), ()), SCOPE, bindings=bindings)
    assert registry.read_bytes() == before


def test_failed_rollback_leaves_journal_then_recovers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, registry, bindings = _temp_factory(tmp_path)
    before_registry, before_bindings = registry.read_bytes(), bindings.read_bytes()
    original_atomic = import_keys._atomic_json
    original_rollback = transaction.ImportTransaction.rollback

    def fail_final(path: Path, document: dict[str, object]) -> None:
        if path == bindings:
            raise OSError("synthetic bindings failure")
        original_atomic(path, document)

    monkeypatch.setattr(import_keys, "_atomic_json", fail_final)
    monkeypatch.setattr(transaction.ImportTransaction, "rollback", lambda self: (
        (_ for _ in ()).throw(transaction.TransactionError("IMPORT_RECOVERY_FAILED"))
    ))
    plan = import_keys.ImportPlan((
        import_keys.ParsedCredential("FRED", "FRED_API_KEY", ENV, OLD_VALUE),
    ), (), (), ())
    with pytest.raises(import_keys.ImportErrorCode, match=r"^IMPORT_RECOVERY_FAILED$"):
        import_keys.import_plan(root, plan, SCOPE, bindings=bindings)
    journals = list((root / ".local" / "registry-backups").glob("tx-*.json"))
    assert len(journals) == 1
    assert json.loads(journals[0].read_text(encoding="utf-8"))["phase"] == "applying"
    monkeypatch.setattr(transaction.ImportTransaction, "rollback", original_rollback)
    monkeypatch.setattr(import_keys, "_atomic_json", original_atomic)
    import_keys.import_plan(root, import_keys.ImportPlan((), (), (), ()), SCOPE,
                            bindings=bindings)
    assert registry.read_bytes() == before_registry
    assert bindings.read_bytes() == before_bindings
    assert list((root / ".local" / "secrets").glob("*.dpapi")) == []
    assert not list((root / ".local" / "registry-backups").glob("tx-*.json"))


def test_recovery_rejects_out_of_root_journal_item(tmp_path: Path) -> None:
    root, registry, bindings = _temp_factory(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("preserve", encoding="utf-8")
    with transaction.import_lock(root) as backup:
        tx = transaction.ImportTransaction.begin(root, bindings, backup,
                                                 [("FRED_API_KEY", SCOPE, ENV)])
        document = json.loads(tx.path.read_text(encoding="utf-8"))
        document["items"][2]["name"] = "../../outside.txt"
        tx.path.write_text(json.dumps(document), encoding="utf-8")
        with pytest.raises(transaction.TransactionError, match=r"^IMPORT_RECOVERY_FAILED$"):
            transaction.recover_pending(root, bindings, backup)
    assert outside.read_text(encoding="utf-8") == "preserve"
    assert registry.is_file() and tx.path.is_file()
