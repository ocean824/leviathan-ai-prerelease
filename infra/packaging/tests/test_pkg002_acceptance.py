from __future__ import annotations

import hashlib
import os
import socket
import subprocess
import sys
import urllib.request
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from infra.packaging.clean_build.manifest import (
    BUILDER_ENVIRONMENT_ALLOWLIST,
    LOCK_PATHS,
    CleanBuildManifestV1,
    FileHashV1,
    ManifestError,
    build_provenance_from_json,
    build_provenance_to_json,
    compare_build_manifests,
    create_build_provenance,
    create_manifest,
    create_source_snapshot_manifest,
    hash_inventory,
    manifest_from_json,
    manifest_to_json,
)
from infra.packaging.clean_build.verify import (
    VerificationError,
    verify_manifest,
    verify_source_snapshot,
)

SOURCE_PATHS = ("src/app.py", *LOCK_PATHS)
INPUT_PATHS = LOCK_PATHS
OUTPUT_PATHS = ("fixture-installer.bin", "provenance.json", "sbom.json")
VCS_HEAD = "a" * 40
TOOLCHAIN_VERSIONS = (("cargo", "1.synthetic"), ("node", "1.synthetic"), ("python", "3.synthetic"))
BUILD_COMMANDS = ("cargo build --locked --offline", "npm run build --offline")
NORMALIZED_TIMESTAMPS = (("source_date_epoch", "1700000000"), ("timezone", "UTC"))
BUILDER_ENVIRONMENT = (("CI", "true"), ("OS", "Windows_NT"), ("SOURCE_DATE_EPOCH", "1700000000"))


def make_roots(base: Path) -> tuple[Path, Path, Path]:
    source_root = base / "source"
    input_root = base / "inputs"
    output_root = base / "outputs"
    (source_root / "src").mkdir(parents=True)
    input_root.mkdir()
    output_root.mkdir()
    (source_root / "src" / "app.py").write_bytes(b"print('synthetic fixture')\n")
    lock_contents = {
        LOCK_PATHS[0]: b"cargo-lock-fixture\n",
        LOCK_PATHS[1]: b'{"lockfileVersion":3}\n',
        LOCK_PATHS[2]: b"uv-lock-fixture\n",
    }
    for relative_path, contents in lock_contents.items():
        for root in (source_root, input_root):
            lock_path = root / relative_path
            lock_path.parent.mkdir(parents=True, exist_ok=True)
            lock_path.write_bytes(contents)
    # Opaque data only. It has no executable behavior and is never launched.
    (output_root / "fixture-installer.bin").write_bytes(b"MZ\x00synthetic-inert-installer-bytes")
    (output_root / "sbom.json").write_bytes(b'{"bomFormat":"CycloneDX","fixture":true}\n')
    return source_root, input_root, output_root


def create_fixture_manifest(
    roots: tuple[Path, Path, Path],
    *,
    source_paths: tuple[str, ...] | None = None,
    input_paths: tuple[str, ...] = INPUT_PATHS,
    output_paths: tuple[str, ...] = OUTPUT_PATHS,
) -> CleanBuildManifestV1:
    source_root, input_root, output_root = roots
    snapshot = create_source_snapshot_manifest(source_root)
    provenance = create_build_provenance(
        snapshot,
        toolchain_versions=TOOLCHAIN_VERSIONS,
        build_commands=BUILD_COMMANDS,
        normalized_timestamps=NORMALIZED_TIMESTAMPS,
        builder_environment=BUILDER_ENVIRONMENT,
    )
    (output_root / "provenance.json").write_bytes(build_provenance_to_json(provenance))
    return create_manifest(
        source_root,
        input_root,
        output_root,
        source_snapshot=snapshot,
        vcs_head=VCS_HEAD,
        source_paths=tuple(sorted(source_paths)) if source_paths is not None else None,
        input_paths=input_paths,
        output_paths=output_paths,
        artifact_path="fixture-installer.bin",
        sbom_path="sbom.json",
    )


def verify_fixture(
    manifest: CleanBuildManifestV1,
    roots: tuple[Path, Path, Path],
    *,
    forbidden_sha256: tuple[str, ...] = (),
):
    return verify_manifest(
        manifest,
        roots[0],
        roots[1],
        roots[2],
        forbidden_sha256=forbidden_sha256,
    )


def test_manifest_bytes_are_deterministic_across_roots_order_and_mtime(tmp_path: Path) -> None:
    first_roots = make_roots(tmp_path / "checkout-one")
    second_roots = make_roots(tmp_path / "checkout-two")
    for root in second_roots:
        for path in root.rglob("*"):
            if path.is_file():
                os.utime(path, (1_700_000_001, 1_700_000_001))

    first = create_fixture_manifest(first_roots)
    second = create_fixture_manifest(
        second_roots,
        source_paths=tuple(reversed(SOURCE_PATHS)),
        input_paths=tuple(reversed(INPUT_PATHS)),
        output_paths=tuple(reversed(OUTPUT_PATHS)),
    )
    first_bytes = manifest_to_json(first)
    second_bytes = manifest_to_json(second)

    assert first_bytes == second_bytes
    assert first.manifest_sha256 == second.manifest_sha256
    assert tuple(row.path for row in first.source_files) == tuple(sorted(SOURCE_PATHS))
    assert tuple(row.path for row in first.input_files) == tuple(sorted(INPUT_PATHS))
    assert tuple(row.path for row in first.output_files) == tuple(sorted(OUTPUT_PATHS))
    assert str(tmp_path).encode("utf-8") not in first_bytes
    assert first.vcs_head == VCS_HEAD
    first_snapshot = create_source_snapshot_manifest(first_roots[0])
    assert first.source_snapshot_manifest_sha256 == first_snapshot.manifest_sha256
    assert first.source_snapshot_manifest_sha256 != first.vcs_head


def test_manifest_json_round_trip_is_canonical_and_self_digesting(tmp_path: Path) -> None:
    manifest = create_fixture_manifest(make_roots(tmp_path))
    encoded = manifest_to_json(manifest)
    restored = manifest_from_json(encoded)

    assert restored == manifest
    assert manifest_to_json(restored) == encoded
    assert restored.manifest_sha256 == manifest.manifest_sha256
    assert len(restored.manifest_sha256) == 64
    assert restored.manifest_sha256 == restored.manifest_sha256.lower()
    with pytest.raises(ManifestError):
        manifest_from_json(encoded + b" ")


def test_verification_checks_hashes_and_sizes_without_running_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    roots = make_roots(tmp_path)

    def forbidden_execution(*_args: object, **_kwargs: object) -> None:
        pytest.fail("verification attempted process execution")

    monkeypatch.setattr(subprocess, "run", forbidden_execution)
    monkeypatch.setattr(subprocess, "Popen", forbidden_execution)
    monkeypatch.setattr(os, "system", forbidden_execution)
    monkeypatch.setattr(os, "startfile", forbidden_execution, raising=False)
    monkeypatch.setattr(socket, "socket", forbidden_execution)
    monkeypatch.setattr(socket, "create_connection", forbidden_execution)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden_execution)
    monkeypatch.setattr(socket, "gethostbyname", forbidden_execution)
    monkeypatch.setattr(urllib.request, "urlopen", forbidden_execution)

    manifest = create_fixture_manifest(roots)
    report = verify_fixture(manifest, roots)

    assert report.verified is True
    assert report.checked_files == len(SOURCE_PATHS) + len(INPUT_PATHS) + len(OUTPUT_PATHS)
    assert report.manifest_sha256 == manifest.manifest_sha256
    assert len(report.source_inventory_sha256) == 64
    assert report.source_inventory_sha256 == report.source_inventory_sha256.lower()


def test_source_snapshot_rejects_dirty_and_untracked_tree_changes(tmp_path: Path) -> None:
    changed_roots = make_roots(tmp_path / "changed")
    changed_snapshot = create_source_snapshot_manifest(changed_roots[0])
    (changed_roots[0] / "src" / "app.py").write_bytes(b"modified after snapshot\n")
    with pytest.raises(VerificationError):
        verify_source_snapshot(changed_snapshot, changed_roots[0])

    extra_roots = make_roots(tmp_path / "extra")
    extra_snapshot = create_source_snapshot_manifest(extra_roots[0])
    (extra_roots[0] / "src" / "untracked-extra.txt").write_text(
        "synthetic extra file\n", encoding="utf-8"
    )
    with pytest.raises(VerificationError):
        verify_source_snapshot(extra_snapshot, extra_roots[0])


def test_source_snapshot_uses_its_declared_generated_file_exclusions(tmp_path: Path) -> None:
    roots = make_roots(tmp_path)
    snapshot = create_source_snapshot_manifest(roots[0])
    ignored = roots[0] / "node_modules" / "synthetic-cache.dat"
    ignored.parent.mkdir()
    ignored.write_bytes(b"excluded synthetic cache data")
    generated = roots[0] / "src" / "__pycache__" / "generated.pyc"
    generated.parent.mkdir()
    generated.write_bytes(b"excluded synthetic bytecode")

    assert verify_source_snapshot(snapshot, roots[0]) is True


def test_source_snapshot_rejects_nested_git_metadata(tmp_path: Path) -> None:
    source = make_roots(tmp_path)[0]
    nested_git = source / "vendor" / ".git"
    nested_git.mkdir(parents=True)
    with pytest.raises(ManifestError):
        create_source_snapshot_manifest(source)


def test_source_and_input_text_scanner_rejects_synthetic_credential_content_without_echo(
    tmp_path: Path,
) -> None:
    canary = "sk_test_SyntheticAcceptanceOnly42"
    source_roots = make_roots(tmp_path / "source-canary")
    source_canary = source_roots[0] / "src" / "credential.fixture"
    source_canary.write_text(f"credential={canary}\n", encoding="utf-8")
    with pytest.raises(ManifestError) as source_error:
        create_source_snapshot_manifest(source_roots[0])
    assert "src/credential.fixture" in str(source_error.value)
    assert canary not in str(source_error.value)

    input_roots = make_roots(tmp_path / "input-canary")
    input_canary = input_roots[1] / "credential.fixture"
    input_canary.write_text(f"credential={canary}\n", encoding="utf-8")
    with pytest.raises(ManifestError) as input_error:
        hash_inventory(input_roots[1], (*INPUT_PATHS, "credential.fixture"))
    assert "credential.fixture" in str(input_error.value)
    assert canary not in str(input_error.value)


@pytest.mark.parametrize(
    ("encoding", "codec"),
    [
        ("utf16le", "utf-16-le"),
        ("utf16be", "utf-16-be"),
        ("utf8bom", "utf-8-sig"),
        ("utf32", "utf-32"),
        ("utf32le", "utf-32-le"),
        ("utf32be", "utf-32-be"),
    ],
)
def test_snapshot_scans_unicode_text_encodings_for_synthetic_credentials(
    tmp_path: Path,
    encoding: str,
    codec: str,
) -> None:
    roots = make_roots(tmp_path)
    canary = "sk_test_UnicodeEncodingAcceptanceCanary42"
    relative = f"src/credential-{encoding}.txt"
    (roots[0] / relative).write_bytes(canary.encode(codec))

    with pytest.raises(ManifestError) as raised:
        create_source_snapshot_manifest(roots[0])
    assert relative in str(raised.value)
    assert canary not in str(raised.value)


def test_snapshot_rejects_undecodable_file_outside_binary_allowlist(tmp_path: Path) -> None:
    source = make_roots(tmp_path)[0]
    payload = b"\xff\x00\x81\xfe\x7f"
    relative = "src/unclassified.dat"
    (source / relative).write_bytes(payload)

    with pytest.raises(ManifestError) as raised:
        create_source_snapshot_manifest(source)
    assert relative in str(raised.value)
    assert payload.hex() not in str(raised.value)


@pytest.mark.parametrize(
    ("filename", "payload"),
    [
        ("synthetic.ico", b"\x00\x00\x01\x00\x00\x00synthetic inert ICO fixture"),
        ("synthetic.png", b"\x89PNG\r\n\x1a\n\x00synthetic inert PNG fixture"),
    ],
)
def test_allowlisted_binary_is_hashed_and_still_checked_against_forbidden_digest(
    tmp_path: Path,
    filename: str,
    payload: bytes,
) -> None:
    roots = make_roots(tmp_path)
    relative = f"src/{filename}"
    (roots[0] / relative).write_bytes(payload)
    snapshot = create_source_snapshot_manifest(roots[0])
    assert relative in {row.path for row in snapshot.files}

    manifest = create_fixture_manifest(roots)
    assert verify_fixture(manifest, roots).verified is True
    with pytest.raises(VerificationError):
        verify_fixture(
            manifest,
            roots,
            forbidden_sha256=(hashlib.sha256(payload).hexdigest(),),
        )


def test_provenance_binds_complete_snapshot_locks_commands_and_safe_builder_metadata(
    tmp_path: Path,
) -> None:
    roots = make_roots(tmp_path)
    manifest = create_fixture_manifest(roots)
    provenance_path = roots[2] / manifest.provenance_path
    encoded = provenance_path.read_bytes()
    provenance = build_provenance_from_json(encoded)

    assert build_provenance_to_json(provenance) == encoded
    assert manifest.provenance_sha256 == hashlib.sha256(encoded).hexdigest()
    assert provenance.source_snapshot_manifest_sha256 == manifest.source_snapshot_manifest_sha256
    assert tuple(row.path for row in provenance.lock_files) == LOCK_PATHS
    assert {name for name, _ in provenance.toolchain_versions} == {"cargo", "node", "python"}
    assert provenance.build_commands == BUILD_COMMANDS
    assert dict(provenance.normalized_timestamps) == dict(NORMALIZED_TIMESTAMPS)
    assert dict(provenance.builder_environment) == dict(BUILDER_ENVIRONMENT)
    assert set(dict(provenance.builder_environment)) <= BUILDER_ENVIRONMENT_ALLOWLIST


def test_provenance_rejects_unallowlisted_environment_and_credential_values(
    tmp_path: Path,
) -> None:
    snapshot = create_source_snapshot_manifest(make_roots(tmp_path)[0])
    with pytest.raises(ManifestError):
        create_build_provenance(
            snapshot,
            toolchain_versions=TOOLCHAIN_VERSIONS,
            build_commands=BUILD_COMMANDS,
            normalized_timestamps=NORMALIZED_TIMESTAMPS,
            builder_environment=(("UNAPPROVED_FIELD", "synthetic"),),
        )
    with pytest.raises(ManifestError):
        create_build_provenance(
            snapshot,
            toolchain_versions=TOOLCHAIN_VERSIONS,
            build_commands=BUILD_COMMANDS,
            normalized_timestamps=NORMALIZED_TIMESTAMPS,
            builder_environment=(("CI", "token=sk_test_SyntheticAcceptanceOnly42"),),
        )


def test_wrong_artifact_or_sbom_digest_and_changed_sbom_are_denied(tmp_path: Path) -> None:
    roots = make_roots(tmp_path)
    manifest = create_fixture_manifest(roots)
    with pytest.raises(ManifestError):
        replace(manifest, artifact_sha256="0" * 64)
    with pytest.raises(ManifestError):
        replace(manifest, sbom_sha256="0" * 64)
    try:
        wrong_provenance_ref = replace(
            manifest, provenance_sha256="0" * 64, manifest_sha256=""
        )
    except ManifestError:
        pass
    else:
        wrong_provenance_ref = manifest_from_json(
            manifest_to_json(wrong_provenance_ref)
        )
        with pytest.raises(VerificationError):
            verify_fixture(wrong_provenance_ref, roots)

    (roots[2] / manifest.sbom_path).write_bytes(b'{"bomFormat":"CycloneDX","components":[]}\n')
    with pytest.raises(VerificationError):
        verify_fixture(manifest, roots)


def test_two_build_comparison_ignores_mtimes_and_flags_changed_artifact(tmp_path: Path) -> None:
    first_roots = make_roots(tmp_path / "build-one")
    second_roots = make_roots(tmp_path / "build-two")
    for root in second_roots:
        for path in root.rglob("*"):
            if path.is_file():
                os.utime(path, (1_700_000_999, 1_700_000_999))
    first = create_fixture_manifest(first_roots)
    same_build = create_fixture_manifest(second_roots)
    normalized = compare_build_manifests(first, same_build)
    assert normalized.equivalent is True
    assert normalized.differences == ()
    assert normalized.filesystem_timestamps_ignored is True

    (second_roots[2] / "fixture-installer.bin").write_bytes(b"different synthetic inert bytes")
    changed_build = create_fixture_manifest(second_roots)
    comparison = compare_build_manifests(first, changed_build)
    assert comparison.equivalent is False
    assert any(
        difference.path == "fixture-installer.bin"
        for difference in comparison.differences
    )


@pytest.mark.parametrize(
    ("root_index", "relative_path", "replacement"),
    [
        (0, "src/app.py", b"X" + b"print('synthetic fixture')\n"[1:]),
        (0, "src/app.py", b"print('synthetic fixture')\nextra"),
        (1, "uv.lock", b"X" + b"uv-lock-fixture\n"[1:]),
        (1, "uv.lock", b"uv-lock-fixture\nextra"),
        (2, "sbom.json", b"X" + b'{"bomFormat":"CycloneDX","fixture":true}\n'[1:]),
        (2, "sbom.json", b'{"bomFormat":"CycloneDX","fixture":true}\nextra'),
        (2, "provenance.json", b'{"fixture":"tampered provenance"}\n'),
    ],
)
def test_tampered_source_input_or_output_bytes_are_denied(
    tmp_path: Path,
    root_index: int,
    relative_path: str,
    replacement: bytes,
) -> None:
    roots = make_roots(tmp_path)
    manifest = create_fixture_manifest(roots)
    (roots[root_index] / relative_path).write_bytes(replacement)

    with pytest.raises(VerificationError):
        verify_fixture(manifest, roots)


def test_declared_synthetic_secret_digest_is_rejected_without_echo(tmp_path: Path) -> None:
    roots = make_roots(tmp_path)
    canary_file = roots[0] / "src" / "opaque-canary.dat"
    canary_bytes = b"opaque synthetic canary bytes"
    canary_file.write_bytes(canary_bytes)
    paths = (*SOURCE_PATHS, "src/opaque-canary.dat")
    manifest = create_fixture_manifest(roots, source_paths=paths)
    canary_digest = hashlib.sha256(canary_bytes).hexdigest()

    with pytest.raises(VerificationError) as raised:
        verify_fixture(manifest, roots, forbidden_sha256=(canary_digest,))

    assert canary_bytes.decode("ascii") not in str(raised.value)
    assert canary_digest not in str(raised.value)
    assert raised.value.args == (str(raised.value),)


def test_tampered_manifest_digest_is_rejected_by_serializer_parser_and_verifier(
    tmp_path: Path,
) -> None:
    roots = make_roots(tmp_path)
    manifest = create_fixture_manifest(roots)
    tampered = replace(manifest, manifest_sha256="0" * 64)

    with pytest.raises(ManifestError):
        manifest_to_json(tampered)
    with pytest.raises(VerificationError):
        verify_fixture(tampered, roots)
    encoded = manifest_to_json(manifest)
    bad_digest_bytes = encoded.replace(manifest.manifest_sha256.encode("ascii"), b"0" * 64, 1)
    with pytest.raises(ManifestError):
        manifest_from_json(bad_digest_bytes)


@pytest.mark.parametrize("missing_mode", ["omitted", "absent"])
def test_all_three_pinned_lockfiles_are_required(
    tmp_path: Path,
    missing_mode: str,
) -> None:
    roots = make_roots(tmp_path)
    if missing_mode == "absent":
        (roots[1] / "uv.lock").unlink()
        paths = INPUT_PATHS
    else:
        paths = tuple(path for path in INPUT_PATHS if path != "uv.lock")

    with pytest.raises(ManifestError):
        create_fixture_manifest(roots, input_paths=paths)


@pytest.mark.parametrize(
    "unsafe_path",
    ["../outside", "/absolute/file", "C:/drive/file", "src\\app.py", "src//file"],
)
def test_inventory_rejects_nonportable_or_escaping_paths(
    tmp_path: Path,
    unsafe_path: str,
) -> None:
    roots = make_roots(tmp_path)

    with pytest.raises(ManifestError):
        hash_inventory(roots[0], (unsafe_path,))


def test_manifest_rejects_duplicate_unsorted_and_invalid_file_rows(tmp_path: Path) -> None:
    roots = make_roots(tmp_path)
    (roots[0] / "src" / "z_extra.py").write_bytes(b"synthetic extra source\n")
    manifest = create_fixture_manifest(
        roots,
        source_paths=(*SOURCE_PATHS, "src/z_extra.py"),
    )
    with pytest.raises(ManifestError):
        replace(manifest, source_files=tuple(reversed(manifest.source_files)))
    with pytest.raises(ManifestError):
        hash_inventory(tmp_path, ("duplicate", "duplicate"))
    with pytest.raises(ManifestError):
        FileHashV1(path="file.bin", sha256="0" * 64, size_bytes=True)  # type: ignore[arg-type]

    with pytest.raises(ManifestError):
        create_manifest(
            roots[0],
            roots[1],
            roots[2],
            source_commit="A" * 40,
            source_paths=SOURCE_PATHS,
            input_paths=INPUT_PATHS,
            output_paths=OUTPUT_PATHS,
        )


def test_verifier_rejects_missing_or_changed_declared_file(tmp_path: Path) -> None:
    roots = make_roots(tmp_path)
    manifest = create_fixture_manifest(roots)
    (roots[0] / "src" / "app.py").unlink()

    with pytest.raises(VerificationError):
        verify_fixture(manifest, roots)


def test_only_top_level_source_git_directory_is_exempt(tmp_path: Path) -> None:
    roots = make_roots(tmp_path)
    manifest = create_fixture_manifest(roots)
    git_dir = roots[0] / ".git"
    git_dir.mkdir()
    (git_dir / "unlisted-metadata").write_bytes(b"synthetic git metadata")

    assert verify_fixture(manifest, roots).verified is True


@pytest.mark.parametrize("root_index", [1, 2])
@pytest.mark.parametrize("git_shape", ["file", "directory"])
def test_git_file_or_non_source_git_payload_is_not_exempt(
    tmp_path: Path,
    root_index: int,
    git_shape: str,
) -> None:
    roots = make_roots(tmp_path)
    manifest = create_fixture_manifest(roots)
    git_path = roots[root_index] / ".git"
    if git_shape == "file":
        git_path.write_bytes(b"synthetic git pointer")
    else:
        git_path.mkdir()
        (git_path / "payload.bin").write_bytes(b"unlisted inert payload")

    with pytest.raises(VerificationError):
        verify_fixture(manifest, roots)


def test_non_ascii_inventory_path_raises_content_free_manifest_error(tmp_path: Path) -> None:
    roots = make_roots(tmp_path)
    with pytest.raises(ManifestError) as raised:
        hash_inventory(roots[0], ("src/caf\u00e9.py",))

    assert "caf\u00e9" not in str(raised.value)
    assert raised.value.args == (str(raised.value),)


@pytest.mark.parametrize(
    "payload",
    [
        b"[" * 5000 + b"]" * 5000,
        None,
    ],
    ids=["deep-recursion", "integer-value-limit"],
)
def test_manifest_parser_converts_recursion_and_integer_limits_to_manifest_error(
    tmp_path: Path,
    payload: bytes | None,
) -> None:
    if payload is None:
        manifest = create_fixture_manifest(make_roots(tmp_path))
        payload = manifest_to_json(manifest)
        marker = b'"size_bytes":'
        offset = payload.index(marker) + len(marker)
        end = offset
        while payload[end : end + 1].isdigit():
            end += 1
        payload = payload[:offset] + b"9" * 5000 + payload[end:]

    with pytest.raises(ManifestError) as raised:
        manifest_from_json(payload)
    assert raised.value.args == (str(raised.value),)


def test_exact_lock_rows_are_nonempty_and_identical_in_source_and_input(
    tmp_path: Path,
) -> None:
    manifest = create_fixture_manifest(make_roots(tmp_path))
    source_rows = {row.path: row for row in manifest.source_files}
    input_rows = {row.path: row for row in manifest.input_files}

    assert tuple(path for path in LOCK_PATHS if path in source_rows) == LOCK_PATHS
    for path in LOCK_PATHS:
        source_row = source_rows[path]
        input_row = input_rows[path]
        assert source_row == input_row
        assert source_row.size_bytes > 0


@pytest.mark.parametrize("lock_path", LOCK_PATHS)
def test_empty_pinned_lockfiles_are_rejected_in_source_and_input(
    tmp_path: Path,
    lock_path: str,
) -> None:
    roots = make_roots(tmp_path)
    for root_index in (0, 1):
        (roots[root_index] / lock_path).write_bytes(b"")

    with pytest.raises(ManifestError):
        create_fixture_manifest(roots)


@pytest.mark.parametrize("lock_path", LOCK_PATHS)
def test_nested_lockfile_paths_do_not_satisfy_repository_lock_requirement(
    tmp_path: Path,
    lock_path: str,
) -> None:
    roots = make_roots(tmp_path)
    nested_path = f"nested/{Path(lock_path).name}"
    for root_index in (0, 1):
        original = roots[root_index] / lock_path
        moved = roots[root_index] / nested_path
        moved.parent.mkdir(parents=True, exist_ok=True)
        original.replace(moved)
    source_paths = (*(path for path in SOURCE_PATHS if path != lock_path), nested_path)
    input_paths = (*(path for path in INPUT_PATHS if path != lock_path), nested_path)

    with pytest.raises(ManifestError):
        create_fixture_manifest(roots, source_paths=source_paths, input_paths=input_paths)


def test_casefold_duplicate_inventory_paths_are_rejected(tmp_path: Path) -> None:
    manifest = create_fixture_manifest(make_roots(tmp_path))
    app_row = next(row for row in manifest.source_files if row.path == "src/app.py")
    alias = FileHashV1(path="SRC/APP.PY", sha256=app_row.sha256, size_bytes=app_row.size_bytes)

    with pytest.raises(ManifestError):
        replace(
            manifest,
            source_files=tuple(sorted((*manifest.source_files, alias), key=lambda row: row.path)),
        )


def test_verifier_rejects_reparse_point_or_junction_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    roots = make_roots(tmp_path)
    manifest = create_fixture_manifest(roots)
    junction = roots[2] / "junction"
    junction.mkdir()
    original_lstat = Path.lstat

    def lstat_with_reparse_flag(path: Path):
        metadata = original_lstat(path)
        if path == junction:
            return SimpleNamespace(
                st_mode=metadata.st_mode,
                st_file_attributes=0x400,
            )
        return metadata

    monkeypatch.setattr(Path, "lstat", lstat_with_reparse_flag)
    with pytest.raises(VerificationError) as raised:
        verify_fixture(manifest, roots)
    assert "junction" not in str(raised.value)
    assert raised.value.args == (str(raised.value),)
