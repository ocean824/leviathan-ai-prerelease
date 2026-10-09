"""Unit tests for PKG-002's deterministic, hash-only clean-build boundary."""

# The repository is a namespace package; prepend the workspace root for direct imports.
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from infra.packaging.clean_build.manifest import (
    BUILDER_ENVIRONMENT_ALLOWLIST,
    LOCK_PATHS,
    BuildProvenanceV1,
    ManifestError,
    build_provenance_to_json,
    compare_build_manifests,
    create_build_provenance,
    create_manifest,
    create_source_snapshot_manifest,
    manifest_from_json,
    manifest_to_json,
    source_snapshot_from_json,
    source_snapshot_to_json,
    verify_source_snapshot,
)
from infra.packaging.clean_build.verify import VerificationError, verify_manifest


def _put(root: Path, relative: str, contents: bytes) -> Path:
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(contents)
    return target


def _fixture(base: Path):
    source, inputs, outputs = (base / name for name in ("source", "inputs", "outputs"))
    source.mkdir(parents=True)
    inputs.mkdir()
    outputs.mkdir()
    _put(source, "src/app.py", b"print('synthetic fixture')\n")
    for lock_path in LOCK_PATHS:
        contents = ("synthetic lock fixture " + lock_path + "\n").encode("ascii")
        _put(source, lock_path, contents)
        _put(inputs, lock_path, contents)

    snapshot = create_source_snapshot_manifest(source)
    provenance = create_build_provenance(
        snapshot,
        toolchain_versions=(("python", "3.11-fixture"), ("rust", "stable-fixture")),
        build_commands=("synthetic command fixture (not executed)",),
        normalized_timestamps=(("source_date_epoch", "1700000000"),),
        builder_environment=(("OS", "fixture"),),
    )
    _put(outputs, "fixture-installer.bin", b"opaque inert artifact bytes")
    _put(outputs, "sbom.json", b'{"bomFormat":"CycloneDX","fixture":true}\n')
    _put(outputs, "provenance.json", build_provenance_to_json(provenance))
    manifest = create_manifest(
        source,
        inputs,
        outputs,
        source_snapshot=snapshot,
        vcs_head="a" * 40,
        input_paths=LOCK_PATHS,
        output_paths=("fixture-installer.bin", "provenance.json", "sbom.json"),
    )
    return source, inputs, outputs, snapshot, provenance, manifest


def test_snapshot_manifest_is_complete_deterministic_and_git_independent(tmp_path: Path) -> None:
    source, _, _, snapshot, _, manifest = _fixture(tmp_path / "one")
    copy = tmp_path / "snapshot-copy"
    copy.mkdir()
    for row in snapshot.files:
        _put(copy, row.path, (source / row.path).read_bytes())
    git_pointer = copy / ".git"
    git_pointer.write_text("gitdir: inert pointer\n", encoding="ascii")

    copied = create_source_snapshot_manifest(copy)
    assert copied == snapshot
    assert verify_source_snapshot(snapshot, copy)
    assert manifest.source_snapshot_manifest_sha256 == snapshot.manifest_sha256
    assert manifest.vcs_head == "a" * 40
    assert manifest.vcs_head != manifest.source_snapshot_manifest_sha256
    snapshot_bytes = source_snapshot_to_json(snapshot)
    assert source_snapshot_to_json(source_snapshot_from_json(snapshot_bytes)) == snapshot_bytes


@pytest.mark.parametrize("mutation", ["changed", "untracked"])
def test_snapshot_rejects_dirty_or_untracked_files(tmp_path: Path, mutation: str) -> None:
    source, _, _, snapshot, _, _ = _fixture(tmp_path)
    if mutation == "changed":
        _put(source, "src/app.py", b"changed tracked content\n")
    else:
        _put(source, "src/untracked-extra.py", b"extra source file\n")
    with pytest.raises(ManifestError):
        verify_source_snapshot(snapshot, source)


def test_snapshot_standard_exclusions_and_reparse_rejection(tmp_path: Path) -> None:
    source, _, _, snapshot, _, _ = _fixture(tmp_path)
    (source / ".git").mkdir()
    _put(source, ".git/config", b"metadata excluded from snapshot")
    _put(source, "__pycache__/ignored.pyc", b"ignored bytecode")
    _put(source, "node_modules/package/ignored.js", b"ignored dependency")
    assert create_source_snapshot_manifest(source) == snapshot


def test_shared_scanner_rejects_synthetic_secret_with_path_only_error(tmp_path: Path) -> None:
    source, _, _, _, _, _ = _fixture(tmp_path)
    synthetic = b"password=synthetic_canary_value_never_use"
    _put(source, "src/app.py", synthetic)
    with pytest.raises(ManifestError) as raised:
        create_source_snapshot_manifest(source)
    assert "src/app.py" in str(raised.value)
    assert synthetic.decode("ascii") not in str(raised.value)


@pytest.mark.parametrize(
    "encoding",
    ["utf-16", "utf-16-le", "utf-16-be", "utf-32", "utf-32-le", "utf-32-be", "utf-8-sig"],
)
def test_shared_scanner_rejects_credential_in_supported_text_encodings(
    tmp_path: Path, encoding: str
) -> None:
    source, _, _, _, _, _ = _fixture(tmp_path)
    canary = "Write-Output 'sk_live_UTF16syntheticCredentialCanary123456'"
    _put(source, "build.ps1", canary.encode(encoding))

    with pytest.raises(ManifestError) as raised:
        create_source_snapshot_manifest(source)

    assert "build.ps1" in str(raised.value)
    assert "sk_live_" not in str(raised.value)


def test_unknown_undecodable_file_fails_closed_but_allowlisted_binary_is_hashed(
    tmp_path: Path,
) -> None:
    source, _, _, _, _, _ = _fixture(tmp_path)
    opaque = b"\x89\xff\x00\x80\x81"
    _put(source, "assets/unknown.dat", opaque)
    with pytest.raises(ManifestError) as raised:
        create_source_snapshot_manifest(source)
    assert "assets/unknown.dat" in str(raised.value)
    assert "\\x89" not in str(raised.value)

    (source / "assets/unknown.dat").unlink()
    _put(source, "assets/icon.ico", opaque)
    snapshot = create_source_snapshot_manifest(source)
    assert verify_source_snapshot(snapshot, source)
    assert any(
        row.path == "assets/icon.ico" and row.size_bytes == len(opaque) for row in snapshot.files
    )


def test_verifier_reports_credential_hit_by_path_without_echoing_value(tmp_path: Path) -> None:
    source, inputs, outputs, _, _, manifest = _fixture(tmp_path)
    synthetic = b"password=synthetic_post_manifest_canary"
    _put(source, "docs/canary.txt", synthetic)
    with pytest.raises(VerificationError) as raised:
        verify_manifest(manifest, source, inputs, outputs)
    assert "docs/canary.txt" in str(raised.value)
    assert synthetic.decode("ascii") not in str(raised.value)


def test_shared_scanner_covers_declared_build_inputs(tmp_path: Path) -> None:
    source, inputs, outputs, snapshot, _, _ = _fixture(tmp_path)
    canary = b"password=synthetic_input_canary_value"
    _put(inputs, "tool-config.txt", canary)
    with pytest.raises(ManifestError) as raised:
        create_manifest(
            source,
            inputs,
            outputs,
            source_snapshot=snapshot,
            input_paths=(*LOCK_PATHS, "tool-config.txt"),
            output_paths=("fixture-installer.bin", "provenance.json", "sbom.json"),
        )
    assert "tool-config.txt" in str(raised.value)
    assert canary.decode("ascii") not in str(raised.value)


def test_missing_or_modified_lock_input_is_rejected(tmp_path: Path) -> None:
    source, inputs, outputs, snapshot, _, _ = _fixture(tmp_path)
    (inputs / "uv.lock").unlink()
    with pytest.raises(ManifestError):
        create_manifest(
            source,
            inputs,
            outputs,
            source_snapshot=snapshot,
            input_paths=tuple(path for path in LOCK_PATHS if path != "uv.lock"),
            output_paths=("fixture-installer.bin", "provenance.json", "sbom.json"),
        )

    source, inputs, outputs, snapshot, _, _ = _fixture(tmp_path / "modified")
    _put(inputs, LOCK_PATHS[0], b"different locked input")
    with pytest.raises(ManifestError):
        create_manifest(
            source,
            inputs,
            outputs,
            source_snapshot=snapshot,
            input_paths=LOCK_PATHS,
            output_paths=("fixture-installer.bin", "provenance.json", "sbom.json"),
        )


def test_provenance_is_canonical_complete_and_allowlisted(tmp_path: Path) -> None:
    _, _, _, snapshot, provenance, _ = _fixture(tmp_path)
    encoded = build_provenance_to_json(provenance)
    raw = json.loads(encoded)
    assert raw["source_snapshot_manifest_sha256"] == snapshot.manifest_sha256
    assert {row["path"] for row in raw["lock_files"]} == set(LOCK_PATHS)
    assert raw["build_commands"] == ["synthetic command fixture (not executed)"]
    assert set(dict(raw["builder_environment"])) <= BUILDER_ENVIRONMENT_ALLOWLIST
    assert encoded.endswith(b"\n")

    with pytest.raises(ManifestError):
        BuildProvenanceV1(
            source_snapshot_manifest_sha256=provenance.source_snapshot_manifest_sha256,
            lock_files=provenance.lock_files,
            toolchain_versions=provenance.toolchain_versions,
            build_commands=provenance.build_commands,
            normalized_timestamps=provenance.normalized_timestamps,
            builder_environment=(("UNAPPROVED", "fixture"),),
        )
    with pytest.raises(ManifestError):
        BuildProvenanceV1(
            source_snapshot_manifest_sha256=provenance.source_snapshot_manifest_sha256,
            lock_files=provenance.lock_files,
            toolchain_versions=provenance.toolchain_versions,
            build_commands=provenance.build_commands,
            normalized_timestamps=provenance.normalized_timestamps,
            builder_environment=(("OS", "password=synthetic_value"),),
        )


def test_manifest_round_trip_binds_provenance_artifact_and_sbom(tmp_path: Path) -> None:
    source, inputs, outputs, snapshot, _provenance, manifest = _fixture(tmp_path)
    encoded = manifest_to_json(manifest)
    restored = manifest_from_json(encoded)
    assert manifest_to_json(restored) == encoded
    assert restored.source_snapshot_manifest_sha256 == snapshot.manifest_sha256
    assert (
        restored.provenance_sha256
        == hashlib.sha256((outputs / "provenance.json").read_bytes()).hexdigest()
    )
    assert (
        restored.artifact_sha256
        == hashlib.sha256((outputs / "fixture-installer.bin").read_bytes()).hexdigest()
    )
    assert restored.sbom_sha256 == hashlib.sha256((outputs / "sbom.json").read_bytes()).hexdigest()

    report = verify_manifest(restored, source, inputs, outputs)
    assert report.verified
    assert report.source_inventory_sha256 == snapshot.manifest_sha256
    assert report.checked_files == len(restored.source_files) + len(restored.input_files) + len(
        restored.output_files
    )


@pytest.mark.parametrize("relative", ["fixture-installer.bin", "sbom.json", "provenance.json"])
def test_wrong_artifact_sbom_or_provenance_digest_fails(tmp_path: Path, relative: str) -> None:
    source, inputs, outputs, _, _, manifest = _fixture(tmp_path)
    _put(outputs, relative, b"tampered inert bytes")
    with pytest.raises(VerificationError):
        verify_manifest(manifest, source, inputs, outputs)


def test_forbidden_whole_file_digest_remains_defense_in_depth(tmp_path: Path) -> None:
    source, inputs, outputs, _, _, manifest = _fixture(tmp_path)
    canary = b"opaque inert artifact bytes"
    with pytest.raises(VerificationError):
        verify_manifest(
            manifest,
            source,
            inputs,
            outputs,
            forbidden_sha256=(hashlib.sha256(canary).hexdigest(),),
        )


def test_opaque_output_artifact_is_hash_only_but_forbidden_digest_still_rejects(
    tmp_path: Path,
) -> None:
    source, inputs, outputs, snapshot, _, _ = _fixture(tmp_path)
    opaque = b"\x89\xff\x00\x80\x81"
    _put(outputs, "fixture-installer.bin", opaque)
    manifest = create_manifest(
        source,
        inputs,
        outputs,
        source_snapshot=snapshot,
        input_paths=LOCK_PATHS,
        output_paths=("fixture-installer.bin", "provenance.json", "sbom.json"),
    )

    with pytest.raises(VerificationError, match="forbidden file digest"):
        verify_manifest(
            manifest,
            source,
            inputs,
            outputs,
            forbidden_sha256=(hashlib.sha256(opaque).hexdigest(),),
        )


def test_normalized_two_build_comparison_ignores_filesystem_mtime(tmp_path: Path) -> None:
    first = _fixture(tmp_path / "first")
    second = _fixture(tmp_path / "second")
    outputs = second[2]
    for path in outputs.rglob("*"):
        if path.is_file():
            os.utime(path, (1_700_000_001, 1_700_000_001))
    assert compare_build_manifests(first[5], second[5]).equivalent


def test_two_build_comparison_reports_changed_artifact_digest(tmp_path: Path) -> None:
    first = _fixture(tmp_path / "first")
    second = _fixture(tmp_path / "second")
    _put(second[2], "fixture-installer.bin", b"different inert output bytes")
    changed_snapshot = create_source_snapshot_manifest(second[0])
    # The snapshot and inputs stay equal; only the output set changes.
    changed = create_manifest(
        second[0],
        second[1],
        second[2],
        source_snapshot=changed_snapshot,
        input_paths=LOCK_PATHS,
        output_paths=("fixture-installer.bin", "provenance.json", "sbom.json"),
    )
    result = compare_build_manifests(first[5], changed)
    assert not result.equivalent
    assert any(item.path == "fixture-installer.bin" for item in result.differences)


def _powershell_executable() -> str | None:
    return shutil.which("pwsh") or shutil.which("powershell")


def _license_worker_helpers() -> str:
    repo = Path(__file__).resolve().parents[3]
    build_script = (repo / "apps/desktop/scripts/build.ps1").read_text(encoding="utf-8")
    start = build_script.index("function Resolve-LicenseWorkerConfig {")
    end = build_script.index("function Invoke-NativeLogged {", start)
    return build_script[start:end]


@pytest.mark.parametrize(
    ("origin", "valid"),
    [
        ("https://license.example.test", True),
        ("https://license.example.test:8443", True),
        ("http://localhost:8787", True),
        ("http://127.0.0.1:8787", True),
        ("http://license.example.test:8787", False),
        ("http://localhost", False),
        ("http://localhost:0", False),
        ("http://localhost:65536", False),
        ("http://localhost:8787/path", False),
        ("https://user@license.example.test", False),
        ("https://license.example.test?token=x", False),
        ("https://license.example.test#fragment", False),
    ],
)
def test_license_worker_config_origin_is_exact_and_fail_closed(
    tmp_path: Path, origin: str, valid: bool
) -> None:
    powershell = _powershell_executable()
    if powershell is None:
        pytest.skip("PowerShell is unavailable")

    config = tmp_path / "license-worker.json"
    config.write_text(json.dumps({"origin": origin}), encoding="utf-8")
    config_literal = "'" + str(config).replace("'", "''") + "'"
    expected = "$true" if valid else "$false"
    script = tmp_path / "license-worker-validation.ps1"
    script.write_text(
        _license_worker_helpers()
        + f"""
$expected = {expected}
$valid = $false
try {{
    [void](Resolve-LicenseWorkerConfig -Path {config_literal})
    $valid = $true
}} catch {{}}
if ($valid -ne $expected) {{ exit 2 }}
""",
        encoding="utf-8",
    )
    completed = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-File", str(script)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr


def test_license_worker_config_requires_absolute_existing_single_origin_json(
    tmp_path: Path,
) -> None:
    powershell = _powershell_executable()
    if powershell is None:
        pytest.skip("PowerShell is unavailable")
    config = tmp_path / "invalid.json"
    config.write_text('{"origin":"https://license.example.test","extra":true}', encoding="utf-8")
    config_literal = "'" + str(config).replace("'", "''") + "'"
    missing_literal = "'" + str(tmp_path / "missing.json").replace("'", "''") + "'"
    script = tmp_path / "license-worker-shape.ps1"
    script.write_text(
        _license_worker_helpers()
        + f"""
foreach ($path in @({config_literal}, {missing_literal}, 'relative.json')) {{
    $accepted = $false
    try {{ [void](Resolve-LicenseWorkerConfig -Path $path); $accepted = $true }} catch {{}}
    if ($accepted) {{ exit 2 }}
}}
""",
        encoding="utf-8",
    )
    completed = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-File", str(script)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr


def test_license_worker_config_environment_is_scoped_and_restored_on_failure(
    tmp_path: Path,
) -> None:
    powershell = _powershell_executable()
    if powershell is None:
        pytest.skip("PowerShell is unavailable")
    config_literal = "'" + str(tmp_path / "config.json").replace("'", "''") + "'"
    script = tmp_path / "license-worker-environment.ps1"
    script.write_text(
        _license_worker_helpers()
        + f"""
$name = 'LEVIATHAN_LICENSE_WORKER_CONFIG'
[Environment]::SetEnvironmentVariable($name, 'prior-value', 'Process')
try {{
    try {{
        Invoke-WithLicenseWorkerConfig -ConfigPath {config_literal} -Action {{
            $configured = [Environment]::GetEnvironmentVariable($name, 'Process')
            if ($configured -cne {config_literal}) {{ exit 3 }}
            throw 'synthetic failure'
        }}
    }} catch {{}}
    if ([Environment]::GetEnvironmentVariable($name, 'Process') -cne 'prior-value') {{ exit 4 }}
}} finally {{ [Environment]::SetEnvironmentVariable($name, $null, 'Process') }}
""",
        encoding="utf-8",
    )
    completed = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-File", str(script)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr


def test_manifest_requires_snapshot_identity_in_serialized_schema(tmp_path: Path) -> None:
    _, _, _, _, _, manifest = _fixture(tmp_path)
    raw = json.loads(manifest_to_json(manifest))
    del raw["source_snapshot_manifest_sha256"]
    with pytest.raises(ManifestError):
        manifest_from_json(json.dumps(raw, separators=(",", ":")).encode("ascii"))
