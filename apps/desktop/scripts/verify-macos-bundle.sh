#!/usr/bin/env bash
set -euo pipefail
python_cmd="${PYTHON:-python3}"

if [[ "${1:-}" == "--self-test" && $# -eq 1 ]]; then
  "$python_cmd" - "$0" <<'PY'
from __future__ import annotations

import importlib.util
import pathlib
import subprocess
import sys

# Exercise the exact fixture parser and all-slice validator without requiring
# Mach-O tools or a macOS host. The later slice is deliberately incompatible.
source = pathlib.Path(sys.argv[1]).resolve()
text = source.read_text(encoding="utf-8")
module_source = ("import pathlib\nminimum = (11, 0)\ndef parse_deployment_versions(" + text.split("\ndef parse_deployment_versions(", 1)[1].split("\n\npaths: set[pathlib.Path] = {sidecar}", 1)[0])
namespace: dict[str, object] = {"__name__": "verifier_fixture", "minimum": (11, 0)}
exec(compile(module_source, str(source), "exec"), namespace)
parse_versions = namespace["parse_deployment_versions"]
validate_slices = namespace["validate_slices"]
first = """Load command 0\n      cmd LC_BUILD_VERSION\n  cmdsize 32\n platform MACOS\n    minos 11.0\n      sdk 15.0\n"""
second = """Load command 0\n      cmd LC_VERSION_MIN_MACOSX\n  cmdsize 16\n  version 12.0\n      sdk 15.0\n"""
records = {
    "x86_64": parse_versions(first),
    "arm64": parse_versions(second),
}
try:
    validate_slices(["x86_64", "arm64"], records, pathlib.Path("fixture-fat-binary"))
except RuntimeError as exc:
    assert "Minimum macOS 12.0 exceeds 11.0" in str(exc), str(exc)
else:
    raise AssertionError("bad deployment target in second slice was accepted")
try:
    validate_slices(
        ["x86_64", "arm64"],
        {"x86_64": [(11, 0)], "arm64": [(11, 0)]},
        pathlib.Path("fixture-fat-binary"),
    )
except RuntimeError as exc:
    assert "Unexpected non-x86_64 slice" in str(exc), str(exc)
else:
    raise AssertionError("non-x86_64 slice was accepted")
print("Verifier fixtures passed: bad second-slice minos and non-x86_64 slice are rejected.")
PY
  exit 0
fi

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <app-bundle> <target-triple> | --self-test" >&2
  exit 2
fi

app="$1"
triple="$2"
[[ -d "$app/Contents" ]] || { echo "App bundle is missing: $app" >&2; exit 1; }
[[ "$triple" == "x86_64-apple-darwin" ]] || {
  echo "This verifier currently accepts the x86_64 Darwin build only" >&2
  exit 2
}
sidecar_name="leviathan-desktop-$triple"
sidecar="$app/Contents/Resources/sidecar/$sidecar_name"
[[ -x "$sidecar" ]] || { echo "Bundled sidecar is missing or not executable: $sidecar" >&2; exit 1; }
[[ -d "$app/Contents/Resources/sidecar/_internal" ]] || {
  echo "PyInstaller sidecar support directory is missing" >&2
  exit 1
}

"$python_cmd" - "$app/Contents" "$sidecar" <<'PY'
from __future__ import annotations

import pathlib
import subprocess
import sys

root = pathlib.Path(sys.argv[1])
sidecar = pathlib.Path(sys.argv[2])
minimum = (11, 0)


def run(*args: str) -> str:
    return subprocess.run(args, check=True, text=True, capture_output=True).stdout


def parse_deployment_versions(loads: str) -> list[tuple[int, ...]]:
    """Extract every deployment record from one architecture's otool output."""
    records: list[tuple[int, ...]] = []
    active_field: str | None = None
    for line in loads.splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[0] == "cmd":
            active_field = {
                "LC_BUILD_VERSION": "minos",
                "LC_VERSION_MIN_MACOSX": "version",
            }.get(fields[1])
        elif active_field is not None and fields and fields[0] == active_field:
            records.append(tuple(int(part) for part in fields[1].split(".")[:2]))
            active_field = None
        elif fields and fields[0] == "Load" and len(fields) > 1 and fields[1] == "command":
            active_field = None
    return records


def validate_slices(
    architectures: list[str],
    records_by_arch: dict[str, list[tuple[int, ...]]],
    path: pathlib.Path,
) -> list[tuple[str, tuple[int, ...]]]:
    if not architectures:
        raise RuntimeError(f"No architecture slices reported for {path}")
    versions: list[tuple[str, tuple[int, ...]]] = []
    missing: list[str] = []
    for architecture in architectures:
        records = records_by_arch.get(architecture, [])
        if not records:
            missing.append(architecture)
            continue
        versions.extend((architecture, version) for version in records)
    for architecture, version in versions:
        if version > minimum:
            raise RuntimeError(
                f"Minimum macOS {'.'.join(map(str, version))} exceeds 11.0 "
                f"in {architecture} slice: {path}"
            )
    if missing:
        raise RuntimeError(f"No macOS deployment target found in {missing} slice(s): {path}")
    unexpected = [architecture for architecture in architectures if architecture != "x86_64"]
    if unexpected:
        raise RuntimeError(f"Unexpected non-x86_64 slice(s) {unexpected}: {path}")
    return versions


paths: set[pathlib.Path] = {sidecar}
main_binaries = [path for path in (root / "MacOS").iterdir() if path.is_file()]
if not main_binaries:
    raise RuntimeError("The app's Contents/MacOS directory contains no executable")
paths.update(main_binaries)
for path in root.rglob("*"):
    if not path.is_file():
        continue
    description = run("file", "-b", str(path))
    if "Mach-O" in description:
        paths.add(path)
    elif path.suffix in {".so", ".dylib"}:
        raise RuntimeError(f"Bundled native extension is not Mach-O: {path}")

if not paths:
    raise RuntimeError("No Mach-O binaries were found in the app bundle")
for path in sorted(paths):
    description = run("file", "-b", str(path))
    if "Mach-O" not in description:
        raise RuntimeError(f"Expected a Mach-O binary: {path}")
    architectures = run("lipo", "-archs", str(path)).split()
    records_by_arch = {
        architecture: parse_deployment_versions(
            run("otool", "-arch", architecture, "-l", str(path))
        )
        for architecture in architectures
    }
    versions = validate_slices(architectures, records_by_arch, path)
    minimums = ", ".join(
        architecture + "=" + ".".join(map(str, version))
        for architecture, version in versions
    )
    print(
        f"OK {path.relative_to(root)}: {description}; slices {architectures}; "
        f"minos {minimums}"
    )
PY