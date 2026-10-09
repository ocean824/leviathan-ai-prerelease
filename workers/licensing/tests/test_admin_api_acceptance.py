"""Independent black-box acceptance for the licensing admin Worker routes."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parents[1]
FIXTURE_DIR = Path(__file__).parent / "fixtures" / "admin_api"
PROBE_TEMPLATE = FIXTURE_DIR / "admin_api_probe.template.ts"
GENERATED_PROBE = FIXTURE_DIR / "admin_api_acceptance.generated.test.ts"
EXPECTED_VITEST_CASES = 19


def test_lic_admin_api_public_worker_acceptance() -> None:
    """Run the owned synthetic probe through the package's pinned local Vitest."""
    node = shutil.which("node")
    assert node is not None, "Node is required to run the pinned Worker acceptance probe"
    vitest_cli = PACKAGE_DIR / "node_modules" / "vitest" / "vitest.mjs"
    assert vitest_cli.is_file(), "Pinned local Vitest is not installed in the licensing package"
    assert PROBE_TEMPLATE.is_file()
    assert not GENERATED_PROBE.exists(), "A prior generated probe was left behind"

    probe = PROBE_TEMPLATE.read_text(encoding="utf-8")
    GENERATED_PROBE.write_text(probe, encoding="utf-8", newline="\n")
    try:
        relative_probe = GENERATED_PROBE.relative_to(PACKAGE_DIR).as_posix()
        result = subprocess.run(
            [node, "node_modules/vitest/vitest.mjs", "run", relative_probe, "--reporter=verbose"],
            cwd=PACKAGE_DIR,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=180,
            check=False,
        )
    finally:
        GENERATED_PROBE.unlink(missing_ok=True)

    output = f"{result.stdout}\n{result.stderr}"
    assert result.returncode == 0, output
    summary = re.search(r"Tests\s+(\d+) passed(?:\s+\((\d+)\))?", output)
    assert summary is not None, output
    passed = int(summary.group(1))
    total = int(summary.group(2) or summary.group(1))
    assert (passed, total) == (EXPECTED_VITEST_CASES, EXPECTED_VITEST_CASES), output
