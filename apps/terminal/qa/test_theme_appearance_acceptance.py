"""Independent THEME-001 acceptance orchestration and reference checks."""

from __future__ import annotations

import json
import math
import os
import re
import shutil
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
TERMINAL_ROOT = REPO_ROOT / "apps" / "terminal"
VITEST_RELATIVE_PATH = "src/settings/test/appearance.acceptance.test.tsx"
FIXTURE_PATH = TERMINAL_ROOT / "qa" / "fixtures" / "THEME-001" / "wcag-contrast-reference.json"
EXPECTED_VITEST_CASES = 8


def _linear_channel(channel: int) -> float:
    srgb = channel / 255
    return srgb / 12.92 if srgb <= 0.04045 else ((srgb + 0.055) / 1.055) ** 2.4


def _relative_luminance(color: str) -> float:
    if not re.fullmatch(r"#[0-9a-fA-F]{6}", color):
        raise ValueError("reference color must be six-digit hex")
    rgb = [int(color[index : index + 2], 16) for index in (1, 3, 5)]
    channels = [_linear_channel(value) for value in rgb]
    return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2]


def _contrast_ratio(foreground: str, background: str) -> float:
    first, second = _relative_luminance(foreground), _relative_luminance(background)
    light, dark = max(first, second), min(first, second)
    return (light + 0.05) / (dark + 0.05)


def test_hand_computed_wcag_reference_pairs() -> None:
    cases = json.loads(FIXTURE_PATH.read_text(encoding="utf-8-sig"))
    for case in cases:
        measured = _contrast_ratio(case["foreground"], case["background"])
        assert math.isclose(measured, case["expected_ratio"], rel_tol=0, abs_tol=1e-12)
    assert _contrast_ratio("#777777", "#ffffff") < 4.5
    assert _contrast_ratio("#767676", "#ffffff") >= 4.5
    assert _contrast_ratio("#ffffff", "#ffffff") == 1


def test_vitest_acceptance_spec_passes_with_pinned_serial_cli() -> None:
    package = json.loads((TERMINAL_ROOT / "package.json").read_text(encoding="utf-8"))
    assert package["devDependencies"]["vitest"] == "^5.0.3"
    npm_cmd = shutil.which("npm.cmd")
    assert npm_cmd is not None, "npm.cmd must be installed for the pinned terminal test run"
    # Windows cannot launch .cmd files directly with CreateProcess. Let cmd.exe
    # resolve npm.cmd from the inherited PATH.
    command = [
        os.environ.get("COMSPEC", "cmd.exe"),
        "/d",
        "/s",
        "/c",
        f"npm.cmd test -- --run --pool=forks --maxWorkers=1 "
        f"--no-file-parallelism {VITEST_RELATIVE_PATH}",
    ]
    result = subprocess.run(
        command,
        cwd=TERMINAL_ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    assert re.search(r"\bRUN\s+v5\.0\.3\b", output), output
    match = re.search(r"Tests\s+(\d+)\s+passed\s+\(\1\)", output)
    assert match is not None, output
    assert int(match.group(1)) == EXPECTED_VITEST_CASES, output


def test_theme_presentation_files_use_css_tokens_not_color_literals() -> None:
    """Keep rendered THEME presentation token-driven; presets live in CSS."""
    color_literal = re.compile(
        r"(?<![A-Za-z0-9_-])#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})(?![0-9a-fA-F])"
    )
    files = (
        TERMINAL_ROOT / "src" / "settings" / "AppearanceSettings.tsx",
        TERMINAL_ROOT / "src" / "settings" / "AppearanceSettings.css",
        TERMINAL_ROOT / "src" / "views" / "design" / "contrast.ts",
    )
    violations = [
        f"{path.relative_to(REPO_ROOT).as_posix()}:{line_number}:{line.strip()}"
        for path in files
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1)
        if color_literal.search(line)
    ]
    assert not violations, "raw color literals in THEME presentation files:\n" + "\n".join(
        violations
    )
