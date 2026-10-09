"""Independent CHAT-003 terminal acceptance orchestration and static guardrails."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
TERMINAL_ROOT = REPO_ROOT / "apps" / "terminal"
VITEST_RELATIVE_PATH = "src/chat/test/chat.acceptance.test.tsx"
EXPECTED_VITEST_CASES = 20


def test_pinned_serial_vitest_acceptance_passes() -> None:
    package = json.loads((TERMINAL_ROOT / "package.json").read_text(encoding="utf-8"))
    assert package["devDependencies"]["vitest"] == "^5.0.3"
    assert (TERMINAL_ROOT / VITEST_RELATIVE_PATH).is_file()
    assert shutil.which("npm.cmd") is not None, (
        "npm.cmd must be installed for the pinned terminal run"
    )
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
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=180,
    )
    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    assert re.search(r"\bRUN\s+v5\.0\.3\b", output), output
    match = re.search(r"Tests\s+(\d+)\s+passed\s+\(\1\)", output)
    assert match is not None, output
    assert int(match.group(1)) == EXPECTED_VITEST_CASES, output


def test_chat_presentation_uses_semantic_theme_tokens_and_no_browser_storage() -> None:
    presentation = (
        TERMINAL_ROOT / "src" / "chat" / "ChatTerminal.tsx",
        TERMINAL_ROOT / "src" / "chat" / "ChatTranscript.tsx",
        TERMINAL_ROOT / "src" / "chat" / "ChatToolCard.tsx",
        TERMINAL_ROOT / "src" / "chat" / "ChatTerminal.css",
    )
    color_literal = re.compile(
        r"(?<![A-Za-z0-9_-])#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})(?![0-9a-fA-F])"
    )
    violations: list[str] = []
    for path in presentation:
        source = path.read_text(encoding="utf-8")
        for line_number, line in enumerate(source.splitlines(), start=1):
            if color_literal.search(line):
                violations.append(
                    f"{path.relative_to(REPO_ROOT).as_posix()}:{line_number}:raw color literal"
                )
            if re.search(r"\b(?:localStorage|sessionStorage)\b", line):
                violations.append(
                    f"{path.relative_to(REPO_ROOT).as_posix()}:{line_number}:browser storage use"
                )
    assert not violations, "CHAT-003 presentation guard failures:\n" + "\n".join(violations)
    css = (TERMINAL_ROOT / "src" / "chat" / "ChatTerminal.css").read_text(encoding="utf-8")
    assert "var(--theme-" in css
    # The chat view uses no motion declarations; the reduced-motion preference is
    # therefore respected without adding animation behavior.
    assert not re.search(r"\b(?:animation|transition)\s*:", css)
