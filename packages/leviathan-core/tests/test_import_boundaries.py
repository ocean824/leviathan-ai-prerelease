"""Architectural boundary tests.

Risk is sovereign: leviathan_core.risk may not import from the modules
it governs. Core may not import I/O frameworks. These tests make the
boundaries executable instead of aspirational.
"""

import ast
import sys
from pathlib import Path

CORE_SRC = Path(__file__).resolve().parents[1] / "src" / "leviathan_core"

FORBIDDEN_IN_RISK = (
    "leviathan_core.execution",
    "leviathan_core.decision",
    "leviathan_core.ingress",
)
FORBIDDEN_IN_CORE = ("fastapi", "uvicorn", "sqlalchemy", "redis", "httpx", "requests")


def _imports_of(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.append(node.module)
    return found


def test_risk_module_imports_nothing_it_governs() -> None:
    for py in (CORE_SRC / "risk").rglob("*.py"):
        for mod in _imports_of(py):
            for forbidden in FORBIDDEN_IN_RISK:
                assert not mod.startswith(forbidden), (
                    f"{py.name} imports {mod} — risk must not depend on what it governs"
                )


def test_core_package_is_free_of_io_frameworks() -> None:
    for py in CORE_SRC.rglob("*.py"):
        for mod in _imports_of(py):
            root = mod.split(".")[0]
            assert root not in FORBIDDEN_IN_CORE, (
                f"{py} imports {mod} — I/O frameworks belong in apps/, not core"
            )


def test_core_imports_cleanly() -> None:
    import leviathan_core
    import leviathan_core.contracts
    import leviathan_core.schemas

    assert leviathan_core.__version__
    assert "leviathan_core.schemas" in sys.modules
