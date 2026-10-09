# Build from the repository root with: uv run --with pyinstaller pyinstaller --noconfirm this.spec
from pathlib import Path
from importlib.util import find_spec

from PyInstaller.utils.hooks import collect_submodules

repo = Path.cwd()
desktop = repo / "apps" / "desktop" / "sidecar"
terminal = repo / "apps" / "terminal" / "dist"
lock = repo / "infra" / "risk" / "risk_governance.lock.yaml"
keyring_imports = collect_submodules("keyring.backends") if find_spec("keyring") else []

a = Analysis(
    [str(desktop / "leviathan_desktop.py")],
    pathex=[str(desktop), str(desktop / "generated")],
    binaries=[],
    datas=[(str(terminal), "web"), (str(lock), "risk")],
    hiddenimports=collect_submodules("uvicorn")
    + keyring_imports
    + ["sqlalchemy.dialects.sqlite.aiosqlite", "aiosqlite"],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "pytest", "mypy", "ruff"],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, [], exclude_binaries=True, name="leviathan-desktop", console=True)
coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=False, name="leviathan-desktop")
