from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import c1_harness as C  # noqa: E402


@pytest.fixture
def prod_real(collector: Path, tmp_path: Path) -> Path:
    """Production wrapper + REAL vendored runtime + real challenge.js; fresh PINNED copy per test."""
    return C.make_variant(collector, f"real-{tmp_path.name}", vendor="real", challenge="real")


@pytest.fixture
def prod_realfc(collector: Path, tmp_path: Path) -> Path:
    """Production wrapper + real vendor, fake challenge window (so no Chrome is ever launched)."""
    return C.make_variant(collector, f"realfc-{tmp_path.name}", vendor="real", challenge="fake")


@pytest.fixture
def prod_stub(collector: Path, tmp_path: Path) -> Path:
    """Production wrapper + scripted vendor + fake challenge window."""
    return C.make_variant(collector, f"stub-{tmp_path.name}", vendor="stub", challenge="fake")


@pytest.fixture
def app_data(tmp_path: Path) -> Path:
    d = tmp_path / "appdata"
    d.mkdir()
    return d


@pytest.fixture
def sidecar1():
    made: list[C.Sidecar1] = []

    def make(variant: Path, data_dir: Path, **kw):
        sc = C.Sidecar1(variant, data_dir, **kw)
        made.append(sc)
        return sc

    yield make
    for sc in made:
        sc.close()
