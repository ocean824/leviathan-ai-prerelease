from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import c2_harness as C  # noqa: E402


@pytest.fixture(scope="session")
def collector(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Cycle-2 production build (the writer's own build script) in scratch; the frozen tree is never written."""
    return C.build(tmp_path_factory.mktemp("c2-build"))


@pytest.fixture
def prod_real(collector: Path, tmp_path: Path) -> Path:
    return C.make_variant(collector, f"real-{tmp_path.name}", vendor="real", challenge="real")


@pytest.fixture
def prod_realfc(collector: Path, tmp_path: Path) -> Path:
    return C.make_variant(collector, f"realfc-{tmp_path.name}", vendor="real", challenge="fake")


@pytest.fixture
def prod_mixed(collector: Path, tmp_path: Path) -> Path:
    """Real vendored call/classify/http; addOperation fed from a recorded capture (no Chrome); fake challenge window."""
    return C.make_variant(collector, f"mixed-{tmp_path.name}", vendor="mixed", challenge="fake")


@pytest.fixture
def prod_stub(collector: Path, tmp_path: Path) -> Path:
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
