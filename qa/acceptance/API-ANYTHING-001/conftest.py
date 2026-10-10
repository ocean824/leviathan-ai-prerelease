from __future__ import annotations

import importlib.util
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import aa_harness as H  # noqa: E402

# Import the code under test from the FROZEN worktree, not from any editable install elsewhere.
sys.path.insert(0, str(H.WORKTREE / "packages" / "leviathan-market-data" / "src"))
import leviathan_market_data  # noqa: E402

_mutant = H.load_mutant()
if _mutant and _mutant["target"] == "client":
    import tempfile

    scratch = Path(tempfile.mkdtemp(prefix="aa-client-mutant-"))
    mutated = scratch / "api_anything_client.py"
    mutated.write_text(H.CLIENT_SRC.read_text(encoding="utf-8"), encoding="utf-8")
    H.apply_mutation(mutated, _mutant["find"], _mutant["replace"])
    name = "leviathan_market_data.public_sources.api_anything_client"
    import leviathan_market_data.public_sources  # noqa: F401

    spec = importlib.util.spec_from_file_location(name, mutated)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    sys.modules["leviathan_market_data.public_sources"].api_anything_client = module  # type: ignore[attr-defined]

from leviathan_market_data.public_sources import api_anything_client as client  # noqa: E402
from leviathan_market_data.public_sources import api_anything_registry as registry  # noqa: E402


def pytest_report_header(config: pytest.Config) -> list[str]:
    return [
        f"worktree under test: {H.WORKTREE}",
        f"leviathan_market_data: {leviathan_market_data.__file__}",
        f"api_anything_client:   {client.__file__}",
        f"tooling (node_modules): {H.TOOLING}",
        f"mutant: {_mutant}",
    ]


@pytest.fixture(scope="session")
def worktree() -> Path:
    return H.WORKTREE


@pytest.fixture(scope="session")
def collector(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return H.build_collector(tmp_path_factory.mktemp("aa-build"))


@pytest.fixture(scope="session")
def v_real(collector: Path) -> Path:
    """Real wrapper, real challenge.js, real vendor (never used for learn)."""
    return H.make_variant(collector, "real", vendor="real", challenge="real")


@pytest.fixture(scope="session")
def v_realvendor_fakechallenge(collector: Path) -> Path:
    return H.make_variant(collector, "rvfc", vendor="real", challenge="fake")


@pytest.fixture(scope="session")
def v_stub(collector: Path) -> Path:
    """Real wrapper + stub vendor + fake challenge window: exercises wrapper decisions."""
    return H.make_variant(collector, "stub", vendor="stub", challenge="fake")


@pytest.fixture
def data_dir(tmp_path: Path) -> Path:
    d = tmp_path / "appdata"
    d.mkdir()
    return d


@pytest.fixture
def sidecar_factory():
    made: list[H.Sidecar] = []

    def make(variant: Path, data_dir: Path, **kw):
        sc = H.Sidecar(variant, data_dir, **kw)
        made.append(sc)
        return sc

    yield make
    for sc in made:
        sc.close()


class FakeSite:
    """Loopback fake of a public site. The only network the suite ever touches."""

    def __init__(self) -> None:
        self.hits = 0
        self.mode = "ok"  # ok | captcha_once | captcha
        self.rows: list[dict] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):  # silence
                pass

            def do_GET(self):
                outer.hits += 1
                if outer.mode == "auth":
                    body = b'{"error":"unauthorized"}'
                    self.send_response(401)
                    self.send_header("content-type", "application/json")
                    self.send_header("content-length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                blocked = outer.mode == "captcha" or (outer.mode == "captcha_once" and outer.hits == 1)
                if blocked:
                    body = b"<html><body>Please verify you are human. CAPTCHA required.</body></html>"
                    self.send_response(403)
                    self.send_header("content-type", "text/html")
                else:
                    body = json.dumps({"data": outer.rows}).encode()
                    self.send_response(200)
                    self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def template(self, site: str, op: str = "current-index") -> bytes:
        op_def = {
            "name": op,
            "description": "acceptance fake",
            "request": {
                "method": "GET",
                "url": "https://www.cnn.com/fg",
                "headers": {"accept": "application/json"},
            },
            "slots": [],
            "volatile": [],
            "trigger": {"url": "https://www.cnn.com/"},
            "match": {"path": "/fg"},
            "response": {"format": "json", "contentType": "application/json", "extract": "data"},
            "params": [],
            "readOnly": True,
            "minTier": 1,
            "learnedLoggedIn": False,
            "learnedAt": "2026-10-01T00:00:00Z",
        }
        return json.dumps(
            {
                "name": site,
                "displayName": "fake",
                "baseUrl": "https://www.cnn.com",
                "description": "acceptance fake",
                "operations": [op_def],
            }
        ).encode()

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def fake_site():
    site = FakeSite()
    site.rows = [
        {"value": 55, "label": "Greed", "observed_at": "2026-10-08T00:00:00Z",
         "knowable_at": "2026-10-08T00:00:05Z"}
    ]
    yield site
    site.stop()


# RETIRED (cycle 5): the cycle-0 suite (test_0*.py) and cycle1/ were written against the generic `extract: data` template, the
# AA_CONTROL test seam and the c1/c2 fixture envelope.  Every behaviour they covered is re-proven, against the production
# entrypoint and each operation's reviewed native-to-contract recipe, in cycle2/ (see cycle2/README-coverage.md).  They are kept
# on disk for history and are not collected; the independent acceptance suite is `pytest qa/acceptance/API-ANYTHING-001/cycle2`.
collect_ignore_glob = ["test_0*.py", "cycle1/*"]
