"""Each test gets an isolated database and a pinned fixture risk lock."""

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from leviathan_api import main as api_main
from leviathan_api.settings import get_settings
from leviathan_api.state import build_app_state
from leviathan_core.execution.order_models import LedgerIntegrityKey
from leviathan_core.risk.halt_store import (
    HaltStore,
    ProfileClassification,
    ProfileEvidence,
)

FIXTURE_LOCK = (
    Path(__file__).resolve().parents[3] / "tests/fixtures/risk_lock/risk_governance.lock.yaml"
)
FIXTURE_LOCK_SHA256 = "46a03497679f8a59c82229ba28cef4bf56b7c1d7c30ae936016f876c9eaf3c51"
_TEST_LEDGER_KEY = LedgerIntegrityKey(b"api-test-synthetic-ledger-key-000000001")


@pytest.fixture(autouse=True)
def _isolated_db(tmp_path, monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    halt_path = tmp_path / "halt-state.sqlite3"
    HaltStore.provision_new(
        halt_path,
        tmp_path,
        ProfileEvidence(
            ProfileClassification.NEVER_PROVISIONED,
            verified=True,
            references=("pytest:isolated-profile",),
        ),
    )
    monkeypatch.setenv("LEVIATHAN_HALT_STORE_PATH", str(halt_path))
    monkeypatch.setenv(
        "LEVIATHAN_DATABASE_URL", f"sqlite+aiosqlite:///{tmp_path.as_posix()}/test.db"
    )
    monkeypatch.setenv("LEVIATHAN_RISK_LOCK_SHA256", FIXTURE_LOCK_SHA256)
    monkeypatch.setattr(
        api_main,
        "build_app_state",
        lambda: build_app_state(
            lock_path=FIXTURE_LOCK,
            ledger_integrity_key=_TEST_LEDGER_KEY,
        ),
    )
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def client() -> Iterator[TestClient]:
    """A fresh, provisioned AppState under the real lifespan for each consumer."""
    with TestClient(api_main.app) as active:
        yield active
