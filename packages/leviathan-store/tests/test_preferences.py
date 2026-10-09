"""Tests for principal-scoped preference storage and conditional writes."""

from __future__ import annotations

from pathlib import Path

import pytest
from leviathan_store.preferences import PreferencesError, PreferencesStore
from sqlalchemy import create_engine


@pytest.fixture
def store() -> PreferencesStore:
    engine = create_engine("sqlite:///:memory:")
    ticks = iter((100, 200, 300, 400))
    result = PreferencesStore(engine, clock_ns=lambda: next(ticks))
    yield result
    engine.dispose()


def test_conditional_create_update_and_scope_isolation(store: PreferencesStore) -> None:
    created = store.put("principal-a", "terminal.theme", {"mode": "dark"}, if_match="*")
    assert (created.revision, created.updated_at_ns) == (1, 100)
    assert store.get("principal-b", "terminal.theme") is None

    updated = store.put("principal-a", "terminal.theme", {"mode": "light"}, if_match="1")
    assert (updated.revision, updated.updated_at_ns) == (2, 200)
    assert updated.document == {"mode": "light"}

    with pytest.raises(PreferencesError) as conflict:
        store.put("principal-a", "terminal.theme", {"mode": "dark"}, if_match="1")
    assert conflict.value.code == "REVISION_CONFLICT"
    assert conflict.value.current == updated


@pytest.mark.parametrize("namespace", ("A", "a", "a ", "a/", "a" * 65))
def test_invalid_namespace_is_rejected(store: PreferencesStore, namespace: str) -> None:
    with pytest.raises(PreferencesError) as exc:
        store.get("principal-a", namespace)
    assert exc.value.code == "PREFERENCES_INVALID"


@pytest.mark.parametrize("key", ("api_key", "accessToken", "secret", "password_hint"))
def test_secret_shaped_property_names_are_rejected(store: PreferencesStore, key: str) -> None:
    with pytest.raises(PreferencesError) as exc:
        store.put("principal-a", "terminal.theme", {key: "opaque"}, if_match="*")
    assert exc.value.code == "PREFERENCES_INVALID"


def test_delete_resets_only_the_scoped_row(store: PreferencesStore) -> None:
    store.put("principal-a", "terminal.theme", {"mode": "dark"}, if_match="*")
    store.put("principal-b", "terminal.theme", {"mode": "light"}, if_match="*")
    store.delete("principal-a", "terminal.theme")
    assert store.get("principal-a", "terminal.theme") is None
    assert store.get("principal-b", "terminal.theme") is not None


def test_document_canonical_json_size_boundary_is_exact(store: PreferencesStore) -> None:
    overhead = len(b'{"value":""}')
    at_limit = {"value": "x" * (65_536 - overhead)}
    record = store.put("principal-a", "terminal.theme", at_limit, if_match="*")
    assert record.document == at_limit

    with pytest.raises(PreferencesError) as too_large:
        store.put(
            "principal-b",
            "terminal.theme",
            {"value": "x" * (65_536 - overhead + 1)},
            if_match="*",
        )
    assert too_large.value.code == "DOCUMENT_TOO_LARGE"


def test_preferences_survive_store_recreation(tmp_path: Path) -> None:
    database = tmp_path / "preferences.sqlite"
    first_engine = create_engine(f"sqlite:///{database}")
    first = PreferencesStore(first_engine, clock_ns=lambda: 1_800_000_000_000_000_000)
    first.put("operator-1", "terminal.chat", {"density": "compact"}, if_match="*")
    first_engine.dispose()

    second_engine = create_engine(f"sqlite:///{database}")
    second = PreferencesStore(second_engine, clock_ns=lambda: 1_800_000_000_000_000_001)
    restored = second.get("operator-1", "terminal.chat")
    second_engine.dispose()

    assert restored is not None
    assert restored.document == {"density": "compact"}
    assert restored.updated_at_ns == 1_800_000_000_000_000_000
    assert restored.revision == 1
