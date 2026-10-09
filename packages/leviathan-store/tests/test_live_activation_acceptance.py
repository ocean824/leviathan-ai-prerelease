from __future__ import annotations

from pathlib import Path

import pytest
from leviathan_store.engine import create_engine_and_sessionmaker, init_schema
from leviathan_store.live_activation import (
    LiveActivationEventV1,
    LiveActivationStoreError,
    LiveActivationStoreV1,
)
from pydantic import ValidationError


def event(
    event_type: str, revision: int, *, org: str = "org-1", account: str = "acct-1"
) -> LiveActivationEventV1:
    return LiveActivationEventV1(
        event_type=event_type,
        organization_id=org,
        account_id=account,
        actor_id="owner-1",
        revision=revision,
        occurred_at_ns=1_800_000_000_000_000_000 + revision,
        entitlement_revision="entitlement-1",
        credential_binding_revision="binding-1",
        risk_policy_sha256="a" * 64,
        reason_code="ACCOUNT_HOLDER_REQUESTED_OFF" if event_type == "DISABLED" else None,
    )


@pytest.mark.asyncio
async def test_live_activation_history_is_append_only_scoped_and_restart_readable(
    tmp_path: Path,
) -> None:
    database = tmp_path / "activation.sqlite"
    url = f"sqlite+aiosqlite:///{database.as_posix()}"
    engine, sessions = create_engine_and_sessionmaker(url)
    try:
        await init_schema(engine)
        store = LiveActivationStoreV1(sessions)
        requested, enabled, disabled = (
            event("ACTIVATION_REQUESTED", 1),
            event("ENABLED", 2),
            event("DISABLED", 3),
        )
        sequences = await store.append_events((requested, enabled))
        assert len(sequences) == 2 and sequences[0] < sequences[1]
        assert await store.read_events("org-1", "acct-1") == (requested, enabled)
        await store.append_events((disabled,))

        # A newly constructed store over a new engine reads the durable OFF event.
        await engine.dispose()
        reopened_engine, reopened_sessions = create_engine_and_sessionmaker(url)
        try:
            reopened_store = LiveActivationStoreV1(reopened_sessions)
            assert await reopened_store.read_events("org-1", "acct-1") == (
                requested,
                enabled,
                disabled,
            )
            assert await reopened_store.read_events("other-org", "acct-1") == ()
            assert await reopened_store.read_events("org-1", "other-account") == ()
        finally:
            await reopened_engine.dispose()
    finally:
        # Engine may already be disposed before reopening; disposal is idempotent.
        await engine.dispose()


@pytest.mark.asyncio
async def test_duplicate_account_revision_cannot_rewrite_existing_event(tmp_path: Path) -> None:
    engine, sessions = create_engine_and_sessionmaker(
        f"sqlite+aiosqlite:///{(tmp_path / 'unique.sqlite').as_posix()}"
    )
    try:
        await init_schema(engine)
        store = LiveActivationStoreV1(sessions)
        original = event("ENABLED", 2)
        await store.append_events((original,))
        conflicting = event("DISABLED", 2)
        with pytest.raises(LiveActivationStoreError):
            await store.append_events((conflicting,))
        assert await store.read_events("org-1", "acct-1") == (original,)
    finally:
        await engine.dispose()


def test_event_schema_rejects_secret_fields_and_unknown_event_or_reason_codes() -> None:
    base = event("ENABLED", 1).model_dump()
    with pytest.raises(ValidationError):
        LiveActivationEventV1.model_validate({**base, "credential_value": "synthetic-secret"})
    with pytest.raises(ValidationError):
        LiveActivationEventV1.model_validate({**base, "event_type": "ORDER_SENT"})
    with pytest.raises(ValidationError):
        LiveActivationEventV1.model_validate({**base, "reason_code": "raw private detail"})


@pytest.mark.asyncio
async def test_invalid_batch_fails_before_any_event_is_written(tmp_path: Path) -> None:
    engine, sessions = create_engine_and_sessionmaker(
        f"sqlite+aiosqlite:///{(tmp_path / 'atomic.sqlite').as_posix()}"
    )
    try:
        await init_schema(engine)
        store = LiveActivationStoreV1(sessions)
        with pytest.raises(LiveActivationStoreError):
            await store.append_events((event("ACTIVATION_REQUESTED", 1), object()))  # type: ignore[arg-type]
        assert await store.read_events("org-1", "acct-1") == ()
    finally:
        await engine.dispose()
