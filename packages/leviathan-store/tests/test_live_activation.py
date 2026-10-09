from __future__ import annotations

import pytest
from leviathan_store.engine import create_engine_and_sessionmaker, init_schema
from leviathan_store.live_activation import (
    LiveActivationEventV1,
    LiveActivationStoreError,
    LiveActivationStoreV1,
)
from pydantic import ValidationError


def _event(event_type: str, revision: int = 1) -> LiveActivationEventV1:
    return LiveActivationEventV1(
        event_type=event_type,
        organization_id="org-1",
        account_id="account-1",
        actor_id="owner-1",
        revision=revision,
        occurred_at_ns=1_800_000_000_000_000_000 + revision,
        entitlement_revision="entitlement-4",
        credential_binding_revision="binding-2",
        risk_policy_sha256="a" * 64,
        reason_code=None,
    )


@pytest.mark.asyncio
async def test_events_append_atomically_and_read_in_revision_order() -> None:
    engine, sessions = create_engine_and_sessionmaker("sqlite+aiosqlite:///:memory:")
    try:
        # Importing live_activation registers its table before the additive schema pass.
        await init_schema(engine)
        store = LiveActivationStoreV1(sessions)
        first, second = _event("ACTIVATION_REQUESTED"), _event("ENABLED", 2)
        sequences = await store.append_events((first, second))
        assert sequences[0] < sequences[1]
        assert await store.read_events("org-1", "account-1") == (first, second)
        assert await store.read_events("org-2", "account-1") == ()
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_events_are_account_and_organization_scoped() -> None:
    engine, sessions = create_engine_and_sessionmaker("sqlite+aiosqlite:///:memory:")
    try:
        await init_schema(engine)
        store = LiveActivationStoreV1(sessions)
        await store.append_events((_event("DISABLED"),))
        assert await store.read_events("org-1", "other-account") == ()
        with pytest.raises(LiveActivationStoreError):
            await store.read_events("org/other", "account-1")
    finally:
        await engine.dispose()


def test_event_schema_is_closed_and_digest_is_lowercase() -> None:
    with pytest.raises(ValidationError):
        LiveActivationEventV1.model_validate(
            {
                **_event("ENABLED").model_dump(),
                "credential_value": "not-persistable",
            }
        )
    with pytest.raises(ValidationError):
        LiveActivationEventV1.model_validate(
            {
                **_event("ENABLED").model_dump(),
                "risk_policy_sha256": "A" * 64,
            }
        )


@pytest.mark.asyncio
async def test_batch_requires_issued_schema_records_before_opening_transaction() -> None:
    engine, sessions = create_engine_and_sessionmaker("sqlite+aiosqlite:///:memory:")
    try:
        await init_schema(engine)
        store = LiveActivationStoreV1(sessions)
        with pytest.raises(LiveActivationStoreError):
            await store.append_events((_event("ENABLED"), object()))  # type: ignore[arg-type]
        assert await store.read_events("org-1", "account-1") == ()
    finally:
        await engine.dispose()
