"""Append-only account LIVE activation event storage.

Importing this module registers the additive SQLAlchemy table on ``StoreBase``
metadata. Applications must import it before ``init_schema``; see the contract
handoff for the single-line startup registration.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr, field_validator
from sqlalchemy import JSON, DateTime, Integer, String, UniqueConstraint, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import Mapped, mapped_column

from leviathan_store.tables import StoreBase

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z", re.ASCII)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_EVENT_TYPES = frozenset({"ACTIVATION_REQUESTED", "ENABLED", "DISABLED", "INVALIDATED"})
_REASON_CODES = frozenset(
    {
        "ACCOUNT_HOLDER_REQUESTED_OFF",
        "ACCOUNT_NOT_SELECTED",
        "ACCOUNT_EVIDENCE_UNAVAILABLE",
        "ACCOUNT_EVIDENCE_STALE",
        "ACCOUNT_BINDING_CHANGED",
        "ACCOUNT_NOT_FOUND",
        "AUTH_REQUIRED",
        "BROKER_BINDING_UNVERIFIED",
        "BROKER_EVIDENCE_STALE",
        "ENTITLEMENT_UNVERIFIED",
        "ENTITLEMENT_CHANGED",
        "EVIDENCE_UNAVAILABLE",
        "FAULT_ACTIVE",
        "FEED_EVIDENCE_STALE",
        "HALT_ACTIVE",
        "HALT_STATUS_UNAVAILABLE",
        "LIVE_ACCOUNT_LIMIT_REACHED",
        "LIVE_FEATURE_NOT_ENTITLED",
        "MFA_STALE",
        "MFA_UNVERIFIED",
        "OWNER_REQUIRED",
        "RECOVERY_NOT_READY",
        "RISK_ACK_MISMATCH",
        "RISK_POLICY_CHANGED",
        "RISK_ACK_STALE",
        "SUBSCRIPTION_INACTIVE",
    }
)


class LiveActivationStoreError(RuntimeError):
    """Content-free persistence error."""

    code = "STORE_UNAVAILABLE"

    def __init__(self) -> None:
        super().__init__(self.code)


class LiveActivationEventV1(BaseModel):
    """Closed, secret-free durable event record."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["live-activation-event/1"] = "live-activation-event/1"
    event_id: StrictStr = Field(default_factory=lambda: uuid4().hex)
    event_type: StrictStr
    organization_id: StrictStr
    account_id: StrictStr
    actor_id: StrictStr
    revision: StrictInt = Field(ge=1)
    occurred_at_ns: StrictInt = Field(ge=0)
    entitlement_revision: StrictStr | None = None
    credential_binding_revision: StrictStr | None = None
    risk_policy_sha256: StrictStr | None = None
    reason_code: StrictStr | None = None

    @field_validator("event_type")
    @classmethod
    def _event_type_is_closed(cls, value: str) -> str:
        if value not in _EVENT_TYPES:
            raise ValueError("invalid event type")
        return value

    @field_validator("organization_id", "account_id", "actor_id")
    @classmethod
    def _identifiers_are_closed(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("invalid identifier")
        return value

    @field_validator("risk_policy_sha256")
    @classmethod
    def _digest_is_closed(cls, value: str | None) -> str | None:
        if value is not None and _SHA256.fullmatch(value) is None:
            raise ValueError("invalid digest")
        return value

    @field_validator("reason_code")
    @classmethod
    def _reason_is_closed(cls, value: str | None) -> str | None:
        if value is not None and value not in _REASON_CODES:
            raise ValueError("invalid reason code")
        return value


class LiveActivationEventRow(StoreBase):
    """Append-only SQL row; no update or delete operation is exposed."""

    __tablename__ = "live_activation_events"
    __table_args__ = (
        UniqueConstraint(
            "organization_id", "account_id", "revision", name="uq_live_activation_account_revision"
        ),
    )

    sequence: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(String, unique=True, index=True)
    organization_id: Mapped[str] = mapped_column(String, index=True)
    account_id: Mapped[str] = mapped_column(String, index=True)
    revision: Mapped[int] = mapped_column(Integer)
    event_type: Mapped[str] = mapped_column(String)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    payload: Mapped[dict[str, object]] = mapped_column(JSON)


class LiveActivationStoreV1:
    """Transactional append/read port over an async SQLAlchemy sessionmaker."""

    def __init__(self, sessions: async_sessionmaker[AsyncSession]) -> None:
        if not callable(sessions):
            raise LiveActivationStoreError()
        self._sessions = sessions

    async def append_events(self, events: tuple[LiveActivationEventV1, ...]) -> tuple[int, ...]:
        if (
            type(events) is not tuple
            or not events
            or any(type(event) is not LiveActivationEventV1 for event in events)
        ):
            raise LiveActivationStoreError()
        rows: list[LiveActivationEventRow] = []
        for event in events:
            payload = event.model_dump(mode="json")
            occurred_at = datetime.fromtimestamp(event.occurred_at_ns / 1_000_000_000, UTC)
            rows.append(
                LiveActivationEventRow(
                    event_id=event.event_id,
                    organization_id=event.organization_id,
                    account_id=event.account_id,
                    revision=event.revision,
                    event_type=event.event_type,
                    occurred_at=occurred_at,
                    payload=payload,
                )
            )
        try:
            async with self._sessions() as session, session.begin():
                session.add_all(rows)
                await session.flush()
                sequences = tuple(int(row.sequence) for row in rows)
            return sequences
        except Exception as exc:
            raise LiveActivationStoreError() from exc

    async def read_events(
        self, organization_id: str, account_id: str
    ) -> tuple[LiveActivationEventV1, ...]:
        if (
            _IDENTIFIER.fullmatch(organization_id) is None
            or _IDENTIFIER.fullmatch(account_id) is None
        ):
            raise LiveActivationStoreError()
        try:
            async with self._sessions() as session:
                rows = await session.scalars(
                    select(LiveActivationEventRow)
                    .where(
                        LiveActivationEventRow.organization_id == organization_id,
                        LiveActivationEventRow.account_id == account_id,
                    )
                    .order_by(LiveActivationEventRow.sequence.asc())
                )
                return tuple(LiveActivationEventV1.model_validate(row.payload) for row in rows)
        except Exception as exc:
            raise LiveActivationStoreError() from exc


__all__ = [
    "LiveActivationEventRow",
    "LiveActivationEventV1",
    "LiveActivationStoreError",
    "LiveActivationStoreV1",
]
