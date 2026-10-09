"""Fake outbound notification transport; this module has no network capability."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .models import FakeTransportStatusV1, NotificationChannelV1


@dataclass(frozen=True, slots=True)
class FakeNotificationAttemptV1:
    channel: NotificationChannelV1
    destination_alias: str
    payload: str
    idempotency_key: str


class NotificationTransportPort(Protocol):
    """Synchronous fake-first boundary; a future adapter owns bounded I/O."""

    def send(
        self,
        *,
        channel: NotificationChannelV1,
        destination_alias: str,
        payload: str,
        idempotency_key: str,
        deadline_monotonic_ns: int,
    ) -> FakeTransportStatusV1: ...


class FakeNotificationTransport:
    """Deterministic fake transport for tests; never uses tokens or network calls."""

    def __init__(
        self,
        outcomes: tuple[FakeTransportStatusV1, ...] = (),
        *,
        error: Exception | None = None,
    ) -> None:
        if type(outcomes) is not tuple or any(
            type(item) is not FakeTransportStatusV1 for item in outcomes
        ):
            raise ValueError("invalid fake transport configuration")
        if error is not None and not isinstance(error, Exception):
            raise ValueError("invalid fake transport configuration")
        self._outcomes = outcomes
        self._error = error
        self._attempts: list[FakeNotificationAttemptV1] = []
        self._outcome_index = 0

    @property
    def attempts(self) -> tuple[FakeNotificationAttemptV1, ...]:
        return tuple(self._attempts)

    def send(
        self,
        *,
        channel: NotificationChannelV1,
        destination_alias: str,
        payload: str,
        idempotency_key: str,
        deadline_monotonic_ns: int,
    ) -> FakeTransportStatusV1:
        if (
            type(channel) is not NotificationChannelV1
            or type(destination_alias) is not str
            or type(payload) is not str
            or type(idempotency_key) is not str
            or type(deadline_monotonic_ns) is not int
            or deadline_monotonic_ns < 1
        ):
            raise ValueError("invalid fake transport request")
        self._attempts.append(
            FakeNotificationAttemptV1(channel, destination_alias, payload, idempotency_key)
        )
        if self._error is not None:
            raise self._error
        if not self._outcomes:
            return FakeTransportStatusV1.UNKNOWN
        index = min(self._outcome_index, len(self._outcomes) - 1)
        self._outcome_index += 1
        return self._outcomes[index]


__all__ = [
    "FakeNotificationAttemptV1",
    "FakeNotificationTransport",
    "NotificationTransportPort",
]
