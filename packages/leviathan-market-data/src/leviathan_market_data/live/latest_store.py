"""Bounded event-time-indexed read model for live market data."""

from __future__ import annotations

import hashlib
import threading
from collections import OrderedDict, deque
from dataclasses import dataclass
from typing import Final

from leviathan_market_data.health import SourceHealthSnapshot
from leviathan_market_data.schema import NormalizedMarketEventV1

MAX_SERIES: Final = 5_000
MAX_EVENTS_PER_SERIES: Final = 1_500
MAX_EVICTIONS: Final = 256
MAX_FRESHNESS_NS: Final = 120_000_000_000


class LatestStoreError(ValueError):
    """Sanitized failure from the bounded latest-event cache."""

    _CODES = frozenset({"INVALID_EVENT", "INVALID_TIME", "CAPACITY_EXCEEDED"})

    def __init__(self, code: str) -> None:
        self.code = code if type(code) is str and code in self._CODES else "INVALID_EVENT"
        super().__init__(self.code)


@dataclass(frozen=True, slots=True)
class LatestEvictionV1:
    series_sha256: str
    reason: str


@dataclass(frozen=True, slots=True)
class LatestSeriesSnapshotV1:
    provider: str
    venue: str
    instrument_id: str
    channel: str
    events: tuple[NormalizedMarketEventV1, ...]
    health: SourceHealthSnapshot | None
    freshness: str


SeriesKey = tuple[str, str, str, str]


class LatestEventStore:
    """Keep a small deterministic event-time tail for every active stream."""

    def __init__(
        self,
        *,
        max_series: int = MAX_SERIES,
        events_per_series: int = MAX_EVENTS_PER_SERIES,
        freshness_ns: int = MAX_FRESHNESS_NS,
    ) -> None:
        if (
            type(max_series) is not int
            or not 1 <= max_series <= MAX_SERIES
            or type(events_per_series) is not int
            or not 1 <= events_per_series <= MAX_EVENTS_PER_SERIES
            or type(freshness_ns) is not int
            or not 1 <= freshness_ns <= MAX_FRESHNESS_NS
        ):
            raise LatestStoreError("INVALID_EVENT")
        self.max_series = max_series
        self.events_per_series = events_per_series
        self.freshness_ns = freshness_ns
        self._events: OrderedDict[SeriesKey, deque[NormalizedMarketEventV1]] = OrderedDict()
        self._health: dict[SeriesKey, SourceHealthSnapshot] = {}
        self._evictions: deque[LatestEvictionV1] = deque(maxlen=MAX_EVICTIONS)
        self._lock = threading.RLock()

    @property
    def evictions(self) -> tuple[LatestEvictionV1, ...]:
        with self._lock:
            return tuple(self._evictions)

    def record(
        self,
        event: NormalizedMarketEventV1,
        health: SourceHealthSnapshot | None = None,
    ) -> None:
        if type(event) is not NormalizedMarketEventV1:
            raise LatestStoreError("INVALID_EVENT")
        if health is not None and type(health) is not SourceHealthSnapshot:
            raise LatestStoreError("INVALID_EVENT")
        key = (event.provider, event.venue, event.instrument_id, event.channel)
        with self._lock:
            series = self._events.get(key)
            if series is None:
                if len(self._events) >= self.max_series:
                    if len(self._evictions) == MAX_EVICTIONS:
                        raise LatestStoreError("CAPACITY_EXCEEDED")
                    old_key = next(iter(self._events))
                    self._evictions.append(
                        LatestEvictionV1(
                            hashlib.sha256("\0".join(old_key).encode("ascii")).hexdigest(),
                            "CAPACITY",
                        )
                    )
                    self._events.pop(old_key)
                    self._health.pop(old_key, None)
                series = deque(maxlen=self.events_per_series)
                self._events[key] = series
            else:
                self._events.move_to_end(key)
            # Never sort or rewrite already committed history. Same-time arrival
            # order is stable; consumers receive exactly the retained tail.
            series.append(event)
            if health is not None:
                self._health[key] = health

    def set_health(self, key: SeriesKey, health: SourceHealthSnapshot) -> None:
        if type(key) is not tuple or len(key) != 4 or type(health) is not SourceHealthSnapshot:
            raise LatestStoreError("INVALID_EVENT")
        with self._lock:
            if key in self._events:
                self._health[key] = health

    def latest(
        self,
        *,
        venue: str,
        instrument: str,
        data_type: str,
        now_ns: int,
    ) -> tuple[NormalizedMarketEventV1 | None, SourceHealthSnapshot | None]:
        if type(now_ns) is not int or now_ns <= 0:
            raise LatestStoreError("INVALID_TIME")
        candidates: list[tuple[NormalizedMarketEventV1, SourceHealthSnapshot | None]] = []
        with self._lock:
            for key, events in self._events.items():
                provider, event_venue, instrument_id, channel = key
                del provider
                if event_venue != venue or instrument_id != instrument:
                    continue
                if not _channel_matches(channel, data_type) or not events:
                    continue
                candidates.append((events[-1], self._health.get(key)))
        if not candidates:
            return None, None
        event, health = max(
            candidates,
            key=lambda pair: (pair[0].event_time_ns, pair[0].received_time_ns or 0),
        )
        # Return the event for diagnosis but a stale source is separately visible
        # through its health snapshot; API callers must not promote it to fresh.
        if now_ns < event.event_time_ns:
            return event, health
        return event, health

    def series_snapshot(
        self,
        *,
        venue: str,
        instrument: str,
        now_ns: int,
    ) -> tuple[LatestSeriesSnapshotV1, ...]:
        if type(now_ns) is not int or now_ns <= 0:
            raise LatestStoreError("INVALID_TIME")
        result: list[LatestSeriesSnapshotV1] = []
        with self._lock:
            for key, events in self._events.items():
                provider, event_venue, instrument_id, channel = key
                if event_venue != venue or instrument_id != instrument or not events:
                    continue
                tail = events[-1]
                age = max(0, now_ns - tail.event_time_ns)
                result.append(
                    LatestSeriesSnapshotV1(
                        provider=provider,
                        venue=event_venue,
                        instrument_id=instrument_id,
                        channel=channel,
                        events=tuple(events),
                        health=self._health.get(key),
                        freshness="STALE" if age > self.freshness_ns else "FRESH",
                    )
                )
        return tuple(sorted(result, key=lambda item: (item.channel, item.provider)))

    def channels(self, *, venue: str | None = None) -> tuple[str, ...]:
        with self._lock:
            return tuple(
                sorted({key[3] for key in self._events if venue is None or key[1] == venue})
            )

    def health_snapshots(self) -> tuple[SourceHealthSnapshot, ...]:
        """Return the bounded health set for venue listing and diagnostics."""
        with self._lock:
            return tuple(self._health[key] for key in self._events if key in self._health)


def _channel_matches(channel: str, data_type: str) -> bool:
    if data_type == "quotes":
        return channel in {"quotes", "mbp-1"}
    return channel == data_type


__all__ = [
    "LatestEventStore",
    "LatestEvictionV1",
    "LatestSeriesSnapshotV1",
    "LatestStoreError",
]
