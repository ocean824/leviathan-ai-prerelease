"""Bounded Massive Stocks Advanced websocket adapter."""

from __future__ import annotations

import asyncio
import importlib
import json
import re
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Final, Protocol
from uuid import uuid4

MAX_FRAME_BYTES: Final = 1_048_576
MAX_EVENTS_PER_FRAME: Final = 1_024
_SYMBOL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,31}\Z", re.ASCII)
_CHANNEL = frozenset({"T", "Q", "A", "AM"})
_ENDPOINT = "wss://socket.massive.com/stocks"


class MassiveLiveError(ValueError):
    """Content-free websocket adapter error."""

    _CODES = frozenset(
        {
            "INVALID_CONFIGURATION",
            "AUTH_UNAVAILABLE",
            "AUTH_REJECTED",
            "SUBSCRIPTION_REJECTED",
            "PROTOCOL_ERROR",
            "NETWORK_UNAVAILABLE",
            "SESSION_CLOSED",
        }
    )

    def __init__(self, code: str) -> None:
        self.code = code if type(code) is str and code in self._CODES else "PROTOCOL_ERROR"
        super().__init__(self.code)


@dataclass(frozen=True, slots=True)
class MassiveLiveSubscriptionV1:
    symbols: tuple[str, ...]
    channels: tuple[str, ...]

    def __post_init__(self) -> None:
        if (
            type(self.symbols) is not tuple
            or not 1 <= len(self.symbols) <= 500
            or any(
                type(symbol) is not str or _SYMBOL.fullmatch(symbol) is None
                for symbol in self.symbols
            )
            or len(set(self.symbols)) != len(self.symbols)
            or type(self.channels) is not tuple
            or not 1 <= len(self.channels) <= 4
            or any(type(channel) is not str or channel not in _CHANNEL for channel in self.channels)
            or len(set(self.channels)) != len(self.channels)
        ):
            raise MassiveLiveError("INVALID_CONFIGURATION")


class MassiveWebSocketPort(Protocol):
    async def send(self, message: str) -> None: ...

    async def recv(self) -> str | bytes: ...

    async def close(self) -> None: ...


class MassiveWebSocketTransportPort(Protocol):
    async def connect(self, endpoint: str, timeout_s: float) -> MassiveWebSocketPort: ...


class _WebsocketsSocket:
    def __init__(self, socket: object) -> None:
        self._socket = socket

    async def send(self, message: str) -> None:
        await self._socket.send(message)  # type: ignore[attr-defined]

    async def recv(self) -> str | bytes:
        result = await self._socket.recv()  # type: ignore[attr-defined]
        if isinstance(result, str):
            return result
        if isinstance(result, bytes):
            return result
        raise MassiveLiveError("PROTOCOL_ERROR")

    async def close(self) -> None:
        await self._socket.close()  # type: ignore[attr-defined]


class WebsocketsMassiveTransport:
    async def connect(self, endpoint: str, timeout_s: float) -> MassiveWebSocketPort:
        if endpoint != _ENDPOINT or type(timeout_s) is not float or not 0.1 <= timeout_s <= 30.0:
            raise MassiveLiveError("INVALID_CONFIGURATION")
        try:
            websockets = importlib.import_module("websockets.asyncio.client")
            socket = await asyncio.wait_for(
                websockets.connect(
                    endpoint,
                    max_size=MAX_FRAME_BYTES,
                    ping_interval=20,
                    ping_timeout=20,
                    close_timeout=2,
                ),
                timeout=timeout_s,
            )
        except Exception:
            raise MassiveLiveError("NETWORK_UNAVAILABLE") from None
        return _WebsocketsSocket(socket)


class MassiveLiveSession:
    def __init__(self, socket: MassiveWebSocketPort, session_id: str) -> None:
        self._socket = socket
        self.session_id = session_id
        self._closed = False

    async def records(self) -> AsyncIterator[dict[str, object]]:
        while not self._closed:
            try:
                raw = await self._socket.recv()
            except Exception:
                raise MassiveLiveError("NETWORK_UNAVAILABLE") from None
            if raw is None:
                raise MassiveLiveError("SESSION_CLOSED")
            items = _decode_frame(raw)
            for item in items:
                if item.get("ev") == "status":
                    status = item.get("status")
                    if status in {"auth_failed", "error"}:
                        raise MassiveLiveError("AUTH_REJECTED")
                    if status in {"success", "subscribe_failed"} and status == "subscribe_failed":
                        raise MassiveLiveError("SUBSCRIPTION_REJECTED")
                    continue
                yield item

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        await self._socket.close()


class MassiveLiveAdapter:
    def __init__(
        self,
        transport: MassiveWebSocketTransportPort | None = None,
        *,
        timeout_s: float = 5.0,
    ) -> None:
        if type(timeout_s) is not float or not 0.1 <= timeout_s <= 30.0:
            raise MassiveLiveError("INVALID_CONFIGURATION")
        self._transport = transport or WebsocketsMassiveTransport()
        self._timeout_s = timeout_s

    async def connect(
        self,
        subscription: MassiveLiveSubscriptionV1,
        *,
        api_key: str,
    ) -> MassiveLiveSession:
        if (
            type(subscription) is not MassiveLiveSubscriptionV1
            or type(api_key) is not str
            or not api_key
            or len(api_key) > 256
            or not api_key.isascii()
            or any(ch in api_key for ch in "\r\n\x00")
        ):
            raise MassiveLiveError("INVALID_CONFIGURATION")
        socket = await self._transport.connect(_ENDPOINT, self._timeout_s)
        try:
            connected = await _recv_status(socket)
            if connected.get("status") != "connected":
                raise MassiveLiveError("PROTOCOL_ERROR")
            # This is the sole outbound occurrence of the credential. It is
            # sent over WSS and is never attached to a log or error object.
            await socket.send(
                json.dumps({"action": "auth", "params": api_key}, separators=(",", ":"))
            )
            auth = await _recv_status(socket)
            if auth.get("status") != "auth_success":
                raise MassiveLiveError("AUTH_REJECTED")
            topics = [
                f"{channel}.{symbol}"
                for channel in subscription.channels
                for symbol in subscription.symbols
            ]
            await socket.send(
                json.dumps(
                    {"action": "subscribe", "params": ",".join(topics)},
                    separators=(",", ":"),
                )
            )
            acknowledgements = await _recv_status_array(socket)
            acknowledged: set[str] = set()
            for item in acknowledgements:
                message = item.get("message")
                if item.get("status") == "success" and type(message) is str:
                    acknowledged.add(message.removeprefix("subscribed to: "))
            if len(acknowledged) != len(topics):
                raise MassiveLiveError("SUBSCRIPTION_REJECTED")
            return MassiveLiveSession(socket, uuid4().hex)
        except MassiveLiveError:
            await socket.close()
            raise
        except Exception:
            await socket.close()
            raise MassiveLiveError("PROTOCOL_ERROR") from None


async def _recv_status(socket: MassiveWebSocketPort) -> dict[str, object]:
    values = await _recv_status_array(socket)
    if not values:
        raise MassiveLiveError("PROTOCOL_ERROR")
    return values[0]


async def _recv_status_array(socket: MassiveWebSocketPort) -> list[dict[str, object]]:
    try:
        raw = await asyncio.wait_for(socket.recv(), timeout=10.0)
    except Exception:
        raise MassiveLiveError("NETWORK_UNAVAILABLE") from None
    items = _decode_frame(raw)
    if not items or any(item.get("ev") != "status" for item in items):
        raise MassiveLiveError("PROTOCOL_ERROR")
    return items


def _decode_frame(raw: str | bytes) -> list[dict[str, object]]:
    if type(raw) is bytes:
        if len(raw) > MAX_FRAME_BYTES:
            raise MassiveLiveError("PROTOCOL_ERROR")
        try:
            text = raw.decode("utf-8")
        except UnicodeError:
            raise MassiveLiveError("PROTOCOL_ERROR") from None
    elif type(raw) is str and len(raw.encode("utf-8")) <= MAX_FRAME_BYTES:
        text = raw
    else:
        raise MassiveLiveError("PROTOCOL_ERROR")
    try:
        value = json.loads(text)
    except Exception:
        raise MassiveLiveError("PROTOCOL_ERROR") from None
    if type(value) is dict:
        values = [value]
    elif type(value) is list and len(value) <= MAX_EVENTS_PER_FRAME:
        values = value
    else:
        raise MassiveLiveError("PROTOCOL_ERROR")
    if any(type(item) is not dict for item in values):
        raise MassiveLiveError("PROTOCOL_ERROR")
    return values


__all__ = [
    "MassiveLiveAdapter",
    "MassiveLiveError",
    "MassiveLiveSession",
    "MassiveLiveSubscriptionV1",
    "MassiveWebSocketPort",
    "MassiveWebSocketTransportPort",
    "WebsocketsMassiveTransport",
]
