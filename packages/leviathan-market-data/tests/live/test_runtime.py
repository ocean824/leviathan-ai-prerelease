"""Fake transport coverage for the local live provider adapters."""

from __future__ import annotations

import hashlib
import json
from collections import deque

import pytest

from leviathan_market_data.providers.databento_live import (
    DatabentoLiveAdapter,
    DatabentoLiveError,
    DatabentoLiveSubscriptionV1,
)
from leviathan_market_data.providers.massive_live import (
    MassiveLiveAdapter,
    MassiveLiveError,
    MassiveLiveSubscriptionV1,
)


class _DbnSocket:
    def __init__(self, lines: list[bytes]) -> None:
        self.lines = deque(lines)
        self.writes: list[bytes] = []
        self.closed = False

    async def read_line(self, _maximum: int) -> bytes:
        return self.lines.popleft()

    async def write(self, data: bytes) -> None:
        self.writes.append(data)

    async def read_chunk(self, _maximum: int) -> bytes:
        return b""

    async def close(self) -> None:
        self.closed = True


class _DbnTransport:
    def __init__(self, socket: _DbnSocket) -> None:
        self.socket = socket
        self.opened: list[tuple[str, int, float]] = []

    async def open(self, host: str, port: int, timeout_s: float) -> _DbnSocket:
        self.opened.append((host, port, timeout_s))
        return self.socket


@pytest.mark.asyncio
async def test_databento_cram_and_symbol_chunking_use_fake_socket_only() -> None:
    api_key = "A" * 27 + "12345"
    socket = _DbnSocket(
        [
            b"lsg_version=1.0\n",
            b"cram=synthetic-challenge\n",
            b"success=1|session_id=fake-session\n",
        ]
    )
    transport = _DbnTransport(socket)
    symbols = tuple(f"SYN{i:03d}" for i in range(501))
    session = await DatabentoLiveAdapter(transport).connect(
        DatabentoLiveSubscriptionV1("GLBX.MDP3", "trades", "raw_symbol", symbols),
        api_key=api_key,
    )

    request = socket.writes[0].decode("ascii")
    digest = hashlib.sha256(f"synthetic-challenge|{api_key}".encode("ascii")).hexdigest()
    assert request == (
        f"auth={digest}-{api_key[-5:]}|dataset=GLBX.MDP3|encoding=dbn|"
        "compression=none|ts_out=1|client=Leviathan/MD-RUNTIME-001\n"
    )
    assert api_key not in request
    subscriptions = [item.decode("ascii") for item in socket.writes[1:3]]
    assert len(subscriptions) == 2
    assert "is_last=0" in subscriptions[0]
    assert "is_last=1" in subscriptions[1]
    assert socket.writes[3] == b"start_session\n"
    assert transport.opened == [("glbx-mdp3.lsg.databento.com", 13_000, 5.0)]
    await session.close()
    assert socket.closed


@pytest.mark.asyncio
async def test_databento_rejection_is_fixed_and_does_not_echo_cram_or_key() -> None:
    api_key = "B" * 32
    socket = _DbnSocket(
        [b"lsg_version=1.0\n", b"cram=private-challenge\n", b"success=0|error=private-error\n"]
    )
    with pytest.raises(DatabentoLiveError) as error:
        await DatabentoLiveAdapter(_DbnTransport(socket)).connect(
            DatabentoLiveSubscriptionV1("GLBX.MDP3", "trades", "raw_symbol", ("SYN",)),
            api_key=api_key,
        )
    assert error.value.code == "AUTH_REJECTED"
    assert str(error.value) == "AUTH_REJECTED"
    assert api_key not in str(error.value)
    assert "private-challenge" not in str(error.value)
    assert "private-error" not in str(error.value)
    assert socket.closed


class _MassiveSocket:
    def __init__(self, frames: list[str]) -> None:
        self.frames = deque(frames)
        self.sent: list[str] = []
        self.closed = False

    async def send(self, message: str) -> None:
        self.sent.append(message)

    async def recv(self) -> str:
        return self.frames.popleft()

    async def close(self) -> None:
        self.closed = True


class _MassiveTransport:
    def __init__(self, socket: _MassiveSocket) -> None:
        self.socket = socket
        self.endpoints: list[str] = []

    async def connect(self, endpoint: str, _timeout_s: float) -> _MassiveSocket:
        self.endpoints.append(endpoint)
        return self.socket


@pytest.mark.asyncio
async def test_massive_fake_websocket_auth_subscription_and_live_event() -> None:
    api_key = "synthetic-massive-key"
    socket = _MassiveSocket(
        [
            json.dumps({"ev": "status", "status": "connected"}),
            json.dumps({"ev": "status", "status": "auth_success"}),
            json.dumps(
                [
                    {"ev": "status", "status": "success", "message": "subscribed to: T.SYN1"},
                    {"ev": "status", "status": "success", "message": "subscribed to: Q.SYN1"},
                ]
            ),
            json.dumps({"ev": "T", "sym": "SYN1", "t": 1_800_000_000_000, "p": 10, "s": 2, "i": 7}),
        ]
    )
    transport = _MassiveTransport(socket)
    session = await MassiveLiveAdapter(transport).connect(
        MassiveLiveSubscriptionV1(("SYN1",), ("T", "Q")), api_key=api_key
    )
    assert transport.endpoints == ["wss://socket.massive.com/stocks"]
    assert json.loads(socket.sent[0]) == {"action": "auth", "params": api_key}
    assert json.loads(socket.sent[1]) == {
        "action": "subscribe",
        "params": "T.SYN1,Q.SYN1",
    }
    event = await anext(session.records())
    assert event == {"ev": "T", "sym": "SYN1", "t": 1_800_000_000_000, "p": 10, "s": 2, "i": 7}
    await session.close()
    assert socket.closed


@pytest.mark.asyncio
async def test_massive_auth_error_is_content_free() -> None:
    socket = _MassiveSocket(
        [
            json.dumps({"ev": "status", "status": "connected"}),
            json.dumps({"ev": "status", "status": "auth_failed", "message": "private-detail"}),
        ]
    )
    with pytest.raises(MassiveLiveError) as error:
        await MassiveLiveAdapter(_MassiveTransport(socket)).connect(
            MassiveLiveSubscriptionV1(("SYN1",), ("T",)), api_key="synthetic-secret"
        )
    assert error.value.code == "AUTH_REJECTED"
    assert str(error.value) == "AUTH_REJECTED"
    assert "synthetic-secret" not in str(error.value)
    assert "private-detail" not in str(error.value)
    assert socket.closed
