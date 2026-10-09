"""Databento Raw Live protocol client with injectable byte transport.

The key is used only to calculate the CRAM response and is never written to the
socket, returned from this module, or included in a raised error.
"""

from __future__ import annotations

import asyncio
import hashlib
import importlib
import operator
import re
from collections.abc import AsyncIterator
from contextlib import suppress
from dataclasses import dataclass
from typing import Any, Final, Protocol, cast
from uuid import NAMESPACE_URL, uuid5

from leviathan_market_data.normalization import NormalizationError, VendorRecord
from leviathan_market_data.providers.databento_mapping import (
    DatabentoMappingError,
    DatabentoResolvedMappingV1,
    DatabentoSessionMappingRegistry,
)

MAX_CONTROL_LINE: Final = 65_536
MAX_CONTROL_CHUNK_SYMBOLS: Final = 500
MAX_DBn_CHUNK: Final = 65_536
_DATASET = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z", re.ASCII)
_SCHEMA = re.compile(r"[a-z0-9_-]{1,32}\Z", re.ASCII)
_SYMBOL = re.compile(r"[A-Za-z0-9._:/-]{1,32}\Z", re.ASCII)


class DatabentoLiveError(ValueError):
    """Fixed-code live protocol error with no provider response retained."""

    _CODES = frozenset(
        {
            "INVALID_CONFIGURATION",
            "AUTH_UNAVAILABLE",
            "AUTH_REJECTED",
            "PROTOCOL_ERROR",
            "SUBSCRIPTION_REJECTED",
            "DECODER_UNAVAILABLE",
            "NETWORK_UNAVAILABLE",
            "SESSION_CLOSED",
            "INVALID_SYMBOL_MAPPING",
            "UNMAPPED_INSTRUMENT",
            "UNSUPPORTED_RECORD",
        }
    )

    def __init__(self, code: str) -> None:
        self.code = code if type(code) is str and code in self._CODES else "PROTOCOL_ERROR"
        super().__init__(self.code)


@dataclass(frozen=True, slots=True)
class DatabentoLiveSubscriptionV1:
    dataset: str
    schema: str
    stype_in: str
    symbols: tuple[str, ...]
    request_snapshot: bool = False

    def __post_init__(self) -> None:
        if (
            type(self.dataset) is not str
            or _DATASET.fullmatch(self.dataset) is None
            or type(self.schema) is not str
            or _SCHEMA.fullmatch(self.schema) is None
            or type(self.stype_in) is not str
            or _SCHEMA.fullmatch(self.stype_in) is None
            or type(self.symbols) is not tuple
            or not self.symbols
            or len(self.symbols) > 50_000
            or any(
                type(item) is not str or _SYMBOL.fullmatch(item) is None for item in self.symbols
            )
            or len(set(self.symbols)) != len(self.symbols)
            or type(self.request_snapshot) is not bool
        ):
            raise DatabentoLiveError("INVALID_CONFIGURATION")


class DatabentoSocketPort(Protocol):
    async def read_line(self, maximum: int) -> bytes: ...

    async def write(self, data: bytes) -> None: ...

    async def read_chunk(self, maximum: int) -> bytes: ...

    async def close(self) -> None: ...


class DatabentoTransportPort(Protocol):
    async def open(self, host: str, port: int, timeout_s: float) -> DatabentoSocketPort: ...


class _DbnDecoderPort(Protocol):
    def write_and_decode(self, chunk: bytes) -> list[object] | tuple[object, ...]: ...


class _AsyncioSocket:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._reader = reader
        self._writer = writer

    async def read_line(self, maximum: int) -> bytes:
        line = await self._reader.readline()
        if len(line) > maximum or not line.endswith(b"\n"):
            raise DatabentoLiveError("PROTOCOL_ERROR")
        return line

    async def write(self, data: bytes) -> None:
        self._writer.write(data)
        await self._writer.drain()

    async def read_chunk(self, maximum: int) -> bytes:
        return await self._reader.read(maximum)

    async def close(self) -> None:
        self._writer.close()
        with suppress(Exception):
            await self._writer.wait_closed()


class AsyncioDatabentoTransport:
    """Plain TCP transport required by Databento Raw Live protocol."""

    async def open(self, host: str, port: int, timeout_s: float) -> DatabentoSocketPort:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout_s
            )
        except Exception:
            raise DatabentoLiveError("NETWORK_UNAVAILABLE") from None
        return _AsyncioSocket(reader, writer)


class DatabentoLiveSession:
    def __init__(
        self,
        *,
        socket: DatabentoSocketPort,
        decoder: object,
        session_id: str,
        mapping_registry: DatabentoSessionMappingRegistry,
    ) -> None:
        self._socket = socket
        self._decoder = decoder
        self.session_id = session_id
        self.mapping_registry = mapping_registry
        self.unmapped_record_count = 0
        self.mapping_degraded = False
        self._transition_pending = True
        self._closed = False

    async def records(self) -> AsyncIterator[object]:
        while not self._closed:
            try:
                chunk = await self._socket.read_chunk(MAX_DBn_CHUNK)
            except Exception:
                raise DatabentoLiveError("NETWORK_UNAVAILABLE") from None
            if not chunk:
                raise DatabentoLiveError("SESSION_CLOSED")
            try:
                decoded = cast(_DbnDecoderPort, self._decoder).write_and_decode(chunk)
            except Exception:
                raise DatabentoLiveError("PROTOCOL_ERROR") from None
            if not isinstance(decoded, (list, tuple)) or len(decoded) > 16_384:
                raise DatabentoLiveError("PROTOCOL_ERROR")
            for record in decoded:
                if type(record).__name__ == "Metadata":
                    continue
                if type(record).__name__ == "SymbolMappingMsg":
                    try:
                        self.mapping_registry.ingest(record)
                    except DatabentoMappingError:
                        raise DatabentoLiveError("INVALID_SYMBOL_MAPPING") from None
                    yield record
                    continue
                if (
                    type(record).__name__
                    in {"MBOMsg", "MBP1Msg", "MBP10Msg", "TradeMsg", "OHLCVMsg"}
                    and self.mapping_for(record) is None
                ):
                    # A record without an effective live mapping is never
                    # exposed to normalization under an inferred symbol.
                    self.unmapped_record_count = min(self.unmapped_record_count + 1, (1 << 63) - 1)
                    self.mapping_degraded = True
                    continue
                yield record

    def mapping_for(self, record: object) -> DatabentoResolvedMappingV1 | None:
        """Resolve the exact publisher/instrument/time tuple for a DBN record."""
        try:
            publisher_id = getattr(record, "publisher_id", None)
            instrument_id = getattr(record, "instrument_id", None)
            event_time_ns = getattr(record, "ts_event", None)
        except Exception:
            return None
        if any(type(value) is not int for value in (publisher_id, instrument_id, event_time_ns)):
            return None
        return self.mapping_registry.resolve(
            publisher_id=cast(int, publisher_id),
            instrument_id=cast(int, instrument_id),
            event_time_ns=cast(int, event_time_ns),
        )

    def vendor_record_for(self, record: object, *, received_time_ns: int) -> VendorRecord:
        """Translate one typed DBN event using its currently valid live mapping."""
        mapping = self.mapping_for(record)
        if mapping is None:
            self.unmapped_record_count = min(self.unmapped_record_count + 1, (1 << 63) - 1)
            self.mapping_degraded = True
            raise DatabentoLiveError("UNMAPPED_INSTRUMENT")
        try:
            vendor = _vendor_record(
                record,
                mapping,
                self.session_id,
                received_time_ns,
                session_transition_confirmed=self._transition_pending,
            )
            self._transition_pending = False
            return vendor
        except (AttributeError, KeyError, TypeError, ValueError, NormalizationError):
            raise DatabentoLiveError("UNSUPPORTED_RECORD") from None

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        await self._socket.close()


class DatabentoLiveAdapter:
    """Authenticate, subscribe, start, and yield decoded DBN records."""

    def __init__(
        self, transport: DatabentoTransportPort | None = None, *, timeout_s: float = 5.0
    ) -> None:
        if type(timeout_s) is not float or not 0.1 <= timeout_s <= 30.0:
            raise DatabentoLiveError("INVALID_CONFIGURATION")
        self._transport = transport or AsyncioDatabentoTransport()
        self._timeout_s = timeout_s

    async def connect(
        self,
        subscription: DatabentoLiveSubscriptionV1,
        *,
        api_key: str,
        compression: str = "none",
        client: str = "Leviathan/MD-RUNTIME-001",
    ) -> DatabentoLiveSession:
        if (
            type(subscription) is not DatabentoLiveSubscriptionV1
            or type(api_key) is not str
            or len(api_key) != 32
            or not api_key.isascii()
            or type(compression) is not str
            or compression not in {"none", "zstd"}
            or type(client) is not str
            or not client.isascii()
            or not 1 <= len(client) <= 64
            or "|" in client
            or "\n" in client
        ):
            raise DatabentoLiveError("INVALID_CONFIGURATION")
        dataset = subscription.dataset
        host = dataset.replace(".", "-").lower() + ".lsg.databento.com"
        socket = await self._transport.open(host, 13_000, self._timeout_s)
        try:
            greeting = _control_fields(await socket.read_line(MAX_CONTROL_LINE))
            if not greeting.get("lsg_version"):
                raise DatabentoLiveError("PROTOCOL_ERROR")
            challenge_fields = _control_fields(await socket.read_line(MAX_CONTROL_LINE))
            challenge = challenge_fields.get("cram")
            if not challenge or any(ch.isspace() for ch in challenge):
                raise DatabentoLiveError("PROTOCOL_ERROR")
            digest = hashlib.sha256(f"{challenge}|{api_key}".encode("ascii")).hexdigest()
            request = (
                f"auth={digest}-{api_key[-5:]}|dataset={dataset}|encoding=dbn|"
                f"compression={compression}|ts_out=1|client={client}\n"
            )
            await socket.write(request.encode("ascii"))
            auth = _control_fields(await socket.read_line(MAX_CONTROL_LINE))
            if auth.get("success") != "1":
                raise DatabentoLiveError("AUTH_REJECTED")
            session_id = auth.get("session_id")
            if not session_id or len(session_id) > 128 or not session_id.isascii():
                raise DatabentoLiveError("PROTOCOL_ERROR")
            chunks = [
                subscription.symbols[i : i + MAX_CONTROL_CHUNK_SYMBOLS]
                for i in range(0, len(subscription.symbols), MAX_CONTROL_CHUNK_SYMBOLS)
            ]
            for index, symbols in enumerate(chunks):
                fields = [
                    f"schema={subscription.schema}",
                    f"stype_in={subscription.stype_in}",
                    "symbols=" + ",".join(symbols),
                    f"snapshot={int(subscription.request_snapshot)}",
                    f"is_last={int(index == len(chunks) - 1)}",
                ]
                line = "|".join(fields) + "\n"
                if len(line.encode("ascii")) > MAX_CONTROL_LINE:
                    raise DatabentoLiveError("INVALID_CONFIGURATION")
                await socket.write(line.encode("ascii"))
            await socket.write(b"start_session\n")
            decoder_module = importlib.import_module("databento_dbn")
            decoder_type = getattr(decoder_module, "DBNDecoder", None)
            if not callable(decoder_type):
                raise DatabentoLiveError("DECODER_UNAVAILABLE")
            try:
                decoder = decoder_type(has_metadata=True, ts_out=True)
            except Exception:
                raise DatabentoLiveError("DECODER_UNAVAILABLE") from None
            mapping_registry = DatabentoSessionMappingRegistry(
                session_id=session_id,
                dataset=subscription.dataset,
                stype_in=subscription.stype_in,
                configured_symbols=subscription.symbols,
            )
            return DatabentoLiveSession(
                socket=socket,
                decoder=decoder,
                session_id=session_id,
                mapping_registry=mapping_registry,
            )
        except DatabentoLiveError:
            await socket.close()
            raise
        except Exception:
            await socket.close()
            raise DatabentoLiveError("PROTOCOL_ERROR") from None


def _control_fields(line: bytes) -> dict[str, str]:
    try:
        text = line.decode("ascii").removesuffix("\n").removesuffix("\r")
    except UnicodeError:
        raise DatabentoLiveError("PROTOCOL_ERROR") from None
    fields: dict[str, str] = {}
    for token in text.split("|"):
        key, separator, value = token.partition("=")
        if not separator or not key or key in fields:
            raise DatabentoLiveError("PROTOCOL_ERROR")
        fields[key] = value
    return fields


def _vendor_record(
    record: object,
    resolved: DatabentoResolvedMappingV1,
    session_id: str,
    received_time_ns: int,
    *,
    session_transition_confirmed: bool,
) -> VendorRecord:
    """Convert supported native DBN message objects without guessing identity."""
    dbn = importlib.import_module("databento_dbn")
    kind_by_type = {
        "TradeMsg": "trades",
        "MBOMsg": "mbo",
        "MBP10Msg": "mbp-10",
        "OHLCVMsg": "ohlcv-1m",
    }
    record_type = type(record).__name__
    channel = kind_by_type.get(record_type)
    record_class = getattr(dbn, record_type, ())
    if (
        channel is None
        or not isinstance(record_class, type)
        or not isinstance(record, record_class)
    ):
        raise DatabentoLiveError("UNSUPPORTED_RECORD")
    native_record = cast(Any, record)
    event_time_ns = _exact_timestamp(native_record.ts_event)
    source_time_ns = getattr(native_record, "ts_recv", None)
    if source_time_ns is not None:
        source_time_ns = _exact_timestamp(source_time_ns)
    received_time_ns = _exact_timestamp(received_time_ns)
    sequence = getattr(native_record, "sequence", None)
    if sequence is not None and (type(sequence) is not int or not 0 <= sequence < (1 << 63)):
        raise DatabentoLiveError("UNSUPPORTED_RECORD")
    raw_action = _enum_name(getattr(native_record, "action", None))
    raw_side = _enum_name(getattr(native_record, "side", None))
    flags = getattr(native_record, "flags", 0)
    if flags is None:
        flags = 0
    if type(flags) is not int or not 0 <= flags <= 255:
        raise DatabentoLiveError("UNSUPPORTED_RECORD")
    publisher_id = native_record.publisher_id
    native_id = native_record.instrument_id
    if type(publisher_id) is not int or type(native_id) is not int:
        raise DatabentoLiveError("UNSUPPORTED_RECORD")
    payload: dict[str, object]
    event_type: str
    if record_type == "TradeMsg" or (record_type == "MBOMsg" and raw_action in {"trade", "fill"}):
        event_type = "trade"
        payload = {
            "price": _fixed_price(native_record.price),
            "size": _size(native_record.size),
            "side": _trade_side(raw_side),
        }
    elif record_type == "MBOMsg":
        action_map = {
            "add": "add",
            "modify": "update",
            "cancel": "delete",
            "clear": "clear",
        }
        action = action_map.get(raw_action)
        if action is None:
            raise DatabentoLiveError("UNSUPPORTED_RECORD")
        event_type = "book_delta"
        payload = {"action": action}
        side = _side(raw_side)
        if side in {"bid", "ask"}:
            payload["side"] = side
        if action != "clear":
            payload["price"] = _fixed_price(native_record.price)
            payload["size"] = _size(native_record.size)
            payload["order_id"] = str(native_record.order_id)
    elif record_type == "MBP10Msg":
        event_type = "book_snapshot"
        levels: list[dict[str, object]] = []
        for level_number, pair in enumerate(native_record.levels or ()):
            for side, price, size in (
                ("bid", pair.bid_px, pair.bid_sz),
                ("ask", pair.ask_px, pair.ask_sz),
            ):
                if type(price) is int and price != (1 << 63) - 1 and type(size) is int and size > 0:
                    levels.append(
                        {
                            "side": side,
                            "price": _fixed_price(price),
                            "size": _size(size),
                            "level": level_number,
                        }
                    )
        payload = {"levels": tuple(levels)}
    else:
        event_type = "bar"
        payload = {
            "interval": "1m",
            "open_time_ns": event_time_ns,
            "open": _fixed_price(native_record.open),
            "high": _fixed_price(native_record.high),
            "low": _fixed_price(native_record.low),
            "close": _fixed_price(native_record.close),
            "volume": _size(native_record.volume),
        }
    rtype = getattr(native_record, "rtype", None)
    try:
        if rtype is None:
            raise TypeError
        rtype_value = operator.index(rtype)
    except (TypeError, ValueError):
        raise DatabentoLiveError("UNSUPPORTED_RECORD") from None
    source_key = (
        f"databento:{resolved.mapping.dataset}:{publisher_id}:{native_id}:"
        f"{channel}:{sequence if sequence is not None else 'unknown'}:{event_time_ns}:{rtype_value}"
    )
    allowed_actions = {
        "add",
        "modify",
        "delete",
        "clear",
        "trade",
        "fill",
        "cancel",
        "correct",
        "status",
        "unknown",
    }
    native_action = raw_action if raw_action in allowed_actions else "unknown"
    native_side = raw_side if raw_side in {"buy", "sell", "bid", "ask"} else "unknown"
    native: dict[str, object] = {
        "publisher_id": publisher_id,
        "native_instrument_id": native_id,
        "rtype": rtype_value,
        "action": native_action,
        "side": native_side,
        "flags": flags,
        "ts_in_delta_ns": getattr(native_record, "ts_in_delta", 0),
    }
    attributes = {
        "databento:raw_flags_code": str(flags),
        "databento:raw_rtype_code": str(rtype_value),
    }
    if raw_action:
        attributes["databento:raw_action_code"] = raw_action
    if raw_side:
        attributes["databento:raw_side_code"] = raw_side
    return VendorRecord(
        provider="databento",
        dataset=resolved.mapping.dataset,
        venue=resolved.mapping.venue,
        native_symbol=resolved.raw_symbol,
        channel=channel,
        event_type=event_type,
        event_time_ns=event_time_ns,
        source_record_ref=source_key,
        payload=payload,
        source_mode="live",
        source_time_ns=source_time_ns,
        exchange_time_ns=event_time_ns,
        native_sequence=sequence,
        source_record_key=source_key,
        event_id=uuid5(NAMESPACE_URL, source_key),
        received_time_ns=received_time_ns,
        provenance_timestamps={"exchange": event_time_ns, "provider": source_time_ns},
        native_provenance=native,
        source_attributes=attributes,
        provider_session_id=session_id,
        session_transition_confirmed=session_transition_confirmed,
    )


def _exact_timestamp(value: object) -> int:
    if type(value) is not int or not 0 < value < (1 << 63):
        raise DatabentoLiveError("UNSUPPORTED_RECORD")
    return value


def _enum_name(value: object) -> str:
    name = getattr(value, "name", None)
    return name.lower() if type(name) is str else ""


def _fixed_price(value: object) -> str:
    if type(value) is not int or not -(1 << 63) < value < (1 << 63) - 1:
        raise DatabentoLiveError("UNSUPPORTED_RECORD")
    sign = "-" if value < 0 else ""
    whole, fraction = divmod(abs(value), 1_000_000_000)
    fractional = f"{fraction:09d}".rstrip("0")
    return f"{sign}{whole}" + (f".{fractional}" if fractional else "")


def _size(value: object) -> str:
    if type(value) is not int or value < 0:
        raise DatabentoLiveError("UNSUPPORTED_RECORD")
    return str(value)


def _side(value: str) -> str:
    return {"bid": "bid", "ask": "ask"}.get(value, "unknown")


def _trade_side(value: str) -> str:
    return {"bid": "buy", "ask": "sell"}.get(value, "unknown")


__all__ = [
    "AsyncioDatabentoTransport",
    "DatabentoLiveAdapter",
    "DatabentoLiveError",
    "DatabentoLiveSession",
    "DatabentoLiveSubscriptionV1",
    "DatabentoSocketPort",
    "DatabentoTransportPort",
]
