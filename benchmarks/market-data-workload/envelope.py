"""Shared serialized envelope and size rules for C-103 profiles and generation."""

from __future__ import annotations

import json
from decimal import Decimal, Inexact, localcontext
from typing import Any

BASE_NS = 1_700_000_000_000_000_000
MAX_EVENT_COUNT = 100_000
MAX_ENVELOPE_BYTES = 65_536


def json_numbers_fit_precision(value: Any) -> bool:
    """Bound significant digits of every JSON number, ignoring trailing zeros."""
    if type(value) in (int, float, Decimal):
        decimal_value = Decimal(str(value))
        if not decimal_value.is_finite():
            return False
        digits = decimal_value.as_tuple().digits
        significant = len(digits)
        while significant > 1 and digits[significant - 1] == 0:
            significant -= 1
        return significant <= 34
    if isinstance(value, dict):
        return all(json_numbers_fit_precision(item) for item in value.values())
    if isinstance(value, list):
        return all(json_numbers_fit_precision(item) for item in value)
    return True


def ms_to_ns(value: int | float | Decimal) -> int:
    """Convert a declared decimal millisecond value exactly; reject sub-ns precision."""
    decimal_value = Decimal(str(value))
    if not decimal_value.is_finite():
        raise ValueError("millisecond value must be finite")
    digits = decimal_value.as_tuple().digits
    significant = len(digits)
    while significant > 1 and digits[significant - 1] == 0:
        significant -= 1
    if significant > 34 or abs(decimal_value.adjusted()) > 38:
        raise ValueError("millisecond value exceeds 34 significant digits")
    with localcontext() as context:
        context.prec = 34
        context.traps[Inexact] = True
        nanoseconds = decimal_value * 1_000_000
    if nanoseconds != nanoseconds.to_integral_value():
        raise ValueError("millisecond value is not representable in integer nanoseconds")
    return int(nanoseconds)


def json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )


def payload_base(event_type: str) -> dict[str, Any]:
    typed: dict[str, dict[str, Any]] = {
        "quote": {"bid": "100.01", "ask": "100.02"},
        "trade": {"price": "100.01", "size": "1"},
        "book_delta": {"side": "bid", "level": 1, "price": "100.01", "size": "1"},
        "status": {"state": "open"},
        "reference": {"description": "synthetic"},
        "corporate_action": {"action": "split", "factor": "2:1"},
        "news": {"headline": "synthetic", "sentiment": 0},
    }
    return dict(typed[event_type])


def sized_payload(event_type: str, target_bytes: int) -> dict[str, Any]:
    """Build a typed payload no larger than its declared byte target."""
    payload = payload_base(event_type)
    minimum = len(json_bytes(payload))
    if target_bytes < minimum:
        raise ValueError(f"{event_type} payload target below typed minimum {minimum}")
    padded_base = len(json_bytes({**payload, "padding": ""}))
    if target_bytes >= padded_base:
        payload["padding"] = "x" * (target_bytes - padded_base)
    return payload


def envelope_fits(byte_length: int) -> bool:
    """The newline is part of the serialized 64 KiB envelope."""
    return byte_length <= MAX_ENVELOPE_BYTES


def max_record_bytes(profile: dict[str, Any], event_type: str) -> int:
    """Conservative generated line bound with longest declared identifiers."""
    traffic = profile["traffic"]
    disorder = profile["disorder"]
    last_index = traffic["event_count"] - 1
    instrument_id = f"SIM-{last_index:04d}"
    venue = max(traffic["venues"], key=lambda item: len(json_bytes(item)))
    channel = max(traffic["channels"], key=lambda item: len(json_bytes(item)))
    ingest_ns = BASE_NS + last_index * 1_000
    skew_ns = ms_to_ns(disorder["clock_skew_ms"]["max"])
    record = {
        "event_id": f"{profile['seed']}:{last_index}",
        "schema_version": "leviathan.market_event/1",
        "source": "C103_SYNTH",
        "venue": venue,
        "instrument_id": instrument_id,
        "symbol": instrument_id,
        "channel": channel,
        "event_type": event_type,
        "event_time_utc_ns": ingest_ns,
        "exchange_time_utc_ns": ingest_ns + skew_ns,
        "ingest_time_utc_ns": ingest_ns,
        "processing_time_utc_ns": ingest_ns + 1_000,
        "sequence": traffic["event_count"] * (disorder["gap_size"] + 1),
        "reconstructed": False,
        "flags": ["synthetic", "late"],
        "payload": sized_payload(event_type, traffic["payload_bytes"][event_type]["max"]),
    }
    return len(json_bytes(record)) + 1
