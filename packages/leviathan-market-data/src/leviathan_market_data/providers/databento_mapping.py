"""Session-local, fail-closed Databento instrument mapping ingestion.

The Raw Live stream is the authority for numeric instrument identifiers. A
new instance is created for each session; mappings from a closed session can
therefore never resolve records from a reconnect.
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass, replace
from typing import Final

from leviathan_market_data.symbology import InstrumentMapping, MappingRegistry

MAX_SESSION_MAPPINGS: Final = 50_000
_INT64_MAX: Final = (1 << 63) - 1
_SYMBOL_CHARS: Final = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:/-"
)


class DatabentoMappingError(ValueError):
    """Sanitized mapping error. No provider symbol or record is included."""

    _CODES = frozenset(
        {"INVALID_CONFIGURATION", "INVALID_SYMBOL_MAPPING", "MAPPING_CONFLICT", "MAPPING_CAPACITY"}
    )

    def __init__(self, code: str) -> None:
        self.code = code if type(code) is str and code in self._CODES else "INVALID_SYMBOL_MAPPING"
        super().__init__(self.code)


@dataclass(frozen=True, slots=True)
class DatabentoResolvedMappingV1:
    provider_id: int
    native_instrument_id: int
    configured_symbol: str
    raw_symbol: str
    valid_from_ns: int
    valid_to_ns: int
    mapping: InstrumentMapping
    registry: MappingRegistry


class DatabentoSessionMappingRegistry:
    """A bounded MappingRegistry index scoped to exactly one live session.

    Each validity interval owns a one-entry existing ``MappingRegistry``.
    This retains that registry's same-key conflict behavior while allowing a
    provider mapping to change without rewriting or silently replacing an
    already observed interval.
    """

    def __init__(
        self,
        *,
        session_id: str,
        dataset: str,
        stype_in: str,
        configured_symbols: tuple[str, ...],
        max_mappings: int = MAX_SESSION_MAPPINGS,
    ) -> None:
        if (
            type(session_id) is not str
            or not session_id
            or not session_id.isascii()
            or type(dataset) is not str
            or not dataset
            or not dataset.isascii()
            or type(stype_in) is not str
            or not stype_in.isascii()
            or not stype_in
            or type(configured_symbols) is not tuple
            or not configured_symbols
            or len(configured_symbols) > 2_000
            or any(not _valid_symbol(item) for item in configured_symbols)
            or len(set(configured_symbols)) != len(configured_symbols)
            or type(max_mappings) is not int
            or not 1 <= max_mappings <= MAX_SESSION_MAPPINGS
        ):
            raise DatabentoMappingError("INVALID_CONFIGURATION")
        self.session_id = session_id
        self.dataset = dataset
        self.stype_in = stype_in
        self.configured_symbols = frozenset(configured_symbols)
        self.max_mappings = max_mappings
        self._by_native: dict[tuple[int, int], list[DatabentoResolvedMappingV1]] = {}
        self._count = 0

    @property
    def mapping_count(self) -> int:
        return self._count

    @property
    def index_size(self) -> int:
        """Number of indexed provider instrument identities, including no failed inserts."""
        return len(self._by_native)

    def ingest(self, record: object) -> DatabentoResolvedMappingV1:
        """Validate a decoded SymbolMappingMsg and register its exact interval."""
        try:
            dbn = importlib.import_module("databento_dbn")
            symbol_mapping_type = dbn.SymbolMappingMsg
            undefined_timestamp = dbn.UNDEF_TIMESTAMP
        except (ImportError, AttributeError):
            raise DatabentoMappingError("INVALID_SYMBOL_MAPPING") from None
        if not isinstance(record, symbol_mapping_type):
            raise DatabentoMappingError("INVALID_SYMBOL_MAPPING")
        try:
            publisher_id = record.publisher_id
            native_id = record.instrument_id
            start_ns = record.start_ts
            end_ns = record.end_ts
            input_symbol = record.stype_in_symbol
            raw_symbol = record.stype_out_symbol
            input_type = record.stype_in
            output_type = record.stype_out
        except Exception:
            raise DatabentoMappingError("INVALID_SYMBOL_MAPPING") from None
        if type(undefined_timestamp) is not int:
            raise DatabentoMappingError("INVALID_SYMBOL_MAPPING")
        # DBN uses the unsigned timestamp sentinel for an absent interval
        # bound. The mapping domain is nonnegative Unix nanoseconds, so an
        # absent start normalizes to its lower bound (0); an absent end stays
        # at the sentinel, above every accepted event timestamp.
        if start_ns == undefined_timestamp:
            start_ns = 0
        end_is_open = end_ns == undefined_timestamp
        if (
            type(publisher_id) is not int
            or not 0 <= publisher_id <= _INT64_MAX
            or type(native_id) is not int
            or not 0 <= native_id <= _INT64_MAX
            or type(start_ns) is not int
            or type(end_ns) is not int
            or not 0 <= start_ns <= _INT64_MAX
            or not 0 <= end_ns <= (undefined_timestamp if end_is_open else _INT64_MAX)
            or not start_ns < end_ns
            or not _valid_symbol(input_symbol)
            or input_symbol not in self.configured_symbols
            or input_type.value != self.stype_in
            or not _valid_symbol(raw_symbol)
            or output_type.value != "raw_symbol"
        ):
            raise DatabentoMappingError("INVALID_SYMBOL_MAPPING")

        entry_key = (publisher_id, native_id)
        entries = self._by_native.get(entry_key, [])
        close_open_intervals: list[int] = []
        for index, existing in enumerate(entries):
            overlaps = start_ns < existing.valid_to_ns and existing.valid_from_ns < end_ns
            same = (
                existing.configured_symbol == input_symbol
                and existing.raw_symbol == raw_symbol
                and existing.valid_from_ns == start_ns
                and existing.valid_to_ns == end_ns
            )
            if same:
                return existing
            if overlaps:
                if (
                    existing.valid_to_ns == undefined_timestamp
                    and start_ns > existing.valid_from_ns
                ):
                    # A later provider remap supersedes an earlier open-ended
                    # interval. Close the old interval at the new start; do
                    # not guess that it becomes active again if the new
                    # mapping has a finite end.
                    close_open_intervals.append(index)
                else:
                    raise DatabentoMappingError("MAPPING_CONFLICT")
        if self._count >= self.max_mappings:
            raise DatabentoMappingError("MAPPING_CAPACITY")

        # Databento defines publisher_id as its dataset/venue identity. Keep it
        # explicitly namespaced instead of pretending it is a venue MIC.
        venue = f"DBN-PUB-{publisher_id}"
        version = f"live-{self.session_id}-{publisher_id}-{native_id}-{start_ns}-{end_ns}"
        mapping = InstrumentMapping(
            provider="databento",
            dataset=self.dataset,
            venue=venue,
            native_symbol=raw_symbol,
            # This is the explicitly subscribed symbol, not a guessed alias.
            instrument_id=input_symbol,
            leviathan_symbol=input_symbol,
            instrument_type="unknown",
            mapping_version=version,
        )
        registry = MappingRegistry((mapping,))
        resolved = DatabentoResolvedMappingV1(
            provider_id=publisher_id,
            native_instrument_id=native_id,
            configured_symbol=input_symbol,
            raw_symbol=raw_symbol,
            valid_from_ns=start_ns,
            valid_to_ns=end_ns,
            mapping=mapping,
            registry=registry,
        )
        for index in close_open_intervals:
            entries[index] = replace(entries[index], valid_to_ns=start_ns)
        if entry_key not in self._by_native:
            self._by_native[entry_key] = entries
        entries.append(resolved)
        entries.sort(key=lambda item: (item.valid_from_ns, item.valid_to_ns))
        self._count += 1
        return resolved

    def lookup_message(self, record: object) -> DatabentoResolvedMappingV1 | None:
        """Return the interval installed for a yielded mapping message.

        A later remap may already have closed an originally open-ended entry
        before the async consumer handles an earlier queued message. Match by
        that message's stable start/input/output identity, not its now-truncated
        end bound.
        """
        try:
            dbn = importlib.import_module("databento_dbn")
            if not isinstance(record, dbn.SymbolMappingMsg):
                return None
            publisher_id = record.publisher_id
            native_id = record.instrument_id
            start_ns = record.start_ts
            undefined_timestamp = dbn.UNDEF_TIMESTAMP
            input_symbol = record.stype_in_symbol
            raw_symbol = record.stype_out_symbol
        except Exception:
            return None
        if (
            type(undefined_timestamp) is not int
            or type(publisher_id) is not int
            or type(native_id) is not int
            or type(start_ns) is not int
            or type(input_symbol) is not str
            or type(raw_symbol) is not str
        ):
            return None
        if start_ns == undefined_timestamp:
            start_ns = 0
        matches = [
            item
            for item in self._by_native.get((publisher_id, native_id), ())
            if item.valid_from_ns == start_ns
            and item.configured_symbol == input_symbol
            and item.raw_symbol == raw_symbol
        ]
        return matches[0] if len(matches) == 1 else None

    def resolve(
        self, *, publisher_id: int, instrument_id: int, event_time_ns: int
    ) -> DatabentoResolvedMappingV1 | None:
        if (
            type(publisher_id) is not int
            or type(instrument_id) is not int
            or type(event_time_ns) is not int
            or not 0 <= publisher_id <= _INT64_MAX
            or not 0 <= instrument_id <= _INT64_MAX
            or not 0 <= event_time_ns <= _INT64_MAX
        ):
            return None
        matches = [
            item
            for item in self._by_native.get((publisher_id, instrument_id), ())
            if item.valid_from_ns <= event_time_ns < item.valid_to_ns
        ]
        return matches[0] if len(matches) == 1 else None


def _valid_symbol(value: object) -> bool:
    return (
        type(value) is str
        and 1 <= len(value) <= 32
        and value.isascii()
        and all(character in _SYMBOL_CHARS for character in value)
    )


__all__ = [
    "MAX_SESSION_MAPPINGS",
    "DatabentoMappingError",
    "DatabentoResolvedMappingV1",
    "DatabentoSessionMappingRegistry",
]
