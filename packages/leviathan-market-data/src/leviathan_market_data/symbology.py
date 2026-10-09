"""Explicit, versioned vendor-to-instrument mapping. Unknown symbols fail closed."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, localcontext

from leviathan_market_data.schema import (
    DECIMAL_CONTEXT,
    MarketDataValueError,
    NoCopy,
    canonical_decimal,
    exact_decimal,
)


@dataclass(frozen=True, slots=True)
class InstrumentMapping(NoCopy):
    provider: str
    dataset: str
    venue: str
    native_symbol: str
    instrument_id: str
    leviathan_symbol: str
    instrument_type: str
    mapping_version: str
    tick_size: str | None = None

    def __post_init__(self) -> None:
        fields = (self.provider, self.dataset, self.venue, self.native_symbol,
                  self.instrument_id, self.leviathan_symbol, self.instrument_type,
                  self.mapping_version)
        if any(not isinstance(value, str) or not value or value.strip() != value
               for value in fields):
            raise MarketDataValueError("INVALID_MAPPING")
        if self.tick_size is not None:
            with localcontext(DECIMAL_CONTEXT):
                if exact_decimal(self.tick_size) <= 0:
                    raise MarketDataValueError("INVALID_DECIMAL")
                object.__setattr__(self, "tick_size", canonical_decimal(self.tick_size))

    @property
    def decimal_tick_size(self) -> Decimal | None:
        with localcontext(DECIMAL_CONTEXT):
            return Decimal(self.tick_size) if self.tick_size is not None else None


class MappingRegistry(NoCopy):
    def __init__(self, mappings: tuple[InstrumentMapping, ...] = ()) -> None:
        self._mappings: dict[tuple[str, str, str, str], InstrumentMapping] = {}
        for mapping in mappings:
            self.register(mapping)

    def register(self, mapping: InstrumentMapping) -> None:
        key = (mapping.provider, mapping.dataset, mapping.venue, mapping.native_symbol)
        if key in self._mappings and self._mappings[key] != mapping:
            raise ValueError("mapping already registered with a different version")
        self._mappings[key] = mapping

    def resolve(self, provider: str, dataset: str, venue: str,
                native_symbol: str) -> InstrumentMapping | None:
        return self._mappings.get((provider, dataset, venue, native_symbol))
