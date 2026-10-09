"""Fake DBN mapping records exercise session-local symbol resolution."""

from __future__ import annotations

import pytest
from databento_dbn import UNDEF_TIMESTAMP, Action, Side, SType, SymbolMappingMsg, TradeMsg

from leviathan_market_data.normalization import Normalizer
from leviathan_market_data.providers.databento_live import (
    DatabentoLiveError,
    DatabentoLiveSession,
)
from leviathan_market_data.providers.databento_mapping import (
    DatabentoMappingError,
    DatabentoSessionMappingRegistry,
)


def _mapping(
    *,
    publisher_id: int = 1,
    instrument_id: int = 42,
    input_symbol: str = "SYN.CONT",
    raw_symbol: str = "SYNM7",
    start_ns: int = 100,
    end_ns: int = 200,
) -> SymbolMappingMsg:
    return SymbolMappingMsg(
        publisher_id=publisher_id,
        instrument_id=instrument_id,
        ts_event=100 if start_ns == UNDEF_TIMESTAMP else start_ns,
        stype_in=SType.CONTINUOUS,
        stype_in_symbol=input_symbol,
        stype_out=SType.RAW_SYMBOL,
        stype_out_symbol=raw_symbol,
        start_ts=start_ns,
        end_ts=end_ns,
    )


def _registry(session_id: str = "session-a") -> DatabentoSessionMappingRegistry:
    return DatabentoSessionMappingRegistry(
        session_id=session_id,
        dataset="GLBX.MDP3",
        stype_in="continuous",
        configured_symbols=("SYN.CONT",),
    )


def test_live_symbol_mapping_msg_feeds_existing_mapping_registry() -> None:
    registry = _registry()
    mapped = registry.ingest(_mapping())

    assert mapped.configured_symbol == "SYN.CONT"
    assert mapped.raw_symbol == "SYNM7"
    assert mapped.provider_id == 1
    assert mapped.native_instrument_id == 42
    assert mapped.mapping.venue == "DBN-PUB-1"
    assert mapped.registry.resolve("databento", "GLBX.MDP3", "DBN-PUB-1", "SYNM7") == (
        mapped.mapping
    )


def test_unknown_id_and_out_of_interval_never_resolve() -> None:
    registry = _registry()
    registry.ingest(_mapping())

    assert registry.resolve(publisher_id=1, instrument_id=99, event_time_ns=150) is None
    assert registry.resolve(publisher_id=1, instrument_id=42, event_time_ns=99) is None
    assert registry.resolve(publisher_id=1, instrument_id=42, event_time_ns=200) is None


def test_mapping_rolls_are_interval_scoped_and_conflicts_fail_closed() -> None:
    registry = _registry()
    first = registry.ingest(_mapping(start_ns=100, end_ns=150))
    second = registry.ingest(_mapping(raw_symbol="SYNZ7", start_ns=150, end_ns=200))

    assert registry.resolve(publisher_id=1, instrument_id=42, event_time_ns=149) == first
    assert registry.resolve(publisher_id=1, instrument_id=42, event_time_ns=150) == second
    with pytest.raises(DatabentoMappingError) as error:
        registry.ingest(_mapping(raw_symbol="OTHER", start_ns=140, end_ns=170))
    assert error.value.code == "MAPPING_CONFLICT"
    assert str(error.value) == "MAPPING_CONFLICT"


def test_open_ended_mapping_is_closed_by_later_remap() -> None:
    registry = _registry()
    first_record = _mapping(start_ns=100, end_ns=UNDEF_TIMESTAMP)
    registry.ingest(first_record)

    later_record = _mapping(raw_symbol="SYNZ7", start_ns=150, end_ns=UNDEF_TIMESTAMP)
    registry.ingest(later_record)

    original_message_mapping = registry.lookup_message(first_record)
    assert original_message_mapping is not None
    assert original_message_mapping.valid_to_ns == 150
    assert registry.lookup_message(later_record) is not None
    before_roll = registry.resolve(publisher_id=1, instrument_id=42, event_time_ns=149)
    at_roll = registry.resolve(publisher_id=1, instrument_id=42, event_time_ns=150)
    after_roll = registry.resolve(publisher_id=1, instrument_id=42, event_time_ns=10_000)
    assert before_roll is not None and before_roll.raw_symbol == "SYNM7"
    assert before_roll.valid_to_ns == 150
    assert at_roll is not None and at_roll.raw_symbol == "SYNZ7"
    assert after_roll == at_roll
    assert registry.mapping_count == 2


def test_undefined_start_is_open_from_timestamp_domain_origin() -> None:
    registry = _registry()

    mapping = registry.ingest(_mapping(start_ns=UNDEF_TIMESTAMP, end_ns=200))

    assert mapping.valid_from_ns == 0
    assert registry.resolve(publisher_id=1, instrument_id=42, event_time_ns=0) == mapping
    assert registry.resolve(publisher_id=1, instrument_id=42, event_time_ns=199) == mapping
    assert registry.resolve(publisher_id=1, instrument_id=42, event_time_ns=200) is None


@pytest.mark.parametrize(
    ("start_ns", "end_ns"),
    [(100, UNDEF_TIMESTAMP - 1), (200, 100)],
)
def test_non_sentinel_garbage_and_reversed_mapping_intervals_stay_invalid(
    start_ns: int, end_ns: int
) -> None:
    with pytest.raises(DatabentoMappingError) as error:
        _registry().ingest(_mapping(start_ns=start_ns, end_ns=end_ns))
    assert error.value.code == "INVALID_SYMBOL_MAPPING"


def test_unconfigured_input_symbol_is_rejected_without_echo() -> None:
    registry = _registry()
    with pytest.raises(DatabentoMappingError) as error:
        registry.ingest(_mapping(input_symbol="CALLER-CHOSEN"))
    assert error.value.code == "INVALID_SYMBOL_MAPPING"
    assert "CALLER-CHOSEN" not in str(error.value)


def test_new_session_does_not_reuse_old_session_mappings() -> None:
    prior = _registry("session-old")
    prior.ingest(_mapping())
    replacement = _registry("session-new")

    assert replacement.mapping_count == 0
    assert replacement.resolve(publisher_id=1, instrument_id=42, event_time_ns=150) is None


def test_failed_mapping_inserts_cannot_grow_unbounded_session_index() -> None:
    registry = DatabentoSessionMappingRegistry(
        session_id="bounded-session",
        dataset="GLBX.MDP3",
        stype_in="continuous",
        configured_symbols=("SYN.CONT",),
        max_mappings=1,
    )
    registry.ingest(_mapping())

    for instrument_id in range(1_000, 2_000):
        with pytest.raises(DatabentoMappingError) as error:
            registry.ingest(_mapping(instrument_id=instrument_id))
        assert error.value.code == "MAPPING_CAPACITY"

    assert registry.mapping_count == 1
    assert registry.index_size == 1


class _Socket:
    def __init__(self) -> None:
        self._chunks = [b"mapping", b"data", b"unmapped", b""]

    async def read_line(self, _maximum: int) -> bytes:
        raise AssertionError("session is already established")

    async def write(self, _data: bytes) -> None:
        raise AssertionError("session is already established")

    async def read_chunk(self, _maximum: int) -> bytes:
        return self._chunks.pop(0)

    async def close(self) -> None:
        return None


class _Decoder:
    def __init__(self) -> None:
        self._records = [
            [_mapping()],
            [
                TradeMsg(
                    publisher_id=1,
                    instrument_id=42,
                    ts_event=120,
                    price=1_000_000_000,
                    size=1,
                    action=Action.TRADE,
                    side=Side.BID,
                    depth=0,
                    ts_recv=121,
                )
            ],
            [
                TradeMsg(
                    publisher_id=1,
                    instrument_id=99,
                    ts_event=120,
                    price=1_000_000_000,
                    size=1,
                    action=Action.TRADE,
                    side=Side.BID,
                    depth=0,
                    ts_recv=121,
                )
            ],
        ]

    def write_and_decode(self, _chunk: bytes) -> list[object]:
        return self._records.pop(0)


@pytest.mark.asyncio
async def test_session_ingests_mapping_before_records_and_drops_unmapped_ids() -> None:
    session = DatabentoLiveSession(
        socket=_Socket(),
        decoder=_Decoder(),
        session_id="session-a",
        mapping_registry=_registry(),
    )
    output: list[object] = []
    with pytest.raises(DatabentoLiveError) as error:
        async for record in session.records():
            output.append(record)

    assert error.value.code == "SESSION_CLOSED"
    assert len(output) == 2
    assert isinstance(output[0], SymbolMappingMsg)
    assert isinstance(output[1], TradeMsg)
    assert session.mapping_for(output[1]) is not None
    assert session.unmapped_record_count == 1
    assert session.mapping_degraded is True


def test_mapped_trade_normalizes_only_to_live_supplied_and_configured_identity() -> None:
    registry = _registry()
    mapped = registry.ingest(_mapping())
    trade = TradeMsg(
        publisher_id=1,
        instrument_id=42,
        ts_event=120,
        price=125_500_000_000,
        size=2,
        action=Action.TRADE,
        side=Side.BID,
        depth=0,
        ts_recv=121,
        sequence=3,
    )
    session = DatabentoLiveSession(
        socket=_Socket(),
        decoder=_Decoder(),
        session_id="session-a",
        mapping_registry=registry,
    )

    vendor_record = session.vendor_record_for(trade, received_time_ns=122)
    event = Normalizer(mapped.registry).normalize(vendor_record, now_ns=122)

    assert event.instrument_id == "SYN.CONT"
    assert event.leviathan_symbol == "SYN.CONT"
    assert event.native_symbol == "SYNM7"
    assert event.venue == "DBN-PUB-1"
    assert event.native_provenance.native_instrument_id == 42
    assert event.payload.kind == "trade"
    assert event.payload.price.value == "125.5"
