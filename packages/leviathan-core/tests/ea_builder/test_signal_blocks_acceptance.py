"""Independent EA-001b acceptance cases.

Requirement-to-case matrix (EA-001b cycle 0; synthetic values only):
- Compare operators and equality: `test_compare_uses_exact_decimal_operator_truth_table`.
- Crossover boundaries: `test_crossover_uses_exact_finalized_bar_predicates`.
- Finalized/as-of, no-lookahead and warmup: numeric factory, series, warmup and asymmetric
  warmup-availability cases below.
- Unit/scope/bar compatibility: compare and crossover mismatch cases below.
- Deterministic replay and signal-only outputs: replay and signal-record cases below.
- Issuance and tamper boundaries: issuance and sealed-record cases below.
- Catalog extension: `test_signal_catalog_extension_is_stable_and_non_mutating`.
- MT4/MT5 parity and reserved additions: mapping and static-scan cases below.
- Recovery asset negatives: sanitized metadata fixture case below.
- This slice grants no order authority: signal-record and MQL fragment cases below.

The worker must provide the frozen source fingerprint before this suite is executed.
"""

from __future__ import annotations

import copy
import json
import pickle
import re
from decimal import Decimal
from pathlib import Path

import pytest
from pydantic import BaseModel

from leviathan_core.ea_builder import BlockCatalogV1, standard_catalog_v1
from leviathan_core.ea_builder.mql4_signal_export import (
    compare_expression_v1 as mql4_compare,
)
from leviathan_core.ea_builder.mql4_signal_export import (
    crossover_expression_v1 as mql4_crossover,
)
from leviathan_core.ea_builder.mql4_signal_export import (
    signal_emission_v1 as mql4_emit,
)
from leviathan_core.ea_builder.mql5_signal_export import (
    compare_expression_v1 as mql5_compare,
)
from leviathan_core.ea_builder.mql5_signal_export import (
    crossover_expression_v1 as mql5_crossover,
)
from leviathan_core.ea_builder.mql5_signal_export import (
    signal_emission_v1 as mql5_emit,
)
from leviathan_core.ea_builder.signal_blocks import (
    EntrySignalV1,
    ExitSignalV1,
    SignalBlockError,
    emit_entry_signal_v1,
    emit_exit_signal_v1,
    evaluate_compare_v1,
    evaluate_crossover_v1,
    make_numeric_series_v1,
    make_numeric_v1,
)
from leviathan_core.ea_builder.signal_catalog import (
    extend_signal_catalog_v1,
    signal_block_definitions_v1,
    signal_catalog_v1,
)
from leviathan_core.seal import SealError, require, verify

REVISION = "a" * 64
DIGEST = "b" * 64
ASOF = 1_800_000_000_000_000_000
SYMBOL = "EURUSD"
TIMEFRAME = "M5"
BAR_INDEX = 20
TEST_DIR = Path(__file__).parent / "fixtures" / "signal_blocks"
FORBIDDEN = re.compile(
    r"\b(?:OrderSend(?:Async)?|OrderClose(?:By)?|OrderModify|OrderDelete|"
    r"PositionOpen|PositionClose(?:Partial|By)?|PositionModify|CTrade|"
    r"MqlTradeRequest|Buy(?:Limit|Stop)?|Sell(?:Limit|Stop)?)\b|"
    r"\btrade\s*\.|\b(?:WebRequest|ShellExecute)\s*\(|"
    r"^\s*#\s*(?:define|import|include)\b",
    re.IGNORECASE | re.MULTILINE,
)


def numeric(
    value: str | int,
    *,
    unit: str = "price",
    symbol: str = SYMBOL,
    timeframe: str = TIMEFRAME,
    bar_id: str = "bar_20",
    bar_index: int = BAR_INDEX,
    asof_ns: int = ASOF,
    available_ns: int = ASOF,
    event_ns: int = ASOF - 2,
    effective_ns: int = ASOF - 1,
    identity_id: str = "synthetic_feed_v1",
    identity_kind: str = "source",
):
    return make_numeric_v1(
        schema_version="1",
        value=Decimal(str(value)),
        unit=unit,
        identity_kind=identity_kind,  # type: ignore[arg-type]
        identity_id=identity_id,
        identity_version=1,
        identity_digest=DIGEST,
        symbol=symbol,
        timeframe=timeframe,
        bar_id=bar_id,
        bar_index=bar_index,
        event_ns=event_ns,
        effective_ns=effective_ns,
        available_ns=available_ns,
        asof_ns=asof_ns,
        finalized=True,
    )


def series(
    previous: str | int | None,
    current: str | int,
    *,
    unit: str = "price",
    symbol: str = SYMBOL,
    timeframe: str = TIMEFRAME,
    previous_bar_id: str = "bar_19",
    current_bar_id: str = "bar_20",
    previous_index: int = BAR_INDEX - 1,
    current_index: int = BAR_INDEX,
    asof_ns: int = ASOF,
    available_ns: int | None = None,
    identity_id: str = "synthetic_feature_sma",
):
    availability = asof_ns if available_ns is None else available_ns
    prior = (
        None
        if previous is None
        else numeric(
            previous,
            unit=unit,
            symbol=symbol,
            timeframe=timeframe,
            bar_id=previous_bar_id,
            bar_index=previous_index,
            asof_ns=asof_ns,
            available_ns=availability,
            identity_id=identity_id,
        )
    )
    now = numeric(
        current,
        unit=unit,
        symbol=symbol,
        timeframe=timeframe,
        bar_id=current_bar_id,
        bar_index=current_index,
        asof_ns=asof_ns,
        available_ns=availability,
        identity_id=identity_id,
    )
    return make_numeric_series_v1(
        symbol=symbol,
        timeframe=timeframe,
        current=now,
        previous=prior,
        asof_ns=asof_ns,
    )


def compare(operation: str, left: str | int, right: str | int, **scope: object):
    return evaluate_compare_v1(
        operation,  # type: ignore[arg-type]
        numeric(left, **scope),
        numeric(right, **scope),
        graph_revision_hash=REVISION,
        node_id="compare_node",
    )


def cross(direction: str, left: tuple[object, object], right: tuple[object, object]):
    return evaluate_crossover_v1(
        direction,  # type: ignore[arg-type]
        series(left[0], left[1]),
        series(right[0], right[1]),
        graph_revision_hash=REVISION,
        node_id="cross_node",
    )


def test_compare_uses_exact_decimal_operator_truth_table() -> None:
    cases = (
        ("gt", "1.250000000000000000000000000001", "1.25", True),
        ("lt", "1.249999999999999999999999999999", "1.25", True),
        ("ge", "1.25", "1.25", True),
        ("le", "1.25", "1.25", True),
        ("gt", "1.25", "1.25", False),
        ("lt", "1.25", "1.25", False),
        ("ge", "1.249", "1.25", False),
        ("le", "1.251", "1.25", False),
    )
    for operation, left, right, expected in cases:
        result = compare(operation, left, right)
        assert result.status == "ready"
        assert type(result.value) is bool
        assert result.value is expected
        assert result.operation == operation


def test_crossover_uses_exact_finalized_bar_predicates() -> None:
    cases = (
        ("above", ("1", "2"), ("1", "1"), True),  # prior equality is inclusive
        ("above", ("2", "3"), ("1", "2"), False),  # already above before
        ("above", ("1", "1"), ("1", "1"), False),  # current equality is strict
        ("below", ("1", "0"), ("1", "1"), True),  # prior equality is inclusive
        ("below", ("0", "0"), ("1", "1"), False),  # already below before
        ("below", ("1", "1"), ("1", "1"), False),  # current equality is strict
    )
    for direction, left, right, expected in cases:
        result = cross(direction, left, right)
        assert result.status == "ready"
        assert result.value is expected


def test_numeric_factory_rejects_unfinalized_or_late_values() -> None:
    feature_value = numeric("1.125", identity_kind="feature")
    assert feature_value.identity_kind == "feature"
    assert feature_value.finalized is True

    with pytest.raises(SignalBlockError) as unfinalized:
        make_numeric_v1(
            schema_version="1",
            value=Decimal("1"),
            unit="price",
            identity_kind="source",
            identity_id="synthetic_feed",
            identity_version=1,
            identity_digest=DIGEST,
            symbol=SYMBOL,
            timeframe=TIMEFRAME,
            bar_id="forming_bar",
            bar_index=1,
            event_ns=1,
            effective_ns=1,
            available_ns=2,
            asof_ns=2,
            finalized=False,  # type: ignore[arg-type]
        )
    assert unfinalized.value.code == "INVALID_SIGNAL_MODEL"

    with pytest.raises(SignalBlockError) as late:
        numeric("1", available_ns=ASOF + 1)
    assert late.value.code == "INVALID_SIGNAL_MODEL"
    assert str(ASOF + 1) not in str(late.value)
    assert all(str(ASOF + 1) not in str(item) for item in late.value.errors())

    with pytest.raises(SignalBlockError) as chronology:
        numeric("1", effective_ns=ASOF + 1)
    assert chronology.value.code == "INVALID_SIGNAL_MODEL"


def test_crossover_warmup_is_not_ready_and_never_emits() -> None:
    left = series(None, "2")
    right = series("1", "1")
    condition = evaluate_crossover_v1(
        "above", left, right, graph_revision_hash=REVISION, node_id="warmup_cross"
    )
    assert condition.status == "not_ready"
    assert condition.value is None
    assert emit_entry_signal_v1(condition, signal_key="entry_v1") is None
    assert emit_exit_signal_v1(condition, signal_key="exit_v1") is None


def test_asymmetric_warmup_keeps_latest_available_input_time() -> None:
    left_current = numeric(
        "2",
        asof_ns=10,
        available_ns=1,
        event_ns=0,
        effective_ns=0,
    )
    right_previous = numeric(
        "1",
        bar_id="bar_19",
        bar_index=BAR_INDEX - 1,
        asof_ns=10,
        available_ns=8,
        event_ns=6,
        effective_ns=7,
    )
    right_current = numeric(
        "1",
        asof_ns=10,
        available_ns=9,
        event_ns=8,
        effective_ns=8,
    )
    left = make_numeric_series_v1(
        symbol=SYMBOL,
        timeframe=TIMEFRAME,
        current=left_current,
        previous=None,
        asof_ns=10,
    )
    right = make_numeric_series_v1(
        symbol=SYMBOL,
        timeframe=TIMEFRAME,
        current=right_current,
        previous=right_previous,
        asof_ns=10,
    )

    condition = evaluate_crossover_v1(
        "above", left, right, graph_revision_hash=REVISION, node_id="asymmetric_warmup"
    )
    assert condition.status == "not_ready"
    assert condition.value is None
    assert condition.available_ns == 9
    assert emit_entry_signal_v1(condition, signal_key="warmup") is None


def test_series_rejects_scope_or_cursor_mismatch() -> None:
    current = numeric("2")
    previous_wrong_scope = numeric("1", symbol="GBPUSD", bar_id="bar_19", bar_index=BAR_INDEX - 1)
    with pytest.raises(SignalBlockError) as scope:
        make_numeric_series_v1(
            symbol=SYMBOL,
            timeframe=TIMEFRAME,
            current=current,
            previous=previous_wrong_scope,
            asof_ns=ASOF,
        )
    assert scope.value.code == "INVALID_SIGNAL_MODEL"

    previous_wrong_cursor = numeric(
        "1",
        bar_id="bar_19",
        bar_index=BAR_INDEX - 1,
        asof_ns=ASOF - 1,
        available_ns=ASOF - 1,
    )
    with pytest.raises(SignalBlockError) as cursor:
        make_numeric_series_v1(
            symbol=SYMBOL,
            timeframe=TIMEFRAME,
            current=current,
            previous=previous_wrong_cursor,
            asof_ns=ASOF,
        )
    assert cursor.value.code == "INVALID_SIGNAL_MODEL"


def test_compare_rejects_unit_scope_bar_or_cursor_mismatch() -> None:
    left = numeric("2")
    incompatible = (
        numeric("1", unit="ticks"),
        numeric("1", symbol="GBPUSD"),
        numeric("1", timeframe="M15"),
        numeric("1", bar_id="another_bar"),
        numeric("1", bar_index=BAR_INDEX + 1),
        numeric("1", asof_ns=ASOF - 1, available_ns=ASOF - 1),
    )
    for right in incompatible:
        with pytest.raises(SignalBlockError) as caught:
            evaluate_compare_v1("gt", left, right, graph_revision_hash=REVISION, node_id="cmp")
        assert caught.value.code == "INCOMPATIBLE_SIGNAL_INPUTS"
        assert "EURUSD" not in str(caught.value)
        assert set(caught.value.errors()[0]) <= {"code", "field", "type"}


def test_crossover_rejects_misaligned_series() -> None:
    valid_left = series("1", "2")
    cases = (
        series("1", "2", symbol="GBPUSD"),
        series("1", "2", timeframe="M15"),
        series("1", "2", unit="ticks"),
        series("1", "2", current_bar_id="bar_21"),
        series(
            "1",
            "2",
            previous_bar_id="bar_20",
            current_bar_id="bar_21",
            previous_index=BAR_INDEX,
            current_index=BAR_INDEX + 1,
        ),
        series("1", "2", asof_ns=ASOF - 1, available_ns=ASOF - 1),
    )
    for incompatible in cases:
        with pytest.raises(SignalBlockError) as caught:
            evaluate_crossover_v1(
                "above",
                valid_left,
                incompatible,
                graph_revision_hash=REVISION,
                node_id="cross",
            )
        assert caught.value.code == "INCOMPATIBLE_SIGNAL_INPUTS"

    broken_pair = series("1", "2", previous_bar_id="wrong_previous")
    with pytest.raises(SignalBlockError) as prior_id:
        evaluate_crossover_v1(
            "above", broken_pair, valid_left, graph_revision_hash=REVISION, node_id="cross"
        )
    assert prior_id.value.code == "INCOMPATIBLE_SIGNAL_INPUTS"

    non_adjacent_current = numeric("2", bar_id="bar_20", bar_index=BAR_INDEX)
    non_adjacent_prior = numeric("1", bar_id="bar_18", bar_index=BAR_INDEX - 2)
    with pytest.raises(SignalBlockError) as adjacency:
        make_numeric_series_v1(
            symbol=SYMBOL,
            timeframe=TIMEFRAME,
            current=non_adjacent_current,
            previous=non_adjacent_prior,
            asof_ns=ASOF,
        )
    assert adjacency.value.code == "INVALID_SIGNAL_MODEL"


def test_evaluation_and_signal_replay_are_deterministic_and_signal_only() -> None:
    left = numeric("2", identity_id="synthetic_sma_fast")
    right = numeric("1", identity_id="synthetic_sma_slow")
    first = evaluate_compare_v1("gt", left, right, graph_revision_hash=REVISION, node_id="entry")
    replay = evaluate_compare_v1("gt", left, right, graph_revision_hash=REVISION, node_id="entry")
    assert first.model_dump_json() == replay.model_dump_json()
    assert verify(first, "ea001b.bool.v1")
    require(first, "ea001b.bool.v1")

    entry = emit_entry_signal_v1(first, signal_key="cross_above")
    entry_replay = emit_entry_signal_v1(first, signal_key="cross_above")
    exit_record = emit_exit_signal_v1(first, signal_key="risk_exit")
    assert isinstance(entry, EntrySignalV1)
    assert isinstance(exit_record, ExitSignalV1)
    assert entry is not None and entry_replay is not None and exit_record is not None
    assert verify(entry, "ea001b.entry_signal.v1")
    assert verify(exit_record, "ea001b.exit_signal.v1")
    assert entry.model_dump_json() == entry_replay.model_dump_json()
    assert entry.deduplication_key == (
        REVISION,
        "entry",
        SYMBOL,
        TIMEFRAME,
        "bar_20",
        "cross_above",
    )
    assert entry.graph_revision_hash == REVISION
    assert entry.finalized_bar_id == "bar_20"
    assert entry.event_ns <= entry.available_ns
    assert entry.effective_ns <= entry.available_ns
    assert first.asof_ns == ASOF
    assert first.available_ns <= first.asof_ns
    next_revision = evaluate_compare_v1(
        "gt", left, right, graph_revision_hash="c" * 64, node_id="entry"
    )
    revised_entry = emit_entry_signal_v1(next_revision, signal_key="cross_above")
    assert revised_entry is not None
    assert revised_entry.deduplication_key != entry.deduplication_key
    assert (
        emit_entry_signal_v1(
            evaluate_compare_v1("lt", left, right, graph_revision_hash=REVISION, node_id="false"),
            signal_key="no_entry",
        )
        is None
    )


def test_only_issued_inputs_can_be_evaluated() -> None:
    issued = numeric("2")
    forged = type(issued)(**issued.model_dump())
    assert not verify(forged, "ea001b.numeric.v1")
    with pytest.raises(SignalBlockError) as caught:
        evaluate_compare_v1(
            "gt", forged, issued, graph_revision_hash=REVISION, node_id="forged_input"
        )
    assert caught.value.code == "UNISSUED_SIGNAL_INPUT"


def test_sealed_numeric_copy_pickle_and_reinitialization_cannot_gain_authority() -> None:
    issued = numeric("2")
    with pytest.raises(SealError):
        issued.value = Decimal("99")
    with pytest.raises(SealError):
        del issued.value
    for copier in (copy.copy, copy.deepcopy):
        with pytest.raises(SealError):
            copier(issued)
    with pytest.raises(SealError):
        pickle.dumps(issued)

    # Pydantic's copy/validation routes may either be denied at construction or
    # produce an unissued value; neither may cross the evaluator boundary.
    for make_unissued in (
        lambda: issued.model_copy(update={"value": Decimal("99")}),
        lambda: type(issued).model_validate(issued.model_dump()),
    ):
        try:
            copied = make_unissued()
        except SealError:
            continue
        assert not verify(copied, "ea001b.numeric.v1")
        with pytest.raises(SignalBlockError) as caught:
            evaluate_compare_v1(
                "gt", copied, issued, graph_revision_hash=REVISION, node_id="copy_boundary"
            )
        assert caught.value.code == "UNISSUED_SIGNAL_INPUT"

    try:
        BaseModel.__init__(issued, **issued.model_dump())
    except SealError:
        pass
    else:
        with pytest.raises(SignalBlockError) as reinitialized:
            evaluate_compare_v1(
                "gt", issued, numeric("1"), graph_revision_hash=REVISION, node_id="reinit"
            )
        assert reinitialized.value.code == "UNISSUED_SIGNAL_INPUT"

    try:
        BaseModel.__setstate__(issued, {"value": Decimal("99")})
    except SealError:
        return
    with pytest.raises(SignalBlockError) as tampered:
        evaluate_compare_v1(
            "gt", issued, numeric("1"), graph_revision_hash=REVISION, node_id="state"
        )
    assert tampered.value.code == "UNISSUED_SIGNAL_INPUT"


def test_tampered_issued_condition_cannot_be_emitted() -> None:
    condition = compare("gt", "2", "1")
    try:
        object.__setattr__(condition, "value", False)
    except SealError as denied:
        assert "SEAL_FORBIDDEN_OPERATION" in str(denied)
    else:
        with pytest.raises(SignalBlockError) as caught:
            emit_entry_signal_v1(condition, signal_key="must_not_emit")
        assert caught.value.code == "UNISSUED_SIGNAL_INPUT"
        assert "False" not in str(caught.value)


def test_signal_records_have_no_order_or_route_fields() -> None:
    condition = compare("gt", "2", "1")
    entry = emit_entry_signal_v1(condition, signal_key="entry_signal")
    exit_record = emit_exit_signal_v1(condition, signal_key="exit_signal")
    assert entry is not None and exit_record is not None
    expected_fields = {
        "schema_version",
        "graph_revision_hash",
        "signal_key",
        "symbol",
        "timeframe",
        "finalized_bar_id",
        "event_ns",
        "effective_ns",
        "available_ns",
        "source_node_id",
    }
    assert set(EntrySignalV1.model_fields) == expected_fields
    assert set(ExitSignalV1.model_fields) == expected_fields


def test_signal_catalog_extension_is_stable_and_non_mutating() -> None:
    definitions = signal_catalog_v1()
    assert definitions == signal_block_definitions_v1()
    ids = tuple(item.block_id for item in definitions)
    assert ids == ("compare.v1", "crossover.v1", "entry_signal.v1", "exit_signal.v1")

    base = standard_catalog_v1()
    before_ids = tuple(item.block_id for item in base.blocks)
    extended = extend_signal_catalog_v1(base)
    extended_replay = extend_signal_catalog_v1(base)
    assert tuple(item.block_id for item in base.blocks) == before_ids
    assert tuple(item.block_id for item in extended.blocks[-4:]) == ids
    assert extended.canonical_digest() == extended_replay.canonical_digest()

    conflicting = BlockCatalogV1(
        catalog_id="synthetic_conflict",
        version=1,
        blocks=(definitions[0],),
    )
    with pytest.raises(SignalBlockError) as caught:
        extend_signal_catalog_v1(conflicting)
    assert caught.value.code == "CATALOG_CONFLICT"
    assert "compare.v1" not in str(caught.value)


def test_mql4_and_mql5_render_equivalent_predicates() -> None:
    operators = {"gt": ">", "lt": "<", "ge": ">=", "le": "<="}
    for operation, token in operators.items():
        expected = f"(fast_now {token} slow_now)"
        assert mql4_compare(operation, "fast_now", "slow_now") == expected
        assert mql5_compare(operation, "fast_now", "slow_now") == expected

    above = "(fast_now > slow_now && fast_prior <= slow_prior)"
    below = "(fast_now < slow_now && fast_prior >= slow_prior)"
    refs = {
        "left_current_ref": "fast_now",
        "right_current_ref": "slow_now",
        "left_previous_ref": "fast_prior",
        "right_previous_ref": "slow_prior",
    }
    assert mql4_crossover("above", **refs) == above
    assert mql5_crossover("above", **refs) == above
    assert mql4_crossover("below", **refs) == below
    assert mql5_crossover("below", **refs) == below

    output4 = mql4_emit("entry", **emission_args())
    output5 = mql5_emit("entry", **emission_args())
    assert output4 == output5
    assert 'kind = "entry"' in output4
    assert 'signal_key = "synthetic_entry"' in output4
    assert "emit = (condition)" in output4


def emission_args() -> dict[str, str]:
    return {
        "condition_ref": "condition",
        "signal_key": "synthetic_entry",
        "graph_revision_hash": REVISION,
        "symbol_ref": "symbol_value",
        "timeframe_ref": "timeframe_value",
        "finalized_bar_id_ref": "finalized_bar_id",
        "event_ns_ref": "event_time",
        "effective_ns_ref": "effective_time",
        "available_ns_ref": "available_time",
        "source_node_id": "entry_node",
    }


def test_mql_mappings_reject_reserved_and_order_capability_names() -> None:
    reserved = (
        "LEVIATHAN_MAGIC",
        "signal_0",
        "handle_0",
        "lv_internal",
        "PERIOD_M5",
        "double",
        "input",
        "if",
        "return",
        "OrderSend",
        "OrderSendAsync",
        "CTrade",
        "PositionClose",
        "Buy",
    )
    for renderer in (mql4_compare, mql5_compare):
        for name in reserved:
            with pytest.raises(SignalBlockError) as caught:
                renderer("gt", name, "safe_value")
            assert caught.value.code == "RESERVED_NAME"
            assert name not in str(caught.value)
    for emitter in (mql4_emit, mql5_emit):
        for name in reserved:
            args = emission_args()
            args["condition_ref"] = name
            with pytest.raises(SignalBlockError) as caught:
                emitter("entry", **args)
            assert caught.value.code == "RESERVED_NAME"
            assert name not in str(caught.value)

    mql5_follow_up = ("interface", "matrix", "vector", "complex", "export", "dynamic_cast")
    for name in mql5_follow_up:
        with pytest.raises(SignalBlockError) as caught:
            mql5_compare("gt", name, "safe_value")
        assert caught.value.code == "RESERVED_NAME"
        assert name not in str(caught.value)

    bad_expression = "fast_now); OrderSend(); (slow_now"
    with pytest.raises(SignalBlockError) as mql4_error:
        mql4_compare("gt", bad_expression, "slow_now")
    assert mql4_error.value.code == "RESERVED_NAME"
    assert bad_expression not in str(mql4_error.value)
    with pytest.raises(SignalBlockError) as mql5_error:
        mql5_compare("gt", "fast_now", bad_expression)
    assert mql5_error.value.code == "RESERVED_NAME"
    assert bad_expression not in str(mql5_error.value)


def test_mql_fragments_have_no_order_trade_or_bridge_capability() -> None:
    fragments = []
    for compare_mapper, cross_mapper, emit_mapper in (
        (mql4_compare, mql4_crossover, mql4_emit),
        (mql5_compare, mql5_crossover, mql5_emit),
    ):
        fragments.extend(
            compare_mapper(operation, "left_value", "right_value")
            for operation in ("gt", "lt", "ge", "le")
        )
        fragments.extend(
            cross_mapper(
                direction,
                left_current_ref="left_now",
                right_current_ref="right_now",
                left_previous_ref="left_prior",
                right_previous_ref="right_prior",
            )
            for direction in ("above", "below")
        )
        fragments.extend(emit_mapper(kind, **emission_args()) for kind in ("entry", "exit"))
    generated = "\n".join(fragments)
    assert FORBIDDEN.search(generated) is None
    assert "OrderSend" not in generated
    assert "trade." not in generated.lower()
    assert "WebRequest" not in generated
    assert "ShellExecute" not in generated


def test_asset_hazard_fixtures_remain_negative_metadata() -> None:
    expected = {
        "mtr-conflicting-variants.json": {"conflict", "failed_oos", "latency_loss"},
        "bitcoin-course-unverified-rights.json": {"unverified_rights", "source_code"},
        "kinnobot-parameter-only.json": {"parameter_only", "unresolved_logic"},
    }
    for filename, hazards in expected.items():
        fixture = json.loads((TEST_DIR / filename).read_text(encoding="utf-8"))
        assert fixture["synthetic"] is True
        assert fixture["auto_codegen_eligible"] is False
        assert hazards.issubset(set(fixture["hazards"]))
        assert fixture["reviewed_signal_rules"] == []
        assert fixture["source_payload_included"] is False
        assert not {"source", "source_text", "source_code_body", "payload", "binary"}.intersection(
            fixture
        )
