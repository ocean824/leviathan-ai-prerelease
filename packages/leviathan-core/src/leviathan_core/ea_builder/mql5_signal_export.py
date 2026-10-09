"""Pure MT5 signal-expression and local emission-fragment mappings."""

from __future__ import annotations

import hashlib
import re
from typing import Literal

from leviathan_core.ea_builder.signal_blocks import CompareOpV1, CrossDirectionV1, SignalBlockError

_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z", re.ASCII)
_ID = re.compile(r"[A-Za-z_][A-Za-z0-9_.:-]{0,127}\Z", re.ASCII)
_HASH = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_MQL5_RESERVED_WORDS_V1 = frozenset(
    {
        "and",
        "array",
        "as",
        "assert",
        "auto",
        "bool",
        "break",
        "case",
        "char",
        "class",
        "color",
        "complex",
        "const",
        "continue",
        "datetime",
        "default",
        "delete",
        "do",
        "double",
        "dynamic_cast",
        "else",
        "enum",
        "event",
        "export",
        "extern",
        "false",
        "final",
        "float",
        "for",
        "group",
        "handle_0",
        "if",
        "import",
        "include",
        "input",
        "int",
        "interface",
        "LEVIATHAN_MAGIC",
        "long",
        "LVSignalEmissionV1",
        "matrix",
        "namespace",
        "new",
        "not",
        "null",
        "offsetof",
        "OnCalculate",
        "OnDeinit",
        "OnInit",
        "OnTick",
        "OnTimer",
        "OrderSend",
        "OrderSendAsync",
        "OrderClose",
        "OrderModify",
        "OrderDelete",
        "OrderCloseBy",
        "PositionOpen",
        "PositionClose",
        "PositionClosePartial",
        "PositionModify",
        "CTrade",
        "MqlTradeRequest",
        "Buy",
        "Sell",
        "BuyLimit",
        "SellLimit",
        "BuyStop",
        "SellStop",
        "operator",
        "or",
        "override",
        "pack",
        "private",
        "property",
        "protected",
        "public",
        "resource",
        "return",
        "short",
        "signal_0",
        "signed",
        "sizeof",
        "sinput",
        "static",
        "string",
        "struct",
        "switch",
        "template",
        "this",
        "throw",
        "true",
        "try",
        "typedef",
        "typename",
        "uchar",
        "uint",
        "ulong",
        "union",
        "unsigned",
        "ushort",
        "using",
        "vector",
        "virtual",
        "void",
        "volatile",
        "while",
        "xor",
    }
)
_MQL5_RESERVED_PREFIXES_V1 = ("lv_", "PERIOD_")
_FORBIDDEN_ORDER_IDENTIFIERS = frozenset(
    name.casefold()
    for name in (
        "OrderSend",
        "OrderSendAsync",
        "OrderClose",
        "OrderModify",
        "OrderDelete",
        "OrderCloseBy",
        "PositionOpen",
        "PositionClose",
        "PositionClosePartial",
        "PositionModify",
        "CTrade",
        "MqlTradeRequest",
        "Buy",
        "Sell",
        "BuyLimit",
        "SellLimit",
        "BuyStop",
        "SellStop",
    )
)


def _ref(value: str, field: str) -> str:
    if (
        type(value) is not str
        or not _IDENTIFIER.fullmatch(value)
        or value in _MQL5_RESERVED_WORDS_V1
        or value.casefold() in _FORBIDDEN_ORDER_IDENTIFIERS
        or value.startswith(_MQL5_RESERVED_PREFIXES_V1)
    ):
        raise SignalBlockError("RESERVED_NAME", field)
    return value


def _literal(value: str, field: str) -> str:
    if type(value) is not str or not _ID.fullmatch(value):
        raise SignalBlockError("INVALID_SIGNAL_MAPPING", field)
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def compare_expression_v1(operation: CompareOpV1, left_ref: str, right_ref: str) -> str:
    """Render a comparison over two already-validated scalar identifiers."""
    operators = {"gt": ">", "lt": "<", "ge": ">=", "le": "<="}
    if type(operation) is not str or operation not in operators:
        raise SignalBlockError("UNSUPPORTED_OPERATOR", "operation")
    left = _ref(left_ref, "left_ref")
    right = _ref(right_ref, "right_ref")
    return f"({left} {operators[operation]} {right})"


def crossover_expression_v1(
    direction: CrossDirectionV1,
    *,
    left_current_ref: str,
    right_current_ref: str,
    left_previous_ref: str,
    right_previous_ref: str,
) -> str:
    """Render a crossover predicate from finalized current/prior value refs."""
    refs = (
        _ref(left_current_ref, "left_current_ref"),
        _ref(right_current_ref, "right_current_ref"),
        _ref(left_previous_ref, "left_previous_ref"),
        _ref(right_previous_ref, "right_previous_ref"),
    )
    lc, rc, lp, rp = refs
    if type(direction) is not str:
        raise SignalBlockError("UNSUPPORTED_OPERATOR", "direction")
    if direction == "above":
        return f"({lc} > {rc} && {lp} <= {rp})"
    if direction == "below":
        return f"({lc} < {rc} && {lp} >= {rp})"
    raise SignalBlockError("UNSUPPORTED_OPERATOR", "direction")


def signal_emission_v1(
    kind: Literal["entry", "exit"],
    *,
    condition_ref: str,
    signal_key: str,
    graph_revision_hash: str,
    symbol_ref: str,
    timeframe_ref: str,
    finalized_bar_id_ref: str,
    event_ns_ref: str,
    effective_ns_ref: str,
    available_ns_ref: str,
    source_node_id: str,
) -> str:
    """Render only an in-process signal record assignment; no trade capability."""
    if type(kind) is not str or kind not in ("entry", "exit"):
        raise SignalBlockError("UNSUPPORTED_SIGNAL_KIND", "kind")
    if type(graph_revision_hash) is not str or not _HASH.fullmatch(graph_revision_hash):
        raise SignalBlockError("INVALID_SIGNAL_MAPPING", "graph_revision_hash")
    if type(source_node_id) is not str or not _ID.fullmatch(source_node_id):
        raise SignalBlockError("INVALID_SIGNAL_MAPPING", "source_node_id")
    refs = {
        "condition": _ref(condition_ref, "condition_ref"),
        "symbol": _ref(symbol_ref, "symbol_ref"),
        "timeframe": _ref(timeframe_ref, "timeframe_ref"),
        "finalized_bar_id": _ref(finalized_bar_id_ref, "finalized_bar_id_ref"),
        "event_ns": _ref(event_ns_ref, "event_ns_ref"),
        "effective_ns": _ref(effective_ns_ref, "effective_ns_ref"),
        "available_ns": _ref(available_ns_ref, "available_ns_ref"),
    }
    key = _literal(signal_key, "signal_key")
    revision = _literal(graph_revision_hash, "graph_revision_hash")
    node = _literal(source_node_id, "source_node_id")
    suffix = hashlib.sha256(f"{kind}\n{source_node_id}\n{signal_key}".encode("ascii")).hexdigest()[
        :12
    ]
    name = f"lv_emit_{suffix}"
    lines = [
        f"LVSignalEmissionV1 {name};",
        f'{name}.kind = "{kind}";',
        f"{name}.graph_revision_hash = {revision};",
        f"{name}.signal_key = {key};",
        f"{name}.symbol = {refs['symbol']};",
        f"{name}.timeframe = {refs['timeframe']};",
        f"{name}.finalized_bar_id = {refs['finalized_bar_id']};",
        f"{name}.event_ns = {refs['event_ns']};",
        f"{name}.effective_ns = {refs['effective_ns']};",
        f"{name}.available_ns = {refs['available_ns']};",
        f"{name}.source_node_id = {node};",
        f"{name}.emit = ({refs['condition']});",
    ]
    return "\n".join(lines)


__all__ = ["compare_expression_v1", "crossover_expression_v1", "signal_emission_v1"]
