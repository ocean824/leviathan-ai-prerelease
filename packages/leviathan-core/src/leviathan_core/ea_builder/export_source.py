"""Deterministic, source-only MT export from freshly validated synthetic graphs.

No generated source can submit an order. Compilation, signing and deployment are
separate gates; this module grants none of those capabilities.
"""

from __future__ import annotations

import base64
import inspect
import io
import json
import re
import zipfile
from dataclasses import dataclass
from decimal import Decimal
from hashlib import sha256
from typing import Any, Literal, NoReturn

from leviathan_core.ea_builder.blocks import (
    MAX_BLOCKS,
    MAX_PARAMS_PER_BLOCK,
    MAX_PORTS_PER_BLOCK,
    BlockCatalogV1,
    BlockDefinitionV1,
    ParameterSpecV1,
    PortV1,
    standard_catalog_v1,
)
from leviathan_core.ea_builder.graph import (
    MAX_EDGES,
    DeclaredRiskParameterV1,
    EdgeV1,
    GraphV1,
    NodeV1,
    ParameterValueV1,
    SourceProvenanceV1,
    TargetV1,
)
from leviathan_core.ea_builder.signal_catalog import extend_signal_catalog_v1
from leviathan_core.ea_builder.validate import validate
from leviathan_core.numeric import (
    NumericError,
    canonical_json,
    canonical_str,
    parse_decimal,
    parse_int,
)
from leviathan_core.seal import Issuer, SealedModel, require

_ID = re.compile(r"[A-Za-z_][A-Za-z0-9_.:-]{0,127}\Z", re.ASCII)
_MQL_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,31}\Z", re.ASCII)
# Closed target-language denylist. Update the version only with a reviewed MQL
# language/platform compatibility change.
_MQL5_RESERVED_IDENTIFIERS_V1 = frozenset(
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
        "continue",
        "const",
        "datetime",
        "default",
        "delete",
        "double",
        "do",
        "else",
        "enum",
        "extern",
        "false",
        "final",
        "float",
        "for",
        "group",
        "import",
        "include",
        "if",
        "input",
        "int",
        "long",
        "namespace",
        "new",
        "not",
        "null",
        "or",
        "offsetof",
        "operator",
        "override",
        "pack",
        "private",
        "property",
        "protected",
        "public",
        "resource",
        "return",
        "short",
        "signed",
        "sinput",
        "sizeof",
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
        "virtual",
        "void",
        "volatile",
        "while",
        "xor",
        # Exact identifiers emitted by both target renderers.
        "ArraySetAsSeries",
        "CopyBuffer",
        "DRAW_LINE",
        "EMPTY_VALUE",
        "INDICATOR_DATA",
        "IndicatorRelease",
        "INIT_FAILED",
        "INIT_SUCCEEDED",
        "INVALID_HANDLE",
        "LEVIATHAN_MAGIC",
        "handle_0",
        "iMA",
        "MODE_SMA",
        "OnCalculate",
        "OnDeinit",
        "OnInit",
        "PRICE_CLOSE",
        "SetIndexBuffer",
        "SetIndexLabel",
        "SetIndexStyle",
        "oncalculate",
        "ondeinit",
        "oninit",
        "ontick",
        "signal_0",
    }
)
_MQL5_RESERVED_PREFIXES_V1 = ("lv_", "PERIOD_")
_HASH = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_COMMIT = re.compile(r"[0-9a-f]{40}\Z", re.ASCII)
_SECRET = re.compile(r"secret|password|passwd|token|api_?key|credential|private_?key", re.I)
_FORBIDDEN_SOURCE = re.compile(
    r"\b(?:OrderSend|OrderSendAsync|OrderClose|OrderModify|PositionOpen|"
    r"PositionClose|CTrade|MqlTradeRequest)\b|\btrade\s*\.",
    re.I,
)
_TIMEFRAMES = frozenset({"M1", "M5", "M15", "M30", "H1", "H4", "D1", "W1", "MN1"})
_SUPPORTED_BLOCKS = frozenset(
    {
        "bar_event",
        "sma_indicator",
        "compare.v1",
        "crossover.v1",
        "entry_signal.v1",
        "exit_signal.v1",
    }
)
_ISSUED_GRAPH = Issuer("ea002.validated_graph")
_ISSUED_PACKAGE = Issuer("ea002.source_package")
MAX_EXPORT_NODES = 256
MAX_PARAMETER_BINDINGS = 512
MAX_ARCHIVE_BYTES = 8_000_000


class SourceExportError(ValueError):
    """Typed, content-free source-export failure."""

    def __init__(self, code: str, field: str) -> None:
        self.code = code
        self.field = field
        super().__init__(code, field)

    def __str__(self) -> str:
        return f"{self.code}:{self.field}"


def _fail(code: str, field: str) -> NoReturn:
    raise SourceExportError(code, field) from None


def _identifier(value: object, field: str, *, mql: bool = False) -> str:
    pattern = _MQL_NAME if mql else _ID
    if (
        mql
        and type(value) is str
        and pattern.fullmatch(value) is not None
        and (value.startswith(_MQL5_RESERVED_PREFIXES_V1) or value in _MQL5_RESERVED_IDENTIFIERS_V1)
    ):
        _fail("RESERVED_NAME", field)
    if type(value) is not str or pattern.fullmatch(value) is None or _SECRET.search(value):
        _fail("INVALID_IDENTIFIER", field)
    return value


def _hash(value: object, field: str, *, commit: bool = False) -> str:
    pattern = _COMMIT if commit else _HASH
    if type(value) is not str or pattern.fullmatch(value) is None:
        _fail("INVALID_HASH", field)
    return value


def _integer(value: object, field: str, minimum: int, maximum: int) -> int:
    try:
        return parse_int(value, field=field, min_value=minimum, max_value=maximum)
    except NumericError:
        _fail("INVALID_INTEGER", field)


def _decimal(value: object, field: str, *, positive: bool = False) -> Decimal:
    try:
        if type(value) is not Decimal:
            _fail("INVALID_DECIMAL", field)
        number = parse_decimal(value, field=field)
    except NumericError:
        _fail("INVALID_DECIMAL", field)
    if positive and number <= 0:
        _fail("INVALID_DECIMAL", field)
    return number


def _tuple(value: object, field: str, maximum: int) -> tuple[Any, ...]:
    if type(value) is not tuple or len(value) > maximum:
        _fail("EXPORT_LIMIT", field)
    return value


@dataclass(frozen=True, slots=True)
class SymbolMappingV1:
    source_symbol: str
    target_symbol: str

    def __post_init__(self) -> None:
        _identifier(self.source_symbol, "source_symbol")
        _identifier(self.target_symbol, "target_symbol")


@dataclass(frozen=True, slots=True)
class TimeframeMappingV1:
    source_timeframe: str
    target_timeframe: str

    def __post_init__(self) -> None:
        _identifier(self.source_timeframe, "source_timeframe")
        if type(self.target_timeframe) is not str or self.target_timeframe not in _TIMEFRAMES:
            _fail("UNRESOLVED_TIMEFRAME", "target_timeframe")


@dataclass(frozen=True, slots=True)
class ParameterBindingV1:
    node_id: str
    parameter_name: str
    mql_name: str

    def __post_init__(self) -> None:
        _identifier(self.node_id, "node_id")
        _identifier(self.parameter_name, "parameter_name")
        _identifier(self.mql_name, "mql_name", mql=True)


@dataclass(frozen=True, slots=True)
class TargetManifestV1:
    supported_symbols: tuple[str, ...]
    supported_timeframes: tuple[str, ...]
    occupied_magic_numbers: tuple[int, ...]
    broker_lot_step: Decimal

    def __post_init__(self) -> None:
        symbols = _tuple(self.supported_symbols, "supported_symbols", 256)
        timeframes = _tuple(self.supported_timeframes, "supported_timeframes", 16)
        occupied = _tuple(self.occupied_magic_numbers, "occupied_magic_numbers", 4096)
        if not symbols or not timeframes:
            _fail("UNRESOLVED_TARGET", "target_manifest")
        for symbol in symbols:
            _identifier(symbol, "supported_symbols")
        if any(type(tf) is not str or tf not in _TIMEFRAMES for tf in timeframes):
            _fail("UNRESOLVED_TIMEFRAME", "supported_timeframes")
        for magic in occupied:
            _integer(magic, "occupied_magic_numbers", 1, 2**31 - 1)
        if len(set(symbols)) != len(symbols) or len(set(timeframes)) != len(timeframes):
            _fail("DUPLICATE_MAPPING", "target_manifest")
        if len(set(occupied)) != len(occupied):
            _fail("DUPLICATE_MAGIC", "occupied_magic_numbers")
        _decimal(self.broker_lot_step, "broker_lot_step", positive=True)


@dataclass(frozen=True, slots=True)
class ExportSpecV1:
    schema_version: int
    artifact_type: Literal["EA", "INDICATOR"]
    platform: Literal["MT4", "MT5"]
    routing_mode: Literal["LocalTerminal", "RemoteBridge"]
    strategy_hash: str
    git_commit: str
    version_label: str
    symbol_map: tuple[SymbolMappingV1, ...]
    timeframe_map: tuple[TimeframeMappingV1, ...]
    target_manifest: TargetManifestV1
    parameter_bindings: tuple[ParameterBindingV1, ...]
    magic_number: int | None

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 1:
            _fail("SCHEMA_VERSION", "schema_version")
        if self.artifact_type not in ("EA", "INDICATOR") or type(self.artifact_type) is not str:
            _fail("ARTIFACT_TYPE", "artifact_type")
        if self.platform not in ("MT4", "MT5") or type(self.platform) is not str:
            _fail("TARGET_MISMATCH", "platform")
        if (
            self.routing_mode not in ("LocalTerminal", "RemoteBridge")
            or type(self.routing_mode) is not str
        ):
            _fail("ROUTING_MODE", "routing_mode")
        _hash(self.strategy_hash, "strategy_hash")
        _hash(self.git_commit, "git_commit", commit=True)
        _identifier(self.version_label, "version_label")
        symbols = _tuple(self.symbol_map, "symbol_map", 16)
        timeframes = _tuple(self.timeframe_map, "timeframe_map", 16)
        bindings = _tuple(self.parameter_bindings, "parameter_bindings", MAX_PARAMETER_BINDINGS)
        if type(self.target_manifest) is not TargetManifestV1:
            _fail("INVALID_TARGET_MANIFEST", "target_manifest")
        for item in symbols:
            if type(item) is not SymbolMappingV1:
                _fail("INVALID_MAPPING", "symbol_map")
            SymbolMappingV1(item.source_symbol, item.target_symbol)
        for item in timeframes:
            if type(item) is not TimeframeMappingV1:
                _fail("INVALID_MAPPING", "timeframe_map")
            TimeframeMappingV1(item.source_timeframe, item.target_timeframe)
        for item in bindings:
            if type(item) is not ParameterBindingV1:
                _fail("INVALID_MAPPING", "parameter_bindings")
            ParameterBindingV1(item.node_id, item.parameter_name, item.mql_name)
        TargetManifestV1(
            *(
                self.target_manifest.supported_symbols,
                self.target_manifest.supported_timeframes,
                self.target_manifest.occupied_magic_numbers,
                self.target_manifest.broker_lot_step,
            )
        )
        if len({item.source_symbol for item in symbols}) != len(symbols):
            _fail("DUPLICATE_MAPPING", "symbol_map")
        if len({item.source_timeframe for item in timeframes}) != len(timeframes):
            _fail("DUPLICATE_MAPPING", "timeframe_map")
        if len({(item.node_id, item.parameter_name) for item in bindings}) != len(bindings):
            _fail("DUPLICATE_MAPPING", "parameter_bindings")
        if len({item.mql_name for item in bindings}) != len(bindings):
            _fail("DUPLICATE_PARAMETER", "parameter_bindings")
        if self.magic_number is not None:
            _integer(self.magic_number, "magic_number", 1, 2**31 - 1)


@dataclass(frozen=True, slots=True)
class TemplateBindingV1:
    block_id: str
    platform: Literal["MT4", "MT5"]

    def __post_init__(self) -> None:
        _identifier(self.block_id, "block_id")
        if self.block_id not in _SUPPORTED_BLOCKS or self.platform not in ("MT4", "MT5"):
            _fail("UNSUPPORTED_BLOCK", "mappings")


@dataclass(frozen=True, slots=True)
class TemplateCatalogV1:
    catalog_id: str
    version: int
    mappings: tuple[TemplateBindingV1, ...]

    def __post_init__(self) -> None:
        _identifier(self.catalog_id, "catalog_id")
        _integer(self.version, "version", 1, 10**38)
        mappings = _tuple(self.mappings, "mappings", 64)
        for item in mappings:
            if type(item) is not TemplateBindingV1:
                _fail("INVALID_MAPPING", "mappings")
            TemplateBindingV1(item.block_id, item.platform)
        if len({(item.block_id, item.platform) for item in mappings}) != len(mappings):
            _fail("DUPLICATE_MAPPING", "mappings")

    def canonical_digest(self) -> str:
        return sha256(canonical_json(_template_document(self))).hexdigest()


def standard_template_catalog_v1() -> TemplateCatalogV1:
    """Fixed reviewed syntax mappings; no caller-provided MQL fragments."""
    platforms: tuple[Literal["MT4", "MT5"], ...] = ("MT4", "MT5")
    return TemplateCatalogV1(
        catalog_id="leviathan_mql_source",
        version=1,
        mappings=tuple(
            TemplateBindingV1(block_id=block_id, platform=platform)
            for platform in platforms
            for block_id in sorted(_SUPPORTED_BLOCKS)
        ),
    )


class ValidatedGraphV1(SealedModel):
    graph_json: str
    catalog_json: str
    target_platform: Literal["MT4", "MT5"]
    validation_json: str
    graph_hash: str
    params_hash: str


class SourcePackageV1(SealedModel):
    archive_b64: str
    source_text: str
    source_filename: str
    manifest_json: str
    parameter_map_json: str
    build_id: str
    graph_hash: str
    params_hash: str
    template_hash: str
    catalog_digest: str
    route_label: str
    export_ready: Literal[False]
    compiled: Literal[False]
    signed: Literal[False]

    @property
    def archive_bytes(self) -> bytes:
        require(self, _ISSUED_PACKAGE.tag)
        return base64.b64decode(self.archive_b64, validate=True)


def _canonical_graph_json(graph: GraphV1) -> str:
    document = graph.model_dump(mode="python")
    for raw, node in zip(document["nodes"], graph.nodes, strict=True):
        raw["parameters"] = {
            name: {"kind": value.kind, "value": value.value}
            for name, value in node.parameters.items()
        }
    document["nodes"] = sorted(document["nodes"], key=lambda item: item["node_id"])
    document["edges"] = sorted(document["edges"], key=lambda item: item["edge_id"])
    return canonical_json(document).decode("ascii")


def _canonical_catalog_json(catalog: BlockCatalogV1) -> str:
    document = catalog.model_dump(mode="python")
    for block in document["blocks"]:
        for group in ("inputs", "outputs", "parameters"):
            if group == "parameters":
                for parameter in block[group]:
                    parameter["choices"] = sorted(parameter["choices"])
            block[group] = sorted(
                block[group], key=lambda item: (item["name"], canonical_json(item))
            )
        block["targets"] = sorted(block["targets"])
    document["blocks"] = sorted(
        document["blocks"], key=lambda item: (item["block_id"], canonical_json(item))
    )
    return canonical_json(document).decode("ascii")


def _load_graph_json(payload: str | bytes) -> GraphV1:
    """Rebuild strict EA-001 tuples and Decimals from a canonical JSON snapshot."""
    try:
        document = json.loads(payload, parse_float=Decimal)
        raw_nodes = document["nodes"]
        raw_edges = document["edges"]
        if type(raw_nodes) is not list or len(raw_nodes) > MAX_EXPORT_NODES:
            _fail("EXPORT_LIMIT", "graph")
        if type(raw_edges) is not list or len(raw_edges) > MAX_EDGES:
            _fail("EXPORT_LIMIT", "graph")
        provenance = document["provenance"]
        provenance["unresolved_claims"] = tuple(provenance["unresolved_claims"])
        document["provenance"] = SourceProvenanceV1(**provenance)
        declared_risk_parameters = document.get("declared_risk_parameters", [])
        if type(declared_risk_parameters) is not list or len(declared_risk_parameters) > 32:
            _fail("EXPORT_LIMIT", "declared_risk_parameters")
        for item in declared_risk_parameters:
            item["value"] = Decimal(item["value"])
        document["declared_risk_parameters"] = tuple(
            DeclaredRiskParameterV1(**item) for item in declared_risk_parameters
        )
        nodes = []
        for raw in raw_nodes:
            if type(raw["parameters"]) is not dict:
                _fail("INVALID_GRAPH", "parameters")
            if len(raw["parameters"]) > MAX_PARAMS_PER_BLOCK:
                _fail("EXPORT_LIMIT", "graph")
            parameters = {}
            for name, parameter in raw["parameters"].items():
                value = parameter["value"]
                if parameter["kind"] in ("decimal", "percent"):
                    value = Decimal(value)
                parameters[name] = ParameterValueV1(kind=parameter["kind"], value=value)
            raw["parameters"] = parameters
            nodes.append(NodeV1(**raw))
        document["nodes"] = tuple(nodes)
        document["edges"] = tuple(EdgeV1(**raw) for raw in document["edges"])
        return GraphV1(**document)
    except SourceExportError:
        raise
    except Exception:
        _fail("INVALID_GRAPH", "graph")


def _load_catalog_json(payload: str | bytes) -> BlockCatalogV1:
    try:
        document = json.loads(payload, parse_float=Decimal)
        raw_blocks = document["blocks"]
        if type(raw_blocks) is not list or len(raw_blocks) > MAX_BLOCKS:
            _fail("CATALOG_BLOCK_LIMIT", "catalog")
        blocks = []
        for raw in raw_blocks:
            if (
                type(raw["inputs"]) is not list
                or type(raw["outputs"]) is not list
                or len(raw["inputs"]) + len(raw["outputs"]) > MAX_PORTS_PER_BLOCK
                or type(raw["parameters"]) is not list
                or len(raw["parameters"]) > MAX_PARAMS_PER_BLOCK
            ):
                _fail("CATALOG_FANOUT_LIMIT", "catalog")
            raw["inputs"] = tuple(PortV1(**item) for item in raw["inputs"])
            raw["outputs"] = tuple(PortV1(**item) for item in raw["outputs"])
            parameters = []
            for parameter in raw["parameters"]:
                parameter["choices"] = tuple(parameter["choices"])
                for bound in ("minimum", "maximum"):
                    if parameter[bound] is not None:
                        parameter[bound] = Decimal(parameter[bound])
                parameters.append(ParameterSpecV1(**parameter))
            raw["parameters"] = tuple(parameters)
            raw["targets"] = tuple(raw["targets"])
            blocks.append(BlockDefinitionV1(**raw))
        document["blocks"] = tuple(blocks)
        return BlockCatalogV1(**document)
    except SourceExportError:
        raise
    except Exception:
        _fail("INVALID_CATALOG", "catalog")


def _params_hash(graph: GraphV1) -> str:
    document = [
        {
            "node_id": node.node_id,
            "parameters": {
                name: {"kind": value.kind, "value": value.value}
                for name, value in node.parameters.items()
            },
        }
        for node in sorted(graph.nodes, key=lambda item: item.node_id)
    ]
    return sha256(canonical_json(document)).hexdigest()


def validate_graph_for_export(
    graph: GraphV1, catalog: BlockCatalogV1, target: TargetV1
) -> ValidatedGraphV1:
    """Revalidate an exact graph/catalog snapshot and issue static evidence."""
    if (
        type(graph) is not GraphV1
        or type(catalog) is not BlockCatalogV1
        or type(target) is not TargetV1
    ):
        _fail("INVALID_GRAPH", "graph")
    if len(graph.nodes) > MAX_EXPORT_NODES:
        _fail("EXPORT_LIMIT", "graph")
    try:
        graph_json = _canonical_graph_json(graph)
        catalog_json = _canonical_catalog_json(catalog)
        fresh_graph = _load_graph_json(graph_json)
        fresh_catalog = _load_catalog_json(catalog_json)
        fresh_target = TargetV1(platform=target.platform)
        result = validate(fresh_graph, fresh_catalog, fresh_target)
        if result.status != "VALID":
            _fail("GRAPH_INVALID", "graph")
        if fresh_graph.provenance.source_asset_kind == "source_code":
            try:
                # STRAT-002 issues the exact lowered GraphV1 after it has checked
                # the reviewed spec and its VerifiedLicenseV1 binding. Requiring
                # that issuance here prevents caller-built provenance from
                # crossing the source export boundary.
                require(graph, "strategy.ea_graph")
            except Exception:
                _fail("SOURCE_PROVENANCE", "graph")
        elif (
            fresh_graph.strategy_source_id is not None
            or fresh_graph.strategy_source_digest is not None
        ):
            _fail("SOURCE_PROVENANCE", "strategy_source")
        validation_json = canonical_json(result.model_dump(mode="json")).decode("ascii")
        return _ISSUED_GRAPH.issue(
            ValidatedGraphV1(
                graph_json=graph_json,
                catalog_json=catalog_json,
                target_platform=fresh_target.platform,
                validation_json=validation_json,
                graph_hash=sha256(graph_json.encode("ascii")).hexdigest(),
                params_hash=_params_hash(fresh_graph),
            )
        )
    except SourceExportError:
        raise
    except Exception:
        _fail("INVALID_GRAPH", "graph")


def _spec_document(spec: ExportSpecV1) -> dict[str, Any]:
    return {
        "schema_version": spec.schema_version,
        "artifact_type": spec.artifact_type,
        "platform": spec.platform,
        "routing_mode": spec.routing_mode,
        "strategy_hash": spec.strategy_hash,
        "git_commit": spec.git_commit,
        "version_label": spec.version_label,
        "symbol_map": [
            {"source_symbol": item.source_symbol, "target_symbol": item.target_symbol}
            for item in spec.symbol_map
        ],
        "timeframe_map": [
            {"source_timeframe": item.source_timeframe, "target_timeframe": item.target_timeframe}
            for item in spec.timeframe_map
        ],
        "target_manifest": {
            "supported_symbols": sorted(spec.target_manifest.supported_symbols),
            "supported_timeframes": sorted(spec.target_manifest.supported_timeframes),
            "occupied_magic_numbers": sorted(spec.target_manifest.occupied_magic_numbers),
            "broker_lot_step": canonical_str(spec.target_manifest.broker_lot_step),
        },
        "parameter_bindings": [
            {
                "node_id": item.node_id,
                "parameter_name": item.parameter_name,
                "mql_name": item.mql_name,
            }
            for item in sorted(
                spec.parameter_bindings, key=lambda item: (item.node_id, item.parameter_name)
            )
        ],
        "magic_number": spec.magic_number,
    }


def _template_document(templates: TemplateCatalogV1) -> dict[str, Any]:
    from leviathan_core.ea_builder.mql4 import render_mql4
    from leviathan_core.ea_builder.mql5 import render_mql5

    renderer_digest = sha256(
        (
            inspect.getsource(render_mql4)
            + inspect.getsource(render_mql5)
            + inspect.getsource(_render_signal_wiring)
        ).encode("utf-8")
    ).hexdigest()
    return {
        "catalog_id": templates.catalog_id,
        "version": templates.version,
        "renderer_digest": renderer_digest,
        "mappings": [
            {"block_id": item.block_id, "platform": item.platform}
            for item in sorted(templates.mappings, key=lambda item: (item.block_id, item.platform))
        ],
    }


def _render_signal_wiring(
    graph: GraphV1,
    *,
    build_id: str,
    graph_hash: str,
    symbol: str,
    timeframe: str,
    sma_nodes: tuple[NodeV1, ...],
) -> tuple[str, tuple[str, ...]]:
    """Create causal, signal-only code over finalized indicator bars."""
    sma_index = {node.node_id: index for index, node in enumerate(sma_nodes)}
    edges_to = {(edge.target_node, edge.target_port): edge.source_node for edge in graph.edges}
    suffix = build_id[:12]
    declarations: list[str] = []
    body: list[str] = []
    signal_nodes = sorted(
        (node for node in graph.nodes if node.block_id in {"entry_signal.v1", "exit_signal.v1"}),
        key=lambda node: node.node_id,
    )
    for signal in signal_nodes:
        emitter_hash = sha256(signal.node_id.encode("ascii")).hexdigest()[:12]
        declarations.extend(
            (
                f"LVSignalEmissionV1 lv_emission_{emitter_hash};",
                f"datetime lv_last_bar_{emitter_hash} = 0;",
            )
        )
        body.append(f"  lv_emission_{emitter_hash}.emit = false;")
    if not signal_nodes:
        return "", ()
    body.append(f"  ArraySetAsSeries(lv_time_{suffix}, true);")
    body.append(f"  if (lv_rates_total_{suffix} > 2) {{")
    for index, _ in enumerate(sma_nodes):
        current = f"lv_sma_{index}_{suffix}[1]"
        previous = f"lv_sma_{index}_{suffix}[2]"
        body.extend(
            (
                f"    if (!MathIsValidNumber({current}) || {current} == EMPTY_VALUE || "
                f"!MathIsValidNumber({previous}) || {previous} == EMPTY_VALUE) "
                f"return lv_rates_total_{suffix};",
            )
        )
    for node in sorted(
        (item for item in graph.nodes if item.block_id in {"compare.v1", "crossover.v1"}),
        key=lambda item: item.node_id,
    ):
        left_id = edges_to.get((node.node_id, "left"))
        right_id = edges_to.get((node.node_id, "right"))
        if left_id not in sma_index or right_id not in sma_index:
            _fail("GRAPH_INVALID", "signal_edges")
        left = f"lv_sma_{sma_index[left_id]}_{suffix}"
        right = f"lv_sma_{sma_index[right_id]}_{suffix}"
        condition = f"lv_condition_{sha256(node.node_id.encode('ascii')).hexdigest()[:12]}"
        if node.block_id == "compare.v1":
            operation = node.parameters["op"].value
            operator = (
                {"gt": ">", "lt": "<", "ge": ">=", "le": "<="}.get(operation)
                if type(operation) is str
                else None
            )
            if operator is None:
                _fail("UNSUPPORTED_BLOCK", "compare")
            expression = f"({left}[1] {operator} {right}[1])"
        else:
            direction = node.parameters["direction"].value
            if direction == "above":
                expression = f"({left}[1] > {right}[1] && {left}[2] <= {right}[2])"
            elif direction == "below":
                expression = f"({left}[1] < {right}[1] && {left}[2] >= {right}[2])"
            else:
                _fail("UNSUPPORTED_BLOCK", "crossover")
        body.append(f"    bool {condition} = {expression};")
        body.append(f"    // signal condition for {node.node_id}")
    body.append(
        f'    string lv_finalized_bar_id_{suffix} = StringFormat("%s|%s|%I64d", '
        f'"{symbol}", "{timeframe}", (long)lv_time_{suffix}[1]);'
    )
    for signal in signal_nodes:
        edge = next(
            (
                item
                for item in graph.edges
                if item.target_node == signal.node_id and item.target_port == "condition"
            ),
            None,
        )
        if edge is None:
            _fail("GRAPH_INVALID", "signal_condition")
        signal_key = signal.parameters["signal_key"].value
        emitter_hash = sha256(signal.node_id.encode("ascii")).hexdigest()[:12]
        condition = f"lv_condition_{sha256(edge.source_node.encode('ascii')).hexdigest()[:12]}"
        kind = "entry" if signal.block_id == "entry_signal.v1" else "exit"
        body.append(f"    if ({condition} && lv_last_bar_{emitter_hash} != lv_time_{suffix}[1]) {{")
        body.extend(
            (
                f'      lv_emission_{emitter_hash}.kind = "{kind}";',
                f'      lv_emission_{emitter_hash}.graph_revision_hash = "{graph_hash}";',
                f'      lv_emission_{emitter_hash}.signal_key = "{signal_key}";',
                f'      lv_emission_{emitter_hash}.symbol = "{symbol}";',
                f'      lv_emission_{emitter_hash}.timeframe = "{timeframe}";',
                f"      lv_emission_{emitter_hash}.finalized_bar_id = "
                f"lv_finalized_bar_id_{suffix};",
                f"      lv_emission_{emitter_hash}.event_ns = "
                f"(long)lv_time_{suffix}[1] * 1000000000;",
                f"      lv_emission_{emitter_hash}.effective_ns = "
                f"(long)lv_time_{suffix}[1] * 1000000000;",
                f"      lv_emission_{emitter_hash}.available_ns = "
                f"(long)lv_time_{suffix}[1] * 1000000000;",
                f'      lv_emission_{emitter_hash}.source_node_id = "{signal.node_id}";',
                f"      lv_emission_{emitter_hash}.emit = true;",
                f"      lv_last_bar_{emitter_hash} = lv_time_{suffix}[1];",
                "    }",
            )
        )
    body.append("  }")
    struct = (
        "struct LVSignalEmissionV1 { string kind; string graph_revision_hash; "
        "string signal_key; string symbol; string timeframe; string finalized_bar_id; "
        "long event_ns; long effective_ns; long available_ns; string source_node_id; bool emit; };"
    )
    # the renderer is a closed source template; insert only into its declaration area.
    return "\n".join((struct, *declarations)), tuple(body)


def _archive(files: dict[str, bytes]) -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED, allowZip64=False) as handle:
        for name in sorted(files):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            handle.writestr(info, files[name])
    result = stream.getvalue()
    if len(result) > MAX_ARCHIVE_BYTES:
        _fail("EXPORT_LIMIT", "archive")
    return result


def export_source(
    validated: ValidatedGraphV1, spec: ExportSpecV1, templates: TemplateCatalogV1
) -> SourcePackageV1:
    """Emit checksum-bound MQL source and a canonical source-only ZIP archive."""
    require(validated, _ISSUED_GRAPH.tag)
    package = _generate_source_package(validated, spec, templates)
    return _ISSUED_PACKAGE.issue(package)


def _generate_source_package(
    validated: ValidatedGraphV1, spec: ExportSpecV1, templates: TemplateCatalogV1
) -> SourcePackageV1:
    """Regenerate canonical package bytes for export or round-trip verification."""
    from leviathan_core.ea_builder.mql4 import render_mql4
    from leviathan_core.ea_builder.mql5 import render_mql5

    if type(spec) is not ExportSpecV1 or type(templates) is not TemplateCatalogV1:
        _fail("INVALID_SPEC", "spec")
    try:
        # Canonical round-trip creates a fresh, fully revalidated input snapshot.
        spec_doc = _spec_document(spec)
        template_doc = _template_document(templates)
        spec = _parse_spec(spec_doc)
        templates = _parse_templates(template_doc)
        graph = _load_graph_json(validated.graph_json)
        catalog = _load_catalog_json(validated.catalog_json)
        target = TargetV1(platform=validated.target_platform)
        fresh = validate(graph, catalog, target)
        if fresh.status != "VALID" or (
            canonical_json(fresh.model_dump(mode="json")).decode("ascii")
            != validated.validation_json
            or _canonical_graph_json(graph) != validated.graph_json
            or _canonical_catalog_json(catalog) != validated.catalog_json
            or sha256(validated.graph_json.encode("ascii")).hexdigest() != validated.graph_hash
            or _params_hash(graph) != validated.params_hash
        ):
            _fail("GRAPH_CHANGED", "validated")
    except SourceExportError:
        raise
    except Exception:
        _fail("INVALID_SPEC", "spec")
    if spec.platform != validated.target_platform:
        _fail("TARGET_MISMATCH", "platform")
    if graph.template_hash != templates.canonical_digest():
        _fail("TEMPLATE_MISMATCH", "templates")
    if graph.provenance.source_asset_kind not in {"original", "source_code"} or (
        graph.provenance.source_rights != "verified"
        or not graph.provenance.reviewed_rules
        or graph.provenance.unresolved_claims
        or graph.provenance.live_order_mode
    ):
        _fail("SOURCE_PROVENANCE", "graph")
    if graph.provenance.source_asset_kind == "source_code" and (
        graph.strategy_source_id != graph.provenance.source_id
        or graph.strategy_source_digest is None
    ):
        _fail("SOURCE_PROVENANCE", "strategy_source")
    if _SECRET.search(validated.graph_json):
        _fail("SECRET_MARKER", "graph")
    if len(graph.nodes) > MAX_EXPORT_NODES:
        _fail("EXPORT_LIMIT", "graph")
    if (
        len(spec.symbol_map) != 1
        or spec.symbol_map[0].source_symbol != graph.symbol
        or (spec.symbol_map[0].target_symbol not in spec.target_manifest.supported_symbols)
    ):
        _fail("UNRESOLVED_SYMBOL", "symbol_map")
    if len(spec.timeframe_map) != 1 or (
        spec.timeframe_map[0].source_timeframe != graph.timeframe
        or spec.timeframe_map[0].target_timeframe not in spec.target_manifest.supported_timeframes
    ):
        _fail("UNRESOLVED_TIMEFRAME", "timeframe_map")
    definitions = {block.block_id: block for block in catalog.blocks}
    reviewed_catalog = extend_signal_catalog_v1(standard_catalog_v1())
    reviewed = {block.block_id: block for block in reviewed_catalog.blocks}
    mapping_set = {(item.block_id, item.platform) for item in templates.mappings}
    for node in graph.nodes:
        definition = definitions[node.block_id]
        if (
            node.block_id not in _SUPPORTED_BLOCKS
            or (node.block_id, spec.platform) not in mapping_set
            or node.block_id not in reviewed
            or definition.model_dump(mode="json") != reviewed[node.block_id].model_dump(mode="json")
        ):
            _fail("UNSUPPORTED_BLOCK", "graph")
    if not any(node.block_id == "bar_event" for node in graph.nodes) or not any(
        node.block_id == "sma_indicator" for node in graph.nodes
    ):
        _fail("UNSUPPORTED_BLOCK", "graph")
    if (
        spec.magic_number is not None
        and spec.magic_number in spec.target_manifest.occupied_magic_numbers
    ):
        _fail("DUPLICATE_MAGIC", "magic_number")
    if spec.magic_number is not None:
        _fail("FORBIDDEN_MAGIC", "magic_number")
    expected_params = {(node.node_id, name) for node in graph.nodes for name in node.parameters}
    actual_params = {(item.node_id, item.parameter_name) for item in spec.parameter_bindings}
    if actual_params != expected_params:
        _fail("PARAMETER_MAP", "parameter_bindings")
    params: list[dict[str, Any]] = []
    declarations: list[str] = []
    node_lookup = {node.node_id: node for node in graph.nodes}
    for binding in sorted(spec.parameter_bindings, key=lambda item: item.mql_name):
        node = node_lookup[binding.node_id]
        parameter = node.parameters[binding.parameter_name]
        parameter_spec = next(
            item
            for item in definitions[node.block_id].parameters
            if item.name == binding.parameter_name
        )
        kind, value = parameter.kind, parameter.value
        if kind == "int" and type(value) is int:
            mql_type, literal = "int", str(value)
        elif kind in ("decimal", "percent") and type(value) is Decimal:
            mql_type, literal = "double", canonical_str(value)
        elif kind == "bool" and type(value) is bool:
            mql_type, literal = "bool", "true" if value else "false"
        elif kind in {"enum", "symbol"} and type(value) is str:
            allowed = (
                {"above", "below"}
                if node.block_id == "crossover.v1" and binding.parameter_name == "direction"
                else {"gt", "lt", "ge", "le"}
                if node.block_id == "compare.v1" and binding.parameter_name == "op"
                else None
            )
            if binding.parameter_name == "signal_key" and node.block_id in {
                "entry_signal.v1",
                "exit_signal.v1",
            }:
                _identifier(value, "signal_key")
            elif allowed is None or value not in allowed:
                _fail("UNSUPPORTED_PARAMETER_KIND", "parameter_bindings")
            mql_type, literal = "", value
        else:
            _fail("UNSUPPORTED_PARAMETER_KIND", "parameter_bindings")
        params.append(
            {
                "node_id": binding.node_id,
                "parameter_name": binding.parameter_name,
                "mql_name": binding.mql_name,
                "kind": kind,
                "value": literal,
                "minimum": (
                    canonical_str(parameter_spec.minimum)
                    if parameter_spec.minimum is not None
                    else None
                ),
                "maximum": (
                    canonical_str(parameter_spec.maximum)
                    if parameter_spec.maximum is not None
                    else None
                ),
            }
        )
        if mql_type:
            declarations.append(f"input {mql_type} {binding.mql_name} = {literal};")
    parameter_json = canonical_json(params).decode("ascii")
    params_hash = sha256(parameter_json.encode("ascii")).hexdigest()
    template_hash = templates.canonical_digest()
    spec_json = canonical_json(spec_doc).decode("ascii")
    template_json = canonical_json(template_doc).decode("ascii")
    build_id = sha256(
        canonical_json(
            {
                "graph_hash": validated.graph_hash,
                "params_hash": params_hash,
                "catalog_digest": catalog.canonical_digest(),
                "template_hash": template_hash,
                "strategy_hash": spec.strategy_hash,
                "export_spec": spec_doc,
            }
        )
    ).hexdigest()
    binding_names = {
        (item.node_id, item.parameter_name): item.mql_name for item in spec.parameter_bindings
    }
    sma_nodes = sorted(
        (node for node in graph.nodes if node.block_id == "sma_indicator"),
        key=lambda item: item.node_id,
    )
    period_names = tuple(binding_names[(node.node_id, "period")] for node in sma_nodes)
    renderer = render_mql4 if spec.platform == "MT4" else render_mql5
    source_text = renderer(
        build_id=build_id,
        strategy_hash=spec.strategy_hash,
        graph_hash=validated.graph_hash,
        params_hash=params_hash,
        template_hash=template_hash,
        catalog_digest=catalog.canonical_digest(),
        git_commit=spec.git_commit,
        symbol=spec.symbol_map[0].target_symbol,
        timeframe=spec.timeframe_map[0].target_timeframe,
        declarations=tuple(declarations),
        sma_periods=period_names,
    )
    if any(node.block_id in {"compare.v1", "crossover.v1"} for node in graph.nodes):
        globals_text, signal_body = _render_signal_wiring(
            graph,
            build_id=build_id,
            graph_hash=validated.graph_hash,
            symbol=spec.symbol_map[0].target_symbol,
            timeframe=spec.timeframe_map[0].target_timeframe,
            sma_nodes=tuple(sma_nodes),
        )
        suffix = build_id[:12]
        init_marker = "int OnInit() {"
        return_marker = f"  return lv_rates_total_{suffix};\n}}"
        if source_text.count(init_marker) != 1 or source_text.count(return_marker) != 1:
            _fail("TEMPLATE_MISMATCH", "renderer")
        source_text = source_text.replace(init_marker, f"{globals_text}\n{init_marker}", 1)
        source_text = source_text.replace(
            return_marker,
            "\n".join((*signal_body, f"  return lv_rates_total_{suffix};", "}")),
            1,
        )
    if _FORBIDDEN_SOURCE.search(source_text):
        _fail("FORBIDDEN_OPERATION", "source")
    source_name = "source.mq4" if spec.platform == "MT4" else "source.mq5"
    route_label = "source-only"
    manifest = {
        "schema_version": 1,
        "build_id": build_id,
        "artifact_type": spec.artifact_type,
        "platform": spec.platform,
        "routing_mode": spec.routing_mode,
        "route_label": route_label,
        "graph_hash": validated.graph_hash,
        "params_hash": params_hash,
        "catalog_digest": catalog.canonical_digest(),
        "template_hash": template_hash,
        "strategy_hash": spec.strategy_hash,
        "source_hash": graph.source_hash,
        "promotion_status": graph.promotion_status,
        "promotable": False,
        "strategy_source_id": graph.strategy_source_id,
        "strategy_source_digest": graph.strategy_source_digest,
        "declared_risk_parameters": [
            {
                "kind": item.kind,
                "value": canonical_str(item.value),
                "unit": item.unit,
                "source_claim_id": item.source_claim_id,
                "enforcement": "NOT_ENFORCED_BY_EA__OMS_RISK_ONLY",
            }
            for item in sorted(
                graph.declared_risk_parameters,
                key=lambda item: (item.kind, item.source_claim_id),
            )
        ],
        "git_commit": spec.git_commit,
        "version_label": spec.version_label,
        "source_sha256": sha256(source_text.encode("utf-8")).hexdigest(),
        "source_filename": source_name,
        "export_ready": False,
        "compiled": False,
        "signed": False,
    }
    manifest_json = canonical_json(manifest).decode("ascii")
    source_notice = (
        "Original synthetic reviewed rules only."
        if graph.provenance.source_asset_kind == "original"
        else "Reviewed STRAT source binding only; source text is not embedded."
    )
    notice = (
        f"{source_notice} Rights: verified. SOURCE ONLY.\n"
        f"Source hash: {graph.source_hash}. Graph revision: {graph.revision}.\n"
        "No compilation, signature, order submission, deployment or live authorization.\n"
        "Only plotted SMA and finalized-bar signal semantics are rendered. "
        "Risk parameters are manifest metadata for OMS/RISK only. "
        "Source asset fragments are never embedded.\n"
    )
    files = {
        source_name: source_text.encode("utf-8"),
        "manifest.json": manifest_json.encode("ascii"),
        "parameter-map.json": parameter_json.encode("ascii"),
        "provenance.txt": notice.encode("ascii"),
        "dependencies.json": b"[]",
        "graph.json": validated.graph_json.encode("ascii"),
        "catalog.json": validated.catalog_json.encode("ascii"),
        "export-spec.json": spec_json.encode("ascii"),
        "templates.json": template_json.encode("ascii"),
        "README.txt": b"SOURCE ONLY; not compiled, signed, deployed or export-ready.\n",
    }
    files["checksums.json"] = canonical_json(
        {name: sha256(content).hexdigest() for name, content in files.items()}
    )
    archive = _archive(files)
    return SourcePackageV1(
        archive_b64=base64.b64encode(archive).decode("ascii"),
        source_text=source_text,
        source_filename=source_name,
        manifest_json=manifest_json,
        parameter_map_json=parameter_json,
        build_id=build_id,
        graph_hash=validated.graph_hash,
        params_hash=params_hash,
        template_hash=template_hash,
        catalog_digest=catalog.canonical_digest(),
        route_label=route_label,
        export_ready=False,
        compiled=False,
        signed=False,
    )


def _parse_spec(document: dict[str, Any]) -> ExportSpecV1:
    try:
        if set(document) != {
            "schema_version",
            "artifact_type",
            "platform",
            "routing_mode",
            "strategy_hash",
            "git_commit",
            "version_label",
            "symbol_map",
            "timeframe_map",
            "target_manifest",
            "parameter_bindings",
            "magic_number",
        }:
            _fail("INVALID_SPEC", "spec")
        target = document["target_manifest"]
        if set(target) != {
            "supported_symbols",
            "supported_timeframes",
            "occupied_magic_numbers",
            "broker_lot_step",
        }:
            _fail("INVALID_SPEC", "target_manifest")
        for key, limit in (
            ("symbol_map", 16),
            ("timeframe_map", 16),
            ("parameter_bindings", MAX_PARAMETER_BINDINGS),
        ):
            if type(document[key]) is not list or len(document[key]) > limit:
                _fail("EXPORT_LIMIT", key)
        for key, limit in (
            ("supported_symbols", 256),
            ("supported_timeframes", 16),
            ("occupied_magic_numbers", 4096),
        ):
            if type(target[key]) is not list or len(target[key]) > limit:
                _fail("EXPORT_LIMIT", key)
        return ExportSpecV1(
            schema_version=document["schema_version"],
            artifact_type=document["artifact_type"],
            platform=document["platform"],
            routing_mode=document["routing_mode"],
            strategy_hash=document["strategy_hash"],
            git_commit=document["git_commit"],
            version_label=document["version_label"],
            symbol_map=tuple(SymbolMappingV1(**item) for item in document["symbol_map"]),
            timeframe_map=tuple(TimeframeMappingV1(**item) for item in document["timeframe_map"]),
            target_manifest=TargetManifestV1(
                supported_symbols=tuple(target["supported_symbols"]),
                supported_timeframes=tuple(target["supported_timeframes"]),
                occupied_magic_numbers=tuple(target["occupied_magic_numbers"]),
                broker_lot_step=Decimal(target["broker_lot_step"]),
            ),
            parameter_bindings=tuple(
                ParameterBindingV1(**item) for item in document["parameter_bindings"]
            ),
            magic_number=document["magic_number"],
        )
    except SourceExportError:
        raise
    except Exception:
        _fail("INVALID_SPEC", "spec")


def _parse_templates(document: dict[str, Any]) -> TemplateCatalogV1:
    try:
        if set(document) != {"catalog_id", "version", "renderer_digest", "mappings"}:
            _fail("INVALID_TEMPLATE", "templates")
        if type(document["mappings"]) is not list or len(document["mappings"]) > 64:
            _fail("EXPORT_LIMIT", "mappings")
        templates = TemplateCatalogV1(
            catalog_id=document["catalog_id"],
            version=document["version"],
            mappings=tuple(TemplateBindingV1(**item) for item in document["mappings"]),
        )
        if _template_document(templates) != document:
            _fail("TEMPLATE_MISMATCH", "templates")
        return templates
    except SourceExportError:
        raise
    except Exception:
        _fail("INVALID_TEMPLATE", "templates")
