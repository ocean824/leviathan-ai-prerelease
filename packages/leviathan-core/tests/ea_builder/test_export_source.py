"""Owned EA-002 source-export boundary regressions; no MQL is executed."""

from __future__ import annotations

import io
import json
import re
import zipfile
from copy import copy
from dataclasses import replace
from decimal import Decimal

import pytest

from leviathan_core.ea_builder import (
    EdgeV1,
    GraphV1,
    NodeV1,
    ParameterValueV1,
    SourceProvenanceV1,
    TargetV1,
    standard_catalog_v1,
)
from leviathan_core.ea_builder.export_source import (
    MAX_ARCHIVE_BYTES,
    MAX_PARAMETER_BINDINGS,
    ExportSpecV1,
    ParameterBindingV1,
    SourceExportError,
    SymbolMappingV1,
    TargetManifestV1,
    TimeframeMappingV1,
    _archive,
    export_source,
    standard_template_catalog_v1,
    validate_graph_for_export,
)
from leviathan_core.ea_builder.roundtrip import import_generated_package
from leviathan_core.seal import SealError


def _node(
    node_id: str, block_id: str, parameters: dict[str, ParameterValueV1], warmup: int = 0
) -> NodeV1:
    return NodeV1(
        node_id=node_id,
        block_id=block_id,
        parameters=parameters,
        symbol="EURUSD",
        timeframe="M1",
        warmup_bars=warmup,
    )


def _edge(
    edge_id: str, source: str, source_port: str, target: str, target_port: str, kind: str
) -> EdgeV1:
    return EdgeV1(
        edge_id=edge_id,
        source_node=source,
        source_port=source_port,
        target_node=target,
        target_port=target_port,
        kind=kind,
    )


def _graph(*, trade: bool) -> GraphV1:
    catalog = standard_catalog_v1()
    if trade:
        nodes = (
            _node("event", "tick_event", {}),
            _node(
                "risk",
                "risk_cap",
                {"max_daily_loss": ParameterValueV1(kind="percent", value=Decimal("5"))},
            ),
            _node(
                "size",
                "money_size",
                {"max_lots": ParameterValueV1(kind="decimal", value=Decimal("0.10"))},
            ),
            _node("entry", "trade_entry", {}),
        )
        edges = (
            _edge("e0", "event", "event", "risk", "event", "event"),
            _edge("e1", "risk", "intent", "size", "intent", "control"),
            _edge("e2", "size", "intent", "entry", "intent", "control"),
        )
        provenance = SourceProvenanceV1.original().model_copy(update={"risk_policy_hash": "c" * 64})
    else:
        nodes = (
            _node("event", "bar_event", {}),
            _node(
                "average",
                "sma_indicator",
                {"period": ParameterValueV1(kind="int", value=5)},
                warmup=5,
            ),
        )
        edges = (_edge("e0", "event", "event", "average", "event", "event"),)
        provenance = SourceProvenanceV1.original()
    return GraphV1(
        graph_id="synthetic_reviewed",
        revision=1,
        catalog_id=catalog.catalog_id,
        catalog_version=catalog.version,
        catalog_digest=catalog.canonical_digest(),
        source_hash="a" * 64,
        template_hash=standard_template_catalog_v1().canonical_digest(),
        effective_ns=1_000_000_000,
        symbol="EURUSD",
        timeframe="M1",
        warmup_bars=5 if not trade else 0,
        provenance=provenance,
        nodes=nodes,
        edges=edges,
    )


def _spec(*, trade: bool, platform: str, routing: str = "LocalTerminal") -> ExportSpecV1:
    bindings = (
        (
            ParameterBindingV1("risk", "max_daily_loss", "MaxDailyLoss"),
            ParameterBindingV1("size", "max_lots", "MaxLots"),
        )
        if trade
        else (ParameterBindingV1("average", "period", "Period"),)
    )
    return ExportSpecV1(
        schema_version=1,
        artifact_type="EA" if trade else "INDICATOR",
        platform=platform,
        routing_mode=routing,
        strategy_hash="d" * 64,
        git_commit="e" * 40,
        version_label="synthetic_v1",
        symbol_map=(SymbolMappingV1("EURUSD", "EURUSD"),),
        timeframe_map=(TimeframeMappingV1("M1", "M1"),),
        target_manifest=TargetManifestV1(
            supported_symbols=("EURUSD",),
            supported_timeframes=("M1",),
            occupied_magic_numbers=(456,),
            broker_lot_step=Decimal("0.01"),
        ),
        parameter_bindings=bindings,
        magic_number=123 if trade else None,
    )


@pytest.mark.parametrize("platform", ["MT4", "MT5"])
def test_indicator_source_package_is_deterministic_and_roundtrips(platform: str) -> None:
    graph = _graph(trade=False)
    catalog = standard_catalog_v1()
    validated = validate_graph_for_export(graph, catalog, TargetV1(platform=platform))
    spec = _spec(trade=False, platform=platform)
    templates = standard_template_catalog_v1()
    first = export_source(validated, spec, templates)
    second = export_source(validated, spec, templates)
    assert first.archive_bytes == second.archive_bytes
    assert first.source_text == second.source_text
    assert first.source_filename == ("source.mq4" if platform == "MT4" else "source.mq5")
    assert not first.export_ready and not first.compiled and not first.signed
    assert not re.search(
        r"OrderSend|OrderSendAsync|PositionOpen|CTrade|\btrade\s*\.", first.source_text, re.I
    )
    assert first.route_label == "source-only"
    assert "#property indicator_plots 1" in first.source_text
    assert "SetIndexBuffer(0," in first.source_text
    assert "iMA(" in first.source_text
    roundtrip = import_generated_package(first.archive_bytes)
    assert roundtrip.graph_hash == first.graph_hash
    assert roundtrip.params_hash == first.params_hash
    rebuilt_nodes = {node.node_id: node for node in roundtrip.graph.nodes}
    for node in graph.nodes:
        assert rebuilt_nodes[node.node_id].block_id == node.block_id
        assert dict(rebuilt_nodes[node.node_id].parameters) == dict(node.parameters)
    assert {edge.edge_id: edge.model_dump(mode="json") for edge in roundtrip.graph.edges} == {
        edge.edge_id: edge.model_dump(mode="json") for edge in graph.edges
    }
    manifest = json.loads(first.manifest_json)
    assert manifest["export_ready"] is False
    assert manifest["compiled"] is False and manifest["signed"] is False
    assert manifest["graph_hash"] == first.graph_hash
    assert manifest["params_hash"] == first.params_hash
    if platform == "MT4":
        assert "CopyBuffer" not in first.source_text
        assert "[lv_bar_0_" in first.source_text
    else:
        assert "CopyBuffer" in first.source_text
        assert "lv_sma_0_" in first.source_text


def test_remote_bridge_indicator_contains_no_credentials_or_order_api() -> None:
    graph = _graph(trade=False)
    validated = validate_graph_for_export(graph, standard_catalog_v1(), TargetV1(platform="MT5"))
    package = export_source(
        validated,
        _spec(trade=False, platform="MT5", routing="RemoteBridge"),
        standard_template_catalog_v1(),
    )
    assert "BridgeInterfaceStub" not in package.source_text
    assert "api_key" not in package.source_text.lower()
    assert not re.search(
        r"OrderSend|OrderSendAsync|PositionOpen|CTrade|\\btrade\\s*\\.", package.source_text, re.I
    )
    assert not package.export_ready


@pytest.mark.parametrize("platform", ["MT4", "MT5"])
def test_trade_graph_fails_closed_as_unsupported(platform: str) -> None:
    graph = _graph(trade=True)
    validated = validate_graph_for_export(graph, standard_catalog_v1(), TargetV1(platform=platform))
    with pytest.raises(SourceExportError) as error:
        export_source(
            validated, _spec(trade=True, platform=platform), standard_template_catalog_v1()
        )
    assert error.value.code == "UNSUPPORTED_BLOCK"


def test_semantic_node_edge_and_catalog_permutations_keep_package_bytes() -> None:
    graph = _graph(trade=False)
    catalog = standard_catalog_v1()
    reordered_blocks = tuple(
        block.model_copy(update={"inputs": tuple(reversed(block.inputs))})
        if block.block_id == "control_if"
        else block
        for block in reversed(catalog.blocks)
    )
    reordered_catalog = catalog.model_copy(update={"blocks": reordered_blocks})
    reordered_graph = graph.model_copy(
        update={
            "nodes": tuple(reversed(graph.nodes)),
            "edges": tuple(reversed(graph.edges)),
        }
    )
    assert reordered_catalog.canonical_digest() == catalog.canonical_digest()
    spec = _spec(trade=False, platform="MT5")
    templates = standard_template_catalog_v1()
    original = export_source(
        validate_graph_for_export(graph, catalog, TargetV1(platform="MT5")), spec, templates
    )
    permuted = export_source(
        validate_graph_for_export(reordered_graph, reordered_catalog, TargetV1(platform="MT5")),
        spec,
        templates,
    )
    assert original.archive_bytes == permuted.archive_bytes


def test_archive_tamper_and_secret_parameter_name_fail_closed() -> None:
    graph = _graph(trade=False)
    validated = validate_graph_for_export(graph, standard_catalog_v1(), TargetV1(platform="MT4"))
    package = export_source(
        validated, _spec(trade=False, platform="MT4"), standard_template_catalog_v1()
    )
    with zipfile.ZipFile(io.BytesIO(package.archive_bytes)) as source:
        files = {name: source.read(name) for name in source.namelist()}
    files["source.mq4"] += b"// changed\n"
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as changed:
        for name in sorted(files):
            changed.writestr(name, files[name])
    with pytest.raises(SourceExportError):
        import_generated_package(stream.getvalue())
    with pytest.raises(SourceExportError) as secret:
        ParameterBindingV1("average", "period", "api_key")
    assert secret.value.code == "INVALID_IDENTIFIER"


@pytest.mark.parametrize(
    "name",
    [
        "LEVIATHAN_MAGIC",
        "signal_0",
        "handle_0",
        "lv_user_value",
        "double",
        "datetime",
        "color",
        "uchar",
        "ushort",
        "uint",
        "ulong",
        "pack",
        "offsetof",
        "group",
        "input",
        "sinput",
        "if",
        "return",
        "PERIOD_M1",
        "PRICE_CLOSE",
        "OnCalculate",
    ],
)
def test_generated_names_and_mql_keywords_are_reserved(name: str) -> None:
    with pytest.raises(SourceExportError) as error:
        ParameterBindingV1("average", "period", name)
    assert error.value.code == "RESERVED_NAME"
    assert name not in str(error.value)


def test_reserved_identifier_matching_is_case_sensitive() -> None:
    assert ParameterBindingV1("average", "period", "DateTime").mql_name == "DateTime"


def test_imported_parameter_only_asset_is_ineligible_for_source_export() -> None:
    graph = _graph(trade=False)
    provenance = SourceProvenanceV1(
        source_rights="verified",
        source_asset_kind="parameter_only",
        source_id="KINNOBOT",
        source_version=1,
        source_digest=graph.source_hash,
        unresolved_claims=(),
        reviewed_rules=True,
        risk_policy_hash=None,
        live_order_mode=False,
    )
    imported = graph.model_copy(update={"provenance": provenance})
    validated = validate_graph_for_export(imported, standard_catalog_v1(), TargetV1(platform="MT5"))
    with pytest.raises(SourceExportError) as blocked:
        export_source(
            validated,
            _spec(trade=False, platform="MT5"),
            standard_template_catalog_v1(),
        )
    assert blocked.value.code == "SOURCE_PROVENANCE"


def test_issued_package_copy_and_raw_mutation_have_no_import_authority() -> None:
    graph = _graph(trade=False)
    validated = validate_graph_for_export(graph, standard_catalog_v1(), TargetV1(platform="MT4"))
    package = export_source(
        validated,
        _spec(trade=False, platform="MT4"),
        standard_template_catalog_v1(),
    )
    with pytest.raises(SealError):
        copy(package)
    object.__setattr__(package, "source_text", "unsafe")
    with pytest.raises(SealError):
        import_generated_package(package)


def test_parameter_and_archive_limits_use_typed_export_limit() -> None:
    specification = _spec(trade=False, platform="MT4")
    bindings = tuple(
        ParameterBindingV1("node", "parameter", f"binding_{index}")
        for index in range(MAX_PARAMETER_BINDINGS + 1)
    )
    with pytest.raises(SourceExportError) as parameter_limit:
        replace(specification, parameter_bindings=bindings)
    assert parameter_limit.value.code == "EXPORT_LIMIT"

    with pytest.raises(SourceExportError) as archive_limit:
        _archive({"source.mq4": b"x" * MAX_ARCHIVE_BYTES})
    assert archive_limit.value.code == "EXPORT_LIMIT"
