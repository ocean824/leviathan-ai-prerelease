"""Independent acceptance tests for deterministic EA-002 source-only export."""

from __future__ import annotations

import hashlib
import io
import json
import re
import subprocess
import sys
import zipfile
from collections.abc import Callable
from dataclasses import replace
from decimal import Decimal, localcontext
from pathlib import Path

import pytest
from pydantic import BaseModel

from leviathan_core.ea_builder import (
    EaModelError,
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
    ExportSpecV1,
    ParameterBindingV1,
    SourceExportError,
    SourcePackageV1,
    SymbolMappingV1,
    TargetManifestV1,
    TemplateCatalogV1,
    TimeframeMappingV1,
    export_source,
    standard_template_catalog_v1,
    validate_graph_for_export,
)
from leviathan_core.ea_builder.roundtrip import import_generated_package
from leviathan_core.seal import SealError, require, verify

ROOT = Path(__file__).resolve().parents[4]
TEMPLATE = standard_template_catalog_v1()
STRATEGY_HASH = "d" * 64
SOURCE_HASH = "a" * 64
COMMIT_HASH = "e" * 40
ORDER_PRIMITIVES = re.compile(
    r"\b(?:OrderSend|OrderSendAsync|OrderClose|OrderModify|PositionOpen|"
    r"PositionClose|CTrade|MqlTradeRequest)\b|\btrade\s*\.",
    re.IGNORECASE,
)


def _node(
    node_id: str,
    block_id: str,
    parameters: dict[str, ParameterValueV1] | None = None,
    *,
    warmup: int = 0,
) -> NodeV1:
    return NodeV1(
        node_id=node_id,
        block_id=block_id,
        parameters={} if parameters is None else parameters,
        symbol="EURUSD",
        timeframe="M1",
        warmup_bars=warmup,
    )


def _edge(
    edge_id: str,
    source: str,
    source_port: str,
    target: str,
    target_port: str,
    kind: str,
) -> EdgeV1:
    return EdgeV1(
        edge_id=edge_id,
        source_node=source,
        source_port=source_port,
        target_node=target,
        target_port=target_port,
        kind=kind,
    )


def make_graph(*, trade: bool, reverse: bool = False) -> GraphV1:
    catalog = standard_catalog_v1()
    if trade:
        provenance = SourceProvenanceV1.original().model_copy(update={"risk_policy_hash": "c" * 64})
        nodes = (
            _node("market_clock", "tick_event"),
            _node(
                "risk_guard",
                "risk_cap",
                {"max_daily_loss": ParameterValueV1(kind="percent", value=Decimal("5"))},
            ),
            _node(
                "position_size",
                "money_size",
                {"max_lots": ParameterValueV1(kind="decimal", value=Decimal("0.1"))},
            ),
            _node("entry_gate", "trade_entry"),
        )
        edges = (
            _edge("ev-market-risk", "market_clock", "event", "risk_guard", "event", "event"),
            _edge("ev-risk-size", "risk_guard", "intent", "position_size", "intent", "control"),
            _edge("ev-size-entry", "position_size", "intent", "entry_gate", "intent", "control"),
        )
    else:
        provenance = SourceProvenanceV1.original()
        nodes = (
            _node("market_bars", "bar_event"),
            _node(
                "trend_average",
                "sma_indicator",
                {"period": ParameterValueV1(kind="int", value=5)},
                warmup=5,
            ),
        )
        edges = (_edge("ev-bars-sma", "market_bars", "event", "trend_average", "event", "event"),)
    if reverse:
        nodes = tuple(reversed(nodes))
        edges = tuple(reversed(edges))
    return GraphV1(
        graph_id="synthetic_reviewed_graph",
        revision=1,
        catalog_id=catalog.catalog_id,
        catalog_version=catalog.version,
        catalog_digest=catalog.canonical_digest(),
        source_hash=SOURCE_HASH,
        template_hash=TEMPLATE.canonical_digest(),
        effective_ns=1_800_000_000_000_000_000,
        symbol="EURUSD",
        timeframe="M1",
        warmup_bars=5 if not trade else 0,
        provenance=provenance,
        nodes=nodes,
        edges=edges,
    )


def make_spec(
    *,
    trade: bool,
    platform: str,
    routing: str = "LocalTerminal",
    reverse: bool = False,
) -> ExportSpecV1:
    bindings = (
        (
            ParameterBindingV1("risk_guard", "max_daily_loss", "MaxDailyLoss"),
            ParameterBindingV1("position_size", "max_lots", "MaxLots"),
        )
        if trade
        else (ParameterBindingV1("trend_average", "period", "AveragePeriod"),)
    )
    if reverse:
        bindings = tuple(reversed(bindings))
    return ExportSpecV1(
        schema_version=1,
        artifact_type="EA" if trade else "INDICATOR",
        platform=platform,
        routing_mode=routing,
        strategy_hash=STRATEGY_HASH,
        git_commit=COMMIT_HASH,
        version_label="synthetic_acceptance_v1",
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


def make_package(
    *,
    trade: bool,
    platform: str = "MT5",
    routing: str = "LocalTerminal",
    reverse: bool = False,
    graph: GraphV1 | None = None,
    spec: ExportSpecV1 | None = None,
    templates: TemplateCatalogV1 | None = None,
) -> SourcePackageV1:
    graph = make_graph(trade=trade, reverse=reverse) if graph is None else graph
    catalog = standard_catalog_v1()
    validated = validate_graph_for_export(graph, catalog, TargetV1(platform=platform))
    chosen_spec = (
        make_spec(trade=trade, platform=platform, routing=routing, reverse=reverse)
        if spec is None
        else spec
    )
    return export_source(
        validated,
        chosen_spec,
        standard_template_catalog_v1() if templates is None else templates,
    )


def assert_safe_export_error(error: SourceExportError, canary: str | None = None) -> None:
    assert error.code
    assert error.field
    assert "http" not in str(error).lower()
    assert canary is None or canary not in str(error)
    assert canary is None or canary not in repr(error.args)


def assert_tampering_is_denied_or_detected(
    package: SourcePackageV1, attempt: Callable[[], object]
) -> None:
    try:
        attempt()
    except SealError as error:
        assert error.code == "SEAL_FORBIDDEN_OPERATION"
        assert "tampered" not in str(error)
    else:
        assert not verify(package, "ea002.source_package")
        with pytest.raises(SealError):
            require(package, "ea002.source_package")
        with pytest.raises(SealError):
            import_generated_package(package)


@pytest.mark.parametrize("platform", ["MT4", "MT5"])
def test_source_package_is_repeatable_roundtrippable_and_source_only(
    platform: str,
) -> None:
    graph = make_graph(trade=False)
    package = make_package(trade=False, platform=platform, graph=graph)
    same = make_package(trade=False, platform=platform, graph=graph)

    assert package.archive_bytes == same.archive_bytes
    assert package.source_text == same.source_text
    assert package.build_id == same.build_id
    assert package.source_filename == ("source.mq4" if platform == "MT4" else "source.mq5")
    assert package.export_ready is False
    assert package.compiled is False
    assert package.signed is False
    assert not ORDER_PRIMITIVES.search(package.source_text)
    assert "SYNTHETIC_SECRET" not in package.source_text
    assert "SYNTHETIC_TOKEN" not in package.archive_bytes.decode("latin1")
    assert package.route_label == "source-only"

    with zipfile.ZipFile(io.BytesIO(package.archive_bytes)) as archive:
        names = archive.namelist()
        files = {name: archive.read(name) for name in names}
    assert names == sorted(names)
    assert set(names) == {
        package.source_filename,
        "README.txt",
        "catalog.json",
        "checksums.json",
        "dependencies.json",
        "export-spec.json",
        "graph.json",
        "manifest.json",
        "parameter-map.json",
        "provenance.txt",
        "templates.json",
    }
    expected_checksums = {
        name: hashlib.sha256(content).hexdigest()
        for name, content in files.items()
        if name != "checksums.json"
    }
    assert json.loads(files["checksums.json"]) == expected_checksums
    manifest = json.loads(package.manifest_json)
    assert manifest["export_ready"] is False
    assert manifest["compiled"] is False and manifest["signed"] is False
    assert manifest["source_filename"] == package.source_filename
    assert files["manifest.json"].decode("ascii") == package.manifest_json
    assert b"SOURCE ONLY" in files["README.txt"]
    assert b"No compilation" in files["provenance.txt"]
    assert json.loads(files["dependencies.json"]) == []

    imported = import_generated_package(package)
    imported_bytes = import_generated_package(package.archive_bytes)
    assert imported.graph_hash == package.graph_hash
    assert imported.params_hash == package.params_hash
    assert imported.build_id == package.build_id
    assert imported.source_text == package.source_text
    assert imported_bytes.graph_hash == package.graph_hash
    before = {node.node_id: node.model_dump(mode="json") for node in graph.nodes}
    after = {node.node_id: node.model_dump(mode="json") for node in imported.graph.nodes}
    assert after == before
    assert {node.node_id: node.block_id for node in imported.graph.nodes} == {
        node.node_id: node.block_id for node in graph.nodes
    }
    assert not ORDER_PRIMITIVES.search(imported.source_text)
    if platform == "MT4":
        assert "CopyBuffer" not in package.source_text
    else:
        assert "CopyBuffer" in package.source_text


@pytest.mark.parametrize("platform", ["MT4", "MT5"])
def test_indicator_exports_publish_sma_values_through_plot_buffers(platform: str) -> None:
    package = make_package(trade=False, platform=platform)
    source = package.source_text
    sma_outputs = sum(node.block_id == "sma_indicator" for node in make_graph(trade=False).nodes)
    plot_match = re.search(r"(?m)^#property indicator_plots\s+(\d+)\s*$", source)

    assert plot_match is not None
    plot_count = int(plot_match.group(1))
    assert plot_count > 0
    assert plot_count == sma_outputs

    buffers = re.findall(
        r"\bSetIndexBuffer\s*\(\s*(\d+)\s*,\s*([A-Za-z_][A-Za-z0-9_]*)",
        source,
    )
    assert [int(index) for index, _ in buffers] == list(range(sma_outputs))
    assert len({name for _, name in buffers}) == sma_outputs
    assert "iMA(" in source
    for _, buffer_name in buffers:
        assigned_sma = re.search(
            rf"\b{re.escape(buffer_name)}\s*\[[^\]]+\]\s*=\s*[^;]*\biMA\s*\(",
            source,
        )
        copied_sma = re.search(rf"\bCopyBuffer\s*\([^;]*,\s*{re.escape(buffer_name)}\s*\)", source)
        assert assigned_sma is not None or copied_sma is not None


@pytest.mark.parametrize(
    "unsupported_block", ["tick_event", "session_event", "state", "control_loop"]
)
def test_block_without_source_semantics_is_rejected_instead_of_comment_only(
    unsupported_block: str,
) -> None:
    base = make_graph(trade=False)
    spec = make_spec(trade=False, platform="MT5")
    if unsupported_block in {"tick_event", "session_event"}:
        graph = base.model_copy(
            update={
                "nodes": (
                    base.nodes[0].model_copy(update={"block_id": unsupported_block}),
                    base.nodes[1],
                )
            }
        )
    else:
        parameters = (
            {"max_iterations": ParameterValueV1(kind="int", value=2)}
            if unsupported_block == "control_loop"
            else {}
        )
        middle_node = _node("comment_only_node", unsupported_block, parameters)
        graph = base.model_copy(
            update={
                "nodes": (base.nodes[0], middle_node, base.nodes[1]),
                "edges": (
                    _edge(
                        "ev-bars-middle",
                        "market_bars",
                        "event",
                        "comment_only_node",
                        "event",
                        "event",
                    ),
                    _edge(
                        "ev-middle-sma",
                        "comment_only_node",
                        "event",
                        "trend_average",
                        "event",
                        "event",
                    ),
                ),
            }
        )
        if parameters:
            spec = replace(
                spec,
                parameter_bindings=(
                    *spec.parameter_bindings,
                    ParameterBindingV1("comment_only_node", "max_iterations", "MaxIterations"),
                ),
            )
    validated = validate_graph_for_export(
        graph,
        standard_catalog_v1(),
        TargetV1(platform="MT5"),
    )

    with pytest.raises(SourceExportError) as caught:
        export_source(validated, spec, TEMPLATE)
    assert caught.value.code == "UNSUPPORTED_BLOCK"


@pytest.mark.parametrize(
    "reserved_name",
    [
        "LEVIATHAN_MAGIC",
        "signal_0",
        "handle_0",
        "lv_user_value",
        "double",
        "input",
        "if",
        "return",
    ],
)
def test_generated_and_mql_reserved_parameter_names_are_rejected(reserved_name: str) -> None:
    with pytest.raises(SourceExportError) as caught:
        ParameterBindingV1("trend_average", "period", reserved_name)
    assert caught.value.code == "RESERVED_NAME"


def test_semantic_permutation_preserves_archive_and_build_identity() -> None:
    original = make_package(trade=False, platform="MT5")
    reordered_graph = make_graph(trade=False, reverse=True)
    reordered_spec = make_spec(trade=False, platform="MT5", reverse=True)
    reordered_templates = TemplateCatalogV1(
        catalog_id=TEMPLATE.catalog_id,
        version=TEMPLATE.version,
        mappings=tuple(reversed(TEMPLATE.mappings)),
    )
    permuted = make_package(
        trade=False,
        platform="MT5",
        reverse=True,
        graph=reordered_graph,
        spec=reordered_spec,
        templates=reordered_templates,
    )

    assert original.archive_bytes == permuted.archive_bytes
    assert original.source_text == permuted.source_text
    assert original.build_id == permuted.build_id
    assert original.graph_hash == permuted.graph_hash
    assert original.params_hash == permuted.params_hash
    assert original.template_hash == permuted.template_hash


def test_identical_input_is_byte_identical_in_a_fresh_process() -> None:
    script = (
        "import hashlib, runpy; "
        f"ns=runpy.run_path({str(Path(__file__).resolve())!r}); "
        "pkg=ns['make_package'](trade=False, platform='MT5'); "
        "print(hashlib.sha256(pkg.archive_bytes).hexdigest())"
    )
    expected = hashlib.sha256(make_package(trade=False).archive_bytes).hexdigest()
    child = subprocess.run(
        [sys.executable, "-c", script],
        cwd=ROOT,
        capture_output=True,
        check=True,
        text=True,
        timeout=30,
    )
    assert child.stderr == ""
    assert child.stdout.strip() == expected


@pytest.mark.parametrize("platform", ["MT4", "MT5"])
@pytest.mark.parametrize("routing", ["LocalTerminal", "RemoteBridge"])
@pytest.mark.parametrize("artifact_trade", [False, True])
def test_trade_graphs_are_unsupported_for_all_routes_and_artifact_types(
    platform: str, routing: str, artifact_trade: bool
) -> None:
    base = make_graph(trade=True)
    graph = base.model_copy(
        update={
            "nodes": (*base.nodes, _node("exit_gate", "trade_exit")),
            "edges": (
                *base.edges,
                _edge("ev-size-exit", "position_size", "intent", "exit_gate", "intent", "control"),
            ),
        }
    )
    spec = make_spec(trade=artifact_trade, platform=platform, routing=routing)

    with pytest.raises(SourceExportError) as caught:
        make_package(
            trade=artifact_trade,
            platform=platform,
            routing=routing,
            graph=graph,
            spec=spec,
        )
    assert caught.value.code == "UNSUPPORTED_BLOCK"
    assert_safe_export_error(caught.value)


def test_unlicensed_parameter_only_opaque_and_unresolved_research_are_ineligible() -> None:
    valid = make_graph(trade=False)
    negative_sources = (
        SourceProvenanceV1(
            source_rights="unverified",
            source_asset_kind="source_code",
            source_id="synthetic_mtr_copy",
            source_version=1,
            source_digest="1" * 64,
            unresolved_claims=("CAND-01",),
            reviewed_rules=False,
            risk_policy_hash=None,
            live_order_mode=False,
        ),
        SourceProvenanceV1(
            source_rights="unverified",
            source_asset_kind="parameter_only",
            source_id="synthetic_kinnobot_set",
            source_version=1,
            source_digest="2" * 64,
            unresolved_claims=("CAND-02",),
            reviewed_rules=False,
            risk_policy_hash=None,
            live_order_mode=False,
        ),
        SourceProvenanceV1(
            source_rights="prohibited",
            source_asset_kind="opaque_binary",
            source_id="synthetic_hft_binary",
            source_version=1,
            source_digest="3" * 64,
            unresolved_claims=("CAND-03",),
            reviewed_rules=False,
            risk_policy_hash=None,
            live_order_mode=False,
        ),
        SourceProvenanceV1(
            source_rights="unverified",
            source_asset_kind="source_code",
            source_id="synthetic_bitcoin_course",
            source_version=1,
            source_digest="4" * 64,
            unresolved_claims=("CAND-04",),
            reviewed_rules=True,
            risk_policy_hash=None,
            live_order_mode=False,
        ),
    )

    for source in negative_sources:
        ineligible = valid.model_copy(update={"provenance": source})
        with pytest.raises(SourceExportError) as caught:
            make_package(
                trade=False,
                platform="MT5",
                graph=ineligible,
            )
        assert_safe_export_error(caught.value)


def test_mtr_conflicting_variants_and_failed_research_never_receive_badges() -> None:
    baseline = make_graph(trade=False)
    variants = (
        SourceProvenanceV1(
            source_rights="unverified",
            source_asset_kind="source_code",
            source_id="synthetic_mtr_grid_mode_a",
            source_version=1,
            source_digest="5" * 64,
            unresolved_claims=("CAND-05", "CAND-06"),
            reviewed_rules=False,
            risk_policy_hash=None,
            live_order_mode=False,
        ),
        SourceProvenanceV1(
            source_rights="unverified",
            source_asset_kind="source_code",
            source_id="synthetic_mtr_grid_mode_b_failed_oos_latency",
            source_version=1,
            source_digest="6" * 64,
            unresolved_claims=("CAND-07", "CAND-08"),
            reviewed_rules=False,
            risk_policy_hash=None,
            live_order_mode=False,
        ),
    )
    outputs: list[bytes] = []

    for source in variants:
        graph = baseline.model_copy(update={"provenance": source})
        assert graph.provenance.source_id != baseline.provenance.source_id
        with pytest.raises(SourceExportError):
            outputs.append(make_package(trade=False, graph=graph).archive_bytes)

    assert outputs == []
    assert variants[0].source_digest != variants[1].source_digest
    assert variants[0].unresolved_claims != variants[1].unresolved_claims


def test_unmapped_unsupported_invalid_and_conflicting_target_inputs_fail_closed() -> None:
    base = make_graph(trade=False)
    package_spec = make_spec(trade=False, platform="MT5")

    bad_symbol = replace(
        package_spec,
        symbol_map=(SymbolMappingV1("EURUSD", "GBPUSD"),),
    )
    with pytest.raises(SourceExportError) as caught:
        make_package(trade=False, platform="MT5", graph=base, spec=bad_symbol)
    assert caught.value.code == "UNRESOLVED_SYMBOL"

    with pytest.raises(SourceExportError) as caught:
        TimeframeMappingV1("M1", "H12")
    assert_safe_export_error(caught.value)
    assert caught.value.code == "UNRESOLVED_TIMEFRAME"

    unsupported = TemplateCatalogV1(
        catalog_id="synthetic_incomplete_templates",
        version=1,
        mappings=tuple(item for item in TEMPLATE.mappings if item.block_id != "sma_indicator"),
    )
    with pytest.raises(SourceExportError):
        make_package(
            trade=False,
            platform="MT5",
            graph=base,
            spec=package_spec,
            templates=unsupported,
        )

    with pytest.raises(SourceExportError):
        validate_graph_for_export(None, standard_catalog_v1(), TargetV1(platform="MT5"))  # type: ignore[arg-type]


def test_trade_parameter_canary_is_rejected_without_reflection() -> None:
    with pytest.raises(SourceExportError) as caught:
        ParameterBindingV1("trend_average", "period", "API_TOKEN_CANARY")
    assert_safe_export_error(caught.value, "API_TOKEN_CANARY")


def test_wrong_parameter_types_and_naive_timestamp_fail_with_typed_errors() -> None:
    with pytest.raises(EaModelError) as caught:
        ParameterValueV1(kind="int", value=True)
    assert caught.value.code == "INVALID_EA_MODEL"

    graph = make_graph(trade=False)
    out_of_bounds = graph.model_copy(
        update={
            "nodes": tuple(
                node.model_copy(
                    update={"parameters": {"period": ParameterValueV1(kind="int", value=0)}}
                )
                if node.node_id == "trend_average"
                else node
                for node in graph.nodes
            )
        }
    )
    with pytest.raises(SourceExportError) as caught:
        validate_graph_for_export(out_of_bounds, standard_catalog_v1(), TargetV1(platform="MT5"))
    assert caught.value.code == "GRAPH_INVALID"

    with pytest.raises(EaModelError) as caught:
        graph.model_copy(update={"effective_ns": "2025-11-02 01:30:00"})
    assert caught.value.code
    assert "2025-11-02" not in str(caught.value)


def test_hostile_identifier_and_spec_failures_are_content_free() -> None:
    spec = make_spec(trade=False, platform="MT5")
    canary = "SYNTHETIC SECRET TOKEN MUST NOT ECHO"
    with pytest.raises(SourceExportError) as caught:
        replace(spec, version_label=canary)
    assert_safe_export_error(caught.value, canary)

    with pytest.raises(SourceExportError) as caught:
        replace(spec, schema_version=True)
    assert caught.value.code == "SCHEMA_VERSION"

    with pytest.raises(SourceExportError) as caught:
        replace(
            spec,
            target_manifest=replace(
                spec.target_manifest,
                occupied_magic_numbers=(True,),  # type: ignore[arg-type]
            ),
        )
    assert caught.value.code == "INVALID_INTEGER"


def test_indicator_export_identity_is_decimal_context_independent() -> None:
    graph = make_graph(trade=False)
    catalog = standard_catalog_v1()
    validated = validate_graph_for_export(graph, catalog, TargetV1(platform="MT4"))
    spec = make_spec(trade=False, platform="MT4")
    spec = replace(
        spec,
        target_manifest=replace(
            spec.target_manifest,
            broker_lot_step=Decimal("0.010000000000000000000000000001"),
        ),
    )
    with localcontext() as context:
        context.prec = 6
        low_precision = export_source(validated, spec, TEMPLATE)
    with localcontext() as context:
        context.prec = 60
        high_precision = export_source(validated, spec, TEMPLATE)

    assert low_precision.archive_bytes == high_precision.archive_bytes


def test_import_rejects_tampered_noncanonical_and_arbitrary_archives() -> None:
    package = make_package(trade=False, platform="MT4")
    tampered = bytearray(package.archive_bytes)
    tampered[-1] ^= 1
    with pytest.raises(SourceExportError):
        import_generated_package(bytes(tampered))
    with pytest.raises(SourceExportError):
        import_generated_package(b"void OnTick() {}")
    with pytest.raises(SourceExportError):
        import_generated_package(b"x" * (MAX_ARCHIVE_BYTES + 1))


def test_issued_export_records_block_copy_reinit_and_tamper_authority() -> None:
    package = make_package(trade=False, platform="MT5")
    validated = validate_graph_for_export(
        make_graph(trade=False),
        standard_catalog_v1(),
        TargetV1(platform="MT5"),
    )

    copied = package.model_copy(update={"source_text": "unsafe"})
    assert not verify(copied, "ea002.source_package")
    with pytest.raises(SealError):
        import_generated_package(copied)
    with pytest.raises(SealError):
        package.source_text = "unsafe"
    with pytest.raises(SealError):
        del package.source_text
    with pytest.raises(SealError):
        package.copy(update={"source_text": "unsafe"})
    with pytest.raises(SealError):
        package.model_construct(source_text="unsafe")
    with pytest.raises(SealError):
        BaseModel.__init__(
            package,
            archive_b64="",
            source_text="rewritten",
            source_filename="source.mq5",
            manifest_json="{}",
            parameter_map_json="[]",
            build_id="0" * 64,
            graph_hash="0" * 64,
            params_hash="0" * 64,
            template_hash="0" * 64,
            catalog_digest="0" * 64,
            route_label="source-only",
            export_ready=False,
            compiled=False,
            signed=False,
        )
    copy_package_pickle(package)

    forged = SourcePackageV1(
        archive_b64="",
        source_text="",
        source_filename="source.mq5",
        manifest_json="{}",
        parameter_map_json="[]",
        build_id="0" * 64,
        graph_hash="0" * 64,
        params_hash="0" * 64,
        template_hash="0" * 64,
        catalog_digest="0" * 64,
        route_label="source-only",
        export_ready=False,
        compiled=False,
        signed=False,
    )
    assert not verify(forged, "ea002.source_package")
    with pytest.raises(SealError):
        import_generated_package(forged)

    class EqualPackage(SourcePackageV1):
        def __eq__(self, other: object) -> bool:
            return True

        def __hash__(self) -> int:
            return 1

    equal_unissued = EqualPackage(**package.model_dump())
    assert equal_unissued == package
    assert not verify(equal_unissued, "ea002.source_package")
    with pytest.raises(SourceExportError):
        import_generated_package(equal_unissued)

    assert_tampering_is_denied_or_detected(
        package,
        lambda: object.__setattr__(package, "source_text", "tampered"),
    )
    assert verify(validated, "ea002.validated_graph")

    replaced_dict = make_package(trade=False, platform="MT5")
    assert_tampering_is_denied_or_detected(
        replaced_dict,
        lambda: object.__setattr__(
            replaced_dict,
            "__dict__",
            {**replaced_dict.__dict__, "source_text": "tampered"},
        ),
    )


def copy_package_pickle(package: SourcePackageV1) -> None:
    import copy
    import pickle

    with pytest.raises(SealError):
        copy.copy(package)
    with pytest.raises(SealError):
        copy.deepcopy(package)
    with pytest.raises(SealError):
        pickle.dumps(package)


def test_base_setstate_tampering_is_rejected_at_package_boundary() -> None:
    package = make_package(trade=False, platform="MT5")
    assert_tampering_is_denied_or_detected(
        package,
        lambda: BaseModel.__setstate__(package, {"source_text": "tampered"}),
    )

    empty_state = make_package(trade=False, platform="MT5")
    assert_tampering_is_denied_or_detected(
        empty_state,
        lambda: BaseModel.__setstate__(empty_state, {}),
    )


def test_export_node_cap_and_parameter_bundle_caps_precede_expansion() -> None:
    graph = make_graph(trade=False)
    oversized_graph = graph.model_copy(
        update={"nodes": tuple(_node(f"extra_{index:04d}", "bar_event") for index in range(257))}
    )
    with pytest.raises(SourceExportError) as caught:
        validate_graph_for_export(
            oversized_graph,
            standard_catalog_v1(),
            TargetV1(platform="MT4"),
        )
    assert caught.value.code == "EXPORT_LIMIT"
