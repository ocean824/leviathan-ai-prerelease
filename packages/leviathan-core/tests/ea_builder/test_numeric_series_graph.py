from __future__ import annotations

from decimal import Decimal

import pytest

from leviathan_core.ea_builder.blocks import BlockCatalogV1, standard_catalog_v1
from leviathan_core.ea_builder.export_source import (
    SourceExportError,
    standard_template_catalog_v1,
    validate_graph_for_export,
)
from leviathan_core.ea_builder.graph import (
    EdgeV1,
    GraphV1,
    NodeV1,
    ParameterValueV1,
    SourceProvenanceV1,
    TargetV1,
)
from leviathan_core.ea_builder.signal_catalog import extend_signal_catalog_v1
from leviathan_core.ea_builder.validate import validate
from leviathan_core.strategy_ingest.codegen import _lower_risk_metadata
from leviathan_core.strategy_ingest.ir import OperatorKindV1, OperatorV1
from leviathan_core.strategy_ingest.models import StrategyIngestError

_HASH = "a" * 64


def _catalog() -> BlockCatalogV1:
    return extend_signal_catalog_v1(standard_catalog_v1())


def _graph(catalog: BlockCatalogV1, *, invalid_series_sink: bool = False) -> GraphV1:
    nodes = (
        NodeV1(
            node_id="bars",
            block_id="bar_event",
            parameters={},
            symbol="EURUSD",
            timeframe="M5",
            warmup_bars=0,
        ),
        NodeV1(
            node_id="fast",
            block_id="sma_indicator",
            parameters={"period": ParameterValueV1(kind="int", value=3)},
            symbol="EURUSD",
            timeframe="M5",
            warmup_bars=3,
        ),
        NodeV1(
            node_id="slow",
            block_id="sma_indicator",
            parameters={"period": ParameterValueV1(kind="int", value=5)},
            symbol="EURUSD",
            timeframe="M5",
            warmup_bars=5,
        ),
        NodeV1(
            node_id="compare",
            block_id="compare.v1",
            parameters={"op": ParameterValueV1(kind="enum", value="gt")},
            symbol="EURUSD",
            timeframe="M5",
            warmup_bars=0,
        ),
        NodeV1(
            node_id="entry",
            block_id="entry_signal.v1",
            parameters={"signal_key": ParameterValueV1(kind="symbol", value="entry")},
            symbol="EURUSD",
            timeframe="M5",
            warmup_bars=0,
        ),
    )
    edges = [
        EdgeV1(
            edge_id="bar_fast",
            source_node="bars",
            source_port="event",
            target_node="fast",
            target_port="event",
            kind="event",
        ),
        EdgeV1(
            edge_id="bar_slow",
            source_node="bars",
            source_port="event",
            target_node="slow",
            target_port="event",
            kind="event",
        ),
        EdgeV1(
            edge_id="fast_left",
            source_node="fast",
            source_port="value",
            target_node="compare",
            target_port="left",
            kind="data",
        ),
        EdgeV1(
            edge_id="slow_right",
            source_node="slow",
            source_port="value",
            target_node="compare",
            target_port="right",
            kind="data",
        ),
        EdgeV1(
            edge_id="condition_entry",
            source_node="fast" if invalid_series_sink else "compare",
            source_port="value" if invalid_series_sink else "condition",
            target_node="entry",
            target_port="condition",
            kind="data",
        ),
    ]
    return GraphV1(
        graph_id="numeric_series_fixture",
        revision=1,
        catalog_id=catalog.catalog_id,
        catalog_version=catalog.version,
        catalog_digest=catalog.canonical_digest(),
        source_hash=_HASH,
        template_hash=standard_template_catalog_v1().canonical_digest(),
        effective_ns=1,
        symbol="EURUSD",
        timeframe="M5",
        warmup_bars=5,
        provenance=SourceProvenanceV1.original(),
        nodes=nodes,
        edges=tuple(edges),
    )


def test_sma_numeric_series_connects_to_existing_decimal_signal_inputs() -> None:
    catalog = _catalog()
    definitions = {block.block_id: block for block in catalog.blocks}
    assert definitions["sma_indicator"].outputs[0].kind == "numeric-series"
    assert {port.kind for port in definitions["compare.v1"].inputs} == {"decimal"}
    assert {port.kind for port in definitions["crossover.v1"].inputs} == {"decimal"}
    result = validate(_graph(catalog), catalog, TargetV1(platform="MT4"))
    assert result.status == "VALID"
    assert not result.errors


def test_numeric_series_cannot_connect_to_boolean_signal_condition() -> None:
    catalog = _catalog()
    result = validate(_graph(catalog, invalid_series_sink=True), catalog, TargetV1(platform="MT4"))
    assert result.status == "INVALID"
    assert any(issue.code == "TYPE_MISMATCH" for issue in result.errors)


def test_synthetic_graph_cannot_claim_strategy_source_provenance() -> None:
    catalog = _catalog()
    graph = _graph(catalog).model_copy(
        update={
            "strategy_source_id": "synthetic-strategy",
            "strategy_source_digest": _HASH,
        }
    )
    with pytest.raises(SourceExportError) as caught:
        validate_graph_for_export(graph, catalog, TargetV1(platform="MT5"))
    assert caught.value.code == "SOURCE_PROVENANCE"
    assert str(caught.value) == "SOURCE_PROVENANCE:strategy_source"


def test_unknown_risk_claim_reference_fails_content_free_in_internal_lowering() -> None:
    operator = OperatorV1(
        node_id="position_cap",
        kind=OperatorKindV1.POSITION_CAP,
        action=None,
        inputs=(),
        period=None,
        value=Decimal("3"),
        unit="positions",
        evidence_id="missing_claim",
    )
    with pytest.raises(StrategyIngestError) as caught:
        _lower_risk_metadata(set(), (operator,))
    assert caught.value.code == "UNKNOWN_SOURCE_CLAIM"
    assert str(caught.value) == "UNKNOWN_SOURCE_CLAIM"
