"""Independent adversarial acceptance tests for the EA-001 static graph contract."""

from __future__ import annotations

import copy
import json
import pickle
from dataclasses import replace
from decimal import Decimal
from pathlib import Path

import pytest

from leviathan_core.ea_builder import (
    BlockCatalogV1,
    BlockDefinitionV1,
    EaModelError,
    EdgeV1,
    FrozenEaRecordError,
    GraphIssueV1,
    GraphV1,
    GraphValidationV1,
    NodeV1,
    ParameterSpecV1,
    ParameterValueV1,
    PortV1,
    RiskCapsCandidateV1,
    SourceProvenanceV1,
    TargetV1,
    validate,
    verify_risk_caps,
)
from leviathan_core.ea_builder.graph import _CAPS_TOKEN, _VERIFIER_TOKEN, VerifiedRiskCapsV1

FIXTURES = Path(__file__).parent / "fixtures" / "graph"
HASH = "a" * 64


def port(
    name: str,
    kind: str,
    *,
    unit: str | None = None,
    required: bool = False,
    symbol_scope: str | None = None,
    timeframe_scope: str | None = None,
) -> PortV1:
    return PortV1(
        name=name,
        kind=kind,
        unit=unit,
        required=required,
        symbol_scope=symbol_scope,
        timeframe_scope=timeframe_scope,
    )


def block(
    block_id: str,
    category: str,
    *,
    inputs: tuple[PortV1, ...] = (),
    outputs: tuple[PortV1, ...] = (),
    parameters: tuple[ParameterSpecV1, ...] = (),
    targets: tuple[str, ...] = ("MT4", "MT5"),
    warmup_bars: int = 0,
    delay_bound: int | None = None,
) -> BlockDefinitionV1:
    return BlockDefinitionV1(
        block_id=block_id,
        category=category,
        inputs=inputs,
        outputs=outputs,
        parameters=parameters,
        targets=targets,
        warmup_bars=warmup_bars,
        delay_bound=delay_bound,
    )


def _acceptance_catalog() -> BlockCatalogV1:
    return BlockCatalogV1(
        catalog_id="acceptance-catalog",
        version=1,
        blocks=(
            block(
                "event",
                "event",
                outputs=(port("pulse", "event"), port("value", "decimal", unit="price")),
            ),
            block(
                "indicator",
                "indicator",
                inputs=(port("value", "decimal", unit="price", required=True),),
                outputs=(port("value", "decimal", unit="price"),),
                warmup_bars=5,
            ),
            block(
                "math",
                "math",
                inputs=(port("in", "decimal", unit="price"),),
                outputs=(port("out", "decimal", unit="price"),),
            ),
            block(
                "risk",
                "risk",
                inputs=(port("in", "event"),),
                outputs=(port("pulse", "event"),),
            ),
            block(
                "trade",
                "trade",
                inputs=(port("trigger", "event", required=True),),
            ),
            block(
                "mt4-only",
                "indicator",
                targets=("MT4",),
            ),
        ),
    )


@pytest.fixture
def base_catalog() -> BlockCatalogV1:
    return _acceptance_catalog()


def node(
    node_id: str,
    block_id: str,
    *,
    parameters: dict[str, ParameterValueV1] | None = None,
    symbol: str = "EURUSD",
    timeframe: str = "M5",
    warmup_bars: int = 5,
) -> NodeV1:
    return NodeV1(
        node_id=node_id,
        block_id=block_id,
        parameters=parameters or {},
        symbol=symbol,
        timeframe=timeframe,
        warmup_bars=warmup_bars,
    )


def edge(
    edge_id: str,
    source: str,
    source_port: str,
    target: str,
    target_port: str,
    *,
    kind: str = "data",
) -> EdgeV1:
    return EdgeV1(
        edge_id=edge_id,
        source_node=source,
        source_port=source_port,
        target_node=target,
        target_port=target_port,
        kind=kind,
    )


def graph(
    nodes: tuple[NodeV1, ...],
    edges: tuple[EdgeV1, ...] = (),
    *,
    warmup_bars: int = 5,
    provenance: SourceProvenanceV1 | None = None,
    catalog: BlockCatalogV1 | None = None,
) -> GraphV1:
    bound_catalog = catalog or _acceptance_catalog()
    return GraphV1(
        graph_id="acceptance-graph",
        revision=1,
        catalog_id=bound_catalog.catalog_id,
        catalog_version=bound_catalog.version,
        catalog_digest=bound_catalog.canonical_digest(),
        source_hash=HASH,
        template_hash=HASH,
        effective_ns=1,
        symbol="EURUSD",
        timeframe="M5",
        warmup_bars=warmup_bars,
        provenance=provenance or SourceProvenanceV1.original(),
        nodes=nodes,
        edges=edges,
    )


def codes(result: object) -> set[str]:
    return {issue.code for issue in result.issues}  # type: ignore[attr-defined]


def assert_ea_error_does_not_echo(error: EaModelError, canary: str) -> None:
    assert canary not in str(error)
    assert canary not in repr(error.args)
    assert canary not in json.dumps(error.errors(), sort_keys=True)


def test_valid_trade_graph_is_static_validation_only(base_catalog: BlockCatalogV1) -> None:
    provenance = SourceProvenanceV1(
        source_rights="verified",
        source_asset_kind="original",
        source_id=None,
        source_version=None,
        source_digest=None,
        unresolved_claims=(),
        reviewed_rules=True,
        risk_policy_hash=HASH,
        live_order_mode=False,
    )
    candidate = graph(
        (node("clock", "event"), node("risk", "risk"), node("trade", "trade")),
        (
            edge("risk-gate-in", "clock", "pulse", "risk", "in", kind="event"),
            edge("trigger", "risk", "pulse", "trade", "trigger", kind="event"),
        ),
        provenance=provenance,
    )

    result = validate(candidate, base_catalog, TargetV1(platform="MT5"))

    assert result.status == "VALID", result.issues
    assert result.exportable is False
    assert result.cap_check == "NOT_PERFORMED"
    assert result.export_ready is False
    assert result.errors == ()
    # Static linting does not return an executable, compiler, deployment, or order handle.
    assert set(type(result).model_fields) == {
        "status",
        "issues",
        "errors",
        "warnings",
        "auto_fixes",
        "exportable",
        "cap_check",
        "export_ready",
    }
    assert not any(
        hasattr(result, name) for name in ("compile", "execute", "submit_order", "deploy")
    )


def test_data_cycle_is_rejected_and_never_exportable(base_catalog: BlockCatalogV1) -> None:
    candidate = graph(
        (node("left", "math"), node("right", "math")),
        (
            edge("left-right", "left", "out", "right", "in"),
            edge("right-left", "right", "out", "left", "in"),
        ),
    )

    result = validate(candidate, base_catalog, TargetV1(platform="MT5"))

    assert result.status == "INVALID"
    assert "DATA_CYCLE" in codes(result)
    assert result.exportable is False


def test_event_path_cannot_bypass_risk_gate(base_catalog: BlockCatalogV1) -> None:
    provenance = SourceProvenanceV1(
        source_rights="verified",
        source_asset_kind="original",
        source_id=None,
        source_version=None,
        source_digest=None,
        unresolved_claims=(),
        reviewed_rules=True,
        risk_policy_hash=HASH,
        live_order_mode=False,
    )
    candidate = graph(
        (node("clock", "event"), node("risk", "risk"), node("trade", "trade")),
        (edge("direct-entry", "clock", "pulse", "trade", "trigger", kind="event"),),
        provenance=provenance,
    )

    result = validate(candidate, base_catalog, TargetV1(platform="MT5"))

    assert {"MISSING_RISK_BLOCK", "RISK_BYPASS"} <= codes(result)
    assert result.exportable is False


def test_order_capable_graph_without_pinned_risk_policy_fails_closed(
    base_catalog: BlockCatalogV1,
) -> None:
    candidate = graph(
        (node("clock", "event"), node("risk", "risk"), node("trade", "trade")),
        (
            edge("risk-gate-in", "clock", "pulse", "risk", "in", kind="event"),
            edge("trigger", "risk", "pulse", "trade", "trigger", kind="event"),
        ),
    )

    result = validate(candidate, base_catalog, TargetV1(platform="MT5"))

    assert "MISSING_RISK_POLICY" in codes(result)
    assert result.exportable is False
    assert result.export_ready is False


def test_flow_cycle_requires_an_explicit_finite_delay(base_catalog: BlockCatalogV1) -> None:
    pulse_out = (port("pulse", "event"),)
    cycle_in = (port("seed", "event"), port("feedback", "event"))
    delayed_catalog = BlockCatalogV1(
        catalog_id="flow-catalog",
        version=1,
        blocks=(
            block("event", "event", outputs=pulse_out),
            block("delay", "delay", inputs=cycle_in, outputs=pulse_out, delay_bound=1),
            block("flow", "control", inputs=cycle_in, outputs=pulse_out),
            block("unbounded", "control", inputs=cycle_in, outputs=pulse_out),
        ),
    )
    nodes = (node("source", "event"), node("state", "delay"), node("step", "flow"))
    edges = (
        edge("seed", "source", "pulse", "state", "seed", kind="event"),
        edge("advance", "state", "pulse", "step", "seed", kind="event"),
        edge("feedback", "step", "pulse", "state", "feedback", kind="event"),
    )

    bounded = validate(
        graph(nodes, edges, catalog=delayed_catalog), delayed_catalog, TargetV1(platform="MT5")
    )
    unbounded = validate(
        graph((nodes[0], node("state", "unbounded"), nodes[2]), edges, catalog=delayed_catalog),
        delayed_catalog,
        TargetV1(platform="MT5"),
    )

    assert bounded.status == "VALID"
    assert "UNBOUNDED_CYCLE" in codes(unbounded)
    assert unbounded.exportable is False


@pytest.mark.parametrize("depth, expected", [(256, False), (257, True), (4097, True)])
def test_longest_dependency_path_has_iterative_node_depth_bound(
    base_catalog: BlockCatalogV1, depth: int, expected: bool
) -> None:
    nodes = tuple(node(f"n{i}", "math") for i in range(depth))
    edges = tuple(edge(f"e{i}", f"n{i}", "out", f"n{i + 1}", "in") for i in range(depth - 1))

    result = validate(graph(nodes, edges), base_catalog, TargetV1(platform="MT5"))

    assert ("DEPTH_LIMIT" in codes(result)) is expected
    assert (result.status == "INVALID") is expected
    assert result.exportable is False


def test_maximum_size_wide_shallow_graph_is_accepted() -> None:
    """Exercise both published size ceilings without recursion or dense cycles."""
    source_outputs = tuple(port(f"o{i}", "decimal", unit="price") for i in range(5))
    target_inputs = tuple(port(f"i{i}", "decimal", unit="price", required=True) for i in range(4))
    catalog = BlockCatalogV1(
        catalog_id="wide-catalog",
        version=1,
        blocks=(
            block("source", "event", outputs=source_outputs),
            block("sink", "math", inputs=target_inputs),
        ),
    )
    nodes = tuple(node(f"s{i}", "source") for i in range(3976)) + tuple(
        node(f"t{i}", "sink") for i in range(1024)
    )
    edges = tuple(
        edge(
            f"e{source_index}_{target_index}_{input_index}",
            f"s{source_index}",
            f"o{source_index % 5}",
            f"t{target_index}",
            f"i{input_index}",
        )
        for target_index in range(1024)
        for input_index in range(4)
        for source_index in ((target_index * 4 + input_index) % 3976,)
    )
    candidate = graph(nodes, edges, catalog=catalog)

    assert len(candidate.nodes) == 5000
    assert len(candidate.edges) == 4096
    result = validate(candidate, catalog, TargetV1(platform="MT5"))

    assert result.status == "VALID", codes(result)
    assert result.exportable is False
    assert result.errors == ()


def test_over_limit_graph_is_rejected_before_graph_walk(base_catalog: BlockCatalogV1) -> None:
    candidate = graph(tuple(node(f"n{i}", "math") for i in range(5001)))

    result = validate(candidate, base_catalog, TargetV1(platform="MT5"))

    assert result.status == "INVALID"
    assert "NODE_LIMIT" in codes(result)
    assert result.exportable is False


def test_4999_edge_chain_is_rejected_before_graph_expansion() -> None:
    nodes = tuple(node(f"n{i}", "math") for i in range(5000))
    edges = tuple(edge(f"e{i}", f"n{i}", "out", f"n{i + 1}", "in") for i in range(4999))

    with pytest.raises(EaModelError) as caught:
        graph(nodes, edges)

    assert caught.value.code == "EDGE_LIMIT"
    assert caught.value.field == "edges"


def test_graph_is_bound_to_the_exact_catalog_digest(base_catalog: BlockCatalogV1) -> None:
    altered_catalog = BlockCatalogV1(
        catalog_id=base_catalog.catalog_id,
        version=base_catalog.version,
        blocks=base_catalog.blocks[:-1],
    )
    candidate = graph((node("clock", "event"),), catalog=base_catalog)

    matched = validate(candidate, base_catalog, TargetV1(platform="MT5"))
    mismatched = validate(candidate, altered_catalog, TargetV1(platform="MT5"))

    assert matched.status == "VALID"
    assert mismatched.status == "INVALID"
    assert "CATALOG_MISMATCH" in codes(mismatched)


def test_event_category_cannot_emit_order_intent() -> None:
    with pytest.raises(EaModelError) as caught:
        block("unsafe-event", "event", outputs=(port("orders", "order-intent"),))

    assert caught.value.field == "outputs"
    assert caught.value.code in {"EVENT_ORDER_INTENT", "BLOCK_CATEGORY_MISMATCH"}


def test_order_intent_emitter_requires_a_risk_path() -> None:
    catalog = BlockCatalogV1(
        catalog_id="order-emitter-catalog",
        version=1,
        blocks=(block("emitter", "trade", outputs=(port("orders", "order-intent"),)),),
    )
    candidate = graph((node("emitter", "emitter"),), catalog=catalog)

    result = validate(candidate, catalog, TargetV1(platform="MT5"))

    assert result.status == "INVALID"
    assert "RISK_PATH_REQUIRED" in codes(result)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source_id", None),
        ("source_version", None),
        ("source_version", True),
        ("source_digest", None),
    ],
)
def test_imported_provenance_requires_typed_exact_source_identity(
    field: str, value: object
) -> None:
    identity: dict[str, object] = {
        "source_rights": "verified",
        "source_asset_kind": "source_code",
        "source_id": "synthetic-import",
        "source_version": 1,
        "source_digest": HASH,
        "unresolved_claims": (),
        "reviewed_rules": True,
        "risk_policy_hash": None,
        "live_order_mode": False,
    }
    identity[field] = value

    with pytest.raises(EaModelError) as caught:
        SourceProvenanceV1(**identity)

    assert caught.value.field in {field, "record"}
    assert caught.value.code


def test_catalog_block_limit_is_checked_before_catalog_expansion() -> None:
    valid_block = block("one", "math").model_dump(mode="json")
    payload = {
        "catalog_id": "oversized",
        "version": 1,
        "blocks": [valid_block] * 513,
    }

    with pytest.raises(EaModelError) as caught:
        BlockCatalogV1.model_validate_json(json.dumps(payload))

    assert caught.value.code == "CATALOG_BLOCK_LIMIT"
    assert caught.value.field == "blocks"


def test_block_port_and_parameter_fanout_limits_are_enforced() -> None:
    inputs = tuple(port(f"in{i}", "decimal") for i in range(17))
    outputs = tuple(port(f"out{i}", "decimal") for i in range(16))
    params = tuple(
        ParameterSpecV1(
            name=f"p{i}",
            kind="int",
            required=False,
            unit=None,
            minimum=None,
            maximum=None,
            choices=(),
        )
        for i in range(65)
    )

    with pytest.raises(EaModelError) as port_error:
        block("too-many-ports", "math", inputs=inputs, outputs=outputs)
    with pytest.raises(EaModelError) as parameter_error:
        block("too-many-parameters", "math", parameters=params)

    assert port_error.value.code == "PORT_LIMIT"
    assert parameter_error.value.code == "PARAMETER_LIMIT"


def test_type_unit_scope_and_target_mismatches_are_errors(base_catalog: BlockCatalogV1) -> None:
    constrained_catalog = BlockCatalogV1(
        catalog_id="scope-catalog",
        version=1,
        blocks=(
            block(
                "source",
                "event",
                outputs=(
                    port(
                        "out", "decimal", unit="price", symbol_scope="EURUSD", timeframe_scope="M5"
                    ),
                ),
            ),
            block(
                "target",
                "indicator",
                inputs=(
                    port(
                        "in",
                        "int",
                        unit="ticks",
                        required=True,
                        symbol_scope="GBPUSD",
                        timeframe_scope="H1",
                    ),
                ),
                targets=("MT4",),
                warmup_bars=0,
            ),
        ),
    )
    candidate = graph(
        (node("src", "source"), node("dst", "target", symbol="GBPUSD", timeframe="H1")),
        (edge("mismatch", "src", "out", "dst", "in"),),
        catalog=constrained_catalog,
    )

    result = validate(candidate, constrained_catalog, TargetV1(platform="MT5"))

    assert {"TYPE_MISMATCH", "UNIT_MISMATCH", "TARGET_UNSUPPORTED"} <= codes(result)
    assert "SYMBOL_SCOPE" in codes(result)
    assert "TIMEFRAME_SCOPE" in codes(result)
    assert result.exportable is False


def test_required_parameters_and_indicator_warmup_are_enforced(
    base_catalog: BlockCatalogV1,
) -> None:
    parameter_catalog = BlockCatalogV1(
        catalog_id="parameter-catalog",
        version=1,
        blocks=(
            block("event", "event"),
            block(
                "indicator",
                "indicator",
                parameters=(
                    ParameterSpecV1(
                        name="period",
                        kind="int",
                        required=True,
                        unit="bars",
                        minimum=Decimal(1),
                        maximum=Decimal(100),
                        choices=(),
                    ),
                    ParameterSpecV1(
                        name="mode",
                        kind="enum",
                        required=True,
                        unit=None,
                        minimum=None,
                        maximum=None,
                        choices=("close", "open"),
                    ),
                    ParameterSpecV1(
                        name="enabled",
                        kind="bool",
                        required=True,
                        unit=None,
                        minimum=None,
                        maximum=None,
                        choices=(),
                    ),
                ),
                warmup_bars=5,
            ),
        ),
    )
    candidate = graph(
        (
            node("clock", "event"),
            node(
                "ma",
                "indicator",
                parameters={
                    "period": ParameterValueV1(kind="decimal", value=Decimal("4")),
                    "mode": ParameterValueV1(kind="enum", value="unsupported"),
                },
                warmup_bars=2,
            ),
        ),
        warmup_bars=2,
        catalog=parameter_catalog,
    )

    result = validate(candidate, parameter_catalog, TargetV1(platform="MT5"))

    assert {"PARAMETER_TYPE", "ENUM_CHOICE", "MISSING_PARAMETER", "INSUFFICIENT_WARMUP"} <= codes(
        result
    )
    assert result.exportable is False


def test_permutation_of_nodes_and_edges_preserves_entire_result(
    base_catalog: BlockCatalogV1,
) -> None:
    nodes = (node("clock", "event"), node("risk", "risk"), node("trade", "trade"))
    edges = (
        edge("risk-gate-in", "clock", "pulse", "risk", "in", kind="event"),
        edge("trigger", "risk", "pulse", "trade", "trigger", kind="event"),
    )
    provenance = SourceProvenanceV1(
        source_rights="verified",
        source_asset_kind="original",
        source_id=None,
        source_version=None,
        source_digest=None,
        unresolved_claims=(),
        reviewed_rules=True,
        risk_policy_hash=HASH,
        live_order_mode=False,
    )
    original = graph(nodes, edges, provenance=provenance)
    permuted = graph(tuple(reversed(nodes)), tuple(reversed(edges)), provenance=provenance)

    first = validate(original, base_catalog, TargetV1(platform="MT5"))
    second = validate(permuted, base_catalog, TargetV1(platform="MT5"))

    assert first == second
    assert first.model_dump(mode="json") == second.model_dump(mode="json")


def test_hostile_free_text_parameter_is_rejected_as_typed_input() -> None:
    canary = "BUY NOW DO NOT ECHO"
    payload = json.loads((FIXTURES / "hostile-parameter.json").read_text(encoding="utf-8"))
    payload["value"] = canary

    with pytest.raises(EaModelError) as caught:
        ParameterValueV1.model_validate(payload)
    assert caught.value.code
    assert_ea_error_does_not_echo(caught.value, canary)


def test_lesson_11_schema_failures_are_typed_and_content_free() -> None:
    canary = "BUY NOW DO NOT ECHO"
    payload = {"kind": "int", "value": canary}

    for construct in (
        lambda: ParameterValueV1(**payload),
        lambda: ParameterValueV1.model_validate(payload),
        lambda: ParameterValueV1.model_validate_json(json.dumps(payload)),
        lambda: ParameterValueV1.model_validate_strings(payload),
    ):
        with pytest.raises(EaModelError) as caught:
            construct()
        assert caught.value.code
        assert caught.value.field == "value"
        assert_ea_error_does_not_echo(caught.value, canary)


def test_lesson_14_public_records_are_frozen_and_copy_revalidates(
    base_catalog: BlockCatalogV1,
) -> None:
    parameter = ParameterValueV1(kind="int", value=4)
    node_record = node("clock", "event", parameters={"length": parameter})
    graph_record = graph((node_record,))
    target = TargetV1(platform="MT5")
    candidate = RiskCapsCandidateV1(
        policy_hash=HASH,
        max_order_lots=Decimal("1"),
        max_open_positions=5,
        max_leverage=Decimal("4"),
        min_stop_distance=Decimal("0.5"),
        max_daily_loss_percent=Decimal("2"),
    )
    issue = GraphIssueV1(
        node_id="clock",
        port=None,
        code="TEST_WARNING",
        severity="warning",
        suggestion="Review the typed graph.",
    )
    validation = validate(graph_record, base_catalog, target)
    assert isinstance(validation, GraphValidationV1)
    records = (
        port("input", "decimal", unit="price"),
        ParameterSpecV1(
            name="length",
            kind="int",
            required=True,
            unit=None,
            minimum=None,
            maximum=None,
            choices=(),
        ),
        parameter,
        base_catalog.blocks[0],
        base_catalog,
        node_record,
        edge("e1", "clock", "pulse", "clock", "pulse", kind="event"),
        graph_record.provenance,
        graph_record,
        target,
        issue,
        validation,
        candidate,
    )
    canary = "MUTATION-CANARY-DO-NOT-ECHO"

    for record in records:
        field_name = next(iter(type(record).model_fields))
        with pytest.raises(FrozenEaRecordError) as assigned:
            setattr(record, field_name, canary)
        assert canary not in str(assigned.value)
        assert canary not in repr(assigned.value.args)

        with pytest.raises(FrozenEaRecordError):
            delattr(record, field_name)
        with pytest.raises(FrozenEaRecordError):
            type(record).model_construct(**{field_name: canary})
        with pytest.raises(FrozenEaRecordError):
            copy.copy(record)
        with pytest.raises(FrozenEaRecordError):
            copy.deepcopy(record)
        with pytest.raises(FrozenEaRecordError):
            pickle.dumps(record)
        assert record.model_copy() == record

    with pytest.raises(EaModelError) as bad_copy:
        parameter.model_copy(update={"value": canary})
    assert bad_copy.value.field == "value"
    assert_ea_error_does_not_echo(bad_copy.value, canary)


@pytest.mark.parametrize(
    ("fixture_name", "expected_codes"),
    [
        ("mtr-conflicting-claims.json", {"UNRESOLVED_CLAIMS", "UNREVIEWED_RULES"}),
        ("bitcoin-course-rights-unverified.json", {"SOURCE_RIGHTS", "UNRESOLVED_CLAIMS"}),
        ("kinnobot-parameter-only.json", {"UNRESOLVED_CLAIMS", "UNREVIEWED_RULES"}),
        (
            "hftcode-unsafe-startup-close.json",
            {"SOURCE_RIGHTS", "UNRESOLVED_CLAIMS", "LIVE_ORDER_MODE"},
        ),
    ],
)
def test_asset_provenance_hazards_are_not_preapproved_templates(
    fixture_name: str, expected_codes: set[str], base_catalog: BlockCatalogV1
) -> None:
    declaration = json.loads((FIXTURES / fixture_name).read_text(encoding="utf-8"))
    declaration.pop("hazards")
    provenance = SourceProvenanceV1.model_validate_json(json.dumps(declaration))
    candidate = graph((node("clock", "event"),), provenance=provenance)

    result = validate(candidate, base_catalog, TargetV1(platform="MT5"))

    assert expected_codes <= codes(result)
    assert result.export_ready is False


def test_opaque_binary_provenance_is_always_rejected(base_catalog: BlockCatalogV1) -> None:
    provenance = SourceProvenanceV1(
        source_rights="verified",
        source_asset_kind="opaque_binary",
        source_id="hftcode",
        source_version=1,
        source_digest=HASH,
        unresolved_claims=(),
        reviewed_rules=True,
        risk_policy_hash=None,
        live_order_mode=False,
    )

    result = validate(
        graph((node("clock", "event"),), provenance=provenance),
        base_catalog,
        TargetV1(platform="MT5"),
    )

    assert "OPAQUE_ASSET" in codes(result)
    assert result.status == "INVALID"


def test_naive_eastern_wall_clock_is_not_accepted_as_effective_utc_ns(
    base_catalog: BlockCatalogV1,
) -> None:
    declaration = json.loads(
        (FIXTURES / "naive-eastern-timestamp.json").read_text(encoding="utf-8")
    )
    payload = graph((node("clock", "event"),)).model_dump()
    payload["effective_ns"] = declaration["effective_ns"]

    with pytest.raises(EaModelError) as caught:
        GraphV1.model_validate(payload)
    assert caught.value.code
    assert caught.value.field == "effective_ns"
    assert_ea_error_does_not_echo(caught.value, str(declaration["effective_ns"]))


class FakeRiskCapsVerifier:
    @property
    def _ea001_trust_token(self) -> object:
        return _VERIFIER_TOKEN

    def verify(self, candidate: RiskCapsCandidateV1) -> bool:
        return True


def risk_caps(policy_hash: str = "b" * 64) -> VerifiedRiskCapsV1:
    candidate = RiskCapsCandidateV1(
        policy_hash=policy_hash,
        max_order_lots=Decimal("1"),
        max_open_positions=5,
        max_leverage=Decimal("4"),
        min_stop_distance=Decimal("0.5"),
        max_daily_loss_percent=Decimal("5"),
    )
    return verify_risk_caps(candidate, FakeRiskCapsVerifier())


def test_verified_caps_are_sealed_and_still_do_not_grant_export_or_order_authority(
    base_catalog: BlockCatalogV1,
) -> None:
    policy_hash = "b" * 64
    provenance = SourceProvenanceV1(
        source_rights="verified",
        source_asset_kind="original",
        source_id=None,
        source_version=None,
        source_digest=None,
        unresolved_claims=(),
        reviewed_rules=True,
        risk_policy_hash=policy_hash,
        live_order_mode=False,
    )
    candidate = graph(
        (node("clock", "event"), node("risk", "risk"), node("trade", "trade")),
        (
            edge("risk-gate-in", "clock", "pulse", "risk", "in", kind="event"),
            edge("trigger", "risk", "pulse", "trade", "trigger", kind="event"),
        ),
        provenance=provenance,
    )
    caps = risk_caps(policy_hash)

    result = validate(candidate, base_catalog, TargetV1(platform="MT5"), risk_caps=caps)

    assert result.status == "VALID"
    assert result.cap_check == "PERFORMED"
    assert result.export_ready is False
    assert not hasattr(caps, "_seal")
    candidate_for_forgery = RiskCapsCandidateV1(
        policy_hash=policy_hash,
        max_order_lots=Decimal("1"),
        max_open_positions=5,
        max_leverage=Decimal("4"),
        min_stop_distance=Decimal("0.5"),
        max_daily_loss_percent=Decimal("5"),
    )
    copied_seal = getattr(caps, "_seal", caps)
    with pytest.raises(TypeError):
        VerifiedRiskCapsV1(candidate_for_forgery, _seal=copied_seal)
    with pytest.raises(TypeError):
        VerifiedRiskCapsV1(candidate_for_forgery, _issuer=copied_seal)  # type: ignore[call-arg]
    with pytest.raises((TypeError, ValueError)):
        replace(caps, _seal=copied_seal)
    with pytest.raises((TypeError, ValueError)):
        replace(caps, _issuer=copied_seal)
    with pytest.raises(TypeError):
        VerifiedRiskCapsV1({}, _seal=_VERIFIER_TOKEN)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        copy.copy(caps)
    with pytest.raises(TypeError):
        copy.deepcopy(caps)
    with pytest.raises(TypeError):
        pickle.dumps(caps)


def test_risk_policy_hash_must_match_verified_caps(base_catalog: BlockCatalogV1) -> None:
    provenance = SourceProvenanceV1(
        source_rights="verified",
        source_asset_kind="original",
        source_id=None,
        source_version=None,
        source_digest=None,
        unresolved_claims=(),
        reviewed_rules=True,
        risk_policy_hash="a" * 64,
        live_order_mode=False,
    )
    candidate = graph((node("clock", "event"),), provenance=provenance)

    result = validate(candidate, base_catalog, TargetV1(platform="MT5"), risk_caps=risk_caps())

    assert "RISK_POLICY_MISMATCH" in codes(result)
    assert result.export_ready is False


def test_issued_caps_reinitialization_is_rejected_before_mutation() -> None:
    caps = risk_caps()
    original_limit = caps.max_order_lots
    too_loose = RiskCapsCandidateV1(
        policy_hash=caps.policy_hash,
        max_order_lots=Decimal("100"),
        max_open_positions=5,
        max_leverage=Decimal("4"),
        min_stop_distance=Decimal("0.5"),
        max_daily_loss_percent=Decimal("5"),
    )

    with pytest.raises((FrozenEaRecordError, TypeError)) as caught:
        VerifiedRiskCapsV1.__init__(caps, too_loose, _seal=_CAPS_TOKEN)

    assert "100" not in str(caught.value)
    assert caps.max_order_lots == original_limit


def test_issued_caps_integrity_failure_is_typed_and_fails_validation(
    base_catalog: BlockCatalogV1,
) -> None:
    policy_hash = "b" * 64
    provenance = SourceProvenanceV1(
        source_rights="verified",
        source_asset_kind="original",
        source_id=None,
        source_version=None,
        source_digest=None,
        unresolved_claims=(),
        reviewed_rules=True,
        risk_policy_hash=policy_hash,
        live_order_mode=False,
    )
    candidate = graph(
        (node("clock", "event"), node("risk", "risk"), node("trade", "trade")),
        (
            edge("risk-gate-in", "clock", "pulse", "risk", "in", kind="event"),
            edge("trigger", "risk", "pulse", "trade", "trigger", kind="event"),
        ),
        provenance=provenance,
    )
    caps = risk_caps(policy_hash)
    object.__setattr__(caps, "max_order_lots", Decimal("100"))

    result = validate(candidate, base_catalog, TargetV1(platform="MT5"), risk_caps=caps)

    assert result.cap_check == "FAILED"
    assert result.status == "INVALID"
    assert "RISK_CAP_INTEGRITY" in codes(result)
    assert result.export_ready is False


def test_verified_caps_reject_setstate_and_dict_replacement() -> None:
    caps = risk_caps()
    original_limit = caps.max_order_lots

    with pytest.raises((FrozenEaRecordError, AttributeError, TypeError)):
        caps.__setstate__({"max_order_lots": Decimal("100")})  # type: ignore[attr-defined]
    with pytest.raises((FrozenEaRecordError, AttributeError, TypeError)):
        object.__setattr__(caps, "__dict__", {"max_order_lots": Decimal("100")})

    assert caps.max_order_lots == original_limit
