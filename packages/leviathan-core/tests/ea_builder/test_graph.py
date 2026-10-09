"""Focused boundary tests for the static EA graph kernel."""

from __future__ import annotations

import copy
import pickle
from dataclasses import replace
from decimal import Decimal

import pytest

from leviathan_core.ea_builder import (
    BlockCatalogV1,
    BlockDefinitionV1,
    EaModelError,
    EdgeV1,
    FrozenEaRecordError,
    GraphV1,
    NodeV1,
    ParameterValueV1,
    PortV1,
    RiskCapsCandidateV1,
    SourceProvenanceV1,
    TargetV1,
    VerifiedRiskCapsV1,
    standard_catalog_v1,
    validate,
    verify_risk_caps,
)
from leviathan_core.ea_builder.graph import (
    _CAPS_TOKEN,
    _VERIFIER_TOKEN,
    _is_verified_risk_caps,
)


def _port(name: str, kind: str, required: bool = False) -> PortV1:
    return PortV1(
        name=name,
        kind=kind,
        unit=None,
        required=required,
        symbol_scope=None,
        timeframe_scope=None,
    )


def _block(
    block_id: str,
    category: str,
    inputs: tuple[PortV1, ...],
    outputs: tuple[PortV1, ...],
    *,
    warmup: int = 0,
    delay_bound: int | None = None,
    targets: tuple[str, ...] = ("MT4", "MT5"),
) -> BlockDefinitionV1:
    return BlockDefinitionV1(
        block_id=block_id,
        category=category,
        inputs=inputs,
        outputs=outputs,
        parameters=(),
        targets=targets,
        warmup_bars=warmup,
        delay_bound=delay_bound,
    )


def _node(index: int, block_id: str = "step", warmup: int = 0) -> NodeV1:
    return NodeV1(
        node_id=f"n{index:04d}",
        block_id=block_id,
        parameters={},
        symbol="EURUSD",
        timeframe="M1",
        warmup_bars=warmup,
    )


def _edge(index: int, source: int, target: int, kind: str = "event") -> EdgeV1:
    return EdgeV1(
        edge_id=f"e{index:05d}",
        source_node=f"n{source:04d}",
        source_port="out",
        target_node=f"n{target:04d}",
        target_port="in",
        kind=kind,
    )


def _graph(
    nodes: tuple[NodeV1, ...],
    edges: tuple[EdgeV1, ...],
    warmup: int = 0,
    *,
    catalog: BlockCatalogV1 | None = None,
) -> GraphV1:
    bound_catalog = catalog if catalog is not None else _flow_catalog()
    return GraphV1(
        graph_id="test_graph",
        revision=1,
        catalog_id=bound_catalog.catalog_id,
        catalog_version=bound_catalog.version,
        catalog_digest=bound_catalog.canonical_digest(),
        source_hash="a" * 64,
        template_hash="b" * 64,
        effective_ns=1_000_000_000,
        symbol="EURUSD",
        timeframe="M1",
        warmup_bars=warmup,
        provenance=SourceProvenanceV1.original(),
        nodes=nodes,
        edges=edges,
    )


def _catalog(*blocks: BlockDefinitionV1) -> BlockCatalogV1:
    return BlockCatalogV1(catalog_id="test_catalog", version=1, blocks=blocks)


def _flow_catalog() -> BlockCatalogV1:
    return _catalog(
        _block("start", "event", (), (_port("out", "event"),)),
        _block("step", "control", (_port("in", "event", True),), (_port("out", "event"),)),
    )


@pytest.mark.parametrize("count,valid", [(256, True), (257, False), (4_097, False)])
def test_longest_dependency_path_is_bounded_iteratively(count: int, valid: bool) -> None:
    nodes = (_node(0, "start"), *(_node(index) for index in range(1, count)))
    edges = tuple(_edge(index, index, index + 1) for index in range(count - 1))
    result = validate(_graph(nodes, edges), _flow_catalog(), TargetV1(platform="MT5"))
    assert (result.status == "VALID") is valid
    assert ("DEPTH_LIMIT" in {issue.code for issue in result.errors}) is not valid
    assert result.exportable is False


def test_wide_shallow_max_node_graph_is_within_depth_cap() -> None:
    # The edge cap connects 4097 nodes; the remaining declared nodes are warnings only.
    catalog = _catalog(*_flow_catalog().blocks, _block("orphan", "control", (), ()))
    nodes = (
        _node(0, "start"),
        *(_node(index) for index in range(1, 4_097)),
        *(_node(index, "orphan") for index in range(4_097, 5_000)),
    )
    edges = tuple(_edge(index, 0, index + 1) for index in range(4_096))
    result = validate(_graph(nodes, edges, catalog=catalog), catalog, TargetV1(platform="MT5"))
    assert result.status == "VALID"


def test_cycle_needs_explicit_finite_delay() -> None:
    start = _block("start", "event", (_port("in", "event"),), (_port("out", "event"),))
    step = _block("step", "control", (_port("in", "event", True),), (_port("out", "event"),))
    delay = _block(
        "delay",
        "delay",
        (_port("in", "event", True),),
        (_port("out", "event"),),
        delay_bound=3,
    )
    edges = (_edge(0, 0, 1), _edge(1, 1, 2), _edge(2, 2, 0))
    unbounded_catalog = _catalog(start, step)
    bounded_catalog = _catalog(start, step, delay)
    unbounded = _graph((_node(0, "start"), _node(1), _node(2)), edges, catalog=unbounded_catalog)
    bounded = _graph(
        (_node(0, "start"), _node(1), _node(2, "delay")), edges, catalog=bounded_catalog
    )
    assert "UNBOUNDED_CYCLE" in {
        issue.code
        for issue in validate(unbounded, unbounded_catalog, TargetV1(platform="MT5")).errors
    }
    assert validate(bounded, bounded_catalog, TargetV1(platform="MT5")).status == "VALID"


def test_chained_indicator_lookback_requires_explicit_graph_warmup() -> None:
    source = _block("source", "event", (), (_port("out", "decimal"),))
    indicator = _block(
        "indicator",
        "indicator",
        (_port("in", "decimal", True),),
        (_port("out", "decimal"),),
        warmup=5,
    )
    nodes = (_node(0, "source"), _node(1, "indicator", 5), _node(2, "indicator", 5))
    edges = (_edge(0, 0, 1, "data"), _edge(1, 1, 2, "data"))
    catalog = _catalog(source, indicator)
    assert "INSUFFICIENT_WARMUP" in {
        issue.code
        for issue in validate(
            _graph(nodes, edges, 5, catalog=catalog), catalog, TargetV1(platform="MT5")
        ).errors
    }
    warmed = validate(_graph(nodes, edges, 10, catalog=catalog), catalog, TargetV1(platform="MT5"))
    assert warmed.status == "VALID"


def test_indicator_period_controls_warmup_not_only_catalog_floor() -> None:
    catalog = standard_catalog_v1()
    nodes = (
        _node(0, "tick_event"),
        NodeV1(
            node_id="n0001",
            block_id="sma_indicator",
            parameters={"period": ParameterValueV1(kind="int", value=14)},
            symbol="EURUSD",
            timeframe="M1",
            warmup_bars=5,
        ),
    )
    edges = (
        EdgeV1(
            edge_id="e0",
            source_node="n0000",
            source_port="event",
            target_node="n0001",
            target_port="event",
            kind="event",
        ),
    )
    result = validate(_graph(nodes, edges, 5, catalog=catalog), catalog, TargetV1(platform="MT5"))
    assert "INSUFFICIENT_WARMUP" in {issue.code for issue in result.errors}
    warmed = _graph(
        (nodes[0], nodes[1].model_copy(update={"warmup_bars": 14})), edges, 14, catalog=catalog
    )
    assert validate(warmed, catalog, TargetV1(platform="MT5")).status == "VALID"


def test_permutation_does_not_change_validation_output() -> None:
    nodes = (_node(0, "start"), _node(1), _node(2))
    edges = (_edge(0, 0, 1), _edge(1, 1, 2))
    catalog = _flow_catalog()
    target = TargetV1(platform="MT4")
    forward = validate(_graph(nodes, edges, catalog=catalog), catalog, target)
    reverse = validate(
        _graph(tuple(reversed(nodes)), tuple(reversed(edges)), catalog=catalog), catalog, target
    )
    assert forward == reverse


def test_typed_values_are_frozen_and_reject_free_text() -> None:
    node = _node(0)
    with pytest.raises(TypeError):
        node.parameters["x"] = ParameterValueV1(kind="int", value=1)
    with pytest.raises(EaModelError):
        ParameterValueV1(kind="decimal", value="1.2")
    with pytest.raises(EaModelError):
        ParameterValueV1(kind="event", value="arbitrary")
    assert ParameterValueV1(kind="percent", value=Decimal("37.5")).value == Decimal("37.5")


def test_asset_provenance_and_naive_time_are_rejected() -> None:
    unsafe = SourceProvenanceV1(
        source_rights="unverified",
        source_asset_kind="source_code",
        source_id="CAND-02",
        source_version=1,
        source_digest="a" * 64,
        unresolved_claims=("CAND-02",),
        reviewed_rules=False,
        risk_policy_hash=None,
        live_order_mode=True,
    )
    graph = _graph((_node(0, "start"),), ()).model_copy(update={"provenance": unsafe})
    result = validate(graph, _flow_catalog(), TargetV1(platform="MT5"))
    assert {"SOURCE_RIGHTS", "UNRESOLVED_CLAIMS", "UNREVIEWED_RULES", "LIVE_ORDER_MODE"} <= {
        issue.code for issue in result.errors
    }
    assert not result.export_ready
    payload = _graph((_node(0, "start"),), ()).model_dump()
    payload["effective_ns"] = "2026-09-30 09:30 Eastern"
    with pytest.raises(EaModelError):
        GraphV1.model_validate(payload)


class _FakeRiskVerifier:
    """Explicit hermetic verifier; production binding is outside EA-001."""

    @property
    def _ea001_trust_token(self) -> object:
        return _VERIFIER_TOKEN

    def verify(self, candidate: RiskCapsCandidateV1) -> bool:
        return candidate.policy_hash == "c" * 64


def test_verified_caps_compare_risk_parameters_without_value_leak() -> None:
    candidate = RiskCapsCandidateV1(
        policy_hash="c" * 64,
        max_order_lots=Decimal("1"),
        max_open_positions=2,
        max_leverage=Decimal("5"),
        min_stop_distance=Decimal("0.0001"),
        max_daily_loss_percent=Decimal("5"),
    )
    with pytest.raises(TypeError):
        VerifiedRiskCapsV1(candidate, _seal=object())
    caps = verify_risk_caps(candidate, _FakeRiskVerifier())
    for clone in (lambda: copy.copy(caps), lambda: replace(caps), lambda: pickle.dumps(caps)):
        with pytest.raises(TypeError):
            clone()

    source = _node(0, "tick_event")
    risk = NodeV1(
        node_id="n0001",
        block_id="risk_cap",
        parameters={"max_daily_loss": ParameterValueV1(kind="percent", value=Decimal("8"))},
        symbol="EURUSD",
        timeframe="M1",
        warmup_bars=0,
    )
    trade = _node(2, "trade_entry")
    graph = _graph(
        (source, risk, trade),
        (
            EdgeV1(
                edge_id="e0",
                source_node="n0000",
                source_port="event",
                target_node="n0001",
                target_port="event",
                kind="event",
            ),
            EdgeV1(
                edge_id="e1",
                source_node="n0001",
                source_port="intent",
                target_node="n0002",
                target_port="intent",
                kind="control",
            ),
        ),
        catalog=standard_catalog_v1(),
    ).model_copy(
        update={
            "provenance": SourceProvenanceV1(
                source_rights="verified",
                source_asset_kind="original",
                source_id=None,
                source_version=None,
                source_digest=None,
                unresolved_claims=(),
                reviewed_rules=True,
                risk_policy_hash="c" * 64,
                live_order_mode=False,
            )
        }
    )
    without_caps = validate(graph, standard_catalog_v1(), TargetV1(platform="MT5"))
    assert without_caps.cap_check == "NOT_PERFORMED"
    assert not without_caps.export_ready
    result = validate(graph, standard_catalog_v1(), TargetV1(platform="MT5"), caps)
    assert result.cap_check == "PERFORMED"
    assert not result.export_ready
    assert ("n0001", "max_daily_loss", "WEAKER_RISK_CAP") in {
        (issue.node_id, issue.port, issue.code) for issue in result.errors
    }
    assert all("8" not in issue.suggestion for issue in result.issues)


def test_issued_caps_reject_reinitialization_and_state_replacement() -> None:
    candidate = RiskCapsCandidateV1(
        policy_hash="c" * 64,
        max_order_lots=Decimal("1"),
        max_open_positions=2,
        max_leverage=Decimal("5"),
        min_stop_distance=Decimal("0.0001"),
        max_daily_loss_percent=Decimal("5"),
    )
    caps = verify_risk_caps(candidate, _FakeRiskVerifier())
    loosened = candidate.model_copy(update={"max_order_lots": Decimal("100")})
    with pytest.raises(TypeError) as reentry:
        VerifiedRiskCapsV1.__init__(caps, loosened, _seal=_CAPS_TOKEN)
    assert "100" not in str(reentry.value)
    assert caps.max_order_lots == Decimal("1")
    assert _is_verified_risk_caps(caps)

    for replace_state in (
        lambda: caps.__setstate__({"max_order_lots": Decimal("100")}),
        lambda: setattr(caps, "__dict__", {"max_order_lots": Decimal("100")}),
        lambda: object.__setattr__(caps, "__dict__", {"max_order_lots": Decimal("100")}),
    ):
        with pytest.raises((AttributeError, TypeError)) as blocked:
            replace_state()
        assert "100" not in str(blocked.value)
        assert caps.max_order_lots == Decimal("1")
        assert _is_verified_risk_caps(caps)


def test_mutated_issued_caps_fail_integrity_before_policy_comparison() -> None:
    candidate = RiskCapsCandidateV1(
        policy_hash="c" * 64,
        max_order_lots=Decimal("1"),
        max_open_positions=2,
        max_leverage=Decimal("5"),
        min_stop_distance=Decimal("0.0001"),
        max_daily_loss_percent=Decimal("5"),
    )
    caps = verify_risk_caps(candidate, _FakeRiskVerifier())
    graph = _graph((_node(0, "start"),), ()).model_copy(
        update={
            "provenance": SourceProvenanceV1.original().model_copy(
                update={"risk_policy_hash": "c" * 64}
            )
        }
    )
    baseline = validate(graph, _flow_catalog(), TargetV1(platform="MT5"), caps)
    assert baseline.status == "VALID"
    assert baseline.cap_check == "PERFORMED"

    object.__setattr__(caps, "max_order_lots", Decimal("100"))
    assert not _is_verified_risk_caps(caps)
    result = validate(graph, _flow_catalog(), TargetV1(platform="MT5"), caps)
    assert result.status == "INVALID"
    assert result.cap_check == "FAILED"
    assert "RISK_CAP_INTEGRITY" in {issue.code for issue in result.errors}
    assert not result.export_ready
    assert all("100" not in issue.suggestion for issue in result.issues)


def test_every_trade_path_must_pass_through_risk() -> None:
    catalog = _catalog(
        _block("start", "event", (), (_port("out", "event"),)),
        _block("risk", "risk", (_port("in", "event", True),), (_port("out", "event"),)),
        _block(
            "trade",
            "trade",
            (_port("safe", "event", True), _port("direct", "event")),
            (),
        ),
    )
    nodes = (_node(0, "start"), _node(1, "risk"), _node(2, "trade"))
    edges = (
        _edge(0, 0, 1),
        EdgeV1(
            edge_id="e_safe",
            source_node="n0001",
            source_port="out",
            target_node="n0002",
            target_port="safe",
            kind="event",
        ),
        EdgeV1(
            edge_id="e_direct",
            source_node="n0000",
            source_port="out",
            target_node="n0002",
            target_port="direct",
            kind="event",
        ),
    )
    provenance = SourceProvenanceV1(
        source_rights="verified",
        source_asset_kind="original",
        source_id=None,
        source_version=None,
        source_digest=None,
        unresolved_claims=(),
        reviewed_rules=True,
        risk_policy_hash="c" * 64,
        live_order_mode=False,
    )
    graph = _graph(nodes, edges, catalog=catalog).model_copy(update={"provenance": provenance})
    result = validate(graph, catalog, TargetV1(platform="MT5"))
    assert "RISK_BYPASS" in {issue.code for issue in result.errors}
    assert not result.exportable


def test_numeric_input_uses_exact_bounded_parser_and_safe_error() -> None:
    precise = Decimal("0.1234567890123456789012345678901234")
    assert ParameterValueV1(kind="decimal", value=precise).value == precise
    with pytest.raises(EaModelError) as failure:
        ParameterValueV1(kind="decimal", value=Decimal("0.12345678901234567890123456789012345"))
    assert failure.value.code == "PRECISION_EXCEEDED"
    assert failure.value.error_type == "value_error"
    assert "12345" not in str(failure.value)
    assert "12345" not in repr(failure.value.args)
    assert "12345" not in repr(failure.value.errors())
    with pytest.raises(EaModelError):
        ParameterValueV1(kind="int", value=True)


def test_ea_records_revalidate_copy_and_reject_mutation_or_unsafe_cloning() -> None:
    value = ParameterValueV1(kind="int", value=3)
    assert value.model_copy(update={"value": 4}).value == 4
    with pytest.raises(EaModelError):
        value.model_copy(update={"value": "invalid"})
    for mutation in (
        lambda: setattr(value, "value", 5),
        lambda: delattr(value, "value"),
        lambda: copy.copy(value),
        lambda: copy.deepcopy(value),
        lambda: pickle.dumps(value),
        lambda: ParameterValueV1.model_construct(kind="int", value=1),
    ):
        with pytest.raises(FrozenEaRecordError):
            mutation()
    with pytest.raises(FrozenEaRecordError) as frozen:
        value.value = "BUY_NOW_DO_NOT_ECHO"
    assert "BUY_NOW_DO_NOT_ECHO" not in str(frozen.value)
    assert "BUY_NOW_DO_NOT_ECHO" not in repr(frozen.value.args)


def test_unissued_caps_with_private_constructor_token_have_no_authority() -> None:
    candidate = RiskCapsCandidateV1(
        policy_hash="c" * 64,
        max_order_lots=Decimal("1"),
        max_open_positions=2,
        max_leverage=Decimal("5"),
        min_stop_distance=Decimal("0.0001"),
        max_daily_loss_percent=Decimal("5"),
    )
    forged = VerifiedRiskCapsV1(candidate, _seal=_CAPS_TOKEN)
    with pytest.raises(TypeError, match="verified risk-cap capability"):
        validate(
            _graph((_node(0, "start"),), ()),
            _flow_catalog(),
            TargetV1(platform="MT5"),
            forged,
        )


def test_order_intent_emitter_requires_risk_path_and_event_cannot_emit_intent() -> None:
    with pytest.raises(EaModelError) as invalid_event:
        _block("bad_event", "event", (), (_port("intent", "order-intent"),))
    assert invalid_event.value.code == "EVENT_ORDER_INTENT"

    catalog = _catalog(
        _block("start", "event", (), (_port("out", "event"),)),
        _block(
            "emit", "control", (_port("in", "event", True),), (_port("intent", "order-intent"),)
        ),
    )
    graph = _graph(
        (_node(0, "start"), _node(1, "emit")),
        (_edge(0, 0, 1),),
        catalog=catalog,
    ).model_copy(
        update={
            "provenance": SourceProvenanceV1.original().model_copy(
                update={"risk_policy_hash": "c" * 64}
            )
        }
    )
    result = validate(graph, catalog, TargetV1(platform="MT5"))
    assert result.status == "INVALID"
    assert "RISK_PATH_REQUIRED" in {issue.code for issue in result.errors}
    assert not result.exportable and not result.export_ready


def test_every_order_intent_path_requires_risk_even_when_one_path_is_safe() -> None:
    catalog = _catalog(
        _block("start", "event", (), (_port("out", "event"),)),
        _block("risk", "risk", (_port("in", "event", True),), (_port("out", "event"),)),
        _block(
            "emit",
            "control",
            (_port("safe", "event", True), _port("direct", "event")),
            (_port("intent", "order-intent"),),
        ),
    )
    nodes = (_node(0, "start"), _node(1, "risk"), _node(2, "emit"))
    safe_edges = (
        _edge(0, 0, 1),
        EdgeV1(
            edge_id="safe",
            source_node="n0001",
            source_port="out",
            target_node="n0002",
            target_port="safe",
            kind="event",
        ),
    )
    provenance = SourceProvenanceV1.original().model_copy(update={"risk_policy_hash": "c" * 64})
    safe = _graph(nodes, safe_edges, catalog=catalog).model_copy(update={"provenance": provenance})
    assert validate(safe, catalog, TargetV1(platform="MT5")).status == "VALID"
    direct = EdgeV1(
        edge_id="direct",
        source_node="n0000",
        source_port="out",
        target_node="n0002",
        target_port="direct",
        kind="event",
    )
    bypass = safe.model_copy(update={"edges": (*safe_edges, direct)})
    result = validate(bypass, catalog, TargetV1(platform="MT5"))
    assert result.status == "INVALID"
    assert "RISK_PATH_REQUIRED" in {issue.code for issue in result.errors}


def test_graph_is_bound_to_exact_catalog_content() -> None:
    original = _flow_catalog()
    reordered = _catalog(*reversed(original.blocks))
    assert original.canonical_digest() == reordered.canonical_digest()
    changed = _catalog(
        _block("start", "event", (), (_port("out", "event"),)),
        _block("step", "trade", (_port("in", "event", True),), (_port("out", "event"),)),
    )
    assert original.catalog_id == changed.catalog_id and original.version == changed.version
    assert original.canonical_digest() != changed.canonical_digest()
    graph = _graph((_node(0, "start"), _node(1)), (_edge(0, 0, 1),), catalog=original)
    assert validate(graph, original, TargetV1(platform="MT5")).status == "VALID"
    assert validate(graph, reordered, TargetV1(platform="MT5")).status == "VALID"
    result = validate(graph, changed, TargetV1(platform="MT5"))
    assert "CATALOG_MISMATCH" in {issue.code for issue in result.errors}
    assert result.status == "INVALID" and not result.exportable


def test_imported_provenance_requires_exact_source_identity_and_digest() -> None:
    with pytest.raises(EaModelError):
        SourceProvenanceV1.original().model_copy(update={"source_asset_kind": "source_code"})
    imported = SourceProvenanceV1.original().model_copy(
        update={
            "source_asset_kind": "source_code",
            "source_id": "CAND-02",
            "source_version": 1,
            "source_digest": "b" * 64,
        }
    )
    with pytest.raises(EaModelError):
        imported.model_copy(update={"source_version": True})
    graph = _graph((_node(0, "start"),), ()).model_copy(update={"provenance": imported})
    result = validate(graph, _flow_catalog(), TargetV1(platform="MT5"))
    assert "SOURCE_DIGEST_MISMATCH" in {issue.code for issue in result.errors}


def test_catalog_and_edge_limits_are_checked_before_model_expansion() -> None:
    base = _block("one", "control", (), ())
    with pytest.raises(EaModelError) as blocks:
        _catalog(*(base for _ in range(513)))
    assert blocks.value.code == "CATALOG_BLOCK_LIMIT"
    with pytest.raises(EaModelError) as ports:
        _block("wide", "control", (), tuple(_port(f"p{i}", "event") for i in range(33)))
    assert ports.value.code == "PORT_LIMIT"
    spec = standard_catalog_v1().blocks[3].parameters[0]
    with pytest.raises(EaModelError) as parameters:
        BlockDefinitionV1(
            block_id="many_params",
            category="control",
            inputs=(),
            outputs=(),
            parameters=tuple(spec for _ in range(65)),
            targets=("MT5",),
            warmup_bars=0,
            delay_bound=None,
        )
    assert parameters.value.code == "PARAMETER_LIMIT"
    with pytest.raises(EaModelError) as edges:
        _graph((_node(0, "start"),), tuple(_edge(i, 0, 0) for i in range(4_097)))
    assert edges.value.code == "EDGE_LIMIT"
