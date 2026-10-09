"""Pure, iterative validation of versioned EA block graphs."""

from __future__ import annotations

from collections import defaultdict, deque
from decimal import Decimal
from typing import Literal

from leviathan_core.ea_builder.blocks import (
    MAX_BLOCKS,
    MAX_PARAMS_PER_BLOCK,
    MAX_PORTS_PER_BLOCK,
    BlockCatalogV1,
    BlockDefinitionV1,
)
from leviathan_core.ea_builder.graph import (
    MAX_EDGES,
    EdgeV1,
    GraphIssueV1,
    GraphV1,
    GraphValidationV1,
    NodeV1,
    TargetV1,
    VerifiedRiskCapsV1,
    _is_issued_risk_caps,
    _is_verified_risk_caps,
)
from leviathan_core.numeric import parse_decimal

MAX_NODES = 5_000
MAX_DEPTH = 256


def _indicator_lookback(node: NodeV1, block: BlockDefinitionV1) -> int:
    if block.category != "indicator":
        return 0
    required = block.warmup_bars
    for name in ("period", "lookback_bars"):
        parameter = node.parameters.get(name)
        if parameter is not None and parameter.kind == "int" and type(parameter.value) is int:
            required = max(required, parameter.value)
    return required


def _ordered_walk(
    ids: set[str], edges: list[EdgeV1], *, break_delay: set[str] | None = None
) -> tuple[dict[str, int], list[str]]:
    """Kahn traversal: returns longest node-count path and nodes in residual cycles."""
    incoming = dict.fromkeys(ids, 0)
    outgoing: dict[str, list[str]] = defaultdict(list)
    for edge in edges:
        if (
            edge.source_node in ids
            and edge.target_node in ids
            and (break_delay is None or edge.source_node not in break_delay)
        ):
            incoming[edge.target_node] += 1
            outgoing[edge.source_node].append(edge.target_node)
    ready = deque(sorted(node for node, count in incoming.items() if count == 0))
    depth = dict.fromkeys(ids, 1)
    while ready:
        source = ready.popleft()
        for target in outgoing[source]:
            depth[target] = max(depth[target], depth[source] + 1)
            incoming[target] -= 1
            if incoming[target] == 0:
                ready.append(target)
    return depth, sorted(node for node, count in incoming.items() if count > 0)


def _required_warmup(
    nodes: dict[str, NodeV1], definitions: dict[str, BlockDefinitionV1], edges: list[EdgeV1]
) -> dict[str, int]:
    """Propagate cumulative indicator lookback over data edges without recursion."""
    incoming = dict.fromkeys(nodes, 0)
    outgoing: dict[str, list[str]] = defaultdict(list)
    for edge in edges:
        incoming[edge.target_node] += 1
        outgoing[edge.source_node].append(edge.target_node)
    required = {
        node_id: _indicator_lookback(node, definitions[node.block_id])
        if node.block_id in definitions
        else 0
        for node_id, node in nodes.items()
    }
    own = dict(required)
    ready = deque(sorted(node for node, count in incoming.items() if count == 0))
    while ready:
        source = ready.popleft()
        for target in outgoing[source]:
            required[target] = max(required[target], required[source] + own[target])
            incoming[target] -= 1
            if incoming[target] == 0:
                ready.append(target)
    return required


def validate(
    graph: GraphV1,
    catalog: BlockCatalogV1,
    target: TargetV1,
    risk_caps: VerifiedRiskCapsV1 | None = None,
) -> GraphValidationV1:
    """Return deterministic lint issues; never mutate or run graph contents."""
    issues: set[tuple[str | None, str | None, str, str, str]] = set()

    def add(node: str | None, port: str | None, code: str, severity: str, suggestion: str) -> None:
        issues.add((node, port, code, severity, suggestion))

    if len(graph.nodes) > MAX_NODES:
        add(
            None,
            None,
            "NODE_LIMIT",
            "error",
            "Split the graph into revisions of at most 5000 nodes",
        )
    if len(graph.edges) > MAX_EDGES:
        add(None, None, "EDGE_LIMIT", "error", "Reduce the graph to at most 4096 edges")
    if not graph.nodes:
        add(None, None, "EMPTY_GRAPH", "error", "Add a typed event source")
    provenance = graph.provenance
    if provenance.source_asset_kind != "original" and provenance.source_digest != graph.source_hash:
        add(None, None, "SOURCE_DIGEST_MISMATCH", "error", "Pin the declared source digest")
    if provenance.source_rights != "verified":
        add(None, None, "SOURCE_RIGHTS", "error", "Verify source reuse rights before inclusion")
    if provenance.source_asset_kind == "opaque_binary":
        add(None, None, "OPAQUE_ASSET", "error", "Use reviewed source or clean-room rules")
    if provenance.unresolved_claims:
        add(None, None, "UNRESOLVED_CLAIMS", "error", "Resolve cited source claims independently")
    if provenance.source_asset_kind != "original" and not provenance.reviewed_rules:
        add(None, None, "UNREVIEWED_RULES", "error", "Review independent entry and exit rules")
    if provenance.live_order_mode:
        add(None, None, "LIVE_ORDER_MODE", "error", "Use static graph mode without real orders")
    cap_check: Literal["PERFORMED", "NOT_PERFORMED", "FAILED"] = "NOT_PERFORMED"
    if risk_caps is not None:
        if not _is_issued_risk_caps(risk_caps):
            raise TypeError("risk_caps must be a verified risk-cap capability")
        if not _is_verified_risk_caps(risk_caps):
            add(None, None, "RISK_CAP_INTEGRITY", "error", "Use a fresh verified risk policy")
            return _result(issues, "FAILED", risk_caps)
        cap_check = "PERFORMED"
        if provenance.risk_policy_hash != risk_caps.policy_hash:
            add(None, None, "RISK_POLICY_MISMATCH", "error", "Pin the verified risk policy")
    # Further graph work is bounded, including in the presence of malformed giant input.
    if len(graph.nodes) > MAX_NODES or len(graph.edges) > MAX_EDGES:
        return _result(issues, cap_check, risk_caps)

    if len(catalog.blocks) > MAX_BLOCKS:
        add(None, None, "CATALOG_BLOCK_LIMIT", "error", "Reduce the bounded catalog")
        return _result(issues, cap_check, risk_caps)
    if any(
        len(block.inputs) + len(block.outputs) > MAX_PORTS_PER_BLOCK
        or len(block.parameters) > MAX_PARAMS_PER_BLOCK
        for block in catalog.blocks
    ):
        add(None, None, "CATALOG_FANOUT_LIMIT", "error", "Reduce block port or parameter fanout")
        return _result(issues, cap_check, risk_caps)
    if (
        graph.catalog_id != catalog.catalog_id
        or graph.catalog_version != catalog.version
        or graph.catalog_digest != catalog.canonical_digest()
    ):
        add(None, None, "CATALOG_MISMATCH", "error", "Bind the exact versioned catalog")
        return _result(issues, cap_check, risk_caps)

    definitions: dict[str, BlockDefinitionV1] = {}
    for block in sorted(catalog.blocks, key=lambda item: (item.block_id, item.model_dump_json())):
        if block.block_id in definitions:
            add(None, None, "DUPLICATE_BLOCK_ID", "error", "Use unique catalog block IDs")
        definitions[block.block_id] = block

    nodes: dict[str, NodeV1] = {}
    for node in sorted(graph.nodes, key=lambda item: (item.node_id, item.model_dump_json())):
        if node.node_id in nodes:
            add(node.node_id, None, "DUPLICATE_NODE_ID", "error", "Assign a unique stable node ID")
        nodes[node.node_id] = node

    edges: dict[str, EdgeV1] = {}
    for edge in sorted(graph.edges, key=lambda item: (item.edge_id, item.model_dump_json())):
        if edge.edge_id in edges:
            add(None, None, "DUPLICATE_EDGE_ID", "error", "Assign a unique stable edge ID")
        edges[edge.edge_id] = edge

    valid_edges: list[EdgeV1] = []
    incoming_ports: dict[tuple[str, str], int] = defaultdict(int)
    outgoing_nodes: dict[str, set[str]] = defaultdict(set)
    for edge in edges.values():
        source = nodes.get(edge.source_node)
        destination = nodes.get(edge.target_node)
        if source is None or destination is None:
            add(
                edge.target_node,
                edge.target_port,
                "UNKNOWN_NODE",
                "error",
                "Connect declared nodes",
            )
            continue
        source_block = definitions.get(source.block_id)
        target_block = definitions.get(destination.block_id)
        if source_block is None or target_block is None:
            continue
        output = next(
            (port for port in source_block.outputs if port.name == edge.source_port), None
        )
        input_port = next(
            (port for port in target_block.inputs if port.name == edge.target_port), None
        )
        if output is None or input_port is None:
            add(
                destination.node_id,
                edge.target_port,
                "UNKNOWN_PORT",
                "error",
                "Use declared input and output ports",
            )
            continue
        numeric_series_signal_input = (
            output.kind == "numeric-series"
            and input_port.kind == "decimal"
            and source.block_id == "sma_indicator"
            and edge.source_port == "value"
            and target_block.block_id in {"compare.v1", "crossover.v1"}
            and edge.target_port in {"left", "right"}
            and edge.kind == "data"
        )
        if output.kind != input_port.kind and not numeric_series_signal_input:
            add(
                destination.node_id,
                edge.target_port,
                "TYPE_MISMATCH",
                "error",
                "Connect ports with the same typed kind",
            )
        if output.unit != input_port.unit:
            add(
                destination.node_id,
                edge.target_port,
                "UNIT_MISMATCH",
                "error",
                "Insert an explicit unit adapter",
            )
        if edge.kind == "data" and output.kind in {"event", "order-intent"}:
            add(
                destination.node_id,
                edge.target_port,
                "EDGE_KIND_MISMATCH",
                "error",
                "Use a compatible event or control connection",
            )
        if edge.kind == "event" and output.kind != "event":
            add(
                destination.node_id,
                edge.target_port,
                "EDGE_KIND_MISMATCH",
                "error",
                "Connect typed event ports",
            )
        if edge.kind == "control" and output.kind not in {"event", "order-intent"}:
            add(
                destination.node_id,
                edge.target_port,
                "EDGE_KIND_MISMATCH",
                "error",
                "Connect event or order-intent ports",
            )
        if (
            source.symbol != destination.symbol
            or (output.symbol_scope is not None and output.symbol_scope != destination.symbol)
            or (input_port.symbol_scope is not None and input_port.symbol_scope != source.symbol)
        ):
            add(
                destination.node_id,
                edge.target_port,
                "SYMBOL_SCOPE",
                "error",
                "Add an explicit symbol scope adapter",
            )
        if (
            source.timeframe != destination.timeframe
            or (
                output.timeframe_scope is not None
                and output.timeframe_scope != destination.timeframe
            )
            or (
                input_port.timeframe_scope is not None
                and input_port.timeframe_scope != source.timeframe
            )
        ):
            add(
                destination.node_id,
                edge.target_port,
                "TIMEFRAME_SCOPE",
                "error",
                "Add an explicit timeframe adapter",
            )
        valid_edges.append(edge)
        incoming_ports[(edge.target_node, edge.target_port)] += 1
        outgoing_nodes[edge.source_node].add(edge.target_node)

    event_sources: set[str] = set()
    trade_nodes: set[str] = set()
    order_emitters: set[str] = set()
    for node in nodes.values():
        node_block = definitions.get(node.block_id)
        if node_block is None:
            add(
                node.node_id,
                None,
                "UNKNOWN_BLOCK",
                "error",
                "Select a block from the pinned catalog",
            )
            continue
        if target.platform not in node_block.targets:
            add(
                node.node_id,
                None,
                "TARGET_UNSUPPORTED",
                "error",
                "Choose a compatible MT target or block",
            )
        if node_block.category == "event":
            event_sources.add(node.node_id)
        if node_block.category == "trade":
            trade_nodes.add(node.node_id)
        if any(port.kind == "order-intent" for port in node_block.outputs):
            order_emitters.add(node.node_id)
        if node_block.category != "portfolio" and node.symbol != graph.symbol:
            add(node.node_id, None, "NODE_SYMBOL_SCOPE", "error", "Match the graph symbol scope")
        if node_block.category != "portfolio" and node.timeframe != graph.timeframe:
            add(node.node_id, None, "NODE_TIMEFRAME_SCOPE", "error", "Match the graph timeframe")
        for port in node_block.inputs:
            count = incoming_ports[(node.node_id, port.name)]
            if port.required and count == 0:
                add(
                    node.node_id,
                    port.name,
                    "UNCONNECTED_PORT",
                    "error",
                    "Connect the required input",
                )
            if count > 1:
                add(
                    node.node_id,
                    port.name,
                    "MULTIPLE_INPUTS",
                    "error",
                    "Keep one source per input port",
                )
        specs = {spec.name: spec for spec in node_block.parameters}
        for spec in node_block.parameters:
            if spec.required and spec.name not in node.parameters:
                add(
                    node.node_id,
                    spec.name,
                    "MISSING_PARAMETER",
                    "error",
                    "Supply the required typed parameter",
                )
        for name, value in node.parameters.items():
            parameter_spec = specs.get(name)
            if parameter_spec is None:
                add(
                    node.node_id,
                    name,
                    "UNKNOWN_PARAMETER",
                    "error",
                    "Remove the undeclared parameter",
                )
                continue
            if value.kind != parameter_spec.kind:
                add(node.node_id, name, "PARAMETER_TYPE", "error", "Use the catalog parameter kind")
                continue
            if parameter_spec.kind == "enum" and value.value not in parameter_spec.choices:
                add(node.node_id, name, "ENUM_CHOICE", "error", "Choose a declared enum value")
            if isinstance(value.value, (Decimal, int)) and not isinstance(value.value, bool):
                numeric = parse_decimal(value.value, field="value")
                if (parameter_spec.minimum is not None and numeric < parameter_spec.minimum) or (
                    parameter_spec.maximum is not None and numeric > parameter_spec.maximum
                ):
                    add(
                        node.node_id,
                        name,
                        "PARAMETER_BOUNDS",
                        "error",
                        "Set the value within declared bounds",
                    )
                if risk_caps is not None and node_block.category in {
                    "risk",
                    "money",
                    "trade",
                    "portfolio",
                }:
                    cap_map = {
                        "max_lots": (risk_caps.max_order_lots, "maximum"),
                        "max_order_lots": (risk_caps.max_order_lots, "maximum"),
                        "max_open_positions": (
                            parse_decimal(risk_caps.max_open_positions, field="max_open_positions"),
                            "maximum",
                        ),
                        "max_leverage": (risk_caps.max_leverage, "maximum"),
                        "min_stop_distance": (risk_caps.min_stop_distance, "minimum"),
                        "max_daily_loss": (risk_caps.max_daily_loss_percent, "maximum"),
                        "max_daily_loss_percent": (risk_caps.max_daily_loss_percent, "maximum"),
                    }
                    cap = cap_map.get(name)
                    if cap is not None and (
                        (cap[1] == "maximum" and numeric > cap[0])
                        or (cap[1] == "minimum" and numeric < cap[0])
                    ):
                        add(
                            node.node_id,
                            name,
                            "WEAKER_RISK_CAP",
                            "error",
                            "Tighten to the verified policy",
                        )
                    elif cap is None and name.startswith(("max_", "min_")):
                        add(
                            node.node_id,
                            name,
                            "UNMAPPED_RISK_CAP",
                            "error",
                            "Map this cap to verified policy",
                        )
        required_warmup = _indicator_lookback(node, node_block)
        if node_block.category == "indicator" and (
            node.warmup_bars < required_warmup or graph.warmup_bars < required_warmup
        ):
            add(
                node.node_id,
                None,
                "INSUFFICIENT_WARMUP",
                "error",
                "Increase explicit node and graph warmup",
            )
        if node_block.category in {"time_filter", "news_filter"}:
            start = node.parameters.get("start_ns")
            end = node.parameters.get("end_ns")
            if (
                start is not None
                and end is not None
                and (
                    type(start.value) is int and type(end.value) is int and start.value > end.value
                )
            ):
                add(
                    node.node_id, None, "FILTER_CONFLICT", "error", "Set a nonempty filter interval"
                )

    order_targets = trade_nodes | order_emitters
    order_capable = bool(order_targets)
    if order_capable and provenance.risk_policy_hash is None:
        add(None, None, "MISSING_RISK_POLICY", "error", "Pin a reviewed C-101 risk policy hash")

    risk_nodes = {
        node_id
        for node_id, node in nodes.items()
        if (risk_block := definitions.get(node.block_id)) is not None
        and risk_block.category == "risk"
    }
    risk_reached = set(risk_nodes)
    pending = deque(sorted(risk_nodes))
    while pending:
        for successor in outgoing_nodes[pending.popleft()]:
            if successor not in risk_reached:
                risk_reached.add(successor)
                pending.append(successor)
    for trade_id in sorted(trade_nodes):
        if trade_id not in risk_reached:
            add(trade_id, None, "MISSING_RISK_BLOCK", "error", "Route entry through a risk block")
    for order_id in sorted(order_targets - risk_reached):
        add(order_id, None, "RISK_PATH_REQUIRED", "error", "Route order intent through risk")
    if order_targets and not event_sources:
        add(None, None, "NO_EVENT_SOURCE", "error", "Add a tick, bar, or session event source")

    # Data dependencies must be a DAG even if a delay block appears in their cycle.
    data_edges = [edge for edge in valid_edges if edge.kind == "data"]
    _, data_cycle = _ordered_walk(set(nodes), data_edges)
    for node_id in data_cycle:
        add(node_id, None, "DATA_CYCLE", "error", "Remove the cyclic data dependency")
    if not data_cycle:
        for node_id, bars in _required_warmup(nodes, definitions, data_edges).items():
            if bars > graph.warmup_bars:
                add(
                    node_id,
                    None,
                    "INSUFFICIENT_WARMUP",
                    "error",
                    "Increase graph warmup to cover chained indicator lookbacks",
                )

    flow_edges = [edge for edge in valid_edges if edge.kind in {"event", "control"}]
    delay_nodes = {
        node.node_id
        for node in nodes.values()
        if (delay_block := definitions.get(node.block_id)) is not None
        and delay_block.category in {"delay", "state"}
        and delay_block.delay_bound is not None
    }
    _, flow_cycle = _ordered_walk(set(nodes), flow_edges, break_delay=delay_nodes)
    for node_id in flow_cycle:
        add(
            node_id,
            None,
            "UNBOUNDED_CYCLE",
            "error",
            "Insert an explicit finite delay or state block",
        )

    # A longest dependency path is counted in nodes. Kahn traversal remains iterative
    # for the full 5000-node permitted size, including malformed cyclic inputs.
    depth, _ = _ordered_walk(set(nodes), valid_edges, break_delay=delay_nodes)
    for node_id, length in depth.items():
        if length > MAX_DEPTH:
            add(node_id, None, "DEPTH_LIMIT", "error", "Reduce dependency depth to 256 nodes")

    if event_sources:
        reached = set(event_sources)
        pending = deque(sorted(event_sources))
        while pending:
            for neighbor in sorted(outgoing_nodes[pending.popleft()]):
                if neighbor not in reached:
                    reached.add(neighbor)
                    pending.append(neighbor)
        for order_id in order_targets - reached:
            add(order_id, None, "UNREACHABLE_ENTRY", "error", "Connect entry to an event source")
        bypass_reached = set(event_sources - risk_nodes)
        pending = deque(sorted(bypass_reached))
        while pending:
            for neighbor in outgoing_nodes[pending.popleft()]:
                if neighbor not in risk_nodes and neighbor not in bypass_reached:
                    bypass_reached.add(neighbor)
                    pending.append(neighbor)
        for trade_id in trade_nodes & bypass_reached:
            add(trade_id, None, "RISK_BYPASS", "error", "Route every entry path through risk")
        for order_id in order_targets & bypass_reached:
            add(order_id, None, "RISK_PATH_REQUIRED", "error", "Route order intent through risk")
        for node_id in set(nodes) - reached:
            add(
                node_id, None, "ORPHAN_NODE", "warning", "Connect the node to an event-driven graph"
            )
    else:
        for node_id in nodes:
            add(node_id, None, "ORPHAN_NODE", "warning", "Connect the node to an event source")

    return _result(issues, cap_check, risk_caps)


def _result(
    entries: set[tuple[str | None, str | None, str, str, str]],
    cap_check: Literal["PERFORMED", "NOT_PERFORMED", "FAILED"],
    risk_caps: VerifiedRiskCapsV1 | None,
) -> GraphValidationV1:
    if cap_check == "PERFORMED" and (risk_caps is None or not _is_verified_risk_caps(risk_caps)):
        entries.add((None, None, "RISK_CAP_INTEGRITY", "error", "Use a fresh verified risk policy"))
        cap_check = "FAILED"
    ordered = sorted(
        entries,
        key=lambda item: (
            0 if item[3] == "error" else 1,
            item[0] or "",
            item[1] or "",
            item[2],
            item[4],
        ),
    )
    issues = tuple(
        GraphIssueV1(
            node_id=node,
            port=port,
            code=code,
            severity="error" if severity == "error" else "warning",
            suggestion=suggestion,
        )
        for node, port, code, severity, suggestion in ordered
    )
    errors = tuple(issue for issue in issues if issue.severity == "error")
    warnings = tuple(issue for issue in issues if issue.severity == "warning")
    return GraphValidationV1(
        status="INVALID" if errors else "VALID",
        issues=issues,
        errors=errors,
        warnings=warnings,
        auto_fixes=tuple(sorted({issue.suggestion for issue in issues})),
        exportable=False,  # EA-001 static lint never grants export authority
        cap_check=cap_check,
        export_ready=False,  # production verifier binding is a later C-101/EA-002 gate
    )
