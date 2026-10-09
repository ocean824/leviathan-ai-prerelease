"""Deterministic, fail-closed outputs from reviewed declarative strategy claims."""

from __future__ import annotations

import re
from decimal import Decimal
from typing import Any, Literal

from leviathan_core.ea_builder.blocks import standard_catalog_v1
from leviathan_core.ea_builder.export_source import standard_template_catalog_v1
from leviathan_core.ea_builder.graph import (
    DeclaredRiskParameterV1,
    EdgeV1,
    GraphV1,
    NodeV1,
    ParameterValueV1,
    SourceProvenanceV1,
)
from leviathan_core.ea_builder.signal_catalog import extend_signal_catalog_v1
from leviathan_core.seal import Issuer, SealError

from .ir import (
    CodeArtifactV1,
    CodegenTargetV1,
    OperatorKindV1,
    OperatorV1,
    StrategyIRV1,
    TemplateCatalogV1,
)
from .models import ReviewedStrategySpecV1, StrategyIngestError, canonical_decimal, digest
from .review import (
    VerifiedLicenseV1,
    _registered_token_entry,
    _token_binding_digest,
    require_reviewed_spec,
)

_ISSUER = Issuer("strategy.codegen")
_EA_GRAPH_ISSUER = Issuer("strategy.ea_graph")
_HASH = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_FIELD = re.compile(r"([a-z_]+)=([A-Za-z0-9_.:-]+)\Z", re.ASCII)
_SMA = re.compile(r"sma\.([A-Za-z][A-Za-z0-9_]*)=([0-9]{1,6})\Z", re.ASCII)
_CROSS = re.compile(
    r"(entry|exit)=cross_(above|below)\(([A-Za-z][A-Za-z0-9_]*),([A-Za-z][A-Za-z0-9_]*)\)\Z",
    re.ASCII,
)
_RISK = re.compile(r"(stop|target)\.pips=([0-9]+(?:\.[0-9]+)?)\Z", re.ASCII)
_POSITION = re.compile(r"position_cap=([1-9][0-9]*)\Z", re.ASCII)


def _error(code: str, location: tuple[str | int, ...] = ()) -> StrategyIngestError:
    return StrategyIngestError(code, location=location)


def _require_issued_license(
    token: VerifiedLicenseV1 | None, spec: ReviewedStrategySpecV1
) -> VerifiedLicenseV1:
    if type(token) is not VerifiedLicenseV1:
        raise _error("SOURCE_RIGHTS_UNVERIFIED")
    try:
        entry = _registered_token_entry(token)
        actual = _token_binding_digest(token)
        if not spec.reviewer_actions:
            raise ValueError("missing final reviewer action")
        final_action = spec.reviewer_actions[-1]
        expected = {
            "source_sha256": spec.source.byte_sha256,
            "license_reference_id": spec.source.license_reference_id,
            "action_id": final_action.action_id,
            "reviewer_id": final_action.reviewer_id,
        }
        expected_digest = digest(expected)
    except Exception:
        raise _error("SOURCE_RIGHTS_UNVERIFIED") from None
    if entry is None or actual != entry[1] or actual != expected_digest:
        raise _error("SOURCE_RIGHTS_UNVERIFIED")
    return token


def _lower_risk_metadata(
    accepted_claim_ids: set[str], operators: tuple[OperatorV1, ...]
) -> tuple[DeclaredRiskParameterV1, ...]:
    risk_kinds: dict[
        OperatorKindV1, Literal["stop_distance", "target_distance", "position_cap"]
    ] = {
        OperatorKindV1.STOP_DISTANCE: "stop_distance",
        OperatorKindV1.TARGET_DISTANCE: "target_distance",
        OperatorKindV1.POSITION_CAP: "position_cap",
    }
    result: list[DeclaredRiskParameterV1] = []
    for op in operators:
        if op.kind not in risk_kinds:
            continue
        if op.evidence_id not in accepted_claim_ids:
            raise _error("UNKNOWN_SOURCE_CLAIM")
        if op.value is None:
            raise _error("INVALID_STRATEGY_IR")
        if op.unit == "pips":
            unit: Literal["pips", "positions"] = "pips"
        elif op.unit == "positions":
            unit = "positions"
        else:
            raise _error("INVALID_STRATEGY_IR")
        result.append(
            DeclaredRiskParameterV1(
                kind=risk_kinds[op.kind],
                value=op.value,
                unit=unit,
                source_claim_id=op.evidence_id,
            )
        )
    return tuple(result)


def _lower_ea_graph(
    spec: ReviewedStrategySpecV1,
    ir: StrategyIRV1,
    license_token: VerifiedLicenseV1 | None,
) -> GraphV1:
    unsupported = tuple(
        op.node_id
        for op in ir.operators
        if op.kind
        not in {
            OperatorKindV1.SMA,
            OperatorKindV1.CROSS_ABOVE,
            OperatorKindV1.CROSS_BELOW,
            OperatorKindV1.STOP_DISTANCE,
            OperatorKindV1.TARGET_DISTANCE,
            OperatorKindV1.POSITION_CAP,
        }
    )
    if unsupported:
        raise _error("UNSUPPORTED_TARGET_OPERATOR")
    _require_issued_license(license_token, spec)
    source = spec.source
    catalog = extend_signal_catalog_v1(standard_catalog_v1())
    template_catalog = standard_template_catalog_v1()
    sma_ops = {op.node_id: op for op in ir.operators if op.kind == OperatorKindV1.SMA}
    cross_ops = sorted(
        (
            op
            for op in ir.operators
            if op.kind in {OperatorKindV1.CROSS_ABOVE, OperatorKindV1.CROSS_BELOW}
        ),
        key=lambda op: op.node_id,
    )
    nodes: list[NodeV1] = []
    edges: list[EdgeV1] = []
    nodes.append(
        NodeV1(
            node_id="bar_source",
            block_id="bar_event",
            parameters={},
            symbol=ir.symbol,
            timeframe=ir.timeframe,
            warmup_bars=0,
        )
    )
    for op in sorted(sma_ops.values(), key=lambda item: item.node_id):
        if op.period is None:
            raise _error("INVALID_STRATEGY_IR")
        nodes.append(
            NodeV1(
                node_id=op.node_id,
                block_id="sma_indicator",
                parameters={"period": ParameterValueV1(kind="int", value=op.period)},
                symbol=ir.symbol,
                timeframe=ir.timeframe,
                warmup_bars=op.period or 0,
            )
        )
        edges.append(
            EdgeV1(
                edge_id=f"edge_bar_{op.node_id}",
                source_node="bar_source",
                source_port="event",
                target_node=op.node_id,
                target_port="event",
                kind="event",
            )
        )
    for op in cross_ops:
        direction = "above" if op.kind == OperatorKindV1.CROSS_ABOVE else "below"
        nodes.append(
            NodeV1(
                node_id=op.node_id,
                block_id="crossover.v1",
                parameters={"direction": ParameterValueV1(kind="enum", value=direction)},
                symbol=ir.symbol,
                timeframe=ir.timeframe,
                warmup_bars=1,
            )
        )
        for port, sma_id in zip(("left", "right"), op.inputs, strict=True):
            edges.append(
                EdgeV1(
                    edge_id=f"edge_{op.node_id}_{port}",
                    source_node=sma_id,
                    source_port="value",
                    target_node=op.node_id,
                    target_port=port,
                    kind="data",
                )
            )
        signal_id = f"signal_{op.node_id}"
        signal_block = "entry_signal.v1" if op.action == "entry" else "exit_signal.v1"
        nodes.append(
            NodeV1(
                node_id=signal_id,
                block_id=signal_block,
                parameters={"signal_key": ParameterValueV1(kind="symbol", value=op.node_id)},
                symbol=ir.symbol,
                timeframe=ir.timeframe,
                warmup_bars=0,
            )
        )
        edges.append(
            EdgeV1(
                edge_id=f"edge_{op.node_id}_signal",
                source_node=op.node_id,
                source_port="condition",
                target_node=signal_id,
                target_port="condition",
                kind="data",
            )
        )
    record_json = source.model_dump(mode="json")
    source_record_digest = digest(record_json)
    accepted_claim_ids = {claim.evidence_id for claim in spec.accepted_claims}
    declared_risk_parameters = _lower_risk_metadata(accepted_claim_ids, ir.operators)
    # EA-001 uses an integer source version; STRAT-001 source records are
    # content-addressed and versionless, so this projection pins schema v1.
    provenance = SourceProvenanceV1(
        source_rights="verified",
        source_asset_kind="source_code",
        source_id=source.source_id,
        source_version=1,
        source_digest=source.byte_sha256,
        unresolved_claims=(),
        reviewed_rules=True,
        risk_policy_hash=None,
        live_order_mode=False,
    )
    return GraphV1(
        graph_id=f"strat_{spec.spec_sha256[:24]}",
        revision=1,
        catalog_id=catalog.catalog_id,
        catalog_version=catalog.version,
        catalog_digest=catalog.canonical_digest(),
        source_hash=source.byte_sha256,
        template_hash=template_catalog.canonical_digest(),
        effective_ns=ir.decision_asof_ns,
        symbol=ir.symbol,
        timeframe=ir.timeframe,
        warmup_bars=max((node.warmup_bars for node in nodes), default=0),
        provenance=provenance,
        promotion_status=spec.promotion_status,
        strategy_source_id=source.source_id,
        strategy_source_digest=source_record_digest,
        declared_risk_parameters=declared_risk_parameters,
        nodes=tuple(nodes),
        edges=tuple(edges),
    )


def _check_spec(spec: ReviewedStrategySpecV1) -> tuple[str, ...]:
    if type(spec) is not ReviewedStrategySpecV1:
        raise _error("REVIEWED_SPEC_REQUIRED")
    try:
        spec = ReviewedStrategySpecV1(**spec.model_dump(mode="python"))
        actual = digest(spec.model_dump(mode="json", exclude={"spec_sha256"}))
    except Exception:
        raise _error("INVALID_REVIEWED_SPEC") from None
    if actual != spec.spec_sha256 or spec.spec_kind != "review_only":
        raise _error("INVALID_REVIEWED_SPEC")
    if spec.conflicts or not spec.reviewer_actions or not spec.accepted_claims:
        raise _error("REVIEW_INCOMPLETE")
    last = spec.reviewer_actions[-1]
    decisions = {item.evidence_id: item.decision for item in last.decisions}
    if set(decisions) != {
        item.evidence_id for item in (*spec.accepted_claims, *spec.rejected_claims)
    }:
        raise _error("REVIEW_INCOMPLETE")
    if any(decisions.get(item.evidence_id) != "accept" for item in spec.accepted_claims):
        raise _error("REVIEW_INCOMPLETE")
    if any(decisions.get(item.evidence_id) != "reject" for item in spec.rejected_claims):
        raise _error("REVIEW_INCOMPLETE")
    return tuple(
        item.evidence_id for item in sorted(spec.accepted_claims, key=lambda x: x.evidence_id)
    )


def _parse_spec(spec: ReviewedStrategySpecV1) -> StrategyIRV1:
    claim_ids = _check_spec(spec)
    values: dict[str, str] = {}
    smas: dict[str, tuple[int, str]] = {}
    entries: list[tuple[str, str, str, str]] = []
    action_counts = {"entry": 0, "exit": 0}
    operators: list[OperatorV1] = []
    ids = {item.evidence_id: item for item in spec.accepted_claims}
    for claim_id in claim_ids:
        item = ids[claim_id]
        text = item.claim_text
        m = _FIELD.fullmatch(text)
        if m and m.group(1) in {"symbol", "timeframe", "session"}:
            key, value = m.groups()
            if key in values:
                raise _error("AMBIGUOUS_CLAIM", (claim_id,))
            values[key] = value
            continue
        m = _SMA.fullmatch(text)
        if m:
            name, period_text = m.groups()
            period = int(period_text)
            if name in smas or not 1 <= period <= 100_000:
                raise _error("UNSUPPORTED_CLAIM", (claim_id,))
            smas[name] = (period, claim_id)
            continue
        m = _CROSS.fullmatch(text)
        if m:
            raw_action, direction, left, right = m.groups()
            if raw_action == "entry":
                action: Literal["entry", "exit"] = "entry"
            elif raw_action == "exit":
                action = "exit"
            else:
                raise _error("UNSUPPORTED_CLAIM", (claim_id,))
            entries.append((action, direction, left, right))
            action_counts[action] += 1
            operators.append(
                OperatorV1(
                    node_id=f"{action}_{action_counts[action]}",
                    kind=OperatorKindV1(f"cross_{direction}"),
                    action=action,
                    inputs=(left, right),
                    period=None,
                    value=None,
                    unit=None,
                    evidence_id=claim_id,
                )
            )
            continue
        m = _RISK.fullmatch(text)
        if m:
            which, number = m.groups()
            kind = (
                OperatorKindV1.STOP_DISTANCE if which == "stop" else OperatorKindV1.TARGET_DISTANCE
            )
            operators.append(
                OperatorV1(
                    node_id=which,
                    kind=kind,
                    action=None,
                    inputs=(),
                    period=None,
                    value=Decimal(number),
                    unit="pips",
                    evidence_id=claim_id,
                )
            )
            continue
        m = _POSITION.fullmatch(text)
        if m:
            operators.append(
                OperatorV1(
                    node_id="position_cap",
                    kind=OperatorKindV1.POSITION_CAP,
                    action=None,
                    inputs=(),
                    period=None,
                    value=Decimal(m.group(1)),
                    unit="positions",
                    evidence_id=claim_id,
                )
            )
            continue
        raise _error("UNSUPPORTED_CLAIM", (claim_id,))
    if not {"symbol", "timeframe", "session"}.issubset(values) or not smas or not entries:
        raise _error("REVIEW_INCOMPLETE")
    for name, (period, claim_id) in sorted(smas.items()):
        operators.append(
            OperatorV1(
                node_id=name,
                kind=OperatorKindV1.SMA,
                action=None,
                inputs=(),
                period=period,
                value=None,
                unit="bars",
                evidence_id=claim_id,
            )
        )
    for _, _, left, right in entries:
        if left not in smas or right not in smas:
            raise _error("UNRESOLVED_OPERATOR_REFERENCE")
    # Keep canonical node order independent of evidence declaration order.
    operators.sort(key=lambda op: (op.node_id, op.kind.value, op.evidence_id))
    try:
        return StrategyIRV1(
            schema_version="1",
            symbol=values["symbol"],
            timeframe=values["timeframe"],
            session=values["session"],
            decision_asof_ns=spec.source.available_ns,
            operators=tuple(operators),
        )
    except Exception:
        raise _error("INVALID_STRATEGY_IR") from None


def _python(ir: StrategyIRV1) -> str:
    sma_ops = [op for op in ir.operators if op.kind == OperatorKindV1.SMA]
    max_period = max(op.period or 0 for op in sma_ops)
    rows = [
        '"""Generated deterministic strategy signals."""',
        "from __future__ import annotations",
        "from decimal import Decimal",
        "from fractions import Fraction",
        "",
        f"SYMBOL = {ir.symbol!r}",
        f"TIMEFRAME = {ir.timeframe!r}",
        f"SESSION = {ir.session!r}",
        f"MAX_INPUT_BARS = {max_period + 1}",
        "",
    ]
    for op in ir.operators:
        if op.kind in {
            OperatorKindV1.STOP_DISTANCE,
            OperatorKindV1.TARGET_DISTANCE,
            OperatorKindV1.POSITION_CAP,
        }:
            constant = {
                OperatorKindV1.STOP_DISTANCE: "STOP_PIPS",
                OperatorKindV1.TARGET_DISTANCE: "TARGET_PIPS",
                OperatorKindV1.POSITION_CAP: "POSITION_CAP",
            }[op.kind]
            if op.value is None:
                raise _error("INVALID_STRATEGY_IR")
            rows.append(f"{constant} = Decimal({canonical_decimal(op.value)!r})")
    rows.append("")
    rows += [
        "",
        "def _close(value: Decimal | str) -> Decimal:",
        "    if type(value) is str:",
        "        if (not value or not value.isascii() or len(value) > 128 or "
        "any(char not in '0123456789.+-eE' for char in value)):",
        "            raise ValueError('INVALID_CLOSE')",
        "        try:",
        "            parsed = Decimal(value)",
        "        except Exception:",
        "            raise ValueError('INVALID_CLOSE') from None",
        "    elif type(value) is Decimal:",
        "        parsed = value",
        "    else:",
        "        raise ValueError('INVALID_CLOSE')",
        "    parts = parsed.as_tuple()",
        "    if not parsed.is_finite() or len(parts.digits) > 128 or abs(parts.exponent) > 1024:",
        "        raise ValueError('INVALID_CLOSE')",
        "    return parsed",
        "",
        "def _average(closes: tuple[Decimal, ...], period: int) -> Fraction:",
        "    return sum((Fraction(value) for value in closes[-period:]), Fraction()) / period",
        "",
        "def signal(finalized_closes: tuple[Decimal | str, ...]) -> tuple[str, ...]:",
        "    if type(finalized_closes) is not tuple or len(finalized_closes) > MAX_INPUT_BARS:",
        "        raise ValueError('INPUT_LIMIT')",
        "    closes = tuple(_close(value) for value in finalized_closes)",
        "    if len(closes) < MAX_INPUT_BARS:",
        "        return ('NO_SIGNAL',)",
        "    previous = closes[:-1]",
        "    current = closes",
        "    sma: dict[str, tuple[Fraction, Fraction]] = {}",
    ]
    for op in sma_ops:
        rows.append(
            f"    sma[{op.node_id!r}] = (_average(previous, {op.period}), "
            f"_average(current, {op.period}))"
        )
    rows += ["    result: list[str] = []"]
    for op in ir.operators:
        if op.kind == OperatorKindV1.CROSS_ABOVE:
            left, right = op.inputs
            label = "ENTRY" if op.action == "entry" else "EXIT"
            rows.extend(
                [
                    "    if (",
                    f"        sma[{left!r}][0] <= sma[{right!r}][0] and ",
                    f"        sma[{left!r}][1] > sma[{right!r}][1]",
                    f"    ): result.append({label!r})",
                ]
            )
        elif op.kind == OperatorKindV1.CROSS_BELOW:
            left, right = op.inputs
            label = "ENTRY" if op.action == "entry" else "EXIT"
            rows.extend(
                [
                    "    if (",
                    f"        sma[{left!r}][0] >= sma[{right!r}][0] and ",
                    f"        sma[{left!r}][1] < sma[{right!r}][1]",
                    f"    ): result.append({label!r})",
                ]
            )
    rows += ["    return tuple(result) if result else ('NO_SIGNAL',)", ""]
    return "\n".join(rows)


def _pine(ir: StrategyIRV1) -> str:
    rows = [
        "//@version=5",
        'indicator("Reviewed strategy signals", overlay=false)',
        f"// symbol={ir.symbol} timeframe={ir.timeframe} session={ir.session}",
    ]
    for op in ir.operators:
        if op.kind == OperatorKindV1.SMA:
            rows.append(f"lv_{op.node_id} = ta.sma(close, {op.period})")
        elif op.kind in {
            OperatorKindV1.STOP_DISTANCE,
            OperatorKindV1.TARGET_DISTANCE,
            OperatorKindV1.POSITION_CAP,
        }:
            name = {
                OperatorKindV1.STOP_DISTANCE: "lv_stop_pips",
                OperatorKindV1.TARGET_DISTANCE: "lv_target_pips",
                OperatorKindV1.POSITION_CAP: "lv_position_cap",
            }[op.kind]
            pine_type = "int" if op.kind == OperatorKindV1.POSITION_CAP else "float"
            if op.value is None:
                raise _error("INVALID_STRATEGY_IR")
            rows.append(f"{name} = {pine_type}({canonical_decimal(op.value)})")
    for op in ir.operators:
        if op.kind in {OperatorKindV1.CROSS_ABOVE, OperatorKindV1.CROSS_BELOW}:
            left, right = op.inputs
            pine_op = "ta.crossover" if op.kind == OperatorKindV1.CROSS_ABOVE else "ta.crossunder"
            rows.append(f"lv_{op.node_id} = {pine_op}(lv_{left}, lv_{right})")
            label = "ENTRY" if op.action == "entry" else "EXIT"
            rows.append(
                f"plotshape(lv_{op.node_id}, title={label!r}, text={label!r}, style=shape.circle)"
            )
    return "\n".join(rows) + "\n"


def compile_spec(
    spec: ReviewedStrategySpecV1,
    catalog: TemplateCatalogV1,
    target: CodegenTargetV1,
    *,
    verified_license: VerifiedLicenseV1 | None = None,
) -> CodeArtifactV1:
    """Compile exact reviewed claim DSL; never infer code from prose."""
    spec = require_reviewed_spec(spec)
    if type(target) is not CodegenTargetV1 or type(catalog) is not TemplateCatalogV1:
        raise _error("INVALID_COMPILE_INPUT")
    try:
        catalog = TemplateCatalogV1.model_validate(catalog.model_dump(mode="python"))
    except Exception:
        raise _error("INVALID_TEMPLATE_CATALOG") from None
    template = catalog.template_for(target)
    ir = _parse_spec(spec)
    python_source = _python(ir) if target == CodegenTargetV1.PYTHON else None
    pine_source = _pine(ir) if target == CodegenTargetV1.PINE_V5 else None
    ea_graph = (
        _lower_ea_graph(spec, ir, verified_license) if target == CodegenTargetV1.EA_GRAPH else None
    )
    artifact = CodeArtifactV1(
        schema_version="1",
        target=target,
        template_id=template.template_id,
        template_version=template.template_version,
        template_sha256=template.template_sha256,
        catalog_id=catalog.catalog_id,
        catalog_version=catalog.catalog_version,
        catalog_sha256=catalog.canonical_sha256(),
        strategy_ir=ir,
        source_provenance=spec.source,
        source_id=spec.source.source_id,
        source_sha256=spec.source.byte_sha256,
        packet_sha256=spec.packet_sha256,
        spec_sha256=spec.spec_sha256,
        reviewer_ids=tuple(sorted({item.reviewer_id for item in spec.reviewer_actions})),
        claim_ids=tuple(sorted(item.evidence_id for item in spec.accepted_claims)),
        reviewer_actions=spec.reviewer_actions,
        accepted_claims=spec.accepted_claims,
        rejected_claims=spec.rejected_claims,
        lineage_edges=spec.lineage_edges,
        conflicts=spec.conflicts,
        promotion_status=spec.promotion_status,
        promotable=False,
        parameter_schema=tuple(
            (op.node_id, "int" if op.kind == OperatorKindV1.SMA else "decimal", op.unit or "")
            for op in ir.operators
            if op.kind
            in {
                OperatorKindV1.SMA,
                OperatorKindV1.STOP_DISTANCE,
                OperatorKindV1.TARGET_DISTANCE,
                OperatorKindV1.POSITION_CAP,
            }
        ),
        dependency_manifest=("python:stdlib",)
        if target == CodegenTargetV1.PYTHON
        else (("pine:v5",) if target == CodegenTargetV1.PINE_V5 else ("ea-001:GraphV1",)),
        python_source=python_source,
        pine_source=pine_source,
        ea_graph=ea_graph,
        unsupported_nodes=(),
        canonical_sha256="0" * 64,
    )
    # Rebuild once with the digest, then bind identity/content to the dedicated issuer.
    payload: dict[str, Any] = artifact.model_dump(mode="python")
    payload["canonical_sha256"] = artifact.calculate_sha256()
    artifact = CodeArtifactV1(**payload)
    try:
        if artifact.ea_graph is not None:
            _EA_GRAPH_ISSUER.issue(artifact.ea_graph)
        return _ISSUER.issue(artifact)
    except SealError:
        raise _error("ARTIFACT_ISSUANCE_FAILED") from None


__all__ = ["compile_spec"]
