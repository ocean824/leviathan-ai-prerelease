"""Independent EA-001c acceptance probes.

Requirement-to-case matrix (written before executable probes):

- NUMERIC_SERIES wiring: valid SMA -> compare/crossover -> signal paths; reject
  series -> event, event -> numeric, wrong ports/kinds, and unsupported edges.
- Strategy lowering: default and inverted entry/exit pairings, plus exit-only,
  retain reviewed action labels and produce no partial graph.
- Rights gate: a valid STRAT-001 issued token compiles EA_GRAPH. Missing,
  unissued, tampered, or mismatched tokens return content-free
  SOURCE_RIGHTS_UNVERIFIED; caller-declared reuse_permitted is insufficient.
- Provenance and promotion: graph and manifest bind strategy_source_id and the
  canonical strategy_source_digest without embedded source JSON. Promotion
  stays BLOCKED_UNVERIFIED_SOURCE; promotable and export_ready remain false.
- Risk metadata: stop, target, and position-cap values appear only in
  declared_risk_parameters with NOT_ENFORCED_BY_EA__OMS_RISK_ONLY. They create
  no graph nodes or MQL logic.
- MQL output: MT4 and MT5 signal-only exports are byte-identical on repeat;
  no OrderSend/trade calls or compilation/execution authority are present.
- Causality: only finalized-bar logic is exported, with no future-bar or
  shift-0 lookahead. Truncating future bars preserves prior signals where
  runtime evaluation is available.
- Seals and safe boundaries: issued graph/package tampering is detected at
  consumer boundaries; wrong types and hostile canaries yield typed,
  content-free errors.
- Cycle-1 provenance: caller-built verified source_code graphs, copied graphs,
  stripped/tampered risk metadata, and imported graphs cannot cross export issuance.
- Cycle-1 license binding: identical source bytes with a different license
  reference or final reviewer identity do not authorize EA_GRAPH lowering.

Only synthetic reviewed source is used. The source snapshot and test hash will be recorded
in the final acceptance handoff after the worker freezes implementation bytes. Each risk
claim reference must match an accepted evidence_id. An absent-ID lowerer branch is
structurally unreachable through public compile_spec and is assigned to the worker unit test;
this acceptance suite checks that tampering with an issued spec is rejected before lowering.
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import zipfile
from decimal import Decimal
from pathlib import Path

import pytest

from leviathan_core.ea_builder import (
    BlockCatalogV1,
    EdgeV1,
    GraphV1,
    NodeV1,
    ParameterValueV1,
    TargetV1,
    standard_catalog_v1,
    validate,
)
from leviathan_core.ea_builder.export_source import (
    ExportSpecV1,
    ParameterBindingV1,
    SourceExportError,
    SymbolMappingV1,
    TargetManifestV1,
    TimeframeMappingV1,
    export_source,
    standard_template_catalog_v1,
    validate_graph_for_export,
)
from leviathan_core.ea_builder.roundtrip import import_generated_package
from leviathan_core.ea_builder.signal_catalog import extend_signal_catalog_v1
from leviathan_core.seal import SealError
from leviathan_core.strategy_ingest import (
    ClaimDecisionV1,
    ExtractedEvidenceV1,
    ReviewedStrategySpecV1,
    ReviewerActionV1,
    SafeScanReceiptV1,
    SourceManifestV1,
    SourceSpanV1,
    StrategyIngestError,
    accept_extraction,
    register_source,
)
from leviathan_core.strategy_ingest.codegen import compile_spec
from leviathan_core.strategy_ingest.ir import (
    CodegenTargetV1,
    OperatorKindV1,
    TargetTemplateV1,
    TemplateCatalogV1,
)
from leviathan_core.strategy_ingest.models import digest
from leviathan_core.strategy_ingest.review import (
    VerifiedLicenseV1,
    _issue_verified_license,
)

FIXTURES = Path(__file__).parent / "fixtures" / "ea001c"
SYNTHETIC_CANARY = "SYNTHETIC_LICENSE_CANARY_DO_NOT_ECHO"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class _TestLicenseVerifier:
    def __init__(self) -> None:
        self.issued: VerifiedLicenseV1 | None = None

    def verify_license(self, *, source_sha256, license_reference_id, reviewer_action):
        self.issued = _issue_verified_license(
            source_sha256=source_sha256,
            license_reference_id=license_reference_id,
            action_id=reviewer_action.action_id,
            reviewer_id=reviewer_action.reviewer_id,
        )
        return self.issued


def _reviewed_spec(
    fixture: str = "sma-crossover.txt",
) -> tuple[ReviewedStrategySpecV1, VerifiedLicenseV1]:
    """Build a genuine review-issued spec from synthetic claims and source bytes."""
    source_bytes = (FIXTURES / fixture).read_bytes()
    source_hash = _sha(source_bytes)
    safe_scan = SafeScanReceiptV1(
        schema_version="1",
        provenance_status="CALLER_DECLARED",
        scanned_sha256=source_hash,
        verdict="clean",
        scanner_name="synthetic-acceptance",
        scanner_version="1",
        scanned_at_ns=2,
    )
    manifest = SourceManifestV1(
        schema_version="1",
        source_id="synthetic_ea001c_strategy",
        source_uri="file:///synthetic/ea001c/strategy.txt",
        source_locator=fixture,
        source_bytes=source_bytes,
        byte_sha256=source_hash,
        media_type="text/plain",
        license_status="reuse_permitted",
        license_reference_id="synthetic_license_record",
        collection_method="provided_upload",
        entitlement_status="authorized",
        entitlement_provenance_status="CALLER_DECLARED",
        drm_status="clear",
        safe_scan=safe_scan,
        parser_version="synthetic-v1",
        transcriber_version=None,
        acquired_ns=1,
        available_ns=2,
        review_asof_ns=3,
    )
    raw = source_bytes.decode("utf-8")
    lines = [line for line in raw.splitlines() if line]
    evidence: list[ExtractedEvidenceV1] = []
    cursor = 0
    for index, text in enumerate(lines):
        encoded = text.encode("utf-8")
        start = source_bytes.index(encoded, cursor)
        end = start + len(encoded)
        cursor = end
        key, _ = text.split("=", 1)
        if key in {"symbol", "timeframe", "session"}:
            kind = "market_assumption"
        elif key == "entry":
            kind = "entry_condition"
        elif key == "exit":
            kind = "exit_condition"
        else:
            kind = "parameter"
        evidence.append(
            ExtractedEvidenceV1(
                schema_version="1",
                evidence_id=f"ea001c_claim_{index:02d}",
                claim_key=key,
                claim_kind=kind,
                claim_text=text,
                confidence=Decimal("0.99"),
                source_sha256=source_hash,
                span=SourceSpanV1(
                    schema_version="1",
                    byte_start=start,
                    byte_end=end,
                    span_sha256=_sha(source_bytes[start:end]),
                    page_start=None,
                    page_end=None,
                    time_start_ms=None,
                    time_end_ms=None,
                ),
                derived_from=(),
                text_ref=None,
                chunk_ref=None,
                embedding_ref=None,
                tags=(),
            )
        )
    packet = register_source(manifest, tuple(evidence))
    action = ReviewerActionV1(
        schema_version="1",
        action_id="ea001c_synthetic_review",
        packet_sha256=packet.packet_sha256,
        reviewer_id="ea001c_synthetic_reviewer",
        reviewed_at_ns=packet.source.review_asof_ns,
        decisions=tuple(
            ClaimDecisionV1(
                schema_version="1",
                evidence_id=item.evidence_id,
                decision="accept",
                reason_code="supported",
            )
            for item in packet.evidence
        ),
    )
    verifier = _TestLicenseVerifier()
    result = accept_extraction(packet, action, license_verifier=verifier)
    assert result.spec is not None and verifier.issued is not None
    return result.spec, verifier.issued


def _template_catalog() -> TemplateCatalogV1:
    templates = tuple(
        TargetTemplateV1(
            target=target,
            template_id=f"synthetic_{target.value.lower()}",
            template_version="1",
            template_sha256=_sha(f"ea001c-template:{target.value}".encode("ascii")),
        )
        for target in CodegenTargetV1
    )
    return TemplateCatalogV1(
        schema_version="1",
        catalog_id="synthetic_ea001c_catalog",
        catalog_version=1,
        templates=templates,
    )


def _compile_ea_graph(
    spec: ReviewedStrategySpecV1,
    token: VerifiedLicenseV1 | None,
):
    return compile_spec(
        spec,
        _template_catalog(),
        CodegenTargetV1.EA_GRAPH,
        verified_license=token,
    )


def _signal_catalog() -> BlockCatalogV1:
    return extend_signal_catalog_v1(standard_catalog_v1())


def _assert_unverified_rights(error: StrategyIngestError, canary: str | None = None) -> None:
    assert error.code == "SOURCE_RIGHTS_UNVERIFIED"
    assert canary is None or canary not in str(error)
    assert canary is None or canary not in repr(error.args)
    assert canary is None or canary not in json.dumps(error.errors())


def _mql_export(spec, graph: GraphV1, platform: str):
    catalog = _signal_catalog()
    validated = validate_graph_for_export(graph, catalog, TargetV1(platform=platform))
    parameter_bindings = tuple(
        ParameterBindingV1(
            node.node_id,
            parameter,
            "Input_" + node.node_id.replace(".", "_") + "_" + parameter,
        )
        for node in graph.nodes
        for parameter in node.parameters
    )
    spec = ExportSpecV1(
        schema_version=1,
        artifact_type="EA",
        platform=platform,
        routing_mode="LocalTerminal",
        strategy_hash=spec.spec_sha256,
        git_commit="e" * 40,
        version_label="ea001c_synthetic_v1",
        symbol_map=(SymbolMappingV1("EURUSD", "EURUSD"),),
        timeframe_map=(TimeframeMappingV1("M5", "M5"),),
        target_manifest=TargetManifestV1(
            supported_symbols=("EURUSD",),
            supported_timeframes=("M5",),
            occupied_magic_numbers=(901,),
            broker_lot_step=Decimal("0.01"),
        ),
        parameter_bindings=parameter_bindings,
        magic_number=None,
    )
    return export_source(validated, spec, standard_template_catalog_v1())


def _assert_signal_only_export(package, spec: ReviewedStrategySpecV1) -> dict[str, object]:
    manifest = json.loads(package.manifest_json)
    assert package.export_ready is False
    assert package.compiled is False
    assert package.signed is False
    assert manifest["export_ready"] is False
    assert manifest["compiled"] is False and manifest["signed"] is False
    assert manifest["promotion_status"] == spec.promotion_status
    assert manifest["promotable"] is False
    assert manifest["strategy_source_id"] == spec.source.source_id
    assert manifest["strategy_source_digest"] == digest(spec.source.model_dump(mode="json"))
    assert "source_bytes" not in package.manifest_json
    assert spec.source.source_uri not in package.manifest_json
    return manifest


def test_ea_graph_requires_matching_strat001_issued_license() -> None:
    spec, token = _reviewed_spec()
    artifact = _compile_ea_graph(spec, token)
    graph = artifact.ea_graph
    assert isinstance(graph, GraphV1)
    assert graph.provenance.source_rights == "verified"
    assert token.source_sha256 == spec.source.byte_sha256
    assert graph.source_hash == spec.source.byte_sha256
    assert graph.strategy_source_id == spec.source.source_id
    assert graph.strategy_source_digest == digest(spec.source.model_dump(mode="json"))
    assert graph.promotion_status == spec.promotion_status == "BLOCKED_UNVERIFIED_SOURCE"
    assert artifact.promotable is False
    assert spec.source.license_status == "reuse_permitted"
    graph_json = graph.model_dump_json()
    assert spec.source.source_uri not in graph_json
    assert "source_bytes" not in graph_json

    with pytest.raises(StrategyIngestError) as missing:
        _compile_ea_graph(spec, None)
    _assert_unverified_rights(missing.value)

    with pytest.raises(StrategyIngestError) as unissued:
        _compile_ea_graph(spec, object())  # type: ignore[arg-type]
    _assert_unverified_rights(unissued.value)

    class EqualButUnissuedLicense(VerifiedLicenseV1):
        __slots__ = ()

        def __hash__(self) -> int:
            return hash(token)

        def __eq__(self, other: object) -> bool:
            return other is token

    equality_forgery = object.__new__(EqualButUnissuedLicense)
    with pytest.raises(StrategyIngestError) as forged_type:
        _compile_ea_graph(spec, equality_forgery)
    _assert_unverified_rights(forged_type.value)

    forged = _issue_verified_license(
        source_sha256="f" * 64,
        license_reference_id=spec.source.license_reference_id,
        action_id="forged_but_issued_action",
        reviewer_id="synthetic_reviewer",
    )
    with pytest.raises(StrategyIngestError) as mismatch:
        _compile_ea_graph(spec, forged)
    _assert_unverified_rights(mismatch.value)

    _, tampered = _reviewed_spec()
    object.__setattr__(tampered, "source_sha256", SYNTHETIC_CANARY)
    with pytest.raises(StrategyIngestError) as damaged:
        _compile_ea_graph(spec, tampered)
    _assert_unverified_rights(damaged.value, SYNTHETIC_CANARY)


def test_license_binding_includes_reference_and_final_reviewer_action() -> None:
    spec, _ = _reviewed_spec()
    final_action = spec.reviewer_actions[-1]
    same_bytes_different_license = _issue_verified_license(
        source_sha256=spec.source.byte_sha256,
        license_reference_id="synthetic_other_license",
        action_id=final_action.action_id,
        reviewer_id=final_action.reviewer_id,
    )
    same_bytes_different_action = _issue_verified_license(
        source_sha256=spec.source.byte_sha256,
        license_reference_id=spec.source.license_reference_id,
        action_id="synthetic_other_action",
        reviewer_id=final_action.reviewer_id,
    )
    same_bytes_different_reviewer = _issue_verified_license(
        source_sha256=spec.source.byte_sha256,
        license_reference_id=spec.source.license_reference_id,
        action_id=final_action.action_id,
        reviewer_id="synthetic_other_reviewer",
    )

    for token in (
        same_bytes_different_license,
        same_bytes_different_action,
        same_bytes_different_reviewer,
    ):
        assert token.source_sha256 == spec.source.byte_sha256
        with pytest.raises(StrategyIngestError) as mismatch:
            _compile_ea_graph(spec, token)
        _assert_unverified_rights(mismatch.value)


def test_python_and_pine_ignore_ea_graph_license_argument() -> None:
    spec, _ = _reviewed_spec()
    templates = _template_catalog()
    for target in (CodegenTargetV1.PYTHON, CodegenTargetV1.PINE_V5):
        without_token = compile_spec(spec, templates, target)
        with_ignored_token = compile_spec(
            spec,
            templates,
            target,
            verified_license=object(),  # type: ignore[arg-type]
        )
        assert with_ignored_token.canonical_sha256 == without_token.canonical_sha256
        assert with_ignored_token.promotion_status == "BLOCKED_UNVERIFIED_SOURCE"
        assert with_ignored_token.promotable is False


def test_compile_requires_issued_review_spec_and_typed_wrong_input_error() -> None:
    spec, token = _reviewed_spec()
    for make_clone in (
        lambda: ReviewedStrategySpecV1.model_validate(spec.model_dump(mode="python")),
        lambda: spec.model_copy(),
        lambda: spec.copy(update={}),
    ):
        try:
            clone = make_clone()
        except StrategyIngestError as error:
            assert error.code
            assert SYNTHETIC_CANARY not in str(error)
            continue
        with pytest.raises(StrategyIngestError) as unissued:
            _compile_ea_graph(clone, token)
        assert unissued.value.code == "REVIEWED_SPEC_NOT_ISSUED"
        assert SYNTHETIC_CANARY not in str(unissued.value)

    changed_spec, changed_token = _reviewed_spec("sma-crossover-risk-metadata.txt")
    object.__setattr__(changed_spec, "accepted_claims", changed_spec.accepted_claims[:-1])
    with pytest.raises(StrategyIngestError) as tampered_claims:
        _compile_ea_graph(changed_spec, changed_token)
    assert tampered_claims.value.code
    assert SYNTHETIC_CANARY not in str(tampered_claims.value)

    with pytest.raises(StrategyIngestError) as wrong_type:
        compile_spec(None, _template_catalog(), CodegenTargetV1.EA_GRAPH)  # type: ignore[arg-type]
    assert wrong_type.value.code == "REVIEWED_SPEC_NOT_ISSUED"
    assert SYNTHETIC_CANARY not in str(wrong_type.value)


@pytest.mark.parametrize(
    ("fixture", "expected"),
    [
        (
            "sma-crossover.txt",
            {"entry": OperatorKindV1.CROSS_ABOVE, "exit": OperatorKindV1.CROSS_BELOW},
        ),
        (
            "sma-crossover-inverted.txt",
            {"entry": OperatorKindV1.CROSS_BELOW, "exit": OperatorKindV1.CROSS_ABOVE},
        ),
        ("sma-exit-only.txt", {"exit": OperatorKindV1.CROSS_BELOW}),
    ],
)
def test_reviewed_pairings_lower_without_partial_graph(
    fixture: str, expected: dict[str, OperatorKindV1]
) -> None:
    spec, token = _reviewed_spec(fixture)
    artifact = _compile_ea_graph(spec, token)
    graph = artifact.ea_graph
    assert isinstance(graph, GraphV1)
    operators = {
        op.action: op.kind
        for op in artifact.strategy_ir.operators
        if op.kind in {OperatorKindV1.CROSS_ABOVE, OperatorKindV1.CROSS_BELOW}
    }
    assert operators == expected
    assert {node.block_id for node in graph.nodes} <= {
        "bar_event",
        "sma_indicator",
        "crossover.v1",
        "entry_signal.v1",
        "exit_signal.v1",
    }
    signal_nodes = {node.block_id for node in graph.nodes}
    assert ("entry_signal.v1" in signal_nodes) is ("entry" in expected)
    assert ("exit_signal.v1" in signal_nodes) is ("exit" in expected)
    lowered_by_id = {node.node_id: node for node in graph.nodes}
    for action, kind in expected.items():
        op = next(
            op for op in artifact.strategy_ir.operators if op.action == action and op.kind == kind
        )
        cross_node = lowered_by_id[op.node_id]
        assert cross_node.block_id == "crossover.v1"
        assert cross_node.parameters["direction"].value == (
            "above" if kind is OperatorKindV1.CROSS_ABOVE else "below"
        )
        expected_signal_block = "entry_signal.v1" if action == "entry" else "exit_signal.v1"
        signal_node = next(
            node
            for node in graph.nodes
            if node.block_id in {"entry_signal.v1", "exit_signal.v1"}
            and node.parameters["signal_key"].value == op.node_id
        )
        assert signal_node.block_id == expected_signal_block


def test_numeric_series_ports_allow_only_declared_wiring() -> None:
    spec, token = _reviewed_spec()
    graph = _compile_ea_graph(spec, token).ea_graph
    assert isinstance(graph, GraphV1)
    catalog = _signal_catalog()
    definitions = {item.block_id: item for item in catalog.blocks}
    assert definitions["sma_indicator"].outputs[0].kind == "numeric-series"
    assert {port.kind for port in definitions["compare.v1"].inputs} == {"decimal"}
    assert {port.kind for port in definitions["crossover.v1"].inputs} == {"decimal"}
    assert definitions["entry_signal.v1"].inputs[0].kind == "bool"
    assert definitions["exit_signal.v1"].inputs[0].kind == "bool"
    valid = validate(graph, catalog, TargetV1(platform="MT4"))
    assert valid.status == "VALID" and not valid.errors
    node_by_id = {node.node_id: node for node in graph.nodes}
    for edge in graph.edges:
        source_block = node_by_id[edge.source_node].block_id
        target_block = node_by_id[edge.target_node].block_id
        if source_block == "bar_event":
            assert (edge.source_port, target_block, edge.target_port, edge.kind) == (
                "event",
                "sma_indicator",
                "event",
                "event",
            )
        elif source_block == "sma_indicator":
            assert (edge.source_port, target_block, edge.target_port, edge.kind) == (
                "value",
                "crossover.v1",
                edge.target_port,
                "data",
            )
            assert edge.target_port in {"left", "right"}
        else:
            assert source_block == "crossover.v1"
            assert (edge.source_port, target_block, edge.target_port, edge.kind) == (
                "condition",
                "entry_signal.v1" if target_block == "entry_signal.v1" else "exit_signal.v1",
                "condition",
                "data",
            )

    base_nodes = tuple(
        node for node in graph.nodes if node.block_id in {"bar_event", "sma_indicator"}
    )
    bar_edges = tuple(edge for edge in graph.edges if edge.source_node == "bar_source")
    compare = NodeV1(
        node_id="compare_fixture",
        block_id="compare.v1",
        parameters={"op": ParameterValueV1(kind="enum", value="gt")},
        symbol=graph.symbol,
        timeframe=graph.timeframe,
        warmup_bars=graph.warmup_bars,
    )
    signal = NodeV1(
        node_id="compare_fixture_signal",
        block_id="entry_signal.v1",
        parameters={"signal_key": ParameterValueV1(kind="symbol", value="compare_result")},
        symbol=graph.symbol,
        timeframe=graph.timeframe,
        warmup_bars=graph.warmup_bars,
    )
    compare_graph = graph.model_copy(
        update={
            "nodes": (*base_nodes, compare, signal),
            "edges": (
                *bar_edges,
                EdgeV1(
                    edge_id="compare_fast",
                    source_node="fast",
                    source_port="value",
                    target_node="compare_fixture",
                    target_port="left",
                    kind="data",
                ),
                EdgeV1(
                    edge_id="compare_slow",
                    source_node="slow",
                    source_port="value",
                    target_node="compare_fixture",
                    target_port="right",
                    kind="data",
                ),
                EdgeV1(
                    edge_id="compare_signal",
                    source_node="compare_fixture",
                    source_port="condition",
                    target_node="compare_fixture_signal",
                    target_port="condition",
                    kind="data",
                ),
            ),
        }
    )
    compare_validation = validate(compare_graph, catalog, TargetV1(platform="MT4"))
    assert compare_validation.status == "VALID" and not compare_validation.errors

    entry_cross = next(node for node in graph.nodes if node.node_id == "entry_1")
    fast_edge = next(
        edge
        for edge in graph.edges
        if edge.source_node == "fast" and edge.target_node == entry_cross.node_id
    )
    wrong_kind = EdgeV1(
        edge_id=fast_edge.edge_id,
        source_node=fast_edge.source_node,
        source_port=fast_edge.source_port,
        target_node=fast_edge.target_node,
        target_port=fast_edge.target_port,
        kind="event",
    )
    invalid_kind_graph = graph.model_copy(
        update={"edges": tuple(wrong_kind if edge == fast_edge else edge for edge in graph.edges)}
    )
    kind_result = validate(invalid_kind_graph, catalog, TargetV1(platform="MT4"))
    assert kind_result.status == "INVALID"
    assert {issue.code for issue in kind_result.errors} & {
        "TYPE_MISMATCH",
        "EDGE_KIND_MISMATCH",
    }

    direct_to_signal = EdgeV1(
        edge_id="invalid_numeric_to_event",
        source_node="fast",
        source_port="value",
        target_node="signal_entry_1",
        target_port="condition",
        kind="data",
    )
    invalid_endpoint_graph = graph.model_copy(update={"edges": (*graph.edges, direct_to_signal)})
    endpoint_result = validate(invalid_endpoint_graph, catalog, TargetV1(platform="MT4"))
    assert endpoint_result.status == "INVALID"
    assert {issue.code for issue in endpoint_result.errors} & {
        "TYPE_MISMATCH",
        "UNKNOWN_PORT",
        "EDGE_KIND_MISMATCH",
    }
    with pytest.raises(SourceExportError) as rejected:
        _mql_export(spec, invalid_endpoint_graph, "MT4")
    assert rejected.value.code == "GRAPH_INVALID"


def test_mql4_and_mql5_exports_are_deterministic_causal_and_signal_only() -> None:
    spec, token = _reviewed_spec()
    artifact = _compile_ea_graph(spec, token)
    graph = artifact.ea_graph
    assert isinstance(graph, GraphV1)
    forbidden = re.compile(
        r"\b(?:OrderSend|OrderSendAsync|OrderClose|OrderModify|OrderDelete|"
        r"PositionOpen|PositionClose|CTrade|MqlTradeRequest)\b|\btrade\s*\.",
        re.IGNORECASE,
    )
    for platform in ("MT4", "MT5"):
        first = _mql_export(spec, graph, platform)
        second = _mql_export(spec, graph, platform)
        manifest = _assert_signal_only_export(first, spec)
        assert first.source_text == second.source_text
        assert first.archive_bytes == second.archive_bytes
        assert first.source_filename == ("source.mq4" if platform == "MT4" else "source.mq5")
        assert not forbidden.search(first.source_text)
        assert "LVSignalEmissionV1" in first.source_text
        assert "finalized_bar_id" in first.source_text
        assert not re.search(r"lv_sma_[A-Za-z0-9_]+\[0\]", first.source_text)
        assert "[1]" in first.source_text and "[2]" in first.source_text
        assert manifest["source_hash"] == spec.source.byte_sha256
        assert all(claim.claim_text not in first.source_text for claim in spec.accepted_claims)
        with zipfile.ZipFile(io.BytesIO(first.archive_bytes)) as archive:
            graph_document = archive.read("graph.json").decode("ascii")
            assert spec.source.source_uri not in graph_document
            assert "source_bytes" not in graph_document
            assert graph.strategy_source_id in graph_document
            assert graph.strategy_source_digest in graph_document
        imported = import_generated_package(first.archive_bytes)
        assert imported.source_text == first.source_text
        assert imported.graph_hash == first.graph_hash
        with pytest.raises(SourceExportError) as reexport_denied:
            validate_graph_for_export(
                imported.graph, _signal_catalog(), TargetV1(platform=platform)
            )
        assert reexport_denied.value.code in {"INVALID_GRAPH", "SOURCE_PROVENANCE"}


@pytest.mark.parametrize(
    ("fixture", "entry_expected"),
    [
        ("sma-crossover.txt", True),
        ("sma-crossover-inverted.txt", True),
        ("sma-exit-only.txt", False),
    ],
)
def test_mql_export_preserves_entry_exit_labels(fixture: str, entry_expected: bool) -> None:
    spec, token = _reviewed_spec(fixture)
    graph = _compile_ea_graph(spec, token).ea_graph
    assert isinstance(graph, GraphV1)
    for platform in ("MT4", "MT5"):
        source = _mql_export(spec, graph, platform).source_text
        assert ('.kind = "entry";' in source) is entry_expected
        assert '.kind = "exit";' in source


def test_risk_parameters_are_sealed_metadata_only_and_never_rendered() -> None:
    spec, token = _reviewed_spec("sma-crossover-risk-metadata.txt")
    artifact = _compile_ea_graph(spec, token)
    graph = artifact.ea_graph
    assert isinstance(graph, GraphV1)
    risk = {item.kind: item for item in graph.declared_risk_parameters}
    assert {kind: item.value for kind, item in risk.items()} == {
        "stop_distance": Decimal("37.125"),
        "target_distance": Decimal("63.875"),
        "position_cap": Decimal("7"),
    }
    accepted_claim_ids = {item.claim_text: item.evidence_id for item in spec.accepted_claims}
    assert {item.source_claim_id for item in risk.values()} <= set(accepted_claim_ids.values())
    assert {
        "stop.pips=37.125": risk["stop_distance"].source_claim_id,
        "target.pips=63.875": risk["target_distance"].source_claim_id,
        "position_cap=7": risk["position_cap"].source_claim_id,
    } == {
        key: accepted_claim_ids[key]
        for key in accepted_claim_ids
        if key
        in {
            "stop.pips=37.125",
            "target.pips=63.875",
            "position_cap=7",
        }
    }
    assert {node.block_id for node in graph.nodes}.isdisjoint(
        {"risk_cap", "money_size", "stop_distance", "target_distance", "position_cap"}
    )
    catalog = _signal_catalog()
    validation = validate(graph, catalog, TargetV1(platform="MT5"))
    assert validation.status == "VALID" and not validation.errors
    without_risk_metadata = graph.model_copy(update={"declared_risk_parameters": ()})
    assert validate(without_risk_metadata, catalog, TargetV1(platform="MT5")).model_dump(
        mode="json"
    ) == validation.model_dump(mode="json")

    package = _mql_export(spec, graph, "MT5")
    manifest = _assert_signal_only_export(package, spec)
    declared = manifest["declared_risk_parameters"]
    assert isinstance(declared, list) and len(declared) == 3
    assert all(item["enforcement"] == "NOT_ENFORCED_BY_EA__OMS_RISK_ONLY" for item in declared)
    assert {item["kind"] for item in declared} == set(risk)
    assert {item["value"] for item in declared} == {"37.125", "63.875", "7"}
    assert {
        (item["kind"], item["value"], item["unit"], item["source_claim_id"]) for item in declared
    } == {
        (item.kind, str(item.value), item.unit, item.source_claim_id)
        for item in graph.declared_risk_parameters
    }
    for forbidden_metadata in (
        "stop_distance",
        "target_distance",
        "position_cap",
        "37.125",
        "63.875",
    ):
        assert forbidden_metadata not in package.source_text

    from leviathan_core.seal import verify

    assert verify(artifact, "strategy.codegen")
    copied_artifact = artifact.model_copy()
    assert not verify(copied_artifact, "strategy.codegen")
    object.__setattr__(graph, "declared_risk_parameters", ())
    assert not verify(artifact, "strategy.codegen")


def test_strategy_source_graph_export_requires_exact_graph_issuance() -> None:
    spec, token = _reviewed_spec("sma-crossover-risk-metadata.txt")
    graph = _compile_ea_graph(spec, token).ea_graph
    assert isinstance(graph, GraphV1)
    assert graph.provenance.source_asset_kind == "source_code"
    assert graph.provenance.source_rights == "verified"
    assert graph.declared_risk_parameters

    caller_built = GraphV1.model_validate(graph.model_dump(mode="python"))
    assert caller_built.provenance.source_asset_kind == "source_code"
    assert caller_built.provenance.source_rights == "verified"
    with pytest.raises(SourceExportError) as self_asserted:
        _mql_export(spec, caller_built, "MT5")
    assert self_asserted.value.code in {"INVALID_GRAPH", "SOURCE_PROVENANCE"}

    copied_graph = graph.model_copy()
    with pytest.raises(SourceExportError) as copied:
        _mql_export(spec, copied_graph, "MT5")
    assert copied.value.code in {"INVALID_GRAPH", "SOURCE_PROVENANCE"}

    stripped_copy = graph.model_copy(update={"declared_risk_parameters": ()})
    empty_manifest_package = None
    with pytest.raises(SourceExportError) as stripped:
        empty_manifest_package = _mql_export(spec, stripped_copy, "MT5")
    assert empty_manifest_package is None
    assert stripped.value.code in {"INVALID_GRAPH", "SOURCE_PROVENANCE"}
    assert SYNTHETIC_CANARY not in str(stripped.value)

    tampered_graph = _compile_ea_graph(spec, token).ea_graph
    assert isinstance(tampered_graph, GraphV1)
    try:
        object.__setattr__(tampered_graph, "declared_risk_parameters", ())
    except SealError:
        # Immediate mutation rejection means an empty risk manifest was not created.
        return
    from leviathan_core.seal import verify

    assert not verify(tampered_graph, "strategy.ea_graph")
    tampered_package = None
    with pytest.raises(SourceExportError) as tampered:
        tampered_package = _mql_export(spec, tampered_graph, "MT5")
    assert tampered_package is None
    assert tampered.value.code in {"INVALID_GRAPH", "SOURCE_PROVENANCE"}


def test_unmapped_operator_rejects_without_partial_graph() -> None:
    spec, token = _reviewed_spec("sma-crossover-unsupported.txt")
    with pytest.raises(StrategyIngestError) as caught:
        _compile_ea_graph(spec, token)
    assert caught.value.code == "UNSUPPORTED_CLAIM"
    assert SYNTHETIC_CANARY not in str(caught.value)
