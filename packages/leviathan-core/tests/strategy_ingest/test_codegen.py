"""Focused owner tests for the STRAT-002 compiler and sealed review boundary."""

from __future__ import annotations

import ast
import hashlib
from decimal import Decimal
from types import SimpleNamespace

import pytest

from leviathan_core.ea_builder.blocks import standard_catalog_v1
from leviathan_core.ea_builder.export_source import SourceExportError, validate_graph_for_export
from leviathan_core.ea_builder.graph import GraphV1, TargetV1
from leviathan_core.ea_builder.signal_catalog import extend_signal_catalog_v1
from leviathan_core.seal import SealError, verify
from leviathan_core.strategy_ingest import (
    ClaimDecisionV1,
    ExtractedEvidenceV1,
    ReviewerActionV1,
    SafeScanReceiptV1,
    SourceManifestV1,
    SourceSpanV1,
    accept_extraction,
    register_source,
)
from leviathan_core.strategy_ingest.codegen import _lower_ea_graph, compile_spec
from leviathan_core.strategy_ingest.ir import (
    CodeArtifactV1,
    CodegenTargetV1,
    TargetTemplateV1,
    TemplateCatalogV1,
)
from leviathan_core.strategy_ingest.models import StrategyIngestError
from leviathan_core.strategy_ingest.review import (
    _issue_verified_license,
    require_reviewed_spec,
)


class _LicenseVerifier:
    def verify_license(
        self, *, source_sha256: str, license_reference_id: str, reviewer_action: ReviewerActionV1
    ):
        return _issue_verified_license(
            source_sha256=source_sha256,
            license_reference_id=license_reference_id,
            action_id=reviewer_action.action_id,
            reviewer_id=reviewer_action.reviewer_id,
        )


def _spec(
    crossovers: tuple[str, ...] = (),
    *,
    license_reference_id: str = "test-license",
    action_id: str = "review01",
    reviewer_id: str = "reviewer01",
):
    texts = (
        "symbol=EURUSD",
        "timeframe=M5",
        "session=UTC_24x5",
        "sma.fast=2",
        "sma.slow=3",
        *(crossovers or ("entry=cross_above(fast,slow)", "exit=cross_below(fast,slow)")),
        "stop.pips=20",
        "target.pips=40",
        "position_cap=1",
    )
    raw = ("\n".join(texts) + "\n").encode()
    source_hash = hashlib.sha256(raw).hexdigest()
    safe_scan = SafeScanReceiptV1(
        schema_version="1",
        provenance_status="CALLER_DECLARED",
        scanned_sha256=source_hash,
        verdict="clean",
        scanner_name="testscan",
        scanner_version="1",
        scanned_at_ns=2,
    )
    manifest = SourceManifestV1(
        schema_version="1",
        source_id="synthetic-strategy",
        source_uri="file:///fixtures/synthetic.txt",
        source_locator="synthetic.txt",
        source_bytes=raw,
        byte_sha256=source_hash,
        media_type="text/plain",
        license_status="reuse_permitted",
        license_reference_id=license_reference_id,
        collection_method="provided_upload",
        entitlement_status="authorized",
        entitlement_provenance_status="CALLER_DECLARED",
        drm_status="clear",
        safe_scan=safe_scan,
        parser_version="test-parser",
        transcriber_version=None,
        acquired_ns=1,
        available_ns=2,
        review_asof_ns=3,
    )
    evidence: list[ExtractedEvidenceV1] = []
    offset = 0
    for index, text in enumerate(texts):
        encoded = text.encode()
        evidence.append(
            ExtractedEvidenceV1(
                schema_version="1",
                evidence_id=f"claim{index:02d}",
                claim_key=f"claim{index:02d}",
                claim_kind=(
                    "entry_condition"
                    if text.startswith("entry=")
                    else "exit_condition"
                    if text.startswith("exit=")
                    else "parameter"
                ),
                claim_text=text,
                confidence=Decimal("1"),
                source_sha256=source_hash,
                span=SourceSpanV1(
                    schema_version="1",
                    byte_start=offset,
                    byte_end=offset + len(encoded),
                    span_sha256=hashlib.sha256(encoded).hexdigest(),
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
        offset += len(encoded) + 1
    packet = register_source(manifest, tuple(evidence))
    action = ReviewerActionV1(
        schema_version="1",
        action_id=action_id,
        packet_sha256=packet.packet_sha256,
        reviewer_id=reviewer_id,
        reviewed_at_ns=3,
        decisions=tuple(
            ClaimDecisionV1(
                schema_version="1",
                evidence_id=item.evidence_id,
                decision="accept",
                reason_code="supported",
            )
            for item in evidence
        ),
    )
    return accept_extraction(packet, action, license_verifier=_LicenseVerifier()).spec


def _license_for_spec(spec):
    action = spec.reviewer_actions[-1]
    return _issue_verified_license(
        source_sha256=spec.source.byte_sha256,
        license_reference_id=spec.source.license_reference_id,
        action_id=action.action_id,
        reviewer_id=action.reviewer_id,
    )


def _export_graph(graph: GraphV1) -> None:
    catalog = extend_signal_catalog_v1(standard_catalog_v1())
    validate_graph_for_export(graph, catalog, TargetV1(platform="MT5"))


def _catalog() -> TemplateCatalogV1:
    return TemplateCatalogV1(
        schema_version="1",
        catalog_id="fixture-catalog",
        catalog_version=1,
        templates=tuple(
            TargetTemplateV1(
                target=target,
                template_id=f"fixture-{target.value.lower()}",
                template_version="1",
                template_sha256=("a" if target == CodegenTargetV1.PYTHON else "b") * 64,
            )
            for target in CodegenTargetV1
        ),
    )


def test_python_uses_exact_bounded_finalized_close_smas_and_is_causal() -> None:
    spec = _spec()
    assert spec is not None
    artifact = compile_spec(spec, _catalog(), CodegenTargetV1.PYTHON)
    assert artifact.promotable is False
    assert artifact.promotion_status == "BLOCKED_UNVERIFIED_SOURCE"
    assert artifact.python_source is not None
    namespace: dict[str, object] = {}
    exec(compile(artifact.python_source, "generated.py", "exec"), namespace)
    signal = namespace["signal"]
    assert signal((Decimal("1"), Decimal("1"), Decimal("1"))) == ("NO_SIGNAL",)
    bars = tuple(map(Decimal, ("1", "1", "1", "2")))
    assert signal(bars) == ("ENTRY",)
    suffix = tuple(map(Decimal, ("9", "1", "1", "2")))
    assert signal(suffix) == ("ENTRY",)
    assert signal(tuple(map(Decimal, ("9", "9", "1", "1", "2")[-4:]))) == signal(suffix)
    assert signal(tuple(("1", Decimal("1"), "1", Decimal("2")))) == ("ENTRY",)
    assert namespace["MAX_INPUT_BARS"] == 4
    assert artifact.dependency_manifest == ("python:stdlib",)
    assert "leviathan_core." not in artifact.python_source
    with pytest.raises(ValueError, match="INPUT_LIMIT"):
        signal(tuple(map(Decimal, ("1", "1", "1", "2", "3"))))


def test_signal_is_invariant_to_changes_after_each_decision_bar() -> None:
    spec = _spec()
    assert spec is not None
    artifact = compile_spec(spec, _catalog(), CodegenTargetV1.PYTHON)
    assert artifact.python_source is not None
    namespace: dict[str, object] = {}
    exec(compile(artifact.python_source, "generated.py", "exec"), namespace)
    signal = namespace["signal"]
    bars = tuple(map(Decimal, ("1", "1", "1", "2", "3", "0", "4", "1")))
    outcomes: list[tuple[str, ...]] = []

    def at(series: tuple[Decimal, ...], index: int) -> tuple[str, ...]:
        return signal(series[: index + 1][-4:])

    for decision_index in range(len(bars)):
        changed = bars[: decision_index + 1] + tuple(
            Decimal(100 + index) for index in range(len(bars) - decision_index - 1)
        )
        assert at(bars, decision_index) == at(changed, decision_index)
        outcomes.append(at(bars, decision_index))
    assert any(result != ("NO_SIGNAL",) for result in outcomes)


def test_crossover_signal_keeps_reviewed_action_not_direction() -> None:
    spec = _spec(("entry=cross_below(fast,slow)", "exit=cross_above(fast,slow)"))
    assert spec is not None
    python = compile_spec(spec, _catalog(), CodegenTargetV1.PYTHON).python_source
    pine = compile_spec(spec, _catalog(), CodegenTargetV1.PINE_V5).pine_source
    assert python is not None and pine is not None
    assert "result.append('ENTRY')" in python
    assert "result.append('EXIT')" in python
    assert "title='ENTRY', text='ENTRY'" in pine
    assert "title='EXIT', text='EXIT'" in pine
    operators = compile_spec(spec, _catalog(), CodegenTargetV1.PYTHON).strategy_ir.operators
    crosses = [op for op in operators if op.kind.value.startswith("cross_")]
    assert {op.action for op in crosses} == {"entry", "exit"}
    namespace: dict[str, object] = {}
    exec(compile(python, "inverted.py", "exec"), namespace)
    assert namespace["signal"](("1", "3", "2", "1")) == ("ENTRY",)
    assert namespace["signal"](("3", "1", "2", "3")) == ("EXIT",)


def test_exit_only_claims_emit_exit_without_inventing_an_entry() -> None:
    spec = _spec(("exit=cross_below(fast,slow)",))
    assert spec is not None
    artifact = compile_spec(spec, _catalog(), CodegenTargetV1.PYTHON)
    assert artifact.python_source is not None
    namespace: dict[str, object] = {}
    exec(compile(artifact.python_source, "generated.py", "exec"), namespace)
    signal = namespace["signal"]
    assert signal(tuple(map(Decimal, ("1", "3", "2", "1")))) == ("EXIT",)
    assert signal(tuple(map(Decimal, ("3", "1", "2", "3")))) == ("NO_SIGNAL",)


def test_pine_has_current_bar_sma_without_future_references() -> None:
    spec = _spec()
    assert spec is not None
    source = compile_spec(spec, _catalog(), CodegenTargetV1.PINE_V5).pine_source
    assert source is not None
    tree = ast.parse("\n".join(line for line in source.splitlines() if not line.startswith("//")))
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
    sma_calls = [
        call
        for call in calls
        if isinstance(call.func, ast.Attribute)
        and isinstance(call.func.value, ast.Name)
        and call.func.value.id == "ta"
        and call.func.attr == "sma"
    ]
    assert len(sma_calls) == 2
    assert all(
        isinstance(call.args[0], ast.Name) and call.args[0].id == "close" for call in sma_calls
    )
    assert {call.args[1].value for call in sma_calls} == {2, 3}
    assert not any(
        isinstance(node, ast.Attribute) and node.attr == "lookahead_on" for node in ast.walk(tree)
    )
    assert not any(
        isinstance(node, ast.Subscript)
        and isinstance(node.slice, ast.UnaryOp)
        and isinstance(node.slice.op, ast.USub)
        for node in ast.walk(tree)
    )


def test_ea_graph_rejects_unsupported_operator_and_unlicensed_crossover() -> None:
    spec = _spec()
    assert spec is not None and require_reviewed_spec(spec) is spec
    with pytest.raises(StrategyIngestError, match="SOURCE_RIGHTS_UNVERIFIED"):
        compile_spec(spec, _catalog(), CodegenTargetV1.EA_GRAPH)

    unsupported_ir = SimpleNamespace(
        operators=(SimpleNamespace(node_id="future_signal", kind="future.signal.v1"),)
    )
    with pytest.raises(StrategyIngestError, match="UNSUPPORTED_TARGET_OPERATOR"):
        _lower_ea_graph(spec, unsupported_ir, None)

    payload = spec.model_dump(mode="python")
    payload["spec_sha256"] = spec.spec_sha256
    from leviathan_core.strategy_ingest.models import ReviewedStrategySpecV1

    forged = ReviewedStrategySpecV1(**payload)
    with pytest.raises(StrategyIngestError, match="REVIEWED_SPEC_NOT_ISSUED"):
        compile_spec(forged, _catalog(), CodegenTargetV1.PYTHON)


def test_artifact_has_canonical_checksum_and_sealed_issuance() -> None:
    spec = _spec()
    assert spec is not None
    artifact = compile_spec(spec, _catalog(), CodegenTargetV1.PYTHON)
    assert artifact.calculate_sha256() == artifact.canonical_sha256
    assert verify(artifact, "strategy.codegen")
    with pytest.raises(SealError):
        CodeArtifactV1.model_construct()


def test_ea_graph_export_requires_exact_issued_strategy_graph() -> None:
    spec = _spec()
    assert spec is not None
    artifact = compile_spec(
        spec,
        _catalog(),
        CodegenTargetV1.EA_GRAPH,
        verified_license=_license_for_spec(spec),
    )
    graph = artifact.ea_graph
    assert graph is not None and graph.declared_risk_parameters

    caller_built = GraphV1.model_validate(graph.model_dump(mode="python"))
    with pytest.raises(SourceExportError) as caught:
        _export_graph(caller_built)
    assert caught.value.code == "SOURCE_PROVENANCE"
    assert str(caught.value) == "SOURCE_PROVENANCE:graph"

    stripped = graph.model_copy(update={"declared_risk_parameters": ()})
    with pytest.raises(SourceExportError) as caught:
        _export_graph(stripped)
    assert caught.value.code == "SOURCE_PROVENANCE"

    copied = graph.model_copy()
    with pytest.raises(SourceExportError) as caught:
        _export_graph(copied)
    assert caught.value.code == "SOURCE_PROVENANCE"

    object.__setattr__(graph, "declared_risk_parameters", ())
    with pytest.raises(SourceExportError) as caught:
        _export_graph(graph)
    assert caught.value.code == "SOURCE_PROVENANCE"


@pytest.mark.parametrize(
    "mismatch",
    [
        {"license_reference_id": "different-license"},
        {"action_id": "different-action"},
        {"reviewer_id": "different-reviewer"},
    ],
)
def test_ea_graph_license_token_binds_final_review_identity(mismatch: dict[str, str]) -> None:
    source_spec = _spec()
    target_spec = _spec(**mismatch)
    assert source_spec is not None and target_spec is not None
    assert source_spec.source.byte_sha256 == target_spec.source.byte_sha256
    token = _license_for_spec(source_spec)
    with pytest.raises(StrategyIngestError) as caught:
        compile_spec(
            target_spec,
            _catalog(),
            CodegenTargetV1.EA_GRAPH,
            verified_license=token,
        )
    assert caught.value.code == "SOURCE_RIGHTS_UNVERIFIED"
    assert str(caught.value) == "SOURCE_RIGHTS_UNVERIFIED"
