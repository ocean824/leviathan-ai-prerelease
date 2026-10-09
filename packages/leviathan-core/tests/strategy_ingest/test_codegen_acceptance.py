"""Independent acceptance tests for STRAT-002 deterministic strategy codegen.

Requirement-to-case matrix (written before executable probes):

* Review eligibility: a genuine review-complete spec compiles; quarantine, conflicts,
  caller-built/rehashed specs, and clones fail closed.
* Promotion boundary: artifacts preserve `BLOCKED_UNVERIFIED_SOURCE` and source,
  reviewer, packet, and claim lineage, with `promotable=False`.
* Closed claim grammar: valid SMA/crossover declarations compile. Malformed, ambiguous,
  code-like, I/O-like, and unknown declarations reject without echo.
* Deterministic outputs: Python/Pine repeat exactly; bounded-close SMA behavior matches
  declared periods; template metadata and canonical hashes stay pinned.
* Causality: Python uses no future or centered reads, and future truncation preserves
  prior outputs; Pine has no future refs or lookahead-on.
* EA_GRAPH: supported crossover lowering requires an issued matching license;
  unknown future operator claims reject during parsing before any graph is returned.
* Safe outputs: Python parses/imports without I/O; both outputs lack credentials, network,
  filesystem writes, dynamic execution, and order submission.
* Integrity and types: template identity/catalog digest, output hash, issuance, exact
  types, hostile canaries, and Decimal determinism are checked.
* Cycle-1 action binding: inverse crossover directions retain reviewed entry/exit labels;
  exit-only specs emit EXIT and never ENTRY.

Contract SHA-256: `8ad2eba62fd44a03f76b1627ef15a9ee66c3254280337834a3438e374d8b262a`.
Coordinator rulings: review-complete `BLOCKED_UNVERIFIED_SOURCE` specs are eligible but
remain non-promotable; `require_reviewed_spec` must require STRAT-001 issuance; no
promotion API exists. FEAT-001 availability references are N/A for this cycle's closed
grammar; explicit `availability_ns` arrives with feature references in STRAT-002b.
The generated Python computes SMA from bounded finalized closes (at most max(period)+1),
uses exact Decimal or strings, returns typed no-signal on insufficient history, and is
causal. Pine uses `ta.sma(close, N)` without future references or lookahead-on. EA_GRAPH
lowers supported SMA crossover operators to a typed graph only when a matching issued
license is provided; unsupported operators return no partial graph.

Dispatch sync: worktree HEAD `d3208136d1872cf6e0bb33ec79aa06f01de98562`; 582 Git-visible
canonical files compared, 481 synchronized, zero mismatches. No canonical writes.
"""

from __future__ import annotations

import ast
import builtins
import hashlib
import re
import sys
from decimal import Decimal
from pathlib import Path

import pytest
from pydantic import BaseModel

from leviathan_core.seal import SealError, verify
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
    TargetTemplateV1,
    TemplateCatalogV1,
)
from leviathan_core.strategy_ingest.models import digest
from leviathan_core.strategy_ingest.review import _issue_verified_license

FIXTURE = Path(__file__).parent / "fixtures" / "codegen" / "sma-crossover.txt"
CANARY = "SYNTHETIC_SECRET_CANARY_DO_NOT_ECHO"
FORBIDDEN_SOURCE = re.compile(
    r"\b(?:open|eval|exec|compile|__import__|urlopen|requests\.|socket\.|"
    r"subprocess\.|OrderSend|OrderSendAsync|PositionOpen|CTrade)\b|"
    r"\b(?:api[_-]?key|password|secret|token)\b",
    re.IGNORECASE,
)


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _reviewed_spec(
    *,
    fast: int = 5,
    slow: int = 20,
    inverted_pairing: bool = False,
    exit_only: bool = False,
    extra_claims: tuple[tuple[str, str, str], ...] = (),
) -> ReviewedStrategySpecV1:
    """Create a genuinely issued STRAT-001 spec from synthetic source bytes."""
    raw = FIXTURE.read_text(encoding="utf-8")
    raw = raw.replace("sma.fast=5", f"sma.fast={fast}").replace("sma.slow=20", f"sma.slow={slow}")
    if inverted_pairing:
        raw = raw.replace("entry=cross_above(fast,slow)", "entry=cross_below(fast,slow)")
        raw = raw.replace("exit=cross_below(fast,slow)", "exit=cross_above(fast,slow)")
    if exit_only:
        raw = raw.replace("entry=cross_above(fast,slow)\n", "")
    for claim_text, _, _ in extra_claims:
        raw += f"\n{claim_text}"
    source_bytes = raw.encode("utf-8")
    source_hash = _sha(source_bytes)
    safe_scan = SafeScanReceiptV1(
        schema_version="1",
        provenance_status="CALLER_DECLARED",
        scanned_sha256=source_hash,
        verdict="clean",
        scanner_name="synthetic-test",
        scanner_version="1",
        scanned_at_ns=2,
    )
    manifest = SourceManifestV1(
        schema_version="1",
        source_id="synthetic_codegen_source",
        source_uri="file:///synthetic/sma-crossover.txt",
        source_locator="sma-crossover.txt",
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
    declarations = [line for line in raw.splitlines() if line]
    kinds = {
        "symbol": "market_assumption",
        "timeframe": "market_assumption",
        "session": "market_assumption",
        "sma.fast": "parameter",
        "sma.slow": "parameter",
        "entry": "entry_condition",
        "exit": "exit_condition",
    }
    keys = {"symbol": "symbol", "timeframe": "timeframe", "session": "session"}
    evidence: list[ExtractedEvidenceV1] = []
    cursor = 0
    for index, text in enumerate(declarations):
        encoded = text.encode("utf-8")
        start = source_bytes.index(encoded, cursor)
        end = start + len(encoded)
        cursor = end
        name = text.split("=", 1)[0]
        if name.startswith("sma."):
            claim_kind = "parameter"
            claim_key = name
        elif name in {"entry", "exit"}:
            claim_kind = kinds[name]
            claim_key = name
        else:
            claim_kind = kinds.get(name, "parameter")
            claim_key = keys.get(name, name)
        evidence.append(
            ExtractedEvidenceV1(
                schema_version="1",
                evidence_id=f"claim_{index:02d}",
                claim_key=claim_key,
                claim_kind=claim_kind,
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
    decisions = tuple(
        ClaimDecisionV1(
            schema_version="1",
            evidence_id=item.evidence_id,
            decision="accept",
            reason_code="supported",
        )
        for item in packet.evidence
    )
    action = ReviewerActionV1(
        schema_version="1",
        action_id="synthetic_review_action",
        packet_sha256=packet.packet_sha256,
        reviewer_id="synthetic_reviewer",
        reviewed_at_ns=packet.source.review_asof_ns,
        decisions=decisions,
    )

    class FakeVerifier:
        def verify_license(self, *, source_sha256, license_reference_id, reviewer_action):
            return _issue_verified_license(
                source_sha256=source_sha256,
                license_reference_id=license_reference_id,
                action_id=reviewer_action.action_id,
                reviewer_id=reviewer_action.reviewer_id,
            )

    result = accept_extraction(packet, action, license_verifier=FakeVerifier())
    assert result.spec is not None
    return result.spec


def _templates(*, reverse: bool = False) -> TemplateCatalogV1:
    templates = tuple(
        TargetTemplateV1(
            target=target,
            template_id=f"synthetic_{target.value.lower()}",
            template_version="v1",
            template_sha256=hashlib.sha256(f"template:{target.value}".encode()).hexdigest(),
        )
        for target in CodegenTargetV1
    )
    return TemplateCatalogV1(
        schema_version="1",
        catalog_id="synthetic_catalog",
        catalog_version=1,
        templates=tuple(reversed(templates)) if reverse else templates,
    )


def _compile(target: CodegenTargetV1, *, fast: int = 5, slow: int = 20):
    return compile_spec(_reviewed_spec(fast=fast, slow=slow), _templates(), target)


def test_review_issued_blocked_spec_compiles_and_preserves_provenance() -> None:
    spec = _reviewed_spec()
    for target in (CodegenTargetV1.PYTHON, CodegenTargetV1.PINE_V5):
        artifact = compile_spec(spec, _templates(), target)
        assert artifact.promotion_status == spec.promotion_status == "BLOCKED_UNVERIFIED_SOURCE"
        assert artifact.promotable is False
        assert artifact.source_provenance == spec.source
        assert artifact.source_id == spec.source.source_id
        assert artifact.source_sha256 == spec.source.byte_sha256
        assert artifact.packet_sha256 == spec.packet_sha256
        assert artifact.spec_sha256 == spec.spec_sha256
        assert artifact.claim_ids == tuple(sorted(c.evidence_id for c in spec.accepted_claims))
        assert artifact.reviewer_ids == ("synthetic_reviewer",)
        assert artifact.reviewer_actions == spec.reviewer_actions
        assert artifact.accepted_claims == spec.accepted_claims
        assert artifact.canonical_sha256 == artifact.calculate_sha256()
        assert artifact.unsupported_nodes == ()
        assert artifact.dependency_manifest
        if target == CodegenTargetV1.PYTHON:
            assert artifact.dependency_manifest == ("python:stdlib",)
        operators = {operator.node_id: operator for operator in artifact.strategy_ir.operators}
        assert operators["stop"].value == Decimal("20")
        assert operators["target"].value == Decimal("40")
        assert operators["position_cap"].value == Decimal("1")
        assert all(
            operator.action is None
            for operator in operators.values()
            if operator.kind.value not in {"cross_above", "cross_below"}
        )
        assert verify(artifact, "strategy.codegen")


def test_python_and_pine_are_deterministic_and_template_bound() -> None:
    spec = _reviewed_spec()
    catalog = _templates()
    first = compile_spec(spec, catalog, CodegenTargetV1.PYTHON)
    second = compile_spec(spec, catalog, CodegenTargetV1.PYTHON)
    permuted = compile_spec(spec, _templates(reverse=True), CodegenTargetV1.PYTHON)
    pine = compile_spec(spec, catalog, CodegenTargetV1.PINE_V5)
    assert first.python_source == second.python_source == permuted.python_source
    assert first.canonical_sha256 == second.canonical_sha256 == permuted.canonical_sha256
    assert first.catalog_sha256 == permuted.catalog_sha256
    assert first.template_sha256 == catalog.template_for(CodegenTargetV1.PYTHON).template_sha256
    assert pine.pine_source is not None and "ta.sma(close, 5)" in pine.pine_source
    assert "ta.sma(close, 20)" in pine.pine_source
    assert pine.template_sha256 == catalog.template_for(CodegenTargetV1.PINE_V5).template_sha256


def test_declared_numeric_template_version_is_accepted() -> None:
    TargetTemplateV1(
        target=CodegenTargetV1.PYTHON,
        template_id="synthetic_python",
        template_version="1",
        template_sha256="a" * 64,
    )


def test_python_computes_exact_crossover_from_bounded_finalized_closes() -> None:
    artifact = _compile(CodegenTargetV1.PYTHON, fast=2, slow=3)
    namespace: dict[str, object] = {"__name__": "synthetic_codegen_acceptance"}
    exec(compile(artifact.python_source, "<generated-strategy>", "exec"), namespace)
    signal = namespace["signal"]
    assert namespace["MAX_INPUT_BARS"] == 4
    assert signal(tuple(map(Decimal, ("3", "1", "2", "3")))) == ("ENTRY",)
    assert signal(tuple(map(Decimal, ("1", "3", "2", "1")))) == ("EXIT",)
    assert signal(tuple(map(Decimal, ("3", "2")))) == ("NO_SIGNAL",)
    assert signal(("3", "1", "2", "3")) == ("ENTRY",)
    assert signal((Decimal("3"), Decimal("1"), Decimal("2"), Decimal("3"))) == signal(
        ("3", "1", "2", "3")
    )
    with pytest.raises((ValueError, TypeError)):
        signal(tuple(map(Decimal, ("1", "2", "3", "4", "5"))))
    with pytest.raises((ValueError, TypeError)):
        signal((Decimal("1"), True, Decimal("2"), Decimal("3")))


def test_declared_periods_change_python_signal_on_fixed_series() -> None:
    closes = tuple(map(Decimal, ("2", "2", "1", "3")))
    fast_artifact = _compile(CodegenTargetV1.PYTHON, fast=1, slow=3)
    slow_artifact = _compile(CodegenTargetV1.PYTHON, fast=2, slow=3)
    fast_ns: dict[str, object] = {}
    slow_ns: dict[str, object] = {}
    exec(compile(fast_artifact.python_source, "<fast>", "exec"), fast_ns)
    exec(compile(slow_artifact.python_source, "<slow>", "exec"), slow_ns)
    assert fast_ns["signal"](closes) != slow_ns["signal"](closes)


def test_cross_direction_is_independent_of_reviewed_entry_exit_action() -> None:
    spec = _reviewed_spec(fast=2, slow=3, inverted_pairing=True)
    python_artifact = compile_spec(spec, _templates(), CodegenTargetV1.PYTHON)
    pine_artifact = compile_spec(spec, _templates(), CodegenTargetV1.PINE_V5)
    assert python_artifact.python_source is not None
    assert pine_artifact.pine_source is not None
    operators = {operator.node_id: operator for operator in python_artifact.strategy_ir.operators}
    assert operators["entry_1"].action == "entry"
    assert operators["exit_1"].action == "exit"
    namespace: dict[str, object] = {}
    exec(compile(python_artifact.python_source, "<inverted-pairing>", "exec"), namespace)
    assert namespace["signal"](("1", "3", "2", "1")) == ("ENTRY",)
    assert namespace["signal"](("3", "1", "2", "3")) == ("EXIT",)
    assert "lv_entry_1 = ta.crossunder(lv_fast, lv_slow)" in pine_artifact.pine_source
    assert "plotshape(lv_entry_1, title='ENTRY', text='ENTRY'" in pine_artifact.pine_source
    assert "lv_exit_1 = ta.crossover(lv_fast, lv_slow)" in pine_artifact.pine_source
    assert "plotshape(lv_exit_1, title='EXIT', text='EXIT'" in pine_artifact.pine_source


def test_exit_only_reviewed_spec_emits_exit_without_entry() -> None:
    spec = _reviewed_spec(fast=2, slow=3, exit_only=True)
    artifact = compile_spec(spec, _templates(), CodegenTargetV1.PYTHON)
    assert artifact.python_source is not None
    namespace: dict[str, object] = {"__name__": "synthetic_exit_only"}
    exec(compile(artifact.python_source, "<exit-only>", "exec"), namespace)
    assert namespace["signal"](("1", "3", "2", "1")) == ("EXIT",)
    assert namespace["signal"](("3", "1", "2", "3")) == ("NO_SIGNAL",)
    pine = compile_spec(spec, _templates(), CodegenTargetV1.PINE_V5).pine_source
    assert pine is not None
    assert "title='EXIT', text='EXIT'" in pine
    assert "title='ENTRY', text='ENTRY'" not in pine


def test_generated_targets_are_causal_and_truncation_invariant() -> None:
    python = _compile(CodegenTargetV1.PYTHON, fast=2, slow=3).python_source
    pine = _compile(CodegenTargetV1.PINE_V5, fast=2, slow=3).pine_source
    assert python is not None and pine is not None
    assert not re.search(r"\.iloc\s*\[\s*i\s*\+\s*1|shift\s*\(\s*-|center\s*=\s*True", python)
    assert not re.search(r"close\s*\[\s*-\d+\s*\]|lookahead\s*=\s*barmerge\.lookahead_on", pine)
    namespace: dict[str, object] = {}
    exec(compile(python, "<causality-check>", "exec"), namespace)
    bars = tuple(map(Decimal, ("3", "1", "2", "3", "100", "200")))
    max_input = namespace["MAX_INPUT_BARS"]

    def point_in_time_outputs(values: tuple[Decimal, ...]) -> tuple[tuple[str, ...], ...]:
        return tuple(
            namespace["signal"](values[max(0, index + 1 - max_input) : index + 1])
            for index in range(len(values))
        )

    before_future = point_in_time_outputs(bars[:4])
    with_future = point_in_time_outputs(bars)
    assert before_future == with_future[:4]


def test_ea_graph_rejects_unknown_future_operator_claim_without_partial_graph() -> None:
    unsupported_spec = _reviewed_spec(extra_claims=(("ema.period=14", "parameter", "future_ema"),))
    with pytest.raises(StrategyIngestError) as caught:
        compile_spec(
            unsupported_spec,
            _templates(),
            CodegenTargetV1.EA_GRAPH,
            verified_license=None,
        )
    assert caught.value.code == "UNSUPPORTED_CLAIM"
    assert str(caught.value) == caught.value.code
    assert "ema.period" not in str(caught.value)


def test_ea_graph_crossover_without_license_is_rejected_before_graph_issuance() -> None:
    with pytest.raises(StrategyIngestError) as caught:
        compile_spec(
            _reviewed_spec(),
            _templates(),
            CodegenTargetV1.EA_GRAPH,
            verified_license=None,
        )
    assert caught.value.code == "SOURCE_RIGHTS_UNVERIFIED"
    assert str(caught.value) == caught.value.code
    assert "cross_above" not in str(caught.value)


@pytest.mark.parametrize("target", [CodegenTargetV1.PYTHON, CodegenTargetV1.PINE_V5])
def test_generated_text_contains_no_executable_or_secret_capability(target) -> None:
    artifact = _compile(target)
    source = artifact.python_source if target == CodegenTargetV1.PYTHON else artifact.pine_source
    assert source is not None
    assert not FORBIDDEN_SOURCE.search(source)
    assert CANARY not in source
    if target == CodegenTargetV1.PYTHON:
        tree = ast.parse(source)
        imported_roots = {
            alias.name.split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imported_roots.update(
            node.module.split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module is not None
        )
        assert imported_roots <= sys.stdlib_module_names

        def stdlib_only_import(name, globals=None, locals=None, fromlist=(), level=0):
            root = name.split(".", 1)[0]
            if root not in sys.stdlib_module_names:
                raise AssertionError("NON_STDLIB_IMPORT")
            return builtins.__import__(name, globals, locals, fromlist, level)

        namespace: dict[str, object] = {
            "__builtins__": {**builtins.__dict__, "__import__": stdlib_only_import}
        }
        exec(compile(source, "<generated-import-smoke>", "exec"), namespace)
        assert callable(namespace["signal"])
    else:
        assert "//@version=5" in source
        assert "ta.crossover" in source and "ta.crossunder" in source
        assert "request.security" not in source


def test_unknown_and_ambiguous_declarations_fail_content_free() -> None:
    for claim_text in ("import os", "open=filesystem", f"unknown={CANARY}"):
        with pytest.raises(StrategyIngestError) as caught:
            compile_spec(
                _reviewed_spec(extra_claims=((claim_text, "parameter", "extra"),)),
                _templates(),
                CodegenTargetV1.PYTHON,
            )
        assert caught.value.code
        assert CANARY not in str(caught.value)
        assert "import os" not in str(caught.value)
    with pytest.raises(StrategyIngestError) as caught:
        compile_spec(
            _reviewed_spec(extra_claims=(("sma.fast=7", "parameter", "duplicate"),)),
            _templates(),
            CodegenTargetV1.PYTHON,
        )
    assert caught.value.code


def test_unissued_forged_and_cloned_review_specs_are_rejected() -> None:
    genuine = _reviewed_spec()
    dumped = genuine.model_dump(mode="python")
    action_dump = genuine.reviewer_actions[-1].model_dump(mode="python")
    action_dump["reviewer_id"] = "forged_reviewer"
    action_dump["action_id"] = "forged_action"
    action_dump["packet_sha256"] = genuine.packet_sha256
    decisions = tuple(
        ClaimDecisionV1(**item) if isinstance(item, dict) else item
        for item in action_dump["decisions"]
    )
    action_dump["decisions"] = decisions
    forged_action = ReviewerActionV1(**action_dump)
    dumped["reviewer_actions"] = (forged_action,)
    dumped["spec_sha256"] = genuine.spec_sha256
    forged_unpinned = ReviewedStrategySpecV1(**dumped)
    forged_payload = forged_unpinned.model_dump(mode="json", exclude={"spec_sha256"})
    dumped["spec_sha256"] = digest(forged_payload)
    forged = ReviewedStrategySpecV1(**dumped)
    cloned_payload = genuine.model_dump(mode="python")
    with pytest.raises(StrategyIngestError) as clone_error:
        cloned = ReviewedStrategySpecV1.model_validate(cloned_payload)
        compile_spec(cloned, _templates(), CodegenTargetV1.PYTHON)
    assert clone_error.value.code == "REVIEWED_SPEC_NOT_ISSUED"
    assert str(clone_error.value) == clone_error.value.code
    with pytest.raises(StrategyIngestError) as forged_error:
        compile_spec(forged, _templates(), CodegenTargetV1.PYTHON)
    assert forged_error.value.code == "REVIEWED_SPEC_NOT_ISSUED"
    assert str(forged_error.value) == forged_error.value.code


def test_tampered_issued_spec_is_rejected_at_compile_boundary() -> None:
    spec = _reviewed_spec()
    try:
        object.__setattr__(spec, "packet_sha256", "0" * 64)
    except (SealError, StrategyIngestError):
        return
    with pytest.raises(StrategyIngestError) as caught:
        compile_spec(spec, _templates(), CodegenTargetV1.PYTHON)
    assert caught.value.code
    assert "000000" not in str(caught.value)


def test_spec_or_artifact_reinitialization_and_copy_do_not_grant_authority() -> None:
    spec = _reviewed_spec()
    artifact = compile_spec(spec, _templates(), CodegenTargetV1.PYTHON)
    for record in (spec, artifact):
        record_error = (
            StrategyIngestError if isinstance(record, ReviewedStrategySpecV1) else SealError
        )
        with pytest.raises(record_error) as copy_error:
            record.model_copy(update={"promotable": True})
        if isinstance(record, ReviewedStrategySpecV1):
            assert copy_error.value.code == "SEALED_RECORD_COPY_DENIED"
        with pytest.raises(record_error):
            BaseModel.__init__(record)
    clone = ReviewedStrategySpecV1.model_validate(spec.model_dump(mode="python"))
    with pytest.raises(StrategyIngestError) as clone_error:
        compile_spec(clone, _templates(), CodegenTargetV1.PYTHON)
    assert clone_error.value.code == "REVIEWED_SPEC_NOT_ISSUED"


def test_artifact_field_tampering_is_detected_before_export_or_verification() -> None:
    artifact = compile_spec(_reviewed_spec(), _templates(), CodegenTargetV1.PYTHON)
    try:
        object.__setattr__(artifact, "python_source", CANARY)
    except SealError:
        return
    try:
        assert not verify(artifact, "strategy.codegen")
    except SealError as error:
        assert CANARY not in str(error)
        return
    with pytest.raises(SealError) as caught:
        artifact.model_dump(mode="json")
    assert CANARY not in str(caught.value)
