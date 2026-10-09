"""Independent acceptance for STRAT-PAPER-PROMOTION-001 (reviewed research to paper).

Written from the Wave 29 contract (section 7) and the coordinator's binding, not from the
writer's tests. Each evidence binding is mutated on its own, the caller's own claim of
identity or digest never grants eligibility, and nothing may touch a broker or the network.
"""

from __future__ import annotations

import dataclasses
import hashlib
import inspect
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from leviathan_core.execution.broker_port_v1 import BrokerEnvironment
from leviathan_core.numeric import canonical_json
from leviathan_core.research import replay_job as replay_module
from leviathan_core.research.replay_job import (
    ReplayArtifacts,
    ReplayJobError,
    canonical_bytes,
    load_verified_replay_result,
    run_replay_job,
    verify_replay_artifacts,
)
from leviathan_core.risk.halt import HaltAuthority
from leviathan_core.schemas.strategy import StrategyGenome
from leviathan_core.strategy_ingest import (
    ClaimDecisionV1,
    ExtractedEvidenceV1,
    ReviewedStrategySpecV1,
    ReviewerActionV1,
    ReviewResultV1,
    SafeScanReceiptV1,
    SourceManifestV1,
    SourceSpanV1,
    accept_extraction,
    register_source,
)
from leviathan_core.strategy_ingest import paper_promotion as promotion
from leviathan_core.strategy_ingest.paper_promotion import (
    PaperPromotionError,
    PaperPromotionResultV1,
    PromotionStrategyIdentityV1,
    assess_paper_eligibility,
    execution_inputs_sha256,
    require_paper_promotion_result,
    strategy_content_sha256,
)
from leviathan_core.strategy_ingest.review import _issue_verified_license

FIXTURE_DIR = Path(__file__).parents[1] / "fixtures" / "replay_job"
FIXTURE = FIXTURE_DIR / "v1-nq.json"
RISK_LOCK = FIXTURE_DIR / "risk_lock.yaml"
RESULT_GOLDEN = FIXTURE_DIR / "v1-nq.result.canonical.golden.json"
LOCK_SHA = hashlib.sha256(RISK_LOCK.read_bytes()).hexdigest()
CANARY = "SYNTHETIC_PROMOTION_CANARY_DO_NOT_ECHO"
REASON_CODES = {
    "ELIGIBLE", "LIVE_ENVIRONMENT", "HALT_ACTIVE", "REVIEW_UNRESOLVED", "REVIEW_IDENTITY_UNBOUND",
    "STRATEGY_IDENTITY_MISMATCH", "REPLAY_INCOMPLETE", "REPLAY_FAILED", "RISK_POLICY_UNBOUND",
    "RISK_POLICY_MISMATCH",
}
FORBIDDEN_FIELDS = re.compile(
    r"activat|order|broker|submit|profit|pnl|sharpe|return|win_rate|account|enable|"
    r"risk_policy_(?:change|update|mutat)|set_policy",
    re.IGNORECASE,
)


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _ns(timestamp: str) -> int:
    moment = datetime.fromisoformat(timestamp.replace("Z", "+00:00")).astimezone(UTC)
    return (moment - datetime(1970, 1, 1, tzinfo=UTC)) // timedelta(microseconds=1) * 1000


def _manifest(**changes: Any) -> dict[str, Any]:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    for dotted, value in changes.items():
        target = data
        *path, last = dotted.split("__")
        for key in path:
            target = target[key]
        target[last] = value
    return data


def _run(tmp_path: Path, name: str = "run", **changes: Any) -> ReplayArtifacts:
    manifest = tmp_path / f"{name}.json"
    manifest.write_text(json.dumps(_manifest(**changes)), encoding="utf-8")
    return run_replay_job(manifest, RISK_LOCK, tmp_path / name)


def _identity_fields(**changes: str) -> dict[str, str]:
    genome = _manifest()["strategy"]
    fields = {
        "strategy_ref": genome["strategy_ref"],
        "strategy_id": genome["genome"]["strategy_id"],
        "strategy_version": genome["strategy_version"],
    }
    fields.update(changes)
    return fields


def _identity(**changes: str) -> PromotionStrategyIdentityV1:
    return PromotionStrategyIdentityV1(**_identity_fields(**changes))


# The legacy label-only claim is superseded by CL-STRAT-IDENTITY-CLAIM: the reviewed claim now
# binds the label triple to the genome content digest and the dataset lineage.
CONTENT_CLAIM_KEY = "strategy_content_identity_v1"


def _claim_text(fields: dict[str, str], content_changes: dict[str, Any] | None = None) -> str:
    data = _manifest(**(content_changes or {}))
    genome = StrategyGenome.model_validate(data["strategy"]["genome"])
    return canonical_json({
        "schema_version": "strat.strategy-content-claim/1",
        "strategy_ref": fields["strategy_ref"], "strategy_id": fields["strategy_id"],
        "strategy_version": fields["strategy_version"],
        "strategy_content_sha256": strategy_content_sha256(genome),
        "dataset_id": data["dataset"]["dataset_id"],
        "dataset_version": data["dataset"]["dataset_version"],
        "bars_sha256": data["dataset"]["bars_sha256"],
        "execution_inputs_sha256": execution_inputs_sha256(
            replay_module.ReplayRunSpec.model_validate(data)
        ),
    }).decode("utf-8")


def _review(
    *,
    claim_fields: dict[str, str] | None = None,
    claim_key: str = CONTENT_CLAIM_KEY,
    include_identity: bool = True,
    accept_identity: bool = True,
    accept_logic: bool = True,
    content_changes: dict[str, Any] | None = None,
) -> ReviewResultV1:
    """A genuinely issued STRAT-001 review result from synthetic source bytes."""
    fields = claim_fields if claim_fields is not None else _identity_fields()
    lines = [
        ("symbol", "market_assumption", "symbol=NQ"),
        ("entry", "entry_condition", "entry=cross_above(fast,slow)"),
        ("exit", "exit_condition", "exit=cross_below(fast,slow)"),
    ]
    if include_identity:
        kind = CONTENT_CLAIM_KEY if claim_key == CONTENT_CLAIM_KEY else "parameter"
        lines.append((claim_key, kind, _claim_text(fields, content_changes)))
    source_bytes = "\n".join(text for _, _, text in lines).encode("utf-8")
    source_hash = _sha(source_bytes)
    manifest = SourceManifestV1(
        schema_version="1", source_id="synthetic_promotion_source",
        source_uri="file:///synthetic/promotion.txt", source_locator="promotion.txt",
        source_bytes=source_bytes, byte_sha256=source_hash, media_type="text/plain",
        license_status="reuse_permitted", license_reference_id="synthetic_license_record",
        collection_method="provided_upload", entitlement_status="authorized",
        entitlement_provenance_status="CALLER_DECLARED", drm_status="clear",
        safe_scan=SafeScanReceiptV1(
            schema_version="1", provenance_status="CALLER_DECLARED", scanned_sha256=source_hash,
            verdict="clean", scanner_name="synthetic-test", scanner_version="1", scanned_at_ns=2,
        ),
        parser_version="synthetic-v1", transcriber_version=None, acquired_ns=1, available_ns=2,
        review_asof_ns=3,
    )
    evidence: list[ExtractedEvidenceV1] = []
    cursor = 0
    for index, (key, kind, text) in enumerate(lines):
        encoded = text.encode("utf-8")
        start = source_bytes.index(encoded, cursor)
        cursor = start + len(encoded)
        evidence.append(ExtractedEvidenceV1(
            schema_version="1", evidence_id=f"claim_{index:02d}", claim_key=key,
            claim_kind=kind, claim_text=text, confidence=Decimal("0.99"),
            source_sha256=source_hash,
            span=SourceSpanV1(
                schema_version="1", byte_start=start, byte_end=cursor,
                span_sha256=_sha(source_bytes[start:cursor]), page_start=None, page_end=None,
                time_start_ms=None, time_end_ms=None,
            ),
            derived_from=(), text_ref=None, chunk_ref=None, embedding_ref=None, tags=(),
        ))
    packet = register_source(manifest, tuple(evidence))

    def decide(item: ExtractedEvidenceV1) -> ClaimDecisionV1:
        logic = item.claim_kind in {"entry_condition", "exit_condition"}
        claim = _claim_text(fields, content_changes)
        identity = item.claim_text == claim and item.claim_key == claim_key
        keep = (accept_logic if logic else True) and (accept_identity if identity else True)
        return ClaimDecisionV1(
            schema_version="1", evidence_id=item.evidence_id,
            decision="accept" if keep else "reject",
            reason_code="supported" if keep else "unsupported",
        )

    action = ReviewerActionV1(
        schema_version="1", action_id="synthetic_review_action", packet_sha256=packet.packet_sha256,
        reviewer_id="synthetic_reviewer", reviewed_at_ns=packet.source.review_asof_ns,
        decisions=tuple(decide(item) for item in packet.evidence),
    )

    class Verifier:
        def verify_license(self, *, source_sha256, license_reference_id, reviewer_action):
            return _issue_verified_license(
                source_sha256=source_sha256, license_reference_id=license_reference_id,
                action_id=reviewer_action.action_id, reviewer_id=reviewer_action.reviewer_id,
            )

    return accept_extraction(packet, action, license_verifier=Verifier())


class _Port:
    def __init__(self, value: object = LOCK_SHA, lock_path: object = RISK_LOCK) -> None:
        self.value = value
        self.lock_path = lock_path
        self.calls = 0

    def current_policy_sha256(self) -> object:
        self.calls += 1
        if isinstance(self.value, Exception):
            raise self.value
        return self.value

    def current_policy_lock_path(self) -> object:
        if isinstance(self.lock_path, Exception):
            raise self.lock_path
        return self.lock_path


def _alternate_port(directory: Path) -> _Port:
    """A port whose digest and lock file agree with each other but not with the replay's lock."""
    alternate = directory / "alternate-risk-lock.yaml"
    alternate.write_bytes(RISK_LOCK.read_bytes() + b"\n# alternate policy\n")
    return _Port(_sha(alternate.read_bytes()), lock_path=alternate)


def _assess(
    verified: Any, *, review: ReviewResultV1 | None = None,
    identity: PromotionStrategyIdentityV1 | None = None,
    environment: BrokerEnvironment = BrokerEnvironment.PAPER,
    halt: HaltAuthority | None = None, port: object | None = None,
) -> PaperPromotionResultV1:
    return assess_paper_eligibility(
        strategy_identity=identity if identity is not None else _identity(),
        review=review if review is not None else _review(),
        replay=verified, environment=environment,
        halt_authority=halt if halt is not None else HaltAuthority(),
        risk_policy_digest_port=port if port is not None else _Port(),
    )


def _verified(tmp_path: Path, name: str = "run", **changes: Any) -> Any:
    return verify_replay_artifacts(_run(tmp_path, name, **changes))


@pytest.fixture(scope="module")
def baseline(tmp_path_factory: pytest.TempPathFactory) -> ReplayArtifacts:
    root = tmp_path_factory.mktemp("promotion-baseline")
    return _run(root)


@pytest.fixture
def verified(baseline: ReplayArtifacts) -> Any:
    return verify_replay_artifacts(baseline)


# Results returned before any replay file is read must not claim file verification.
EARLY_REASONS = {
    "LIVE_ENVIRONMENT", "HALT_ACTIVE",
    "REPLAY_INCOMPLETE",  # a missing replay was never verified
}


def _assert_not_eligible(result: PaperPromotionResultV1, code: str) -> None:
    assert result.status == "NOT_ELIGIBLE"
    assert result.reason_code == code
    if code in EARLY_REASONS:
        assert result.provenance == "C102_NOT_VERIFIED"
    elif code in {"REVIEW_UNRESOLVED", "REVIEW_IDENTITY_UNBOUND"}:
        # The contract does not say whether a review failure that follows a verified replay is
        # "not verified" or "rehashed"; it must never claim reproduction.
        assert result.provenance in {"C102_NOT_VERIFIED", "C102_COMPLETE_REHASHED"}
    else:
        assert result.provenance == "C102_COMPLETE_REHASHED"
    assert require_paper_promotion_result(result) is result


def _never_eligible(action: Any) -> None:
    try:
        outcome = action()
    except (PaperPromotionError, ReplayJobError, TypeError, ValueError):
        return
    assert outcome.status != "ELIGIBLE"


# --------------------------------------------------------------------------- happy path


def test_exact_bindings_give_an_explainable_advisory_eligibility(verified: Any) -> None:
    port = _Port()
    result = _assess(verified, port=port)
    assert (result.status, result.reason_code) == ("ELIGIBLE", "ELIGIBLE")
    assert result.provenance == "REPRODUCED"
    assert port.calls >= 1
    assert require_paper_promotion_result(result) is result
    assert _assess(verified).model_dump_json() == _assess(verified).model_dump_json()


def test_the_verified_replay_carries_typed_scalar_lineage_not_nested_manifests(
    verified: Any,
) -> None:
    fields = set(type(verified).model_fields)
    assert not {"input_spec", "result_payload"} & fields
    manifest = _manifest()
    expected = {
        "strategy_ref": manifest["strategy"]["strategy_ref"],
        "strategy_id": manifest["strategy"]["genome"]["strategy_id"],
        "strategy_version": manifest["strategy"]["strategy_version"],
        "dataset_id": manifest["dataset"]["dataset_id"],
        "dataset_version": manifest["dataset"]["dataset_version"],
        "bars_sha256": manifest["dataset"]["bars_sha256"],
        "verified_lock_sha256": LOCK_SHA,
        "result_status": "completed",
        "status": "COMPLETE",
        "provenance": "C102_COMPLETE_REHASHED",
    }
    for name, value in expected.items():
        assert getattr(verified, name) == value, name
    for name in ("truth_provider", "truth_status", "truth_sha256"):
        assert name in fields
    # The bar window is sealed from the re-hashed bars file during verification.
    bars = manifest["dataset"]["bars"]
    assert verified.first_bar_ns == _ns(bars[0]["timestamp"])
    assert verified.last_bar_ns == _ns(bars[-1]["timestamp"])
    assert verified.first_bar_ns <= verified.last_bar_ns
    pairs = [verified.artifact_sha256]
    assert len(pairs[0]) == 6
    assert list(pairs[0]) == sorted(pairs[0])
    assert all(re.fullmatch(r"[0-9a-f]{64}", digest) for _, digest in pairs[0])


def test_reason_vocabulary_is_closed_and_contains_no_action_or_claim_fields(verified: Any) -> None:
    result = _assess(verified)
    assert result.reason_code in REASON_CODES
    assert not [name for name in type(result).model_fields if FORBIDDEN_FIELDS.search(name)]
    dumped = result.model_dump_json()
    assert not re.search(r"profit|pnl|sharpe|activate|place_order|cancel", dumped, re.IGNORECASE)


def test_the_public_function_is_keyword_only_with_the_frozen_inputs() -> None:
    parameters = inspect.signature(assess_paper_eligibility).parameters
    assert list(parameters) == [
        "strategy_identity", "review", "replay", "environment", "halt_authority",
        "risk_policy_digest_port",
    ]
    assert all(p.kind is inspect.Parameter.KEYWORD_ONLY for p in parameters.values())
    with pytest.raises(TypeError):
        assess_paper_eligibility(_identity())  # type: ignore[call-arg]


# ------------------------------------------------------- one binding mutated at a time


def test_live_environment_is_rejected_and_paper_is_not(verified: Any) -> None:
    _assert_not_eligible(_assess(verified, environment=BrokerEnvironment.LIVE), "LIVE_ENVIRONMENT")
    assert _assess(verified, environment=BrokerEnvironment.PAPER).status == "ELIGIBLE"
    for bogus in ("live", "LIVE", "paper", None, 1):
        _never_eligible(lambda bogus=bogus: _assess(verified, environment=bogus))  # type: ignore[arg-type]


def test_an_active_halt_blocks(verified: Any) -> None:
    halted = HaltAuthority()
    halted.engage("operator_hold")
    _assert_not_eligible(_assess(verified, halt=halted), "HALT_ACTIVE")
    cleared = HaltAuthority()
    assert _assess(verified, halt=cleared).status == "ELIGIBLE"


def test_a_halt_read_fault_fails_closed(verified: Any) -> None:
    class Faulty(HaltAuthority):
        @property
        def halted(self) -> bool:  # type: ignore[override]
            raise RuntimeError(CANARY)

    _never_eligible(lambda: _assess(verified, halt=Faulty()))


def test_a_review_without_an_accepted_strategy_is_unresolved(verified: Any) -> None:
    review = _review(accept_logic=False)
    assert review.spec is None
    _assert_not_eligible(_assess(verified, review=review), "REVIEW_UNRESOLVED")


def test_the_identity_claim_must_be_accepted_exact_and_under_its_key(verified: Any) -> None:
    unbound = "REVIEW_IDENTITY_UNBOUND"
    cases = {
        "no identity claim": _review(include_identity=False),
        "claim rejected by the reviewer": _review(accept_identity=False),
        "claim under another key": _review(claim_key="strategy_label"),
        "claim for another strategy_id": _review(
            claim_fields=_identity_fields(strategy_id="another-strategy-v9")),
        "claim for another version": _review(claim_fields=_identity_fields(strategy_version="9")),
        "claim for another ref": _review(
            claim_fields=_identity_fields(strategy_ref="static_genome/9")),
    }
    for label, review in cases.items():
        assert _assess(verified, review=review).reason_code == unbound, label


def test_a_caller_supplied_identity_alone_never_grants_eligibility(verified: Any) -> None:
    # The caller's identity equals the replay's, but nothing reviewed binds it.
    result = _assess(verified, review=_review(include_identity=False), identity=_identity())
    assert result.status == "NOT_ELIGIBLE"
    assert result.reason_code == "REVIEW_IDENTITY_UNBOUND"


@pytest.mark.parametrize("field,value", [
    ("strategy_id", "another-strategy-v9"), ("strategy_version", "2"),
    ("strategy_ref", "static_genome/2"),
])
def test_each_identity_field_must_equal_the_replay_independently(
    verified: Any, field: str, value: str,
) -> None:
    changed = _identity_fields(**{field: value})
    review = _review(claim_fields=changed)  # the review binds exactly what the caller passes
    result = _assess(verified, review=review, identity=PromotionStrategyIdentityV1(**changed))
    _assert_not_eligible(result, "STRATEGY_IDENTITY_MISMATCH")


def test_a_replay_of_another_strategy_is_a_mismatch(tmp_path: Path) -> None:
    other = _verified(tmp_path, "other", strategy__genome__strategy_id="another-strategy-v9")
    reviewed = _review(content_changes={"strategy__genome__strategy_id": "another-strategy-v9"})
    _assert_not_eligible(_assess(other, review=reviewed), "STRATEGY_IDENTITY_MISMATCH")


def test_a_replay_that_ran_but_did_not_complete_its_route_is_not_eligible(tmp_path: Path) -> None:
    blocked = _verified(tmp_path, "blocked", risk__initial_halts=["operator_hold"])
    _assert_not_eligible(_assess(blocked), "REPLAY_FAILED")


def test_the_risk_policy_digest_comes_only_from_the_trusted_port(
    verified: Any, tmp_path: Path,
) -> None:
    _assert_not_eligible(_assess(verified, port=_Port(None)), "RISK_POLICY_UNBOUND")
    # A digest that is not the hash of the port's own lock bytes is unbound, never trusted.
    _assert_not_eligible(_assess(verified, port=_Port("0" * 64)), "RISK_POLICY_UNBOUND")
    _assert_not_eligible(_assess(verified, port=_Port(LOCK_SHA[:-1] + "0")), "RISK_POLICY_UNBOUND")
    # A consistent port for another policy is a mismatch with the replay's recorded lock.
    _assert_not_eligible(_assess(verified, port=_alternate_port(tmp_path)), "RISK_POLICY_MISMATCH")
    assert _assess(verified, port=_Port(LOCK_SHA)).status == "ELIGIBLE"
    for bad in (LOCK_SHA.upper(), 12345, "", CANARY, b"bytes", [LOCK_SHA]):
        _never_eligible(lambda bad=bad: _assess(verified, port=_Port(bad)))
    _never_eligible(lambda: _assess(verified, port=_Port(RuntimeError(CANARY))))
    # No parameter lets a caller supply a digest of their own.
    assert "digest" not in " ".join(inspect.signature(assess_paper_eligibility).parameters
                                    ).replace("risk_policy_digest_port", "")


def test_a_missing_port_or_wrong_input_types_raise_a_content_free_error(verified: Any) -> None:
    bad_inputs: list[dict[str, object]] = [
        {"strategy_identity": _identity_fields()},
        {"review": None},
        {"review": "reviewed"},
        {"replay": None},
        {"halt_authority": object()},
        {"risk_policy_digest_port": None},
        {"risk_policy_digest_port": object()},
    ]
    base: dict[str, Any] = dict(
        strategy_identity=_identity(), review=_review(), replay=verified,
        environment=BrokerEnvironment.PAPER, halt_authority=HaltAuthority(),
        risk_policy_digest_port=_Port(),
    )
    for override in bad_inputs:
        _never_eligible(lambda override=override: assess_paper_eligibility(**{**base, **override}))
    with pytest.raises(PaperPromotionError) as raised:
        assess_paper_eligibility(**{**base, "risk_policy_digest_port": object()})
    assert raised.value.code == "INVALID_INPUT"
    assert CANARY not in f"{raised.value!r} {raised.value}"


# ------------------------------------------------------------ the C-102 proof itself


def _copy_run(artifacts: ReplayArtifacts, destination: Path) -> ReplayArtifacts:
    shutil.copytree(artifacts.result_path.parent, destination)
    return dataclasses.replace(
        artifacts,
        input_path=destination / artifacts.input_path.name,
        result_path=destination / artifacts.result_path.name,
        complete_path=destination / artifacts.complete_path.name,
    )


def test_a_copied_untouched_run_still_verifies(baseline: ReplayArtifacts, tmp_path: Path) -> None:
    copied = _copy_run(baseline, tmp_path / "copy")
    assert _assess(verify_replay_artifacts(copied)).status == "ELIGIBLE"


@pytest.mark.parametrize("victim", ["input", "result", "complete", "audit"])
def test_a_tampered_artifact_file_is_rejected(
    baseline: ReplayArtifacts, tmp_path: Path, victim: str,
) -> None:
    copied = _copy_run(baseline, tmp_path / "tampered")
    target = {
        "input": copied.input_path, "result": copied.result_path, "complete": copied.complete_path,
        "audit": copied.result_path.parent / "risk_audit.jsonl",
    }[victim]
    target.write_bytes(target.read_bytes() + b" ")
    with pytest.raises(ReplayJobError) as raised:
        verify_replay_artifacts(copied)
    assert raised.value.code == "ARTIFACT_INVALID"
    assert CANARY not in f"{raised.value!r}"


@pytest.mark.parametrize("victim", ["input", "result", "complete", "audit"])
def test_a_missing_artifact_file_is_rejected(
    baseline: ReplayArtifacts, tmp_path: Path, victim: str,
) -> None:
    copied = _copy_run(baseline, tmp_path / "missing")
    target = {
        "input": copied.input_path, "result": copied.result_path, "complete": copied.complete_path,
        "audit": copied.result_path.parent / "risk_audit.jsonl",
    }[victim]
    target.unlink()
    with pytest.raises(ReplayJobError):
        verify_replay_artifacts(copied)


def test_an_extra_artifact_file_is_rejected(baseline: ReplayArtifacts, tmp_path: Path) -> None:
    copied = _copy_run(baseline, tmp_path / "extra")
    (copied.result_path.parent / "extra.bin").write_bytes(b"unexpected")
    with pytest.raises(ReplayJobError) as raised:
        verify_replay_artifacts(copied)
    assert raised.value.code == "ARTIFACT_INVALID"


def test_a_run_that_never_completed_cannot_become_proof(tmp_path: Path) -> None:
    with pytest.raises(ReplayJobError):
        _run(tmp_path, "lockmismatch", risk__expected_lock_sha256="0" * 64)
    assert not (tmp_path / "lockmismatch" / "COMPLETE").exists()
    ghost = ReplayArtifacts(
        input_sha256="0" * 64, result_sha256="0" * 64,
        input_path=tmp_path / "nope" / "input.canonical.json",
        result_path=tmp_path / "nope" / "result.canonical.json",
        complete_path=tmp_path / "nope" / "COMPLETE",
    )
    with pytest.raises(ReplayJobError):
        verify_replay_artifacts(ghost)


def _junction(target: Path, link: Path) -> None:
    import _winapi  # stdlib on Windows; no administrator rights needed

    _winapi.CreateJunction(str(target), str(link))


def test_the_loader_round_trips_the_verified_result_and_catches_later_tampering(
    baseline: ReplayArtifacts, tmp_path: Path,
) -> None:
    copied = _copy_run(baseline, tmp_path / "loader")
    verified_copy = verify_replay_artifacts(copied)
    loaded = load_verified_replay_result(verified_copy)
    assert canonical_bytes(loaded) == baseline.result_path.read_bytes()
    copied.result_path.write_bytes(copied.result_path.read_bytes() + b" ")
    with pytest.raises(ReplayJobError) as raised:
        load_verified_replay_result(verified_copy)
    assert raised.value.code == "ARTIFACT_INVALID"


@pytest.mark.skipif(sys.platform != "win32", reason="directory junctions are Windows-only")
def test_a_junction_for_the_artifact_root_is_rejected(
    baseline: ReplayArtifacts, tmp_path: Path,
) -> None:
    real = _copy_run(baseline, tmp_path / "real-run")
    link = tmp_path / "linked-run"
    _junction(real.result_path.parent, link)
    through_link = dataclasses.replace(
        real,
        input_path=link / real.input_path.name,
        result_path=link / real.result_path.name,
        complete_path=link / real.complete_path.name,
    )
    with pytest.raises(ReplayJobError) as raised:
        verify_replay_artifacts(through_link)
    assert raised.value.code == "ARTIFACT_INVALID"
    assert CANARY not in f"{raised.value!r}"


@pytest.mark.skipif(sys.platform != "win32", reason="directory junctions are Windows-only")
@pytest.mark.parametrize("swap", ["same-content", "other-run"])
def test_a_junction_swapped_in_after_verification_is_rejected_on_load(
    baseline: ReplayArtifacts, tmp_path: Path, swap: str,
) -> None:
    copied = _copy_run(baseline, tmp_path / "swapped")
    verified_copy = verify_replay_artifacts(copied)
    run_dir = copied.result_path.parent
    if swap == "same-content":
        moved = tmp_path / "swapped-moved"
        os.rename(run_dir, moved)
        _junction(moved, run_dir)
    else:
        other = _copy_run(_run(tmp_path, "other-source", seed=7), tmp_path / "other-run")
        shutil.rmtree(run_dir)
        _junction(other.result_path.parent, run_dir)
    with pytest.raises(ReplayJobError) as raised:
        load_verified_replay_result(verified_copy)
    assert raised.value.code == "ARTIFACT_INVALID"
    assert CANARY not in f"{raised.value!r}"


def test_a_lying_artifact_record_cannot_pass_verification(
    baseline: ReplayArtifacts, tmp_path: Path,
) -> None:
    copied = _copy_run(baseline, tmp_path / "lie")
    for lie in (
        dataclasses.replace(copied, result_sha256="0" * 64),
        dataclasses.replace(copied, input_sha256="f" * 64),
    ):
        with pytest.raises(ReplayJobError):
            verify_replay_artifacts(lie)


def test_a_forged_or_altered_verified_replay_is_rejected(verified: Any) -> None:
    forged = object.__new__(type(verified))
    for name in getattr(type(verified), "model_fields", {}):
        object.__setattr__(forged, name, getattr(verified, name))
    _never_eligible(lambda: _assess(forged))
    with pytest.raises(PaperPromotionError) as raised:
        _assess(forged)
    assert raised.value.code == "EVIDENCE_NOT_ISSUED"
    with pytest.raises(PaperPromotionError) as constructed:
        _assess(type(verified).model_construct())
    assert constructed.value.code == "EVIDENCE_NOT_ISSUED"
    for not_proof in ("verified", {"status": "COMPLETE"}, object(), 7):
        with pytest.raises(PaperPromotionError):
            _assess(not_proof)


def test_a_missing_replay_is_not_eligible_and_not_claimed_verified() -> None:
    result = _assess(None)
    _assert_not_eligible(result, "REPLAY_INCOMPLETE")
    assert result.provenance == "C102_NOT_VERIFIED"


def test_an_issued_verified_replay_altered_afterwards_is_rejected(
    baseline: ReplayArtifacts,
) -> None:
    altered = verify_replay_artifacts(baseline)
    fields = list(getattr(type(altered), "model_fields", {}))
    assert fields
    for name in fields:
        current = getattr(altered, name)
        if isinstance(current, str):
            object.__setattr__(altered, name, current + "x")
            break
    with pytest.raises(PaperPromotionError) as raised:
        _assess(altered)
    assert raised.value.code == "EVIDENCE_NOT_ISSUED"


def test_an_unissued_review_spec_is_rejected(verified: Any) -> None:
    # The wrapper record carries no authority of its own: the issued packet and spec do.
    # A spec rebuilt from data (so never issued) must not carry an accepted identity claim.
    real = _review()
    assert real.spec is not None
    rebuilt = ReviewedStrategySpecV1(**real.spec.model_dump())
    forged = ReviewResultV1(schema_version="1", packet=real.packet, spec=rebuilt)
    _never_eligible(lambda: _assess(verified, review=forged))
    with pytest.raises(PaperPromotionError) as raised:
        _assess(verified, review=forged)
    assert raised.value.code in {"EVIDENCE_NOT_ISSUED", "INVALID_INPUT"}


# --------------------------------------------------------------------------- precedence


def test_precedence_when_several_bindings_fail_together(tmp_path: Path) -> None:
    halted = HaltAuthority()
    halted.engage("operator_hold")
    blocked = _verified(tmp_path, "prec-blocked", risk__initial_halts=["operator_hold"])
    other = _verified(tmp_path, "prec-other", strategy__genome__strategy_id="another-strategy-v9")
    ok = _verified(tmp_path, "prec-ok")
    unresolved = _review(accept_logic=False)
    unbound = _review(include_identity=False)
    unset = _Port(None)
    # LIVE, then HALT.
    assert _assess(blocked, review=unresolved, halt=halted, port=unset,
                   environment=BrokerEnvironment.LIVE).reason_code == "LIVE_ENVIRONMENT"
    assert _assess(blocked, review=unresolved, halt=halted, port=unset
                   ).reason_code == "HALT_ACTIVE"
    # The replay checks come before review and identity.
    assert _assess(None, review=unresolved, port=unset).reason_code == "REPLAY_INCOMPLETE"
    assert _assess(blocked, review=unresolved, port=unset).reason_code == "REPLAY_FAILED"
    # Then the review and identity group, in order.
    assert _assess(other, review=unresolved, port=unset).reason_code == "REVIEW_UNRESOLVED"
    assert _assess(other, review=unbound, port=unset).reason_code == "REVIEW_IDENTITY_UNBOUND"
    reviewed_other = _review(
        content_changes={"strategy__genome__strategy_id": "another-strategy-v9"}
    )
    assert _assess(other, review=reviewed_other, port=unset
                   ).reason_code == "STRATEGY_IDENTITY_MISMATCH"
    # Then the risk policy, and only then reproduction.
    assert _assess(ok, port=unset).reason_code == "RISK_POLICY_UNBOUND"
    assert _assess(ok, port=_Port("0" * 64)).reason_code == "RISK_POLICY_UNBOUND"
    assert _assess(ok, port=_alternate_port(tmp_path)).reason_code == "RISK_POLICY_MISMATCH"


# ----------------------------------------------------- deterministic reproduction


@pytest.fixture
def runs(monkeypatch: pytest.MonkeyPatch) -> list[tuple[Path, Path, Path, str, str]]:
    """Count every reproduction run, recording what the runner was handed at call time."""
    real = replay_module.run_replay_job
    record: list[tuple[Path, Path, Path, str, str]] = []

    def spy(fixture: Path, risk_lock: Path, output_dir: Path) -> ReplayArtifacts:
        record.append((
            Path(fixture), Path(risk_lock), Path(output_dir),
            _sha(Path(fixture).read_bytes()), _sha(Path(risk_lock).read_bytes()),
        ))
        return real(fixture, risk_lock, output_dir)

    monkeypatch.setattr(replay_module, "run_replay_job", spy)
    monkeypatch.setattr(promotion, "run_replay_job", spy, raising=False)
    return record


@pytest.fixture
def temp_dirs(monkeypatch: pytest.MonkeyPatch) -> list[Path]:
    """Every TemporaryDirectory the assessment creates, so cleanup can be checked."""
    created: list[Path] = []
    real = tempfile.TemporaryDirectory

    class Tracking(real):  # type: ignore[misc, valid-type]
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            created.append(Path(self.name))

    monkeypatch.setattr(tempfile, "TemporaryDirectory", Tracking)
    return created


def test_a_genuine_bundle_is_reproduced_from_private_copies(
    verified: Any, runs: list[Any], temp_dirs: list[Path], baseline: ReplayArtifacts,
) -> None:
    result = _assess(verified)
    assert (result.status, result.reason_code, result.provenance) == (
        "ELIGIBLE", "ELIGIBLE", "REPRODUCED",
    )
    assert len(runs) == 1
    fixture, lock, output, fixture_sha, lock_sha = runs[0]
    # The runner got copies of the lock and the verified input, never the originals.
    assert fixture != baseline.input_path and lock != RISK_LOCK
    assert fixture_sha == verified.input_sha256 and lock_sha == LOCK_SHA
    assert temp_dirs and all(not path.exists() for path in temp_dirs)
    assert not fixture.exists() and not lock.exists() and not output.exists()
    assert require_paper_promotion_result(result) is result


@pytest.mark.parametrize("scenario", [
    "live", "halt", "unresolved_review", "unbound_identity", "identity_mismatch",
    "replay_failed", "replay_missing", "policy_unbound", "policy_mismatch", "lock_unbound",
])
def test_an_already_ineligible_request_never_runs_a_replay(
    tmp_path: Path, runs: list[Any], temp_dirs: list[Path], scenario: str,
) -> None:
    good = _verified(tmp_path, "good")
    halted = HaltAuthority()
    halted.engage("operator_hold")
    kwargs: dict[str, Any] = {}
    subject: Any = good
    if scenario == "live":
        kwargs["environment"] = BrokerEnvironment.LIVE
    elif scenario == "halt":
        kwargs["halt"] = halted
    elif scenario == "unresolved_review":
        kwargs["review"] = _review(accept_logic=False)
    elif scenario == "unbound_identity":
        kwargs["review"] = _review(include_identity=False)
    elif scenario == "identity_mismatch":
        subject = _verified(tmp_path, "other", strategy__genome__strategy_id="another-strategy-v9")
    elif scenario == "replay_failed":
        subject = _verified(tmp_path, "blk", risk__initial_halts=["operator_hold"])
    elif scenario == "replay_missing":
        subject = None
    elif scenario == "policy_unbound":
        kwargs["port"] = _Port(None)
    elif scenario == "policy_mismatch":
        kwargs["port"] = _Port("0" * 64)
    elif scenario == "lock_unbound":
        kwargs["port"] = _Port(lock_path=None)
    result = _assess(subject, **kwargs)
    assert result.status == "NOT_ELIGIBLE" and result.provenance != "REPRODUCED"
    assert runs == []
    assert all(not path.exists() for path in temp_dirs)


def test_a_lock_that_cannot_be_read_or_does_not_match_is_unbound(
    verified: Any, runs: list[Any], tmp_path: Path,
) -> None:
    altered = tmp_path / "altered-lock.yaml"
    altered.write_bytes(RISK_LOCK.read_bytes() + b"\n# changed\n")
    consistent = tmp_path / "consistent-with-port.yaml"
    consistent.write_bytes(altered.read_bytes())
    for lock in (None, altered, tmp_path / "missing.yaml", tmp_path, "not a path"):
        _assert_not_eligible(
            _assess(verified, port=_Port(LOCK_SHA, lock_path=lock)), "RISK_POLICY_UNBOUND"
        )
    _never_eligible(
        lambda: _assess(verified, port=_Port(LOCK_SHA, lock_path=RuntimeError(CANARY)))
    )
    # The file agrees with the port but not with the replay's recorded lock digest.
    outcome = _assess(verified, port=_Port(_sha(consistent.read_bytes()), lock_path=consistent))
    assert outcome.status == "NOT_ELIGIBLE"
    assert outcome.reason_code in {"RISK_POLICY_UNBOUND", "RISK_POLICY_MISMATCH"}
    assert runs == []


def test_swapping_the_lock_or_the_input_after_hashing_does_not_affect_the_run(
    baseline: ReplayArtifacts, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    copied = _copy_run(baseline, tmp_path / "swap-run")
    copied_verified = verify_replay_artifacts(copied)
    lock = tmp_path / "swap-lock.yaml"
    lock.write_bytes(RISK_LOCK.read_bytes())
    real = replay_module.run_replay_job
    calls: list[int] = []

    def swapping(fixture: Path, risk_lock: Path, output_dir: Path) -> ReplayArtifacts:
        calls.append(1)
        lock.write_bytes(b"swapped after the hash")
        copied.input_path.write_bytes(b"swapped after the hash")
        return real(fixture, risk_lock, output_dir)

    monkeypatch.setattr(replay_module, "run_replay_job", swapping)
    monkeypatch.setattr(promotion, "run_replay_job", swapping, raising=False)
    result = _assess(copied_verified, port=_Port(LOCK_SHA, lock_path=lock))
    assert calls == [1]
    assert (result.status, result.provenance) == ("ELIGIBLE", "REPRODUCED")


def _forged_bundle(tmp_path: Path) -> ReplayArtifacts:
    """A blocked run edited to say completed, with every hash and the manifest made consistent."""
    source = _run(tmp_path, "forge-source", risk__initial_halts=["operator_hold"])
    forged = _copy_run(source, tmp_path / "forged-run")
    run_dir = forged.result_path.parent
    raw = forged.result_path.read_bytes()
    assert raw.count(b'"status":"blocked"') == 1
    rewritten = raw.replace(b'"status":"blocked"', b'"status":"completed"')
    forged.result_path.write_bytes(rewritten)
    result_sha = _sha(rewritten)
    diagnostics = run_dir / "diagnostics.json"
    diagnostics_raw = diagnostics.read_bytes()
    assert diagnostics_raw.count(b'"status":"blocked"') == 1
    diagnostics.write_bytes(diagnostics_raw.replace(b'"status":"blocked"', b'"status":"completed"'))
    marker = run_dir / "result.sha256"
    marker.write_bytes(result_sha.encode("ascii") + marker.read_bytes()[64:])
    manifest_text = forged.complete_path.read_bytes().decode("utf-8")
    manifest = json.loads(manifest_text)
    manifest["files"]["result.canonical.json"] = result_sha
    manifest["files"]["diagnostics.json"] = _sha(diagnostics.read_bytes())
    manifest["files"]["result.sha256"] = _sha(marker.read_bytes())
    manifest["result_sha256"] = result_sha
    tail = "\n" if manifest_text.endswith("\n") else ""
    forged.complete_path.write_bytes(
        (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + tail).encode("utf-8")
    )
    return dataclasses.replace(forged, result_sha256=result_sha)


def test_a_hand_rewritten_bundle_is_not_reproduced(
    tmp_path: Path, runs: list[Any], temp_dirs: list[Path],
) -> None:
    forged = _forged_bundle(tmp_path)
    # The rewrite is internally consistent, so the C-102 verifier accepts it: only
    # reproduction can tell it from a genuine run.
    forged_verified = verify_replay_artifacts(forged)
    assert forged_verified.result_status == "completed"
    result = _assess(forged_verified)
    assert (result.status, result.reason_code) == ("NOT_ELIGIBLE", "REPLAY_NOT_REPRODUCED")
    assert result.provenance != "REPRODUCED"
    assert len(runs) == 1
    assert temp_dirs and all(not path.exists() for path in temp_dirs)


def test_the_temp_directory_is_removed_when_the_reproduction_run_fails(
    verified: Any, temp_dirs: list[Path], monkeypatch: pytest.MonkeyPatch,
) -> None:
    def broken(*_args: object, **_kwargs: object) -> ReplayArtifacts:
        raise ReplayJobError("ARTIFACT_INVALID", CANARY)

    monkeypatch.setattr(replay_module, "run_replay_job", broken)
    monkeypatch.setattr(promotion, "run_replay_job", broken, raising=False)
    try:
        outcome = _assess(verified)
    except (PaperPromotionError, ReplayJobError) as raised:
        assert CANARY not in f"{raised!r}"
    else:
        assert outcome.status == "NOT_ELIGIBLE"
        assert outcome.reason_code == "REPLAY_NOT_REPRODUCED"
        assert CANARY not in outcome.model_dump_json()
    assert temp_dirs and all(not path.exists() for path in temp_dirs)


# ------------------------------------------------------------------ the result itself


def test_the_result_is_issued_and_cannot_be_forged_or_altered(verified: Any) -> None:
    result = _assess(verified)
    forged = object.__new__(PaperPromotionResultV1)
    for name in type(result).model_fields:
        object.__setattr__(forged, name, getattr(result, name))
    with pytest.raises(PaperPromotionError) as raised:
        require_paper_promotion_result(forged)
    assert raised.value.code == "RESULT_NOT_ISSUED"
    for value in (None, "ELIGIBLE", {"status": "ELIGIBLE"}, object()):
        with pytest.raises(PaperPromotionError):
            require_paper_promotion_result(value)
    altered = _assess(verified, environment=BrokerEnvironment.LIVE)
    object.__setattr__(altered, "status", "ELIGIBLE")
    object.__setattr__(altered, "reason_code", "ELIGIBLE")
    with pytest.raises(PaperPromotionError):
        require_paper_promotion_result(altered)


def test_a_not_eligible_result_cannot_be_turned_into_an_eligible_one(verified: Any) -> None:
    result = _assess(verified, environment=BrokerEnvironment.LIVE)
    # A copy edited to say ELIGIBLE has no standing: copies are never issued.
    edited = result.model_copy(update={"status": "ELIGIBLE", "reason_code": "ELIGIBLE"})
    with pytest.raises(PaperPromotionError) as raised:
        require_paper_promotion_result(edited)
    assert raised.value.code == "RESULT_NOT_ISSUED"
    assert result.status == "NOT_ELIGIBLE"
    assert require_paper_promotion_result(result) is result


# ------------------------------------------------------- no side effects, no network


def test_assessment_makes_no_network_broker_or_process_call_and_writes_nothing(
    baseline: ReplayArtifacts, monkeypatch: pytest.MonkeyPatch,
) -> None:
    verified = verify_replay_artifacts(baseline)
    review = _review()
    run_dir = baseline.result_path.parent
    before = {p.name: _sha(p.read_bytes()) for p in sorted(run_dir.iterdir())}

    def blocked(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("network or process call during assessment")

    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    monkeypatch.setattr(subprocess, "Popen", blocked)
    for environment in (BrokerEnvironment.PAPER, BrokerEnvironment.LIVE):
        _assess(verified, review=review, environment=environment)
    after = {p.name: _sha(p.read_bytes()) for p in sorted(run_dir.iterdir())}
    assert after == before


def test_the_replay_runner_output_bytes_are_unchanged(baseline: ReplayArtifacts) -> None:
    assert baseline.result_path.read_bytes() == RESULT_GOLDEN.read_bytes()
