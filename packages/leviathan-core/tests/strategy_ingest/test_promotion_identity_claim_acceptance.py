"""Independent acceptance for CL-STRAT-IDENTITY-CLAIM (content-bound reviewed strategy identity).

Written from the Wave 30 contract (section 7) and the coordinator's binding, not from the
writer's tests. The reviewed claim kind binds the strategy label triple to a canonical content
digest of the genome and to the dataset lineage; promotion must compare both against what the
reproduced replay actually contains. A genuine replay of different logic or data under the
reviewed labels, and every label-only, stale, wrong-digest, rejected or altered claim, gives
REVIEW_IDENTITY_UNBOUND. Nothing here grants activation, routing or any approval.
"""

from __future__ import annotations

import dataclasses
import hashlib
import inspect
import json
import re
import shutil
import socket
import subprocess
import tempfile
from decimal import Decimal
from pathlib import Path
from typing import Any, get_args

import pytest

from leviathan_core.execution.broker_port_v1 import BrokerEnvironment
from leviathan_core.numeric import canonical_json
from leviathan_core.research import replay_job as replay_module
from leviathan_core.research.replay_job import (
    ReplayArtifacts,
    ReplayJobError,
    run_replay_job,
    verify_replay_artifacts,
)
from leviathan_core.risk.halt import HaltAuthority
from leviathan_core.schemas.strategy import StrategyGenome
from leviathan_core.strategy_ingest import (
    ClaimDecisionV1,
    ExtractedEvidenceV1,
    ReviewerActionV1,
    ReviewResultV1,
    SafeScanReceiptV1,
    SourceManifestV1,
    SourceSpanV1,
    accept_extraction,
    register_source,
)
from leviathan_core.strategy_ingest import paper_promotion as promotion
from leviathan_core.strategy_ingest.models import ClaimKind, StrategyIngestError
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
from leviathan_core.text.safe_label import is_safe_identifier

FIXTURE_DIR = Path(__file__).parents[1] / "fixtures" / "replay_job"
FIXTURE = FIXTURE_DIR / "v1-nq.json"
RISK_LOCK = FIXTURE_DIR / "risk_lock.yaml"
LOCK_SHA = hashlib.sha256(RISK_LOCK.read_bytes()).hexdigest()
CANARY = "SYNTHETIC_IDENTITY_CLAIM_CANARY_DO_NOT_ECHO"

CLAIM_KEY = "strategy_content_identity_v1"
CLAIM_SCHEMA = "strat.strategy-content-claim/1"
CONTENT_SCHEMA = "strat.strategy-content/1"
CLAIM_FIELDS = (
    "schema_version", "strategy_ref", "strategy_id", "strategy_version",
    "strategy_content_sha256", "dataset_id", "dataset_version", "bars_sha256",
    "execution_inputs_sha256",
)
REASON_CODES = {
    "ELIGIBLE", "LIVE_ENVIRONMENT", "HALT_ACTIVE", "REVIEW_UNRESOLVED", "REVIEW_IDENTITY_UNBOUND",
    "STRATEGY_IDENTITY_MISMATCH", "REPLAY_INCOMPLETE", "REPLAY_FAILED", "RISK_POLICY_UNBOUND",
    "RISK_POLICY_MISMATCH", "REPLAY_NOT_REPRODUCED",
}
UNBOUND = "REVIEW_IDENTITY_UNBOUND"
FORBIDDEN_FIELDS = re.compile(
    r"activat|order|broker|submit|route|routing|profit|pnl|sharpe|return|win_rate|account|enable|"
    r"risk_policy_(?:change|update|mutat)|set_policy|approv",
    re.IGNORECASE,
)


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


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


def _bar_changes() -> dict[str, Any]:
    """Genuinely different bars: one volume changed and the dataset digest recomputed."""
    base = _manifest()
    bars = json.loads(json.dumps(base["dataset"]["bars"]))
    bars[0]["volume"] = "1001"
    dataset = {**base["dataset"], "bars": bars, "bars_sha256": "0" * 64}
    parsed = replay_module.ReplayDataset.model_validate(dataset)
    digest = _sha(replay_module.canonical_bytes(parsed.bars))
    return {"dataset__bars": bars, "dataset__bars_sha256": digest}


def _genome_of(manifest: dict[str, Any]) -> StrategyGenome:
    return StrategyGenome.model_validate(manifest["strategy"]["genome"])


def _independent_content_digest(genome: StrategyGenome) -> str:
    return _sha(canonical_json(
        {"schema_version": CONTENT_SCHEMA, "genome": genome.model_dump(mode="json")}
    ))


def _independent_execution_digest(manifest: dict[str, Any]) -> str:
    """Digest of the decision inputs, fill model, seed and universe, from the replay spec."""
    spec = replay_module.ReplayRunSpec.model_validate(manifest)
    return _sha(canonical_json({
        "decision_inputs": spec.decision_inputs.model_dump(mode="json"),
        "fill_model": spec.fill_model.model_dump(mode="json"),
        "seed": spec.seed,
        "universe_version": spec.dataset.universe_version,
    }))


def _identity_fields(manifest: dict[str, Any] | None = None, **changes: str) -> dict[str, str]:
    strategy = (manifest or _manifest())["strategy"]
    fields = {
        "strategy_ref": strategy["strategy_ref"],
        "strategy_id": strategy["genome"]["strategy_id"],
        "strategy_version": strategy["strategy_version"],
    }
    fields.update(changes)
    return fields


def _identity(
    manifest: dict[str, Any] | None = None, **changes: str
) -> PromotionStrategyIdentityV1:
    return PromotionStrategyIdentityV1(**_identity_fields(manifest, **changes))


def _content_fields(manifest: dict[str, Any] | None = None, **changes: str) -> dict[str, str]:
    """The reviewed claim for one manifest: labels, genome content digest and dataset lineage."""
    data = manifest or _manifest()
    fields = {
        "schema_version": CLAIM_SCHEMA,
        **_identity_fields(data),
        "strategy_content_sha256": _independent_content_digest(_genome_of(data)),
        "dataset_id": data["dataset"]["dataset_id"],
        "dataset_version": data["dataset"]["dataset_version"],
        "bars_sha256": data["dataset"]["bars_sha256"],
        "execution_inputs_sha256": _independent_execution_digest(data),
    }
    fields.update(changes)
    return fields


def _claim_text(fields: dict[str, Any], style: str = "canonical") -> str:
    if style == "canonical":
        return canonical_json(fields).decode("utf-8")
    if style == "spaced":
        # One extra space keeps the nine-field claim inside the 512-character evidence bound.
        return canonical_json(fields).decode("utf-8").replace(",", ", ", 1)
    if style == "unsorted":
        return json.dumps(fields, separators=(",", ":"))
    raise AssertionError(style)


def _review(
    *,
    manifest: dict[str, Any] | None = None,
    fields: dict[str, Any] | None = None,
    texts: tuple[str, ...] | None = None,
    claim_key: str = CLAIM_KEY,
    claim_kind: str = CLAIM_KEY,
    include_content: bool = True,
    legacy_label_claim: bool = False,
    accept_content: bool = True,
    accept_logic: bool = True,
) -> ReviewResultV1:
    """A genuinely issued STRAT-001 review result from synthetic source bytes."""
    content = fields if fields is not None else _content_fields(manifest)
    lines: list[tuple[str, str, str]] = [
        ("symbol", "market_assumption", "symbol=NQ"),
        ("entry", "entry_condition", "entry=cross_above(fast,slow)"),
        ("exit", "exit_condition", "exit=cross_below(fast,slow)"),
    ]
    content_lines: list[tuple[str, str, str]] = []
    if legacy_label_claim:
        legacy = canonical_json(_identity_fields(manifest)).decode("utf-8")
        lines.append(("strategy_identity", "parameter", legacy))
    if include_content:
        for text in texts or (_claim_text(content),):
            content_lines.append((claim_key, claim_kind, text))
    lines.extend(content_lines)
    source_bytes = "\n".join(text for _, _, text in lines).encode("utf-8")
    source_hash = _sha(source_bytes)
    source = SourceManifestV1(
        schema_version="1", source_id="synthetic_identity_claim_source",
        source_uri="file:///synthetic/identity-claim.txt", source_locator="identity-claim.txt",
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
    content_ids: set[str] = set()
    cursor = 0
    for index, (key, kind, text) in enumerate(lines):
        encoded = text.encode("utf-8")
        start = source_bytes.index(encoded, cursor)
        cursor = start + len(encoded)
        evidence_id = f"claim_{index:02d}"
        if (key, kind, text) in content_lines:
            content_ids.add(evidence_id)
        evidence.append(ExtractedEvidenceV1(
            schema_version="1", evidence_id=evidence_id, claim_key=key,
            claim_kind=kind, claim_text=text, confidence=Decimal("0.99"),
            source_sha256=source_hash,
            span=SourceSpanV1(
                schema_version="1", byte_start=start, byte_end=cursor,
                span_sha256=_sha(source_bytes[start:cursor]), page_start=None, page_end=None,
                time_start_ms=None, time_end_ms=None,
            ),
            derived_from=(), text_ref=None, chunk_ref=None, embedding_ref=None, tags=(),
        ))
    packet = register_source(source, tuple(evidence))

    def decide(item: ExtractedEvidenceV1) -> ClaimDecisionV1:
        logic = item.claim_kind in {"entry_condition", "exit_condition"}
        keep = accept_logic if logic else (
            accept_content if item.evidence_id in content_ids else True
        )
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

    def current_policy_sha256(self) -> object:
        return self.value

    def current_policy_lock_path(self) -> object:
        return self.lock_path


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


def _verified(tmp_path: Path, name: str, **changes: Any) -> Any:
    return verify_replay_artifacts(_run(tmp_path, name, **changes))


def _copy_run(artifacts: ReplayArtifacts, destination: Path) -> ReplayArtifacts:
    shutil.copytree(artifacts.result_path.parent, destination)
    return dataclasses.replace(
        artifacts,
        input_path=destination / artifacts.input_path.name,
        result_path=destination / artifacts.result_path.name,
        complete_path=destination / artifacts.complete_path.name,
    )


def _never_eligible(action: Any) -> None:
    try:
        outcome = action()
    except (PaperPromotionError, ReplayJobError, TypeError, ValueError):
        return
    assert outcome.status != "ELIGIBLE"


def _assert_unbound(result: PaperPromotionResultV1) -> None:
    assert result.status == "NOT_ELIGIBLE"
    assert result.reason_code == UNBOUND
    # Provenance for this reason is not fixed by the contract; it must never claim reproduction.
    assert result.provenance in {"C102_NOT_VERIFIED", "C102_COMPLETE_REHASHED"}
    assert require_paper_promotion_result(result) is result


@pytest.fixture(scope="module")
def baseline(tmp_path_factory: pytest.TempPathFactory) -> ReplayArtifacts:
    return _run(tmp_path_factory.mktemp("identity-claim-baseline"))


@pytest.fixture
def verified(baseline: ReplayArtifacts) -> Any:
    return verify_replay_artifacts(baseline)


@pytest.fixture
def runs(monkeypatch: pytest.MonkeyPatch) -> list[tuple[Path, Path, Path]]:
    """Count every reproduction run; an already-ineligible request must never start one."""
    real = replay_module.run_replay_job
    record: list[tuple[Path, Path, Path]] = []

    def spy(fixture: Path, risk_lock: Path, output_dir: Path) -> ReplayArtifacts:
        record.append((Path(fixture), Path(risk_lock), Path(output_dir)))
        return real(fixture, risk_lock, output_dir)

    monkeypatch.setattr(replay_module, "run_replay_job", spy)
    monkeypatch.setattr(promotion, "run_replay_job", spy, raising=False)
    return record


# --------------------------------------------------------------------------- the claim kind


def test_the_claim_kind_is_a_versioned_literal_beside_the_existing_kinds() -> None:
    kinds = set(get_args(ClaimKind))
    assert CLAIM_KEY in kinds
    assert {"entry_condition", "exit_condition", "market_assumption", "parameter"} <= kinds


def test_the_public_interface_and_the_reason_vocabulary_are_unchanged() -> None:
    parameters = inspect.signature(assess_paper_eligibility).parameters
    assert list(parameters) == [
        "strategy_identity", "review", "replay", "environment", "halt_authority",
        "risk_policy_digest_port",
    ]
    assert all(p.kind is inspect.Parameter.KEYWORD_ONLY for p in parameters.values())
    reasons = set(get_args(PaperPromotionResultV1.model_fields["reason_code"].annotation))
    assert reasons == REASON_CODES


def test_the_content_digest_follows_its_published_formula() -> None:
    genome = _genome_of(_manifest())
    digest = strategy_content_sha256(genome)
    assert re.fullmatch(r"[0-9a-f]{64}", digest)
    assert digest == _independent_content_digest(genome)
    assert strategy_content_sha256(_genome_of(_manifest())) == digest


@pytest.mark.parametrize("change", [
    {"strategy__genome__exit_conditions": ["target or stop touched", "time exit"]},
    {"strategy__genome__entry_conditions": ["structure break above range high"]},
    {"strategy__genome__family": "mean_reversion"},
    {"strategy__genome__risk_profile": "aggressive_intraday"},
    {"strategy__genome__strategy_id": "synthetic-nq-breakout-v2"},
    {"strategy__genome__market": "ES"},
    {"strategy__genome__prop_firm_compatible": False},
])
def test_any_genome_change_changes_the_content_digest(change: dict[str, Any]) -> None:
    original = strategy_content_sha256(_genome_of(_manifest()))
    assert strategy_content_sha256(_genome_of(_manifest(**change))) != original


def test_the_content_digest_ignores_labels_and_dataset_outside_the_genome() -> None:
    original = strategy_content_sha256(_genome_of(_manifest()))
    other = _manifest(strategy__strategy_version="9", dataset__dataset_id="another-dataset")
    assert strategy_content_sha256(_genome_of(other)) == original


EXECUTION_VARIANTS = {
    "stop_loss": {"decision_inputs__stop_loss": "18241"},
    "take_profit": {"decision_inputs__take_profit": "18271"},
    "requested_size": {"decision_inputs__requested_size": "2"},
    "slippage": {"fill_model__slippage": "0.5"},
    "seed": {"seed": 103},
    "universe": {"dataset__universe_version": "nq-only-v2"},
}


def test_the_execution_digest_follows_its_published_formula() -> None:
    spec = replay_module.ReplayRunSpec.model_validate(_manifest())
    digest = execution_inputs_sha256(spec)
    assert re.fullmatch(r"[0-9a-f]{64}", digest)
    assert digest == _independent_execution_digest(_manifest())
    again = replay_module.ReplayRunSpec.model_validate(_manifest())
    assert execution_inputs_sha256(again) == digest


@pytest.mark.parametrize("name", list(EXECUTION_VARIANTS))
def test_any_execution_input_change_changes_the_execution_digest(name: str) -> None:
    original = execution_inputs_sha256(replay_module.ReplayRunSpec.model_validate(_manifest()))
    changed = replay_module.ReplayRunSpec.model_validate(_manifest(**EXECUTION_VARIANTS[name]))
    assert execution_inputs_sha256(changed) != original


def test_the_execution_digest_ignores_genome_labels_and_bars() -> None:
    original = execution_inputs_sha256(replay_module.ReplayRunSpec.model_validate(_manifest()))
    other = _manifest(strategy__genome__family="mean_reversion")
    assert execution_inputs_sha256(replay_module.ReplayRunSpec.model_validate(other)) == original
    assert strategy_content_sha256(_genome_of(_manifest())) != original


def test_the_execution_digest_refuses_anything_that_is_not_a_replay_spec() -> None:
    for bad in (None, {}, "spec", 7, _manifest(), object()):
        with pytest.raises((TypeError, ValueError, AttributeError, PaperPromotionError)):
            execution_inputs_sha256(bad)  # type: ignore[arg-type]


def test_the_content_digest_refuses_anything_that_is_not_a_genome() -> None:
    for bad in (None, {}, "genome", 7, _manifest()["strategy"]["genome"], object()):
        with pytest.raises((TypeError, ValueError, AttributeError, PaperPromotionError)):
            strategy_content_sha256(bad)  # type: ignore[arg-type]


# -------------------------------------------------------------------------- the happy path


def test_a_matching_content_bound_claim_and_a_matching_reproduction_is_eligible(
    verified: Any, runs: list[Any],
) -> None:
    review = _review()
    assert review.spec is not None
    claims = [c for c in review.spec.accepted_claims if c.claim_key == CLAIM_KEY]
    assert len(claims) == 1 and claims[0].claim_kind == CLAIM_KEY
    assert len(claims[0].claim_text) <= 512
    assert list(json.loads(claims[0].claim_text)) == sorted(CLAIM_FIELDS)
    result = _assess(verified, review=review)
    assert (result.status, result.reason_code, result.provenance) == (
        "ELIGIBLE", "ELIGIBLE", "REPRODUCED",
    )
    assert result.advisory_only is True
    assert len(runs) == 1
    assert require_paper_promotion_result(result) is result
    assert _assess(verified, review=review) == result


def test_the_result_still_has_no_activation_routing_or_approval_surface(verified: Any) -> None:
    result = _assess(verified)
    fields = set(type(result).model_fields)
    assert not [name for name in fields if FORBIDDEN_FIELDS.search(name)]
    dumped = result.model_dump_json()
    assert not re.search(r"activate|route|submit|place_order|approve|enable", dumped, re.I)
    public = [
        name for name in dir(promotion)
        if not name.startswith("_") and callable(getattr(promotion, name))
    ]
    action_words = r"activat|submit|rout|place_order|approve|enable"
    assert not [name for name in public if re.search(action_words, name, re.I)]


def test_assessment_makes_no_network_or_process_call(
    verified: Any, monkeypatch: pytest.MonkeyPatch,
) -> None:
    blocked_calls: list[str] = []
    real_connect = socket.socket.connect

    def guarded_connect(self: socket.socket, address: Any) -> None:
        # asyncio builds a loopback socket pair for its event loop; anything else is outbound.
        host = address[0] if isinstance(address, tuple) else address
        if host not in {"127.0.0.1", "::1", "localhost"}:
            blocked_calls.append(f"connect:{host}")
            raise AssertionError("outbound network call during assessment")
        real_connect(self, address)

    def blocked(name: str) -> Any:
        def refuse(*_args: object, **_kwargs: object) -> None:
            blocked_calls.append(name)
            raise AssertionError(f"{name} during assessment")

        return refuse

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    monkeypatch.setattr(socket, "create_connection", blocked("create_connection"))
    monkeypatch.setattr(socket, "getaddrinfo", blocked("getaddrinfo"))
    monkeypatch.setattr(subprocess, "Popen", blocked("Popen"))
    result = _assess(verified)
    assert blocked_calls == []
    assert (result.status, result.reason_code) == ("ELIGIBLE", "ELIGIBLE")


# ---------------------------------------------- claims that must give REVIEW_IDENTITY_UNBOUND

_OTHER_DIGEST = _independent_content_digest(
    _genome_of(_manifest(strategy__genome__family="mean_reversion"))
)
_GOOD_DIGEST = _independent_content_digest(_genome_of(_manifest()))
_FLIPPED = _GOOD_DIGEST[:-1] + ("0" if _GOOD_DIGEST[-1] != "0" else "1")
_GOOD_EXEC = _independent_execution_digest(_manifest())
_OTHER_EXEC = _independent_execution_digest(_manifest(seed=103))
_FLIPPED_EXEC = _GOOD_EXEC[:-1] + ("0" if _GOOD_EXEC[-1] != "0" else "1")
_GOOD_BARS = _manifest()["dataset"]["bars_sha256"]
_FLIPPED_BARS = _GOOD_BARS[:-1] + ("0" if _GOOD_BARS[-1] != "0" else "1")

UNBOUND_CLAIMS: dict[str, dict[str, Any]] = {
    "label-only legacy claim": {"include_content": False, "legacy_label_claim": True},
    "no identity claim at all": {"include_content": False},
    "claim under another key": {"claim_key": "strategy_content_identity_other"},
    "claim of another kind": {"claim_kind": "parameter"},
    "rejected claim": {"accept_content": False},
    "stale claim schema": {"fields_changes": {"schema_version": "strat.strategy-content-claim/0"}},
    "future claim schema": {"fields_changes": {"schema_version": "strat.strategy-content-claim/2"}},
    "another strategy ref": {"fields_changes": {"strategy_ref": "static_genome/2"}},
    "another strategy id": {"fields_changes": {"strategy_id": "synthetic-nq-breakout-v2"}},
    "stale version": {"fields_changes": {"strategy_version": "0"}},
    "newer version": {"fields_changes": {"strategy_version": "2"}},
    "wrong digest": {"fields_changes": {"strategy_content_sha256": _FLIPPED}},
    "digest of other logic": {"fields_changes": {"strategy_content_sha256": _OTHER_DIGEST}},
    "upper-case digest": {"fields_changes": {"strategy_content_sha256": _GOOD_DIGEST.upper()}},
    "short digest": {"fields_changes": {"strategy_content_sha256": _GOOD_DIGEST[:-1]}},
    "empty digest": {"fields_changes": {"strategy_content_sha256": ""}},
    "wrong execution digest": {"fields_changes": {"execution_inputs_sha256": _FLIPPED_EXEC}},
    "digest of other execution inputs": {
        "fields_changes": {"execution_inputs_sha256": _OTHER_EXEC}
    },
    "upper-case execution digest": {
        "fields_changes": {"execution_inputs_sha256": _GOOD_EXEC.upper()}
    },
    "short execution digest": {"fields_changes": {"execution_inputs_sha256": _GOOD_EXEC[:-1]}},
    "null execution digest": {"fields_changes": {"execution_inputs_sha256": None}},
    "other dataset id": {"fields_changes": {"dataset_id": "synthetic-nq-other"}},
    "other dataset version": {"fields_changes": {"dataset_version": "synthetic-nq-2026-04-15-v2"}},
    "wrong bars digest": {"fields_changes": {"bars_sha256": _FLIPPED_BARS}},
    "upper-case bars digest": {"fields_changes": {"bars_sha256": _GOOD_BARS.upper()}},
    "numeric version": {"fields_changes": {"strategy_version": 1}},
    "null digest": {"fields_changes": {"strategy_content_sha256": None}},
    "extra field": {"fields_extra": {"x": ""}},
    "spaced non-canonical text": {"style": "spaced"},
    "unsorted non-canonical text": {"style": "unsorted"},
    **{f"missing {name}": {"fields_drop": (name,)} for name in CLAIM_FIELDS},
}


def _unbound_review(options: dict[str, Any]) -> ReviewResultV1:
    options = dict(options)
    fields = _content_fields()
    fields.update(options.pop("fields_changes", {}))
    fields.update(options.pop("fields_extra", {}))
    for name in options.pop("fields_drop", ()):
        del fields[name]
    style = options.pop("style", "canonical")
    text = _claim_text(fields, style)
    if style != "canonical":
        assert text != _claim_text(fields)
    return _review(fields=fields, texts=(text,), **options)


@pytest.mark.parametrize("name", list(UNBOUND_CLAIMS))
def test_every_label_only_stale_wrong_or_altered_claim_is_unbound_and_never_reproduced(
    verified: Any, runs: list[Any], name: str,
) -> None:
    result = _assess(verified, review=_unbound_review(UNBOUND_CLAIMS[name]))
    _assert_unbound(result)
    assert runs == []


@pytest.mark.parametrize("field", ["strategy_ref", "strategy_id", "strategy_version"])
def test_the_claim_must_name_the_identity_the_caller_asks_about(
    verified: Any, field: str,
) -> None:
    # The claim matches the replay, but the caller asks about a different label.
    other = "9" if field == "strategy_version" else "another-label"
    result = _assess(verified, identity=_identity(**{field: other}))
    assert result.status == "NOT_ELIGIBLE"
    assert result.reason_code in {UNBOUND, "STRATEGY_IDENTITY_MISMATCH"}


def test_a_claim_for_another_version_than_the_replay_is_not_eligible(
    tmp_path: Path, runs: list[Any],
) -> None:
    # Reviewed and asked about version 2, but the genuine replay is version 1 of that logic.
    manifest = _manifest()
    reviewed = _review(fields=_content_fields(manifest, strategy_version="2"))
    result = _assess(
        _verified(tmp_path, "v1"), review=reviewed, identity=_identity(strategy_version="2"),
    )
    assert result.status == "NOT_ELIGIBLE"
    assert result.reason_code in {UNBOUND, "STRATEGY_IDENTITY_MISMATCH"}
    assert runs == []


# ----------------------------------- genuine replays of other logic or data under the same labels

GENOME_VARIANTS = {
    "exit logic": {"strategy__genome__exit_conditions": ["target or stop touched", "time exit"]},
    "entry logic": {"strategy__genome__entry_conditions": ["structure break above range high"]},
    "family": {"strategy__genome__family": "mean_reversion"},
    "risk profile": {"strategy__genome__risk_profile": "aggressive_intraday"},
}
DATASET_VARIANTS = {
    "dataset id": {"dataset__dataset_id": "synthetic-nq-other"},
    "dataset version": {"dataset__dataset_version": "synthetic-nq-2026-04-15-v2"},
    "bars": _bar_changes(),
}


@pytest.mark.parametrize(
    "name", list(GENOME_VARIANTS) + list(DATASET_VARIANTS) + list(EXECUTION_VARIANTS)
)
def test_a_genuine_replay_of_other_logic_data_or_execution_inputs_is_unbound(
    tmp_path: Path, runs: list[Any], name: str,
) -> None:
    change = {**GENOME_VARIANTS, **DATASET_VARIANTS, **EXECUTION_VARIANTS}[name]
    other = _verified(tmp_path, "other", **change)
    # Same strategy_ref, strategy_id and strategy_version as the reviewed claim, genuine run.
    assert other.strategy_id == _identity_fields()["strategy_id"]
    assert other.result_status == "completed"
    reviewed = _review()  # the claim reviewed for the baseline logic and dataset
    result = _assess(other, review=reviewed)
    _assert_unbound(result)
    assert runs == []
    # Control: reviewing exactly what ran makes the same run eligible, so the refusal above
    # comes from the content binding and from nothing else.
    runs.clear()
    matching = _review(manifest=_manifest(**change))
    control = _assess(other, review=matching)
    assert (control.status, control.reason_code, control.provenance) == (
        "ELIGIBLE", "ELIGIBLE", "REPRODUCED",
    )
    assert len(runs) == 1


def test_a_claim_reviewed_for_other_content_never_binds_any_baseline_replay(verified: Any) -> None:
    other_claim = _review(manifest=_manifest(**GENOME_VARIANTS["family"]))
    _assert_unbound(_assess(verified, review=other_claim))
    other_data = _review(manifest=_manifest(**DATASET_VARIANTS["bars"]))
    _assert_unbound(_assess(verified, review=other_data))
    for change in EXECUTION_VARIANTS.values():
        _assert_unbound(_assess(verified, review=_review(manifest=_manifest(**change))))


# ------------------------------------------------ rejected, unreviewed, altered and conflicting


def test_an_unresolved_review_is_still_unresolved_not_unbound(verified: Any) -> None:
    result = _assess(verified, review=_review(accept_logic=False))
    assert (result.status, result.reason_code) == ("NOT_ELIGIBLE", "REVIEW_UNRESOLVED")


def test_an_issued_spec_or_claim_cannot_be_copied_with_changes(verified: Any) -> None:
    good = _review()
    assert good.spec is not None
    claim = next(c for c in good.spec.accepted_claims if c.claim_key == CLAIM_KEY)
    edited_text = _claim_text(_content_fields(strategy_content_sha256=_FLIPPED))
    with pytest.raises(StrategyIngestError, match="SEALED_RECORD_COPY_DENIED"):
        claim.model_copy(update={"claim_text": edited_text})
    with pytest.raises(StrategyIngestError, match="SEALED_RECORD_COPY_DENIED"):
        good.spec.model_copy(update={"accepted_claims": (claim,)})
    # The refusal leaves the genuine review usable.
    assert _assess(verified, review=good).status == "ELIGIBLE"


def test_a_hand_built_or_edited_spec_never_grants_eligibility(verified: Any) -> None:
    good = _review()
    assert good.spec is not None
    claim = next(c for c in good.spec.accepted_claims if c.claim_key == CLAIM_KEY)
    edited_text = _claim_text(_content_fields(strategy_content_sha256=_FLIPPED))
    with pytest.raises(StrategyIngestError, match="SEALED_RECORD_CONSTRUCTION_DENIED"):
        type(claim).model_construct(**{**dict(claim), "claim_text": edited_text})
    # A validly constructed but never-issued claim is not issued evidence either.
    edited_claim = type(claim)(**{**dict(claim), "claim_text": edited_text})
    # An issued spec cannot be hand-built.
    with pytest.raises(StrategyIngestError, match="SEALED_RECORD_CONSTRUCTION_DENIED"):
        type(good.spec).model_construct(**{**dict(good.spec), "accepted_claims": (edited_claim,)})
    # Editing an issued spec or claim in place breaks its seal.
    for victim_claims in ((edited_claim,), (claim, edited_claim)):
        review = _review()
        assert review.spec is not None
        object.__setattr__(review.spec, "accepted_claims", victim_claims)
        _never_eligible(lambda review=review: _assess(verified, review=review))
    review = _review()
    assert review.spec is not None
    target = next(c for c in review.spec.accepted_claims if c.claim_key == CLAIM_KEY)
    object.__setattr__(target, "claim_text", edited_text)
    _never_eligible(lambda: _assess(verified, review=review))
    _never_eligible(lambda: _assess(verified, review=object()))  # type: ignore[arg-type]
    assert _assess(verified, review=good).status == "ELIGIBLE"


def test_conflicting_claims_for_one_identity_never_grant_eligibility(verified: Any) -> None:
    right = _claim_text(_content_fields())
    wrong = _claim_text(_content_fields(strategy_content_sha256=_OTHER_DIGEST))
    for texts in ((right, wrong), (wrong, right)):
        try:
            review = _review(texts=texts)
        except ValueError:
            continue  # the review stage refused the conflicting pair outright
        outcome = _assess(verified, review=review)
        assert outcome.status == "NOT_ELIGIBLE"
        assert outcome.reason_code == UNBOUND


# ------------------------------------------- the content comes from the replay's sealed input


def test_a_caller_cannot_supply_a_genome_or_digest() -> None:
    names = " ".join(inspect.signature(assess_paper_eligibility).parameters)
    names = names.replace("risk_policy_digest_port", "")
    assert not re.search(r"genome|content|digest|dataset|bars", names)


def test_an_input_swapped_after_verification_is_never_eligible(
    baseline: ReplayArtifacts, tmp_path: Path,
) -> None:
    copied = _copy_run(baseline, tmp_path / "swap-after-verify")
    copied_verified = verify_replay_artifacts(copied)
    other = _run(tmp_path, "swap-source", **GENOME_VARIANTS["family"])
    copied.input_path.write_bytes(other.input_path.read_bytes())
    _never_eligible(lambda: _assess(copied_verified))
    # The reviewed claim of the other logic does not make it eligible either.
    swapped_claim = _review(manifest=_manifest(**GENOME_VARIANTS["family"]))
    _never_eligible(lambda: _assess(copied_verified, review=swapped_claim))


def test_an_input_edited_after_verification_is_never_eligible(
    baseline: ReplayArtifacts, tmp_path: Path,
) -> None:
    copied = _copy_run(baseline, tmp_path / "edit-after-verify")
    copied_verified = verify_replay_artifacts(copied)
    copied.input_path.write_bytes(copied.input_path.read_bytes() + b" ")
    _never_eligible(lambda: _assess(copied_verified))


def test_a_missing_input_file_after_verification_is_never_eligible(
    baseline: ReplayArtifacts, tmp_path: Path,
) -> None:
    copied = _copy_run(baseline, tmp_path / "delete-after-verify")
    copied_verified = verify_replay_artifacts(copied)
    copied.input_path.unlink()
    _never_eligible(lambda: _assess(copied_verified))


# ------------------------------------------------------- paper-only behavior is preserved


def test_live_halt_and_missing_or_blocked_replays_keep_their_reasons(
    verified: Any, tmp_path: Path,
) -> None:
    live = _assess(verified, environment=BrokerEnvironment.LIVE)
    assert (live.status, live.reason_code) == ("NOT_ELIGIBLE", "LIVE_ENVIRONMENT")
    halted = HaltAuthority()
    halted.engage("operator_hold")
    assert _assess(verified, halt=halted).reason_code == "HALT_ACTIVE"
    assert _assess(None, review=_review()).reason_code == "REPLAY_INCOMPLETE"
    blocked = _verified(tmp_path, "blocked", risk__initial_halts=["operator_hold"])
    assert _assess(blocked).reason_code == "REPLAY_FAILED"


def test_review_identity_unbound_precedes_the_risk_policy_reasons(verified: Any) -> None:
    bad_claim = _review(fields=_content_fields(strategy_content_sha256=_FLIPPED))
    assert _assess(verified, review=bad_claim, port=_Port(None)).reason_code == UNBOUND
    assert _assess(verified, review=bad_claim, port=_Port("0" * 64)).reason_code == UNBOUND
    # With a valid claim the policy reasons are reached as before.
    assert _assess(verified, port=_Port(None)).reason_code == "RISK_POLICY_UNBOUND"


def test_a_failed_replay_and_an_unresolved_review_still_precede_the_claim_check(
    tmp_path: Path,
) -> None:
    blocked = _verified(tmp_path, "blocked-first", risk__initial_halts=["operator_hold"])
    bad_claim = _review(fields=_content_fields(strategy_content_sha256=_FLIPPED))
    assert _assess(blocked, review=bad_claim).reason_code == "REPLAY_FAILED"
    ok = _verified(tmp_path, "ok-first")
    unresolved = _review(
        accept_logic=False, fields=_content_fields(strategy_content_sha256=_FLIPPED)
    )
    assert _assess(ok, review=unresolved).reason_code == "REVIEW_UNRESOLVED"


def test_a_replay_of_another_label_triple_keeps_the_identity_mismatch_reason(
    tmp_path: Path,
) -> None:
    # The claim is reviewed for exactly what the other genuine replay contains, and the caller
    # asks about that identity, so only the replay's labels differ from the reviewed ones.
    change = {"strategy__genome__strategy_id": "another-strategy-v9"}
    other_manifest = _manifest(**change)
    other = _verified(tmp_path, "relabelled", **change)
    reviewed = _review(manifest=other_manifest)
    result = _assess(other, review=reviewed, identity=_identity(other_manifest))
    assert (result.status, result.reason_code) == ("ELIGIBLE", "ELIGIBLE")
    mismatch = _assess(other, review=_review(), identity=_identity())
    assert mismatch.status == "NOT_ELIGIBLE"
    assert mismatch.reason_code in {UNBOUND, "STRATEGY_IDENTITY_MISMATCH"}


def test_the_reproduction_stays_the_last_check_and_runs_once(
    verified: Any, runs: list[Any],
) -> None:
    ok = _assess(verified)
    assert ok.provenance == "REPRODUCED" and len(runs) == 1
    runs.clear()
    stale = _review(fields=_content_fields(bars_sha256=_FLIPPED_BARS))
    _assert_unbound(_assess(verified, review=stale))
    assert runs == []
    leftovers = Path(tempfile.gettempdir()).glob("strat-paper-promotion-*")
    assert not [path for path in leftovers if path.is_dir()]


def test_a_hand_rewritten_replay_is_still_not_reproduced(
    tmp_path: Path, runs: list[Any],
) -> None:
    source = _run(tmp_path, "forge-source", risk__initial_halts=["operator_hold"])
    forged = _copy_run(source, tmp_path / "forged-run")
    run_dir = forged.result_path.parent
    raw = forged.result_path.read_bytes()
    assert raw.count(b'"status":"blocked"') == 1
    rewritten = raw.replace(b'"status":"blocked"', b'"status":"completed"')
    forged.result_path.write_bytes(rewritten)
    diagnostics = run_dir / "diagnostics.json"
    text = diagnostics.read_bytes()
    assert text.count(b'"status":"blocked"') == 1
    diagnostics.write_bytes(text.replace(b'"status":"blocked"', b'"status":"completed"'))
    result_sha = _sha(rewritten)
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
    forged = dataclasses.replace(forged, result_sha256=result_sha)
    forged_verified = verify_replay_artifacts(forged)
    reviewed = _review(manifest=_manifest(risk__initial_halts=["operator_hold"]))
    result = _assess(forged_verified, review=reviewed)
    assert result.status == "NOT_ELIGIBLE"
    assert result.reason_code in {"REPLAY_NOT_REPRODUCED", UNBOUND}
    assert result.provenance != "REPRODUCED"


# ----------------------------------------- label diagnostic and the bounded input read


def test_the_label_diagnostic_is_a_closed_optional_field() -> None:
    annotation = PaperPromotionResultV1.model_fields["diagnostic_code"].annotation
    members: set[Any] = set()
    for member in get_args(annotation):
        members.update(get_args(member) if get_args(member) else {member})
    assert members == {"IDENTITY_LABEL_DISALLOWED", type(None)}
    assert set(get_args(PaperPromotionResultV1.model_fields["reason_code"].annotation)) == (
        REASON_CODES
    )


def test_ordinary_results_carry_no_diagnostic(verified: Any) -> None:
    assert _assess(verified).diagnostic_code is None
    unbound = _assess(verified, review=_review(fields=_content_fields(bars_sha256=_FLIPPED_BARS)))
    _assert_unbound(unbound)
    assert unbound.diagnostic_code is None


@pytest.mark.parametrize("field,label", [
    ("strategy_id", "api"),
    ("strategy_id", "api-key-strategy"),
    ("strategy_id", "synthetic_token_bucket"),
    ("strategy_id", "nq-secret-v1"),
    ("strategy_version", "auth"),
    ("strategy_ref", "static_genome/password"),
])
def test_a_deny_word_in_the_identity_label_is_unbound_with_a_closed_diagnostic(
    verified: Any, runs: list[Any], field: str, label: str,
) -> None:
    identity = _identity(**{field: label})
    review = _review(fields=_content_fields(**{field: label}))  # the claim names the same label
    result = _assess(verified, review=review, identity=identity)
    _assert_unbound(result)
    assert result.diagnostic_code == "IDENTITY_LABEL_DISALLOWED"
    dumped = result.model_dump_json()
    claim_fields = _content_fields(**{field: label})
    # The claim text and its digests are never echoed; only the caller's own identity is.
    assert _claim_text(claim_fields) not in dumped
    assert claim_fields["strategy_content_sha256"] not in dumped
    assert claim_fields["execution_inputs_sha256"] not in dumped
    assert require_paper_promotion_result(result) is result
    assert runs == []


def test_a_malformed_identity_label_is_refused_by_the_identity_model() -> None:
    for bad in ("", " ", "has space", "semi;colon", "x" * 4096, f"{CANARY}\n"):
        with pytest.raises(ValueError):
            _identity(strategy_id=bad)


@pytest.mark.parametrize("limit", [1, 16])
def test_an_oversized_sealed_input_fails_closed_without_a_run(
    verified: Any, runs: list[Any], monkeypatch: pytest.MonkeyPatch, limit: int,
) -> None:
    monkeypatch.setattr(promotion, "_MAX_PROMOTION_INPUT_BYTES", limit)
    result = _assess(verified)
    assert (result.status, result.reason_code) == ("NOT_ELIGIBLE", "REPLAY_INCOMPLETE")
    assert result.provenance != "REPRODUCED"
    assert runs == []


# --------------------------------------------- maximum-length identifiers in the claim text


def _max_identifier(prefix: str) -> str:
    """A distinct identifier of exactly the grammar's maximum length (128 characters)."""
    value = ((prefix + "-nq-breakout-") * 20)[:128]
    assert len(value) == 128 and is_safe_identifier(value)
    return value


MAX_IDENTIFIER_FIELDS = (
    "strategy_ref", "strategy_id", "strategy_version", "dataset_id", "dataset_version",
)


def test_a_replay_with_maximum_length_identifiers_binds_and_is_eligible(
    tmp_path: Path, runs: list[Any],
) -> None:
    change = {
        "strategy__genome__strategy_id": _max_identifier("alpha"),
        "dataset__dataset_id": _max_identifier("bravo"),
        "dataset__dataset_version": _max_identifier("charlie"),
    }
    manifest = _manifest(**change)
    other = _verified(tmp_path, "max-ids", **change)
    assert other.result_status == "completed"
    review = _review(manifest=manifest)
    assert review.spec is not None
    claim = next(c for c in review.spec.accepted_claims if c.claim_key == CLAIM_KEY)
    assert len(claim.claim_text) > 512  # beyond the former bound, so the new bound is exercised
    result = _assess(other, review=review, identity=_identity(manifest))
    assert (result.status, result.reason_code, result.provenance) == (
        "ELIGIBLE", "ELIGIBLE", "REPRODUCED",
    )
    assert len(runs) == 1


def test_a_claim_with_every_identifier_field_at_maximum_length_is_accepted_and_unbound(
    verified: Any, runs: list[Any],
) -> None:
    labels = {name: _max_identifier(name[:6]) for name in MAX_IDENTIFIER_FIELDS}
    review = _review(fields=_content_fields(**labels))  # the review stage accepts the claim text
    # The assessed identity is the valid replay identity (version labels are bounded at 64 and
    # the replay's ref and version are fixed), so the long-label claim describes another strategy.
    result = _assess(verified, review=review)
    _assert_unbound(result)
    assert runs == []


@pytest.mark.parametrize("field", MAX_IDENTIFIER_FIELDS)
def test_an_identifier_one_over_the_grammar_maximum_is_never_bound(
    verified: Any, field: str,
) -> None:
    over = _max_identifier("over") + "x"
    assert len(over) == 129
    try:
        review = _review(fields=_content_fields(**{field: over}))
    except ValueError:
        return  # refused when the claim is built
    result = _assess(verified, review=review)
    assert result.status == "NOT_ELIGIBLE"
    assert result.reason_code == UNBOUND


def test_a_claim_text_far_over_the_evidence_bound_is_refused_when_built() -> None:
    fields = _content_fields()
    fields["x"] = "y" * 4096
    with pytest.raises(ValueError):
        _review(fields=fields, texts=(_claim_text(fields),))


def _padded_claim_text(length: int) -> str:
    """A nine-field claim plus one empty extra field, padded to exactly *length* characters."""
    fields = _content_fields()
    fields["x"] = ""
    base = len(_claim_text(fields))
    fields["x"] = "y" * (length - base)
    text = _claim_text(fields)
    assert len(text) == length
    return text


def test_the_claim_text_bound_is_exactly_1200_characters_for_this_kind(verified: Any) -> None:
    accepted = _review(texts=(_padded_claim_text(1200),))  # exactly at the bound builds
    result = _assess(verified, review=accepted)
    _assert_unbound(result)  # an extra field is never a valid claim, but it is not an error
    with pytest.raises(ValueError):
        _review(texts=(_padded_claim_text(1201),))


def test_other_claim_kinds_keep_the_original_512_character_bound() -> None:
    long_text = "entry=" + "a" * (513 - len("entry="))
    assert len(long_text) == 513
    with pytest.raises(ValueError):
        ExtractedEvidenceV1(
            schema_version="1", evidence_id="claim_99", claim_key="entry", claim_kind="parameter",
            claim_text=long_text, confidence=Decimal("0.99"), source_sha256="a" * 64,
            span=SourceSpanV1(
                schema_version="1", byte_start=0, byte_end=1, span_sha256="b" * 64,
                page_start=None, page_end=None, time_start_ms=None, time_end_ms=None,
            ),
            derived_from=(), text_ref=None, chunk_ref=None, embedding_ref=None, tags=(),
        )
