from __future__ import annotations

import hashlib
import json
from decimal import Decimal
from pathlib import Path

import pytest

from leviathan_core.numeric.canonical import canonical_json
from leviathan_core.research.replay_job import ReplayRunSpec
from leviathan_core.schemas.strategy import StrategyGenome
from leviathan_core.strategy_ingest.models import ExtractedEvidenceV1, StrategyIngestError
from leviathan_core.strategy_ingest.paper_promotion import (
    PromotionStrategyIdentityV1,
    _content_claim_matches,
    execution_inputs_sha256,
    strategy_content_sha256,
)

_PACKAGE_ROOT = Path(__file__).parents[2]
_FIXTURE = _PACKAGE_ROOT / "tests" / "fixtures" / "replay_job" / "v1-nq.json"
_CLAIM_KIND = "strategy_content_identity_v1"


def _replay_spec() -> ReplayRunSpec:
    return ReplayRunSpec.model_validate_json(_FIXTURE.read_bytes())


def _identity(spec: ReplayRunSpec) -> PromotionStrategyIdentityV1:
    return PromotionStrategyIdentityV1(
        strategy_ref=spec.strategy.strategy_ref,
        strategy_id=spec.strategy.genome.strategy_id,
        strategy_version=spec.strategy.strategy_version,
    )


def _claim_text(spec: ReplayRunSpec) -> str:
    genome_sha = hashlib.sha256(
        canonical_json(
            {
                "schema_version": "strat.strategy-content/1",
                "genome": spec.strategy.genome.model_dump(mode="json"),
            }
        )
    ).hexdigest()
    return canonical_json(
        {
            "schema_version": "strat.strategy-content-claim/1",
            "strategy_ref": spec.strategy.strategy_ref,
            "strategy_id": spec.strategy.genome.strategy_id,
            "strategy_version": spec.strategy.strategy_version,
            "strategy_content_sha256": genome_sha,
            "dataset_id": spec.dataset.dataset_id,
            "dataset_version": spec.dataset.dataset_version,
            "bars_sha256": spec.dataset.bars_sha256,
            "execution_inputs_sha256": execution_inputs_sha256(spec),
        }
    ).decode("utf-8")


def test_content_digest_is_canonical_and_binds_all_genome_fields() -> None:
    spec = _replay_spec()
    genome = spec.strategy.genome
    expected = hashlib.sha256(
        canonical_json(
            {
                "schema_version": "strat.strategy-content/1",
                "genome": genome.model_dump(mode="json"),
            }
        )
    ).hexdigest()

    assert strategy_content_sha256(genome) == expected
    assert strategy_content_sha256(genome) == strategy_content_sha256(
        StrategyGenome.model_validate(genome.model_dump(mode="python"))
    )
    changed = StrategyGenome.model_validate(
        {**genome.model_dump(mode="python"), "family": "different_family"}
    )
    assert strategy_content_sha256(changed) != expected


def test_execution_inputs_digest_is_canonical_and_binds_runtime_inputs() -> None:
    spec = _replay_spec()
    assert spec.decision_inputs.stop_loss is not None
    assert spec.decision_inputs.take_profit is not None
    payload = {
        "decision_inputs": spec.decision_inputs.model_dump(mode="json"),
        "fill_model": spec.fill_model.model_dump(mode="json"),
        "seed": spec.seed,
        "universe_version": spec.dataset.universe_version,
    }
    expected = hashlib.sha256(canonical_json(payload)).hexdigest()
    assert execution_inputs_sha256(spec) == expected

    changes = (
        (
            "decision_inputs",
            "stop_loss",
            str(spec.decision_inputs.stop_loss + Decimal("0.01")),
        ),
        (
            "decision_inputs",
            "take_profit",
            str(spec.decision_inputs.take_profit + Decimal("0.01")),
        ),
        (
            "decision_inputs",
            "requested_size",
            str(spec.decision_inputs.requested_size + Decimal("1")),
        ),
        ("fill_model", "slippage", str(spec.fill_model.slippage + Decimal("0.01"))),
    )
    for section, field, value in changes:
        changed_payload = spec.model_dump(mode="json")
        changed_payload[section][field] = value
        changed_spec = ReplayRunSpec.model_validate(changed_payload)
        assert execution_inputs_sha256(changed_spec) != expected

    changed_seed = spec.model_dump(mode="json")
    changed_seed["seed"] = spec.seed + 1
    assert execution_inputs_sha256(ReplayRunSpec.model_validate(changed_seed)) != expected

    changed_universe = spec.model_dump(mode="json")
    changed_universe["dataset"]["universe_version"] = f"{spec.dataset.universe_version}-next"
    assert execution_inputs_sha256(ReplayRunSpec.model_validate(changed_universe)) != expected


def test_canonical_input_read_is_bounded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import leviathan_core.strategy_ingest.paper_promotion as paper_promotion

    path = tmp_path / "input.canonical.json"
    path.write_bytes(b"12345")
    monkeypatch.setattr(paper_promotion, "_MAX_PROMOTION_INPUT_BYTES", 4)
    assert paper_promotion._read_bounded_input(path) is None


def test_content_claim_binds_identity_genome_and_dataset_lineage() -> None:
    spec = _replay_spec()
    identity = _identity(spec)
    text = _claim_text(spec)
    assert len(text.encode("utf-8")) < 512

    assert _content_claim_matches(
        claim_text=text,
        identity=identity,
        genome=spec.strategy.genome,
        dataset_id=spec.dataset.dataset_id,
        dataset_version=spec.dataset.dataset_version,
        bars_sha256=spec.dataset.bars_sha256,
        execution_inputs_digest=execution_inputs_sha256(spec),
    )

    for field, value in (
        ("strategy_ref", "different/ref"),
        ("strategy_id", "different-strategy"),
        ("strategy_version", "2"),
        ("strategy_content_sha256", "0" * 64),
        ("dataset_id", "different-dataset"),
        ("dataset_version", "different-version"),
        ("bars_sha256", "f" * 64),
        ("execution_inputs_sha256", "0" * 64),
    ):
        payload = json.loads(text)
        payload[field] = value
        assert not _content_claim_matches(
            claim_text=canonical_json(payload).decode("utf-8"),
            identity=identity,
            genome=spec.strategy.genome,
            dataset_id=spec.dataset.dataset_id,
            dataset_version=spec.dataset.dataset_version,
            bars_sha256=spec.dataset.bars_sha256,
            execution_inputs_digest=execution_inputs_sha256(spec),
        )

    payload = json.loads(text)
    del payload["execution_inputs_sha256"]
    assert not _content_claim_matches(
        claim_text=canonical_json(payload).decode("utf-8"),
        identity=identity,
        genome=spec.strategy.genome,
        dataset_id=spec.dataset.dataset_id,
        dataset_version=spec.dataset.dataset_version,
        bars_sha256=spec.dataset.bars_sha256,
        execution_inputs_digest=execution_inputs_sha256(spec),
    )


@pytest.mark.parametrize(
    "text",
    (
        "not-json",
        '{"schema_version":"strat.strategy-content-claim/1","schema_version":"strat.strategy-content-claim/1"}',
        '{ "schema_version": "strat.strategy-content-claim/1" }',
    ),
)
def test_malformed_or_noncanonical_claim_is_unbound(text: str) -> None:
    spec = _replay_spec()
    assert not _content_claim_matches(
        claim_text=text,
        identity=_identity(spec),
        genome=spec.strategy.genome,
        dataset_id=spec.dataset.dataset_id,
        dataset_version=spec.dataset.dataset_version,
        bars_sha256=spec.dataset.bars_sha256,
        execution_inputs_digest=execution_inputs_sha256(spec),
    )


def test_claim_identifiers_and_digest_grammar_are_closed() -> None:
    spec = _replay_spec()
    identity = _identity(spec)
    payload = json.loads(_claim_text(spec))
    payload["dataset_id"] = "api"
    assert not _content_claim_matches(
        claim_text=canonical_json(payload).decode("utf-8"),
        identity=identity,
        genome=spec.strategy.genome,
        dataset_id="api",
        dataset_version=spec.dataset.dataset_version,
        bars_sha256=spec.dataset.bars_sha256,
        execution_inputs_digest=execution_inputs_sha256(spec),
    )

    payload = json.loads(_claim_text(spec))
    payload["strategy_content_sha256"] = "A" * 64
    assert not _content_claim_matches(
        claim_text=canonical_json(payload).decode("utf-8"),
        identity=identity,
        genome=spec.strategy.genome,
        dataset_id=spec.dataset.dataset_id,
        dataset_version=spec.dataset.dataset_version,
        bars_sha256=spec.dataset.bars_sha256,
        execution_inputs_digest=execution_inputs_sha256(spec),
    )

    payload = json.loads(_claim_text(spec))
    payload["execution_inputs_sha256"] = "A" * 64
    assert not _content_claim_matches(
        claim_text=canonical_json(payload).decode("utf-8"),
        identity=identity,
        genome=spec.strategy.genome,
        dataset_id=spec.dataset.dataset_id,
        dataset_version=spec.dataset.dataset_version,
        bars_sha256=spec.dataset.bars_sha256,
        execution_inputs_digest=execution_inputs_sha256(spec),
    )


def test_versioned_claim_kind_is_accepted_by_the_review_model() -> None:
    spec = _replay_spec()
    evidence = {
        "schema_version": "1",
        "evidence_id": "content-evidence-1",
        "claim_key": _CLAIM_KIND,
        "claim_kind": _CLAIM_KIND,
        "claim_text": _claim_text(spec),
        "confidence": "1",
        "source_sha256": "a" * 64,
        "span": {
            "schema_version": "1",
            "byte_start": 0,
            "byte_end": 1,
            "span_sha256": "b" * 64,
            "page_start": None,
            "page_end": None,
            "time_start_ms": None,
            "time_end_ms": None,
        },
        "derived_from": (),
        "text_ref": None,
        "chunk_ref": None,
        "embedding_ref": None,
        "tags": (),
    }
    assert ExtractedEvidenceV1.model_validate(evidence).claim_kind == _CLAIM_KIND
    with pytest.raises(StrategyIngestError):
        ExtractedEvidenceV1.model_validate({**evidence, "claim_kind": "unknown-content-claim"})

    longest_identifier = "s" + "x" * 127
    max_length_claim = canonical_json(
        {
            "schema_version": "strat.strategy-content-claim/1",
            "strategy_ref": longest_identifier,
            "strategy_id": longest_identifier,
            "strategy_version": longest_identifier,
            "strategy_content_sha256": "a" * 64,
            "dataset_id": longest_identifier,
            "dataset_version": longest_identifier,
            "bars_sha256": "b" * 64,
            "execution_inputs_sha256": "c" * 64,
        }
    ).decode("utf-8")
    assert len(max_length_claim) > 512
    assert len(max_length_claim) <= 1200
    assert (
        ExtractedEvidenceV1.model_validate({**evidence, "claim_text": max_length_claim}).claim_text
        == max_length_claim
    )

    with pytest.raises(StrategyIngestError):
        ExtractedEvidenceV1.model_validate({**evidence, "claim_text": "x" * 1201})
    with pytest.raises(StrategyIngestError):
        ExtractedEvidenceV1.model_validate(
            {
                **evidence,
                "claim_key": "strategy_identity",
                "claim_kind": "strategy_identity",
                "claim_text": "x" * 513,
            }
        )
