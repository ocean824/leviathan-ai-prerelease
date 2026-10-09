"""Independent acceptance for the scribe's safe display-label policy."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pytest
import test_scribe_acceptance as scribe_fixtures

from leviathan_core.agent_council.publication_models import require_manifest
from leviathan_core.agent_council.state_models import ExperimentSpecV1, HypothesisV1

_LABEL = re.compile(
    r"(?=.{1,40}\Z)(?:UNLABELLED|[A-Za-z]{1,16}\d{0,3}(?:[ -][A-Za-z]{1,16}\d{0,3}){0,2})\Z"
)
_SECRET_NAMES = (
    "postgresql://admin:CANARY_DBPASS@db.internal:5432/prod",
    "sk_live_CANARYKEY0123456789abcdef",
    "ghp_CANARY0123456789abcdef0123456789",
    "xoxb-123456789012-1234567890123-CANARYTOKEN",
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJDQU5BUlkifQ.SIGNATURECANARY",
    "Authorization header Bearer CANARYTOKEN0123456789",
    "the password is CANARY_TEXT_SECRET",
    "https://db.internal/?api_key=CANARY_QUERY_SECRET",
    "password=CANARY_ASSIGNMENT_SECRET",
)


def _outputs(result: object, manifest: object, files: dict[str, bytes]) -> tuple[bytes, ...]:
    return (
        result.model_dump_json().encode("utf-8"),  # type: ignore[attr-defined]
        manifest.model_dump_json().encode("utf-8"),  # type: ignore[attr-defined]
        *files.values(),
    )


def test_safe_label_is_whole_string_and_free_text_hashes_are_absent(
    tmp_path: Path,
) -> None:
    strategy_name = "Momentum Alpha"
    signal_version = "release-7"
    inputs = scribe_fixtures._publish_inputs(
        strategy_name=strategy_name,
        signal_version=signal_version,
    )
    service, vault = scribe_fixtures._service(tmp_path)

    result = scribe_fixtures._publish(service, inputs)

    manifest = require_manifest(result.manifest)
    published = vault.bytes_by_relative_path()
    output = _outputs(result, manifest, published)
    output_text = b"\n".join(output).decode("latin1")
    hypothesis_doc = published[f"{manifest.session_id}/hypothesis.md"].decode("utf-8")
    tldr = published[f"{manifest.session_id}/TLDR.md"].decode("utf-8")
    summary_json = hypothesis_doc.split("```json\n", 1)[1].split("\n```", 1)[0]
    assert _LABEL.fullmatch(manifest.display_label)
    assert manifest.display_label == strategy_name
    assert manifest.display_label_source == "strategy_name"
    summary = json.loads(summary_json)
    assert summary["display_label"] == strategy_name
    assert summary["display_label_source"] == "strategy_name"
    assert f"Display label: {strategy_name} (strategy name)" in tldr
    assert "character_count" not in output_text
    free_text = (
        strategy_name,
        signal_version,
        "close-v1",
        "SYNTH",
        "sharpe_ratio",
    )
    for value in free_text:
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest().encode("ascii")
        assert all(digest not in content for content in output)


def test_unusable_candidates_publish_only_the_fixed_unlabelled_marker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_hypothesis = scribe_fixtures.hypothesis
    original_experiment = scribe_fixtures.experiment

    def no_safe_label(*, strategy_name: str, signal_version: str) -> HypothesisV1:
        base = original_hypothesis(
            strategy_name=strategy_name,
            signal_version=signal_version,
        )
        payload = base.model_dump(mode="python")
        payload["markets"] = ("API",)
        payload["target_metrics"] = ("secret",)
        payload["signal_refs"] = ({"signal_id": "AKIA-Key", "version": "1"},)
        return HypothesisV1.model_validate(payload)

    def matching_experiment(*, signal_version: str) -> ExperimentSpecV1:
        run = original_experiment(signal_version=signal_version)
        run_payload = run.model_dump(mode="python")
        run_payload["signal_refs"] = ({"signal_id": "AKIA-Key", "version": signal_version},)
        return ExperimentSpecV1.model_validate(run_payload)

    monkeypatch.setattr(scribe_fixtures, "experiment", matching_experiment)
    monkeypatch.setattr(scribe_fixtures, "hypothesis", no_safe_label)
    inputs = scribe_fixtures._publish_inputs(strategy_name="SK-Live-R4ndom")
    service, vault = scribe_fixtures._service(tmp_path)

    result = scribe_fixtures._publish(service, inputs)

    manifest = require_manifest(result.manifest)
    output = b"\n".join(_outputs(result, manifest, vault.bytes_by_relative_path()))
    assert manifest.display_label == "UNLABELLED"
    assert manifest.display_label_source == "market_symbol"
    assert b"Display label: UNLABELLED (market symbol)" in output
    assert b"sk-live-r4ndom" not in output.lower()
    assert b"akia-key" not in output.lower()


@pytest.mark.parametrize("secret", _SECRET_NAMES)
def test_secret_bearing_strategy_names_never_appear_in_publication(
    tmp_path: Path,
    secret: str,
) -> None:
    strategy_name = f"Research strategy notes include {secret}; synthetic narrative"
    inputs = scribe_fixtures._publish_inputs(strategy_name=strategy_name)
    service, vault = scribe_fixtures._service(tmp_path)

    result = scribe_fixtures._publish(service, inputs)

    manifest = require_manifest(result.manifest)
    output = _outputs(result, manifest, vault.bytes_by_relative_path())
    serialized = b"\n".join(output)
    assert manifest.display_label == "SYNTH"
    assert manifest.display_label_source == "market_symbol"
    assert b"Display label: SYNTH (market symbol)" in b"\n".join(output)
    assert all(strategy_name.encode("utf-8") not in content for content in output)
    assert all(secret.casefold().encode("utf-8") not in content.lower() for content in output)
    assert b"canary" not in serialized.lower()
    for value in (secret, strategy_name):
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest().encode("ascii")
        assert all(digest not in content for content in output)


@pytest.mark.parametrize(
    ("candidate", "expected"),
    (
        ("Momentum-Alpha V2", "Momentum-Alpha V2"),
        ("Alpha1 Beta20 Gamma300", "Alpha1 Beta20 Gamma300"),
        ("Alpha7", "Alpha7"),
        ("Momentum Alpha Delta Echo", "SYNTH"),
        ("A" * 17, "SYNTH"),
        ("Momentum--Alpha", "SYNTH"),
        ("Momentum  Alpha", "SYNTH"),
        ("Alpha1234", "SYNTH"),
    ),
)
def test_display_label_uses_revised_closed_grammar(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    candidate: str,
    expected: str,
) -> None:
    original_hypothesis = scribe_fixtures.hypothesis

    def candidate_hypothesis(*, strategy_name: str, signal_version: str) -> HypothesisV1:
        base = original_hypothesis(
            strategy_name=strategy_name,
            signal_version=signal_version,
        )
        payload = base.model_dump(mode="python")
        payload["strategy_name"] = candidate
        return HypothesisV1.model_validate(payload)

    monkeypatch.setattr(scribe_fixtures, "hypothesis", candidate_hypothesis)
    inputs = scribe_fixtures._publish_inputs(strategy_name="Synthetic Label Test")
    service, vault = scribe_fixtures._service(tmp_path)

    result = scribe_fixtures._publish(service, inputs)

    manifest = require_manifest(result.manifest)
    published = vault.bytes_by_relative_path()
    output = _outputs(result, manifest, published)
    assert _LABEL.fullmatch(manifest.display_label)
    assert manifest.display_label == expected
    if expected != candidate:
        assert all(candidate.encode("utf-8") not in content for content in output)
        digest = hashlib.sha256(candidate.encode("utf-8")).hexdigest().encode("ascii")
        assert all(digest not in content for content in output)


@pytest.mark.parametrize(
    "candidate",
    (
        "ApiKey",
        "PasswdVault",
        "BearerPlan",
        "AuthCenter",
        "AKIA-ABCD123",
        "GHP-Client",
        "XOX-Chat",
        "SK-Live-R4ndom",
        "Random-Token",
        "AKIA-Key",
    ),
)
def test_compounded_and_split_secret_markers_are_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    candidate: str,
) -> None:
    original_hypothesis = scribe_fixtures.hypothesis

    def candidate_hypothesis(*, strategy_name: str, signal_version: str) -> HypothesisV1:
        base = original_hypothesis(
            strategy_name=strategy_name,
            signal_version=signal_version,
        )
        payload = base.model_dump(mode="python")
        payload["strategy_name"] = candidate
        return HypothesisV1.model_validate(payload)

    monkeypatch.setattr(scribe_fixtures, "hypothesis", candidate_hypothesis)
    inputs = scribe_fixtures._publish_inputs(strategy_name="Synthetic Label Test")
    service, vault = scribe_fixtures._service(tmp_path)

    result = scribe_fixtures._publish(service, inputs)

    manifest = require_manifest(result.manifest)
    output = _outputs(result, manifest, vault.bytes_by_relative_path())
    assert manifest.display_label == "SYNTH"
    assert all(candidate.casefold().encode("utf-8") not in item.lower() for item in output)
    digest = hashlib.sha256(candidate.encode("utf-8")).hexdigest().encode("ascii")
    assert all(digest not in item for item in output)


@pytest.mark.parametrize(
    "candidate",
    ("pass-wd", "my secretary", "my-secretary", "passwordless", "MySecretPlan", "PasswordManager"),
)
def test_whole_word_policy_preserves_non_secret_substrings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    candidate: str,
) -> None:
    original_hypothesis = scribe_fixtures.hypothesis

    def candidate_hypothesis(*, strategy_name: str, signal_version: str) -> HypothesisV1:
        base = original_hypothesis(
            strategy_name=strategy_name,
            signal_version=signal_version,
        )
        payload = base.model_dump(mode="python")
        payload["strategy_name"] = candidate
        return HypothesisV1.model_validate(payload)

    monkeypatch.setattr(scribe_fixtures, "hypothesis", candidate_hypothesis)
    inputs = scribe_fixtures._publish_inputs(strategy_name="Synthetic Label Test")
    service, vault = scribe_fixtures._service(tmp_path)

    result = scribe_fixtures._publish(service, inputs)

    manifest = require_manifest(result.manifest)
    output = _outputs(result, manifest, vault.bytes_by_relative_path())
    assert manifest.display_label == candidate
    assert any(candidate.encode("utf-8") in item for item in output)


@pytest.mark.parametrize(
    ("source", "label", "rendered_source"),
    (
        ("strategy_name", "Momentum-Alpha V2", "strategy name"),
        ("market_symbol", "SYNTH", "market symbol"),
        ("target_metric", "Sharpe V2", "target metric"),
        ("signal_id", "close-v1", "signal id"),
    ),
)
def test_manifest_and_rendered_label_identify_the_selected_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    source: str,
    label: str,
    rendered_source: str,
) -> None:
    original_hypothesis = scribe_fixtures.hypothesis
    original_experiment = scribe_fixtures.experiment
    selected_signal_id = label if source == "signal_id" else "Random-Token"

    def selected_candidate(*, strategy_name: str, signal_version: str) -> HypothesisV1:
        base = original_hypothesis(
            strategy_name=strategy_name,
            signal_version=signal_version,
        )
        payload = base.model_dump(mode="python")
        payload["strategy_name"] = label if source == "strategy_name" else "Random-Token"
        payload["markets"] = (label,) if source == "market_symbol" else ("AKIA-Key",)
        payload["target_metrics"] = (label,) if source == "target_metric" else ("ApiKey",)
        payload["signal_refs"] = ({"signal_id": selected_signal_id, "version": "1"},)
        return HypothesisV1.model_validate(payload)

    def matching_experiment(*, signal_version: str) -> ExperimentSpecV1:
        run = original_experiment(signal_version=signal_version)
        run_payload = run.model_dump(mode="python")
        run_payload["signal_refs"] = ({"signal_id": selected_signal_id, "version": signal_version},)
        return ExperimentSpecV1.model_validate(run_payload)

    monkeypatch.setattr(scribe_fixtures, "experiment", matching_experiment)
    monkeypatch.setattr(scribe_fixtures, "hypothesis", selected_candidate)
    inputs = scribe_fixtures._publish_inputs(strategy_name="Synthetic Label Test")
    service, vault = scribe_fixtures._service(tmp_path)

    result = scribe_fixtures._publish(service, inputs)

    manifest = require_manifest(result.manifest)
    published = vault.bytes_by_relative_path()
    output = b"\n".join(_outputs(result, manifest, published))
    assert manifest.display_label == label
    assert manifest.display_label_source == source
    assert f"Display label: {label} ({rendered_source})".encode() in output
    hypothesis_doc = published[f"{manifest.session_id}/hypothesis.md"].decode("utf-8")
    summary_json = hypothesis_doc.split("```json\n", 1)[1].split("\n```", 1)[0]
    summary = json.loads(summary_json)
    assert summary["display_label"] == label
    assert summary["display_label_source"] == source
