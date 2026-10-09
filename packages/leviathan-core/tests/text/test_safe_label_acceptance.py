"""Independent acceptance checks for the shared safe-label policy."""

from __future__ import annotations

import csv
import re
from collections.abc import Callable
from pathlib import Path
from time import perf_counter

import pytest

from leviathan_core import mt_export_audit, mt_export_telemetry
from leviathan_core.agent_council import publication_models
from leviathan_core.text import safe_label
from leviathan_core.text.credential_patterns import (
    MAX_CREDENTIAL_SCAN_CHARS,
    contains_credential_value,
)
from leviathan_core.text.safe_label import contains_deny_word

REPO_ROOT = Path(__file__).resolve().parents[4]
FIXTURE_PATH = REPO_ROOT / "apps/terminal/src/shared/safeLabelCases.tsv"
SafePredicate = Callable[[object], bool]
COUNCIL_DISPLAY_LABEL: SafePredicate = publication_models.is_safe_display_label
ACCEPTED = ("risk", "desk", "risk-control", "fx-majors")
ACCEPTED_DISPLAY_ONLY = ("Alpha v2", "hunter2", "my secretary")
ACCEPTED_IDENTIFIER_ONLY = ("wave-2", "bridge-1")
ACCEPTED_BOTH = ("my-secretary", "passwordless", "MY-SECRETARY", "PASSWORDLESS")
REJECTED = (
    "password123",
    "my-secret2",
    "apikeyprod",
    "api-gateway",
    "my password",
    "MY PASSWORD",
    "secret",
    "SECRET",
    "sk_live",
    "ghp_x",
    "akia-secret",
    "API-GATEWAY",
)
CREDENTIAL_SHAPES = (
    "glpat-testfixturetoken",
    "pypi-testfixturetoken",
    "sk-testfixturetoken",
    "github_pat_testfixturetoken",
    "ghp_testfixturetoken",
    "xoxb-test-fixture-token",
    "AKIA000000000000TEST",
    "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJl",
)
EMBEDDED_CREDENTIAL_SHAPES = (
    "foo_glpat-testfixturetoken",
    "x_pypi-testfixturetoken",
    "a_ghp_testfixturetoken",
    "pre-sk-testfixturetoken",
    "a.github_pat_testfixturetoken",
    "x:xoxb-test-fixture-token",
)
SAFE_IDENTIFIER_CONTROLS = ("wave-2", "risk_control", "desk_1", "alpha-v2")
DENY_WORD_SEGMENTS = (
    "apikey",
    "api",
    "key",
    "secret",
    "token",
    "passwd",
    "password",
    "bearer",
    "auth",
    "akia",
    "ghp",
    "xox",
    "sk",
)
LONG_DIGIT_INPUTS = ("123456789", "123456789012")


def _fixtures() -> tuple[tuple[str, str, bool], ...]:
    with FIXTURE_PATH.open(encoding="utf-8", newline="") as stream:
        rows = tuple(csv.DictReader(stream, delimiter="\t"))
    assert rows, "shared safe-label fixture table must not be empty"
    assert set(rows[0]) == {"predicate", "value", "safe"}
    return tuple(
        (row["predicate"], row["value"], row["safe"] == "true")
        for row in rows
    )


@pytest.mark.parametrize("predicate,value,expected", _fixtures())
def test_python_matches_shared_fixture_table(
    predicate: str, value: str, expected: bool
) -> None:
    check = {
        "display": safe_label.is_safe_display_label,
        "identifier": safe_label.is_safe_identifier,
    }[predicate]
    assert check(value) is expected


@pytest.mark.parametrize("value", ACCEPTED)
@pytest.mark.parametrize(
    "check", (safe_label.is_safe_display_label, safe_label.is_safe_identifier)
)
def test_required_safe_examples_are_accepted(check: SafePredicate, value: str) -> None:
    assert check(value)


@pytest.mark.parametrize("value", ACCEPTED_DISPLAY_ONLY)
def test_coordinator_ruled_display_examples_are_accepted(value: str) -> None:
    assert safe_label.is_safe_display_label(value)


@pytest.mark.parametrize("value", ACCEPTED_IDENTIFIER_ONLY)
def test_coordinator_ruled_identifier_examples_are_accepted(value: str) -> None:
    assert safe_label.is_safe_identifier(value)


@pytest.mark.parametrize("value", ACCEPTED_BOTH)
@pytest.mark.parametrize(
    "check", (safe_label.is_safe_display_label, safe_label.is_safe_identifier)
)
def test_whole_word_prefixes_do_not_reject_larger_words(
    check: SafePredicate, value: str
) -> None:
    assert check(value)


@pytest.mark.parametrize("value", REJECTED)
@pytest.mark.parametrize(
    "check", (safe_label.is_safe_display_label, safe_label.is_safe_identifier)
)
def test_required_secret_examples_are_rejected(check: SafePredicate, value: str) -> None:
    assert not check(value)


@pytest.mark.parametrize("value", LONG_DIGIT_INPUTS)
@pytest.mark.parametrize(
    "check", (safe_label.is_safe_display_label, safe_label.is_safe_identifier)
)
def test_nine_or_more_digit_runs_are_rejected(check: SafePredicate, value: str) -> None:
    assert not check(value)


@pytest.mark.parametrize("value", CREDENTIAL_SHAPES)
def test_credential_family_shapes_are_rejected_as_identifiers(value: str) -> None:
    assert not safe_label.is_safe_identifier(value)


@pytest.mark.parametrize("value", EMBEDDED_CREDENTIAL_SHAPES)
def test_embedded_credential_family_shapes_are_rejected_as_identifiers(
    value: str,
) -> None:
    assert not safe_label.is_safe_identifier(value)


@pytest.mark.parametrize("value", SAFE_IDENTIFIER_CONTROLS)
def test_safe_identifier_controls_remain_accepted(value: str) -> None:
    assert safe_label.is_safe_identifier(value)


@pytest.mark.parametrize("segment", DENY_WORD_SEGMENTS)
@pytest.mark.parametrize("value_case", (str.lower, str.upper))
def test_contains_deny_word_matches_all_thirteen_whole_segments_case_insensitively(
    segment: str, value_case: Callable[[str], str]
) -> None:
    assert contains_deny_word(value_case(segment))


@pytest.mark.parametrize(
    "value,expected",
    (
        ("api_key_secret_review_canary", True),
        ("canary-api-review", True),
        ("canary.api.review", True),
        ("canary:api:review", True),
        ("canary/api/review", True),
        ("canary api review", True),
        ("risk_control", False),
        ("wave-2", False),
        ("desk_1", False),
    ),
)
def test_contains_deny_word_uses_its_own_segment_delimiters(
    value: str, expected: bool
) -> None:
    assert contains_deny_word(value) is expected


def test_token_bucket_is_a_deny_word_compound_but_valid_identifier() -> None:
    assert contains_deny_word("token_bucket")
    assert safe_label.is_safe_identifier("token_bucket")


def test_credential_scanner_is_bounded_at_64kib() -> None:
    adversarial = "x_" * (MAX_CREDENTIAL_SCAN_CHARS // 2)
    assert len(adversarial) == MAX_CREDENTIAL_SCAN_CHARS

    started = perf_counter()
    assert not contains_credential_value(adversarial)
    assert perf_counter() - started < 0.1

    assert contains_credential_value(adversarial + "x")


def test_hunter2_is_rejected_as_an_identifier() -> None:
    assert not safe_label.is_safe_identifier("hunter2")


def test_hunter2_remains_valid_as_a_display_label() -> None:
    assert safe_label.is_safe_display_label("hunter2")


def test_shared_table_contains_required_acceptance_cases() -> None:
    fixtures = {(predicate, value, expected) for predicate, value, expected in _fixtures()}
    for value in ACCEPTED:
        assert ("display", value, True) in fixtures
        assert ("identifier", value, True) in fixtures
    for value in ACCEPTED_DISPLAY_ONLY:
        assert ("display", value, True) in fixtures
    for value in ACCEPTED_IDENTIFIER_ONLY:
        assert ("identifier", value, True) in fixtures
        assert ("display", value, False) in fixtures
    for value in ACCEPTED_BOTH:
        assert ("display", value, True) in fixtures
        assert ("identifier", value, True) in fixtures
    assert ("display", "hunter2", True) in fixtures
    assert ("identifier", "hunter2", False) in fixtures
    for value in REJECTED:
        assert ("display", value, False) in fixtures
        assert ("identifier", value, False) in fixtures
    for value in CREDENTIAL_SHAPES:
        assert ("identifier", value, False) in fixtures
    for value in EMBEDDED_CREDENTIAL_SHAPES:
        assert ("identifier", value, False) in fixtures
    for value in SAFE_IDENTIFIER_CONTROLS:
        assert ("identifier", value, True) in fixtures
    for predicate in ("display", "identifier"):
        assert any(
            expected is False
            and max((len(run) for run in re.findall(r"[0-9]+", value)), default=0) >= 9
            for row_predicate, value, expected in _fixtures()
            if row_predicate == predicate
        )


@pytest.mark.parametrize(
    "predicate,consumer",
    (
        ("display", COUNCIL_DISPLAY_LABEL),
        ("identifier", mt_export_telemetry._safe_identifier),
    ),
)
def test_python_consumers_agree_with_shared_table(
    predicate: str, consumer: SafePredicate
) -> None:
    helper = {
        "display": safe_label.is_safe_display_label,
        "identifier": safe_label.is_safe_identifier,
    }[predicate]
    for kind, value, expected in _fixtures():
        if kind != predicate:
            continue
        if predicate == "identifier" and consumer is mt_export_telemetry._safe_identifier:
            legacy_gate = (
                type(value) is str
                and len(value) <= mt_export_telemetry._MAX_IDENTIFIER_CHARS
                and mt_export_telemetry._IDENTIFIER.fullmatch(value) is not None
            )
            assert consumer(value) is (legacy_gate and expected)
        else:
            assert consumer(value) is helper(value)


def test_council_display_label_consumer_uses_shared_helper() -> None:
    assert COUNCIL_DISPLAY_LABEL is safe_label.is_safe_display_label


def test_telemetry_identifier_consumer_delegates_after_legacy_syntax_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def deny(_value: object) -> bool:
        return False

    def allow(_value: object) -> bool:
        return True

    monkeypatch.setattr(mt_export_telemetry, "is_safe_identifier", deny)
    assert not mt_export_telemetry._safe_identifier("safe-id")
    monkeypatch.setattr(mt_export_telemetry, "is_safe_identifier", allow)
    assert mt_export_telemetry._safe_identifier("safe-id")


def test_audit_identifier_consumer_agrees_with_shared_table() -> None:
    for predicate, value, expected in _fixtures():
        if predicate != "identifier":
            continue
        assert mt_export_audit._identifier(value) is expected


def test_audit_identifier_consumer_delegates_after_its_syntax_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def deny(_value: object) -> bool:
        return False

    def allow(_value: object) -> bool:
        return True

    monkeypatch.setattr(mt_export_audit, "is_safe_identifier", deny)
    assert not mt_export_audit._identifier("safe-id")
    monkeypatch.setattr(mt_export_audit, "is_safe_identifier", allow)
    assert mt_export_audit._identifier("safe-id")
