from __future__ import annotations

from time import process_time

import pytest

from leviathan_core.text.credential_patterns import (
    MAX_CREDENTIAL_SCAN_CHARS,
    contains_credential_value,
)
from leviathan_core.text.safe_label import is_safe_display_label, is_safe_identifier


@pytest.mark.parametrize(
    "candidate",
    (
        "glpat-testfixturetoken",
        "pypi-testfixturetoken",
        "sk-testfixturetoken",
        "github_pat_testfixturetoken",
        "ghp_testfixturetoken",
        "xoxb-test-fixture-token",
        "AKIA000000000000TEST",
        "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJl",
    ),
)
def test_known_credential_families_are_rejected_from_text_and_labels(candidate: str) -> None:
    assert contains_credential_value(candidate)
    assert not is_safe_identifier(candidate)
    assert not is_safe_display_label(candidate)


@pytest.mark.parametrize(
    "candidate",
    (
        "foo_glpat-testfixturetoken",
        "x_pypi-testfixturetoken",
        "a_ghp_testfixturetoken",
        "pre-sk-testfixturetoken",
        "a.github_pat_testfixturetoken",
        "x:xoxb-test-fixture-token",
    ),
)
def test_underscore_does_not_hide_embedded_credential_families(candidate: str) -> None:
    assert not is_safe_identifier(candidate)


@pytest.mark.parametrize(
    "candidate",
    (
        "foo_glpat-testfixturetoken",
        "x_pypi-testfixturetoken",
        "a_ghp_testfixturetoken",
    ),
)
def test_regex_word_boundary_misses_underscore_prefixed_families(candidate: str) -> None:
    assert not contains_credential_value(candidate)


@pytest.mark.parametrize("candidate", ("wave-2", "risk_control", "desk_1", "alpha-v2"))
def test_safe_identifier_separators_remain_accepted(candidate: str) -> None:
    assert is_safe_identifier(candidate)


def test_identifier_suffix_scanning_is_bounded_by_identifier_grammar() -> None:
    candidate = "a_" * 62 + "desk"
    assert len(candidate) <= 128
    started = process_time()
    assert is_safe_identifier(candidate)
    assert process_time() - started < 0.1


@pytest.mark.parametrize(
    "candidate",
    (
        "eyJ." * 16_384,
        "a." * 32_768,
        "a-" * 32_768,
    ),
    ids=("jwt-prefix-repeat", "dotted-text", "hyphenated-text"),
)
def test_scanner_time_is_bounded_for_65k_adversarial_text(candidate: str) -> None:
    assert len(candidate) == MAX_CREDENTIAL_SCAN_CHARS
    started = process_time()
    assert not contains_credential_value(candidate)
    assert process_time() - started < 0.1


def test_scanner_fails_closed_above_its_bounded_input_size() -> None:
    assert contains_credential_value("x" * (MAX_CREDENTIAL_SCAN_CHARS + 1))
