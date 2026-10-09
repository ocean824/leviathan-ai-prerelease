from __future__ import annotations

from pathlib import Path

import pytest

from leviathan_core.agent_council.publication_models import (
    is_safe_display_label as council_is_safe_display_label,
)
from leviathan_core.text.safe_label import (
    contains_deny_word,
    is_safe_display_label,
    is_safe_identifier,
)

_FIXTURE = (
    Path(__file__).resolve().parents[4]
    / "apps"
    / "terminal"
    / "src"
    / "shared"
    / "safeLabelCases.tsv"
)


def _cases() -> tuple[tuple[str, str, bool], ...]:
    rows = _FIXTURE.read_text(encoding="utf-8").splitlines()
    assert rows[0] == "predicate\tvalue\tsafe"
    return tuple(
        (predicate, value, expected == "true")
        for predicate, value, expected in (row.split("\t") for row in rows[1:])
    )


@pytest.mark.parametrize(("predicate", "value", "expected"), _cases())
def test_shared_fixture_cases(predicate: str, value: str, expected: bool) -> None:
    check = is_safe_display_label if predicate == "display" else is_safe_identifier
    assert check(value) is expected


def test_publication_model_delegates_to_neutral_helper() -> None:
    assert council_is_safe_display_label is is_safe_display_label


@pytest.mark.parametrize("value", ("api_key_secret_review_canary", "API_key_secret_review_canary"))
def test_contains_deny_word_matches_existing_lesson_19_segments(value: str) -> None:
    assert contains_deny_word(value)


@pytest.mark.parametrize(
    "segment",
    (
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
    ),
)
def test_contains_deny_word_covers_the_closed_lesson_19_segments(segment: str) -> None:
    assert contains_deny_word(segment)


@pytest.mark.parametrize("value", ("risk_control", "wave-2", "desk_1"))
def test_contains_deny_word_ignores_safe_segments(value: str) -> None:
    assert not contains_deny_word(value)


def test_contains_deny_word_does_not_change_identifier_policy() -> None:
    assert contains_deny_word("token_bucket")
    assert is_safe_identifier("token_bucket")


@pytest.mark.parametrize("value", (None, 1, True, [], {}, "éclair"))
def test_helpers_reject_non_strings_and_non_ascii(value: object) -> None:
    assert not is_safe_display_label(value)
    assert not is_safe_identifier(value)
