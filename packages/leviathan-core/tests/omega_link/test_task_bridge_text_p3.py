"""Regression coverage for OMEGA task-context text boundaries."""

from __future__ import annotations

import base64
import json
from time import process_time

import pytest

from leviathan_core.omega_link.task_bridge import (
    MAX_SOURCE_REF_CHARS,
    MAX_SOURCE_REF_COUNT,
    MAX_SOURCE_REFS_CHARS,
    HandoffRequestV1,
    TaskBridgeError,
    _contains_credential_value,
)


def _compact_token(header: dict[str, str], *, signature: str | None) -> str:
    def encode(value: object) -> str:
        raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    prefix = f"{encode(header)}.{encode({'sub': 'synthetic'})}"
    return prefix if signature is None else f"{prefix}.{signature}"


def _request(context: dict[str, object], *, task_type: str = "research") -> HandoffRequestV1:
    return HandoffRequestV1(
        type=task_type,
        priority="normal",
        assigned_to="agent-1",
        ttl_ms=1_000,
        sla_ms=1_000,
        context=context,
    )


def _assert_content_free_denial(context: dict[str, object], expected_code: str) -> None:
    request = _request(context)
    with pytest.raises(TaskBridgeError) as caught:
        request.canonical_context()
    assert caught.value.code == expected_code
    assert caught.value.args == (expected_code,)
    rendered = f"{caught.value!s} {caught.value!r} {caught.value.args!r}"

    def strings(value: object) -> list[str]:
        if type(value) is str:
            return [value]
        if type(value) is dict:
            return [part for item in value.items() for part in strings(item)]
        if type(value) in {list, tuple}:
            return [part for item in value for part in strings(item)]
        return []

    assert all(not candidate or candidate not in rendered for candidate in strings(context))


@pytest.mark.parametrize(
    "token",
    (
        _compact_token({"alg": "none"}, signature=""),
        _compact_token({"alg": "RS256"}, signature=None),
        _compact_token({"alg": "RS256"}, signature="x"),
        _compact_token({"alg": "RS256"}, signature="short"),
    ),
    ids=("unsigned-alg-none", "two-segment", "one-char-signature", "short-signature"),
)
def test_compact_jwt_variants_are_denied_without_echo(token: str) -> None:
    _assert_content_free_denial({"question": f"research this {token}"}, "CONTEXT_SECRET_DENIED")


@pytest.mark.parametrize("wrapper", ("{}.", "session-{}", "session_{}"))
def test_jwt_with_sentence_or_identifier_separator_is_denied(wrapper: str) -> None:
    token = _compact_token({"alg": "RS256"}, signature="eA")
    _assert_content_free_denial({"question": wrapper.format(token)}, "CONTEXT_SECRET_DENIED")


@pytest.mark.parametrize(
    "text",
    (
        "matplotlib.pyplot.figure",
        "statsmodels.regression.linear_model",
        "https://docs.example.invalid/pipeline.guide.page",
        "configuration.environment.production",
    ),
)
def test_ordinary_dotted_prose_remains_accepted(text: str) -> None:
    _request({"question": text}).canonical_context()


@pytest.mark.parametrize(
    "secret",
    (
        "sk-syntheticSecretValue012345",
        "github_pat_syntheticSecretValue012345",
        "ghu_syntheticSecretValue012345",
        "ghr_syntheticSecretValue012345",
        "glpat-syntheticSecretValue012345",
        "AIzaSyntheticSecretValue01234567890",
        "xoxe-synthetic-secret-value-012345",
    ),
)
def test_additional_credential_families_are_denied(secret: str) -> None:
    _assert_content_free_denial({"question": secret}, "CONTEXT_SECRET_DENIED")


def test_source_refs_accept_exact_aggregate_boundary() -> None:
    refs = ["r" * MAX_SOURCE_REF_CHARS for _ in range(MAX_SOURCE_REF_COUNT)]
    assert sum(map(len, refs)) == MAX_SOURCE_REFS_CHARS
    _request({"source_refs": refs}).canonical_context()


@pytest.mark.parametrize(
    "refs",
    (
        ["r" * (MAX_SOURCE_REF_CHARS + 1)],
        ["r" * MAX_SOURCE_REF_CHARS for _ in range(MAX_SOURCE_REF_COUNT + 1)],
        ["r" * MAX_SOURCE_REF_CHARS for _ in range(MAX_SOURCE_REF_COUNT - 1)]
        + ["r" * (MAX_SOURCE_REF_CHARS + 1)],
        ["r" * MAX_SOURCE_REF_CHARS, {"ref": "nested"}],
    ),
    ids=("item-too-long", "count-exceeds-aggregate", "aggregate-over-bound", "not-a-string-ref"),
)
def test_source_refs_reject_out_of_schema_values(refs: list[object]) -> None:
    _assert_content_free_denial({"source_refs": refs}, "CONTEXT_SCHEMA_DENIED")


def test_closed_context_schema_is_primary_and_scanner_is_a_backstop() -> None:
    # Unknown fields are rejected by the closed schema before value scanning.
    _assert_content_free_denial(
        {"unknown": "sk-syntheticSecretValue012345"}, "CONTEXT_SCHEMA_DENIED"
    )
    # Known bounded free text is additionally scanned for credential-shaped values.
    _assert_content_free_denial(
        {"question": "sk-syntheticSecretValue012345"}, "CONTEXT_SECRET_DENIED"
    )
    _request({"max_tokens": 100, "question": "ordinary research prompt"}).canonical_context()


@pytest.mark.parametrize(
    "adversarial_text",
    (
        "eyJ." * 16_384,
        "a." * 32_768,
        "a-" * 32_768,
    ),
    ids=("jwt-prefix-repeat", "dotted-text", "hyphenated-text"),
)
def test_scanner_time_is_bounded_for_65k_adversarial_text(adversarial_text: str) -> None:
    assert len(adversarial_text) == 65_536
    started = process_time()
    assert not _contains_credential_value(adversarial_text)
    elapsed = process_time() - started
    assert elapsed < 0.1
