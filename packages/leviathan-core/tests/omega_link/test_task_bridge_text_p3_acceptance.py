"""Independent P3 acceptance for OMEGA task-context text scanning and bounds."""

from __future__ import annotations

from time import process_time
from typing import Any

import pytest

from leviathan_core.omega_link.task_bridge import (
    MAX_SOURCE_REF_CHARS,
    MAX_SOURCE_REF_COUNT,
    MAX_SOURCE_REFS_CHARS,
    HandoffRequestV1,
    TaskBridgeError,
    _contains_credential_value,
)


def _canonical_context(
    context: dict[str, Any], *, task_type: str = "research"
) -> tuple[bytes | None, str]:
    request = HandoffRequestV1(
        **{
            "type": task_type,
            "priority": "normal",
            "assigned_to": "agent.worker",
            "ttl_ms": 1_000,
            "sla_ms": 500,
            "context": context,
        }
    )
    return request.canonical_context()


def _assert_denied_without_echo(
    context: dict[str, Any], *, code: str, marker: str, task_type: str = "research"
) -> None:
    with pytest.raises(TaskBridgeError) as caught:
        _canonical_context(context, task_type=task_type)

    error = caught.value
    assert error.code == code
    assert error.status_code == 422
    surfaces = (str(error), repr(error), repr(error.args), repr(error.__cause__))
    assert all(marker not in surface for surface in surfaces)


@pytest.mark.parametrize(
    ("candidate", "marker"),
    [
        (
            "eyJhbGciOiJub25lIn0.eyJzdWIiOiJzdWJqZWN0In0.",
            "eyJhbGciOiJub25lIn0",
        ),
        (
            "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzdWJqZWN0In0",
            "eyJhbGciOiJSUzI1NiJ9",
        ),
        (
            "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzdWJqZWN0In0.sig",
            "eyJhbGciOiJSUzI1NiJ9",
        ),
    ],
    ids=["alg-none-empty-signature", "two-part-jwt", "short-signature"],
)
def test_unsigned_incomplete_and_short_signature_jwts_are_rejected(
    candidate: str, marker: str
) -> None:
    _assert_denied_without_echo(
        {"question": candidate}, code="CONTEXT_SECRET_DENIED", marker=marker
    )


@pytest.mark.parametrize(
    ("candidate", "marker"),
    [
        (
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0dXJlMTIzNDU2Nzg.",
            "eyJhbGciOiJIUzI1NiJ9",
        ),
        (
            "session-eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0dXJlMTIzNDU2Nzg",
            "session-",
        ),
        (
            "session_eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0dXJlMTIzNDU2Nzg",
            "session_",
        ),
    ],
    ids=["terminal-full-stop", "session-hyphen-prefix", "session-underscore-prefix"],
)
def test_valid_jwt_terminal_and_session_wrappers_are_rejected_without_echo(
    candidate: str, marker: str
) -> None:
    _assert_denied_without_echo(
        {"question": candidate}, code="CONTEXT_SECRET_DENIED", marker=marker
    )


@pytest.mark.parametrize(
    "candidate",
    [
        "eyJ." * 16_384,
        ("dotted.text." * 5_462)[:65_536],
        "hyphenated-text-" * 4_096,
    ],
    ids=["repeated-eyj-separator", "dotted-prose", "hyphenated-prose"],
)
def test_credential_scanner_handles_65kb_inputs_with_bounded_cpu_time(candidate: str) -> None:
    assert len(candidate) == 65_536

    start = process_time()
    detected = _contains_credential_value(candidate)
    elapsed = process_time() - start

    assert detected is False
    assert elapsed < 0.1


@pytest.mark.parametrize(
    "candidate",
    [
        "sk-0123456789abcdef0123456789abcdef",
        "github_pat_11AA22BB33CC44DD55EE66FF77GG88HH99",
        "ghu_0123456789abcdef0123456789",
        "ghr_0123456789abcdef0123456789",
        "glpat-0123456789abcdef0123456789",
        "AIzaSyD0123456789abcdef0123456789",
        "xoxe-0123456789abcdef0123456789",
    ],
    ids=[
        "sk-dash",
        "github-pat",
        "github-user",
        "github-refresh",
        "gitlab",
        "google",
        "slack-xoxe",
    ],
)
def test_additional_provider_tokens_are_rejected_without_echo(candidate: str) -> None:
    _assert_denied_without_echo(
        {"question": f"credential {candidate} seen"},
        code="CONTEXT_SECRET_DENIED",
        marker=candidate,
    )


def test_source_refs_accept_exact_aggregate_boundary() -> None:
    assert MAX_SOURCE_REF_COUNT == 16
    assert MAX_SOURCE_REF_CHARS == 512
    assert MAX_SOURCE_REFS_CHARS == 8_192
    refs = ["r" * MAX_SOURCE_REF_CHARS for _ in range(MAX_SOURCE_REF_COUNT)]

    canonical, digest = _canonical_context({"question": "bounded research", "source_refs": refs})

    assert canonical is not None
    assert len(refs) == MAX_SOURCE_REF_COUNT
    assert sum(map(len, refs)) == MAX_SOURCE_REFS_CHARS
    assert len(digest) == 64
    assert b'"source_refs"' in canonical


@pytest.mark.parametrize(
    ("refs", "marker"),
    [
        (
            ["x" * MAX_SOURCE_REF_CHARS] * MAX_SOURCE_REF_COUNT + ["overflow-ref-sentinel"],
            "overflow-ref-sentinel",
        ),
        (["x" * (MAX_SOURCE_REF_CHARS + 1)], "x" * (MAX_SOURCE_REF_CHARS + 1)),
        (["valid-ref", 17], "valid-ref"),
        (["valid-ref", {"uri": "nested-ref-sentinel"}], "nested-ref-sentinel"),
        (["valid-ref", ["nested-list-sentinel"]], "nested-list-sentinel"),
        (("valid-ref",), "valid-ref"),
    ],
    ids=[
        "too-many-refs-over-aggregate",
        "per-ref-length",
        "non-string",
        "nested-mapping",
        "nested-list",
        "tuple-is-not-a-list",
    ],
)
def test_source_refs_reject_count_item_and_non_string_shapes_without_echo(
    refs: list[object], marker: str
) -> None:
    _assert_denied_without_echo(
        {"question": "bounded research", "source_refs": refs},
        code="CONTEXT_SCHEMA_DENIED",
        marker=marker,
    )


@pytest.mark.parametrize(
    "question",
    [
        "matplotlib.pyplot.figure",
        "docs.example.invalid/pipeline.guide.page",
        "a plain research sentence with version 3.4.1",
    ],
)
def test_ordinary_dotted_text_and_host_paths_remain_accepted(question: str) -> None:
    canonical, digest = _canonical_context({"question": question})

    assert canonical is not None
    assert question.encode() in canonical
    assert len(digest) == 64


def test_question_length_boundary_and_max_tokens_remain_unchanged() -> None:
    canonical, _ = _canonical_context({"question": "q" * 2_000, "max_tokens": 100})

    assert canonical is not None
    assert b'"max_tokens":100' in canonical
    _assert_denied_without_echo(
        {"question": "q" * 2_001},
        code="CONTEXT_SCHEMA_DENIED",
        marker="q" * 2_001,
    )


@pytest.mark.parametrize(
    ("question", "marker"),
    [
        ("postgresql://user:CANARY_DB_PASSWORD@db.example/prod", "CANARY_DB_PASSWORD"),
        ("https://api.example.invalid/v1?api_key=CANARY_QUERY_KEY", "CANARY_QUERY_KEY"),
        ("use sk_live_CANARYKEY0123456789 now", "sk_live_CANARYKEY0123456789"),
        (
            "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJlMTIzNDU2Nzg",
            "eyJhbGciOiJSUzI1NiJ9",
        ),
        ("password=CANARY_PASSWORD", "CANARY_PASSWORD"),
        ("passwd: CANARY_PASSWD", "CANARY_PASSWD"),
        ("Cookie: session=CANARY_COOKIE", "CANARY_COOKIE"),
        ("Authorization: Bearer CANARY_AUTH_TOKEN", "CANARY_AUTH_TOKEN"),
        ("ghp_CANARY_GITHUB_TOKEN0123456789", "ghp_CANARY_GITHUB_TOKEN0123456789"),
        ("gho_CANARY_GITHUB_TOKEN0123456789", "gho_CANARY_GITHUB_TOKEN0123456789"),
        ("ghs_CANARY_GITHUB_TOKEN0123456789", "ghs_CANARY_GITHUB_TOKEN0123456789"),
        ("xoxb-1234567890-1234567890-CANARYTOKEN", "xoxb-1234567890-1234567890-CANARYTOKEN"),
        ("xoxa-1234567890-1234567890-CANARYTOKEN", "xoxa-1234567890-1234567890-CANARYTOKEN"),
        ("xoxp-1234567890-1234567890-CANARYTOKEN", "xoxp-1234567890-1234567890-CANARYTOKEN"),
        ("xoxr-1234567890-1234567890-CANARYTOKEN", "xoxr-1234567890-1234567890-CANARYTOKEN"),
        ("AKIA1234567890ABCDEF", "AKIA1234567890ABCDEF"),
        ("ASIA1234567890ABCDEF", "ASIA1234567890ABCDEF"),
        (
            "-----BEGIN PRIVATE KEY-----\nCANARY_PRIVATE_KEY\n-----END PRIVATE KEY-----",
            "CANARY_PRIVATE_KEY",
        ),
        (
            "https://hooks.slack.com/services/T00000000/B00000000/CANARYSLACKTOKEN123456",
            "CANARYSLACKTOKEN123456",
        ),
        (
            "https://discord.com/api/webhooks/123456789012345678/CANARYDISCORDTOKEN123456",
            "CANARYDISCORDTOKEN123456",
        ),
    ],
)
def test_prior_omega003_and_cl_text_secret_rejections_remain(question: str, marker: str) -> None:
    _assert_denied_without_echo(
        {"question": question},
        code="CONTEXT_SECRET_DENIED",
        marker=marker,
    )


def test_source_ref_secret_scan_remains_active() -> None:
    marker = "ghp_CANARYSOURCE0123456789"
    _assert_denied_without_echo(
        {"question": "review source", "source_refs": [f"ref {marker}"]},
        code="CONTEXT_SECRET_DENIED",
        marker=marker,
    )
