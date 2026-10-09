"""Independent acceptance for shared task-bridge credential patterns."""

from __future__ import annotations

import logging
from time import process_time

import pytest

from leviathan_core.omega_link import task_bridge
from leviathan_core.omega_link.task_bridge import HandoffRequestV1, TaskBridgeError
from leviathan_core.text.credential_patterns import contains_credential_value

CANONICAL_BASELINE_SOURCE_SHA256 = (
    "B4730C0924EE979709E6636C139C468EDA71B417A01D601B1D726CA1F1881672"
)


def _canonical_context(question: str) -> tuple[bytes | None, str]:
    request = HandoffRequestV1(
        **{
            "type": "research",
            "priority": "normal",
            "assigned_to": "agent.worker",
            "ttl_ms": 1_000,
            "sla_ms": 500,
            "context": {"question": question},
        }
    )
    return request.canonical_context()


def _assert_secret_denied_without_echo(
    question: str, marker: str, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.clear()
    with (
        caplog.at_level(logging.DEBUG),
        pytest.raises(TaskBridgeError) as caught,
    ):
        _canonical_context(question)

    error = caught.value
    assert error.code == "CONTEXT_SECRET_DENIED"
    assert error.status_code == 422
    surfaces = (str(error), repr(error), repr(error.args), repr(error.__cause__))
    assert all(marker not in surface for surface in surfaces)
    assert marker not in caplog.text


_SHARED_CREDENTIAL_CASES = [
    pytest.param("sk-0123456789abcdef0123456789abcdef", "sk-", id="sk-dash"),
    pytest.param("ghp_0123456789abcdef0123456789abcdef", "ghp_", id="github-personal"),
    pytest.param(
        "github_pat_11AA22BB33CC44DD55EE66FF77GG88HH99",
        "github_pat_",
        id="github-fine-grained",
    ),
    pytest.param("glpat-0123456789abcdef0123456789", "glpat-", id="gitlab"),
    pytest.param("xoxb-1234567890-1234567890-CANARYTOKEN", "xoxb-", id="slack-bot"),
    pytest.param("AKIA1234567890ABCDEF", "AKIA", id="aws-access-key"),
    pytest.param("ASIA1234567890ABCDEF", "ASIA", id="aws-session-key"),
    pytest.param("AIzaSyD0123456789abcdef0123456789", "AIza", id="google-api-key"),
    pytest.param(
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0dXJlMTIzNDU2Nzg",
        "eyJhbGciOiJIUzI1NiJ9",
        id="jwt",
    ),
    pytest.param(
        "pypi-AgEIcHlwaS5vcmcCAQAAAAA0bW9jay10b2tlbi1mb3ItdGVzdHM",
        "pypi-",
        id="pypi-new-family",
    ),
]


@pytest.mark.parametrize(("candidate", "marker"), _SHARED_CREDENTIAL_CASES)
def test_shared_credential_families_are_denied_content_free(
    candidate: str, marker: str, caplog: pytest.LogCaptureFixture
) -> None:
    _assert_secret_denied_without_echo(candidate, marker, caplog)


@pytest.mark.parametrize(
    "question",
    [
        "skilled researchers sketch ordinary prose about a skillset",
        "github_patience and glpatella are words, not credentials",
        "xoxology, AKIAsmith, ASIAN-American and AIzalea are near misses",
        "pypi is the package index; ordinary package prose is accepted",
        "A short dotted sentence with one.two.three is not a JWT.",
    ],
    ids=["sk-near-miss", "github-gitlab-near-miss", "provider-words", "pypi-prose", "dotted-prose"],
)
def test_safe_near_miss_words_and_ordinary_prose_remain_accepted(question: str) -> None:
    canonical, digest = _canonical_context(question)

    assert canonical is not None
    assert question.encode("utf-8") in canonical
    assert len(digest) == 64


def test_baseline_results_are_preserved_except_for_pypi() -> None:
    """Baseline captured from canonical source SHA recorded above."""
    baseline = {
        "sk-dash": "deny",
        "github-personal": "deny",
        "github-fine-grained": "deny",
        "gitlab": "deny",
        "slack-bot": "deny",
        "aws-access-key": "deny",
        "aws-session-key": "deny",
        "google-api-key": "deny",
        "jwt": "deny",
        "pypi-new-family": "accept",
    }
    changed_family = "pypi-new-family"

    for item in _SHARED_CREDENTIAL_CASES:
        candidate, _marker = item.values
        case_id = item.id
        try:
            _canonical_context(candidate)
            current = "accept"
        except TaskBridgeError as error:
            assert error.code == "CONTEXT_SECRET_DENIED"
            current = "deny"

        expected = "deny" if case_id == changed_family else baseline[case_id]
        assert current == expected


def test_bridge_has_no_private_credential_pattern_table() -> None:
    assert not hasattr(task_bridge, "_CONTEXT_VALUE_PATTERNS")


@pytest.mark.parametrize(
    "question",
    [
        "eyJ." * 16_384,
        ("dotted.text." * 5_462)[:65_536],
        "hyphenated-text-" * 4_096,
    ],
    ids=["jwt-separator", "dotted-text", "hyphenated-text"],
)
def test_credential_pattern_scan_stays_under_cpu_ceiling(question: str) -> None:
    assert len(question) == 65_536
    started = process_time()
    detected = contains_credential_value(question)
    elapsed = process_time() - started

    assert detected is False
    assert elapsed < 0.1
