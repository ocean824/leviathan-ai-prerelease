"""Regression tests for safe, bounded council publication labels."""

from __future__ import annotations

from decimal import Decimal
from types import SimpleNamespace
from typing import cast

import pytest

from leviathan_core.agent_council.scribe_service import _display_label, _render_hypothesis
from leviathan_core.agent_council.state_models import (
    CouncilStateV1,
    HypothesisV1,
    SignalRefV1,
    TimeWindowV1,
)


def _hypothesis(
    strategy_name: str,
    *,
    markets: tuple[str, ...] = ("SYNTH",),
    target_metrics: tuple[str, ...] = ("sharpe_ratio",),
    signal_id: str = "close-v1",
    signal_version: str = "version1",
) -> HypothesisV1:
    return HypothesisV1(
        hypothesis_id="hypothesis-private-id",
        version=1,
        strategy_name=strategy_name,
        signal_refs=(SignalRefV1(signal_id=signal_id, version=signal_version),),
        markets=markets,
        horizon=TimeWindowV1(start_ns=1, end_ns=10),
        target_metrics=target_metrics,
        max_leverage=Decimal("1"),
        max_loss_per_trade=Decimal("0.01"),
        seed_policy="fixed",
        seed=1,
        source_hashes=("a" * 64,),
    )


def test_display_label_accepts_only_bounded_closed_grammar() -> None:
    assert _display_label(_hypothesis("Momentum Alpha")) == ("Momentum Alpha", "strategy_name")
    assert _display_label(_hypothesis("A" * 64)) == ("SYNTH", "market_symbol")
    assert _display_label(_hypothesis("Momentum-Alpha")) == ("Momentum-Alpha", "strategy_name")
    assert _display_label(_hypothesis("Alpha-v2")) == ("Alpha-v2", "strategy_name")
    assert _display_label(_hypothesis("Risk3")) == ("Risk3", "strategy_name")


@pytest.mark.parametrize(
    "secret_text",
    (
        "postgresql://user:password@example.test/db",
        "sk_live_0123456789abcdef",
        "ghp_0123456789abcdef",
        "xoxb-0123456789abcdef",
        "eyJhbGci.eyJzdWIi.signature",
        "Bearer abcdef012345",
        "the password is hunter2",
        "api_key=secret-value",
        "credential token secret",
    ),
)
def test_free_text_is_never_rendered_or_hashed(secret_text: str) -> None:
    hypothesis = _hypothesis(secret_text, signal_id=secret_text, signal_version=secret_text)
    state = cast(CouncilStateV1, SimpleNamespace(hypothesis=hypothesis))
    rendered = _render_hypothesis(state).decode("utf-8")

    assert secret_text not in rendered
    assert "sha256" not in rendered.lower()
    assert '"display_label":"SYNTH"' in rendered
    assert '"display_label_source":"market_symbol"' in rendered
    assert "Display label: SYNTH (market symbol)" in rendered
    assert '"strategy_name":"redacted"' in rendered
    assert '"signal_refs":{"count":1,"summary":"redacted"}' in rendered


def test_unlabelled_when_every_candidate_fails_grammar() -> None:
    hypothesis = _hypothesis(
        "postgresql://db.example/private",
        markets=("sk_live_secret",),
        target_metrics=("xoxb-secret",),
        signal_id="Bearer",
    )

    assert _display_label(hypothesis) == ("UNLABELLED", "market_symbol")


def test_long_candidate_is_not_truncated_to_make_a_label() -> None:
    long_name = "Momentum " + "A" * 60
    hypothesis = _hypothesis(long_name, markets=("SAFE",))

    assert _display_label(hypothesis) == ("SAFE", "market_symbol")
    assert _display_label(
        _hypothesis("postgresql://db.example/x", markets=("?",), signal_id="?")
    ) == (
        "UNLABELLED",
        "market_symbol",
    )


@pytest.mark.parametrize(
    "unsafe_label",
    (
        "sk9Xk2LmQp0rTz7 Ab3Cd4Ef5Gh6Ij7 Kl8Mn9Op0Qr1St2",
        "AKIAIOSFODNN7 EXAMPLE",
        "apiKey Alpha",
        "alpha-api-key",
        "passwd",
        "xox-secret",
        "sk9Example",
        "Alpha123Beta",
        "Alpha.Beta",
        "Mömentum Alpha",
    ),
)
def test_credential_markers_and_out_of_grammar_labels_fall_back(
    unsafe_label: str,
) -> None:
    assert _display_label(_hypothesis(unsafe_label)) == ("SYNTH", "market_symbol")


def test_whole_segment_policy_keeps_non_secret_prefix_words() -> None:
    assert _display_label(_hypothesis("ghpExample")) == ("ghpExample", "strategy_name")
    assert _display_label(_hypothesis("sketch")) == ("sketch", "strategy_name")


@pytest.mark.parametrize(
    "safe_label",
    ("pass-wd", "my secretary", "my-secretary", "passwordless", "MySecretPlan", "PasswordManager"),
)
def test_whole_word_policy_preserves_non_secret_substrings(safe_label: str) -> None:
    assert _display_label(_hypothesis(safe_label)) == (safe_label, "strategy_name")
