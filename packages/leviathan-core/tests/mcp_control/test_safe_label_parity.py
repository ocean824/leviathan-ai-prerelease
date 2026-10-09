"""The neutral policy helper must match the original publication grammar."""

import pytest

from leviathan_core.agent_council.publication_models import (
    is_safe_display_label as council_is_safe_display_label,
)
from leviathan_core.text.safe_label import is_safe_display_label


@pytest.mark.parametrize(
    "label",
    (
        "Aster-Node7-Team",
        "Safe Label3",
        "risk-control",
        "sketch",
        "MySecretKey",
        "skAlpha",
        "ghpAlpha",
        "xoxAlpha",
        "Pass-Word",
        "AKIAIOSFODNNEXAMPLE",
        "Cap-Id",
        "A" * 40,
        "A" * 38,
        "Aster--Node",
        "Aster_ Node",
        "Tokenish",
        "Safe-Apikey7",
    ),
)
def test_neutral_display_label_matches_publication_policy(label: str) -> None:
    assert is_safe_display_label(label) is council_is_safe_display_label(label)
