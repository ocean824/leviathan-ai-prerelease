"""The sidecar only mints a local principal from a matching shell launch binding."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from session_identity import session_identity_from_shell_env


def test_matching_shell_subject_and_entitlement_digest_issue_profile() -> None:
    features = "charts,live_trading,paper_trading"
    digest = hashlib.sha256(features.encode("utf-8")).hexdigest()
    profile, enabled = session_identity_from_shell_env("user-7", digest, features)
    assert profile is not None
    assert profile.principal_id == "user-7"
    assert enabled == frozenset({"charts", "live_trading", "paper_trading"})


def test_missing_or_changed_shell_binding_issues_no_principal() -> None:
    features = "live_trading"
    digest = hashlib.sha256(features.encode("utf-8")).hexdigest()
    for identity in (
        (None, digest, features),
        ("user-7", "0" * 64, features),
        ("user-7", digest, "paper_trading,live_trading"),
        ("user-7/forged", digest, features),
        ("user-7", digest, "live_trading,live_trading"),
    ):
        profile, enabled = session_identity_from_shell_env(*identity)
        assert profile is None
        assert enabled == frozenset()
