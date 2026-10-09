"""Risk-lock guardian: SHA-256 verification of risk_governance.lock.yaml."""

from pathlib import Path

import pytest

from leviathan_core.risk import RiskLockError, compute_lock_sha256, verify_risk_lock

REPO_ROOT = Path(__file__).resolve().parents[3]
LOCK_FILE = REPO_ROOT / "infra" / "risk" / "risk_governance.lock.yaml"


def test_lock_file_exists_in_repo() -> None:
    assert LOCK_FILE.is_file(), "sovereign risk lock file must ship with the repo"


def test_verify_accepts_matching_hash() -> None:
    verify_risk_lock(LOCK_FILE, compute_lock_sha256(LOCK_FILE))


def test_verify_rejects_tampered_hash() -> None:
    with pytest.raises(RiskLockError, match="hash mismatch"):
        verify_risk_lock(LOCK_FILE, "0" * 64)


def test_verify_refuses_empty_expected_hash() -> None:
    with pytest.raises(RiskLockError, match="refusing to trade blind"):
        verify_risk_lock(LOCK_FILE, "")


def test_missing_lock_file_is_fatal(tmp_path: Path) -> None:
    with pytest.raises(RiskLockError, match="not found"):
        compute_lock_sha256(tmp_path / "nope.yaml")
