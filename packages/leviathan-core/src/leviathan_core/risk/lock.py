"""Risk-lock guardian primitives.

The sovereign risk limits live in an immutable YAML file
(infra/risk/risk_governance.lock.yaml). Before any order is routed, the
guardian verifies the file's SHA-256 against the expected master hash.
On mismatch, order routing is refused — no exceptions, no overrides.
"""

import hashlib
from pathlib import Path


class RiskLockError(Exception):
    """Risk lock file is missing or its hash does not match the master."""


def compute_lock_sha256(lock_path: Path) -> str:
    if not lock_path.is_file():
        raise RiskLockError(f"risk lock file not found: {lock_path}")
    return hashlib.sha256(lock_path.read_bytes()).hexdigest()


def verify_risk_lock(lock_path: Path, expected_sha256: str) -> None:
    if not expected_sha256:
        raise RiskLockError("expected risk-lock SHA-256 is empty — refusing to trade blind")
    actual = compute_lock_sha256(lock_path)
    if actual != expected_sha256.lower():
        raise RiskLockError(
            f"risk lock hash mismatch: expected {expected_sha256}, got {actual}. "
            "Order routing is refused until the lock is restored."
        )
