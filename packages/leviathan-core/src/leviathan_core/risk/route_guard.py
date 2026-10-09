"""Read-only route guard for the sovereign lock, policy, freshness and kills."""

import hashlib
from datetime import timedelta
from pathlib import Path

import yaml

from leviathan_core.risk.lock import RiskLockError, compute_lock_sha256
from leviathan_core.risk.policy import RiskPolicy, load_risk_policy_bytes
from leviathan_core.schemas import GateFinding, RiskGateContext


class RouteGuard:
    def __init__(
        self,
        lock_path: Path,
        expected_lock_sha256: str,
        bound_policy_sha256: str | None = None,
    ) -> None:
        self._lock_path = lock_path
        self._expected_sha = expected_lock_sha256.lower()
        self._bound_policy_sha = bound_policy_sha256.lower() if bound_policy_sha256 else None

    def proves_policy(self, policy: RiskPolicy) -> bool:
        """Prove current policy content equals the pinned lock's parsed bytes."""
        if not self._expected_sha:
            return False
        try:
            lock_bytes = self._lock_path.read_bytes()
            if hashlib.sha256(lock_bytes).hexdigest() != self._expected_sha:
                return False
            return load_risk_policy_bytes(lock_bytes) == policy
        except (OSError, ValueError, UnicodeError, yaml.YAMLError):
            return False

    def check(self, context: RiskGateContext | None) -> tuple[GateFinding, ...]:
        """Return all route blockers in stable lock, context, kill, stream order."""
        findings: list[GateFinding] = []
        lock_exists = self._lock_path.is_file()
        if not lock_exists:
            findings.append(GateFinding.LOCK_MISSING)
        if not self._expected_sha:
            findings.append(GateFinding.LOCK_HASH_EMPTY)
        if (
            self._expected_sha
            and self._bound_policy_sha is not None
            and self._bound_policy_sha != self._expected_sha
        ):
            findings.append(GateFinding.LOCK_TAMPERED)
        if lock_exists and self._expected_sha:
            try:
                if compute_lock_sha256(self._lock_path) != self._expected_sha:
                    findings.append(GateFinding.LOCK_TAMPERED)
            except (OSError, RiskLockError):
                findings.append(GateFinding.LOCK_TAMPERED)

        if context is None or not context.required:
            findings.append(GateFinding.CONTEXT_MISSING)
            return tuple(dict.fromkeys(findings))

        kill_active = (
            context.kill.kill_expires_at is None
            or context.kill.kill_expires_at > context.as_of
        )
        if kill_active:
            if context.kill.global_kill:
                findings.append(GateFinding.GLOBAL_KILL)
            if any(item.provider in context.kill.killed_providers for item in context.required):
                findings.append(GateFinding.PROVIDER_KILL)

        for required in context.required:
            matches = (
                item for item in context.observed
                if (item.stream_id, item.symbol, item.provider)
                == (required.stream_id, required.symbol, required.provider)
            )
            observed = next(matches, None)
            if observed is None:
                findings.append(GateFinding.STREAM_UNKNOWN)
                continue
            timestamps = tuple(
                value for value in (observed.source_ts, observed.exchange_ts) if value is not None
            )
            if not timestamps:
                findings.append(GateFinding.STREAM_UNKNOWN)
                continue
            effective = max(timestamps)
            if context.as_of - effective > timedelta(milliseconds=context.max_staleness_ms):
                findings.append(GateFinding.STREAM_STALE)
            if abs(observed.received_at - effective) > timedelta(
                milliseconds=context.max_clock_skew_ms
            ):
                findings.append(GateFinding.CLOCK_SKEW)

        return tuple(dict.fromkeys(findings))
