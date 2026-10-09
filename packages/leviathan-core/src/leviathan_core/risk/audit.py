"""Legacy JSONL risk diagnostic projection.

C-101 v0.4 uses route_attempts in SQLite as the sole authorization and final
outcome authority. These file entries, including pre-v0.4 final markers, are
unverified diagnostics and never permit simulation.
"""

import json
import os
import tempfile
import threading
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path
from typing import Any, Literal

from leviathan_core.schemas import GateFinding, RiskVerdict, utcnow


class RiskAuditError(OSError):
    """A risk decision could not be durably recorded."""


class RiskAuditRecheckError(Exception):
    """Authorization changed while the final audit event was being prepared."""

    def __init__(self, findings: tuple[GateFinding, ...]) -> None:
        super().__init__("risk route changed during audit write")
        self.findings = findings


class RiskAuditLog:
    def __init__(self, log_path: Path) -> None:
        self._path = log_path
        self._quarantine_path = log_path.with_name(f"{log_path.name}.quarantine")
        self._lock = threading.RLock()

    def record(
        self,
        verdict: RiskVerdict,
        context: dict[str, Any] | None = None,
        *,
        phase: Literal["assessment", "route_recheck"] = "assessment",
        seq: int = 1,
        final: bool = True,
        authorization_check: Callable[[], tuple[GateFinding, ...]] | None = None,
    ) -> None:
        entry = {
            "at": utcnow().isoformat(),
            "decision_id": verdict.decision_id,
            "phase": phase,
            "seq": seq,
            "final": final,
            "action": verdict.action.value,
            "reason": verdict.reason,
            "findings": [finding.value for finding in verdict.findings],
            "adjusted_size": str(verdict.adjusted_size) if verdict.adjusted_size else None,
            "halts_engaged": list(verdict.halts_engaged),
            "context": context or {},
        }
        line = (json.dumps(entry, separators=(",", ":")) + "\n").encode("utf-8")
        # Publish only after the candidate file is durable and the last
        # authorization check has passed. A failed fsync cannot expose final=true.
        with self._lock:
            if self._quarantine_path.exists():
                raise RiskAuditError("risk audit is quarantined pending operator review")
            try:
                previous = self._path.read_bytes() if self._path.exists() else b""
            except OSError as exc:
                raise RiskAuditError(f"risk audit read failed: {self._path}") from exc
            self._publish(previous + line, authorization_check)

    def reconcile_final(self, verdict: RiskVerdict) -> None:
        """Amend the unconsumed route final when authorization changes before intent."""
        with self._lock:
            if self._quarantine_path.exists():
                raise RiskAuditError("risk audit is quarantined pending operator review")
            try:
                lines = self._path.read_bytes().splitlines(keepends=True)
                last = json.loads(lines[-1])
                if (
                    last["decision_id"] != verdict.decision_id
                    or last["phase"] != "route_recheck"
                    or last["final"] is not True
                    or last["action"] not in ("allow", "reduce_size")
                    or verdict.action.value in ("allow", "reduce_size")
                ):
                    raise RiskAuditError("latest final does not match route decision")
                context = last.get("context")
                if not isinstance(context, dict):
                    context = {}
                context["pre_intent_reconciliation"] = {
                    "action": last["action"],
                    "reason": last["reason"],
                }
                last.update(
                    action=verdict.action.value,
                    reason=verdict.reason,
                    findings=[finding.value for finding in verdict.findings],
                    adjusted_size=(str(verdict.adjusted_size) if verdict.adjusted_size else None),
                    halts_engaged=list(verdict.halts_engaged),
                    context=context,
                )
                updated = (json.dumps(last, separators=(",", ":")) + "\n").encode("utf-8")
                payload = b"".join(lines[:-1]) + updated
            except (OSError, IndexError, KeyError, ValueError) as exc:
                raise RiskAuditError("risk audit final reconciliation failed") from exc
            self._publish(payload, None)

    def quarantine(self) -> None:
        """Hide a final that could not be reconciled, retaining it for review."""
        with self._lock:
            try:
                os.replace(self._path, self._quarantine_path)
            except OSError as exc:
                raise RiskAuditError("risk audit quarantine failed") from exc

    def _publish(
        self,
        payload: bytes,
        authorization_check: Callable[[], tuple[GateFinding, ...]] | None,
    ) -> None:
        candidate: Path | None = None
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(
                mode="wb",
                dir=self._path.parent,
                prefix=f".{self._path.name}.",
                delete=False,
            ) as fh:
                candidate = Path(fh.name)
                fh.write(payload)
                fh.flush()
                os.fsync(fh.fileno())
            if authorization_check is not None:
                try:
                    findings = authorization_check()
                except Exception as exc:
                    raise RiskAuditError("risk authorization recheck failed") from exc
                if findings:
                    raise RiskAuditRecheckError(findings)
            os.replace(candidate, self._path)
        except RiskAuditRecheckError:
            raise
        except OSError as exc:
            raise RiskAuditError(f"risk audit write failed: {self._path}") from exc
        finally:
            if candidate is not None:
                with suppress(OSError):
                    candidate.unlink(missing_ok=True)

    def entries(self) -> list[dict[str, Any]]:
        with self._lock:
            if self._quarantine_path.exists():
                return []
            if not self._path.exists():
                return []
            entries: list[dict[str, Any]] = []
            for line in self._path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    entry = json.loads(line)
                    entry["legacy_final"] = bool(entry.get("final"))
                    entry["final"] = False
                    entry["authority"] = "legacy_unverified"
                    entries.append(entry)
            return entries
