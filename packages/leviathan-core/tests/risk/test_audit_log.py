"""A failed audit write must not expose an uncommitted final verdict."""

import os
from pathlib import Path

import pytest

from leviathan_core.risk import audit as audit_module
from leviathan_core.risk.audit import RiskAuditError, RiskAuditLog
from leviathan_core.schemas import RiskAction, RiskVerdict


def test_fsync_failure_leaves_only_the_committed_nonfinal_assessment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    audit = RiskAuditLog(tmp_path / "audit.jsonl")
    verdict = RiskVerdict(
        decision_id="decision-test",
        action=RiskAction.ALLOW,
        reason="verified",
        execution_capable=True,
    )
    audit.record(verdict, final=False)

    def fail_fsync(_fd: int) -> None:
        raise OSError("synthetic fsync failure")

    monkeypatch.setattr(audit_module.os, "fsync", fail_fsync)
    with pytest.raises(RiskAuditError):
        audit.record(verdict, phase="route_recheck", seq=2, final=True)

    entries = audit.entries()
    assert len(entries) == 1
    assert entries[0]["phase"] == "assessment"
    assert entries[0]["final"] is False


def test_audit_commit_is_readable(tmp_path: Path) -> None:
    audit = RiskAuditLog(tmp_path / "audit.jsonl")
    verdict = RiskVerdict(decision_id="decision-test", action=RiskAction.REJECT, reason="blocked")
    audit.record(verdict)
    assert audit.entries()[0]["final"] is False
    assert audit.entries()[0]["legacy_final"] is True
    assert audit.entries()[0]["authority"] == "legacy_unverified"
    assert os.path.isfile(tmp_path / "audit.jsonl")


def test_quarantined_audit_refuses_new_final_entries(tmp_path: Path) -> None:
    audit = RiskAuditLog(tmp_path / "audit.jsonl")
    verdict = RiskVerdict(
        decision_id="decision-test", action=RiskAction.ALLOW, reason="preliminary"
    )
    audit.record(verdict)
    audit.quarantine()

    assert audit.entries() == []
    assert (tmp_path / "audit.jsonl.quarantine").is_file()
    with pytest.raises(RiskAuditError, match="quarantined"):
        audit.record(verdict)
