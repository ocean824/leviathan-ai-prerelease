"""Application state — the wired LEVIATHAN engine.

One AppState per process: sovereign risk stack (policy, halt authority,
audit log, veto engine), council, paper engine. Built once at startup;
routers pull it from FastAPI app.state.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from leviathan_api.settings import Settings, get_settings
from leviathan_core.decision.engine import CouncilDecisionEngine
from leviathan_core.execution.order_models import LedgerIntegrityKey
from leviathan_core.execution.paper_sim import PaperExecutionEngine
from leviathan_core.risk import (
    HaltAuthority,
    RiskAuditLog,
    RiskPolicy,
    RouteGuard,
    VetoEngine,
)
from leviathan_core.risk.halt_store import HaltStore
from leviathan_core.risk.policy import load_risk_policy_bytes

if TYPE_CHECKING:
    from leviathan_api.routers.orders import (
        OrderRuntime,
        PaperDispatchGate,
        _DispatchFence,
    )


def repo_root() -> Path:
    return Path(__file__).resolve().parents[4]


@dataclass
class AppState:
    settings: Settings
    policy: RiskPolicy
    halts: HaltAuthority
    audit: RiskAuditLog
    veto: VetoEngine
    council: CouncilDecisionEngine
    paper: PaperExecutionEngine
    lock_path: Path
    killed_providers: set[str] = field(default_factory=set)
    orders: OrderRuntime | None = None
    dispatch_fence: _DispatchFence | None = None
    dispatch_gate: PaperDispatchGate | None = None
    ledger_integrity_key: LedgerIntegrityKey | None = None


def build_app_state(
    settings: Settings | None = None,
    lock_path: Path | None = None,
    *,
    ledger_integrity_key: LedgerIntegrityKey | None = None,
) -> AppState:
    if ledger_integrity_key is not None and type(ledger_integrity_key) is not LedgerIntegrityKey:
        raise TypeError("ledger_integrity_key must be LedgerIntegrityKey or None")
    settings = settings or get_settings()
    root = repo_root()
    lock_path = lock_path or root / "infra" / "risk" / "risk_governance.lock.yaml"
    lock_bytes = lock_path.read_bytes()
    policy = load_risk_policy_bytes(lock_bytes)
    policy_sha256 = hashlib.sha256(lock_bytes).hexdigest()
    halt_path = settings.halt_store_path or root / "data" / "halt-state.sqlite3"
    store = HaltStore(halt_path, halt_path.parent)
    try:
        halts = HaltAuthority(store)
        audit = RiskAuditLog(root / "data" / "risk_audit.jsonl")
        veto = VetoEngine(
            policy=policy,
            halt_authority=halts,
            audit_log=audit,
            route_guard=RouteGuard(
                lock_path, settings.risk_lock_sha256, bound_policy_sha256=policy_sha256
            ),
        )
        return AppState(
            settings=settings,
            policy=policy,
            halts=halts,
            audit=audit,
            veto=veto,
            council=CouncilDecisionEngine(),
            paper=PaperExecutionEngine(),
            lock_path=lock_path,
            ledger_integrity_key=ledger_integrity_key,
        )
    except Exception:
        store.close()
        raise
