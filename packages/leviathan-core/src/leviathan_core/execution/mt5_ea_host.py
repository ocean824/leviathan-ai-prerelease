"""Local, demo-only hosting boundary for operator-supplied MetaTrader EAs.

This module validates and places opaque compiled files and their SET preset. It
never loads, starts, compiles, decompiles, or otherwise inspects an EA binary.
The terminal is always loaded by the operator. LIVE is not an available mode.
"""

from __future__ import annotations

import hashlib
import os
import re
import tempfile
import uuid
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from threading import RLock
from typing import Literal, Protocol, cast

from leviathan_core.execution.broker_port_v1 import (
    AccountViewV1,
    BrokerEnvironment,
    BrokerVenue,
    VenueIdentityV1,
    require_account_view,
    require_venue_identity,
)
from leviathan_core.execution.order_models import BrokerObservation
from leviathan_core.risk.halt import HaltAuthority
from leviathan_core.risk.halt_reasons import HaltReasonV1
from leviathan_core.seal._registry import Issuer
from leviathan_core.seal._registry import require as require_sealed
from leviathan_core.seal.errors import SealError
from leviathan_core.seal.model import SealedModel

TerminalFamily = Literal["MT4", "MT5"]
CapStatus = Literal["WITHIN_CAPS", "BREACH", "UNKNOWN"]

MAX_EA_BYTES = 64 * 1024 * 1024
MAX_SET_BYTES = 1024 * 1024
MAX_HTTP_BODY_BYTES = 90 * 1024 * 1024
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_. -]{0,94}[A-Za-z0-9_]\Z", re.ASCII)
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z", re.ASCII)
_SYMBOL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,31}\Z", re.ASCII)
_TIMEFRAMES = frozenset(
    {
        "M1",
        "M2",
        "M3",
        "M4",
        "M5",
        "M6",
        "M10",
        "M12",
        "M15",
        "M20",
        "M30",
        "H1",
        "H2",
        "H3",
        "H4",
        "H6",
        "H8",
        "H12",
        "D1",
        "W1",
        "MN1",
    }
)
_WINDOWS_RESERVED = frozenset(
    {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        *(f"COM{i}" for i in range(1, 10)),
        *(f"LPT{i}" for i in range(1, 10)),
    }
)
_ISSUER = Issuer("ea_hosting.v1")


class EaHostingError(ValueError):
    """Fixed-code, content-free failure at the EA hosting boundary."""

    __slots__ = ("code",)

    _CODES = frozenset(
        {
            "INVALID_EA_REQUEST",
            "INVALID_EA_FILE",
            "INVALID_SET_FILE",
            "FILE_TOO_LARGE",
            "DEMO_IDENTITY_REQUIRED",
            "FILESYSTEM_UNAVAILABLE",
            "SESSION_NOT_FOUND",
            "ACCOUNT_VIEW_UNKNOWN",
            "CAPS_UNKNOWN",
            "EA_KILL_OUTCOME_UNKNOWN",
            "UNISSUED_RESULT",
        }
    )

    def __init__(self, code: str) -> None:
        safe = code if type(code) is str and code in self._CODES else "INVALID_EA_REQUEST"
        self.code = safe
        super().__init__(safe)


@dataclass(frozen=True, slots=True)
class EaInstallRequestV1:
    ea_filename: str
    ea_bytes: bytes
    set_filename: str
    set_bytes: bytes
    terminal_family: TerminalFamily
    symbol: str
    timeframe: str


class EaFileSystemPortV1(Protocol):
    """One atomic pair-write seam; implementations must refuse link escapes."""

    def install_pair(
        self,
        *,
        root: Path,
        expert_relative_path: str,
        expert_bytes: bytes,
        preset_relative_path: str,
        preset_bytes: bytes,
    ) -> None: ...


class LocalEaFileSystemV1:
    """Atomic, contained pair writer for a user-configured terminal directory."""

    @staticmethod
    def _is_link(path: Path) -> bool:
        is_junction = getattr(os.path, "isjunction", None)
        return path.is_symlink() or bool(is_junction(path)) if is_junction else path.is_symlink()

    @classmethod
    def _parent(cls, root: Path, relative: str) -> tuple[Path, Path]:
        if type(relative) is not str or "\\" in relative or ":" in relative:
            raise EaHostingError("FILESYSTEM_UNAVAILABLE")
        pure = PurePosixPath(relative)
        if pure.is_absolute() or not pure.parts or any(p in {"", ".", ".."} for p in pure.parts):
            raise EaHostingError("FILESYSTEM_UNAVAILABLE")
        try:
            resolved_root = root.resolve(strict=True)
            if not resolved_root.is_dir():
                raise OSError
            current = resolved_root
            for part in pure.parts[:-1]:
                child = current / part
                if child.exists() or cls._is_link(child):
                    if cls._is_link(child) or not child.is_dir():
                        raise OSError
                else:
                    child.mkdir()
                resolved = child.resolve(strict=True)
                if resolved != resolved_root and resolved_root not in resolved.parents:
                    raise OSError
                current = resolved
            target = current / pure.parts[-1]
            if cls._is_link(target) or (target.exists() and not target.is_file()):
                raise OSError
            return current, target
        except EaHostingError:
            raise
        except Exception:
            raise EaHostingError("FILESYSTEM_UNAVAILABLE") from None

    @classmethod
    def install_pair(
        cls,
        *,
        root: Path,
        expert_relative_path: str,
        expert_bytes: bytes,
        preset_relative_path: str,
        preset_bytes: bytes,
    ) -> None:
        """Stage both files, then replace as a rollback-capable pair."""
        pairs = ((expert_relative_path, expert_bytes), (preset_relative_path, preset_bytes))
        targets: list[tuple[Path, Path, Path]] = []
        backups: list[tuple[Path, Path]] = []
        installed: list[Path] = []
        succeeded = False
        try:
            for relative, data in pairs:
                if type(data) is not bytes:
                    raise EaHostingError("FILESYSTEM_UNAVAILABLE")
                parent, target = cls._parent(root, relative)
                fd, temp_name = tempfile.mkstemp(prefix=".ea-host-", suffix=".tmp", dir=parent)
                temp = Path(temp_name)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
                targets.append((parent, target, temp))
            for _, target, temp in targets:
                if cls._is_link(target):
                    raise OSError
                if target.exists():
                    backup = target.with_name(f".{target.name}.{uuid.uuid4().hex}.bak")
                    os.replace(target, backup)
                    backups.append((target, backup))
                os.replace(temp, target)
                installed.append(target)
            succeeded = True
        except Exception:
            for target in reversed(installed):
                with suppress(OSError):
                    target.unlink(missing_ok=True)
            for target, backup in reversed(backups):
                with suppress(OSError):
                    os.replace(backup, target)
            raise EaHostingError("FILESYSTEM_UNAVAILABLE") from None
        finally:
            for _, _, temp in targets:
                with suppress(OSError):
                    temp.unlink(missing_ok=True)
            if succeeded:
                for _, backup in backups:
                    with suppress(OSError):
                        backup.unlink(missing_ok=True)


class EaHostingBridgePortV1(Protocol):
    """Adapter over the reviewed MT5 bridge, scoped to one exact DEMO account."""

    @property
    def venue(self) -> VenueIdentityV1: ...

    def read_account_view(self, account_id: str) -> AccountViewV1: ...

    def disable_expert(self, session_id: str) -> bool: ...

    def close_all(self, account_id: str) -> bool: ...


class EaCapAssessmentV1(SealedModel):
    status: CapStatus
    account_id: str
    observed_at_ns: int
    view_digest: str


def _view_digest(view: AccountViewV1) -> str:
    return hashlib.sha256(repr(view.seal_payload()).encode("utf-8")).hexdigest()


def issue_ea_cap_assessment(
    view: AccountViewV1, *, status: CapStatus, observed_at_ns: int
) -> EaCapAssessmentV1:
    """Adapter helper: issue a cap decision bound to one sealed account snapshot.

    Production adapters must call this only after the canonical sovereign cap
    engine has evaluated the complete account state. A fake can issue synthetic
    evidence for offline tests; it must never be wired into a live process.
    """
    try:
        checked = require_account_view(view)
        if (
            type(status) is not str
            or status not in {"WITHIN_CAPS", "BREACH", "UNKNOWN"}
            or type(observed_at_ns) is not int
            or observed_at_ns < 0
            or checked.broker_observed_at is None
            or _datetime_ns(checked.broker_observed_at) > observed_at_ns
        ):
            raise ValueError
        result = EaCapAssessmentV1(
            status=status,
            account_id=checked.account_id,
            observed_at_ns=observed_at_ns,
            view_digest=_view_digest(checked),
        )
        return _ISSUER.issue(result)
    except Exception:
        raise EaHostingError("CAPS_UNKNOWN") from None


class EaCapEvaluatorPortV1(Protocol):
    def assess(self, view: AccountViewV1, *, as_of_ns: int) -> EaCapAssessmentV1: ...


class EaHostingServiceV1:
    """Demo-only file placement, monitoring and operator kill service."""

    def __init__(
        self,
        *,
        data_root: str | Path,
        bridge: EaHostingBridgePortV1,
        filesystem: EaFileSystemPortV1,
        cap_evaluator: EaCapEvaluatorPortV1 | None,
        halt: HaltAuthority,
        clock_ns: Callable[[], int],
    ) -> None:
        try:
            venue = require_venue_identity(bridge.venue)
        except Exception:
            raise EaHostingError("DEMO_IDENTITY_REQUIRED") from None
        if (
            venue.venue is not BrokerVenue.MT5
            or venue.environment is not BrokerEnvironment.DEMO
            or not (type(data_root) is str or isinstance(data_root, Path))
            or not callable(clock_ns)
            or type(halt) is not HaltAuthority
            or not callable(getattr(filesystem, "install_pair", None))
            or not callable(getattr(bridge, "read_account_view", None))
            or not callable(getattr(bridge, "disable_expert", None))
            or not callable(getattr(bridge, "close_all", None))
        ):
            raise EaHostingError("DEMO_IDENTITY_REQUIRED")
        self._root = Path(data_root)
        self._account_id = venue.account_id
        self._bridge = bridge
        self._filesystem = filesystem
        self._cap_evaluator = cap_evaluator
        self._halt = halt
        self._clock_ns = clock_ns
        self._sessions: dict[str, EaInstallResultV1] = {}
        self._session_operators: dict[str, str] = {}
        self._mutex = RLock()

    @property
    def account_id(self) -> str:
        return self._account_id

    def install(self, request: EaInstallRequestV1, *, operator_id: str) -> EaInstallResultV1:
        if type(request) is not EaInstallRequestV1 or not _safe_id(operator_id):
            raise EaHostingError("INVALID_EA_REQUEST")
        family = request.terminal_family
        if type(family) is not str or family not in {"MT4", "MT5"}:
            raise EaHostingError("INVALID_EA_REQUEST")
        extension = ".ex4" if family == "MT4" else ".ex5"
        ea_name = _validated_filename(request.ea_filename, extension, "INVALID_EA_FILE")
        set_name = _validated_filename(request.set_filename, ".set", "INVALID_SET_FILE")
        if type(request.ea_bytes) is not bytes or not request.ea_bytes:
            raise EaHostingError("INVALID_EA_FILE")
        if type(request.set_bytes) is not bytes or not request.set_bytes:
            raise EaHostingError("INVALID_SET_FILE")
        if len(request.ea_bytes) > MAX_EA_BYTES or len(request.set_bytes) > MAX_SET_BYTES:
            raise EaHostingError("FILE_TOO_LARGE")
        if (
            type(request.symbol) is not str
            or _SYMBOL.fullmatch(request.symbol) is None
            or type(request.timeframe) is not str
            or request.timeframe not in _TIMEFRAMES
        ):
            raise EaHostingError("INVALID_EA_REQUEST")
        root_name = "MQL4" if family == "MT4" else "MQL5"
        expert_rel = f"{root_name}/Experts/{ea_name}"
        preset_rel = f"{root_name}/Presets/{set_name}"
        try:
            installed_at = self._clock_ns()
            if type(installed_at) is not int or installed_at < 0:
                raise ValueError
            self._filesystem.install_pair(
                root=self._root,
                expert_relative_path=expert_rel,
                expert_bytes=request.ea_bytes,
                preset_relative_path=preset_rel,
                preset_bytes=request.set_bytes,
            )
        except EaHostingError:
            raise
        except Exception:
            raise EaHostingError("FILESYSTEM_UNAVAILABLE") from None
        session_id = "ea-" + uuid.uuid4().hex
        ea_hash = hashlib.sha256(request.ea_bytes).hexdigest()
        set_hash = hashlib.sha256(request.set_bytes).hexdigest()
        provenance = EaFileProvenanceV1(
            ea_filename=ea_name,
            set_filename=set_name,
            ea_sha256=ea_hash,
            set_sha256=set_hash,
            ea_size_bytes=len(request.ea_bytes),
            set_size_bytes=len(request.set_bytes),
            installed_at_ns=installed_at,
            operator_id=operator_id,
        )
        startup = EaStartupConfigV1(
            terminal_family=family,
            expert_name=ea_name,
            set_file=set_name,
            symbol=request.symbol,
            timeframe=request.timeframe,
            environment="DEMO",
            execution_allowed=False,
        )
        result = _ISSUER.issue(
            EaInstallResultV1(
                session_id=session_id,
                account_id=self._account_id,
                environment="DEMO",
                terminal_family=family,
                expert_relative_path=expert_rel,
                preset_relative_path=preset_rel,
                ea_sha256=ea_hash,
                set_sha256=set_hash,
                provenance=provenance,
                startup_config=startup,
                execution_allowed=False,
            )
        )
        with self._mutex:
            self._sessions[session_id] = result
            self._session_operators[session_id] = operator_id
        return result

    def monitor(self, session_id: str, *, operator_id: str) -> EaMonitorResultV1:
        session = self._session(session_id, operator_id=operator_id)
        observed_at = self._now()
        try:
            view = require_account_view(self._bridge.read_account_view(self._account_id))
            if view.account_id != self._account_id or view.broker_observed_at is None:
                raise ValueError
            view_ns = _datetime_ns(view.broker_observed_at)
            if view_ns > observed_at or observed_at - view_ns > 30_000_000_000:
                raise ValueError
            evaluator = self._cap_evaluator
            if evaluator is None:
                status: CapStatus = "UNKNOWN"
            else:
                assessment = evaluator.assess(view, as_of_ns=observed_at)
                require_sealed(assessment, _ISSUER.tag)
                if (
                    type(assessment) is not EaCapAssessmentV1
                    or assessment.account_id != self._account_id
                    or assessment.observed_at_ns != observed_at
                    or assessment.view_digest != _view_digest(view)
                ):
                    raise ValueError
                status = assessment.status
        except Exception:
            view = None
            status = "UNKNOWN"
        state: Literal["MONITORING", "HALT_REQUIRED"] = (
            "MONITORING" if status == "WITHIN_CAPS" else "HALT_REQUIRED"
        )
        if state == "HALT_REQUIRED":
            self._halt_and_stop(session.session_id, risk=status == "BREACH")
        if view is None:
            orders: tuple[EaOpenOrderV1, ...] = ()
            positions: tuple[tuple[str, str], ...] = ()
            observed_at = self._now()
        else:
            orders = tuple(_order_projection(item) for item in view.open_orders)
            positions = tuple(
                (instrument, str(quantity)) for instrument, quantity in view.positions
            )
        return _ISSUER.issue(
            EaMonitorResultV1(
                session_id=session.session_id,
                account_id=self._account_id,
                environment="DEMO",
                observed_at_ns=observed_at,
                open_order_count=len(orders),
                open_orders=orders,
                positions=positions,
                cap_status=status,
                state=state,
                execution_allowed=False,
            )
        )

    def kill(self, session_id: str, *, operator_id: str) -> EaKillResultV1:
        session = self._session(session_id, operator_id=operator_id)
        halted, disabled, closed = self._halt_and_stop(session.session_id, risk=False)
        state: Literal["STOPPED", "UNKNOWN"] = (
            "STOPPED" if halted and disabled and closed else "UNKNOWN"
        )
        return _ISSUER.issue(
            EaKillResultV1(
                session_id=session.session_id,
                environment="DEMO",
                state=state,
                disabled=disabled,
                close_attempted=True,
                execution_allowed=False,
            )
        )

    def _halt_and_stop(self, session_id: str, *, risk: bool) -> tuple[bool, bool, bool]:
        halted = False
        disabled = False
        closed = False
        with suppress(Exception):
            self._halt.engage(
                HaltReasonV1.RISK_LIMIT_BREACH.value if risk else HaltReasonV1.OPERATOR_HALT.value
            )
            halted = True
        with suppress(Exception):
            result = self._bridge.disable_expert(session_id)
            disabled = type(result) is bool and result
        with suppress(Exception):
            result = self._bridge.close_all(self._account_id)
            closed = type(result) is bool and result
        return halted, disabled, closed

    def _session(self, session_id: object, *, operator_id: object) -> EaInstallResultV1:
        if not _safe_id(session_id) or not _safe_id(operator_id):
            raise EaHostingError("SESSION_NOT_FOUND")
        session_key = cast(str, session_id)
        owner_id = cast(str, operator_id)
        with self._mutex:
            result = self._sessions.get(session_key)
            owner = self._session_operators.get(session_key)
        if result is None or owner != owner_id:
            raise EaHostingError("SESSION_NOT_FOUND")
        try:
            require_sealed(result, _ISSUER.tag)
        except SealError:
            raise EaHostingError("UNISSUED_RESULT") from None
        return result

    def _now(self) -> int:
        try:
            value = self._clock_ns()
        except Exception:
            raise EaHostingError("CAPS_UNKNOWN") from None
        if type(value) is not int or value < 0:
            raise EaHostingError("CAPS_UNKNOWN")
        return value


class EaFileProvenanceV1(SealedModel):
    ea_filename: str
    set_filename: str
    ea_sha256: str
    set_sha256: str
    ea_size_bytes: int
    set_size_bytes: int
    installed_at_ns: int
    operator_id: str


class EaStartupConfigV1(SealedModel):
    terminal_family: TerminalFamily
    expert_name: str
    set_file: str
    symbol: str
    timeframe: str
    environment: Literal["DEMO"]
    execution_allowed: Literal[False]


class EaInstallResultV1(SealedModel):
    session_id: str
    account_id: str
    environment: Literal["DEMO"]
    terminal_family: TerminalFamily
    expert_relative_path: str
    preset_relative_path: str
    ea_sha256: str
    set_sha256: str
    provenance: EaFileProvenanceV1
    startup_config: EaStartupConfigV1
    execution_allowed: Literal[False]


class EaOpenOrderV1(SealedModel):
    client_order_id: str
    venue_order_id: str | None
    venue: str
    status: str
    observed_at_ns: int


class EaMonitorResultV1(SealedModel):
    session_id: str
    account_id: str
    environment: Literal["DEMO"]
    observed_at_ns: int
    open_order_count: int
    open_orders: tuple[EaOpenOrderV1, ...]
    positions: tuple[tuple[str, str], ...]
    cap_status: CapStatus
    state: Literal["MONITORING", "HALT_REQUIRED"]
    execution_allowed: Literal[False]


class EaKillResultV1(SealedModel):
    session_id: str
    environment: Literal["DEMO"]
    state: Literal["STOPPED", "UNKNOWN"]
    disabled: bool
    close_attempted: Literal[True]
    execution_allowed: Literal[False]


def _safe_id(value: object) -> bool:
    return type(value) is str and _ID.fullmatch(value) is not None


def _validated_filename(value: object, extension: str, code: str) -> str:
    if type(value) is not str or not value.isascii() or "/" in value or "\\" in value:
        raise EaHostingError(code)
    stem, dot, suffix = value.rpartition(".")
    if (
        not dot
        or suffix.lower() != extension[1:]
        or _NAME.fullmatch(stem) is None
        or stem.upper().split(".", 1)[0] in _WINDOWS_RESERVED
        or value.endswith((".", " "))
    ):
        raise EaHostingError(code)
    return stem + extension


def _order_projection(order: object) -> EaOpenOrderV1:
    # Explicit allowlist prevents arbitrary adapter fields from reaching UI.
    if type(order) is not BrokerObservation:
        raise EaHostingError("ACCOUNT_VIEW_UNKNOWN")
    try:
        if (
            order.environment != "demo"
            or order.venue != "MT5"
            or order.status.value not in {"WORKING", "PARTIALLY_FILLED"}
        ):
            raise ValueError
        return EaOpenOrderV1(
            client_order_id=order.client_order_id,
            venue_order_id=order.venue_order_id,
            venue=order.venue,
            status=order.status.value,
            observed_at_ns=_datetime_ns(order.observed_at),
        )
    except Exception:
        raise EaHostingError("ACCOUNT_VIEW_UNKNOWN") from None


def _datetime_ns(value: datetime) -> int:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise EaHostingError("CAPS_UNKNOWN")
    delta = value.astimezone(UTC) - datetime(1970, 1, 1, tzinfo=UTC)
    return ((delta.days * 86_400 + delta.seconds) * 1_000_000_000) + delta.microseconds * 1_000


__all__ = [
    "MAX_EA_BYTES",
    "MAX_SET_BYTES",
    "CapStatus",
    "EaCapAssessmentV1",
    "EaCapEvaluatorPortV1",
    "EaFileProvenanceV1",
    "EaFileSystemPortV1",
    "EaHostingBridgePortV1",
    "EaHostingError",
    "EaHostingServiceV1",
    "EaInstallRequestV1",
    "EaInstallResultV1",
    "EaKillResultV1",
    "EaMonitorResultV1",
    "EaOpenOrderV1",
    "EaStartupConfigV1",
    "LocalEaFileSystemV1",
    "TerminalFamily",
    "issue_ea_cap_assessment",
]
