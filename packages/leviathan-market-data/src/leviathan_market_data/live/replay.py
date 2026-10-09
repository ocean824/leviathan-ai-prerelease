"""Deterministic replay from the durable WAL into an idempotent sink."""

from __future__ import annotations

import threading
import weakref
from collections.abc import Callable
from typing import Literal, Protocol, cast

from pydantic import field_validator

from leviathan_core.seal import Issuer, SealedModel, SealError
from leviathan_core.seal import require as seal_require
from leviathan_market_data.ingress import SinkAck
from leviathan_market_data.live.checkpoint import (
    AtomicCheckpoint,
    ContinuityVerdictV1,
    GapManifestV1,
    NativeResumePositionV1,
    SinkCommitReceiptV1,
    _issue_gap_manifest,
    _issue_native_resume_position,
    _issue_sink_commit_receipt,
    _reconcile_native_position,
    is_issued_checkpoint,
)
from leviathan_market_data.live.wal import (
    AppendOnlyWal,
    RawWalRecordV1,
    SessionTransitionEvidenceV1,
    WalError,
    _issue_session_transition_evidence,
    is_issued_raw_wal_record,
)

_RECEIPT_ISSUER = Issuer("md005.replay_receipt.v1")
_TRUSTED_PROVIDER_ISSUER = Issuer("md005.trusted_provider_capability.v1")
_TRUSTED_PROVIDER_BINDINGS: dict[
    int,
    tuple[
        weakref.ReferenceType[TrustedProviderCapabilityV1],
        weakref.ReferenceType[object],
        str,
    ],
] = {}
_RESUME_TOKEN_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._~-"
)
ReplayStatus = Literal[
    "COMMITTED",
    "DUPLICATE",
    "BACKPRESSURE",
    "SINK_FAULT",
    "CHECKPOINT_FAILURE",
    "WAL_QUARANTINED",
    "CONTINUITY_UNPROVEN",
    "READY",
]


class RawRecordSink(Protocol):
    """Idempotent downstream raw-record write boundary."""

    def write(self, record: RawWalRecordV1) -> SinkAck | None: ...


class ContinuitySourcePort(Protocol):
    """MD-004 adapter response boundary for native resume and gap evidence."""

    @property
    def provider_id(self) -> str: ...

    def continuity_snapshot(self) -> NativeContinuitySnapshotV1: ...

    def confirm_session_transition(
        self, old_session_id: str, new_session_id: str
    ) -> SessionTransitionConfirmationV1: ...


class SessionTransitionConfirmationV1(SealedModel):
    """Typed response returned by a continuity-capable source adapter port."""

    schema_version: Literal["leviathan.session-transition-confirmation/1"] = (
        "leviathan.session-transition-confirmation/1"
    )
    from_session_id: str
    to_session_id: str
    status: Literal["CONFIRMED", "UNCONFIRMED"]

    @field_validator("from_session_id", "to_session_id", mode="before")
    @classmethod
    def _session(cls, value: object) -> str:
        if type(value) is not str or not value or len(value) > 128 or not value.isascii():
            raise ValueError("INVALID_SESSION")
        return value

    @field_validator("status", mode="before")
    @classmethod
    def _status(cls, value: object) -> Literal["CONFIRMED", "UNCONFIRMED"]:
        if type(value) is not str or value not in {"CONFIRMED", "UNCONFIRMED"}:
            raise ValueError("INVALID_TRANSITION_STATUS")
        return cast(Literal["CONFIRMED", "UNCONFIRMED"], value)


class TrustedProviderCapabilityV1(SealedModel):
    """SEAL-issued authority bound to one provider adapter object and ID."""

    schema_version: Literal["leviathan.trusted-provider-capability/1"] = (
        "leviathan.trusted-provider-capability/1"
    )
    provider_id: str

    @field_validator("provider_id", mode="before")
    @classmethod
    def _provider(cls, value: object) -> str:
        if (
            type(value) is not str
            or not value
            or len(value) > 128
            or value != value.strip()
            or "\x00" in value
            or not value.isascii()
        ):
            raise ValueError("INVALID_PROVIDER_ID")
        return value


def _issue_trusted_provider_capability(
    source: object, provider_id: str
) -> TrustedProviderCapabilityV1:
    """Private registration seam; no public provider-capability factory exists."""
    try:
        source_provider_id = getattr(source, "provider_id", None)
    except Exception:
        raise SealError("SEAL_INVALID_MODEL") from None
    if (
        type(provider_id) is not str
        or not provider_id
        or len(provider_id) > 128
        or provider_id != provider_id.strip()
        or "\x00" in provider_id
        or not provider_id.isascii()
        or source_provider_id != provider_id
    ):
        raise SealError("SEAL_INVALID_MODEL")
    try:
        weakref.ref(source)
    except TypeError:
        raise SealError("SEAL_UNSUPPORTED_TYPE") from None
    capability = _TRUSTED_PROVIDER_ISSUER.issue(
        TrustedProviderCapabilityV1(provider_id=provider_id)
    )
    capability_id = id(capability)

    def forget(_: object) -> None:
        _TRUSTED_PROVIDER_BINDINGS.pop(capability_id, None)

    try:
        capability_ref = weakref.ref(capability, forget)
    except TypeError:
        raise SealError("SEAL_UNSUPPORTED_TYPE") from None
    _TRUSTED_PROVIDER_BINDINGS[capability_id] = (
        capability_ref,
        weakref.ref(source, forget),
        provider_id,
    )
    return capability


def is_issued_trusted_provider_capability(value: object) -> bool:
    try:
        seal_require(value, _TRUSTED_PROVIDER_ISSUER.tag)
        binding = _TRUSTED_PROVIDER_BINDINGS.get(id(value))
        return (
            binding is not None
            and binding[0]() is value
            and binding[1]() is not None
            and type(value) is TrustedProviderCapabilityV1
            and value.provider_id == binding[2]
        )
    except Exception:
        return False


def is_trusted_provider_capability_for(value: object, source: object) -> bool:
    """Check that an issued provider capability is bound to this exact port."""
    if (
        type(value) is not TrustedProviderCapabilityV1
        or not is_issued_trusted_provider_capability(value)
    ):
        return False
    capability = value
    try:
        binding = _TRUSTED_PROVIDER_BINDINGS.get(id(capability))
        return (
            binding is not None
            and binding[0]() is capability
            and binding[1]() is source
            and binding[2] == capability.provider_id
            and getattr(source, "provider_id", None) == capability.provider_id
        )
    except Exception:
        return False


class NativeContinuitySnapshotV1(SealedModel):
    """Validated shape returned by the injected MD-004 source port."""

    schema_version: Literal["leviathan.native-continuity-snapshot/1"] = (
        "leviathan.native-continuity-snapshot/1"
    )
    session_id: str
    next_sequence: int
    resume_token: str | None = None
    gap_ranges: tuple[tuple[int, int], ...]

    @field_validator("session_id", mode="before")
    @classmethod
    def _session(cls, value: object) -> str:
        if type(value) is not str or not value or len(value) > 128 or not value.isascii():
            raise ValueError("INVALID_SESSION")
        return value

    @field_validator("next_sequence", mode="before")
    @classmethod
    def _sequence(cls, value: object) -> int:
        if type(value) is not int or not 0 <= value <= (1 << 63) - 1:
            raise ValueError("INVALID_SEQUENCE")
        return value

    @field_validator("resume_token", mode="before")
    @classmethod
    def _resume_token(cls, value: object) -> str | None:
        if value is not None and (
            type(value) is not str
            or not value.isascii()
            or len(value) > 256
            or any(char not in _RESUME_TOKEN_CHARS for char in value)
            or not value
        ):
            raise ValueError("INVALID_RESUME_TOKEN")
        return value

    @field_validator("gap_ranges", mode="before")
    @classmethod
    def _gaps(cls, value: object) -> tuple[tuple[int, int], ...]:
        if type(value) is not tuple or len(value) > 1024:
            raise ValueError("INVALID_GAP_MANIFEST")
        return value


class SourceAdapter:
    """Issue continuity proofs only under a trusted provider capability."""

    def __init__(
        self, source: object, capability: TrustedProviderCapabilityV1 | None = None
    ) -> None:
        self._source = source
        self._capability = capability

    def _trusted(self) -> bool:
        return is_trusted_provider_capability_for(self._capability, self._source)

    def continuity(
        self,
    ) -> tuple[NativeResumePositionV1 | None, GapManifestV1 | None]:
        capability = self._capability
        if capability is None or not self._trusted():
            return None, None
        try:
            reader = getattr(self._source, "continuity_snapshot", None)
            confirmer = getattr(self._source, "confirm_session_transition", None)
            if not callable(reader) or not callable(confirmer):
                return None, None
            snapshot = reader()
            if type(snapshot) is not NativeContinuitySnapshotV1 or not self._trusted():
                raise WalError("UNKNOWN_CONTINUITY")
            position = _issue_native_resume_position(
                provider_id=capability.provider_id,
                session_id=snapshot.session_id,
                next_sequence=snapshot.next_sequence,
                resume_token=snapshot.resume_token,
            )
            gaps = _issue_gap_manifest(
                provider_id=capability.provider_id,
                session_id=snapshot.session_id, ranges=snapshot.gap_ranges
            )
            return position, gaps
        except Exception:
            return None, None

    def confirm_session_transition(
        self, old_session_id: str, new_session_id: str
    ) -> SessionTransitionEvidenceV1 | None:
        if not self._trusted():
            return None
        confirm = getattr(self._source, "confirm_session_transition", None)
        if not callable(confirm):
            return None
        try:
            confirmed = confirm(old_session_id, new_session_id)
        except Exception:
            return None
        if (
            type(confirmed) is not SessionTransitionConfirmationV1
            or not self._trusted()
        ):
            return None
        if (
            confirmed.from_session_id != old_session_id
            or confirmed.to_session_id != new_session_id
            or confirmed.status != "CONFIRMED"
        ):
            return None
        capability = self._capability
        if capability is None:
            return None
        return _issue_session_transition_evidence(
            capability.provider_id, old_session_id, new_session_id
        )


class CommittingSink:
    """Issue checkpoint proof only after the wrapped sink write succeeds."""

    def __init__(self, sink: RawRecordSink) -> None:
        if not callable(getattr(sink, "write", None)):
            raise WalError("INVALID_POLICY")
        self._sink = sink

    def write(self, record: RawWalRecordV1) -> SinkCommitReceiptV1 | SinkAck:
        try:
            result = self._sink.write(record)
        except Exception:
            raise WalError("SINK_FAULT") from None
        if isinstance(result, SinkAck):
            if result.backpressure:
                return result
            if not result.accepted:
                raise WalError("SINK_FAULT") from None
        elif result is not None:
            raise WalError("SINK_FAULT") from None
        return _issue_sink_commit_receipt(record)


class ReplayReceiptV1(SealedModel):
    schema_version: Literal["leviathan.wal-replay-receipt/1"] = "leviathan.wal-replay-receipt/1"
    status: ReplayStatus
    stream_identity: tuple[str, str, str, str, str]
    session_id: str
    source_record_key: str
    native_sequence: int
    byte_offset: int
    sink_committed: bool
    checkpoint_offset: int
    live_ready: bool
    reason: str | None = None

    @field_validator("stream_identity", mode="before")
    @classmethod
    def _identity(cls, value: object) -> tuple[str, str, str, str, str]:
        if (
            type(value) is not tuple
            or len(value) != 5
            or any(type(part) is not str for part in value)
        ):
            raise ValueError("INVALID_IDENTITY")
        return value

    @field_validator("native_sequence", "byte_offset", "checkpoint_offset", mode="before")
    @classmethod
    def _integer(cls, value: object) -> int:
        if type(value) is not int or value < 0:
            raise ValueError("INVALID_INTEGER")
        return value

    @field_validator("sink_committed", "live_ready", mode="before")
    @classmethod
    def _boolean(cls, value: object) -> bool:
        if type(value) is not bool:
            raise ValueError("INVALID_BOOLEAN")
        return value


def is_issued_replay_receipt(value: object) -> bool:
    return _RECEIPT_ISSUER.issued_here(value)


def _issue_receipt(
    record: RawWalRecordV1 | None,
    *,
    status: ReplayStatus,
    checkpoint_offset: int,
    sink_committed: bool,
    reason: str | None = None,
) -> ReplayReceiptV1:
    try:
        return _RECEIPT_ISSUER.issue(
            ReplayReceiptV1(
                status=status,
                stream_identity=record.stream_identity
                if record is not None
                else ("", "", "", "", ""),
                session_id=record.session_id if record is not None else "unknown",
                source_record_key=record.source_record_key if record is not None else "unknown",
                native_sequence=record.native_sequence if record is not None else 0,
                byte_offset=record.byte_offset if record is not None else 0,
                sink_committed=sink_committed,
                checkpoint_offset=checkpoint_offset,
                live_ready=False,
                reason=reason,
            )
        )
    except (SealError, ValueError, TypeError):
        raise WalError("INVALID_RECORD") from None


class DeterministicReplay:
    """Replay committed-WAL records in durable order; no implicit gap filling."""

    def __init__(
        self,
        wal: AppendOnlyWal,
        checkpoint: AtomicCheckpoint,
        sink: RawRecordSink,
        *,
        fault_hook: Callable[[str], None] | None = None,
    ) -> None:
        if (
            not isinstance(wal, AppendOnlyWal)
            or not isinstance(checkpoint, AtomicCheckpoint)
            or not callable(getattr(sink, "write", None))
            or (fault_hook is not None and not callable(fault_hook))
        ):
            raise WalError("INVALID_POLICY")
        self.wal = wal
        self.checkpoint = checkpoint
        self.sink = sink if isinstance(sink, CommittingSink) else CommittingSink(sink)
        self._fault_hook = fault_hook
        self._lock = threading.RLock()
        self._live_ready = False
        self._replay_complete = False

    @property
    def live_ready(self) -> bool:
        return self._live_ready

    def replay(self) -> tuple[ReplayReceiptV1, ...]:
        with self._lock:
            self._live_ready = False
            self._replay_complete = False
            try:
                records = self.wal.read_all()
            except WalError as exc:
                if exc.code in {"WAL_QUARANTINED", "WAL_TAIL_QUARANTINED", "WAL_CORRUPT"}:
                    return (
                        _issue_receipt(
                            None,
                            status="WAL_QUARANTINED",
                            checkpoint_offset=0,
                            sink_committed=False,
                            reason=exc.code,
                        ),
                    )
                raise
            current = self.checkpoint.load()
            if current is not None and not is_issued_checkpoint(current):
                raise WalError("UNISSUED_VALUE")
            committed_end = current.committed_byte_offset if current is not None else 0
            if current is not None:
                matching = [
                    item
                    for item in records
                    if item.byte_offset + item.frame_size == current.committed_byte_offset
                ]
                if len(matching) != 1:
                    raise WalError("CHECKPOINT_CORRUPT")
                marker = matching[0]
                if (
                    marker.stream_identity != current.stream_identity
                    or marker.session_id != current.session_id
                    or marker.native_sequence != current.native_sequence
                    or marker.source_record_key != current.source_record_key
                    or marker.raw_payload_sha256 != current.payload_sha256
                ):
                    raise WalError("CHECKPOINT_CORRUPT")
            receipts: list[ReplayReceiptV1] = []
            for record in records:
                if not is_issued_raw_wal_record(record):
                    raise WalError("UNISSUED_VALUE")
                end = record.byte_offset + record.frame_size
                if end <= committed_end:
                    receipts.append(
                        _issue_receipt(
                            record,
                            status="DUPLICATE",
                            checkpoint_offset=committed_end,
                            sink_committed=True,
                        )
                    )
                    continue
                try:
                    ack = self.sink.write(record)
                except Exception:
                    receipts.append(
                        _issue_receipt(
                            record,
                            status="SINK_FAULT",
                            checkpoint_offset=committed_end,
                            sink_committed=False,
                            reason="SINK_FAULT",
                        )
                    )
                    break
                if isinstance(ack, SinkAck) and ack.backpressure:
                    receipts.append(
                        _issue_receipt(
                            record,
                            status="BACKPRESSURE",
                            checkpoint_offset=committed_end,
                            sink_committed=False,
                        )
                    )
                    break
                if not isinstance(ack, SinkCommitReceiptV1):
                    receipts.append(
                        _issue_receipt(
                            record,
                            status="SINK_FAULT",
                            checkpoint_offset=committed_end,
                            sink_committed=False,
                            reason="INVALID_SINK_ACK",
                        )
                    )
                    break
                try:
                    self._fault("replay.after_sink_commit_before_checkpoint")
                    saved = self.checkpoint.commit(record, ack)
                except WalError:
                    receipts.append(
                        _issue_receipt(
                            record,
                            status="CHECKPOINT_FAILURE",
                            checkpoint_offset=committed_end,
                            sink_committed=True,
                            reason="CHECKPOINT_FAILURE",
                        )
                    )
                    break
                except Exception:
                    receipts.append(
                        _issue_receipt(
                            record,
                            status="CHECKPOINT_FAILURE",
                            checkpoint_offset=committed_end,
                            sink_committed=True,
                            reason="CHECKPOINT_FAILURE",
                        )
                    )
                    break
                committed_end = saved.committed_byte_offset
                receipts.append(
                    _issue_receipt(
                        record,
                        status="COMMITTED",
                        checkpoint_offset=committed_end,
                        sink_committed=True,
                    )
                )
            else:
                self._replay_complete = True
            return tuple(receipts)

    def reconcile_native_position(
        self, position: NativeResumePositionV1 | None, gaps: GapManifestV1 | None
    ) -> ContinuityVerdictV1:
        with self._lock:
            current = self.checkpoint.load()
            verdict = _reconcile_native_position(
                position, gaps, current if self._replay_complete else None
            )
            self._live_ready = verdict.live_ready
            return verdict

    def _fault(self, point: str) -> None:
        if self._fault_hook is not None:
            self._fault_hook(point)
