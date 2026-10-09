"""Capability-gated, exact-range gap filling over the durable MD-005 WAL."""

from __future__ import annotations

import hashlib
import re
import threading
import weakref
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol, cast

from pydantic import Field, field_validator, model_validator

from leviathan_core.numeric import canonical_json
from leviathan_core.seal import Issuer, SealedModel, SealError
from leviathan_core.seal import require as seal_require
from leviathan_market_data.live.checkpoint import GapManifestV1, is_issued_gap_manifest
from leviathan_market_data.live.replay import (
    TrustedProviderCapabilityV1,
    is_issued_trusted_provider_capability,
    is_trusted_provider_capability_for,
)
from leviathan_market_data.live.wal import MAX_WAL_BYTES, AppendOnlyWal, RawWalRecordV1
from leviathan_market_data.schema import INT64_MAX

_GAP_FILL_ISSUER = Issuer("md006.gap_fill_manifest.v1")
_GAP_FILL_RESULT_ISSUER = Issuer("md006.gap_fill_result.v1")
_RECONSTRUCTED_RECORD_ISSUER = Issuer("md006.reconstructed_wal_record.v1")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
MAX_GAP_FILL_RECORDS = 100_000
MAX_GAP_FILL_PAYLOAD_BYTES = 1_048_576
MAX_GAP_FILL_BYTES = MAX_WAL_BYTES

GapFillState = Literal["OPEN", "FILLING", "FILLED", "FAILED"]


class GapFillError(ValueError):
    """Content-free gap-fill boundary failure."""

    _CODES = frozenset(
        {
            "INVALID_POLICY",
            "INVALID_GAP_MANIFEST",
            "UNTRUSTED_PROVIDER",
            "PROVIDER_MISMATCH",
            "INVALID_FILL_RESPONSE",
            "GAP_COVERAGE_INCOMPLETE",
            "GAP_ALREADY_CLOSED",
            "WAL_APPEND_FAILED",
            "CAPACITY_EXCEEDED",
        }
    )

    def __init__(self, code: str) -> None:
        self.code = code if type(code) is str and code in self._CODES else "INVALID_POLICY"
        super().__init__(self.code)


class GapFillRecordV1(SealedModel):
    """Validated input record returned by a fake or registered fill source."""

    schema_version: Literal["leviathan.gap-fill-record/1"] = "leviathan.gap-fill-record/1"
    provider_id: str
    session_id: str
    source_record_key: str
    native_record_id: str | None
    native_sequence: int
    source_time_ns: int | None
    received_time_ns: int
    raw_payload: bytes

    @field_validator("provider_id", "session_id", "source_record_key", mode="before")
    @classmethod
    def _identifier(cls, value: object) -> str:
        if (
            type(value) is not str
            or not value
            or len(value) > 512
            or value != value.strip()
            or not value.isascii()
            or "\x00" in value
        ):
            raise ValueError("INVALID_IDENTIFIER")
        return value

    @field_validator("native_record_id", mode="before")
    @classmethod
    def _native_id(cls, value: object) -> str | None:
        if value is not None and (
            type(value) is not str
            or not value
            or len(value) > 256
            or value != value.strip()
            or not value.isascii()
            or "\x00" in value
        ):
            raise ValueError("INVALID_NATIVE_ID")
        return value

    @field_validator("native_sequence", mode="before")
    @classmethod
    def _sequence(cls, value: object) -> int:
        if type(value) is not int or not 0 <= value <= INT64_MAX:
            raise ValueError("INVALID_SEQUENCE")
        return value

    @field_validator("source_time_ns", mode="before")
    @classmethod
    def _source_time(cls, value: object) -> int | None:
        if value is not None and (type(value) is not int or not 0 < value <= INT64_MAX):
            raise ValueError("INVALID_TIME")
        return value

    @field_validator("received_time_ns", mode="before")
    @classmethod
    def _received_time(cls, value: object) -> int:
        if type(value) is not int or not 0 < value <= INT64_MAX:
            raise ValueError("INVALID_TIME")
        return value

    @field_validator("raw_payload", mode="before")
    @classmethod
    def _payload(cls, value: object) -> bytes:
        if type(value) is not bytes or len(value) > MAX_GAP_FILL_PAYLOAD_BYTES:
            raise ValueError("INVALID_PAYLOAD")
        return value


class GapFillBatchV1(SealedModel):
    """Bounded response envelope; its provider/session are rechecked at use."""

    schema_version: Literal["leviathan.gap-fill-batch/1"] = "leviathan.gap-fill-batch/1"
    provider_id: str
    session_id: str
    records: tuple[GapFillRecordV1, ...] = Field(default_factory=tuple)

    @field_validator("provider_id", "session_id", mode="before")
    @classmethod
    def _identifier(cls, value: object) -> str:
        if type(value) is not str or not value or len(value) > 128 or not value.isascii():
            raise ValueError("INVALID_IDENTIFIER")
        return value

    @field_validator("records", mode="before")
    @classmethod
    def _records(cls, value: object) -> tuple[GapFillRecordV1, ...]:
        if type(value) is not tuple or len(value) > MAX_GAP_FILL_RECORDS:
            raise ValueError("INVALID_RECORDS")
        return value

    @model_validator(mode="after")
    def _bounded_bytes(self) -> GapFillBatchV1:
        if sum(len(record.raw_payload) for record in self.records) > MAX_GAP_FILL_BYTES:
            raise ValueError("CAPACITY_EXCEEDED")
        return self


class GapFillSourcePort(Protocol):
    @property
    def provider_id(self) -> str: ...

    def fetch_gap(
        self, *, session_id: str, start_sequence: int, end_sequence: int
    ) -> GapFillBatchV1: ...


@dataclass(frozen=True, slots=True)
class _GapFillAdapterBinding:
    source: GapFillSourcePort
    capability: TrustedProviderCapabilityV1
    provider_id: str | None


_GAP_FILL_ADAPTER_BINDINGS: weakref.WeakKeyDictionary[
    object, _GapFillAdapterBinding
] = weakref.WeakKeyDictionary()
_GAP_FILL_ADAPTER_BINDINGS_LOCK = threading.RLock()


class GapFillManifestV1(SealedModel):
    """MD-006 operational fill state referencing, not replacing, an MD-005 gap."""

    schema_version: Literal["leviathan.gap-fill-manifest/1"] = (
        "leviathan.gap-fill-manifest/1"
    )
    source_gap_sha256: str
    provider_id: str
    session_id: str
    start_sequence: int
    end_sequence: int
    state: GapFillState
    filled_count: int = 0
    generation: int = 0

    @field_validator("source_gap_sha256", mode="before")
    @classmethod
    def _digest(cls, value: object) -> str:
        if type(value) is not str or _DIGEST.fullmatch(value) is None:
            raise ValueError("INVALID_DIGEST")
        return value

    @field_validator("provider_id", "session_id", mode="before")
    @classmethod
    def _identifier(cls, value: object) -> str:
        if (
            type(value) is not str
            or not value
            or len(value) > 128
            or value != value.strip()
            or not value.isascii()
            or "\x00" in value
        ):
            raise ValueError("INVALID_IDENTIFIER")
        return value

    @field_validator("start_sequence", "end_sequence", "filled_count", "generation", mode="before")
    @classmethod
    def _integer(cls, value: object) -> int:
        if type(value) is not int or not 0 <= value <= INT64_MAX:
            raise ValueError("INVALID_INTEGER")
        return value

    @field_validator("state", mode="before")
    @classmethod
    def _state(cls, value: object) -> GapFillState:
        if type(value) is not str or value not in {"OPEN", "FILLING", "FILLED", "FAILED"}:
            raise ValueError("INVALID_STATE")
        return cast(GapFillState, value)

    @model_validator(mode="after")
    def _range(self) -> GapFillManifestV1:
        if self.start_sequence >= self.end_sequence:
            raise ValueError("INVALID_RANGE")
        if self.filled_count > self.end_sequence - self.start_sequence:
            raise ValueError("INVALID_COUNT")
        if self.state == "FILLED" and self.filled_count != self.end_sequence - self.start_sequence:
            raise ValueError("INVALID_STATE")
        return self


class ReconstructedWalRecordV1(SealedModel):
    """Explicit MD-006 provenance wrapper around an appended raw WAL record."""

    schema_version: Literal["leviathan.reconstructed-wal-record/1"] = (
        "leviathan.reconstructed-wal-record/1"
    )
    record: RawWalRecordV1
    provider_id: str
    source_gap_sha256: str
    reconstructed: Literal[True] = True


@dataclass(frozen=True, slots=True, weakref_slot=True)
class GapFillResultV1:
    """Sealed outcome; UNKNOWN is the only result for incomplete coverage."""

    manifest: GapFillManifestV1
    continuity: Literal["CONTINUOUS", "UNKNOWN"]
    appended_sequences: tuple[int, ...] = field(default_factory=tuple)
    reconstructed_records: tuple[ReconstructedWalRecordV1, ...] = field(default_factory=tuple)
    error_code: str | None = None
    schema_version: Literal["leviathan.gap-fill-result/1"] = "leviathan.gap-fill-result/1"


def _gap_digest(gap: GapManifestV1) -> str:
    try:
        seal_require(gap, "md005.gap_manifest.v1")
        if not is_issued_gap_manifest(gap):
            raise SealError("SEAL_UNISSUED")
        return hashlib.sha256(canonical_json(gap.model_dump(mode="json"))).hexdigest()
    except Exception:
        raise GapFillError("INVALID_GAP_MANIFEST") from None


def _issue_manifest(**values: object) -> GapFillManifestV1:
    try:
        return _GAP_FILL_ISSUER.issue(GapFillManifestV1(**cast(Any, values)))
    except Exception:
        raise GapFillError("INVALID_GAP_MANIFEST") from None


def is_issued_gap_fill_manifest(value: object) -> bool:
    try:
        seal_require(value, _GAP_FILL_ISSUER.tag)
        return type(value) is GapFillManifestV1
    except Exception:
        return False


def _issue_result(**values: object) -> GapFillResultV1:
    try:
        return _GAP_FILL_RESULT_ISSUER.issue(GapFillResultV1(**cast(Any, values)))
    except Exception:
        raise GapFillError("INVALID_POLICY") from None


def is_issued_gap_fill_result(value: object) -> bool:
    try:
        seal_require(value, _GAP_FILL_RESULT_ISSUER.tag)
        return type(value) is GapFillResultV1
    except Exception:
        return False


def _issue_reconstructed_record(
    record: RawWalRecordV1, *, provider_id: str, source_gap_sha256: str
) -> ReconstructedWalRecordV1:
    try:
        return _RECONSTRUCTED_RECORD_ISSUER.issue(
            ReconstructedWalRecordV1(
                record=record,
                provider_id=provider_id,
                source_gap_sha256=source_gap_sha256,
            )
        )
    except Exception:
        raise GapFillError("WAL_APPEND_FAILED") from None


def is_issued_reconstructed_wal_record(value: object) -> bool:
    try:
        seal_require(value, _RECONSTRUCTED_RECORD_ISSUER.tag)
        return type(value) is ReconstructedWalRecordV1
    except Exception:
        return False


class GapFillAdapter:
    """Fill exact, bounded sequence ranges through a capability-verified source."""

    def __init__(
        self,
        source: GapFillSourcePort,
        capability: TrustedProviderCapabilityV1,
        *,
        max_records: int = MAX_GAP_FILL_RECORDS,
        clock_ns: Callable[[], int] | None = None,
    ) -> None:
        if (
            type(max_records) is not int
            or not 1 <= max_records <= MAX_GAP_FILL_RECORDS
            or (clock_ns is not None and not callable(clock_ns))
        ):
            raise GapFillError("INVALID_POLICY")
        self._max_records = max_records
        self._clock_ns = clock_ns
        try:
            provider_id = (
                capability.provider_id
                if is_trusted_provider_capability_for(capability, source)
                else None
            )
        except Exception:
            provider_id = None
        binding = _GapFillAdapterBinding(source, capability, provider_id)
        with _GAP_FILL_ADAPTER_BINDINGS_LOCK:
            _GAP_FILL_ADAPTER_BINDINGS[self] = binding

    def _binding(self) -> _GapFillAdapterBinding:
        with _GAP_FILL_ADAPTER_BINDINGS_LOCK:
            binding = _GAP_FILL_ADAPTER_BINDINGS.get(self)
        if binding is None or binding.provider_id is None:
            raise GapFillError("UNTRUSTED_PROVIDER")
        try:
            seal_require(binding.capability, "md005.trusted_provider_capability.v1")
            if (
                not is_issued_trusted_provider_capability(binding.capability)
                or not is_trusted_provider_capability_for(
                    binding.capability, binding.source
                )
                or binding.capability.provider_id != binding.provider_id
                or binding.source.provider_id != binding.provider_id
            ):
                raise SealError("SEAL_NOT_ISSUED")
        except Exception:
            raise GapFillError("UNTRUSTED_PROVIDER") from None
        return binding

    def _provider(self) -> str:
        try:
            binding = self._binding()
            provider_id = binding.provider_id
            if provider_id is None:
                raise GapFillError("UNTRUSTED_PROVIDER")
        except Exception:
            raise GapFillError("UNTRUSTED_PROVIDER") from None
        return provider_id

    def open_gap(
        self, gap: GapManifestV1, *, range_index: int = 0
    ) -> GapFillManifestV1:
        provider = self._provider()
        digest = _gap_digest(gap)
        if gap.provider_id != provider:
            raise GapFillError("PROVIDER_MISMATCH")
        if len(gap.ranges) != 1:
            # This version proves a single exact interval per operational state;
            # it never marks a multi-range source manifest continuous early.
            raise GapFillError("INVALID_GAP_MANIFEST")
        if type(range_index) is not int or not 0 <= range_index < len(gap.ranges):
            raise GapFillError("INVALID_GAP_MANIFEST")
        start, end = gap.ranges[range_index]
        return _issue_manifest(
            source_gap_sha256=digest,
            provider_id=provider,
            session_id=gap.session_id,
            start_sequence=start,
            end_sequence=end,
            state="OPEN",
            filled_count=0,
            generation=0,
        )

    def fill(self, manifest: GapFillManifestV1, wal: AppendOnlyWal) -> GapFillResultV1:
        if not is_issued_gap_fill_manifest(manifest):
            raise GapFillError("INVALID_GAP_MANIFEST")
        provider = self._provider()
        if manifest.provider_id != provider:
            raise GapFillError("PROVIDER_MISMATCH")
        if manifest.state == "FILLED":
            raise GapFillError("GAP_ALREADY_CLOSED")
        if not isinstance(wal, AppendOnlyWal):
            raise GapFillError("INVALID_POLICY")
        count = manifest.end_sequence - manifest.start_sequence
        if count > self._max_records:
            return self._failed(manifest, "CAPACITY_EXCEEDED", ())
        binding = self._binding()
        try:
            batch = binding.source.fetch_gap(
                session_id=manifest.session_id,
                start_sequence=manifest.start_sequence,
                end_sequence=manifest.end_sequence,
            )
        except Exception:
            return self._failed(manifest, "INVALID_FILL_RESPONSE", ())
        try:
            if self._binding() is not binding:
                return self._failed(manifest, "UNTRUSTED_PROVIDER", ())
        except GapFillError as error:
            return self._failed(manifest, error.code, ())
        if not isinstance(batch, GapFillBatchV1):
            return self._failed(manifest, "INVALID_FILL_RESPONSE", ())
        try:
            # Revalidate the source object at this use boundary. A caller-made
            # response is data, never trust evidence; capability + IDs grant authority.
            batch = GapFillBatchV1.model_validate(batch.model_dump(mode="python"))
        except Exception:
            return self._failed(manifest, "INVALID_FILL_RESPONSE", ())
        if batch.provider_id != provider or batch.session_id != manifest.session_id:
            return self._failed(manifest, "PROVIDER_MISMATCH", ())
        expected = tuple(range(manifest.start_sequence, manifest.end_sequence))
        actual = tuple(record.native_sequence for record in batch.records)
        if actual != expected or len(batch.records) != count:
            return self._failed(manifest, "GAP_COVERAGE_INCOMPLETE", ())
        if any(
            record.provider_id != provider or record.session_id != manifest.session_id
            for record in batch.records
        ):
            return self._failed(manifest, "PROVIDER_MISMATCH", ())
        # The WAL binds its own stream identity. A missing prior identity means
        # there is no proven stream to reconcile this detected gap against.
        existing = wal.read_all()
        if not existing:
            return self._failed(manifest, "WAL_APPEND_FAILED", ())
        stream_identity = existing[-1].stream_identity
        if stream_identity[0] != provider:
            return self._failed(manifest, "PROVIDER_MISMATCH", ())
        appended: list[RawWalRecordV1] = []
        try:
            for record in batch.records:
                received = record.received_time_ns
                if self._clock_ns is not None:
                    received = self._clock_ns()
                appended.append(
                    wal.append(
                        stream_identity=stream_identity,
                        session_id=record.session_id,
                        source_record_key=record.source_record_key,
                        native_record_id=record.native_record_id,
                        native_sequence=record.native_sequence,
                        source_time_ns=record.source_time_ns,
                        received_time_ns=received,
                        raw_payload=record.raw_payload,
                    )
                )
        except Exception:
            return self._failed(
                manifest,
                "WAL_APPEND_FAILED",
                tuple(item.native_sequence for item in appended),
                filled_count=len(appended),
                records=tuple(appended),
            )
        updated = _issue_manifest(
            source_gap_sha256=manifest.source_gap_sha256,
            provider_id=manifest.provider_id,
            session_id=manifest.session_id,
            start_sequence=manifest.start_sequence,
            end_sequence=manifest.end_sequence,
            state="FILLED",
            filled_count=count,
            generation=manifest.generation + 1,
        )
        return _issue_result(
            manifest=updated,
            continuity="CONTINUOUS",
            appended_sequences=tuple(item.native_sequence for item in appended),
            reconstructed_records=tuple(
                _issue_reconstructed_record(
                    item,
                    provider_id=provider,
                    source_gap_sha256=manifest.source_gap_sha256,
                )
                for item in appended
            ),
            error_code=None,
        )

    def _failed(
        self,
        manifest: GapFillManifestV1,
        code: str,
        appended: tuple[int, ...],
        *,
        filled_count: int = 0,
        records: tuple[RawWalRecordV1, ...] = (),
    ) -> GapFillResultV1:
        updated = _issue_manifest(
            source_gap_sha256=manifest.source_gap_sha256,
            provider_id=manifest.provider_id,
            session_id=manifest.session_id,
            start_sequence=manifest.start_sequence,
            end_sequence=manifest.end_sequence,
            state="FAILED" if filled_count else "OPEN",
            filled_count=filled_count,
            generation=manifest.generation + 1,
        )
        return _issue_result(
            manifest=updated,
            continuity="UNKNOWN",
            appended_sequences=appended,
            reconstructed_records=tuple(
                _issue_reconstructed_record(
                    item,
                    provider_id=manifest.provider_id,
                    source_gap_sha256=manifest.source_gap_sha256,
                )
                for item in records
            ),
            error_code=code,
        )
