"""Typed, fail-closed client for the private-stdio api-anything sidecar."""

from __future__ import annotations

import hashlib
import json
import os
import queue
import subprocess
import threading
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Literal, cast

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

MAX_LINE_BYTES = 1_100_000
MAX_RECORDS = 500
MAX_EVIDENCE_REFS = 128
CALL_TIMEOUT_SECONDS = 150.0
MAX_PROCESS_LIFETIME_SECONDS = 900.0


class PublicOperationErrorCode(StrEnum):
    COLLECTOR_UNAVAILABLE = "COLLECTOR_UNAVAILABLE"
    OPERATION_DEGRADED = "OPERATION_DEGRADED"
    SCHEMA_INVALID = "SCHEMA_INVALID"
    TEMPLATE_UNAVAILABLE = "TEMPLATE_UNAVAILABLE"
    USER_ACTION_DECLINED = "USER_ACTION_DECLINED"
    USER_ACTION_REQUIRED = "USER_ACTION_REQUIRED"
    TIMEOUT = "TIMEOUT"


class PublicOperationError(RuntimeError):
    """An allowlisted, content-free error suitable for propagation to the app."""

    def __init__(self, code: PublicOperationErrorCode) -> None:
        self.code = code
        super().__init__(code.value)


class OperationStatus(StrEnum):
    OK = "OK"
    DEGRADED = "DEGRADED"
    USER_ACTION_REQUIRED = "USER_ACTION_REQUIRED"
    USER_ACTION_DECLINED = "USER_ACTION_DECLINED"
    TIMEOUT = "TIMEOUT"


OperationId = Literal[
    "calendar.fed",
    "earnings.forward",
    "senate.efd.ptr",
    "cboe.daily.stats",
    "cnn.fear_greed",
]
QualityStatus = Literal[
    "source_timestamped",
    "first_observed",
    "availability_unknown",
]


class StrictModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)


class CollectorNotificationV1(StrictModel):
    type: Literal["notification"]
    request_id: str
    status: Literal["USER_ACTION_REQUIRED"]
    source_id: str = Field(min_length=1, max_length=128)
    operation_id: OperationId
    message: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def source_matches_operation(self) -> CollectorNotificationV1:
        if self.source_id != f"api_anything.{self.operation_id}":
            raise ValueError("source identity mismatch")
        return self


class CalendarValueV1(StrictModel):
    event_name: str = Field(min_length=1, max_length=512)
    agency: str = Field(min_length=1, max_length=128)
    release_type: str = Field(min_length=1, max_length=128)
    scheduled_at: datetime
    published_at: datetime | None


class EarningsValueV1(StrictModel):
    ticker: str = Field(pattern=r"^[A-Z0-9.-]{1,16}$")
    fiscal_period: str | None = Field(max_length=64)
    event_type: Literal["earnings", "conference_call", "guidance"]
    scheduled_at: datetime
    status: str = Field(min_length=1, max_length=128)
    published_at: datetime | None


class SenateTransactionV1(StrictModel):
    ticker: str | None = Field(max_length=16)
    trade_date: datetime | None
    transaction_type: str = Field(min_length=1, max_length=128)
    amount_range: str = Field(min_length=1, max_length=128)


class SenatePTRValueV1(StrictModel):
    report_url: str = Field(min_length=1, max_length=2048)
    filed_at: datetime | None
    transactions: tuple[SenateTransactionV1, ...] = Field(max_length=200)


class CboeValueV1(StrictModel):
    observed_at: datetime
    metric: Literal["put_call_ratio", "vix_term_structure"]
    value: float
    unit: str = Field(min_length=1, max_length=64)
    maturity: str | None = Field(max_length=64)
    published_at: datetime | None


class FearGreedValueV1(StrictModel):
    value: int = Field(ge=0, le=100)
    label: str = Field(min_length=1, max_length=128)
    observed_at: datetime


class CalendarQueryV1(StrictModel):
    year: int = Field(ge=2020, le=2100)


class EarningsQueryV1(StrictModel):
    symbols: tuple[str, ...] = Field(min_length=1, max_length=100)


class SenateQueryV1(StrictModel):
    page: int = Field(ge=1, le=10)


class CboeQueryV1(StrictModel):
    date: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")

    @field_validator("date")
    @classmethod
    def date_must_exist(cls, value: str) -> str:
        from datetime import date

        date.fromisoformat(value)
        return value


class EmptyQueryV1(StrictModel):
    pass


OperationValueV1 = (
    CalendarValueV1 | EarningsValueV1 | SenatePTRValueV1 | CboeValueV1 | FearGreedValueV1
)


@dataclass(frozen=True, slots=True)
class PublicOperationRecordV1:
    operation_id: str
    template_version: str
    source_id: str
    source_tier: Literal[3]
    record_id: str
    fetched_at: datetime
    as_of: datetime
    event_at: datetime | None
    published_at: datetime | None
    available_at: datetime | None
    knowable_at: datetime | None
    factor_tags: tuple[str, ...]
    quality: QualityStatus
    status: OperationStatus
    data: OperationValueV1
    values: tuple[tuple[str, str], ...] = field(init=False)
    redistribution: Literal[False] = False
    record_digest: str = field(init=False)

    def __post_init__(self) -> None:
        if not self.record_id or len(self.record_id) > 512:
            raise PublicOperationError(PublicOperationErrorCode.SCHEMA_INVALID)
        for stamp in (
            self.fetched_at,
            self.as_of,
            self.event_at,
            self.published_at,
            self.available_at,
            self.knowable_at,
        ):
            if stamp is not None and (stamp.tzinfo is None or stamp.utcoffset() is None):
                raise PublicOperationError(PublicOperationErrorCode.SCHEMA_INVALID)
        if self.as_of > self.fetched_at or (
            self.knowable_at is not None and self.knowable_at > self.fetched_at
        ):
            raise PublicOperationError(PublicOperationErrorCode.SCHEMA_INVALID)
        if self.redistribution is not False:
            raise PublicOperationError(PublicOperationErrorCode.SCHEMA_INVALID)
        data = self.data.model_dump(mode="json")
        values = tuple(
            (key, json.dumps(value, sort_keys=True, separators=(",", ":")))
            for key, value in sorted(data.items())
        )
        object.__setattr__(self, "values", values)
        canonical = json.dumps(
            {
                "operation_id": self.operation_id,
                "template_version": self.template_version,
                "source_tier": self.source_tier,
                "source_id": self.source_id,
                "record_id": self.record_id,
                "fetched_at": _iso(self.fetched_at),
                "as_of": _iso(self.as_of),
                "event_at": _iso(self.event_at),
                "published_at": _iso(self.published_at),
                "available_at": _iso(self.available_at),
                "knowable_at": _iso(self.knowable_at),
                "quality": self.quality,
                "status": self.status.value,
                "factor_tags": self.factor_tags,
                "values": self.values,
                "redistribution": False,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        object.__setattr__(self, "record_digest", hashlib.sha256(canonical).hexdigest())


@dataclass(frozen=True, slots=True)
class PublicOperationResultV1:
    operation_id: str
    template_version: str
    source_id: str
    source_tier: Literal[3]
    status: OperationStatus
    fetched_at: datetime
    as_of: datetime | None
    knowable_at: datetime | None
    records: tuple[PublicOperationRecordV1, ...]
    redistribution: Literal[False] = False

    def __post_init__(self) -> None:
        if self.source_tier != 3 or self.redistribution is not False:
            raise PublicOperationError(PublicOperationErrorCode.SCHEMA_INVALID)
        if self.fetched_at.tzinfo is None or self.fetched_at.utcoffset() is None:
            raise PublicOperationError(PublicOperationErrorCode.SCHEMA_INVALID)
        for stamp in (self.as_of, self.knowable_at):
            if stamp is not None and (stamp.tzinfo is None or stamp.utcoffset() is None):
                raise PublicOperationError(PublicOperationErrorCode.SCHEMA_INVALID)
        if self.as_of is not None and self.as_of > self.fetched_at:
            raise PublicOperationError(PublicOperationErrorCode.SCHEMA_INVALID)
        if self.knowable_at is not None and self.knowable_at > self.fetched_at:
            raise PublicOperationError(PublicOperationErrorCode.SCHEMA_INVALID)
        if len(self.records) > MAX_RECORDS:
            raise PublicOperationError(PublicOperationErrorCode.SCHEMA_INVALID)

    def evidence_records(self, decision_as_of: datetime) -> tuple[PublicOperationRecordV1, ...]:
        """Return only knowable records; future observation or availability is invalid."""
        if decision_as_of.tzinfo is None or decision_as_of.utcoffset() is None:
            raise PublicOperationError(PublicOperationErrorCode.SCHEMA_INVALID)
        if self.status is not OperationStatus.OK:
            code = {
                OperationStatus.USER_ACTION_REQUIRED: PublicOperationErrorCode.USER_ACTION_REQUIRED,
                OperationStatus.USER_ACTION_DECLINED: PublicOperationErrorCode.USER_ACTION_DECLINED,
                OperationStatus.TIMEOUT: PublicOperationErrorCode.TIMEOUT,
            }.get(self.status, PublicOperationErrorCode.OPERATION_DEGRADED)
            raise PublicOperationError(code)
        if self.as_of is not None and self.as_of > decision_as_of:
            raise PublicOperationError(PublicOperationErrorCode.SCHEMA_INVALID)
        selected: list[PublicOperationRecordV1] = []
        for record in self.records:
            if record.as_of > decision_as_of:
                raise PublicOperationError(PublicOperationErrorCode.SCHEMA_INVALID)
            if record.knowable_at is not None and record.knowable_at > decision_as_of:
                raise PublicOperationError(PublicOperationErrorCode.SCHEMA_INVALID)
            if record.knowable_at is not None and record.knowable_at <= decision_as_of:
                selected.append(record)
        if len(selected) > MAX_EVIDENCE_REFS:
            # No silent truncation: caller must make an explicit deterministic selection.
            raise PublicOperationError(PublicOperationErrorCode.SCHEMA_INVALID)
        return tuple(selected)


_INPUT_MODELS: dict[str, type[StrictModel]] = {
    "calendar.fed": CalendarQueryV1,
    "earnings.forward": EarningsQueryV1,
    "senate.efd.ptr": SenateQueryV1,
    "cboe.daily.stats": CboeQueryV1,
    "cnn.fear_greed": EmptyQueryV1,
}

_FACTOR_TAGS: dict[str, tuple[str, ...]] = {
    "calendar.fed": ("event_risk",),
    "earnings.forward": ("earnings", "event_risk"),
    "senate.efd.ptr": ("political_trades",),
    "cboe.daily.stats": ("volatility",),
    "cnn.fear_greed": ("sentiment",),
}

_VALUE_MODELS: dict[str, type[StrictModel]] = {
    "calendar.fed": CalendarValueV1,
    "earnings.forward": EarningsValueV1,
    "senate.efd.ptr": SenatePTRValueV1,
    "cboe.daily.stats": CboeValueV1,
    "cnn.fear_greed": FearGreedValueV1,
}

_SOURCE_IDS = {operation_id: f"api_anything.{operation_id}" for operation_id in _VALUE_MODELS}


def parse_operation_result(reply: SidecarReply) -> PublicOperationResultV1:
    if reply.error_code is not None:
        raise PublicOperationError(reply.error_code)
    operation_id = reply.operation_id
    if operation_id is None or operation_id not in _VALUE_MODELS:
        raise PublicOperationError(PublicOperationErrorCode.SCHEMA_INVALID)
    if (
        reply.source_id != _SOURCE_IDS[operation_id]
        or reply.source_tier != 3
        or reply.template_version is None
    ):
        raise PublicOperationError(PublicOperationErrorCode.SCHEMA_INVALID)
    fetched_at = reply.fetched_at.astimezone(UTC)
    observation = (reply.as_of or fetched_at).astimezone(UTC)
    records: list[PublicOperationRecordV1] = []
    for raw in reply.records:
        try:
            if raw.get("redistribution") is not False:
                raise ValueError("redistribution required")
            data_raw = raw.get("values")
            if not isinstance(data_raw, dict):
                raise ValueError("record values missing")
            event_at = _parse_datetime(raw.get("event_at"))
            published_at = _parse_datetime(raw.get("published_at"))
            available_at = _parse_datetime(raw.get("available_at"))
            knowable_at = _parse_datetime(raw.get("knowable_at"))
            record_as_of = _parse_datetime(raw.get("as_of")) or observation
            quality = raw.get("quality")
            if quality not in {"source_timestamped", "first_observed", "availability_unknown"}:
                raise ValueError("invalid quality status")
            record_id = str(raw["record_id"])
            data = cast(
                OperationValueV1,
                _VALUE_MODELS[operation_id].model_validate_json(
                    json.dumps(
                        {
                            key: value
                            for key, value in data_raw.items()
                            if key not in {"record_id", "as_of", "available_at", "knowable_at"}
                        },
                        allow_nan=False,
                    )
                ),
            )
            records.append(
                PublicOperationRecordV1(
                    operation_id=operation_id,
                    template_version=reply.template_version,
                    source_id=reply.source_id,
                    source_tier=3,
                    record_id=record_id,
                    fetched_at=fetched_at,
                    as_of=record_as_of,
                    event_at=event_at,
                    published_at=published_at,
                    available_at=available_at,
                    knowable_at=knowable_at,
                    factor_tags=_FACTOR_TAGS[operation_id],
                    quality=cast(QualityStatus, quality),
                    status=reply.status,
                    data=data,
                )
            )
        except (KeyError, TypeError, ValueError, ValidationError):
            raise PublicOperationError(PublicOperationErrorCode.SCHEMA_INVALID) from None
    return PublicOperationResultV1(
        operation_id=operation_id,
        template_version=reply.template_version,
        source_id=reply.source_id,
        source_tier=3,
        status=reply.status,
        fetched_at=fetched_at,
        as_of=observation,
        knowable_at=reply.knowable_at.astimezone(UTC) if reply.knowable_at else None,
        records=tuple(records),
    )


def _parse_datetime(value: object) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("timestamp must be text")
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timezone-aware timestamp required")
    return parsed.astimezone(UTC)


def _iso(value: datetime | None) -> str | None:
    return value.astimezone(UTC).isoformat() if value is not None else None


class SidecarReply(StrictModel):
    schema_version: Literal[1]
    request_id: str
    operation_id: str | None = None
    template_version: str | None = None
    source_id: str | None = None
    source_tier: Literal[3] | None = None
    status: OperationStatus
    fetched_at: datetime
    as_of: datetime | None
    knowable_at: datetime | None
    redistribution: Literal[False]
    records: tuple[dict[str, object], ...] = Field(max_length=MAX_RECORDS)
    error_code: PublicOperationErrorCode | None = None

    @field_validator("fetched_at", "as_of", "knowable_at")
    @classmethod
    def timestamps_must_be_aware(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("timezone-aware timestamp required")
        return value

    @model_validator(mode="after")
    def provenance_is_complete(self) -> SidecarReply:
        if self.status is OperationStatus.OK and self.operation_id is not None and any(
            value is None
            for value in (
                self.operation_id,
                self.template_version,
                self.source_id,
                self.source_tier,
            )
        ):
            raise ValueError("missing operation provenance")
        if self.redistribution is not False:
            raise ValueError("redistribution must be false")
        return self


class CollectorSupervisor:
    """Owns one bounded Node child and one serialized request/reply stream."""

    def __init__(
        self,
        node_executable: str | Path,
        sidecar_script: str | Path,
        *,
        data_dir: str | Path | None = None,
        timeout_s: float = CALL_TIMEOUT_SECONDS,
    ) -> None:
        if not 0 < timeout_s <= 180:
            raise ValueError("INVALID_TIMEOUT")
        self._node = str(node_executable)
        self._script = str(sidecar_script)
        self._data_dir = str(data_dir) if data_dir is not None else None
        self._timeout_s = timeout_s
        self._proc: subprocess.Popen[bytes] | None = None
        self._started_at = 0.0
        self._replies: queue.Queue[bytes | BaseException] = queue.Queue(maxsize=8)
        self.events: queue.Queue[CollectorNotificationV1] = queue.Queue(maxsize=16)
        self._lock = threading.Lock()

    def _start(self) -> subprocess.Popen[bytes]:
        if self._proc is not None and self._proc.poll() is None:
            if time.monotonic() - self._started_at < MAX_PROCESS_LIFETIME_SECONDS:
                return self._proc
            self.close(force=True)
        if self._data_dir is None:
            raise PublicOperationError(PublicOperationErrorCode.COLLECTOR_UNAVAILABLE)
        try:
            child_env = os.environ.copy()
            child_env["LEVIATHAN_COLLECTOR_DATA"] = self._data_dir
            self._proc = subprocess.Popen(
                [self._node, self._script],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                shell=False,
                close_fds=True,
                env=child_env,
            )
        except OSError:
            raise PublicOperationError(PublicOperationErrorCode.COLLECTOR_UNAVAILABLE) from None
        self._replies = queue.Queue(maxsize=8)
        self.events = queue.Queue(maxsize=16)
        self._started_at = time.monotonic()
        threading.Thread(target=self._read_replies, args=(self._proc,), daemon=True).start()
        return self._proc

    def _read_replies(self, process: subprocess.Popen[bytes]) -> None:
        assert process.stdout is not None
        try:
            while True:
                line = process.stdout.readline(MAX_LINE_BYTES + 1)
                if not line:
                    self._replies.put(
                        PublicOperationError(PublicOperationErrorCode.COLLECTOR_UNAVAILABLE)
                    )
                    return
                if len(line) > MAX_LINE_BYTES or not line.endswith(b"\n"):
                    self._replies.put(PublicOperationError(PublicOperationErrorCode.SCHEMA_INVALID))
                    return
                try:
                    event = json.loads(line)
                except (UnicodeDecodeError, json.JSONDecodeError):
                    self._replies.put(PublicOperationError(PublicOperationErrorCode.SCHEMA_INVALID))
                    return
                if isinstance(event, dict) and event.get("type") == "notification":
                    try:
                        notification = CollectorNotificationV1.model_validate_json(line)
                    except ValidationError:
                        self._replies.put(
                            PublicOperationError(PublicOperationErrorCode.SCHEMA_INVALID)
                        )
                        return
                    self.events.put(notification)
                    continue
                self._replies.put(line)
        except BaseException:
            self._replies.put(PublicOperationError(PublicOperationErrorCode.COLLECTOR_UNAVAILABLE))

    def _request(
        self,
        method: str,
        operation_id: str | None = None,
        args: Mapping[str, object] | None = None,
        examples: tuple[Mapping[str, object], Mapping[str, object]] | None = None,
    ) -> SidecarReply:
        with self._lock:
            request_id = str(uuid.uuid4())
            message: dict[str, object] = {"method": method, "request_id": request_id}
            if operation_id is not None:
                message["operation_id"] = operation_id
                if method == "learn":
                    message["examples"] = [dict(example) for example in examples or ()]
                else:
                    message["args"] = dict(args or {})
            encoded = json.dumps(message, separators=(",", ":")).encode("utf-8") + b"\n"
            if len(encoded) > MAX_LINE_BYTES:
                raise PublicOperationError(PublicOperationErrorCode.SCHEMA_INVALID)
            process = self._start()
            assert process.stdin is not None
            try:
                process.stdin.write(encoded)
                process.stdin.flush()
                raw = self._replies.get(timeout=self._timeout_s)
            except (OSError, queue.Empty):
                self.close(force=True)
                raise PublicOperationError(PublicOperationErrorCode.COLLECTOR_UNAVAILABLE) from None
            if isinstance(raw, BaseException):
                self.close(force=True)
                if isinstance(raw, PublicOperationError):
                    raise raw
                raise PublicOperationError(PublicOperationErrorCode.COLLECTOR_UNAVAILABLE) from None
            try:
                reply = SidecarReply.model_validate_json(raw)
            except ValidationError:
                self.close(force=True)
                raise PublicOperationError(PublicOperationErrorCode.SCHEMA_INVALID) from None
            if reply.request_id != request_id:
                self.close(force=True)
                raise PublicOperationError(PublicOperationErrorCode.SCHEMA_INVALID)
            if reply.error_code is not None:
                raise PublicOperationError(reply.error_code)
            return reply

    def health(self) -> SidecarReply:
        return self._request("health")

    def call(self, operation_id: str, args: Mapping[str, object]) -> PublicOperationResultV1:
        return self._typed_operation("call", operation_id, args)

    def repair(self, operation_id: str, args: Mapping[str, object]) -> PublicOperationResultV1:
        return self._typed_operation("repair", operation_id, args)

    def learn(
        self,
        operation_id: str,
        examples: tuple[Mapping[str, object], Mapping[str, object]],
    ) -> str:
        """Learn from two validated examples and return the canary-approved template version."""
        model = _INPUT_MODELS.get(operation_id)
        if model is None or len(examples) != 2:
            raise PublicOperationError(PublicOperationErrorCode.SCHEMA_INVALID)
        try:
            validated = tuple(
                model.model_validate_json(json.dumps(dict(example), allow_nan=False)).model_dump(
                    mode="json"
                )
                for example in examples
            )
        except (TypeError, ValueError, ValidationError):
            raise PublicOperationError(PublicOperationErrorCode.SCHEMA_INVALID) from None
        reply = self._request(
            "learn",
            operation_id,
            examples=(
                cast(Mapping[str, object], validated[0]),
                cast(Mapping[str, object], validated[1]),
            ),
        )
        if reply.status is not OperationStatus.OK or reply.template_version is None:
            raise PublicOperationError(PublicOperationErrorCode.OPERATION_DEGRADED)
        return reply.template_version

    def _typed_operation(
        self, method: str, operation_id: str, args: Mapping[str, object]
    ) -> PublicOperationResultV1:
        model = _INPUT_MODELS.get(operation_id)
        if model is None:
            raise PublicOperationError(PublicOperationErrorCode.SCHEMA_INVALID)
        try:
            validated = model.model_validate_json(json.dumps(dict(args), allow_nan=False))
        except (TypeError, ValueError, ValidationError):
            raise PublicOperationError(PublicOperationErrorCode.SCHEMA_INVALID) from None
        reply = self._request(method, operation_id, validated.model_dump(mode="json"))
        return parse_operation_result(reply)

    def next_event(self, timeout_s: float = 0.0) -> CollectorNotificationV1 | None:
        try:
            return self.events.get(timeout=timeout_s)
        except queue.Empty:
            return None

    def close(self, *, force: bool = False) -> None:
        process, self._proc = self._proc, None
        if process is None or process.poll() is not None:
            return
        if force:
            process.kill()
        else:
            process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)


__all__ = [
    "CALL_TIMEOUT_SECONDS",
    "MAX_EVIDENCE_REFS",
    "MAX_LINE_BYTES",
    "MAX_PROCESS_LIFETIME_SECONDS",
    "MAX_RECORDS",
    "CollectorNotificationV1",
    "CollectorSupervisor",
    "OperationStatus",
    "PublicOperationError",
    "PublicOperationErrorCode",
    "PublicOperationRecordV1",
    "PublicOperationResultV1",
    "QualityStatus",
]
