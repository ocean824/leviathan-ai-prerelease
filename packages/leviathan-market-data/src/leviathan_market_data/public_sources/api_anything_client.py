"""Typed, fail-closed client for the private-stdio api-anything sidecar."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import queue
import re
import signal
import subprocess
import threading
import time
import uuid
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Literal, cast

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

MAX_LINE_BYTES = 1_100_000
MAX_RECORDS = 500
MAX_EVIDENCE_REFS = 128
CALL_TIMEOUT_SECONDS = 150.0
LEARN_REPAIR_TIMEOUT_SECONDS = 750.0
HUMAN_ACTION_TIMEOUT_SECONDS = 600.0
MAX_PROCESS_LIFETIME_SECONDS = 900.0
MAX_EVIDENCE_AGE: dict[str, timedelta] = {
    "calendar.fed": timedelta(days=365),
    "earnings.forward": timedelta(days=90),
    "senate.efd.ptr": timedelta(days=365),
    "cboe.daily.stats": timedelta(days=14),
    "cnn.fear_greed": timedelta(days=7),
}
_POSIX_KILL = "killpg"
_POSIX_KILL_SIGNAL = "SIGKILL"


class PublicOperationErrorCode(StrEnum):
    COLLECTOR_UNAVAILABLE = "COLLECTOR_UNAVAILABLE"
    OPERATION_DEGRADED = "OPERATION_DEGRADED"
    SCHEMA_INVALID = "SCHEMA_INVALID"
    TEMPLATE_UNAVAILABLE = "TEMPLATE_UNAVAILABLE"
    PIN_REGISTRY_INVALID = "PIN_REGISTRY_INVALID"
    FIRST_SEEN_LEDGER_INVALID = "FIRST_SEEN_LEDGER_INVALID"
    USER_ACTION_DECLINED = "USER_ACTION_DECLINED"
    USER_ACTION_REQUIRED = "USER_ACTION_REQUIRED"
    TIMEOUT = "TIMEOUT"
    CHALLENGE_WINDOW_FAILED = "CHALLENGE_WINDOW_FAILED"
    BROWSER_UNAVAILABLE = "BROWSER_UNAVAILABLE"
    RATE_LIMITED = "RATE_LIMITED"
    NOT_DUE = "NOT_DUE"
    TEMPLATE_UNPINNED = "TEMPLATE_UNPINNED"


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
    first_seen_at: datetime
    as_of: datetime
    event_at: datetime | None
    published_at: datetime | None
    available_at: datetime | None
    knowable_at: datetime | None
    factor_tags: tuple[str, ...]
    quality: QualityStatus
    status: OperationStatus
    template_sha256: str
    approval_id: str
    approval_deadline: datetime
    freshness_deadline: datetime
    data: OperationValueV1
    values: tuple[tuple[str, str], ...] = field(init=False)
    redistribution: Literal[False] = False
    record_digest: str = field(init=False)

    def __post_init__(self) -> None:
        if not self.record_id or len(self.record_id) > 512:
            raise PublicOperationError(PublicOperationErrorCode.SCHEMA_INVALID)
        for stamp in (
            self.fetched_at,
            self.first_seen_at,
            self.as_of,
            self.event_at,
            self.published_at,
            self.available_at,
            self.knowable_at,
            self.approval_deadline,
            self.freshness_deadline,
        ):
            if stamp is not None and (stamp.tzinfo is None or stamp.utcoffset() is None):
                raise PublicOperationError(PublicOperationErrorCode.SCHEMA_INVALID)
        if (
            self.as_of > self.fetched_at
            or self.first_seen_at > self.fetched_at
            or self.freshness_deadline < self.fetched_at
            or (self.knowable_at is not None and self.knowable_at > self.fetched_at)
            or (self.knowable_at is not None and self.as_of > self.knowable_at)
            or (self.published_at is not None and self.published_at > self.fetched_at)
            or (
                self.published_at is not None
                and self.knowable_at is not None
                and self.published_at > self.knowable_at
            )
            or (
                self.available_at is not None
                and self.knowable_at is not None
                and self.available_at > self.knowable_at
            )
            or (self.knowable_at is not None and self.knowable_at < self.first_seen_at)
            or (self.quality == "availability_unknown" and self.knowable_at is not None)
            or (self.quality != "availability_unknown" and self.knowable_at is None)
            or (
                self.quality == "source_timestamped"
                and (
                    self.knowable_at is None
                    or (self.published_at is None and self.available_at is None)
                )
            )
            or (
                self.quality == "first_observed"
                and self.knowable_at != self.first_seen_at
            )
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
                "first_seen_at": _iso(self.first_seen_at),
                "as_of": _iso(self.as_of),
                "event_at": _iso(self.event_at),
                "published_at": _iso(self.published_at),
                "available_at": _iso(self.available_at),
                "knowable_at": _iso(self.knowable_at),
                "quality": self.quality,
                "status": self.status.value,
                "template_sha256": self.template_sha256,
                "approval_id": self.approval_id,
                "approval_deadline": _iso(self.approval_deadline),
                "freshness_deadline": _iso(self.freshness_deadline),
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
    template_sha256: str
    approval_id: str
    approval_deadline: datetime
    freshness_deadline: datetime
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
        if (
            not re.fullmatch(r"[a-f0-9]{64}", self.template_sha256)
            or not self.approval_id
            or self.freshness_deadline.tzinfo is None
            or self.freshness_deadline.utcoffset() is None
            or self.approval_deadline.tzinfo is None
            or self.approval_deadline.utcoffset() is None
        ):
            raise PublicOperationError(PublicOperationErrorCode.SCHEMA_INVALID)
        if self.fetched_at > datetime.now(UTC) + timedelta(minutes=5):
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
        known = [record.knowable_at for record in self.records if record.knowable_at is not None]
        expected_knowable = max(known) if known else None
        if self.knowable_at != expected_knowable:
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
        if decision_as_of > self.freshness_deadline:
            raise PublicOperationError(PublicOperationErrorCode.TEMPLATE_UNAVAILABLE)
        selected: list[PublicOperationRecordV1] = []
        for record in self.records:
            if record.as_of > decision_as_of:
                raise PublicOperationError(PublicOperationErrorCode.SCHEMA_INVALID)
            if decision_as_of - record.as_of > MAX_EVIDENCE_AGE[self.operation_id]:
                raise PublicOperationError(PublicOperationErrorCode.OPERATION_DEGRADED)
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


def parse_operation_result(
    reply: SidecarReply,
    expected_pin: Mapping[str, object] | None = None,
) -> PublicOperationResultV1:
    if reply.error_code is not None:
        raise PublicOperationError(reply.error_code)
    operation_id = reply.operation_id
    if operation_id is None or operation_id not in _VALUE_MODELS:
        raise PublicOperationError(PublicOperationErrorCode.SCHEMA_INVALID)
    if (
        reply.source_id != _SOURCE_IDS[operation_id]
        or reply.source_tier != 3
        or reply.template_version is None
        or reply.template_sha256 is None
        or reply.approval_id is None
        or reply.approval_deadline is None
        or reply.freshness_deadline is None
    ):
        raise PublicOperationError(PublicOperationErrorCode.SCHEMA_INVALID)
    if expected_pin is not None and (
        expected_pin.get("version") != reply.template_version
        or expected_pin.get("sha256") != reply.template_sha256
        or expected_pin.get("tos_review_id") != reply.approval_id
    ):
        raise PublicOperationError(PublicOperationErrorCode.TEMPLATE_UNAVAILABLE)
    if expected_pin is not None:
        try:
            approved_at = _parse_datetime(expected_pin.get("approved_at"))
            if approved_at is None:
                raise ValueError
            if reply.approval_deadline.astimezone(UTC) != approved_at + timedelta(
                days=90
            ):
                raise ValueError
        except (TypeError, ValueError):
            raise PublicOperationError(PublicOperationErrorCode.TEMPLATE_UNAVAILABLE) from None
    if reply.fetched_at.astimezone(UTC) > datetime.now(UTC) + timedelta(minutes=5):
        raise PublicOperationError(PublicOperationErrorCode.SCHEMA_INVALID)
    fetched_at = reply.fetched_at.astimezone(UTC)
    if (
        reply.approval_deadline is None
        or reply.freshness_deadline is None
        or reply.approval_deadline.astimezone(UTC) < fetched_at
        or reply.freshness_deadline.astimezone(UTC) < fetched_at
        or reply.freshness_deadline.astimezone(UTC) > fetched_at + timedelta(hours=48, minutes=5)
    ):
        raise PublicOperationError(PublicOperationErrorCode.SCHEMA_INVALID)
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
            first_seen_at = _parse_datetime(raw.get("first_seen_at"))
            record_as_of = _parse_datetime(raw.get("as_of"))
            quality = raw.get("quality")
            if quality not in {"source_timestamped", "first_observed", "availability_unknown"}:
                raise ValueError("invalid quality status")
            record_id = str(raw["record_id"])
            if first_seen_at is None or record_as_of is None or record_as_of > fetched_at:
                raise ValueError("collector timestamps required")
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
                    first_seen_at=first_seen_at,
                    as_of=record_as_of,
                    event_at=event_at,
                    published_at=published_at,
                    available_at=available_at,
                    knowable_at=knowable_at,
                    factor_tags=_FACTOR_TAGS[operation_id],
                    quality=cast(QualityStatus, quality),
                    status=reply.status,
                    template_sha256=reply.template_sha256,
                    approval_id=reply.approval_id,
                    approval_deadline=reply.approval_deadline.astimezone(UTC),
                    freshness_deadline=reply.freshness_deadline.astimezone(UTC),
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
        template_sha256=reply.template_sha256,
        approval_id=reply.approval_id,
        approval_deadline=reply.approval_deadline.astimezone(UTC),
        freshness_deadline=reply.freshness_deadline.astimezone(UTC),
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
    template_sha256: str | None = None
    approval_id: str | None = None
    approval_deadline: datetime | None = None
    freshness_deadline: datetime | None = None
    candidate_only: bool = False
    status: OperationStatus
    fetched_at: datetime
    as_of: datetime | None
    knowable_at: datetime | None
    redistribution: Literal[False]
    records: tuple[dict[str, object], ...] = Field(max_length=MAX_RECORDS)
    error_code: PublicOperationErrorCode | None = None

    @field_validator(
        "fetched_at", "as_of", "knowable_at", "approval_deadline", "freshness_deadline"
    )
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
        mac_version = platform.mac_ver()[0]
        self._replay_only = bool(
            platform.system() == "Darwin"
            and mac_version
            and tuple(int(part) for part in mac_version.split(".")[:2]) <= (11, 7)
        )
        self._timeout_s = timeout_s
        self._proc: subprocess.Popen[bytes] | None = None
        self._started_at = 0.0
        self._replies: queue.Queue[bytes | BaseException] = queue.Queue(maxsize=8)
        self.events: queue.Queue[CollectorNotificationV1] = queue.Queue(maxsize=16)
        self._challenge_waiting = threading.Event()
        self._lock = threading.Lock()

    def _start(self) -> subprocess.Popen[bytes]:
        if self._proc is not None and self._proc.poll() is None:
            if time.monotonic() - self._started_at < MAX_PROCESS_LIFETIME_SECONDS:
                return self._proc
            self.close(force=True)
        if self._data_dir is None:
            raise PublicOperationError(PublicOperationErrorCode.COLLECTOR_UNAVAILABLE)
        try:
            child_env = {
                key: os.environ[key]
                for key in (
                    "PATH",
                    "SYSTEMROOT",
                    "WINDIR",
                    "TEMP",
                    "TMP",
                    "TMPDIR",
                    "LOCALAPPDATA",
                    "PROGRAMFILES",
                    "PROGRAMFILES(X86)",
                )
                if key in os.environ
            }
            child_env["LEVIATHAN_COLLECTOR_DATA"] = self._data_dir
            child_env["LEVIATHAN_PUBLIC_USER_AGENT"] = "LeviathanPublicCollector/1.0"
            if self._replay_only:
                child_env["LEVIATHAN_REPLAY_ONLY"] = "1"
            self._proc = subprocess.Popen(
                [self._node, self._script],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                shell=False,
                close_fds=True,
                env=child_env,
                creationflags=(
                    cast(int, getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
                    if os.name == "nt"
                    else 0
                ),
                start_new_session=os.name != "nt",
            )
        except OSError:
            raise PublicOperationError(PublicOperationErrorCode.COLLECTOR_UNAVAILABLE) from None
        self._replies = queue.Queue(maxsize=8)
        self.events = queue.Queue(maxsize=16)
        self._challenge_waiting.clear()
        self._started_at = time.monotonic()
        threading.Thread(
            target=self._read_replies,
            args=(self._proc, self._replies, self.events),
            daemon=True,
        ).start()
        return self._proc

    def _read_replies(
        self,
        process: subprocess.Popen[bytes],
        replies: queue.Queue[bytes | BaseException],
        events: queue.Queue[CollectorNotificationV1],
    ) -> None:
        assert process.stdout is not None
        def enqueue_error(error: PublicOperationError) -> None:
            with suppress(queue.Full):
                replies.put_nowait(error)

        try:
            while True:
                line = process.stdout.readline(MAX_LINE_BYTES + 1)
                if not line:
                    enqueue_error(PublicOperationError(PublicOperationErrorCode.COLLECTOR_UNAVAILABLE))
                    return
                if len(line) > MAX_LINE_BYTES or not line.endswith(b"\n"):
                    enqueue_error(PublicOperationError(PublicOperationErrorCode.SCHEMA_INVALID))
                    return
                try:
                    event = json.loads(line)
                except (UnicodeDecodeError, json.JSONDecodeError):
                    enqueue_error(PublicOperationError(PublicOperationErrorCode.SCHEMA_INVALID))
                    return
                if isinstance(event, dict) and event.get("type") == "notification":
                    try:
                        notification = CollectorNotificationV1.model_validate_json(line)
                    except ValidationError:
                        enqueue_error(PublicOperationError(PublicOperationErrorCode.SCHEMA_INVALID))
                        return
                    try:
                        events.put_nowait(notification)
                    except queue.Full:
                        with suppress(queue.Empty):
                            events.get_nowait()
                        with suppress(queue.Full):
                            events.put_nowait(notification)
                    if notification.status == "USER_ACTION_REQUIRED":
                        self._challenge_waiting.set()
                    continue
                try:
                    replies.put_nowait(line)
                except queue.Full:
                    enqueue_error(PublicOperationError(PublicOperationErrorCode.SCHEMA_INVALID))
                    return
        except BaseException:
            enqueue_error(PublicOperationError(PublicOperationErrorCode.COLLECTOR_UNAVAILABLE))

    def _request(
        self,
        method: str,
        operation_id: str | None = None,
        args: Mapping[str, object] | None = None,
        examples: tuple[Mapping[str, object], Mapping[str, object]] | None = None,
        timeout_s: float | None = None,
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
                timeout = timeout_s or (
                    LEARN_REPAIR_TIMEOUT_SECONDS
                    if method in {"learn", "repair"}
                    else self._timeout_s
                )
                deadline = time.monotonic() + timeout
                while True:
                    if self._challenge_waiting.is_set():
                        deadline = max(
                            deadline,
                            time.monotonic()
                            + HUMAN_ACTION_TIMEOUT_SECONDS
                            + CALL_TIMEOUT_SECONDS,
                        )
                        self._challenge_waiting.clear()
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise queue.Empty
                    try:
                        raw = self._replies.get(timeout=min(0.25, remaining))
                        break
                    except queue.Empty:
                        continue
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
        if self._replay_only:
            raise PublicOperationError(PublicOperationErrorCode.BROWSER_UNAVAILABLE)
        return self._typed_operation("repair", operation_id, args)

    def learn(
        self,
        operation_id: str,
        examples: tuple[Mapping[str, object], Mapping[str, object]],
    ) -> str:
        """Learn two validated examples and return the quarantined candidate version."""
        if self._replay_only:
            raise PublicOperationError(PublicOperationErrorCode.BROWSER_UNAVAILABLE)
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
        if (
            reply.status is not OperationStatus.OK
            or reply.template_version is None
            or reply.template_sha256 is None
            or reply.candidate_only is not True
        ):
            raise PublicOperationError(PublicOperationErrorCode.OPERATION_DEGRADED)
        return reply.template_version

    def _pinned_entry(self, operation_id: str) -> Mapping[str, object]:
        collector_root = Path(self._script).resolve().parent.parent
        registry_path = collector_root / "templates" / "PINNED.json"
        try:
            registry_bytes = registry_path.read_bytes()
            manifest_path = collector_root / "runtime-manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            if hashlib.sha256(registry_bytes).hexdigest() != manifest.get("pin_registry_sha256"):
                raise ValueError("pin registry hash mismatch")
            registry = json.loads(registry_bytes)
            entry = registry["operations"][operation_id]
            if (
                not isinstance(entry, dict)
                or not isinstance(entry.get("version"), str)
                or not isinstance(entry.get("sha256"), str)
                or not re.fullmatch(r"[a-f0-9]{64}", entry["sha256"])
                or not isinstance(entry.get("tos_review_id"), str)
                or not isinstance(entry.get("approved_at"), str)
                or not isinstance(entry.get("allowed_hosts"), list)
                or not isinstance(entry.get("challenge_hosts"), list)
                or not isinstance(entry.get("review_note"), str)
            ):
                raise ValueError
            return cast(Mapping[str, object], entry)
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
            raise PublicOperationError(PublicOperationErrorCode.TEMPLATE_UNPINNED) from None

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
        pinned = self._pinned_entry(operation_id)
        reply = self._request(
            method,
            operation_id,
            validated.model_dump(mode="json"),
        )
        return parse_operation_result(reply, pinned)

    def next_event(self, timeout_s: float = 0.0) -> CollectorNotificationV1 | None:
        try:
            return self.events.get(timeout=timeout_s)
        except queue.Empty:
            return None

    def _clear_profile_locks(self) -> None:
        if self._data_dir is None:
            return
        data_dir = Path(self._data_dir).resolve()
        for profile_root in (data_dir / "isolated", data_dir / "learning"):
            if not profile_root.exists():
                continue
            for lock_name in ("SingletonLock", "SingletonCookie", "SingletonSocket", "lockfile"):
                for lock_path in profile_root.glob(f"**/{lock_name}"):
                    try:
                        lock_path.unlink()
                    except OSError:
                        continue

    def close(self, *, force: bool = False) -> None:
        process, self._proc = self._proc, None
        if process is None:
            return
        if process.poll() is not None:
            if force:
                self._clear_profile_locks()
            return
        if force and os.name == "nt":
            subprocess.run(
                ["taskkill.exe", "/PID", str(process.pid), "/T", "/F"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                creationflags=cast(int, getattr(subprocess, "CREATE_NO_WINDOW", 0)),
                timeout=10,
            )
        elif force:
            with suppress(ProcessLookupError):
                getattr(os, _POSIX_KILL)(process.pid, getattr(signal, _POSIX_KILL_SIGNAL))
        else:
            process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            if os.name == "nt":
                subprocess.run(
                    ["taskkill.exe", "/PID", str(process.pid), "/T", "/F"],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                    creationflags=cast(int, getattr(subprocess, "CREATE_NO_WINDOW", 0)),
                    timeout=10,
                )
            else:
                with suppress(ProcessLookupError):
                    getattr(os, _POSIX_KILL)(process.pid, getattr(signal, _POSIX_KILL_SIGNAL))
            process.wait(timeout=2)
        if force:
            self._clear_profile_locks()


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
