"""Fake-first live subscription and freshness value contracts."""

from __future__ import annotations

import re
from decimal import Decimal
from typing import Literal

from pydantic import Field, field_validator

from leviathan_core.seal import Issuer, SealedModel
from leviathan_market_data.schema import INT64_MAX

EntitlementState = Literal["GRANTED", "DENIED", "UNKNOWN"]
SourceState = Literal["ACTIVE", "HALTED", "DISCONNECTED", "UNKNOWN"]
FreshnessState = Literal[
    "UNKNOWN", "HEALTHY", "DEGRADED", "STALE", "DISCONNECTED", "HALTED", "UNENTITLED"
]
SequencePolicy = Literal[
    "contiguous", "monotonic_noncontiguous_session_reset", "unavailable"
]
StreamKey = tuple[str, str, str, str, str, str]

_SUBSCRIPTION_ISSUER = Issuer("md004.subscription.v1")
_HEARTBEAT_ISSUER = Issuer("md004.heartbeat.v1")
_HEALTH_ISSUER = Issuer("md004.stream_health.v1")
_VERDICT_ISSUER = Issuer("md004.freshness_verdict.v1")
_RESUME_TOKEN = re.compile(r"[A-Za-z0-9._~-]{1,256}\Z", re.ASCII)


def _valid_resume_token(value: object) -> bool:
    return type(value) is str and _RESUME_TOKEN.fullmatch(value) is not None


class LiveStateError(ValueError):
    """Content-free error for live freshness state transitions."""

    _CODES = frozenset(
        {
            "INVALID_IDENTITY",
            "INVALID_TIME",
            "INVALID_POLICY",
            "INVALID_STATE",
            "SUBSCRIPTION_EXISTS",
            "SUBSCRIPTION_MISSING",
            "RATE_LIMITED",
            "INVALID_HEARTBEAT",
            "SESSION_MISMATCH",
            "ENVELOPE_TOO_LARGE",
            "INVALID_ENVELOPE",
            "INVALID_SUBSCRIPTION",
            "INVALID_DRIFT",
            "SOURCE_FAILURE",
            "MONOTONIC_CLOCK_REGRESSION",
            "REQUIRED_STREAM_MISSING",
            "REQUIRED_STREAM_UNHEALTHY",
            "CAPACITY_EXCEEDED",
            "INVALID_RESUME_TOKEN",
        }
    )

    def __init__(self, code: str) -> None:
        self.code = code if type(code) is str and code in self._CODES else "INVALID_STATE"
        super().__init__(self.code)


class LiveSubscriptionV1(SealedModel):
    """Immutable identity and heartbeat contract for one subscribed stream."""

    schema_version: Literal["leviathan.live-subscription/1"] = "leviathan.live-subscription/1"
    provider: str
    dataset: str
    venue: str
    instrument_id: str
    channel: str
    session_id: str
    heartbeat_interval_ns: int
    sequence_policy: SequencePolicy
    required: bool = True
    required_group: str | None = None

    @field_validator(
        "provider", "dataset", "venue", "instrument_id", "channel", "session_id"
    )
    @classmethod
    def _identity(cls, value: str) -> str:
        if type(value) is not str or not value or value != value.strip() or len(value) > 128:
            raise ValueError("INVALID_IDENTITY")
        return value

    @field_validator("heartbeat_interval_ns", mode="before")
    @classmethod
    def _interval(cls, value: object) -> int:
        if type(value) is not int or not 0 < value <= INT64_MAX:
            raise ValueError("INVALID_POLICY")
        return value

    @field_validator("required", mode="before")
    @classmethod
    def _required(cls, value: object) -> bool:
        if type(value) is not bool:
            raise ValueError("INVALID_STATE")
        return value

    @field_validator("required_group", mode="before")
    @classmethod
    def _required_group(cls, value: object) -> str | None:
        if value is None:
            return None
        if type(value) is not str or not value or value != value.strip() or len(value) > 128:
            raise ValueError("INVALID_POLICY")
        return value

    @property
    def stream_key(self) -> StreamKey:
        return (
            self.provider,
            self.dataset,
            self.venue,
            self.instrument_id,
            self.channel,
            self.session_id,
        )


class LiveHeartbeatV1(SealedModel):
    """Typed provider heartbeat frame; receipt time is captured by the kernel."""

    schema_version: Literal["leviathan.live-heartbeat/1"] = "leviathan.live-heartbeat/1"
    session_id: str
    provider_time_ns: int | None = None
    resume_token: str | None = None

    @field_validator("session_id")
    @classmethod
    def _session(cls, value: str) -> str:
        if type(value) is not str or not value or value != value.strip() or len(value) > 128:
            raise ValueError("INVALID_IDENTITY")
        return value

    @field_validator("provider_time_ns", mode="before")
    @classmethod
    def _provider_time(cls, value: object) -> int | None:
        if value is not None and (type(value) is not int or not 0 < value <= INT64_MAX):
            raise ValueError("INVALID_TIME")
        return value

    @field_validator("resume_token")
    @classmethod
    def _resume_token(cls, value: str | None) -> str | None:
        if value is not None and not _valid_resume_token(value):
            raise ValueError("INVALID_RESUME_TOKEN")
        return value


class StreamHealthV1(SealedModel):
    """Sealed observation of source health; it grants no execution authority."""

    schema_version: Literal["leviathan.stream-health/1"] = "leviathan.stream-health/1"
    stream_key: StreamKey
    state: FreshnessState
    last_heartbeat_utc_ns: int | None
    last_heartbeat_monotonic_ns: int | None
    last_provider_time_ns: int | None
    evaluated_utc_ns: int
    heartbeat_age_ns: int | None
    node_drift_ms: Decimal | None
    entitlement: EntitlementState
    source_status: SourceState
    resume_token: str | None
    reason_codes: tuple[str, ...] = Field(max_length=8)


class FreshnessVerdictV1(SealedModel):
    """Fail-closed publication decision; this package never enables execution."""

    schema_version: Literal["leviathan.freshness-verdict/1"] = "leviathan.freshness-verdict/1"
    stream_key: StreamKey | None
    state: FreshnessState
    evaluated_utc_ns: int
    publication_allowed: bool
    execution_eligible: Literal[False] = False
    heartbeat_age_ns: int | None
    node_drift_ms: Decimal | None
    reason_codes: tuple[str, ...] = Field(max_length=8)

    @field_validator("publication_allowed", mode="before")
    @classmethod
    def _publication_allowed(cls, value: object) -> bool:
        if type(value) is not bool:
            raise ValueError("INVALID_STATE")
        return value


def make_live_subscription(
    *,
    provider: str,
    dataset: str,
    venue: str,
    instrument_id: str,
    channel: str,
    session_id: str,
    heartbeat_interval_ns: int,
    sequence_policy: SequencePolicy,
    required: bool = True,
    required_group: str | None = None,
) -> LiveSubscriptionV1:
    """Create an identity-checked, sealed subscription request."""
    identities = (provider, dataset, venue, instrument_id, channel, session_id)
    if any(
        type(value) is not str or not value or value != value.strip() or len(value) > 128
        for value in identities
    ):
        raise LiveStateError("INVALID_IDENTITY")
    if type(heartbeat_interval_ns) is not int or not 0 < heartbeat_interval_ns <= INT64_MAX:
        raise LiveStateError("INVALID_POLICY")
    if sequence_policy not in (
        "contiguous", "monotonic_noncontiguous_session_reset", "unavailable"
    ):
        raise LiveStateError("INVALID_POLICY")
    if type(required) is not bool:
        raise LiveStateError("INVALID_STATE")
    if required and (
        type(required_group) is not str
        or not required_group
        or required_group != required_group.strip()
        or len(required_group) > 128
    ):
        raise LiveStateError("INVALID_POLICY")
    if not required and required_group is not None and (
        type(required_group) is not str
        or not required_group
        or required_group != required_group.strip()
        or len(required_group) > 128
    ):
        raise LiveStateError("INVALID_POLICY")
    try:
        candidate = LiveSubscriptionV1(
            provider=provider,
            dataset=dataset,
            venue=venue,
            instrument_id=instrument_id,
            channel=channel,
            session_id=session_id,
            heartbeat_interval_ns=heartbeat_interval_ns,
            sequence_policy=sequence_policy,
            required=required,
            required_group=required_group,
        )
        return _SUBSCRIPTION_ISSUER.issue(candidate)
    except Exception:
        raise LiveStateError("INVALID_STATE") from None


def _issue_health(**values: object) -> StreamHealthV1:
    return _HEALTH_ISSUER.issue(StreamHealthV1(**values))  # type: ignore[arg-type]


def make_live_heartbeat(
    *, session_id: str, provider_time_ns: int | None = None, resume_token: str | None = None
) -> LiveHeartbeatV1:
    """Create an immutable fake or adapter heartbeat frame."""
    try:
        return _HEARTBEAT_ISSUER.issue(
            LiveHeartbeatV1(
                session_id=session_id,
                provider_time_ns=provider_time_ns,
                resume_token=resume_token,
            )
        )
    except Exception:
        raise LiveStateError("INVALID_HEARTBEAT") from None


def _issue_verdict(**values: object) -> FreshnessVerdictV1:
    return _VERDICT_ISSUER.issue(FreshnessVerdictV1(**values))  # type: ignore[arg-type]


def _is_issued_subscription(value: object) -> bool:
    return _SUBSCRIPTION_ISSUER.issued_here(value)


def _is_issued_heartbeat(value: object) -> bool:
    return _HEARTBEAT_ISSUER.issued_here(value)
