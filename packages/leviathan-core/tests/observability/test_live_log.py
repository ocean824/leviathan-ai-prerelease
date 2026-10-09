"""Unit coverage for the bounded OBS-002 live-log kernel."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from leviathan_core.observability.context import (
    BuildIdentityV1,
    DiagnosticIdFactoryV1,
    DiagnosticRegistriesV1,
    DiagnosticRuntimeV1,
    ObservationContextV1,
    RegistrySnapshotV1,
)
from leviathan_core.observability.live_log import (
    LiveLogBufferV1,
    LiveLogError,
    LiveLogErrorCodeV1,
    LiveLogEventV1,
    LiveLogResultCodeV1,
    LiveLogSummaryCodeV1,
    LiveLogToolCategoryV1,
    LiveLogToolNameV1,
)
from leviathan_core.observability.redaction import MAX_LINE_BYTES, RedactionError
from leviathan_core.security.principal_verifier import (
    PrincipalVerifier,
    RSAPublicKeyV1,
    TrustedIssuerV1,
    VerifiedPrincipalV1,
)

_NOW = datetime(2026, 10, 6, 12, 0, tzinfo=UTC)
_BASE_UTC_NS = int(_NOW.timestamp()) * 1_000_000_000
_ISSUER = "issuer.synthetic"
_AUDIENCE = "api.synthetic"
_KID = "live-test-key"
_DER_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")
_KEY_PATH = Path(__file__).parents[1] / "security" / "fixtures" / "sec003_synthetic_rsa.json"
_KEY_DATA = json.loads(_KEY_PATH.read_text(encoding="utf-8"))
_MODULUS = int(_KEY_DATA["modulus_hex"], 16)
_EXPONENT = int(_KEY_DATA["private_exponent_hex"], 16)


class _KeySet:
    def get_key(self, issuer: str, kid: str) -> RSAPublicKeyV1 | None:
        if issuer == _ISSUER and kid == _KID:
            return RSAPublicKeyV1(_MODULUS, 65537)
        return None


class _Revocations:
    def is_revoked(self, issuer: str, jti: str) -> bool:
        return False


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _principal(
    *,
    org_id: str = "org-live-a",
    role: str = "Operator",
    scopes: tuple[str, ...] = ("logs.append", "logs.read"),
) -> VerifiedPrincipalV1:
    issued = int(_NOW.timestamp())
    claims: dict[str, object] = {
        "iss": _ISSUER,
        "aud": _AUDIENCE,
        "org": org_id,
        "sub": "service.agent-alpha",
        "role": role,
        "scope": list(scopes),
        "env": "staging",
        "jti": f"jti-{org_id}",
        "iat": issued,
        "nbf": issued,
        "exp": issued + 300,
        "venue": None,
        "portfolio": None,
        "strategy": None,
    }
    header = {"alg": "RS256", "kid": _KID, "typ": "JWT"}
    segments = [
        _b64(json.dumps(item, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        for item in (header, claims)
    ]
    message = ".".join(segments)
    digest_info = _DER_PREFIX + hashlib.sha256(message.encode("ascii")).digest()
    key_bytes = (_MODULUS.bit_length() + 7) // 8
    padding_length = key_bytes - len(digest_info) - 3
    encoded = b"\x00\x01" + b"\xff" * padding_length + b"\x00" + digest_info
    signature = pow(int.from_bytes(encoded, "big"), _EXPONENT, _MODULUS).to_bytes(
        key_bytes, "big"
    )
    token = f"{message}.{_b64(signature)}"
    verifier = PrincipalVerifier(
        trusted_issuer=TrustedIssuerV1(
            _ISSUER,
            _AUDIENCE,
            org_id,
            "leviathan-ai",
            "staging",
        ),
        key_set=_KeySet(),
        revocations=_Revocations(),
        clock=lambda: _NOW,
    )
    return verifier.verify(token)


def _context() -> ObservationContextV1:
    runtime = DiagnosticRuntimeV1(
        registries=DiagnosticRegistriesV1(
            services=RegistrySnapshotV1.from_members({"leviathan-ai"}),
            components=RegistrySnapshotV1.from_members({"agent-alpha"}),
            strategies=RegistrySnapshotV1.from_members({"strategy-alpha"}),
            instruments=RegistrySnapshotV1.from_members({"AAPL"}),
            venues=RegistrySnapshotV1.from_members({"XNAS"}),
        ),
        id_factory=DiagnosticIdFactoryV1(uuid4_factory=uuid4),
        build_identity=BuildIdentityV1("1.2.3"),
    )
    return ObservationContextV1.create(
        runtime=runtime,
        service="leviathan-ai",
        component="agent-alpha",
        env="staging",
    )


def _event(
    *,
    context: ObservationContextV1 | None = None,
    summary_code: object = LiveLogSummaryCodeV1.TOOL_COMPLETED,
) -> LiveLogEventV1:
    return LiveLogEventV1.create(
        context=context or _context(),
        started_utc_ns=_BASE_UTC_NS,
        ended_utc_ns=_BASE_UTC_NS + 1_000,
        tool_name=LiveLogToolNameV1.TERMINAL,
        tool_category=LiveLogToolCategoryV1.RESEARCH,
        result_code=LiveLogResultCodeV1.SUCCESS,
        summary_code=summary_code,  # type: ignore[arg-type]
    )


def test_event_serializes_only_registered_identity_and_closed_summary_values() -> None:
    principal = _principal()
    event = _event()
    payload = json.loads(event.to_json())

    assert payload["agent_identity"] == {
        "service": "leviathan-ai",
        "component": "agent-alpha",
    }
    assert payload["tool_name"] == "TERMINAL"
    assert payload["tool_category"] == "RESEARCH"
    assert payload["summary_code"] == "TOOL_COMPLETED"
    assert payload["result_code"] == "SUCCESS"
    assert payload["event_id"] == event.event_id
    assert payload["correlation_id"] == event.correlation_id
    assert len(event.to_json().encode("utf-8")) <= MAX_LINE_BYTES
    assert principal.org_id not in event.to_json()
    assert principal.subject_id not in event.to_json()


@pytest.mark.parametrize(
    ("summary", "expected_redacted"),
    [
        (None, False),
        ("private reasoning: do not log", True),
        ("Bearer synthetic-token-value", True),
    ],
)
def test_missing_or_unpermitted_summary_is_not_emitted(
    summary: object, expected_redacted: bool
) -> None:
    event = _event(summary_code=summary)
    serialized = event.to_json()

    assert event.summary_code is LiveLogSummaryCodeV1.DETAIL_UNAVAILABLE
    assert event.redacted is expected_redacted
    assert "private reasoning" not in serialized
    assert "synthetic-token-value" not in serialized
    assert "DETAIL_UNAVAILABLE" in serialized


def test_unicode_summary_and_unexpected_payload_arguments_never_enter_log() -> None:
    secret_shaped_text = "研究" * 100_000
    event = _event(summary_code=secret_shaped_text)

    assert event.summary_code is LiveLogSummaryCodeV1.DETAIL_UNAVAILABLE
    assert secret_shaped_text not in event.to_json()
    with pytest.raises(TypeError):
        LiveLogEventV1.create(
            context=_context(),
            started_utc_ns=1,
            ended_utc_ns=2,
            tool_name=LiveLogToolNameV1.TERMINAL,
            tool_category=LiveLogToolCategoryV1.RESEARCH,
            result_code=LiveLogResultCodeV1.SUCCESS,
            summary_code=LiveLogSummaryCodeV1.TOOL_COMPLETED,
            tool_payload={"output": "do not log"},  # type: ignore[call-arg]
        )


def test_event_rejects_raw_tool_names_and_invalid_timestamps() -> None:
    with pytest.raises(LiveLogError) as invalid_tool:
        LiveLogEventV1.create(
            context=_context(),
            started_utc_ns=1,
            ended_utc_ns=2,
            tool_name="run-private-shell",  # type: ignore[arg-type]
            tool_category=LiveLogToolCategoryV1.RESEARCH,
            result_code=LiveLogResultCodeV1.SUCCESS,
        )
    assert invalid_tool.value.code is LiveLogErrorCodeV1.EVENT_INVALID
    assert "run-private-shell" not in str(invalid_tool.value)

    with pytest.raises(LiveLogError) as invalid_time:
        LiveLogEventV1.create(
            context=_context(),
            started_utc_ns=True,  # type: ignore[arg-type]
            ended_utc_ns=2,
            tool_name=LiveLogToolNameV1.TERMINAL,
            tool_category=LiveLogToolCategoryV1.RESEARCH,
            result_code=LiveLogResultCodeV1.SUCCESS,
        )
    assert invalid_time.value.code is LiveLogErrorCodeV1.EVENT_INVALID

    current_epoch = LiveLogEventV1.create(
        context=_context(),
        started_utc_ns=_BASE_UTC_NS,
        ended_utc_ns=_BASE_UTC_NS + 1_000,
        tool_name=LiveLogToolNameV1.TERMINAL,
        tool_category=LiveLogToolCategoryV1.RESEARCH,
        result_code=LiveLogResultCodeV1.SUCCESS,
    )
    assert current_epoch.started_utc_ns == _BASE_UTC_NS
    assert current_epoch.ended_utc_ns == _BASE_UTC_NS + 1_000

    with pytest.raises(LiveLogError) as overflow_time:
        LiveLogEventV1.create(
            context=_context(),
            started_utc_ns=2**63,
            ended_utc_ns=2**63,
            tool_name=LiveLogToolNameV1.TERMINAL,
            tool_category=LiveLogToolCategoryV1.RESEARCH,
            result_code=LiveLogResultCodeV1.SUCCESS,
        )
    assert overflow_time.value.code is LiveLogErrorCodeV1.EVENT_INVALID


def test_redaction_failure_becomes_a_constant_safe_event(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import leviathan_core.observability.models as observation_models

    def fail_redaction(*args: object, **kwargs: object) -> Any:
        raise RedactionError("simulated unsafe input must not escape")

    monkeypatch.setattr(observation_models, "sanitize_fields", fail_redaction)
    event = _event()
    serialized = event.to_json()

    assert event.result_code is LiveLogResultCodeV1.REDACTION_FAILURE
    assert event.summary_code is LiveLogSummaryCodeV1.DETAIL_UNAVAILABLE
    assert event.error_code is not None
    assert event.redacted is False
    assert "simulated unsafe input" not in serialized
    assert "REDACTION_FAILURE" in serialized
    assert len(serialized.encode("utf-8")) <= MAX_LINE_BYTES


def test_append_read_scopes_and_cross_org_isolation() -> None:
    async def scenario() -> None:
        buffer = LiveLogBufferV1(max_entries=8, max_orgs=8)
        view = buffer.view()
        writer = _principal()
        event = _event()
        sequence = await buffer.append(writer, event)
        rows = await view.read_live(writer)

        assert sequence == 1
        assert len(rows) == 1
        assert rows[0].sequence == 1
        assert rows[0].gap_before is False
        assert rows[0].event is event

        other_org = _principal(org_id="org-live-b")
        assert await view.read_live(other_org) == ()
        assert "org-live-a" not in rows[0].event.to_json()
        assert "service.agent-alpha" not in rows[0].event.to_json()
        assert not hasattr(view, "append")
        assert not hasattr(view, "pause")
        assert not hasattr(view, "export")

    asyncio.run(scenario())


def test_missing_scope_and_non_operator_reads_fail_with_code_only_errors() -> None:
    async def scenario() -> None:
        buffer = LiveLogBufferV1(max_orgs=8)
        reader = _principal(scopes=("logs.append",))
        with pytest.raises(LiveLogError) as no_read_scope:
            await buffer.view().read_live(reader)
        assert no_read_scope.value.code is LiveLogErrorCodeV1.READ_FORBIDDEN
        assert no_read_scope.value.args == (LiveLogErrorCodeV1.READ_FORBIDDEN.value,)

        non_operator = _principal(role="researcher", scopes=("logs.read", "logs.append"))
        with pytest.raises(LiveLogError) as wrong_role:
            await buffer.view().read_live(non_operator)
        assert wrong_role.value.code is LiveLogErrorCodeV1.READ_FORBIDDEN

        no_append_scope = _principal(scopes=("logs.read",))
        with pytest.raises(LiveLogError) as no_append:
            await buffer.append(no_append_scope, _event())
        assert no_append.value.code is LiveLogErrorCodeV1.APPEND_FORBIDDEN

    asyncio.run(scenario())


def test_concurrent_appends_preserve_per_org_order_and_eviction_reports_gap() -> None:
    async def scenario() -> None:
        buffer = LiveLogBufferV1(max_entries=3, max_orgs=8)
        writer = _principal()
        events = [_event() for _ in range(5)]
        sequence_numbers = await asyncio.gather(
            *(buffer.append(writer, item) for item in events)
        )

        assert sequence_numbers == [1, 2, 3, 4, 5]
        rows = await buffer.view().read_live(writer)
        assert [row.sequence for row in rows] == [3, 4, 5]
        assert [row.gap_before for row in rows] == [True, False, False]

    asyncio.run(scenario())


def test_org_capacity_bounds_sequence_state_without_reusing_counters() -> None:
    async def scenario() -> None:
        buffer = LiveLogBufferV1(max_entries=1, max_orgs=4)
        principals = [
            _principal(org_id=f"org-live-{index}") for index in range(12)
        ]

        accepted = [
            await buffer.append(principal, _event())
            for principal in principals[:4]
        ]
        assert accepted == [1, 1, 1, 1]
        assert len(buffer._entries) == 1
        assert len(buffer._sequences) == 4

        for principal in principals[4:]:
            with pytest.raises(LiveLogError) as capacity_error:
                await buffer.append(principal, _event())
            assert capacity_error.value.code is LiveLogErrorCodeV1.CAPACITY_EXCEEDED
            assert capacity_error.value.args == (
                LiveLogErrorCodeV1.CAPACITY_EXCEEDED.value,
            )
            assert principal.org_id not in str(capacity_error.value)

        assert len(buffer._entries) == 1
        assert len(buffer._sequences) == 4

        # Eviction releases the event but not its admitted organization's cursor.
        sequence = await buffer.append(principals[0], _event())
        assert sequence == 2
        rows = await buffer.view().read_live(principals[0])
        assert [(row.sequence, row.gap_before) for row in rows] == [(2, True)]

    asyncio.run(scenario())


@pytest.mark.parametrize("max_orgs", [0, -1, 100_001, True])
def test_buffer_rejects_invalid_org_capacity(max_orgs: object) -> None:
    with pytest.raises(LiveLogError) as invalid_capacity:
        LiveLogBufferV1(max_orgs=max_orgs)  # type: ignore[arg-type]
    assert invalid_capacity.value.code is LiveLogErrorCodeV1.BUFFER_INVALID


def test_live_stream_yields_appends_in_sequence_order() -> None:
    async def scenario() -> None:
        buffer = LiveLogBufferV1(max_entries=8, max_orgs=8)
        writer = _principal()
        view = buffer.view()
        stream = view.stream_live(writer)
        first_waiter = asyncio.create_task(anext(stream))
        await asyncio.sleep(0)
        first_sequence = await buffer.append(writer, _event())
        first = await asyncio.wait_for(first_waiter, timeout=1)
        second_sequence = await buffer.append(writer, _event())
        second = await asyncio.wait_for(anext(stream), timeout=1)
        await stream.aclose()

        assert (first.sequence, second.sequence) == (first_sequence, second_sequence)
        assert first.sequence < second.sequence

    asyncio.run(scenario())
