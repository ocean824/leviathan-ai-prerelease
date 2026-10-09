"""Independent OBS-002 public-surface acceptance with synthetic identities."""

from __future__ import annotations

import base64
import hashlib
import json
import pickle
from datetime import UTC, datetime
from pathlib import Path
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
from leviathan_core.observability.models import ErrorCode
from leviathan_core.observability.redaction import RedactionError
from leviathan_core.seal import SealError
from leviathan_core.security.principal_verifier import (
    PrincipalVerifier,
    RSAPublicKeyV1,
    TrustedIssuerV1,
    VerifiedPrincipalV1,
)

FIXTURES = Path(__file__).parent.parent / "security" / "fixtures"
_KEY_DATA = json.loads((FIXTURES / "sec003_synthetic_rsa.json").read_text(encoding="utf-8"))
_PUBLIC_N = int(_KEY_DATA["modulus_hex"], 16)
_PUBLIC_E = int(_KEY_DATA["public_exponent_hex"], 16)
_PRIVATE_D = int(_KEY_DATA["private_exponent_hex"], 16)
_ISSUER = "https://issuer.synthetic.invalid"
_AUDIENCE = "leviathan-api"
_PROJECT = "leviathan-ai"
_ENV = "staging"
_KID = "synthetic-key-v1"
_NOW = datetime(2026, 10, 5, 18, 30, tzinfo=UTC)
_NOW_SECONDS = int(_NOW.timestamp())


class _KeySet:
    def get_key(self, issuer: str, kid: str) -> RSAPublicKeyV1 | None:
        if (issuer, kid) == (_ISSUER, _KID):
            return RSAPublicKeyV1(_PUBLIC_N, _PUBLIC_E)
        return None


class _Revocations:
    def is_revoked(self, issuer: str, jti: str) -> bool:
        return False


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _segment(value: object) -> str:
    return _b64(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def _sign(message: bytes) -> bytes:
    digest_info = bytes.fromhex("3031300d060960864801650304020105000420")
    digest_info += hashlib.sha256(message).digest()
    size = (_PUBLIC_N.bit_length() + 7) // 8
    padding = size - len(digest_info) - 3
    encoded = b"\x00\x01" + b"\xff" * padding + b"\x00" + digest_info
    return pow(int.from_bytes(encoded, "big"), _PRIVATE_D, _PUBLIC_N).to_bytes(size, "big")


def _principal(*, org: str = "org-obs002", role: str = "Operator",
               scopes: tuple[str, ...] = ("logs.append", "logs.read")) -> VerifiedPrincipalV1:
    claims = {
        "iss": _ISSUER,
        "aud": _AUDIENCE,
        "org": org,
        "sub": "synthetic-observer",
        "role": role,
        "scope": list(scopes),
        "env": _ENV,
        "jti": f"jti-{uuid4().hex}",
        "iat": _NOW_SECONDS,
        "nbf": _NOW_SECONDS,
        "exp": _NOW_SECONDS + 600,
    }
    header = {"alg": "RS256", "kid": _KID, "typ": "JWT"}
    signing_input = f"{_segment(header)}.{_segment(claims)}".encode("ascii")
    token = f"{signing_input.decode('ascii')}.{_b64(_sign(signing_input))}"
    verifier = PrincipalVerifier(
        trusted_issuer=TrustedIssuerV1(
            issuer=_ISSUER,
            audience=_AUDIENCE,
            org_id=org,
            project_id=_PROJECT,
            env=_ENV,
        ),
        key_set=_KeySet(),
        revocations=_Revocations(),
        clock=lambda: _NOW,
    )
    return verifier.verify(token)


def _context() -> ObservationContextV1:
    registries = DiagnosticRegistriesV1(
        services=RegistrySnapshotV1.from_members(("agent-runtime",)),
        components=RegistrySnapshotV1.from_members(("live-log",)),
        strategies=RegistrySnapshotV1.from_members(("synthetic-strategy",)),
        instruments=RegistrySnapshotV1.from_members(("SYNTH-X",)),
        venues=RegistrySnapshotV1.from_members(("XNAS",)),
    )
    runtime = DiagnosticRuntimeV1(
        registries=registries,
        id_factory=DiagnosticIdFactoryV1(uuid4_factory=uuid4),
        build_identity=BuildIdentityV1("1.2.3"),
    )
    return ObservationContextV1.create(
        runtime=runtime,
        service="agent-runtime",
        component="live-log",
        env="staging",
    )


def _event(*, summary=LiveLogSummaryCodeV1.TOOL_COMPLETED) -> LiveLogEventV1:
    return LiveLogEventV1.create(
        context=_context(),
        started_utc_ns=1_800_000_000_000_000_000,
        ended_utc_ns=1_800_000_000_000_000_250,
        tool_name=LiveLogToolNameV1.SEARCH,
        tool_category=LiveLogToolCategoryV1.RESEARCH,
        result_code=LiveLogResultCodeV1.SUCCESS,
        summary_code=summary,
    )


def test_event_contains_only_allowlisted_metadata_and_fixed_summary() -> None:
    event = _event()
    payload = json.loads(event.to_json())

    assert event.duration_ns == 250
    assert event.service == "agent-runtime"
    assert event.component == "live-log"
    assert event.summary_code is LiveLogSummaryCodeV1.TOOL_COMPLETED
    assert payload["tool_name"] == "SEARCH"
    assert payload["tool_category"] == "RESEARCH"
    assert payload["result_code"] == "SUCCESS"
    assert payload["summary_code"] == "TOOL_COMPLETED"
    assert payload["message"] == "Operation completed."
    assert payload["started_utc_ns"] == event.started_utc_ns
    assert payload["ended_utc_ns"] == event.ended_utc_ns
    assert len(event.to_json().encode("utf-8")) <= 64 * 1024
    for forbidden in (
        "org-obs002",
        "synthetic-observer",
        "prompt",
        "chain_of_thought",
        "arguments",
    ):
        assert forbidden not in event.to_json().casefold()


@pytest.mark.parametrize("summary", [None, "SYNTHETIC_SECRET_CANARY", 7])
def test_absent_or_non_enum_summary_degrades_to_detail_unavailable(summary) -> None:
    event = _event(summary=summary)

    assert event.summary_code is LiveLogSummaryCodeV1.DETAIL_UNAVAILABLE
    assert event.redacted is (summary is not None)
    assert "SYNTHETIC_SECRET_CANARY" not in event.to_json()
    assert event.message == "Observation recorded."


def test_prompt_or_tool_payload_cannot_be_passed_at_event_boundary() -> None:
    with pytest.raises(TypeError) as caught:
        LiveLogEventV1.create(
            context=_context(),
            started_utc_ns=10,
            ended_utc_ns=11,
            tool_name=LiveLogToolNameV1.MCP,
            tool_category=LiveLogToolCategoryV1.DATA,
            result_code=LiveLogResultCodeV1.SUCCESS,
            prompt="SYNTHETIC_SECRET_CANARY",
        )
    assert "SYNTHETIC_SECRET_CANARY" not in str(caught.value)


def test_redaction_failure_emits_only_fixed_fallback(monkeypatch) -> None:
    def fail_redaction(*_args, **_kwargs):
        raise RedactionError("synthetic failure details must not escape")

    monkeypatch.setattr("leviathan_core.observability.models.sanitize_fields", fail_redaction)
    event = _event()

    assert event.result_code is LiveLogResultCodeV1.REDACTION_FAILURE
    assert event.summary_code is LiveLogSummaryCodeV1.DETAIL_UNAVAILABLE
    assert event.error_code is ErrorCode.REDACTION_FAILURE
    assert event.message == "Observation redaction failed."
    assert "synthetic failure details" not in event.to_json()


@pytest.mark.asyncio
async def test_append_read_are_scope_checked_and_org_partitioned() -> None:
    buffer = LiveLogBufferV1(max_entries=4, max_orgs=4)
    view = buffer.view()
    owner = _principal()
    other_org = _principal(org="org-other")
    event = _event()

    assert await buffer.append(owner, event) == 1
    assert await view.read_live(other_org) == ()
    entries = await view.read_live(owner)
    assert len(entries) == 1
    assert entries[0].sequence == 1
    assert entries[0].gap_before is False
    assert entries[0].event is event
    assert "org-obs002" not in event.to_json()

    with pytest.raises(LiveLogError) as denied:
        await buffer.append(_principal(scopes=("logs.read",)), event)
    assert denied.value.code is LiveLogErrorCodeV1.APPEND_FORBIDDEN
    assert denied.value.args == (LiveLogErrorCodeV1.APPEND_FORBIDDEN.value,)

    with pytest.raises(LiveLogError) as no_scope:
        await view.read_live(_principal(scopes=("logs.append",)))
    assert no_scope.value.code is LiveLogErrorCodeV1.READ_FORBIDDEN

    with pytest.raises(LiveLogError) as wrong_role:
        await view.read_live(_principal(role="Researcher"))
    assert wrong_role.value.code is LiveLogErrorCodeV1.READ_FORBIDDEN

    for candidate in ({"org_id": "org-obs002"}, object()):
        with pytest.raises(LiveLogError) as invalid:
            await view.read_live(candidate)  # type: ignore[arg-type]
        assert invalid.value.code is LiveLogErrorCodeV1.PRINCIPAL_INVALID
        assert invalid.value.args == (LiveLogErrorCodeV1.PRINCIPAL_INVALID.value,)


@pytest.mark.asyncio
async def test_bounded_retention_exposes_gaps_and_preserves_order() -> None:
    buffer = LiveLogBufferV1(max_entries=2, max_orgs=4)
    view = buffer.view()
    principal = _principal()
    events = [_event() for _ in range(3)]

    assert [await buffer.append(principal, event) for event in events] == [1, 2, 3]
    entries = await view.read_live(principal, after_sequence=0)
    assert [entry.sequence for entry in entries] == [2, 3]
    assert [entry.gap_before for entry in entries] == [True, False]
    stream = view.stream_live(principal, after_sequence=1)
    streamed = [await anext(stream), await anext(stream)]
    await stream.aclose()
    assert [entry.sequence for entry in streamed] == [2, 3]


@pytest.mark.asyncio
async def test_org_admission_capacity_is_bounded_without_reusing_sequences() -> None:
    buffer = LiveLogBufferV1(max_entries=1, max_orgs=4)
    principals = [
        _principal(org=f"org-capacity-{index}") for index in range(1, 13)
    ]
    event = _event()

    sequences = [
        await buffer.append(principal, event) for principal in principals[:4]
    ]
    assert sequences == [1, 1, 1, 1]
    assert len(buffer._sequences) == 4

    for principal in principals[4:]:
        with pytest.raises(LiveLogError) as capacity_error:
            await buffer.append(principal, event)
        assert capacity_error.value.code is LiveLogErrorCodeV1.CAPACITY_EXCEEDED
        assert capacity_error.value.args == (
            LiveLogErrorCodeV1.CAPACITY_EXCEEDED.value,
        )
        assert principal.org_id not in str(capacity_error.value)
        assert len(buffer._sequences) == 4

    # Event eviction does not free an admitted org slot or reset its sequence.
    assert await buffer.append(principals[0], event) == 2
    retained = await buffer.view().read_live(principals[0])
    assert [(entry.sequence, entry.gap_before) for entry in retained] == [(2, True)]
    assert len(buffer._sequences) == 4


def test_live_view_has_no_write_or_control_methods_and_events_cannot_be_forged() -> None:
    view = LiveLogBufferV1(max_orgs=1).view()
    assert not any(hasattr(view, name) for name in ("append", "pause", "filter", "export", "route"))

    event = _event()
    with pytest.raises(SealError):
        LiveLogEventV1.model_validate(event.model_dump())
    with pytest.raises((TypeError, ValueError)):
        pickle.dumps(event)
