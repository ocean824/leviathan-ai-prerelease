"""Offline advisory assessment from reviewed source to paper eligibility.

This module grants no account, order, risk-policy or profitability authority.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO, Literal, Protocol

from pydantic import field_validator

from leviathan_core.execution.broker_port_v1 import BrokerEnvironment
from leviathan_core.numeric.canonical import canonical_json
from leviathan_core.research.replay_job import (
    ReplayArtifacts,
    ReplayJobError,
    ReplayRunSpec,
    VerifiedReplayArtifactsV1,
    _reject_reparse_point,
    canonical_bytes,
    require_verified_replay_artifacts,
    run_replay_job,
    verify_replay_artifacts,
)
from leviathan_core.risk.halt import HaltAuthority
from leviathan_core.schemas.base import LeviathanModel
from leviathan_core.schemas.strategy import StrategyGenome
from leviathan_core.seal import Issuer, SealedModel, SealError, require
from leviathan_core.text.safe_label import contains_deny_word, is_safe_identifier

from .models import VERSION, ReviewResultV1, StrategyIngestError
from .review import require_reviewed_spec

_IDENT = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,127}\Z", re.ASCII)
_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z", re.ASCII)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_PROMOTION_ISSUER = Issuer("strat.paper_promotion.result.v1")
_CONTENT_CLAIM_KIND = "strategy_content_identity_v1"
_CONTENT_CLAIM_SCHEMA = "strat.strategy-content-claim/1"
_CONTENT_DIGEST_SCHEMA = "strat.strategy-content/1"
_MAX_PROMOTION_INPUT_BYTES = 64 * 1024 * 1024

PromotionReasonV1 = Literal[
    "ELIGIBLE",
    "LIVE_ENVIRONMENT",
    "HALT_ACTIVE",
    "REVIEW_UNRESOLVED",
    "REVIEW_IDENTITY_UNBOUND",
    "STRATEGY_IDENTITY_MISMATCH",
    "REPLAY_INCOMPLETE",
    "REPLAY_FAILED",
    "REPLAY_NOT_REPRODUCED",
    "RISK_POLICY_UNBOUND",
    "RISK_POLICY_MISMATCH",
]


class PaperPromotionError(ValueError):
    """Content-free input and issuance error for the advisory promotion boundary."""

    _CODES = frozenset({"INVALID_INPUT", "EVIDENCE_NOT_ISSUED", "RESULT_NOT_ISSUED"})

    def __init__(self, code: str) -> None:
        if code not in self._CODES:
            code = "INVALID_INPUT"
        self.code = code
        super().__init__(code)


class PromotionStrategyIdentityV1(LeviathanModel):
    """Closed-grammar identity that must bind review and replay independently."""

    strategy_ref: str
    strategy_id: str
    strategy_version: str

    @field_validator("strategy_ref")
    @classmethod
    def _valid_ref(cls, value: str) -> str:
        if type(value) is not str or _REF.fullmatch(value) is None:
            raise ValueError("invalid strategy reference")
        return value

    @field_validator("strategy_id")
    @classmethod
    def _valid_id(cls, value: str) -> str:
        if type(value) is not str or _IDENT.fullmatch(value) is None:
            raise ValueError("invalid strategy identity")
        return value

    @field_validator("strategy_version")
    @classmethod
    def _valid_version(cls, value: str) -> str:
        if type(value) is not str or VERSION.fullmatch(value) is None:
            raise ValueError("invalid strategy version")
        return value


class RiskPolicyDigestPort(Protocol):
    """Trusted source of the currently governed risk-lock digest."""

    def current_policy_sha256(self) -> str | None: ...

    def current_policy_lock_path(self) -> Path | None: ...


class PaperPromotionResultV1(SealedModel):
    """SEAL-issued, data-only advisory result; it contains no action capability."""

    schema_version: Literal["strat.paper-promotion-result/1"]
    status: Literal["ELIGIBLE", "NOT_ELIGIBLE"]
    reason_code: PromotionReasonV1
    provenance: Literal["C102_COMPLETE_REHASHED", "C102_NOT_VERIFIED", "REPRODUCED"]
    diagnostic_code: Literal["IDENTITY_LABEL_DISALLOWED"] | None = None
    strategy_identity: PromotionStrategyIdentityV1
    strategy_spec_sha256: str | None
    review_packet_sha256: str | None
    replay_input_sha256: str | None
    replay_result_sha256: str | None
    dataset_id: str | None
    dataset_version: str | None
    bars_sha256: str | None
    truth_sha256: str | None
    risk_policy_sha256: str | None
    advisory_only: Literal[True]


def require_paper_promotion_result(value: object) -> PaperPromotionResultV1:
    """Require an exact result issued by this module."""
    if type(value) is not PaperPromotionResultV1:
        raise PaperPromotionError("RESULT_NOT_ISSUED")
    try:
        return require(value, _PROMOTION_ISSUER.tag)
    except SealError:
        raise PaperPromotionError("RESULT_NOT_ISSUED") from None


def strategy_content_sha256(genome: StrategyGenome) -> str:
    """Hash the exact canonical strategy genome content for a reviewed claim."""
    if type(genome) is not StrategyGenome:
        raise PaperPromotionError("INVALID_INPUT")
    payload = {
        "schema_version": _CONTENT_DIGEST_SCHEMA,
        "genome": genome.model_dump(mode="json"),
    }
    return hashlib.sha256(canonical_json(payload)).hexdigest()


def execution_inputs_sha256(spec: ReplayRunSpec) -> str:
    """Hash the replay parameters that determine execution behavior."""
    if type(spec) is not ReplayRunSpec:
        raise PaperPromotionError("INVALID_INPUT")
    payload = {
        "decision_inputs": spec.decision_inputs.model_dump(mode="json"),
        "fill_model": spec.fill_model.model_dump(mode="json"),
        "seed": spec.seed,
        "universe_version": spec.dataset.universe_version,
    }
    return hashlib.sha256(canonical_json(payload)).hexdigest()


def _read_bounded_input(path: Path) -> bytes | None:
    """Read at most the promotion input budget plus one sentinel byte."""
    with _open_regular_no_follow(path) as source:
        contents = source.read(_MAX_PROMOTION_INPUT_BYTES + 1)
    return None if len(contents) > _MAX_PROMOTION_INPUT_BYTES else contents


def _open_regular_no_follow(path: Path) -> BinaryIO:
    """Open a verified artifact without following a final link or reparse point."""
    try:
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            os.close(descriptor)
            raise OSError("artifact is not a regular file")
        if os.name == "nt" and getattr(info, "st_file_attributes", 0) & 0x400:
            os.close(descriptor)
            raise OSError("artifact is a reparse point")
        return os.fdopen(descriptor, "rb")
    except OSError:
        raise


def _content_claim_matches(
    *,
    claim_text: str,
    identity: PromotionStrategyIdentityV1,
    genome: StrategyGenome,
    dataset_id: str,
    dataset_version: str,
    bars_sha256: str,
    execution_inputs_digest: str,
) -> bool:
    expected = {
        "schema_version": _CONTENT_CLAIM_SCHEMA,
        "strategy_ref": identity.strategy_ref,
        "strategy_id": identity.strategy_id,
        "strategy_version": identity.strategy_version,
        "strategy_content_sha256": strategy_content_sha256(genome),
        "dataset_id": dataset_id,
        "dataset_version": dataset_version,
        "bars_sha256": bars_sha256,
        "execution_inputs_sha256": execution_inputs_digest,
    }
    identifier_fields = (
        "strategy_ref",
        "strategy_id",
        "strategy_version",
        "dataset_id",
        "dataset_version",
    )
    if any(
        not is_safe_identifier(expected[field]) or contains_deny_word(expected[field])
        for field in identifier_fields
    ):
        return False
    if any(
        _SHA256.fullmatch(expected[field]) is None
        for field in (
            "strategy_content_sha256",
            "bars_sha256",
            "execution_inputs_sha256",
        )
    ):
        return False

    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate claim field")
            result[key] = value
        return result

    try:
        parsed = json.loads(claim_text, object_pairs_hook=unique_object)
        if (
            type(parsed) is not dict
            or set(parsed) != set(expected)
            or any(type(value) is not str for value in parsed.values())
            or canonical_json(parsed).decode("utf-8") != claim_text
        ):
            return False
        for field in identifier_fields:
            value = parsed[field]
            if not is_safe_identifier(value) or contains_deny_word(value):
                return False
        for field in (
            "strategy_content_sha256",
            "bars_sha256",
            "execution_inputs_sha256",
        ):
            value = parsed[field]
            if _SHA256.fullmatch(value) is None:
                return False
        return parsed == expected
    except Exception:
        return False


def _load_verified_replay_spec(
    verified: VerifiedReplayArtifactsV1,
) -> ReplayRunSpec | None:
    """Read the sealed canonical input before review; unreadable input is incomplete."""
    try:
        root = Path(verified.artifact_root)
        _reject_reparse_point(root)
        if str(root.resolve(strict=True)) != verified.artifact_root:
            return None
        path = root / "input.canonical.json"
        _reject_reparse_point(path)
        contents = _read_bounded_input(path)
        if contents is None:
            return None
        if hashlib.sha256(contents).hexdigest() != verified.input_sha256:
            return None
        spec = ReplayRunSpec.model_validate_json(contents)
        if canonical_bytes(spec) != contents:
            return None

        bars = spec.dataset.bars
        epoch = datetime(1970, 1, 1, tzinfo=UTC)

        def timestamp_ns(value: datetime) -> int:
            delta = value.astimezone(UTC) - epoch
            return (
                delta.days * 86_400 + delta.seconds
            ) * 1_000_000_000 + delta.microseconds * 1_000

        if (
            spec.strategy.strategy_ref != verified.strategy_ref
            or spec.strategy.strategy_version != verified.strategy_version
            or spec.strategy.genome.strategy_id != verified.strategy_id
            or spec.dataset.dataset_id != verified.dataset_id
            or spec.dataset.dataset_version != verified.dataset_version
            or spec.dataset.bars_sha256 != verified.bars_sha256
            or not bars
            or timestamp_ns(bars[0].timestamp) != verified.first_bar_ns
            or timestamp_ns(bars[-1].timestamp) != verified.last_bar_ns
            or spec.truth.truth_provider != verified.truth_provider
            or spec.truth.result.truth_status != verified.truth_status
            or hashlib.sha256(canonical_bytes(spec.truth)).hexdigest() != verified.truth_sha256
        ):
            return None
        return spec
    except Exception:
        return None


def _result(
    *,
    identity: PromotionStrategyIdentityV1,
    reason: PromotionReasonV1,
    spec_sha256: str | None = None,
    packet_sha256: str | None = None,
    replay: VerifiedReplayArtifactsV1 | None = None,
    policy_sha256: str | None = None,
    diagnostic_code: Literal["IDENTITY_LABEL_DISALLOWED"] | None = None,
) -> PaperPromotionResultV1:
    result = _PROMOTION_ISSUER.issue(
        PaperPromotionResultV1(
            schema_version="strat.paper-promotion-result/1",
            status="ELIGIBLE" if reason == "ELIGIBLE" else "NOT_ELIGIBLE",
            reason_code=reason,
            provenance=(
                "C102_NOT_VERIFIED"
                if replay is None
                else "REPRODUCED"
                if reason == "ELIGIBLE"
                else "C102_COMPLETE_REHASHED"
            ),
            diagnostic_code=diagnostic_code,
            strategy_identity=identity,
            strategy_spec_sha256=spec_sha256,
            review_packet_sha256=packet_sha256,
            replay_input_sha256=replay.input_sha256 if replay is not None else None,
            replay_result_sha256=replay.result_sha256 if replay is not None else None,
            dataset_id=replay.dataset_id if replay is not None else None,
            dataset_version=replay.dataset_version if replay is not None else None,
            bars_sha256=replay.bars_sha256 if replay is not None else None,
            truth_sha256=replay.truth_sha256 if replay is not None else None,
            risk_policy_sha256=policy_sha256,
            advisory_only=True,
        )
    )
    return require_paper_promotion_result(result)


def assess_paper_eligibility(
    *,
    strategy_identity: PromotionStrategyIdentityV1,
    review: ReviewResultV1,
    replay: VerifiedReplayArtifactsV1,
    environment: BrokerEnvironment,
    halt_authority: HaltAuthority,
    risk_policy_digest_port: RiskPolicyDigestPort,
) -> PaperPromotionResultV1:
    """Return an advisory eligibility result from verified evidence.

    A bounded C-102 input read-back is an early REPLAY_INCOMPLETE gate, before
    review identity and policy checks. The existing safety and reason precedence
    otherwise remains unchanged.
    """
    if (
        type(strategy_identity) is not PromotionStrategyIdentityV1
        or type(review) is not ReviewResultV1
        or type(environment) is not BrokerEnvironment
        or type(halt_authority) is not HaltAuthority
        or not callable(getattr(risk_policy_digest_port, "current_policy_sha256", None))
        or not callable(getattr(risk_policy_digest_port, "current_policy_lock_path", None))
    ):
        raise PaperPromotionError("INVALID_INPUT")
    identity_label_disallowed = any(
        not is_safe_identifier(value) or contains_deny_word(value)
        for value in (
            strategy_identity.strategy_ref,
            strategy_identity.strategy_id,
            strategy_identity.strategy_version,
        )
    )

    if environment is BrokerEnvironment.LIVE:
        return _result(identity=strategy_identity, reason="LIVE_ENVIRONMENT")
    try:
        is_halted = halt_authority.halted
    except Exception:
        is_halted = True
    if is_halted:
        return _result(identity=strategy_identity, reason="HALT_ACTIVE")

    if replay is None:
        return _result(identity=strategy_identity, reason="REPLAY_INCOMPLETE")
    try:
        verified_replay = require_verified_replay_artifacts(replay)
    except ReplayJobError:
        raise PaperPromotionError("EVIDENCE_NOT_ISSUED") from None
    if verified_replay.result_status != "completed":
        return _result(
            identity=strategy_identity,
            reason="REPLAY_FAILED",
            replay=verified_replay,
        )
    replay_spec = _load_verified_replay_spec(verified_replay)
    if replay_spec is None:
        return _result(
            identity=strategy_identity,
            reason="REPLAY_INCOMPLETE",
            replay=verified_replay,
        )

    spec = review.spec
    if (
        review.packet.status != "REVIEWED"
        or spec is None
        or review.packet.packet_sha256 != spec.packet_sha256
        or review.packet.source != spec.source
        or review.packet.reviewer_actions != spec.reviewer_actions
    ):
        return _result(identity=strategy_identity, reason="REVIEW_UNRESOLVED")
    try:
        require_reviewed_spec(spec)
    except StrategyIngestError:
        raise PaperPromotionError("EVIDENCE_NOT_ISSUED") from None

    identity_claims = tuple(
        claim
        for claim in spec.accepted_claims
        if claim.claim_key == _CONTENT_CLAIM_KIND or claim.claim_kind == _CONTENT_CLAIM_KIND
    )
    if (
        len(identity_claims) != 1
        or identity_claims[0].claim_kind != _CONTENT_CLAIM_KIND
        or identity_claims[0].claim_key != _CONTENT_CLAIM_KIND
        or not _content_claim_matches(
            claim_text=identity_claims[0].claim_text,
            identity=strategy_identity,
            genome=replay_spec.strategy.genome,
            dataset_id=replay_spec.dataset.dataset_id,
            dataset_version=replay_spec.dataset.dataset_version,
            bars_sha256=replay_spec.dataset.bars_sha256,
            execution_inputs_digest=execution_inputs_sha256(replay_spec),
        )
    ):
        return _result(
            identity=strategy_identity,
            reason="REVIEW_IDENTITY_UNBOUND",
            spec_sha256=spec.spec_sha256,
            packet_sha256=spec.packet_sha256,
            diagnostic_code=("IDENTITY_LABEL_DISALLOWED" if identity_label_disallowed else None),
        )

    if (
        strategy_identity.strategy_ref != verified_replay.strategy_ref
        or strategy_identity.strategy_id != verified_replay.strategy_id
        or strategy_identity.strategy_version != verified_replay.strategy_version
    ):
        return _result(
            identity=strategy_identity,
            reason="STRATEGY_IDENTITY_MISMATCH",
            spec_sha256=spec.spec_sha256,
            packet_sha256=spec.packet_sha256,
            replay=verified_replay,
        )

    try:
        policy_sha256 = risk_policy_digest_port.current_policy_sha256()
        lock_path = risk_policy_digest_port.current_policy_lock_path()
        if not isinstance(lock_path, Path):
            raise OSError("risk policy lock unavailable")
        lock_bytes = lock_path.read_bytes()
        lock_sha256 = hashlib.sha256(lock_bytes).hexdigest()
    except Exception:
        policy_sha256 = None
        lock_path = None
        lock_bytes = None
        lock_sha256 = None
    if type(policy_sha256) is not str or _SHA256.fullmatch(policy_sha256) is None:
        return _result(
            identity=strategy_identity,
            reason="RISK_POLICY_UNBOUND",
            spec_sha256=spec.spec_sha256,
            packet_sha256=spec.packet_sha256,
            replay=verified_replay,
        )
    if lock_bytes is None or lock_sha256 != policy_sha256:
        return _result(
            identity=strategy_identity,
            reason="RISK_POLICY_UNBOUND",
            spec_sha256=spec.spec_sha256,
            packet_sha256=spec.packet_sha256,
            replay=verified_replay,
        )
    if policy_sha256 != verified_replay.verified_lock_sha256:
        return _result(
            identity=strategy_identity,
            reason="RISK_POLICY_MISMATCH",
            spec_sha256=spec.spec_sha256,
            packet_sha256=spec.packet_sha256,
            replay=verified_replay,
            policy_sha256=policy_sha256,
        )
    if not _replay_is_reproduced(verified_replay, lock_bytes):
        return _result(
            identity=strategy_identity,
            reason="REPLAY_NOT_REPRODUCED",
            spec_sha256=spec.spec_sha256,
            packet_sha256=spec.packet_sha256,
            replay=verified_replay,
            policy_sha256=policy_sha256,
        )
    return _result(
        identity=strategy_identity,
        reason="ELIGIBLE",
        spec_sha256=spec.spec_sha256,
        packet_sha256=spec.packet_sha256,
        replay=verified_replay,
        policy_sha256=policy_sha256,
    )


def _replay_is_reproduced(verified: VerifiedReplayArtifactsV1, lock_bytes: bytes) -> bool:
    """Re-run a verified local input against copied lock bytes and compare hashes."""
    try:
        artifact_root = Path(verified.artifact_root)
        if str(artifact_root.resolve(strict=True)) != verified.artifact_root:
            return False
        input_path = artifact_root / "input.canonical.json"
        result_path = artifact_root / "result.canonical.json"
        _reject_reparse_point(input_path)
        _reject_reparse_point(result_path)
        with _open_regular_no_follow(input_path) as source:
            input_bytes = source.read(_MAX_PROMOTION_INPUT_BYTES + 1)
        with _open_regular_no_follow(result_path) as source:
            original_result_bytes = source.read(_MAX_PROMOTION_INPUT_BYTES + 1)
        if (
            len(input_bytes) > _MAX_PROMOTION_INPUT_BYTES
            or len(original_result_bytes) > _MAX_PROMOTION_INPUT_BYTES
        ):
            return False
        if hashlib.sha256(input_bytes).hexdigest() != verified.input_sha256:
            return False
        if hashlib.sha256(original_result_bytes).hexdigest() != verified.result_sha256:
            return False
        if hashlib.sha256(lock_bytes).hexdigest() != verified.verified_lock_sha256:
            return False

        with tempfile.TemporaryDirectory(prefix="strat-paper-promotion-") as temporary:
            temporary_root = Path(temporary)
            fixture_copy = temporary_root / "input.canonical.json"
            lock_copy = temporary_root / "risk-lock.yaml"
            fixture_copy.write_bytes(input_bytes)
            lock_copy.write_bytes(lock_bytes)
            output_dir = temporary_root / "reproduction-output"
            output_dir.mkdir()
            if any(output_dir.iterdir()):
                return False

            artifacts: ReplayArtifacts = run_replay_job(
                fixture_copy,
                lock_copy,
                output_dir,
            )
            reproduced = verify_replay_artifacts(artifacts)
            reproduced_result_bytes = (output_dir / "result.canonical.json").read_bytes()
            return (
                reproduced.input_sha256 == verified.input_sha256
                and reproduced.result_sha256 == verified.result_sha256
                and reproduced.artifact_sha256 == verified.artifact_sha256
                and reproduced_result_bytes == original_result_bytes
            )
    except Exception:
        return False
