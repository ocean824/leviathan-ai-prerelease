"""Pure, bounded publication orchestration over an injected vault port."""

from __future__ import annotations

import hashlib
import json
import re
import stat
import struct
import zlib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal, Protocol

from leviathan_core.agent_revision_hash import (
    RevisionHashError,
    hypothesis_full_revision_from_hypothesis,
)
from leviathan_core.numeric import NumericError, canonical_json
from leviathan_core.seal import verify
from leviathan_core.security import (
    ActionV1,
    AuthorizationContextV1,
    AuthorizationDecisionV1,
    AuthorizationPolicyV1,
    EffectV1,
    ResourceV1,
    TrustedPrincipalV1,
    authorize,
)

from .critic_policy import require_critique_decision, require_publication_exception
from .experiment_identity import canonical_decimal
from .leak_models import CritiqueDecisionV1, LeakDecisionV1
from .leak_rules import require_leak_decision
from .publication_models import (
    MAX_CONFLICT_SUFFIX,
    MAX_PUBLICATION_ATTEMPTS,
    MAX_PUBLICATION_FILE_BYTES,
    MAX_PUBLICATION_FILES,
    MAX_PUBLICATION_RETRIES,
    MAX_PUBLICATION_TOTAL_BYTES,
    DisplayLabelSource,
    PublicationConflictV1,
    PublicationManifestV1,
    PublicationPlotV1,
    PublicationResultV1,
    PublishedFileV1,
    ScribeError,
    SummaryIntentV1,
    _issue_conflict,
    _issue_manifest,
    _issue_publication_result,
    _issue_published_file,
    _issue_summary_intent,
    is_safe_display_label,
)
from .runner_models import ReplayOutcomeV1, require_replay_outcome
from .state_machine import restore_verified_state
from .state_models import CouncilStateV1, HypothesisV1

COUNCIL_VAULT_PREFIX = "/Leviathan/Council/"
MAX_OUTCOMES = 256
MAX_PORT_ATTEMPTS = MAX_PUBLICATION_ATTEMPTS
_RETRY_DELAYS_NS = (10_000_000, 20_000_000, 40_000_000)
_WINDOWS_COMPONENT = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,126}[A-Za-z0-9])?\Z", re.ASCII
)
_WINDOWS_RESERVED = re.compile(
    r"(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])\Z", re.ASCII | re.IGNORECASE
)
_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_PNG_MAX_DIMENSION = 16_384
_PNG_MAX_PIXELS = 100_000_000
_PNG_MAX_DECODED_BYTES = 64 * 1024 * 1024
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(api[_ -]?key|access[_ -]?token|refresh[_ -]?token|password|secret|authorization)"
    r"(\s*[:=]\s*)([^\s,;\"']+)"
)
_SECRET_TOKEN = re.compile(r"\b(?:sk-[A-Za-z0-9_-]{20,}|AKIA[A-Z0-9]{16})\b")


class ScopedNoOverwriteVaultPort(Protocol):
    """Filesystem-scoped vault rooted at ``root``.

    Implementations must open existing files without following links (for
    example with ``O_NOFOLLOW`` on POSIX) and create files atomically without
    following reparse points. The service checks the full virtual path before
    every operation; the adapter must repeat the check at the open boundary
    to close races between validation and I/O.
    """

    @property
    def root(self) -> Path: ...

    @property
    def vault_id(self) -> str: ...

    @property
    def allowed_prefix(self) -> str: ...

    def read(self, path: str) -> bytes | None: ...

    def create_no_overwrite(
        self, path: str, content: bytes
    ) -> Literal["CREATED", "EXISTS", "OFFLINE"]: ...

    def wait_before_retry(self, delay_ns: int) -> None: ...


class PublicationClock(Protocol):
    def now_ns(self) -> int: ...


class StateChainVerifier(Protocol):
    def __call__(self, session_id: str, transition_chain_digest: str) -> bool: ...


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_reparse_or_symlink(path: Path) -> bool:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        raise ScribeError("VAULT_UNAVAILABLE") from None
    attributes = getattr(info, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISLNK(info.st_mode) or bool(attributes & reparse_flag)


def _guard_scoped_vault_path(root: Path, scoped_path: str) -> None:
    """Reject a scoped path that traverses a link or resolves outside root."""
    if (
        not isinstance(root, Path)
        or not root.is_absolute()
        or type(scoped_path) is not str
        or not scoped_path.startswith(COUNCIL_VAULT_PREFIX)
    ):
        raise ScribeError("VAULT_UNAVAILABLE")
    relative = scoped_path.lstrip("/").split("/")
    if not relative or any(not _windows_component(part) for part in relative):
        raise ScribeError("VAULT_UNAVAILABLE")

    absolute_root = root.absolute()
    cursor = Path(absolute_root.anchor)
    for part in absolute_root.parts[1:]:
        cursor = cursor / part
        try:
            if _is_reparse_or_symlink(cursor):
                raise ScribeError("VAULT_UNAVAILABLE")
            cursor.resolve(strict=True)
        except ScribeError:
            raise
        except FileNotFoundError:
            # A configured vault root may be created on the first write.
            break
        except OSError:
            raise ScribeError("VAULT_UNAVAILABLE") from None

    try:
        canonical_root = absolute_root.resolve(strict=False)
    except OSError:
        raise ScribeError("VAULT_UNAVAILABLE") from None
    target = absolute_root.joinpath(*relative)
    cursor = absolute_root
    for part in relative:
        cursor = cursor / part
        try:
            if _is_reparse_or_symlink(cursor):
                raise ScribeError("VAULT_UNAVAILABLE")
            resolved = cursor.resolve(strict=True)
        except ScribeError:
            raise
        except FileNotFoundError:
            # Missing descendants are safe only after all existing ancestors
            # have been checked for links and strict resolution escapes.
            resolved = cursor.resolve(strict=False)
        except OSError:
            raise ScribeError("VAULT_UNAVAILABLE") from None
        if not resolved.is_relative_to(canonical_root):
            raise ScribeError("VAULT_UNAVAILABLE")
    try:
        resolved_target = target.resolve(strict=False)
    except OSError:
        raise ScribeError("VAULT_UNAVAILABLE") from None
    if not resolved_target.is_relative_to(canonical_root):
        raise ScribeError("VAULT_UNAVAILABLE")


def _windows_component(value: str) -> bool:
    return (
        _WINDOWS_COMPONENT.fullmatch(value) is not None
        and _WINDOWS_RESERVED.fullmatch(value.split(".", 1)[0]) is None
    )


def _display_label(hypothesis: HypothesisV1) -> tuple[str, DisplayLabelSource]:
    """Select a short, safe label and identify its source without hashing text."""
    candidates: tuple[tuple[str, DisplayLabelSource], ...] = (
        (hypothesis.strategy_name, "strategy_name"),
        *((item, "market_symbol") for item in hypothesis.markets),
        *((item, "target_metric") for item in hypothesis.target_metrics),
        *((item.signal_id, "signal_id") for item in hypothesis.signal_refs),
    )
    for candidate, source in candidates:
        if is_safe_display_label(candidate):
            return candidate, source
    return "UNLABELLED", "market_symbol"


def _label_source_text(source: DisplayLabelSource) -> str:
    return {
        "strategy_name": "strategy name",
        "market_symbol": "market symbol",
        "target_metric": "target metric",
        "signal_id": "signal id",
    }[source]


def _validate_png(content: bytes) -> None:
    """Accept a bounded structural PNG profile without metadata extensions."""
    if type(content) is not bytes or not content.startswith(_PNG_SIGNATURE):
        raise ScribeError("PUBLICATION_INPUT_INVALID")
    offset = len(_PNG_SIGNATURE)
    chunk_index = 0
    width = height = color_type = 0
    bit_depth = 0
    idat_parts: list[bytes] = []
    saw_palette = False
    saw_data = False
    data_ended = False
    saw_end = False
    while offset < len(content):
        if len(content) - offset < 12:
            raise ScribeError("PUBLICATION_INPUT_INVALID")
        length = struct.unpack_from(">I", content, offset)[0]
        chunk_type = content[offset + 4 : offset + 8]
        data_start = offset + 8
        data_end = data_start + length
        chunk_end = data_end + 4
        if (
            chunk_end > len(content)
            or len(chunk_type) != 4
            or any(not (65 <= byte <= 90 or 97 <= byte <= 122) for byte in chunk_type)
            or not 65 <= chunk_type[2] <= 90
        ):
            raise ScribeError("PUBLICATION_INPUT_INVALID")
        data = content[data_start:data_end]
        expected_crc = struct.unpack_from(">I", content, data_end)[0]
        if zlib.crc32(chunk_type + data) & 0xFFFFFFFF != expected_crc:
            raise ScribeError("PUBLICATION_INPUT_INVALID")
        if chunk_index == 0:
            if chunk_type != b"IHDR" or length != 13:
                raise ScribeError("PUBLICATION_INPUT_INVALID")
            width, height, bit_depth, color_type, compression, filtering, interlace = (
                struct.unpack(">IIBBBBB", data)
            )
            allowed_depths = {
                0: {1, 2, 4, 8, 16},
                2: {8, 16},
                3: {1, 2, 4, 8},
                4: {8, 16},
                6: {8, 16},
            }
            if (
                width == 0
                or height == 0
                or width > _PNG_MAX_DIMENSION
                or height > _PNG_MAX_DIMENSION
                or width * height > _PNG_MAX_PIXELS
                or bit_depth not in allowed_depths.get(color_type, set())
                or compression != 0
                or filtering != 0
                or interlace != 0
            ):
                raise ScribeError("PUBLICATION_INPUT_INVALID")
        elif chunk_type == b"PLTE":
            if (
                color_type not in {2, 3, 6}
                or saw_palette
                or saw_data
                or length == 0
                or length > 768
                or length % 3
                or (color_type == 3 and length // 3 > 2**bit_depth)
            ):
                raise ScribeError("PUBLICATION_INPUT_INVALID")
            saw_palette = True
        elif chunk_type == b"IDAT":
            if not data or data_ended or (color_type == 3 and not saw_palette):
                raise ScribeError("PUBLICATION_INPUT_INVALID")
            saw_data = True
            idat_parts.append(data)
        elif chunk_type == b"IEND":
            if length != 0 or not saw_data or chunk_end != len(content):
                raise ScribeError("PUBLICATION_INPUT_INVALID")
            saw_end = True
            offset = chunk_end
            break
        else:
            # Text metadata, animation and unrecognized chunks aren't in this
            # publication-safe profile.
            raise ScribeError("PUBLICATION_INPUT_INVALID")
        if saw_data and chunk_type != b"IDAT":
            data_ended = True
        offset = chunk_end
        chunk_index += 1
    if not saw_end or offset != len(content):
        raise ScribeError("PUBLICATION_INPUT_INVALID")
    channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}[color_type]
    scanline_bytes = (width * channels * bit_depth + 7) // 8 + 1
    expected_bytes = height * scanline_bytes
    if expected_bytes > _PNG_MAX_DECODED_BYTES:
        raise ScribeError("PUBLICATION_INPUT_INVALID")
    try:
        decompressor = zlib.decompressobj()
        decoded = decompressor.decompress(b"".join(idat_parts), expected_bytes + 1)
    except zlib.error:
        raise ScribeError("PUBLICATION_INPUT_INVALID") from None
    if (
        len(decoded) != expected_bytes
        or not decompressor.eof
        or decompressor.unused_data
        or decompressor.unconsumed_tail
        or any(decoded[row * scanline_bytes] > 4 for row in range(height))
    ):
        raise ScribeError("PUBLICATION_INPUT_INVALID")


def _hypothesis_revision_hash(hypothesis: HypothesisV1) -> str:
    """Match AGENT-004's full-hypothesis binding, not AGENT-001's semantic hash."""
    try:
        return hypothesis_full_revision_from_hypothesis(hypothesis).sha256_hex
    except RevisionHashError:
        raise ScribeError("PUBLICATION_GATE_DENIED") from None


def _text(value: object) -> str:
    if type(value) is not str:
        raise ScribeError("PUBLICATION_INPUT_INVALID")
    redacted = _SECRET_ASSIGNMENT.sub(lambda m: f"{m.group(1)}{m.group(2)}[REDACTED]", value)
    return _SECRET_TOKEN.sub("[REDACTED]", redacted)


def _safe_scalar(value: object) -> object:
    if type(value) is str:
        return _text(value)
    if value is None or type(value) in {bool, int}:
        return value
    if isinstance(value, list | tuple):
        return [_safe_scalar(item) for item in value]
    if isinstance(value, dict):
        return {_text(str(key)): _safe_scalar(item) for key, item in value.items()}
    return value


def _canonical_bytes(value: object) -> bytes:
    try:
        return canonical_json(value)
    except (NumericError, TypeError, ValueError):
        raise ScribeError("PUBLICATION_INPUT_INVALID") from None


def _utc_from_ns(value: int) -> datetime:
    seconds, nanos = divmod(value, 1_000_000_000)
    return datetime(1970, 1, 1, tzinfo=UTC) + timedelta(seconds=seconds, microseconds=nanos // 1000)


def _json(data: object) -> bytes:
    return _canonical_bytes(_safe_scalar(data))


def _render_hypothesis(state: CouncilStateV1) -> bytes:
    hypothesis = state.hypothesis
    label, label_source = _display_label(hypothesis)
    summary = {
        "schema_version": "1.0.0",
        "display_label": label,
        "display_label_source": label_source,
        "hypothesis_id": "redacted",
        "version": hypothesis.version,
        "strategy_name": "redacted",
        "signal_refs": {"summary": "redacted", "count": len(hypothesis.signal_refs)},
        "markets": {"summary": "redacted", "count": len(hypothesis.markets)},
        "horizon": hypothesis.horizon.model_dump(mode="json"),
        "target_metrics": {"summary": "redacted", "count": len(hypothesis.target_metrics)},
        "max_leverage": canonical_decimal(hypothesis.max_leverage),
        "max_loss_per_trade": canonical_decimal(hypothesis.max_loss_per_trade),
        "seed_policy": hypothesis.seed_policy,
        "seed": hypothesis.seed,
        "source_hashes": list(hypothesis.source_hashes),
    }
    return (
        "# Hypothesis summary\n\n"
        f"Display label: {label} ({_label_source_text(label_source)})\n\n"
        "```json\n"
        + json.dumps(summary, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n```\n"
    ).encode("utf-8")


def _render_tldr(
    state: CouncilStateV1,
    outcomes: tuple[ReplayOutcomeV1, ...],
    critique: CritiqueDecisionV1,
) -> bytes:
    hypothesis = state.hypothesis
    label, label_source = _display_label(hypothesis)
    metrics: list[str] = []
    for outcome in outcomes:
        for evidence in outcome.metrics:
            if evidence.critique_metrics is None:
                continue
            for metric in evidence.critique_metrics.metrics:
                metrics.append(f"- {metric.name}: {canonical_decimal(metric.value)}")
    risks = ["[REDACTED]" for _ in critique.risk_flags]
    risks.extend(f"Metric threshold: {item.metric}" for item in critique.metric_failures)
    sections = [
        "# Council publication\n",
        "## Hypothesis\n",
        f"Display label: {label} ({_label_source_text(label_source)})\n",
        "## Setup\n",
        f"Markets: {len(hypothesis.markets)} configured; identifiers redacted\n",
        f"Signals: {len(hypothesis.signal_refs)} configured; identifiers redacted\n",
        "## Results\n",
        f"Decision: {critique.status}\n",
        f"Completed runs: {critique.completed_runs}/{critique.required_runs}\n",
        *(f"{line}\n" for line in (metrics or ["- No metric rows were supplied"])),
        "## Risks\n",
        *(f"- {item}\n" for item in (risks or ["None recorded"])),
        "## Next Steps\n",
        "Review the attached evidence before any separate promotion decision.\n",
    ]
    return _text("".join(sections)).encode("utf-8")


def _render_critique(critique: CritiqueDecisionV1, leak: LeakDecisionV1) -> bytes:
    risk_lines = ["- [REDACTED]" for _item in critique.risk_flags]
    if not risk_lines:
        risk_lines = ["- None recorded"]
    rows = [
        "# Critique\n",
        f"Status: {critique.status}\n",
        f"Completed runs: {critique.completed_runs}/{critique.required_runs}\n",
        "\n## Leak rules\n",
        *(f"- {item.rule_id}: {'PASS' if item.passed else item.code}\n" for item in leak.results),
        "\n## Metric failures\n",
        *(
            f"- {item.metric}: {canonical_decimal(item.actual)} "
            f"{item.comparison} {canonical_decimal(item.threshold)}\n"
            for item in critique.metric_failures
        ),
        "\n## Risk flags\n",
        *(f"{item}\n" for item in risk_lines),
    ]
    return _text("".join(rows)).encode("utf-8")


def _render_metrics(outcomes: tuple[ReplayOutcomeV1, ...]) -> bytes:
    runs: list[dict[str, object]] = []
    for run_index, outcome in enumerate(outcomes, start=1):
        values: list[dict[str, object]] = []
        for evidence in outcome.metrics:
            if evidence.critique_metrics is not None:
                values.extend(
                    {"name": metric.name, "value": metric.value}
                    for metric in evidence.critique_metrics.metrics
                )
        runs.append(
            {
                "run_index": run_index,
                "status": outcome.outcome,
                "metrics": values,
            }
        )
    return _json({"schema_version": "1.0.0", "runs": runs})


def _artifact_digest(files: dict[str, bytes]) -> str:
    entries = [
        {"path": name, "sha256": _hash(content), "size_bytes": len(content)}
        for name, content in sorted(files.items())
    ]
    return _hash(_canonical_bytes(entries))


def _result(
    status: Literal["synced", "error"],
    *,
    manifest: PublicationManifestV1 | None = None,
    intent: SummaryIntentV1 | None = None,
    error_code: Literal["VAULT_UNAVAILABLE", "VAULT_POSTCONDITION_FAILED"] | None = None,
    attempts: int = 0,
) -> PublicationResultV1:
    result = PublicationResultV1(
        status=status,
        manifest=manifest,
        summary_intent=intent,
        error_code=error_code,
        attempts=attempts,
    )
    # Pydantic revalidates nested sealed models and may copy them while building
    # the result. Issue the exact children held by the final result before sealing
    # the root, so callers can independently require each public receipt.
    if result.manifest is not None:
        for published_file in result.manifest.files:
            if not verify(published_file, "agent005.published_file.v1"):
                _issue_published_file(published_file)
        for conflict in result.manifest.conflicts:
            if not verify(conflict, "agent005.publication_conflict.v1"):
                _issue_conflict(conflict)
        if not verify(result.manifest, "agent005.publication_manifest.v1"):
            _issue_manifest(result.manifest)
    if result.summary_intent is not None and not verify(
        result.summary_intent, "agent005.summary_intent.v1"
    ):
        _issue_summary_intent(result.summary_intent)
    return _issue_publication_result(result)


class ScribePublicationService:
    """Publish only approved, leak-clean council evidence to a scoped port."""

    def __init__(
        self,
        vault_port: ScopedNoOverwriteVaultPort,
        authorization_policy: AuthorizationPolicyV1,
        clock: PublicationClock,
        state_chain_verifier: StateChainVerifier,
    ) -> None:
        if (
            type(authorization_policy) is not AuthorizationPolicyV1
            or not callable(getattr(vault_port, "read", None))
            or not callable(getattr(vault_port, "create_no_overwrite", None))
            or not callable(getattr(vault_port, "wait_before_retry", None))
            or not callable(getattr(clock, "now_ns", None))
            or not callable(state_chain_verifier)
        ):
            raise ScribeError("PUBLICATION_INPUT_INVALID")
        vault_id = getattr(vault_port, "vault_id", None)
        prefix = getattr(vault_port, "allowed_prefix", None)
        vault_root = getattr(vault_port, "root", None)
        if (
            type(vault_id) is not str
            or not _windows_component(vault_id)
            or type(prefix) is not str
            or prefix != COUNCIL_VAULT_PREFIX
            or not isinstance(vault_root, Path)
            or not vault_root.is_absolute()
        ):
            raise ScribeError("VAULT_SCOPE_INVALID")
        self._vault_port = vault_port
        self._vault_root = vault_root
        self._vault_id = vault_id
        self._policy = authorization_policy
        self._clock = clock
        self._state_chain_verifier = state_chain_verifier

    def _authorize(
        self,
        principal: TrustedPrincipalV1,
        *,
        role: str,
        action: str,
        session_id: str,
        at_ns: int,
    ) -> None:
        if (
            type(principal) is not TrustedPrincipalV1
            or role not in principal.roles
            or principal.project_id != self._policy.project_id
        ):
            raise ScribeError("AUTHORIZATION_DENIED")
        try:
            resource_id = f"council:sha256:{hashlib.sha256(session_id.encode('utf-8')).hexdigest()}"
            decision = authorize(
                principal,
                ActionV1(action),
                ResourceV1(resource_id, principal.project_id, principal.env),
                AuthorizationContextV1(
                    project_id=principal.project_id,
                    env=principal.env,
                    at=_utc_from_ns(at_ns),
                    venue=principal.venue,
                    portfolio=principal.portfolio,
                    strategy=principal.strategy,
                ),
                self._policy,
            )
        except Exception:
            raise ScribeError("AUTHORIZATION_DENIED") from None
        if type(decision) is not AuthorizationDecisionV1 or decision.decision is not EffectV1.ALLOW:
            raise ScribeError("AUTHORIZATION_DENIED")

    def _verify_inputs(
        self,
        *,
        state: CouncilStateV1,
        outcomes: tuple[ReplayOutcomeV1, ...],
        leak_decision: LeakDecisionV1,
        critique_decision: CritiqueDecisionV1,
        plots: tuple[PublicationPlotV1, ...],
        reviewer: TrustedPrincipalV1 | None,
        publisher: TrustedPrincipalV1,
        now_ns: int,
    ) -> tuple[
        CouncilStateV1,
        tuple[ReplayOutcomeV1, ...],
        LeakDecisionV1,
        CritiqueDecisionV1,
        str,
    ]:
        if (
            type(state) is not CouncilStateV1
            or type(outcomes) is not tuple
            or not 1 <= len(outcomes) <= MAX_OUTCOMES
            or type(plots) is not tuple
            or not 1 <= len(plots) <= MAX_PUBLICATION_FILES - 5
            or any(type(plot) is not PublicationPlotV1 for plot in plots)
        ):
            raise ScribeError("PUBLICATION_INPUT_INVALID")
        # Reject path-bearing identifiers before serializing or restoring an
        # untrusted state object. This is only a deny check; the state is still
        # fully chain-verified below before any identifier is used.
        raw_session_id = object.__getattribute__(state, "session_id")
        if (
            type(raw_session_id) is not str
            or not _windows_component(raw_session_id)
        ):
            raise ScribeError("PUBLICATION_INPUT_INVALID")
        try:
            restored = restore_verified_state(
                state.model_dump_json(), verify_chain=self._state_chain_verifier
            )
        except Exception:
            raise ScribeError("STATE_UNTRUSTED") from None
        if (
            type(restored) is not CouncilStateV1
            or restored.status != "approved"
            or not _windows_component(restored.session_id)
            or not _windows_component(restored.hypothesis.hypothesis_id)
            or restored.final_decision_event_id is None
        ):
            raise ScribeError("STATE_UNTRUSTED")
        if any(
            not _windows_component(signal.version)
            for signal in restored.hypothesis.signal_refs
        ):
            raise ScribeError("PUBLICATION_INPUT_INVALID")
        try:
            leak = require_leak_decision(leak_decision)
        except Exception:
            raise ScribeError("LEAK_RESULT_UNTRUSTED") from None
        try:
            critique = require_critique_decision(critique_decision)
        except Exception:
            raise ScribeError("CRITIQUE_RESULT_UNTRUSTED") from None
        verified_outcomes: list[ReplayOutcomeV1] = []
        try:
            for outcome in outcomes:
                verified_outcomes.append(require_replay_outcome(outcome))
        except Exception:
            raise ScribeError("PUBLICATION_INPUT_INVALID") from None
        hypothesis_revision_hash = _hypothesis_revision_hash(restored.hypothesis)
        if (
            type(publisher) is not TrustedPrincipalV1
            or (reviewer is not None and type(reviewer) is not TrustedPrincipalV1)
            or (
                critique.status == "METRIC_FAILURE"
                and (
                    reviewer is None
                    or reviewer.project_id != publisher.project_id
                )
            )
            or critique.experiment_id not in restored.completed_experiment_ids
            or critique.revision_hash != hypothesis_revision_hash
            or leak.revision_hash != hypothesis_revision_hash
            or leak.revision_hash != critique.revision_hash
            or leak.snapshot_hash != critique.snapshot_hash
            or leak.experiment_id != critique.experiment_id
            or not leak.passed
            or leak.failed_rule_ids
            or critique.leak_failures
            or critique.status not in {"PASS", "METRIC_FAILURE"}
            or (critique.status == "PASS" and critique.passed is not True)
            or (critique.status == "METRIC_FAILURE" and critique.passed is not False)
            or any(item.experiment_id != critique.experiment_id for item in verified_outcomes)
            or any(item.snapshot_hash != critique.snapshot_hash for item in verified_outcomes)
            or any(
                metric.revision_hash != hypothesis_revision_hash
                for item in verified_outcomes
                for metric in item.metrics
            )
            or len({item.run_id for item in verified_outcomes}) != len(verified_outcomes)
            or len({item.result_digest for item in verified_outcomes}) != len(verified_outcomes)
            or sum(item.outcome == "COMPLETED" for item in verified_outcomes)
            != critique.completed_runs
        ):
            raise ScribeError("PUBLICATION_GATE_DENIED")
        leak_digest = _hash(_canonical_bytes(leak.model_dump(mode="json")))
        if critique.leak_digest != leak_digest:
            raise ScribeError("PUBLICATION_GATE_DENIED")
        if critique.status == "METRIC_FAILURE":
            exception = critique.publication_exception
            if exception is None:
                raise ScribeError("PUBLICATION_GATE_DENIED")
            try:
                verified_exception = require_publication_exception(exception)
            except Exception:
                raise ScribeError("PUBLICATION_EXCEPTION_UNTRUSTED") from None
            if (
                verified_exception.experiment_id != critique.experiment_id
                or verified_exception.revision_hash != critique.revision_hash
                or verified_exception.author_id != restored.hypothesis_author_id
                or reviewer is None
                or verified_exception.reviewer_id != reviewer.principal_id
                or reviewer.principal_id == restored.hypothesis_author_id
            ):
                raise ScribeError("PUBLICATION_GATE_DENIED")
        return restored, tuple(verified_outcomes), leak, critique, hypothesis_revision_hash

    def _render(
        self,
        state: CouncilStateV1,
        outcomes: tuple[ReplayOutcomeV1, ...],
        leak: LeakDecisionV1,
        critique: CritiqueDecisionV1,
        plots: tuple[PublicationPlotV1, ...],
    ) -> dict[str, bytes]:
        if (
            any(len(plot.content) > MAX_PUBLICATION_FILE_BYTES for plot in plots)
            or sum(len(plot.content) for plot in plots) > MAX_PUBLICATION_TOTAL_BYTES
        ):
            raise ScribeError("PUBLICATION_TOO_LARGE", http_status=413)
        for plot in plots:
            _validate_png(plot.content)
        files: dict[str, bytes] = {
            "TLDR.md": _render_tldr(state, outcomes, critique),
            "hypothesis.md": _render_hypothesis(state),
            "critique.md": _render_critique(critique, leak),
            "metrics.json": _render_metrics(outcomes),
        }
        for index, plot in enumerate(plots, start=1):
            relative_path = f"artifacts/plot-{index:04d}.png"
            files[relative_path] = plot.content
        if len(files) >= MAX_PUBLICATION_FILES:
            raise ScribeError("PUBLICATION_INPUT_INVALID")
        checksums = {
            "schema_version": "1.0.0",
            "files": [
                {"path": name, "sha256": _hash(content), "size_bytes": len(content)}
                for name, content in sorted(files.items())
            ],
        }
        files["checksums.json"] = _json(checksums)
        if any(len(content) > MAX_PUBLICATION_FILE_BYTES for content in files.values()):
            raise ScribeError("PUBLICATION_TOO_LARGE", http_status=413)
        if sum(map(len, files.values())) > MAX_PUBLICATION_TOTAL_BYTES:
            raise ScribeError("PUBLICATION_TOO_LARGE", http_status=413)
        return files

    def _read(self, path: str) -> bytes | None:
        try:
            _guard_scoped_vault_path(self._vault_root, path)
            value = self._vault_port.read(path)
        except Exception:
            raise ScribeError("VAULT_UNAVAILABLE") from None
        if value is not None and type(value) is not bytes:
            raise ScribeError("VAULT_POSTCONDITION_FAILED")
        return value

    def _select_folder(
        self, base_folder: str, files: dict[str, bytes]
    ) -> tuple[str, tuple[tuple[str, str, str], ...]]:
        conflicts: dict[str, str] = {}
        for suffix in range(MAX_CONFLICT_SUFFIX + 1):
            folder = base_folder if suffix == 0 else f"{base_folder}-{suffix}"
            mismatch = False
            for relative_path, content in sorted(files.items()):
                existing = self._read(f"{folder}/{relative_path}")
                if existing is not None and existing != content:
                    mismatch = True
                    conflicts.setdefault(relative_path, _hash(existing))
            if not mismatch:
                rows = tuple(
                    (f"{base_folder}/{rel}", digest, rel)
                    for rel, digest in sorted(conflicts.items())
                )
                return folder, rows
        raise ScribeError("PUBLICATION_CONFLICT_LIMIT")

    def _write_file(
        self, path: str, content: bytes
    ) -> tuple[Literal["ok", "offline", "invalid"], int]:
        for attempt in range(1, MAX_PORT_ATTEMPTS + 1):
            _guard_scoped_vault_path(self._vault_root, path)
            try:
                result = self._vault_port.create_no_overwrite(path, content)
            except Exception:
                result = "OFFLINE"
            if result == "OFFLINE":
                if attempt <= MAX_PUBLICATION_RETRIES:
                    try:
                        self._vault_port.wait_before_retry(_RETRY_DELAYS_NS[attempt - 1])
                    except Exception:
                        return "offline", attempt
                    continue
                return "offline", attempt
            if result not in {"CREATED", "EXISTS"}:
                return "invalid", attempt
            try:
                persisted = self._read(path)
            except ScribeError:
                return "offline", attempt
            if persisted != content:
                return "invalid", attempt
            return "ok", attempt
        return "offline", MAX_PORT_ATTEMPTS

    def publish(
        self,
        *,
        state: CouncilStateV1,
        outcomes: tuple[ReplayOutcomeV1, ...],
        leak_decision: LeakDecisionV1,
        critique_decision: CritiqueDecisionV1,
        plots: tuple[PublicationPlotV1, ...],
        reviewer: TrustedPrincipalV1 | None = None,
        publisher: TrustedPrincipalV1,
    ) -> PublicationResultV1:
        """Return only sanitized typed errors across the publication boundary."""
        failure: ScribeError | None = None
        try:
            return self._publish_impl(
                state=state,
                outcomes=outcomes,
                leak_decision=leak_decision,
                critique_decision=critique_decision,
                plots=plots,
                reviewer=reviewer,
                publisher=publisher,
            )
        except ScribeError as error:
            error.__context__ = None
            error.__cause__ = None
            error.__suppress_context__ = True
            failure = error
        except Exception:
            failure = ScribeError("PUBLICATION_INPUT_INVALID")
        if failure is not None:
            raise failure
        raise ScribeError("PUBLICATION_INPUT_INVALID")

    def _publish_impl(
        self,
        *,
        state: CouncilStateV1,
        outcomes: tuple[ReplayOutcomeV1, ...],
        leak_decision: LeakDecisionV1,
        critique_decision: CritiqueDecisionV1,
        plots: tuple[PublicationPlotV1, ...],
        reviewer: TrustedPrincipalV1 | None = None,
        publisher: TrustedPrincipalV1,
    ) -> PublicationResultV1:
        """Validate, authorize, atomically no-overwrite each file, and verify it."""
        try:
            now_ns = self._clock.now_ns()
        except Exception:
            raise ScribeError("PUBLICATION_INPUT_INVALID") from None
        if type(now_ns) is not int or not 0 < now_ns <= 2**63 - 1:
            raise ScribeError("PUBLICATION_INPUT_INVALID")
        (
            verified_state,
            verified_outcomes,
            leak,
            critique,
            hypothesis_revision_hash,
        ) = self._verify_inputs(
            state=state,
            outcomes=outcomes,
            leak_decision=leak_decision,
            critique_decision=critique_decision,
            plots=plots,
            reviewer=reviewer,
            publisher=publisher,
            now_ns=now_ns,
        )
        if critique.status == "METRIC_FAILURE":
            if reviewer is None:
                raise ScribeError("AUTHORIZATION_DENIED")
            self._authorize(
                reviewer,
                role="reviewer",
                action="council.publication.review",
                session_id=verified_state.session_id,
                at_ns=now_ns,
            )
        self._authorize(
            publisher,
            role="scribe",
            action="council.publication.publish",
            session_id=verified_state.session_id,
            at_ns=now_ns,
        )
        files = self._render(verified_state, verified_outcomes, leak, critique, plots)
        artifact_digest = _artifact_digest(files)
        base_folder = f"{COUNCIL_VAULT_PREFIX}{verified_state.session_id}"
        folder, conflict_rows = self._select_folder(base_folder, files)
        issued_conflicts = tuple(
            _issue_conflict(
                PublicationConflictV1(
                    requested_path=requested,
                    published_path=f"{folder}/{relative}",
                    existing_sha256=existing,
                    requested_sha256=_hash(files[relative]),
                )
            )
            for requested, existing, relative in conflict_rows
        )
        attempts_used = 0
        actual_files: list[PublishedFileV1] = []
        for relative_path, content in sorted(files.items()):
            if relative_path == "checksums.json":
                continue
            full_path = f"{folder}/{relative_path}"
            outcome, attempts = self._write_file(full_path, content)
            attempts_used = max(attempts_used, attempts)
            if outcome == "offline":
                return _result("error", error_code="VAULT_UNAVAILABLE", attempts=attempts_used)
            if outcome != "ok":
                return _result(
                    "error", error_code="VAULT_POSTCONDITION_FAILED", attempts=attempts_used
                )
            actual_files.append(
                _issue_published_file(
                    PublishedFileV1(
                        path=relative_path,
                        sha256=_hash(content),
                        size_bytes=len(content),
                    )
                )
            )
        relative_path = "checksums.json"
        content = files[relative_path]
        full_path = f"{folder}/{relative_path}"
        outcome, attempts = self._write_file(full_path, content)
        attempts_used = max(attempts_used, attempts)
        if outcome == "offline":
            return _result("error", error_code="VAULT_UNAVAILABLE", attempts=attempts_used)
        if outcome != "ok":
            return _result(
                "error", error_code="VAULT_POSTCONDITION_FAILED", attempts=attempts_used
            )
        actual_files.append(
            _issue_published_file(
                PublishedFileV1(
                    path=relative_path,
                    sha256=_hash(content),
                    size_bytes=len(content),
                )
            )
        )
        # A publication exists only after every file has been read back byte-for-byte.
        file_records = tuple(actual_files)
        critique_digest = _hash(_canonical_bytes(critique.model_dump(mode="json")))
        leak_digest = _hash(_canonical_bytes(leak.model_dump(mode="json")))
        display_label, display_label_source = _display_label(verified_state.hypothesis)
        manifest = PublicationManifestV1(
            session_id=verified_state.session_id,
            hypothesis_id=verified_state.hypothesis.hypothesis_id,
            experiment_id=critique.experiment_id,
            state_semantic_hash=verified_state.revision_content_hash,
            hypothesis_revision_hash=hypothesis_revision_hash,
            snapshot_hash=critique.snapshot_hash,
            critique_digest=critique_digest,
            leak_digest=leak_digest,
            artifact_digest=artifact_digest,
            vault_id=self._vault_id,
            path=folder,
            display_label=display_label,
            display_label_source=display_label_source,
            files=file_records,
            conflicts=issued_conflicts,
            reviewer_id=(
                reviewer.principal_id if critique.status == "METRIC_FAILURE" and reviewer else None
            ),
            review_basis=(
                "METRIC_EXCEPTION" if critique.status == "METRIC_FAILURE" else "CRITIC_PASS"
            ),
            publisher_id=publisher.principal_id,
            published_at_ns=now_ns,
        )
        manifest = _issue_manifest(manifest)
        manifest_digest = _hash(_canonical_bytes(manifest.model_dump(mode="json")))
        intent = _issue_summary_intent(
            SummaryIntentV1(
                session_id=verified_state.session_id,
                idempotency_key=f"council-publication:{verified_state.session_id}",
                publication_digest=manifest_digest,
                vault_id=self._vault_id,
                path=folder,
            )
        )
        return _result("synced", manifest=manifest, intent=intent, attempts=attempts_used)


__all__ = [
    "COUNCIL_VAULT_PREFIX",
    "PublicationClock",
    "ScopedNoOverwriteVaultPort",
    "ScribePublicationService",
    "StateChainVerifier",
]
