"""Private authenticated reload helpers for persisted C-101 terminal records.

These helpers intentionally expose no public model-to-issuer operation. The store
must first validate the route row and every linked database record, then present
the exact canonical payload and its keyed proof to the private reload function.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from leviathan_core.execution.order_models import LedgerIntegrityKey
from leviathan_core.schemas.journal import TradeJournalRecord, _issue_trade_journal_record
from leviathan_core.schemas.risk import RiskVerdict, _issue_risk_verdict

_PROOF_SCHEMA = "c101.terminal-records"
_PROOF_VERSION = 1
_PROOF_ALGORITHM = "hmac-sha256"


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _build_terminal_proof(key: LedgerIntegrityKey, document: dict[str, Any]) -> dict[str, Any]:
    if type(key) is not LedgerIntegrityKey:
        raise ValueError("invalid integrity key")
    payload = _canonical_json_bytes(document)
    return {
        "schema": _PROOF_SCHEMA,
        "version": _PROOF_VERSION,
        "algorithm": _PROOF_ALGORITHM,
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "mac": key.sign(payload),
    }


def _issue_verified_terminal_records(
    *,
    key: LedgerIntegrityKey,
    document: dict[str, Any],
    proof: object,
) -> tuple[RiskVerdict, TradeJournalRecord]:
    """Revalidate one authenticated persisted pair, then privately issue it."""
    if type(key) is not LedgerIntegrityKey or type(proof) is not dict:
        raise ValueError("invalid persisted proof")
    expected_fields = {"schema", "version", "algorithm", "payload_sha256", "mac"}
    if (
        set(proof) != expected_fields
        or proof.get("schema") != _PROOF_SCHEMA
        or type(proof.get("version")) is not int
        or proof.get("version") != _PROOF_VERSION
        or proof.get("algorithm") != _PROOF_ALGORITHM
    ):
        raise ValueError("invalid persisted proof")
    payload = _canonical_json_bytes(document)
    digest = hashlib.sha256(payload).hexdigest()
    signature = proof.get("mac")
    if (
        proof.get("payload_sha256") != digest
        or not isinstance(signature, str)
        or not key.verify(payload, signature)
    ):
        raise ValueError("invalid persisted proof")
    verdict_payload = document.get("final_verdict")
    journal_payload = document.get("journal_record")
    if type(verdict_payload) is not dict or type(journal_payload) is not dict:
        raise ValueError("invalid persisted records")
    verdict = RiskVerdict.model_validate(verdict_payload)
    journal = TradeJournalRecord.model_validate(journal_payload)
    if (
        verdict.model_dump(mode="json") != verdict_payload
        or journal.model_dump(mode="json") != journal_payload
        or verdict.decision_id != document.get("decision_id")
        or journal.decision_id != document.get("decision_id")
        or journal.setup_id != document.get("setup_id")
    ):
        raise ValueError("persisted records differ from proof")
    return _issue_risk_verdict(verdict), _issue_trade_journal_record(journal)
