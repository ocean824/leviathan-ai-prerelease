from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal

import pytest

from leviathan_core.execution.broker_port import FakeBrokerPort
from leviathan_core.execution.broker_port_v1 import (
    BrokerPortError,
    EquityEvidenceKindV1,
    EquityEvidenceV1,
    _digest,
    _issue_account_view,
    _issue_equity_evidence,
)
from leviathan_core.execution.broker_reconciliation import FakeBrokerReconciliation

_SINCE = datetime(2026, 10, 1, tzinfo=UTC)
_V13_DIGEST = "52f3bf57435bf35e72bbcb96613d776d6d8d831250dbd0a6dd2133bd591b754e"


def test_equity_evidence_is_exact_validated_and_seal_issued() -> None:
    evidence = _issue_equity_evidence(
        "USD", Decimal("1234.5600"), EquityEvidenceKindV1.NET_LIQUIDATION, 123, "alpaca-v1"
    )

    assert evidence.currency == "USD"
    assert evidence.amount == Decimal("1234.56")
    assert evidence.kind is EquityEvidenceKindV1.NET_LIQUIDATION
    assert evidence.broker_observed_at_ns == 123
    assert evidence.semantics_declared_by == "alpaca-v1"
    evidence.assert_sealed()

    with pytest.raises(BrokerPortError) as unissued:
        EquityEvidenceV1("USD", Decimal("1"), EquityEvidenceKindV1.TOTAL_EQUITY, 0, "adapter")
    assert unissued.value.code == "UNISSUED_BROKER_RECORD"

    for currency, amount, kind, observed_at, adapter in (
        ("usd", Decimal("1"), EquityEvidenceKindV1.TOTAL_EQUITY, 0, "adapter"),
        ("US1", Decimal("1"), EquityEvidenceKindV1.TOTAL_EQUITY, 0, "adapter"),
        ("USD", 1, EquityEvidenceKindV1.TOTAL_EQUITY, 0, "adapter"),
        ("USD", Decimal("NaN"), EquityEvidenceKindV1.TOTAL_EQUITY, 0, "adapter"),
        ("USD", Decimal("1E+100000"), EquityEvidenceKindV1.TOTAL_EQUITY, 0, "adapter"),
        ("USD", Decimal("1"), "TOTAL_EQUITY", 0, "adapter"),
        ("USD", Decimal("1"), EquityEvidenceKindV1.TOTAL_EQUITY, True, "adapter"),
        ("USD", Decimal("1"), EquityEvidenceKindV1.TOTAL_EQUITY, -1, "adapter"),
        ("USD", Decimal("1"), EquityEvidenceKindV1.TOTAL_EQUITY, 0, "bad adapter id"),
    ):
        with pytest.raises(BrokerPortError) as invalid:
            _issue_equity_evidence(currency, amount, kind, observed_at, adapter)  # type: ignore[arg-type]
        assert invalid.value.code == "INVALID_EQUITY_EVIDENCE"


def test_absent_equity_preserves_v13_payload_and_digest() -> None:
    view = _issue_account_view("synthetic-account", (), (), 1, (), _SINCE, complete=True)

    assert view.equity is None
    assert "equity" not in view.seal_payload()
    assert _digest(view).hex() == _V13_DIGEST
    view.assert_sealed()


def test_equity_is_bound_to_account_view_seal() -> None:
    equity = _issue_equity_evidence(
        "USD", Decimal("100000"), EquityEvidenceKindV1.TOTAL_EQUITY, 0, "fake-broker-v1"
    )
    view = _issue_account_view(
        "synthetic-account", (), (), 1, (), _SINCE, complete=True, equity=equity
    )

    assert view.equity is equity
    assert view.seal_payload()["equity"] == [
        "USD",
        Decimal("100000"),
        "TOTAL_EQUITY",
        0,
        "fake-broker-v1",
    ]
    view.assert_sealed()

    object.__setattr__(equity, "amount", Decimal("1"))
    with pytest.raises(BrokerPortError) as tampered:
        view.assert_sealed()
    assert tampered.value.code == "BROKER_RECORD_TAMPERED"

    with pytest.raises(BrokerPortError) as unissued:
        _issue_account_view(
            "synthetic-account",
            (),
            (),
            1,
            (),
            _SINCE,
            complete=True,
            equity=object(),  # type: ignore[arg-type]
        )
    assert unissued.value.code == "INVALID_ACCOUNT_VIEW"


def test_fake_broker_emits_deterministic_equity_evidence() -> None:
    broker = FakeBrokerPort(FakeBrokerReconciliation(), account_id="fake-account")

    first = broker.read_account_view("fake-account")
    second = broker.read_account_view("fake-account")

    assert first.equity is not None
    assert first.equity.currency == "USD"
    assert first.equity.amount == Decimal("100000")
    assert first.equity.kind is EquityEvidenceKindV1.TOTAL_EQUITY
    assert first.equity.broker_observed_at_ns == 0
    assert first.equity.semantics_declared_by == "fake-broker-v1"
    assert _digest(first) == _digest(second)
    assert first.seal_payload() == second.seal_payload()
    first.assert_sealed()
    second.assert_sealed()
