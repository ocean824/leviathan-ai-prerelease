from __future__ import annotations

import copy
import hashlib
import pickle
from collections.abc import Callable
from dataclasses import fields, replace
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any, cast

import pytest

from leviathan_core.execution import broker_port_v1 as broker
from leviathan_core.execution.order_models import OrderState
from leviathan_core.numeric import canonical_json

_SINCE = datetime(2026, 10, 1, tzinfo=UTC)
_V13_CANONICAL_PAYLOAD_SHA256 = bytes.fromhex(
    "f05de6f4fec8fd4604b4955d70c2530c31c63485aefc1f3bee320400a20da73a"
)
_V14_CANONICAL_PAYLOAD_SHA256 = bytes.fromhex(
    "f279eb0798c1d84805542d2d1bc33620f9d9f03ebdd2403f368bc6d50b326045"
)
_V13_LEGACY_RECORD_DIGEST = bytes.fromhex(
    "52f3bf57435bf35e72bbcb96613d776d6d8d831250dbd0a6dd2133bd591b754e"
)
_V14_LEGACY_RECORD_DIGEST = bytes.fromhex(
    "6027716d11f2cd6d2c0bc0710ce531138726bc65534bd3e0757b7001c5553d8a"
)

# Canonical-first byte fingerprints for unaffected consumers of broker records.
_CONSUMER_SHA256 = {
    "packages/leviathan-core/src/leviathan_core/execution/broker_reconciliation.py": (
        "e462dd2b7527a1d68ea3a4e2dd97689f554586a3d2d269d71b46f11299d48908"
    ),
    "packages/leviathan-core/src/leviathan_core/execution/reconciliation.py": (
        "b5bd64bd0b564a2a772b55092d61ad82a97e7d1a549d375fb28596768098b702"
    ),
    "packages/leviathan-core/src/leviathan_core/risk_limits/live_guard.py": (
        "408a867cb34a364b20aaec81b13d291c0654e6081bdcdad1194284f0d0176a8a"
    ),
    "apps/api/tests/test_paper_e2e.py": (
        "578ba47a4f60491189380041d5d868c24a89d9e9970beed514ce2be7c38b5a1d"
    ),
}


def _records() -> tuple[tuple[object, Callable[[Any], Any]], ...]:
    execution = broker._issue_execution(
        "exec-1",
        "venue-order-1",
        "client-1",
        "AAPL",
        "BUY",
        Decimal("1.25"),
        Decimal("100.50"),
        _SINCE,
    )
    balance = broker._issue_balance("USD", Decimal("1000.00"))
    equity = broker._issue_equity_evidence(
        "USD",
        Decimal("1234.5600"),
        broker.EquityEvidenceKindV1.NET_LIQUIDATION,
        123456789,
        "synthetic-provider-v1",
    )
    account_view = broker._issue_account_view(
        "synthetic-account",
        (),
        (("AAPL", Decimal("1.25")),),
        7,
        (execution,),
        _SINCE,
        complete=True,
        balances=(balance,),
        equity=equity,
    )
    return (
        (
            broker._issue_venue_capability(True),
            broker.require_venue_dispatch_capability,
        ),
        (
            broker._issue_venue_identity(
                broker.BrokerVenue.ALPACA, broker.BrokerEnvironment.PAPER, "synthetic-account"
            ),
            broker.require_venue_identity,
        ),
        (
            broker._issue_submit_result("venue-order-1", OrderState.WORKING),
            broker.require_submit_result,
        ),
        (broker._issue_cancel_result(True), broker.require_cancel_result),
        (execution, broker.require_execution),
        (balance, broker.require_balance),
        (equity, broker.require_equity_evidence),
        (account_view, broker.require_account_view),
    )


def _field_values(value: Any) -> dict[str, object]:
    return {item.name: getattr(value, item.name) for item in fields(value)}


def _content_hash(value: object) -> bytes:
    return hashlib.sha256(canonical_json(value)).digest()


def _assert_rejected(call: Callable[[], object]) -> None:
    with pytest.raises(broker.BrokerPortError) as raised:
        call()
    assert raised.value.args == (raised.value.code,)


def _model_construct(record_type: type[object], kwargs: dict[str, object]) -> object:
    constructor = record_type.__dict__.get("model_construct")
    if constructor is None:
        raise AttributeError("model_construct is unavailable")
    return constructor(**kwargs)


@pytest.mark.parametrize("index", range(8))
def test_each_broker_record_is_issued_and_typed_require_returns_same_object(index: int) -> None:
    record, require_record = _records()[index]

    assert require_record(record) is record
    record.assert_sealed()


def test_account_view_v13_and_v14_payload_digests_match_canonical_goldens() -> None:
    v13 = broker._issue_account_view("synthetic-account", (), (), 1, (), _SINCE, complete=True)
    equity = broker._issue_equity_evidence(
        "USD",
        Decimal("1234.5600"),
        broker.EquityEvidenceKindV1.NET_LIQUIDATION,
        123456789,
        "synthetic-provider-v1",
    )
    v14 = broker._issue_account_view(
        "synthetic-account", (), (), 1, (), _SINCE, complete=True, equity=equity
    )

    assert v13.equity is None
    v13_payload = cast(dict[str, object], v13.seal_payload())
    v14_payload = cast(dict[str, object], v14.seal_payload())
    assert "equity" not in v13_payload
    assert _content_hash(v13_payload) == _V13_CANONICAL_PAYLOAD_SHA256
    assert broker._digest(v13) == _V13_LEGACY_RECORD_DIGEST
    assert v14.equity is equity
    assert _content_hash(v14_payload) == _V14_CANONICAL_PAYLOAD_SHA256
    assert broker._digest(v14) == _V14_LEGACY_RECORD_DIGEST
    assert broker.require_account_view(v13) is v13
    assert broker.require_account_view(v14) is v14


@pytest.mark.parametrize("index", range(8))
def test_object_new_clone_cannot_borrow_issuance(index: int) -> None:
    record, require_record = _records()[index]
    forged = object.__new__(type(record))
    for name, value in _field_values(record).items():
        object.__setattr__(forged, name, value)

    _assert_rejected(lambda: require_record(forged))


def _operation_fails_or_returns_unissued(
    attempt: Callable[[], object], require_record: Callable[[Any], Any]
) -> None:
    try:
        forged = attempt()
    except broker.BrokerPortError as error:
        assert error.args == (error.code,)
        return
    except (TypeError, AttributeError):
        return
    if type(forged) is bytes:
        try:
            forged = pickle.loads(forged)
        except (broker.BrokerPortError, TypeError, AttributeError, pickle.PickleError):
            return
    _assert_rejected(lambda: require_record(forged))


@pytest.mark.parametrize("index", range(8))
def test_copy_deepcopy_pickle_replace_and_model_construct_cannot_forge(index: int) -> None:
    record, require_record = _records()[index]
    kwargs = _field_values(record)

    for attempt in (
        lambda: copy.copy(record),
        lambda: copy.deepcopy(record),
        lambda: pickle.dumps(record),
        lambda: replace(cast(Any, record)),
        lambda: _model_construct(type(record), kwargs),
    ):
        _operation_fails_or_returns_unissued(attempt, require_record)


@pytest.mark.parametrize("index", range(8))
def test_reinitialization_is_denied_before_any_record_field_changes(index: int) -> None:
    record, require_record = _records()[index]
    before = _field_values(record)

    _assert_rejected(lambda: type(record).__init__(record, **before))

    assert _field_values(record) == before
    assert require_record(record) is record


@pytest.mark.parametrize(
    ("index", "field_name", "replacement"),
    [
        (0, "atomic_revision_dispatch", False),
        (1, "account_id", "changed-account"),
        (2, "venue_order_id", "changed-order"),
        (3, "confirmed", False),
        (4, "quantity", Decimal("2.25")),
        (5, "amount", Decimal("2000")),
        (6, "amount", Decimal("2")),
        (7, "broker_revision", 8),
    ],
)
def test_tampering_with_each_issued_record_is_detected(
    index: int, field_name: str, replacement: object
) -> None:
    record, require_record = _records()[index]
    object.__setattr__(record, field_name, replacement)

    _assert_rejected(lambda: require_record(record))


def test_nested_execution_tampering_invalidates_containing_account_view() -> None:
    records = _records()
    view, require_view = records[7]
    execution, require_execution = records[4]
    object.__setattr__(execution, "quantity", Decimal("9"))

    _assert_rejected(lambda: require_execution(execution))
    _assert_rejected(lambda: require_view(view))


def test_reconciliation_live_guard_and_paper_e2e_consumers_are_unchanged() -> None:
    repo_root = Path(__file__).resolve().parents[4]
    for relative_path, expected_sha256 in _CONSUMER_SHA256.items():
        actual = hashlib.sha256((repo_root / relative_path).read_bytes()).hexdigest()
        assert actual == expected_sha256, relative_path
