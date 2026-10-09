"""Independent contract acceptance for the offline entitled-chain adapter."""

from __future__ import annotations

import copy
import json
import pickle
from datetime import date
from decimal import Decimal
from pathlib import Path

import pytest
from pydantic import ValidationError

from leviathan_core.dealer_gamma.chain_adapter import (
    ChainAdaptationV1,
    ChainAdapterError,
    ChainDeliverableV1,
    ChainEnvelopeV1,
    ChainHorizonV1,
    ChainRowV1,
    ChainSessionV1,
    OptionChainSourcePortV1,
    require_adaptation,
    translate_chain,
    verify_adaptation,
)
from leviathan_core.seal import SealError

FIXTURES = Path(__file__).parent / "fixtures" / "chain"
BASE_ASOF_NS = 1_000_000_000_000


def _raw() -> dict[str, object]:
    return json.loads((FIXTURES / "base_spx_live.json").read_text(encoding="utf-8"))


def _models(raw: dict[str, object] | None = None) -> tuple[
    OptionChainSourcePortV1, ChainEnvelopeV1, int
]:
    data = _raw() if raw is None else raw
    port_data = copy.deepcopy(data["port"])
    envelope_data = copy.deepcopy(data["envelope"])
    assert isinstance(port_data, dict) and isinstance(envelope_data, dict)
    for name in ("entitled_underliers", "supported_expiry_kinds", "supported_settlements"):
        port_data[name] = tuple(port_data[name])
    port = OptionChainSourcePortV1(**port_data)
    live_data = envelope_data["live"]
    settled_data = envelope_data["settled"]
    live = None if live_data is None else _horizon(live_data)
    settled = None if settled_data is None else _horizon(settled_data)
    envelope = ChainEnvelopeV1(
        envelope_id=envelope_data["envelope_id"],
        manifest_id=envelope_data["manifest_id"],
        underlier=envelope_data["underlier"],
        live=live,
        settled=settled,
    )
    return port, envelope, int(data["asof_ns"])


def _horizon(data: dict[str, object]) -> ChainHorizonV1:
    session_data = data["session"]
    assert isinstance(session_data, dict)
    session = ChainSessionV1(
        **{
            **session_data,
            "trade_date": date.fromisoformat(session_data["trade_date"]),
        }
    )
    rows_data = data["rows"]
    rows = rows_data
    if isinstance(rows_data, list):
        built_rows = []
        decimal_fields = (
            "strike", "multiplier", "open_interest", "spot", "bid", "ask",
            "implied_vol", "gamma", "split_factor",
        )
        for source in rows_data:
            assert isinstance(source, dict)
            row = copy.deepcopy(source)
            row["expiry_date"] = date.fromisoformat(row["expiry_date"])
            row["oi_asof_date"] = date.fromisoformat(row["oi_asof_date"])
            for name in decimal_fields:
                if row[name] is not None:
                    row[name] = Decimal(row[name])
            row["deliverable_units"] = tuple(
                ChainDeliverableV1(
                    **{**leg, "units": Decimal(leg["units"])}
                )
                for leg in row["deliverable_units"]
            )
            built_rows.append(ChainRowV1(**row))
        rows = tuple(built_rows)
    elif type(rows_data) is tuple:
        rows = rows_data
    expiries = data["eligible_expiries"]
    return ChainHorizonV1(
        **{
            **data,
            "session": session,
            "eligible_expiries": tuple(date.fromisoformat(item) for item in expiries),
            "eligible_oi_denominator": (
                None if data["eligible_oi_denominator"] is None
                else Decimal(data["eligible_oi_denominator"])
            ),
            "rows": rows,
        }
    )


def _translate(raw: dict[str, object] | None = None, *, asof_ns: int | None = None):
    port, envelope, fixture_asof = _models(raw)
    return translate_chain(port, envelope, asof_ns=fixture_asof if asof_ns is None else asof_ns)


def _mutable_live(
    raw: dict[str, object],
) -> tuple[dict[str, object], dict[str, object], list[dict[str, object]]]:
    envelope = raw["envelope"]
    assert isinstance(envelope, dict)
    live = envelope["live"]
    assert isinstance(live, dict)
    rows = live["rows"]
    assert isinstance(rows, list)
    return envelope, live, rows


def test_valid_synthetic_spx_fixture_maps_entitled_prior_close_series_with_exact_coverage() -> None:
    port, envelope, asof_ns = _models()
    result = translate_chain(port, envelope, asof_ns=asof_ns)

    assert result.status == "OK"
    assert result.live is not None and result.live.status == "OK"
    assert result.live.coverage_exact == (4, 5)
    assert result.live.coverage_ratio == Decimal("0.8")
    assert result.live.coverage_numerator == Decimal("80")
    assert result.live.coverage_denominator == Decimal("100")
    assert result.live.oi_family == "OFFICIAL_PRIOR_CLOSE"
    assert result.live.oi_asof_dates == (date(2026, 10, 5),)
    assert result.live.mapped_series_ids == ("OPRA:SPX-20261009-C-06000000",)
    assert result.snapshot is not None and result.snapshot.live is not None
    assert result.snapshot.live.series[0].multiplier == Decimal("100")
    assert result.dealer_sign_inferred is False
    assert result.pin_probability is None
    assert verify_adaptation(result)
    assert require_adaptation(result) is result
    assert translate_chain(port, envelope, asof_ns=asof_ns) == result


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    (
        ("chain_entitlement_status", "DENIED", "MISSING_CHAIN_ENTITLEMENT"),
        ("chain_entitlement_status", "UNKNOWN", "MISSING_CHAIN_ENTITLEMENT"),
        ("chain_entitlement_id", None, "MISSING_CHAIN_ENTITLEMENT"),
        ("entitled_underliers", [], "UNENTITLED_UNDERLIER"),
        ("greek_convention_verified", False, "UNVERIFIED_GREEK_CONVENTION"),
        ("greek_convention", "UNVERIFIED_GAMMA", "UNVERIFIED_GREEK_CONVENTION"),
        ("oi_family", "INTRADAY", "OI_FAMILY_UNSUPPORTED"),
        ("spot_unit", "INDEX_POINTS", "UNVERIFIED_UNITS"),
    ),
)
def test_manifest_must_prove_entitlement_units_and_greek_convention(
    field: str, value: object, reason: str
) -> None:
    raw = _raw()
    port_data = raw["port"]
    assert isinstance(port_data, dict)
    port_data[field] = value
    result = _translate(raw)
    assert result.live is not None
    assert result.live.status == "UNAVAILABLE"
    assert reason in result.live.reasons
    assert result.snapshot is None


def test_api_key_presence_alone_cannot_substitute_for_manifest_entitlement() -> None:
    raw = _raw()
    port_data = raw["port"]
    assert isinstance(port_data, dict)
    port_data["api_key_present"] = True
    port_data["chain_entitlement_status"] = "DENIED"
    result = _translate(raw)
    assert result.live is not None and result.live.status == "UNAVAILABLE"
    assert "MISSING_CHAIN_ENTITLEMENT" in result.live.reasons


@pytest.mark.parametrize("mutation,reason", [
    (lambda env, port: env.__setitem__("manifest_id", "other-manifest"), "MANIFEST_MISMATCH"),
    (lambda env, port: port.__setitem__("coverage_start_ns", 999_700_000_000),
     "OUTSIDE_SOURCE_COVERAGE"),
])
def test_manifest_identity_and_source_window_are_bound_to_chain(
    mutation, reason: str
) -> None:
    raw = _raw()
    port_data = raw["port"]
    envelope_data = raw["envelope"]
    assert isinstance(port_data, dict) and isinstance(envelope_data, dict)
    mutation(envelope_data, port_data)
    result = _translate(raw)
    assert result.live is not None and result.live.status == "UNAVAILABLE"
    assert reason in result.live.reasons


def test_series_requires_its_own_greek_entitlement_and_supported_expiry_family() -> None:
    raw = _raw()
    _, _, rows = _mutable_live(raw)
    rows[0]["greek_entitlement_status"] = "DENIED"
    result = _translate(raw)
    assert result.live is not None and result.live.status == "UNAVAILABLE"
    assert "MISSING_GREEK_ENTITLEMENT" in result.live.reasons

    raw = _raw()
    _, _, rows = _mutable_live(raw)
    rows[0]["expiry_kind"] = "DAILY"
    result = _translate(raw)
    assert result.live is not None and result.live.status == "UNAVAILABLE"
    assert "UNSUPPORTED_EXPIRY" in result.live.reasons


def test_coverage_equality_passes_but_undercoverage_and_unknown_denominator_do_not() -> None:
    exact = _translate()
    assert exact.live is not None and exact.live.status == "OK"
    assert exact.live.coverage_exact == (4, 5)

    raw = _raw()
    _, live, rows = _mutable_live(raw)
    rows[0]["open_interest"] = "79"
    result = _translate(raw)
    assert result.live is not None and result.live.status == "DEGRADED"
    assert "LOW_OI_COVERAGE" in result.live.reasons
    assert result.live.coverage_exact == (79, 100)

    raw = _raw()
    _, live, _ = _mutable_live(raw)
    live["eligible_oi_denominator"] = None
    result = _translate(raw)
    assert result.live is not None and result.live.status == "UNAVAILABLE"
    assert "UNKNOWN_OI_DENOMINATOR" in result.live.reasons
    assert result.snapshot is None


def test_stale_boundaries_are_exact_for_spot_iv_quote_greek_and_prior_close_oi() -> None:
    spot_at_boundary = _translate(asof_ns=999_000_000_000 + 2_000_000_000)
    assert spot_at_boundary.live is not None
    assert "STALE_SPOT" not in spot_at_boundary.live.reasons
    spot_one_ns_stale = _translate(asof_ns=999_000_000_000 + 2_000_000_001)
    assert spot_one_ns_stale.live is not None
    assert "STALE_SPOT" in spot_one_ns_stale.live.reasons

    iv_at_boundary = _translate(asof_ns=999_000_000_000 + 10_000_000_000)
    assert iv_at_boundary.live is not None
    assert "STALE_IV" not in iv_at_boundary.live.reasons
    iv_one_ns_stale = _translate(asof_ns=999_000_000_000 + 10_000_000_001)
    assert iv_one_ns_stale.live is not None
    assert "STALE_IV" in iv_one_ns_stale.live.reasons
    assert "STALE_QUOTE" in iv_one_ns_stale.live.reasons
    assert "STALE_GREEK" in iv_one_ns_stale.live.reasons

    raw = _raw()
    _, live, _ = _mutable_live(raw)
    _, _, rows = _mutable_live(raw)
    raw["asof_ns"] = 899_000_000_000 + 172_800_000_000_000
    live["session"]["session_close_ns"] = 200_000_000_000_000
    rows[0]["expiry_cutoff_ns"] = 199_000_000_000_000
    oi_at_boundary = _translate(raw)
    assert oi_at_boundary.live is not None
    assert "STALE_OI" not in oi_at_boundary.live.reasons
    raw = _raw()
    _, live, rows = _mutable_live(raw)
    raw["asof_ns"] = 899_000_000_000 + 172_800_000_000_001
    live["session"]["session_close_ns"] = 200_000_000_000_000
    rows[0]["expiry_cutoff_ns"] = 199_000_000_000_000
    oi_stale = _translate(raw)
    assert oi_stale.live is not None and "STALE_OI" in oi_stale.live.reasons


def test_crossed_quote_expired_and_halted_series_are_never_mapped_as_eligible() -> None:
    raw = _raw()
    _, _, rows = _mutable_live(raw)
    rows[0]["bid"] = "11"
    rows[0]["ask"] = "10"
    crossed = _translate(raw)
    assert crossed.live is not None and crossed.live.status == "UNAVAILABLE"
    assert any(item.reason == "CROSSED_QUOTE" for item in crossed.live.excluded)

    raw = _raw()
    _, _, rows = _mutable_live(raw)
    rows[0]["expiry_cutoff_ns"] = BASE_ASOF_NS
    expired = _translate(raw)
    assert expired.live is not None and expired.live.status == "UNAVAILABLE"
    assert any(item.reason == "EXPIRED_SERIES" for item in expired.live.excluded)

    raw = _raw()
    _, _, rows = _mutable_live(raw)
    rows[0]["halted"] = True
    halted = _translate(raw)
    assert halted.live is not None and halted.live.status == "UNAVAILABLE"
    assert any(item.reason == "HALTED_SERIES" for item in halted.live.excluded)


@pytest.mark.parametrize(
    ("underlier", "basis"),
    (("SPX", "CASH_INDEX"), ("SPY", "ETF_SPOT"), ("QQQ", "ETF_SPOT"),
     ("AAPL", "EQUITY_SPOT")),
)
def test_sanitized_index_etf_and_equity_underliers_keep_explicit_unit_basis(
    underlier: str, basis: str
) -> None:
    raw = _raw()
    port_data = raw["port"]
    envelope_data, live, rows = _mutable_live(raw)
    assert isinstance(port_data, dict)
    port_data["entitled_underliers"] = [underlier]
    envelope_data["underlier"] = underlier
    live["eligible_expiries"] = ["2026-10-09"]
    rows[0]["underlier"] = underlier
    rows[0]["contract_id"] = f"{underlier}-20261009-C-06000000"
    rows[0]["deliverable_units"][0]["asset_id"] = underlier
    rows[0]["underlier_basis"] = basis
    result = _translate(raw)
    assert result.live is not None and result.live.status == "OK"
    assert result.snapshot is not None
    assert result.snapshot.live is not None
    assert result.snapshot.live.underlier == underlier


def test_split_adjusted_multiplier_requires_deliverable_evidence() -> None:
    raw = _raw()
    _, _, rows = _mutable_live(raw)
    rows[0]["multiplier_basis"] = "PRE_ACTION"
    rows[0]["split_factor"] = "2"
    rows[0]["deliverable_units"][0]["units"] = "200"
    adapted = _translate(raw)
    assert adapted.live is not None and adapted.live.status == "OK"
    assert adapted.snapshot is not None and adapted.snapshot.live is not None
    assert adapted.snapshot.live.series[0].deliverable_units[0].units == Decimal("200")

    raw = _raw()
    _, _, rows = _mutable_live(raw)
    rows[0]["multiplier_basis"] = "PRE_ACTION"
    rows[0]["split_factor"] = "2"
    rows[0]["deliverable_units"][0]["units"] = "100"
    mismatch = _translate(raw)
    assert mismatch.live is not None and mismatch.live.status == "UNAVAILABLE"
    assert "DELIVERABLE_MULTIPLIER_MISMATCH" in mismatch.live.reasons


@pytest.mark.parametrize("leg_kind", ("CASH", "OTHER_ASSET"))
def test_negative_non_underlier_deliverable_is_excluded_before_row_and_oi_coverage(
    leg_kind: str,
) -> None:
    raw = _raw()
    _, live, rows = _mutable_live(raw)
    negative_row = copy.deepcopy(rows[0])
    negative_row.update(
        row_id=f"synthetic-negative-{leg_kind.lower()}-row",
        contract_id=f"SPX-20261009-{leg_kind}-06000000",
        option_type="PUT",
    )
    negative_row["deliverable_units"].append(
        {
            "kind": leg_kind,
            "asset_id": "SYNTHETIC-CASH" if leg_kind == "CASH" else "SYNTHETIC-ASSET",
            "units": "-1",
            "currency": "USD",
        }
    )
    live["rows"] = [rows[0], negative_row]
    live["eligible_oi_denominator"] = "160"
    live["expected_series_count"] = 2

    result = _translate(raw)

    assert result.live is not None and result.live.status == "DEGRADED"
    assert "NEGATIVE_DELIVERABLE_UNITS" in result.live.reasons
    assert result.live.mapped_series_ids == ("OPRA:SPX-20261009-C-06000000",)
    assert result.live.coverage_numerator == Decimal("80")
    assert result.live.coverage_denominator == Decimal("160")
    assert result.live.coverage_exact == (1, 2)
    assert result.live.coverage_ratio == Decimal("0.5")
    assert result.snapshot is not None and result.snapshot.live is not None
    assert len(result.snapshot.live.series) == 1
    assert result.snapshot.live.series[0].contract == "SPX-20261009-C-06000000"
    assert all("-1" not in reason for reason in result.live.reasons)
    assert any(
        item.series_id == f"OPRA:{negative_row['contract_id']}"
        and item.reason == "NEGATIVE_DELIVERABLE_UNITS"
        for item in result.live.excluded
    )


def test_weekly_monthly_and_0dte_expiries_preserve_early_close_calendar() -> None:
    raw = _raw()
    _, live, rows = _mutable_live(raw)
    weekly = copy.deepcopy(rows[0])
    monthly = copy.deepcopy(rows[0])
    same_day = copy.deepcopy(rows[0])
    monthly.update(
        row_id="synthetic-monthly-row", contract_id="SPX-20261016-C-06000000",
        expiry_date="2026-10-16", expiry_kind="MONTHLY", open_interest="80",
    )
    same_day.update(
        row_id="synthetic-0dte-row", contract_id="SPX-20261006-C-06000000",
        expiry_date="2026-10-06", expiry_kind="WEEKLY", expiry_cutoff_ns=1_010_000_000_000,
        open_interest="80",
    )
    weekly["open_interest"] = "80"
    live["rows"] = [weekly, monthly, same_day]
    live["eligible_expiries"] = ["2026-10-06", "2026-10-09", "2026-10-16"]
    live["eligible_oi_denominator"] = "240"
    live["expected_series_count"] = 3
    live["session"]["early_close"] = True
    live["session"]["session_close_ns"] = 1_010_000_000_000
    result = _translate(raw)
    assert result.live is not None and result.live.status == "OK"
    assert result.live.has_0dte
    assert len(result.live.mapped_series_ids) == 3
    assert result.snapshot is not None and result.snapshot.live is not None
    assert result.snapshot.live.calendar.early_close is True


def test_replay_collapses_identical_rows_and_valid_correction_chain_supersedes_old_row() -> None:
    raw = _raw()
    _, live, rows = _mutable_live(raw)
    original = copy.deepcopy(rows[0])
    live["rows"] = [original, copy.deepcopy(original)]
    live["eligible_oi_denominator"] = "80"
    result = _translate(raw)
    assert result.live is not None and result.live.status == "OK"
    assert len(result.live.mapped_series_ids) == 1

    raw = _raw()
    _, live, rows = _mutable_live(raw)
    original = copy.deepcopy(rows[0])
    correction = copy.deepcopy(original)
    correction.update(
        row_id="synthetic-row-1-correction", row_revision=2,
        corrects_row_id="synthetic-row-1", correction_id="synthetic-correction-1",
        open_interest="80", gamma="0.03",
    )
    live["rows"] = [original, correction]
    live["eligible_oi_denominator"] = "80"
    corrected = _translate(raw)
    assert corrected.live is not None and corrected.live.status == "OK"
    assert corrected.live.correction_ids == ("synthetic-correction-1",)
    assert corrected.live.mapped_series_ids == ("OPRA:SPX-20261009-C-06000000",)
    assert any(item.reason == "SUPERSEDED_BY_CORRECTION" for item in corrected.live.excluded)


def test_conflicting_duplicate_contract_and_wrong_oi_family_fail_closed() -> None:
    raw = _raw()
    _, live, rows = _mutable_live(raw)
    conflict = copy.deepcopy(rows[0])
    conflict["row_id"] = "conflicting-row"
    conflict["gamma"] = "0.03"
    live["rows"] = [rows[0], conflict]
    result = _translate(raw)
    assert result.live is not None and result.live.status == "UNAVAILABLE"
    assert "DUPLICATE_CONFLICTING_CONTRACT" in result.live.reasons

    raw = _raw()
    _, _, rows = _mutable_live(raw)
    rows[0]["oi_family"] = "INTRADAY"
    mismatch = _translate(raw)
    assert mismatch.live is not None and mismatch.live.status == "UNAVAILABLE"
    assert "OI_FAMILY_MISMATCH" in mismatch.live.reasons


def _settled_fixture() -> dict[str, object]:
    raw = _raw()
    envelope_data = raw["envelope"]
    assert isinstance(envelope_data, dict)
    live = envelope_data["live"]
    assert isinstance(live, dict)
    settled = copy.deepcopy(live)
    settled.update(
        data_state="SETTLED", snapshot_id="settled-snapshot-1",
        source_chain_id="settled-chain-1", observed_ns=1_010_000_000_000,
        published_ns=1_011_000_000_000, available_ns=1_012_000_000_000,
        official_settlement_ns=1_010_000_000_000,
    )
    settled["session"]["session_close_ns"] = 1_000_000_000_000
    for index, row in enumerate(settled["rows"]):
        row.update(
            row_id=f"settled-row-{index}", corrects_row_id=None, correction_id=None,
            spot_observed_ns=1_009_000_000_000, spot_available_ns=1_011_000_000_000,
            quote_observed_ns=1_009_000_000_000, quote_available_ns=1_011_000_000_000,
            iv_observed_ns=1_009_000_000_000, iv_available_ns=1_011_000_000_000,
            greek_observed_ns=1_009_000_000_000, greek_available_ns=1_011_000_000_000,
            published_ns=1_010_000_000_000,
        )
    envelope_data["settled"] = settled
    raw["asof_ns"] = 1_020_000_000_000
    return raw


def test_settled_horizon_uses_independent_official_settlement_and_never_copies_live() -> None:
    raw = _settled_fixture()
    result = _translate(raw)
    assert result.live is not None
    assert result.settled is not None and result.settled.status == "OK"
    assert result.settled.data_state == "SETTLED"
    assert result.settled.official_settlement_ns == 1_010_000_000_000
    assert result.live.snapshot_id != result.settled.snapshot_id
    assert result.live.source_chain_id != result.settled.source_chain_id
    assert result.snapshot is not None and result.snapshot.settled is not None
    assert result.snapshot.live is not None
    assert result.snapshot.live is not result.snapshot.settled

    raw = _settled_fixture()
    envelope_data = raw["envelope"]
    assert isinstance(envelope_data, dict)
    envelope_data["settled"]["official_settlement_ns"] = None
    missing = _translate(raw)
    assert missing.settled is not None and missing.settled.status == "UNAVAILABLE"
    assert "MISSING_SETTLEMENT_TIMESTAMP" in missing.settled.reasons
    assert missing.snapshot is None or missing.snapshot.settled is None

    raw = _settled_fixture()
    envelope_data = raw["envelope"]
    assert isinstance(envelope_data, dict)
    envelope_data["settled"]["source_chain_id"] = envelope_data["live"]["source_chain_id"]
    copied = _translate(raw)
    assert copied.settled is not None and copied.settled.status == "UNAVAILABLE"
    assert "SETTLED_COPIES_LIVE" in copied.settled.reasons
    assert copied.snapshot is not None and copied.snapshot.settled is None


def test_empty_horizons_are_unavailable_and_never_invent_snapshot_or_pin_odds() -> None:
    raw = _raw()
    envelope_data = raw["envelope"]
    assert isinstance(envelope_data, dict)
    envelope_data["live"] = None
    result = _translate(raw)
    assert result.status == "UNAVAILABLE"
    assert result.snapshot is None
    assert "NO_HORIZON" in result.reasons
    assert result.dealer_sign_inferred is False
    assert result.pin_probability is None


def test_structural_errors_are_typed_and_issued_results_cannot_be_forged_or_reissued() -> None:
    port, envelope, asof_ns = _models()
    with pytest.raises(ChainAdapterError) as invalid_asof:
        translate_chain(port, envelope, asof_ns=True)
    assert invalid_asof.value.code == "INVALID_ASOF"
    assert str(invalid_asof.value) == "INVALID_ASOF"
    with pytest.raises(ChainAdapterError) as invalid_input:
        translate_chain(object(), envelope, asof_ns=asof_ns)  # type: ignore[arg-type]
    assert invalid_input.value.code == "INVALID_INPUT"

    result = translate_chain(port, envelope, asof_ns=asof_ns)
    with pytest.raises(SealError):
        ChainAdaptationV1.model_validate(result.model_dump())
    for operation in (lambda: copy.copy(result), lambda: copy.deepcopy(result),
                      lambda: pickle.dumps(result)):
        with pytest.raises((SealError, TypeError)):
            operation()
    object.__setattr__(result, "status", "UNAVAILABLE")
    assert not verify_adaptation(result)
    with pytest.raises(SealError):
        require_adaptation(result)


def test_constructor_rejects_nonfinite_decimal_and_mutable_nested_evidence() -> None:
    raw = _raw()
    _, _, rows = _mutable_live(raw)
    rows[0]["gamma"] = "NaN"
    with pytest.raises(SealError):
        _models(raw)

    raw = _raw()
    _, live, _ = _mutable_live(raw)
    live["rows"] = {"mutable": "not-an-array"}
    with pytest.raises((SealError, ValidationError)):
        _models(raw)
