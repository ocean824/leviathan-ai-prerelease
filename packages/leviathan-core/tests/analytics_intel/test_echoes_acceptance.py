"""Independent INT-008A acceptance cases with a tiny calendar and synthetic bars."""

from __future__ import annotations

import copy
import json
import pickle
from dataclasses import replace
from decimal import ROUND_UP, Decimal, localcontext
from pathlib import Path

import pytest

from leviathan_core.analytics_intel.echoes import (
    EchoPolicyV1,
    EchoQueryV1,
    EchoSampleV1,
    evaluate_echoes,
)
from leviathan_core.analytics_intel.read_model import AnalyticsError, PolicyV1, decimal_context

FIXTURE = Path(__file__).parent / "fixtures" / "echoes" / "exact_values.json"
VALUES = json.loads(FIXTURE.read_text(encoding="utf-8"))
ASOF = 10_000
QUERY_BAR = 3_000


class Calendar:
    version = "calendar-v1"

    def session_for_ns(self, event_ns: int) -> str | None:
        return "2026-09-30" if 0 <= event_ns <= ASOF else None

    def trailing_sessions(self, asof_ns: int, count: int) -> tuple[str, ...]:
        return ("2026-09-30",)

    def hour_for_ns(self, event_ns: int) -> tuple[str, str, int, int] | None:
        return ("2026-09-30", "09", 0, 0)


def policy() -> PolicyV1:
    return PolicyV1(
        "INT-008-POLICY-v1",
        "echoes",
        EchoPolicyV1(
            policy_version="INT-008-POLICY-v1",
            k=20,
            max_lookback_years=5,
            horizons=(5, 20, 60),
            wilson_z=Decimal("1.96"),
            negligible_d=Decimal("0.2"),
        ),
    )


def query(
    horizon: int = 5,
    *,
    asof_ns: int = ASOF,
    availability_ns: int | None = None,
    finalized: bool = True,
) -> EchoQueryV1:
    return EchoQueryV1(
        state_id="query",
        instrument_id="XYZ",
        venue="XNYS",
        bar_index=QUERY_BAR,
        event_ns=5_000,
        asof_ns=asof_ns,
        feature_version="features-v1",
        regime_version="regimes-v1",
        regime="RANGE",
        features={"momentum": Decimal("0")},
        horizon=horizon,
        calendar_version="calendar-v1",
        entitlement="synthetic-entitled",
        stale=False,
        availability_ns=5_000 if availability_ns is None else availability_ns,
        finalized=finalized,
    )


def history(*, count: int = 24, horizon: int = 5) -> list[EchoSampleV1]:
    returns = [Decimal(value) for value in VALUES["horizon_returns"]]
    # The final four records are deliberately farther from the query. Their
    # outcomes remain in the unconditional lookback distribution for Cohen's d.
    returns.extend((Decimal("-0.08"), Decimal("-0.04"), Decimal("0.04"), Decimal("0.08")))
    rows: list[EchoSampleV1] = []
    for i in range(min(count, 24)):
        bar = 100 + (horizon + 10) * i
        feature = Decimal(i) if i < 20 else Decimal(100 + i)
        rows.append(
            EchoSampleV1(
                state_id=f"s{i:02d}",
                instrument_id="XYZ",
                venue="XNYS",
                bar_index=bar,
                event_ns=bar,
                availability_ns=bar,
                finalized=True,
                feature_version="features-v1",
                regime_version="regimes-v1",
                regime="RANGE",
                features={"momentum": feature},
                close=Decimal("1"),
                source_version="source-v1",
                dataset_version="dataset-v1",
                revision="r1",
                quality="VALID",
            )
        )
        if i < count:
            with localcontext(decimal_context()):
                end_close = returns[i].exp()
            end_bar = bar + horizon
            rows.append(
                EchoSampleV1(
                    state_id=f"end-{i:02d}",
                    instrument_id="XYZ",
                    venue="XNYS",
                    bar_index=end_bar,
                    event_ns=end_bar,
                    availability_ns=end_bar,
                    finalized=True,
                    feature_version="features-v1",
                    regime_version="regimes-v1",
                    regime="RANGE",
                    features={"momentum": Decimal(i + 1)},
                    close=end_close,
                    source_version="source-v1",
                    dataset_version="dataset-v1",
                    revision="r1",
                    quality="VALID",
                )
            )
    return rows


def test_k20_positive_share_wilson_and_advisory_tile_are_exact() -> None:
    result = evaluate_echoes(query(), history(), policy(), Calendar())

    assert result.status == "READY"
    assert len(result.neighbors) == 20
    assert result.positive_share == Decimal("0.6")
    assert Decimal("0.3865") < result.wilson_low < Decimal("0.3867")
    assert Decimal("0.7811") < result.wilson_high < Decimal("0.7813")
    assert result.tile.label == "MODEL_ESTIMATE"
    assert result.tile.policy_version == "INT-008-POLICY-v1"
    assert not {"route_permit", "order_intent", "order_authority"}.intersection(result.tile.payload)
    assert result.effect_label == "NEGLIGIBLE"


def test_cohens_d_matches_pooled_sample_sd_against_unconditional_lookback() -> None:
    result = evaluate_echoes(query(), history(), policy(), Calendar())
    chosen = [Decimal(value) for value in VALUES["horizon_returns"]]
    baseline = [*chosen, Decimal("-0.08"), Decimal("-0.04"), Decimal("0.04"), Decimal("0.08")]

    def sample_variance(values: list[Decimal]) -> Decimal:
        mean = sum(values) / Decimal(len(values))
        return sum((value - mean) ** 2 for value in values) / Decimal(len(values) - 1)

    with localcontext(decimal_context()):
        mean_difference = sum(chosen) / Decimal(len(chosen)) - sum(baseline) / Decimal(
            len(baseline)
        )
        pooled_variance = (
            Decimal(len(chosen) - 1) * sample_variance(chosen)
            + Decimal(len(baseline) - 1) * sample_variance(baseline)
        ) / Decimal(len(chosen) + len(baseline) - 2)
        expected = mean_difference / pooled_variance.sqrt()

    assert abs(result.cohens_d - expected) < Decimal("1e-30")


def test_fewer_than_twenty_mature_nonoverlapping_states_is_insufficient() -> None:
    result = evaluate_echoes(query(), history(count=19), policy(), Calendar())

    assert result.status == "INSUFFICIENT_DATA"
    assert result.tile.missing_reason == "INSUFFICIENT_DATA"
    assert result.positive_share is None


@pytest.mark.parametrize("horizon", [5, 20, 60])
def test_only_full_horizon_outcomes_are_used(horizon: int) -> None:
    result = evaluate_echoes(
        query(horizon), history(count=24, horizon=horizon), policy(), Calendar()
    )

    assert result.query.horizon == horizon
    assert result.status == "READY"
    assert len(result.forward_returns) == 20


def test_tied_distances_break_by_event_then_state_id_and_exclude_overlapping_candidates() -> None:
    samples = history()
    # Force an exact standardized-distance tie; earlier event must sort first.
    ties = {"s00": 100, "s01": 100, "s02": 99}
    samples = [
        replace(item, features={"momentum": Decimal("0")}, event_ns=ties[item.state_id])
        if item.state_id in ties
        else item
        for item in samples
    ]
    overlap = EchoSampleV1(
        state_id="overlap",
        instrument_id="XYZ",
        venue="XNYS",
        bar_index=QUERY_BAR - 5,
        event_ns=4_995,
        availability_ns=4_995,
        finalized=True,
        feature_version="features-v1",
        regime_version="regimes-v1",
        regime="RANGE",
        features={"momentum": Decimal("0")},
        close=Decimal("1"),
        source_version="source-v1",
        dataset_version="dataset-v1",
        revision="r1",
        quality="VALID",
    )
    result = evaluate_echoes(query(), [*samples, overlap], policy(), Calendar())

    assert "overlap" not in result.neighbors
    assert result.neighbors.index("s02") < result.neighbors.index("s00")
    assert result.neighbors.index("s00") < result.neighbors.index("s01")


def test_zero_sigma_excludes_feature_instead_of_dividing_by_zero() -> None:
    rows = [replace(item, features={"momentum": Decimal("1")}) for item in history()]
    result = evaluate_echoes(query(), rows, policy(), Calendar())
    assert result.status == "INSUFFICIENT_DATA"
    assert result.excluded_features == ("momentum",)


def test_one_eligible_feature_state_cannot_define_standard_deviation() -> None:
    rows = history(count=1)[:1]
    result = evaluate_echoes(query(), rows, policy(), Calendar())
    assert result.status == "INSUFFICIENT_DATA"
    assert "momentum" in result.excluded_features


def test_feature_standardization_uses_sample_sd_and_records_denominator() -> None:
    rows = history()
    result = evaluate_echoes(query(), rows, policy(), Calendar())
    values = [row.features["momentum"] for row in rows]
    with localcontext(decimal_context()):
        mean = sum(values) / Decimal(len(values))
        variance = sum((value - mean) ** 2 for value in values) / Decimal(len(values) - 1)
        expected = Decimal("3") / variance.sqrt()

    index = result.neighbors.index("s03")
    assert abs(result.distances[index] - expected) < Decimal("1e-30")
    assert result.tile.payload["standardization_sd"] == "SAMPLE_N_MINUS_1"
    assert result.tile.payload["standardization_sample_count"] == len(rows)


def test_missing_policy_is_rejected() -> None:
    with pytest.raises(AnalyticsError) as error:
        evaluate_echoes(query(), history(), None, Calendar())  # type: ignore[arg-type]
    assert error.value.code == "MISSING_POLICY"


def test_wrong_kind_policy_is_rejected() -> None:
    domain = EchoPolicyV1(
        policy_version="INT-008-POLICY-v1",
        k=20,
        max_lookback_years=5,
        horizons=(5, 20, 60),
        wilson_z=Decimal("1.96"),
        negligible_d=Decimal("0.2"),
    )
    with pytest.raises(AnalyticsError) as error:
        PolicyV1("INT-008-POLICY-v1", "market_clock", domain)
    assert error.value.code == "UNSUPPORTED_POLICY"


def test_wrong_policy_version_is_rejected() -> None:
    with pytest.raises(AnalyticsError) as error:
        PolicyV1(
            "INT-008-POLICY-v2",
            "echoes",
            EchoPolicyV1(
                policy_version="INT-008-POLICY-v1",
                k=20,
                max_lookback_years=5,
                horizons=(5, 20, 60),
                wilson_z=Decimal("1.96"),
                negligible_d=Decimal("0.2"),
            ),
        )
    assert error.value.code == "UNSUPPORTED_POLICY"


def test_policy_bounds_are_enforced_at_construction_and_replace() -> None:
    exact = policy()
    with pytest.raises(AnalyticsError) as invalid:
        replace(exact.domain, k=19)
    assert invalid.value.code == "POLICY_OUT_OF_BOUNDS"
    with pytest.raises(AnalyticsError) as wrong_horizon:
        replace(exact.domain, horizons=(5, 20, 30))
    assert wrong_horizon.value.code == "POLICY_OUT_OF_BOUNDS"


def test_arithmetic_is_invariant_to_ambient_decimal_context() -> None:
    expected = evaluate_echoes(query(), history(), policy(), Calendar())
    with localcontext() as ambient:
        ambient.prec = 6
        ambient.rounding = ROUND_UP
        actual = evaluate_echoes(query(), history(), policy(), Calendar())
    assert actual == expected


def test_future_available_and_unfinalized_samples_do_not_warm_result() -> None:
    rows = history(count=20)
    changed: list[EchoSampleV1] = []
    for row in rows:
        if row.state_id in {"s00", "s01"}:
            row = replace(
                row,
                availability_ns=ASOF + 1 if row.state_id == "s00" else row.availability_ns,
                finalized=False if row.state_id == "s01" else row.finalized,
            )
        changed.append(row)

    result = evaluate_echoes(query(), changed, policy(), Calendar())
    assert result.status == "INSUFFICIENT_DATA"


@pytest.mark.parametrize(
    ("availability_ns", "finalized", "code"),
    [(10_001, True, "FUTURE_DATA"), (5_000, False, "UNFINALIZED_QUERY")],
)
def test_query_bar_must_be_finalized_and_available_by_asof(
    availability_ns: int, finalized: bool, code: str
) -> None:
    with pytest.raises(AnalyticsError) as error:
        evaluate_echoes(
            query(availability_ns=availability_ns, finalized=finalized),
            history(),
            policy(),
            Calendar(),
        )
    assert error.value.code == code


def test_late_correction_is_invisible_until_its_availability_time() -> None:
    rows = history()
    original = next(row for row in rows if row.state_id == "s00")
    corrected = replace(
        original,
        availability_ns=7_000,
        revision="r2",
        source_version="source-v2",
    )
    rows.append(corrected)

    before = evaluate_echoes(query(asof_ns=6_000), rows, policy(), Calendar())
    after = evaluate_echoes(query(asof_ns=8_000), rows, policy(), Calendar())

    before_revisions = dict(
        zip(before.tile.payload["neighbors"], before.tile.payload["source_revisions"], strict=True)
    )
    after_revisions = dict(
        zip(after.tile.payload["neighbors"], after.tile.payload["source_revisions"], strict=True)
    )
    assert before_revisions["s00"] == "r1"
    assert after_revisions["s00"] == "r2"


def test_parallel_feature_version_does_not_displace_pinned_v1_history() -> None:
    v1_rows = history()
    baseline = evaluate_echoes(query(), v1_rows, policy(), Calendar())
    v2_rows = [
        replace(
            row,
            state_id=f"v2-{row.state_id}",
            feature_version="features-v2",
            availability_ns=row.availability_ns + 1,
            source_version="feat2-source",
            dataset_version="feat2-dataset",
            revision="r10",
            features={"momentum": Decimal("999")},
        )
        for row in v1_rows
    ]

    parallel = evaluate_echoes(query(), [*v1_rows, *v2_rows], policy(), Calendar())

    assert parallel == baseline
    assert not any(state_id.startswith("v2-") for state_id in parallel.neighbors)


def test_late_corrected_endpoint_updates_tile_availability_and_versions() -> None:
    rows = history()
    endpoint = next(row for row in rows if row.state_id == "end-00")
    rows.append(
        replace(
            endpoint,
            availability_ns=9_000,
            revision="r2",
            source_version="source-v2",
            dataset_version="dataset-v2",
            close=Decimal("1.2"),
        )
    )

    before = evaluate_echoes(query(asof_ns=8_000), rows, policy(), Calendar())
    after = evaluate_echoes(query(), rows, policy(), Calendar())

    assert after.status == "READY"
    assert after.tile.availability_ns == "9000"
    assert after.tile.availability_ns != before.tile.availability_ns
    assert after.tile.source_version == "MIXED"
    assert after.tile.dataset_version == "MIXED"
    assert after.tile.source_version != before.tile.source_version
    assert after.tile.dataset_version != before.tile.dataset_version


def test_final_log_return_is_correctly_rounded_once_from_exact_ratio() -> None:
    rows = history()
    rows = [replace(row, close=Decimal("3")) if row.state_id == "s00" else row for row in rows]
    rows = [replace(row, close=Decimal("4")) if row.state_id == "end-00" else row for row in rows]

    result = evaluate_echoes(query(), rows, policy(), Calendar())

    index = result.neighbors.index("s00")
    assert result.forward_returns[index] == Decimal("0.2876820724517809274392190059938274")


def test_endpoint_at_query_bar_is_included_as_a_matured_neighbor_outcome() -> None:
    rows = history()
    rows = [
        replace(
            row,
            bar_index=QUERY_BAR - 5,
            event_ns=4_995,
            availability_ns=4_995,
        )
        if row.state_id == "s00"
        else row
        for row in rows
    ]
    rows = [row for row in rows if row.state_id != "end-00"]
    origin = next(row for row in rows if row.state_id == "s00")
    rows.append(
        replace(
            origin,
            state_id="query-endpoint",
            bar_index=QUERY_BAR,
            event_ns=5_000,
            availability_ns=5_000,
            close=Decimal("1.01"),
        )
    )

    result = evaluate_echoes(query(), rows, policy(), Calendar())

    assert result.status == "READY"
    assert len(result.neighbors) == 20
    assert "s00" in result.neighbors
    assert result.tile.payload["unconditional_sample_count"] == 24


def test_revision_suffixes_use_integer_order_and_equal_revision_conflicts_fail() -> None:
    rows = history()
    original = next(row for row in rows if row.state_id == "s00")
    rows.extend((replace(original, revision="r9"), replace(original, revision="r10")))

    result = evaluate_echoes(query(), rows, policy(), Calendar())

    index = result.neighbors.index("s00")
    assert result.tile.payload["source_revisions"][index] == "r10"

    ambiguous = [
        replace(original, revision="r10", close=Decimal("1")),
        replace(original, revision="r10", close=Decimal("1.01")),
    ]
    for ordered in (ambiguous, list(reversed(ambiguous))):
        conflict_rows = [row for row in rows if row.state_id != "s00"] + ordered
        with pytest.raises(AnalyticsError) as error:
            evaluate_echoes(query(), conflict_rows, policy(), Calendar())
        assert error.value.code == "HISTORY_CONFLICT"


@pytest.mark.parametrize("future_record", ["neighbor", "outcome"])
def test_future_query_event_neighbor_or_outcome_is_excluded(future_record: str) -> None:
    rows = history()
    target_id = "s00" if future_record == "neighbor" else "end-00"
    rows = [
        replace(row, event_ns=6_000, availability_ns=6_000) if row.state_id == target_id else row
        for row in rows
    ]

    result = evaluate_echoes(query(), rows, policy(), Calendar())

    assert result.status == "READY"
    assert "s00" not in result.neighbors
    assert result.tile.payload["unconditional_sample_count"] == 23


def test_outcome_available_after_asof_is_excluded_even_when_neighbor_is_prior() -> None:
    rows = history()
    rows = [
        replace(row, availability_ns=ASOF + 1) if row.state_id == "end-00" else row for row in rows
    ]

    result = evaluate_echoes(query(), rows, policy(), Calendar())

    assert result.status == "READY"
    assert "s00" not in result.neighbors
    assert result.tile.payload["unconditional_sample_count"] == 23


def test_derived_standardized_distance_below_input_floor_is_accepted() -> None:
    rows = history()
    rows = [
        replace(
            row, features={"momentum": Decimal("1E+38") if row.state_id == "s23" else Decimal(0)}
        )
        for row in rows
    ]
    tiny_query = replace(query(), features={"momentum": Decimal("1E-38")})

    result = evaluate_echoes(tiny_query, rows, policy(), Calendar())

    assert result.status == "READY"
    assert len(result.distances) == 20
    assert all(Decimal(0) < distance < Decimal("1E-38") for distance in result.distances)


class InvalidCalendar(Calendar):
    invalid_query: bool

    def __init__(self, *, invalid_query: bool) -> None:
        self.invalid_query = invalid_query

    def session_for_ns(self, event_ns: int) -> str | None:
        if self.invalid_query or event_ns != 5_000:
            return "CALENDAR_CANARY_9781"
        return "2026-09-30"


@pytest.mark.parametrize("invalid_query", [True, False], ids=["query-session", "sample-session"])
def test_invalid_calendar_value_is_not_chained_into_public_error(invalid_query: bool) -> None:
    with pytest.raises(AnalyticsError) as error:
        evaluate_echoes(query(), history(), policy(), InvalidCalendar(invalid_query=invalid_query))

    assert error.value.code == "INVALID_CALENDAR"
    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert "CALENDAR_CANARY_9781" not in repr(error.value)


def test_integer_and_decimal_boundaries_are_typed_and_content_free() -> None:
    sample = history()[0]
    with pytest.raises(AnalyticsError) as boolean_index:
        replace(sample, bar_index=True)
    assert boolean_index.value.code == "INVALID_INTEGER"

    with pytest.raises(AnalyticsError) as excessive_precision:
        replace(sample, close=Decimal("1." + "1" * 35))
    assert excessive_precision.value.code == "PRECISION_EXCEEDED"

    with pytest.raises(AnalyticsError) as excessive_magnitude:
        replace(sample, close=Decimal("1E+39"))
    assert excessive_magnitude.value.code == "DECIMAL_OUT_OF_BOUNDS"


def test_query_sample_and_result_reject_copy_deepcopy_and_pickle() -> None:
    result = evaluate_echoes(query(), history(), policy(), Calendar())
    for value in (query(), history()[0], result, result.tile):
        for operation in (
            copy.copy,
            copy.deepcopy,
            lambda item: pickle.loads(pickle.dumps(item)),
        ):
            with pytest.raises(AnalyticsError):
                operation(value)
