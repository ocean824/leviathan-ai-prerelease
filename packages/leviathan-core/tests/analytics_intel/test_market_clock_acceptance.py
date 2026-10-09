"""Independent INT-008C session-window, band, alert and volatility cases."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import date, timedelta
from decimal import Decimal, localcontext
from fractions import Fraction
from pathlib import Path

import pytest

from leviathan_core.analytics_intel.market_clock import (
    MINUTE_NS,
    MarketClockBarV1,
    MarketClockPolicyV1,
    aggregate_clock,
)
from leviathan_core.analytics_intel.read_model import AnalyticsError, PolicyV1, decimal_context

FIXTURE = Path(__file__).parent / "fixtures" / "market_clock" / "exact_values.json"
VALUES = json.loads(FIXTURE.read_text(encoding="utf-8"))
HOUR_NS = 60 * MINUTE_NS
DAY_NS = 24 * HOUR_NS
CURRENT_INDEX = 60
ASOF = CURRENT_INDEX * DAY_NS + 10 * HOUR_NS
CURRENT_HOUR = CURRENT_INDEX * DAY_NS + 9 * HOUR_NS


class Calendar:
    def session_for_ns(self, event_ns: int) -> str | None:
        index = event_ns // DAY_NS
        if index < 0:
            return None
        return (date(2026, 1, 1) + timedelta(days=index)).isoformat()

    def trailing_sessions(self, asof_ns: int, count: int) -> tuple[str, ...]:
        last = asof_ns // DAY_NS
        first = max(0, last - count + 1)
        return tuple(
            (date(2026, 1, 1) + timedelta(days=index)).isoformat()
            for index in range(first, last + 1)
        )

    def hour_for_ns(self, event_ns: int) -> tuple[str, str, int, int] | None:
        session = self.session_for_ns(event_ns)
        if session is None:
            return None
        day_start = (event_ns // DAY_NS) * DAY_NS
        hour = (event_ns - day_start) // HOUR_NS
        return session, f"{hour:02d}", day_start + hour * HOUR_NS, 0

    def hour_end_ns(self, hour_start_ns: int) -> int:
        # Synthetic shortened session hour exercises the minimum 30-subbar rule.
        return hour_start_ns + 30 * MINUTE_NS


def policy() -> PolicyV1:
    domain = MarketClockPolicyV1(
        policy_version="INT-008-POLICY-v1",
        lookback_sessions=60,
        minimum_sessions=40,
        lower_percentile=Decimal("0.2"),
        upper_percentile=Decimal("0.8"),
        minimum_subbars=30,
        bar_interval_ns=MINUTE_NS,
        volatility_estimator="SAMPLE_SD_1M_CLOSE_LOG_RETURN",
        movement_estimator="ABS_HOURLY_OPEN_CLOSE_LOG_RETURN",
        annualized=False,
        strict_alert=True,
    )
    return PolicyV1("INT-008-POLICY-v1", "market_clock", domain)


def session_bars(
    index: int,
    move: Decimal,
    *,
    count: int = 30,
    returns: tuple[Decimal, ...] | None = None,
    first_id: str | None = None,
    hour_of_day: int = 9,
    timezone: str = "UTC",
) -> list[MarketClockBarV1]:
    day_start = index * DAY_NS
    hour_start = day_start + hour_of_day * HOUR_NS
    if returns is None:
        # Twenty-nine 1-minute returns: all zero except the final return. This
        # keeps the independently specified open-to-close log move transparent.
        returns = (Decimal(0),) * (count - 2) + (move,)
    assert len(returns) == count - 1
    with localcontext(decimal_context()):
        closes = [Decimal(1)]
        for change in returns:
            closes.append(closes[-1] * change.exp())
    session = (date(2026, 1, 1) + timedelta(days=index)).isoformat()
    prefix = first_id or f"s{index:02d}"
    bars: list[MarketClockBarV1] = []
    for minute in range(count):
        start = hour_start + minute * MINUTE_NS
        opening = Decimal(1) if minute == 0 else closes[minute - 1]
        closing = closes[minute]
        bars.append(
            MarketClockBarV1(
                bar_id=f"{prefix}-m{minute:02d}",
                instrument_id="XYZ",
                venue="XNYS",
                interval_start_ns=start,
                interval_end_ns=start + MINUTE_NS,
                availability_ns=start + MINUTE_NS,
                finalized=True,
                session=session,
                calendar_version="calendar-v1",
                timezone=timezone,
                source_version="source-v1",
                adjustment_version="adjustment-v1",
                dataset_version="dataset-v1",
                quality="VALID",
                open=opening,
                close=closing,
                high=max(opening, closing),
                low=min(opening, closing),
            )
        )
    return bars


def full_window_bars(*, current_move: Decimal = Decimal("0.032")) -> list[MarketClockBarV1]:
    moves = [Decimal(i // 12) / Decimal(100) for i in range(60)]
    bars = [bar for i, move in enumerate(moves) for bar in session_bars(i, move)]
    bars.extend(session_bars(CURRENT_INDEX, current_move, first_id="current"))
    return bars


def constant_window_bars(
    *, historical_move: Decimal, current_move: Decimal
) -> list[MarketClockBarV1]:
    bars = [bar for i in range(60) for bar in session_bars(i, historical_move)]
    bars.extend(session_bars(CURRENT_INDEX, current_move, first_id="current"))
    return bars


def exact_close_bars(index: int, close: Decimal, *, first_id: str) -> list[MarketClockBarV1]:
    bars = session_bars(index, Decimal(0), first_id=first_id)
    last = bars[-1]
    bars[-1] = replace(last, close=close, high=max(last.open, close), low=min(last.open, close))
    return bars


def result_for(bars: list[MarketClockBarV1], *, current_move: Decimal = Decimal("0.032")):
    return aggregate_clock(bars, ASOF, policy(), Calendar(), CURRENT_HOUR)[0]


def test_trailing_60_session_cell_uses_40_minimum_and_linear_20_80_bands() -> None:
    result = result_for(full_window_bars())

    assert result.status == "READY"
    assert result.session_count == 60
    assert result.missing_session_count == 0
    assert abs(result.move_p20 - Decimal("0.008")) < Decimal("1e-30")
    assert abs(result.move_p80 - Decimal("0.032")) < Decimal("1e-30")
    assert abs(result.mean_abs_return - Decimal("0.02")) < Decimal("1e-30")
    assert result.tile.payload["percentile_method"] == "linear_interpolation"
    assert result.tile.label == "MODEL_ESTIMATE"
    assert result.tile.policy_version == "INT-008-POLICY-v1"
    assert not {"route_permit", "order_intent", "order_authority"}.intersection(result.tile.payload)


def test_strict_alert_is_false_at_p80_and_true_only_above() -> None:
    equal = result_for(
        constant_window_bars(
            historical_move=Decimal("0.02"),
            current_move=Decimal("0.02"),
        ),
        current_move=Decimal("0.02"),
    )
    above = result_for(
        constant_window_bars(
            historical_move=Decimal("0.02"),
            current_move=Decimal("0.0201"),
        ),
        current_move=Decimal("0.0201"),
    )

    assert equal.move_p80 == equal.alert_move
    assert equal.alert_candidate is False
    assert above.alert_candidate is True
    assert above.tile.payload["alert_threshold"] == str(above.move_p80)
    assert above.tile.payload["alert_hour_start_ns"] == CURRENT_HOUR


def test_distinct_near_tied_log_moves_keep_strict_alert_ordering() -> None:
    historical_close = Decimal("3.000000000000000000000000000000001")
    current_close = Decimal("3.000000000000000000000000000000002")
    bars = [
        bar
        for index in range(60)
        for bar in exact_close_bars(index, historical_close, first_id=f"hist-{index:02d}")
    ]
    bars.extend(exact_close_bars(CURRENT_INDEX, current_close, first_id="current-exact"))

    result = result_for(bars)

    assert result.status == "READY"
    assert result.session_count == 60
    # The reported 34-digit log values may round together; exact price-ratio
    # ordering still distinguishes these inputs and must drive the alert.
    assert Fraction(current_close) > Fraction(historical_close)
    assert result.alert_candidate is True


def test_only_39_valid_sessions_is_insufficient_and_29_subbars_do_not_count() -> None:
    bars = [bar for i in range(39) for bar in session_bars(i, Decimal("0.01"))]
    bars.extend(session_bars(CURRENT_INDEX, Decimal("0.02"), count=30, first_id="current"))
    too_few_sessions = result_for(bars, current_move=Decimal("0.02"))

    assert too_few_sessions.status == "INSUFFICIENT_DATA"
    assert too_few_sessions.session_count == 39
    assert too_few_sessions.tile.missing_reason == "INSUFFICIENT_DATA"

    thirty_nine = [bar for i in range(40) for bar in session_bars(i, Decimal("0.01"))]
    thirty_nine.extend(session_bars(CURRENT_INDEX, Decimal("0.02"), count=30, first_id="current"))
    # One historical cell has 29 finalized one-minute bars, so it cannot be a
    # valid sample and the remaining 39 fall below the required 40 sessions.
    short = session_bars(0, Decimal("0.01"), count=29)
    short_ids = {bar.bar_id for bar in session_bars(0, Decimal("0.01"))}
    thirty_nine = [bar for bar in thirty_nine if bar.bar_id not in short_ids] + short
    invalid_subbars = result_for(thirty_nine, current_move=Decimal("0.02"))
    assert invalid_subbars.status == "INSUFFICIENT_DATA"
    assert invalid_subbars.session_count == 39


def test_realized_volatility_is_sample_sd_of_1m_log_returns_and_not_annualized() -> None:
    returns = (Decimal("0.01"), Decimal("-0.01")) + (Decimal(0),) * 27
    bars = [bar for i in range(40) for bar in session_bars(i, Decimal(0), returns=returns)]
    bars.extend(session_bars(CURRENT_INDEX, Decimal(0), returns=returns, first_id="current"))
    result = result_for(bars, current_move=Decimal(0))

    # 29 returns, mean 0, sample variance 0.0002/28; annualization would alter it.
    with localcontext(decimal_context()):
        expected = (Decimal("0.0002") / Decimal(28)).sqrt()
    assert abs(result.mean_realized_volatility - expected) < Decimal("1e-30")
    assert result.tile.payload["annualized"] is False
    assert result.tile.units == "log_return_nonannualized"


def test_future_and_unfinalized_bars_do_not_enter_session_cell() -> None:
    bars = full_window_bars(current_move=Decimal("0.04"))
    bars[-1] = MarketClockBarV1(
        **{
            "bar_id": "current-future",
            "instrument_id": "XYZ",
            "venue": "XNYS",
            "interval_start_ns": CURRENT_HOUR + 29 * MINUTE_NS,
            "interval_end_ns": CURRENT_HOUR + 30 * MINUTE_NS,
            "availability_ns": ASOF + 1,
            "finalized": False,
            "session": Calendar().session_for_ns(ASOF) or "",
            "calendar_version": "calendar-v1",
            "timezone": "UTC",
            "source_version": "source-v1",
            "adjustment_version": "adjustment-v1",
            "dataset_version": "dataset-v1",
            "quality": "VALID",
            "open": Decimal("1"),
            "close": Decimal("1.04"),
            "high": Decimal("1.04"),
            "low": Decimal("1"),
        }
    )
    result = result_for(bars, current_move=Decimal("0.04"))
    assert result.status == "READY"
    assert result.session_count == 60
    assert result.alert_candidate is False


def test_current_hour_is_not_final_before_calendar_hour_end() -> None:
    bars = full_window_bars(current_move=Decimal("0.04"))
    result = aggregate_clock(
        bars,
        CURRENT_HOUR + 30 * MINUTE_NS - 1,
        policy(),
        Calendar(),
        CURRENT_HOUR,
    )[0]

    assert result.status == "READY"
    assert result.alert_candidate is False


class FoldCalendar(Calendar):
    def hour_for_ns(self, event_ns: int) -> tuple[str, str, int, int] | None:
        session = self.session_for_ns(event_ns)
        if session is None:
            return None
        day_start = (event_ns // DAY_NS) * DAY_NS
        hour = (event_ns - day_start) // HOUR_NS
        if hour == 1:
            return session, "01", day_start + HOUR_NS, -300
        if hour == 2:
            return session, "01", day_start + 2 * HOUR_NS, -360
        return super().hour_for_ns(event_ns)


def test_dst_repeated_local_hour_is_split_by_utc_offset() -> None:
    timezone = "America/New_York"
    bars = [
        bar
        for index in range(60)
        for bar in (
            *session_bars(
                index,
                Decimal("0.01"),
                first_id=f"first-fold-{index:02d}",
                hour_of_day=1,
                timezone=timezone,
            ),
            *session_bars(
                index,
                Decimal("0.03"),
                first_id=f"second-fold-{index:02d}",
                hour_of_day=2,
                timezone=timezone,
            ),
        )
    ]
    current_hour = CURRENT_INDEX * DAY_NS + 2 * HOUR_NS
    bars.extend(
        session_bars(
            CURRENT_INDEX,
            Decimal("0.02"),
            first_id="current-second-fold",
            hour_of_day=2,
            timezone=timezone,
        )
    )

    result = aggregate_clock(
        bars,
        ASOF,
        policy(),
        FoldCalendar(),
        current_hour,
    )

    repeated = [bucket for bucket in result if bucket.session_hour == "01"]
    assert len(repeated) == 2
    assert {bucket.utc_offset_minutes for bucket in repeated} == {-360, -300}
    assert all(bucket.status == "READY" and bucket.session_count == 60 for bucket in repeated)


def test_missing_or_wrong_policy_is_rejected() -> None:
    bars = full_window_bars()
    with pytest.raises(AnalyticsError) as error:
        aggregate_clock(bars, ASOF, None, Calendar(), CURRENT_HOUR)  # type: ignore[arg-type]
    assert error.value.code == "MISSING_POLICY"

    with pytest.raises(AnalyticsError) as error:
        MarketClockPolicyV1(
            "INT-008-POLICY-v2",
            60,
            40,
            Decimal("0.2"),
            Decimal("0.8"),
            30,
            MINUTE_NS,
            "SAMPLE_SD_1M_CLOSE_LOG_RETURN",
            "ABS_HOURLY_OPEN_CLOSE_LOG_RETURN",
            False,
            True,
        )
    assert error.value.code == "UNSUPPORTED_POLICY"

    with pytest.raises(AnalyticsError) as error:
        PolicyV1("INT-008-POLICY-v1", "echoes", policy().domain)
    assert error.value.code == "UNSUPPORTED_POLICY"
