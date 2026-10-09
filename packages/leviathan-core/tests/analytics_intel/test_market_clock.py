"""Worker unit checks for the 60-session hourly clock estimator."""

from __future__ import annotations

from dataclasses import replace
from datetime import date, timedelta
from decimal import Decimal
from fractions import Fraction

from leviathan_core.analytics_intel.market_clock import (
    MINUTE_NS,
    MarketClockBarV1,
    MarketClockPolicyV1,
    _alert_decision,
    aggregate_clock,
)
from leviathan_core.analytics_intel.read_model import PolicyV1

_SESSION_NS = 10_000_000_000_000


class _Calendar:
    def _index(self, event_ns: int) -> int:
        return event_ns // _SESSION_NS - 1

    def session_for_ns(self, event_ns: int) -> str:
        return str(date(2026, 1, 1) + timedelta(days=self._index(event_ns)))

    def trailing_sessions(self, asof_ns: int, count: int) -> tuple[str, ...]:
        index = self._index(asof_ns)
        first = max(0, index - count + 1)
        return tuple(str(date(2026, 1, 1) + timedelta(days=i)) for i in range(first, index + 1))

    def hour_for_ns(self, event_ns: int) -> tuple[str, str, int, int]:
        index = self._index(event_ns)
        return self.session_for_ns(event_ns), "09", (index + 1) * _SESSION_NS, -300

    def hour_end_ns(self, hour_start_ns: int) -> int:
        return hour_start_ns + 60 * MINUTE_NS


def _policy() -> PolicyV1:
    return PolicyV1(
        "INT-008-POLICY-v1",
        "market_clock",
        MarketClockPolicyV1(
            "INT-008-POLICY-v1",
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
        ),
    )


def test_interpolated_alert_returns_indeterminate_when_margin_cannot_decide() -> None:
    alert, reason = _alert_decision(Fraction(2), [Fraction(1), Fraction(4)], Decimal("0.5"))
    assert alert is False
    assert reason == "ALERT_INDETERMINATE"
    assert _alert_decision(Fraction(3), [Fraction(1), Fraction(4)], Decimal("0.5")) == (
        True,
        None,
    )


def _hour(session_index: int, *, surge: bool = False) -> list[MarketClockBarV1]:
    session = str(date(2026, 1, 1) + timedelta(days=session_index))
    start = (session_index + 1) * _SESSION_NS
    base = Decimal(100 + session_index)
    increment = Decimal(1) if surge else Decimal("0.01")
    return [
        MarketClockBarV1(
            f"{session_index}-{minute}",
            "A",
            "XNYS",
            start + minute * MINUTE_NS,
            start + (minute + 1) * MINUTE_NS,
            start + (minute + 1) * MINUTE_NS,
            True,
            session,
            "cal1",
            "America/New_York",
            "source1",
            "adj1",
            "dataset1",
            "OK",
            base + increment * minute,
            base + increment * (minute + 1),
            base + increment * (minute + 1),
            base + increment * minute,
        )
        for minute in range(60)
    ]


def test_minimum_sessions_and_strict_advisory_alert() -> None:
    historical = [bar for session in range(40) for bar in _hour(session)]
    current = _hour(40, surge=True)
    asof = 41 * _SESSION_NS + 60 * MINUTE_NS
    missing = aggregate_clock(
        [*historical[60:], *current],
        asof,
        _policy(),
        _Calendar(),
        41 * _SESSION_NS,
    )[0]
    assert missing.status == "INSUFFICIENT_DATA"
    assert missing.session_count == 39
    ready = aggregate_clock(
        [*historical, *current],
        asof,
        _policy(),
        _Calendar(),
        41 * _SESSION_NS,
    )[0]
    assert ready.status == "READY"
    assert ready.session_count == 40
    assert ready.mean_abs_return is not None
    assert ready.move_p20 is not None and ready.move_p80 is not None
    assert ready.move_p20 <= ready.mean_abs_return <= ready.move_p80
    assert ready.alert_candidate is True
    assert ready.alert_move is not None and ready.alert_move > ready.move_p80
    assert ready.tile.to_dict()["payload"]["volatility_estimator"] == (
        "SAMPLE_SD_1M_CLOSE_LOG_RETURN"
    )
    incomplete_current = aggregate_clock(
        [*historical, *current[:-1]],
        asof,
        _policy(),
        _Calendar(),
        41 * _SESSION_NS,
    )[0]
    assert incomplete_current.status == "READY"
    assert incomplete_current.alert_candidate is False
    assert incomplete_current.missing_subbar_count == 1


def test_repeated_local_hour_is_separated_by_utc_offset() -> None:
    class FoldCalendar(_Calendar):
        def hour_for_ns(self, event_ns: int) -> tuple[str, str, int, int]:
            base = (self._index(event_ns) + 1) * _SESSION_NS
            second = event_ns >= base + 60 * MINUTE_NS
            return (
                self.session_for_ns(event_ns),
                "01",
                base + (60 * MINUTE_NS if second else 0),
                -300 if second else -240,
            )

    first = _hour(0)
    second = [
        replace(
            bar,
            bar_id=f"fold-{bar.bar_id}",
            interval_start_ns=bar.interval_start_ns + 60 * MINUTE_NS,
            interval_end_ns=bar.interval_end_ns + 60 * MINUTE_NS,
            availability_ns=bar.availability_ns + 60 * MINUTE_NS,
        )
        for bar in first
    ]
    result = aggregate_clock(
        [*first, *second],
        _SESSION_NS + 120 * MINUTE_NS,
        _policy(),
        FoldCalendar(),
    )
    assert len(result) == 2
    assert {bucket.utc_offset_minutes for bucket in result} == {-240, -300}
    assert all(bucket.session_hour == "01" for bucket in result)
