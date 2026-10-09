from __future__ import annotations

import copy
import json
import pickle
from dataclasses import fields, replace
from datetime import UTC, date, datetime, timedelta, timezone
from decimal import Decimal, localcontext
from pathlib import Path

import pytest

from leviathan_core.events_monitor import (
    AlertCandidateV1,
    AmbiguousEventIdentityError,
    CorporateActionSnapshotV1,
    CorporateEventRevisionV1,
    DpOverlayEvidenceV1,
    EventMarketEvidenceV1,
    EventMetricPolicyV1,
    EventMetricsV1,
    EventOverlayV1,
    EventSnapshotV1,
    ExchangeSessionV1,
    ExpectedMoveWindowV1,
    FlowOverlayEvidenceV1,
    FrozenRecordReconstructionError,
    IntegerFieldTypeError,
    PrecisionExceededError,
    SealedResultError,
    calendar_window,
    evaluate_event,
    select_revision,
)

FIXTURES = Path(__file__).parent / "fixtures" / "kernel"


def _event(*, revision=1, state="scheduled", start=1000, end=1000,
           precision="exact", published=100, received=100, available=100,
           native="vendor-native-42", related_tickers=()):
    return CorporateEventRevisionV1(
        event_id="issuer-42:earnings:q3fy26", issuer_id="issuer-42", ticker="XYZ",
        event_type="earnings", state=state, source="synthetic-vendor", native_id=native,
        vendor_revision=revision, event_start_ns=start, event_end_ns=end, precision=precision,
        session="regular", exchange_tz="UTC", published_ns=published, received_ns=received,
        available_ns=available, fiscal_year=2026, fiscal_quarter=3,
        related_tickers=related_tickers,
    )


def test_vendor_revision_is_visible_only_after_publication_receipt_and_availability():
    v = json.loads((FIXTURES / "revision_visibility.json").read_text(encoding="utf-8-sig"))
    old = _event(revision=v["old_revision"], available=v["old_available_ns"])
    revised = _event(revision=v["new_revision"], state="revised", start=1050, end=1050,
                     published=v["new_published_ns"], received=v["new_received_ns"],
                     available=v["new_available_ns"])
    assert select_revision((old, revised), v["asof_before_revision"]) == old
    assert select_revision((old, revised), v["asof_after_revision"]) == revised
    assert select_revision((old, revised), v["asof_before_revision"]).event_start_ns == 1000


def test_canceled_revision_suppresses_alert_but_remains_selected_and_auditable():
    scheduled = _event(revision=1, available=100)
    canceled = _event(revision=2, state="canceled", published=200, received=200, available=200)
    assert select_revision((scheduled, canceled), 199) == scheduled
    assert select_revision((scheduled, canceled), 200) == canceled


def test_uncertain_session_time_is_a_range_and_not_a_fabricated_instant():
    event = _event(
        start=1_800_000_000_000_000, end=1_810_800_000_000_000,
        precision="session", native="stable-id",
    )
    result = evaluate_event(
        revisions=(event,), evidence=(), sessions=(), tzdata={"UTC": UTC},
        requested_tz="UTC", asof_ns=3000, policy=EventMetricPolicyV1(),
    )
    assert result.revision == event
    assert result.event_start_exchange_local is not None
    assert result.event_end_exchange_local is not None
    assert result.event_start_exchange_local != result.event_end_exchange_local
    assert result.status in {"MISSING", "PARTIAL"}
    assert result.expected_abs_move_relative is None
    assert result.realized_abs_log_move is None
    assert result.alert_candidates == ()


def test_missing_market_evidence_degrades_metrics_and_does_not_infer_event_free_state():
    event = _event()
    result = evaluate_event(
        revisions=(event,), evidence=(), sessions=(), tzdata={"UTC": UTC},
        requested_tz="UTC", asof_ns=3000,
    )
    assert result.status in {"MISSING", "PARTIAL"}
    assert result.pre is None or result.pre.status in {"MISSING", "PARTIAL"}
    assert result.post is None or result.post.status in {"MISSING", "PARTIAL"}
    assert result.surprise is None


def test_flow_and_dp_overlay_input_availability_is_bounded_by_asof():
    event = _event()
    future_iv = EventMarketEvidenceV1(
        kind="iv30d", ticker="XYZ", observed_ns=500, published_ns=501,
        received_ns=502, available_ns=502, value=Decimal("0.4"),
        source="fixture", native_id="future-iv",
    )
    result = evaluate_event(
        revisions=(event,), evidence=(future_iv,), sessions=(),
        tzdata={"UTC": UTC}, requested_tz="UTC", asof_ns=400,
    )
    assert result.asof_ns == 400
    assert result.pre is None or "future-iv" not in result.pre.evidence_ids
    assert result.post is None or "future-iv" not in result.post.evidence_ids



def _ns(year, month, day, hour, minute=0):
    return int(datetime(year, month, day, hour, minute, tzinfo=UTC).timestamp()) * 1_000_000_000


def _sessions_around_dst():
    values = (
        (date(2026, 3, 5), _ns(2026, 3, 5, 14, 30), _ns(2026, 3, 5, 21)),
        (date(2026, 3, 6), _ns(2026, 3, 6, 14, 30), _ns(2026, 3, 6, 21)),
        (date(2026, 3, 9), _ns(2026, 3, 9, 13, 30), _ns(2026, 3, 9, 20)),
        (date(2026, 3, 13), _ns(2026, 3, 13, 13, 30), _ns(2026, 3, 13, 20)),
    )
    return tuple(ExchangeSessionV1(*row) for row in values)


def test_dst_aware_event_snapshots_use_injected_calendar_and_pre_post_closes():
    expected = json.loads((FIXTURES / "known_event_metrics.json").read_text(encoding="utf-8-sig"))
    sessions = _sessions_around_dst()
    event_time = _ns(2026, 3, 9, 15)
    event = _event(start=event_time, end=event_time)
    pre_close = sessions[1].close_ns
    post_close = sessions[2].close_ns
    evidence = [
        EventMarketEvidenceV1("adjusted_close", "XYZ", sessions[0].close_ns,
                              sessions[0].close_ns, sessions[0].close_ns,
                              sessions[0].close_ns, Decimal("99"), "fixture", "close-thu"),
            EventMarketEvidenceV1("adjusted_close", "XYZ", pre_close, pre_close, pre_close,
                                  pre_close, Decimal("100"), "fixture", "close-pre-adjusted",
                                  adjustment_version="split-v2"),
            EventMarketEvidenceV1("adjusted_close", "XYZ", post_close, post_close, post_close,
                                  post_close, Decimal("110"), "fixture", "close-post-adjusted",
                                  adjustment_version="split-v2"),
        EventMarketEvidenceV1("spot", "XYZ", pre_close, pre_close, pre_close,
                              pre_close, Decimal("100"), "fixture", "spot-pre"),
        EventMarketEvidenceV1(
            "straddle", "XYZ", pre_close, pre_close, pre_close, pre_close,
            Decimal("5"), "fixture", "front-week-straddle",
            option_expiry_ns=sessions[3].close_ns, strike=Decimal("100"),
            call_bid=Decimal("2"), call_ask=Decimal("3"),
            put_bid=Decimal("2"), put_ask=Decimal("3"),
        ),
        EventMarketEvidenceV1("iv30d", "XYZ", sessions[0].close_ns, sessions[0].close_ns,
                              sessions[0].close_ns, sessions[0].close_ns, Decimal("0.2"),
                              "fixture", "iv-thu"),
        EventMarketEvidenceV1("iv30d", "XYZ", pre_close, pre_close, pre_close,
                              pre_close, Decimal("0.3"), "fixture", "iv-pre"),
        EventMarketEvidenceV1("iv30d", "XYZ", post_close, post_close, post_close,
                              post_close, Decimal("0.4"), "fixture", "iv-post"),
    ]
    policy = EventMetricPolicyV1(
        lookback_trading_days=3, min_iv_samples=2,
        expected_window=ExpectedMoveWindowV1(date(2026, 3, 6), date(2026, 3, 13)),
    )
    result = evaluate_event(
        revisions=(event,), evidence=tuple(evidence), sessions=sessions,
        tzdata={"UTC": UTC}, requested_tz="UTC", asof_ns=post_close,
        policy=policy,
    )
    assert result.pre.close_ns == pre_close
    assert result.post.close_ns == post_close
    assert result.pre.adjusted_close == Decimal(expected["pre_close"])
    assert result.post.adjusted_close == Decimal(expected["post_close"])
    assert result.pre.iv_rank == Decimal("100")
    assert result.expected_abs_move_relative == Decimal(expected["expected_relative"])
    assert result.expected_abs_move_currency == Decimal(expected["expected_currency"])
    with localcontext() as context:
        context.prec = 34
        observed_ratio = Decimal(expected["post_close"]) / Decimal(expected["pre_close"])
        expected_log_move = observed_ratio.ln()
    assert result.realized_abs_log_move == expected_log_move
    assert result.signed_simple_percent == Decimal(expected["signed_simple_percent"])
    assert result.signed_dollar_move == Decimal(expected["signed_dollar_move"])
    assert result.surprise is None
    assert result.surprise_reason == "WINDOW_MISMATCH"


def test_early_close_and_injected_holiday_calendar_choose_adjacent_trading_closes():
    sessions = (
        ExchangeSessionV1(date(2026, 7, 1), _ns(2026, 7, 1, 13, 30), _ns(2026, 7, 1, 20)),
        ExchangeSessionV1(date(2026, 7, 2), _ns(2026, 7, 2, 13, 30), _ns(2026, 7, 2, 17)),
        # July 3 is deliberately omitted as the injected holiday schedule.
        ExchangeSessionV1(date(2026, 7, 6), _ns(2026, 7, 6, 13, 30), _ns(2026, 7, 6, 20)),
    )
    event = _event(start=_ns(2026, 7, 2, 18), end=_ns(2026, 7, 2, 18))
    evidence = (
        EventMarketEvidenceV1(
            "adjusted_close", "XYZ", sessions[1].close_ns,
            sessions[1].close_ns, sessions[1].close_ns, sessions[1].close_ns,
            Decimal("50"), "fixture", "pre-split-adjusted-close", adjustment_version="split-v2",
        ),
        EventMarketEvidenceV1(
            "adjusted_close", "XYZ", sessions[2].close_ns,
            sessions[2].close_ns, sessions[2].close_ns, sessions[2].close_ns,
            Decimal("55"), "fixture", "post-split-adjusted-close", adjustment_version="split-v2",
        ),
    )
    result = evaluate_event(
        revisions=(event,), evidence=evidence, sessions=sessions,
        tzdata={"UTC": UTC}, requested_tz="UTC", asof_ns=sessions[2].close_ns,
    )
    assert result.pre.close_ns == sessions[1].close_ns
    assert result.post.close_ns == sessions[2].close_ns
    assert result.pre.adjusted_close == Decimal("50")
    assert result.post.adjusted_close == Decimal("55")
    assert "split-v2" in " ".join(result.pre.evidence_ids + result.post.evidence_ids)


def test_iv_window_is_derived_from_expiry_and_tenor_is_intrinsic_to_iv30d():
    sessions = (
        ExchangeSessionV1(date(2026, 3, 6), _ns(2026, 3, 6, 14), _ns(2026, 3, 6, 21)),
        ExchangeSessionV1(date(2026, 3, 9), _ns(2026, 3, 9, 13), _ns(2026, 3, 9, 20)),
        ExchangeSessionV1(date(2026, 3, 10), _ns(2026, 3, 10, 13), _ns(2026, 3, 10, 20)),
    )
    session = sessions[0]
    event = _event(start=_ns(2026, 3, 9, 14), end=_ns(2026, 3, 9, 14))
    expiry_ns = sessions[2].close_ns
    evidence = (
        EventMarketEvidenceV1(
            "spot", "XYZ", session.close_ns, session.close_ns,
            session.close_ns, session.close_ns, Decimal("100"), "fixture", "spot",
        ),
        EventMarketEvidenceV1(
            "iv30d", "XYZ", session.close_ns, session.close_ns,
            session.close_ns, session.close_ns, Decimal("0.3"), "fixture", "iv",
            option_expiry_ns=expiry_ns,
        ),
    )
    policy = EventMetricPolicyV1(
        expected_method="iv", expected_window=ExpectedMoveWindowV1(
            date(2026, 3, 6), date(2026, 3, 9),
        ), lookback_trading_days=1, min_iv_samples=1,
    )
    result = evaluate_event(
        revisions=(event,), evidence=evidence, sessions=sessions,
        tzdata={"UTC": UTC}, requested_tz="UTC", asof_ns=session.close_ns,
        policy=policy,
    )
    expected_days = Decimal(expiry_ns - session.close_ns) / Decimal(86_400_000_000_000)
    with localcontext() as context:
        context.prec = 34
        expected_days = Decimal(expiry_ns - session.close_ns) / Decimal(86_400_000_000_000)
        expected_relative = Decimal("0.3") * (expected_days / Decimal(365)).sqrt()
        expected_currency = Decimal("100") * expected_relative
    assert result.expected_abs_move_relative == expected_relative
    assert result.expected_abs_move_currency == expected_currency
    assert result.days_to_window == expected_days
    assert result.day_count_basis == policy.day_count_basis
    assert result.iv_tenor_days == 30
    assert result.expected_window == ExpectedMoveWindowV1(date(2026, 3, 6), date(2026, 3, 10))
    assert result.surprise is None
    assert result.surprise_reason == "WINDOW_MISMATCH"
    with pytest.raises(TypeError):
        EventMetricPolicyV1(iv_tenor_days=60)

    missing_expiry = evaluate_event(
        revisions=(event,), evidence=(evidence[0], replace(evidence[1], option_expiry_ns=None)),
        sessions=sessions, tzdata={"UTC": UTC}, requested_tz="UTC",
        asof_ns=session.close_ns, policy=policy,
    )
    assert missing_expiry.expected_abs_move_relative is None
    assert missing_expiry.surprise is None
    assert "EXPIRY_MISSING" in missing_expiry.reasons
    assert missing_expiry.surprise_reason == "WINDOW_MISMATCH"


def test_canceled_event_emits_only_state_change_alert_and_no_upcoming_alert():
    event = _event(state="canceled", start=10_000_000_000_000, end=10_000_000_000_000)
    result = evaluate_event(
        revisions=(event,), evidence=(), sessions=(), tzdata={"UTC": UTC},
        requested_tz="UTC", asof_ns=3000,
    )
    assert tuple(candidate.kind for candidate in result.alert_candidates) == ("state_change",)


def test_unstable_event_identity_is_quarantined_instead_of_deduplicated_by_guess():
    unkeyed = _event(native=None)
    with pytest.raises(AmbiguousEventIdentityError):
        select_revision((unkeyed,), 300)
    result = evaluate_event(
        revisions=(unkeyed,), evidence=(), sessions=(), tzdata={"UTC": UTC},
        requested_tz="UTC", asof_ns=300,
    )
    assert result.status == "QUARANTINED"


def test_stale_chain_and_missing_market_values_remain_explicitly_unavailable():
    session = ExchangeSessionV1(date(2026, 3, 6), _ns(2026, 3, 6, 14), _ns(2026, 3, 6, 21))
    event = _event(start=_ns(2026, 3, 9, 14), end=_ns(2026, 3, 9, 14))
    stale_at_close = session.close_ns - 61_000_000_000
    evidence = (
        EventMarketEvidenceV1(
            "spot", "XYZ", stale_at_close, stale_at_close,
            stale_at_close, stale_at_close, Decimal("100"), "fixture", "old-spot",
        ),
        EventMarketEvidenceV1("straddle", "XYZ", stale_at_close, stale_at_close,
                              stale_at_close, stale_at_close, Decimal("5"), "fixture", "old-chain"),
    )
    result = evaluate_event(
        revisions=(event,), evidence=evidence, sessions=(session,),
        tzdata={"UTC": UTC}, requested_tz="UTC", asof_ns=session.close_ns,
    )
    assert result.expected_abs_move_relative is None
    assert result.expected_abs_move_currency is None
    assert any("STALE" in reason for reason in result.reasons)


def test_flow_overlay_uses_twenty_day_baseline_and_only_typed_available_evidence():
    weekdays = []
    day = date(2026, 2, 20)
    while len(weekdays) < 11:
        if day.weekday() < 5:
            weekdays.append(day)
        day += timedelta(days=1)
    sessions = tuple(
        ExchangeSessionV1(current, _ns(current.year, current.month, current.day, 9),
                          _ns(current.year, current.month, current.day, 16))
        for current in weekdays
    )
    event_day = weekdays[-1]
    event = _event(start=_ns(event_day.year, event_day.month, event_day.day, 15),
                   end=_ns(event_day.year, event_day.month, event_day.day, 15))
    items = tuple(
        FlowOverlayEvidenceV1(
            "XYZ", session.close_ns, session.close_ns, session.close_ns, session.close_ns,
            Decimal("20") if index == 10 else Decimal(str(index + 1)),
            "flow-fixture", f"flow-{index}",
        )
        for index, session in enumerate(sessions)
    )
    future = FlowOverlayEvidenceV1(
        "XYZ", sessions[-1].close_ns + 1, sessions[-1].close_ns + 1,
        sessions[-1].close_ns + 1, sessions[-1].close_ns + 1, Decimal("1000"),
        "flow-fixture", "future-flow",
    )
    result = evaluate_event(
        revisions=(event,), evidence=(), sessions=sessions,
        tzdata={"UTC": UTC}, requested_tz="UTC",
        asof_ns=sessions[-1].close_ns,
        policy=EventMetricPolicyV1(flow_window_before_days=20, min_overlay_samples=10),
        flow_evidence=(*items, future),
    )
    candidate = next(item for item in result.overlays if item.source_id.endswith("flow-10:1"))
    assert candidate.baseline_count == 10
    assert candidate.z_score is not None
    assert candidate.threshold_crossed is True
    assert all("future-flow" not in item.source_id for item in result.overlays)


def test_late_market_revision_changes_content_version_without_rewriting_prior_asof():
    sessions = _sessions_around_dst()
    event = _event(start=_ns(2026, 3, 9, 15), end=_ns(2026, 3, 9, 15))
    pre_close = sessions[1].close_ns
    old = EventMarketEvidenceV1("adjusted_close", "XYZ", pre_close, pre_close, pre_close,
                                pre_close, Decimal("100"), "fixture", "split-close", revision=1)
    revised = EventMarketEvidenceV1(
        "adjusted_close", "XYZ", pre_close, pre_close + 1, pre_close + 1, pre_close + 1,
        Decimal("101"), "fixture", "split-close", revision=2, correction_of_revision=1,
        adjustment_version="split-v2",
    )
    before = evaluate_event(
        revisions=(event,), evidence=(old, revised), sessions=sessions,
        tzdata={"UTC": UTC}, requested_tz="UTC", asof_ns=pre_close,
    )
    after = evaluate_event(
        revisions=(event,), evidence=(old, revised), sessions=sessions,
        tzdata={"UTC": UTC}, requested_tz="UTC", asof_ns=pre_close + 1,
    )
    replay = evaluate_event(
        revisions=(event,), evidence=(old, revised), sessions=sessions,
        tzdata={"UTC": UTC}, requested_tz="UTC", asof_ns=pre_close,
    )
    assert before.pre.adjusted_close == Decimal("100")
    assert after.pre.adjusted_close == Decimal("101")
    assert after.result_version != before.result_version
    assert replay.result_version == before.result_version




def test_calendar_window_uses_supplied_standard_and_daylight_offsets_without_system_tzdb():
    standard = timezone(timedelta(hours=-5), "fixture-standard")
    daylight = timezone(timedelta(hours=-4), "fixture-daylight")
    march_6 = calendar_window(
        now_ns=_ns(2026, 3, 6, 15), exchange_tz="NY", tzdata={"NY": standard},
    )
    march_9 = calendar_window(
        now_ns=_ns(2026, 3, 9, 15), exchange_tz="NY", tzdata={"NY": daylight},
    )
    assert datetime.fromtimestamp(march_6[0] / 1_000_000_000, UTC).hour == 5
    assert datetime.fromtimestamp(march_9[0] / 1_000_000_000, UTC).hour == 4


def test_unentitled_evidence_is_excluded_and_typed_overlay_ports_cannot_be_swapped():
    session = ExchangeSessionV1(date(2026, 3, 6), _ns(2026, 3, 6, 14), _ns(2026, 3, 6, 21))
    event = _event(start=_ns(2026, 3, 9, 14), end=_ns(2026, 3, 9, 14))
    spot = EventMarketEvidenceV1(
        "spot", "XYZ", session.close_ns, session.close_ns, session.close_ns,
        session.close_ns, Decimal("100"), "fixture", "unentitled-spot", feed_state="UNENTITLED",
    )
    result = evaluate_event(
        revisions=(event,), evidence=(spot,), sessions=(session,),
        tzdata={"UTC": UTC}, requested_tz="UTC", asof_ns=session.close_ns,
    )
    assert result.expected_abs_move_relative is None
    assert any("UNENTITLED" in reason for reason in result.reasons)
    wrong_port = DpOverlayEvidenceV1(
        "XYZ", session.close_ns, session.close_ns, session.close_ns, session.close_ns,
        Decimal("1"), "dp-fixture", "dp-1",
    )
    with pytest.raises(ValueError, match="typed upstream evidence"):
        evaluate_event(
            revisions=(event,), evidence=(), sessions=(session,),
            tzdata={"UTC": UTC}, requested_tz="UTC", asof_ns=session.close_ns,
            flow_evidence=(wrong_port,),
        )


def test_equal_time_iv_source_conflict_is_permutation_stable_or_policy_ranked():
    sessions = _sessions_around_dst()
    event = _event(start=_ns(2026, 3, 9, 15), end=_ns(2026, 3, 9, 15))
    pre_close = sessions[1].close_ns
    expiry_ns = sessions[3].close_ns
    common = dict(
        kind="iv30d", ticker="XYZ", observed_ns=pre_close,
        published_ns=pre_close, received_ns=pre_close, available_ns=pre_close,
        option_expiry_ns=expiry_ns,
    )
    lower = EventMarketEvidenceV1(value=Decimal("0.2"), source="fallback",
                                  native_id="iv-fallback", **common)
    higher = EventMarketEvidenceV1(value=Decimal("0.4"), source="preferred",
                                   native_id="iv-preferred", **common)
    prior = EventMarketEvidenceV1(
        "iv30d", "XYZ", sessions[0].close_ns, sessions[0].close_ns,
        sessions[0].close_ns, sessions[0].close_ns, Decimal("0.1"),
        "history", "iv-prior",
    )
    spot = EventMarketEvidenceV1(
        "spot", "XYZ", pre_close, pre_close, pre_close, pre_close,
        Decimal("100"), "fixture", "spot-pre",
    )
    ambiguous_policy = EventMetricPolicyV1(
        expected_method="iv", lookback_trading_days=3, min_iv_samples=2,
        expected_window=ExpectedMoveWindowV1(date(2026, 3, 6), date(2026, 3, 13)),
    )
    first = evaluate_event(
        revisions=(event,), evidence=(prior, lower, higher, spot), sessions=sessions,
        tzdata={"UTC": UTC}, requested_tz="UTC", asof_ns=sessions[2].close_ns,
        policy=ambiguous_policy,
    )
    permuted = evaluate_event(
        revisions=(event,), evidence=(higher, prior, lower, spot), sessions=sessions,
        tzdata={"UTC": UTC}, requested_tz="UTC", asof_ns=sessions[2].close_ns,
        policy=ambiguous_policy,
    )
    assert repr(first).encode() == repr(permuted).encode()
    assert "QUOTE_CONFLICT" in first.reasons
    assert first.expected_abs_move_relative is None
    assert first.surprise is None

    ranked = evaluate_event(
        revisions=(event,), evidence=(prior, lower, higher, spot), sessions=sessions,
        tzdata={"UTC": UTC}, requested_tz="UTC", asof_ns=sessions[2].close_ns,
        policy=replace(ambiguous_policy, source_priority=("preferred", "fallback")),
    )
    assert ranked.pre.iv_value == Decimal("0.4")
    assert ranked.expected_abs_move_relative is not None
    assert "QUOTE_CONFLICT" not in ranked.reasons


def test_overlay_baseline_from_another_source_is_not_used_for_anomaly():
    dates = []
    day = date(2026, 2, 2)
    while len(dates) < 21:
        if day.weekday() < 5:
            dates.append(day)
        day += timedelta(days=1)
    sessions = tuple(
        ExchangeSessionV1(d, _ns(d.year, d.month, d.day, 9),
                          _ns(d.year, d.month, d.day, 16))
        for d in dates
    )
    event_session = sessions[-1]
    event = _event(start=_ns(event_session.session_date.year, event_session.session_date.month,
                            event_session.session_date.day, 15),
                   end=_ns(event_session.session_date.year, event_session.session_date.month,
                          event_session.session_date.day, 15))
    baseline = tuple(
        FlowOverlayEvidenceV1(
            "XYZ", session.close_ns, session.close_ns, session.close_ns, session.close_ns,
            Decimal(index + 1), "source-a", f"history-{index}",
        )
        for index, session in enumerate(sessions[:-1])
    )
    candidate = FlowOverlayEvidenceV1(
        "XYZ", event_session.close_ns, event_session.close_ns, event_session.close_ns,
        event_session.close_ns, Decimal("100"), "source-b", "event-value",
    )
    result = evaluate_event(
        revisions=(event,), evidence=(), sessions=sessions,
        tzdata={"UTC": UTC}, requested_tz="UTC", asof_ns=event_session.close_ns,
        policy=EventMetricPolicyV1(overlay_baseline_days=20, min_overlay_samples=20),
        flow_evidence=(*baseline, candidate),
    )

    overlay = next(item for item in result.overlays if item.source_id.endswith("event-value:1"))
    assert overlay.reason == "SOURCE_MISMATCH"
    assert overlay.z_score is None
    assert overlay.threshold_crossed is False
    assert not any(alert.kind == "anomaly" for alert in result.alert_candidates)


def test_mixed_adjustment_versions_withhold_realized_move_and_surprise():
    sessions = (
        ExchangeSessionV1(date(2026, 3, 6), _ns(2026, 3, 6, 14), _ns(2026, 3, 6, 21)),
        ExchangeSessionV1(date(2026, 3, 9), _ns(2026, 3, 9, 13), _ns(2026, 3, 9, 20)),
    )
    event = _event(start=_ns(2026, 3, 9, 15), end=_ns(2026, 3, 9, 15))
    evidence = (
        EventMarketEvidenceV1(
            "adjusted_close", "XYZ", sessions[0].close_ns, sessions[0].close_ns,
            sessions[0].close_ns, sessions[0].close_ns, Decimal("100"),
            "fixture", "before-split", adjustment_version="pre-split",
        ),
        EventMarketEvidenceV1(
            "adjusted_close", "XYZ", sessions[1].close_ns, sessions[1].close_ns,
            sessions[1].close_ns, sessions[1].close_ns, Decimal("50"),
            "fixture", "after-split", adjustment_version="post-split",
        ),
    )
    result = evaluate_event(
        revisions=(event,), evidence=evidence, sessions=sessions,
        tzdata={"UTC": UTC}, requested_tz="UTC", asof_ns=sessions[1].close_ns,
    )
    assert result.realized_abs_log_move is None
    assert result.signed_simple_percent is None
    assert result.signed_dollar_move is None
    assert result.surprise is None
    assert "ADJUSTMENT_VERSION_MISMATCH" in result.reasons


def test_visible_corporate_action_snapshot_maps_unversioned_close_pair():
    sessions = (
        ExchangeSessionV1(date(2026, 3, 6), _ns(2026, 3, 6, 14), _ns(2026, 3, 6, 21)),
        ExchangeSessionV1(date(2026, 3, 9), _ns(2026, 3, 9, 13), _ns(2026, 3, 9, 20)),
    )
    event = _event(start=_ns(2026, 3, 9, 15), end=_ns(2026, 3, 9, 15))
    evidence = (
        EventMarketEvidenceV1(
            "adjusted_close", "XYZ", sessions[0].close_ns, sessions[0].close_ns,
            sessions[0].close_ns, sessions[0].close_ns, Decimal("100"),
            "fixture", "before-split",
        ),
        EventMarketEvidenceV1(
            "adjusted_close", "XYZ", sessions[1].close_ns, sessions[1].close_ns,
            sessions[1].close_ns, sessions[1].close_ns, Decimal("50"),
            "fixture", "after-split",
        ),
    )
    action = CorporateActionSnapshotV1(
        "split-map-v1", "fixture-actions", sessions[1].close_ns + 1,
        "common-basis-v1", (("fixture:before-split:1", Decimal("0.5")),
                             ("fixture:after-split:1", Decimal("1"))),
    )
    result = evaluate_event(
        revisions=(event,), evidence=evidence, sessions=sessions,
        tzdata={"UTC": UTC}, requested_tz="UTC", asof_ns=sessions[1].close_ns,
        corporate_actions=(action,),
    )
    assert result.realized_abs_log_move is None
    assert "ADJUSTMENT_VERSION_MISMATCH" in result.reasons
    visible = evaluate_event(
        revisions=(event,), evidence=evidence, sessions=sessions,
        tzdata={"UTC": UTC}, requested_tz="UTC", asof_ns=sessions[1].close_ns + 1,
        corporate_actions=(action,),
    )
    assert visible.realized_abs_log_move == Decimal(0)
    assert visible.signed_simple_percent == Decimal(0)


def test_related_ticker_aliases_are_frozen_across_replay_and_reconstruction():
    aliases = ["ABC"]
    event = _event(related_tickers=aliases)
    aliases.append("MUTATED")
    variants = (event, replace(event))
    assert event.related_tickers == ("ABC",)
    results = tuple(evaluate_event(
        revisions=(variant,), evidence=(), sessions=(), tzdata={"UTC": UTC},
        requested_tz="UTC", asof_ns=300,
    ) for variant in variants)
    assert all(variant.related_tickers == ("ABC",) for variant in variants)
    assert len({result.result_version for result in results}) == 1
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(FrozenRecordReconstructionError) as exc:
            operation(event)
        assert exc.value.code == "FROZEN_RECORD_RECONSTRUCTION_FORBIDDEN"


def test_decimal_equivalence_is_canonical_and_bounds_are_enforced():
    event = _event()
    def spot(value):
        return EventMarketEvidenceV1(
            "spot", "XYZ", 200, 200, 200, 200, value, "fixture", "same-spot",
        )
    canonical = evaluate_event(
        revisions=(event,), evidence=(spot(Decimal("100")),), sessions=(),
        tzdata={"UTC": UTC}, requested_tz="UTC", asof_ns=300,
    )
    equivalent = evaluate_event(
        revisions=(event,), evidence=(spot(Decimal("100.0")),), sessions=(),
        tzdata={"UTC": UTC}, requested_tz="UTC", asof_ns=300,
    )
    assert canonical.result_version == equivalent.result_version
    assert spot(Decimal("100")).value == spot(Decimal("100.0")).value
    with pytest.raises(ValueError, match="decimal bounds"):
        spot(Decimal("1e1000000"))
    with pytest.raises(PrecisionExceededError, match="PRECISION_EXCEEDED"):
        spot(Decimal("1" * 51))


def test_late_overlay_anomaly_and_metrics_alerts_are_never_due_before_availability():
    dates = []
    day = date(2026, 2, 2)
    while len(dates) < 11:
        if day.weekday() < 5:
            dates.append(day)
        day += timedelta(days=1)
    sessions = tuple(
        ExchangeSessionV1(d, _ns(d.year, d.month, d.day, 9),
                          _ns(d.year, d.month, d.day, 16))
        for d in dates
    )
    event_session = sessions[-1]
    event_time = _ns(event_session.session_date.year, event_session.session_date.month,
                     event_session.session_date.day, 15)
    event = _event(start=event_time, end=event_time)
    baseline = tuple(
        FlowOverlayEvidenceV1(
            "XYZ", session.close_ns, session.close_ns, session.close_ns, session.close_ns,
            Decimal(index + 1), "flow-source", f"history-{index}",
        )
        for index, session in enumerate(sessions[:-1])
    )
    late_available = event_session.close_ns + 7 * 3_600_000_000_000
    candidate = FlowOverlayEvidenceV1(
        "XYZ", event_session.close_ns, event_session.close_ns, event_session.close_ns,
        late_available, Decimal("100"), "flow-source", "late-anomaly",
    )
    result = evaluate_event(
        revisions=(event,), evidence=(), sessions=sessions,
        tzdata={"UTC": UTC}, requested_tz="UTC", asof_ns=late_available,
        policy=EventMetricPolicyV1(overlay_baseline_days=20, min_overlay_samples=10),
        flow_evidence=(*baseline, candidate),
    )
    anomaly = next(alert for alert in result.alert_candidates if alert.kind == "anomaly")
    assert anomaly.available_ns == late_available
    assert anomaly.scheduled_ns == event_session.close_ns
    assert anomaly.due_ns == late_available
    assert all(alert.due_ns >= alert.available_ns for alert in result.alert_candidates)


def test_decimal_precision_over_34_is_rejected_without_collapsing_distinct_quotes():
    with pytest.raises(ValueError, match="PRECISION_EXCEEDED"):
        EventMarketEvidenceV1(
            "spot", "XYZ", 200, 200, 200, 200,
            Decimal("1.12345678901234567890123456789012345"), "fixture", "too-precise",
        )

    sessions = _sessions_around_dst()
    event = _event(start=_ns(2026, 3, 9, 15), end=_ns(2026, 3, 9, 15))
    pre_close = sessions[1].close_ns
    common = dict(
        kind="iv30d", ticker="XYZ", observed_ns=pre_close,
        published_ns=pre_close, received_ns=pre_close, available_ns=pre_close,
        option_expiry_ns=sessions[3].close_ns,
    )
    first = EventMarketEvidenceV1(
        value=Decimal("0." + "0" * 32 + "1"), source="source-a", native_id="iv-a", **common,
    )
    second = EventMarketEvidenceV1(
        value=Decimal("0." + "0" * 32 + "2"), source="source-b", native_id="iv-b", **common,
    )
    spot = EventMarketEvidenceV1(
        "spot", "XYZ", pre_close, pre_close, pre_close, pre_close,
        Decimal("100"), "fixture", "spot-pre",
    )
    prior = EventMarketEvidenceV1(
        "iv30d", "XYZ", sessions[0].close_ns, sessions[0].close_ns,
        sessions[0].close_ns, sessions[0].close_ns, Decimal("0.1"),
        "history", "iv-prior", option_expiry_ns=sessions[3].close_ns,
    )
    result = evaluate_event(
        revisions=(event,), evidence=(first, second, spot, prior), sessions=sessions,
        tzdata={"UTC": UTC}, requested_tz="UTC", asof_ns=sessions[2].close_ns,
        policy=EventMetricPolicyV1(
            expected_method="iv", lookback_trading_days=3, min_iv_samples=2,
            expected_window=ExpectedMoveWindowV1(date(2026, 3, 6), date(2026, 3, 13)),
        ),
    )
    assert first.value != second.value
    assert "QUOTE_CONFLICT" in result.reasons
    assert result.expected_abs_move_relative is None


def test_bool_is_rejected_in_integer_policy_evidence_revision_and_time_fields():
    event = _event()
    policy = EventMetricPolicyV1()
    evidence = EventMarketEvidenceV1(
        "spot", "XYZ", 200, 200, 200, 200, Decimal("100"), "fixture", "spot",
    )
    session = ExchangeSessionV1(date(2026, 3, 6), 100, 200)
    invalid_replacements = (
        lambda: replace(policy, min_iv_samples=True),
        lambda: replace(policy, max_evidence_age_ns=True),
        lambda: replace(event, vendor_revision=True),
        lambda: replace(event, event_start_ns=True),
        lambda: replace(evidence, revision=True),
        lambda: replace(evidence, observed_ns=True),
        lambda: replace(session, open_ns=True),
    )
    for reconstruct in invalid_replacements:
        with pytest.raises(IntegerFieldTypeError) as exc:
            reconstruct()
        assert exc.value.code == "INVALID_INTEGER"


def test_overlay_exact_sqrt_three_halves_stays_below_34_digit_threshold():
    dates = []
    day = date(2026, 1, 5)
    while len(dates) < 13:
        if day.weekday() < 5:
            dates.append(day)
        day += timedelta(days=1)
    sessions = tuple(
        ExchangeSessionV1(d, _ns(d.year, d.month, d.day, 9),
                          _ns(d.year, d.month, d.day, 16))
        for d in dates
    )
    event_session = sessions[-1]
    event_ns = _ns(event_session.session_date.year, event_session.session_date.month,
                   event_session.session_date.day, 15)
    event = _event(start=event_ns, end=event_ns)
    baseline_values = (0, 0, 0, 0, 2, 2, 2, 2, 1, 1, 1, 1)
    baseline = tuple(
        FlowOverlayEvidenceV1(
            "XYZ", session.close_ns, session.close_ns, session.close_ns, session.close_ns,
            Decimal(value), "flow-source", f"sqrt-baseline-{index}",
        )
        for index, (session, value) in enumerate(zip(sessions[:-1], baseline_values, strict=True))
    )
    candidate = FlowOverlayEvidenceV1(
        "XYZ", event_session.close_ns, event_session.close_ns, event_session.close_ns,
        event_session.close_ns, Decimal("2"), "flow-source", "sqrt-candidate",
    )
    threshold = Decimal("1.224744871391589049098642037352946")
    result = evaluate_event(
        revisions=(event,), evidence=(), sessions=sessions,
        tzdata={"UTC": UTC}, requested_tz="UTC", asof_ns=event_session.close_ns,
        policy=EventMetricPolicyV1(
            overlay_baseline_days=12, min_overlay_samples=10,
            overlay_z_threshold=threshold,
        ),
        flow_evidence=(*baseline, candidate),
    )
    overlay = next(item for item in result.overlays if item.source_id.endswith("sqrt-candidate:1"))
    assert overlay.z_score == threshold
    assert overlay.threshold_crossed is False
    assert not any(alert.kind == "anomaly" for alert in result.alert_candidates)


def test_exact_adjusted_close_dollar_move_overflow_raises_precision_error():
    sessions = (
        ExchangeSessionV1(date(2026, 3, 6), _ns(2026, 3, 6, 14), _ns(2026, 3, 6, 21)),
        ExchangeSessionV1(date(2026, 3, 9), _ns(2026, 3, 9, 13), _ns(2026, 3, 9, 20)),
    )
    event = _event(start=_ns(2026, 3, 9, 15), end=_ns(2026, 3, 9, 15))
    pre_id = "fixture:large-pre:1"
    post_id = "fixture:small-post:1"
    closes = (
        EventMarketEvidenceV1(
            "adjusted_close", "XYZ", sessions[0].close_ns, sessions[0].close_ns,
            sessions[0].close_ns, sessions[0].close_ns,
            Decimal("9" * 34), "fixture", "large-pre",
        ),
        EventMarketEvidenceV1(
            "adjusted_close", "XYZ", sessions[1].close_ns, sessions[1].close_ns,
            sessions[1].close_ns, sessions[1].close_ns,
            Decimal("2"), "fixture", "small-post",
        ),
    )
    action = CorporateActionSnapshotV1(
        "large-adjustment", "fixture-actions", sessions[1].close_ns,
        "common-basis-v1", ((pre_id, Decimal("3")), (post_id, Decimal("1"))),
    )
    with pytest.raises(PrecisionExceededError, match="PRECISION_EXCEEDED"):
        evaluate_event(
            revisions=(event,), evidence=closes, sessions=sessions,
            tzdata={"UTC": UTC}, requested_tz="UTC", asof_ns=sessions[1].close_ns,
            corporate_actions=(action,),
        )


def test_atm_distance_exact_one_third_fails_slightly_smaller_tolerance():
    sessions = (
        ExchangeSessionV1(date(2026, 3, 6), _ns(2026, 3, 6, 14), _ns(2026, 3, 6, 21)),
        ExchangeSessionV1(date(2026, 3, 9), _ns(2026, 3, 9, 13), _ns(2026, 3, 9, 20)),
    )
    event = _event(start=_ns(2026, 3, 9, 15), end=_ns(2026, 3, 9, 15))
    pre_close = sessions[0].close_ns
    expiry_ns = sessions[1].close_ns + 1
    evidence = (
        EventMarketEvidenceV1(
            "spot", "XYZ", pre_close, pre_close, pre_close, pre_close,
            Decimal("3"), "fixture", "three-dollar-spot",
        ),
        EventMarketEvidenceV1(
            "straddle", "XYZ", pre_close, pre_close, pre_close, pre_close,
            Decimal("1"), "fixture", "strike-two-straddle", option_expiry_ns=expiry_ns,
            strike=Decimal("2"), call_bid=Decimal("0.5"), call_ask=Decimal("0.5"),
            put_bid=Decimal("0.5"), put_ask=Decimal("0.5"),
        ),
    )
    result = evaluate_event(
        revisions=(event,), evidence=evidence, sessions=sessions,
        tzdata={"UTC": UTC}, requested_tz="UTC", asof_ns=pre_close,
        policy=EventMetricPolicyV1(
            atm_tolerance_relative=Decimal("0.3333333333333333333333333333333333"),
        ),
    )
    assert result.expected_abs_move_relative is None
    assert "NOT_ATM" in result.reasons


def test_public_result_replace_rejects_invalid_decimals_and_trailing_zeros_canonicalize():
    event = _event()
    output = evaluate_event(
        revisions=(event,), evidence=(), sessions=(), tzdata={"UTC": UTC},
        requested_tz="UTC", asof_ns=300,
    )
    for value in (Decimal("1e1000000"), Decimal("NaN"), 1.0):
        with pytest.raises((TypeError, ValueError)):
            replace(output, expected_abs_move_relative=value)

    trailing_zero_value = Decimal("1." + "0" * 50)
    evidence = EventMarketEvidenceV1(
        "spot", "XYZ", 200, 200, 200, 200, trailing_zero_value,
        "fixture", "trailing-zero-spot",
    )
    assert evidence.value == Decimal("1")


def test_straddle_expiry_must_be_after_first_post_event_close_without_fallback():
    sessions = (
        ExchangeSessionV1(date(2026, 1, 6), _ns(2026, 1, 6, 14), _ns(2026, 1, 6, 21)),
        ExchangeSessionV1(date(2026, 1, 7), _ns(2026, 1, 7, 14), _ns(2026, 1, 7, 21)),
    )
    event_ns = _ns(2026, 1, 6, 22)
    event = _event(start=event_ns, end=event_ns)
    pre_close, first_post_close = sessions[0].close_ns, sessions[1].close_ns

    for expiry_ns in (pre_close, first_post_close):
        evidence = (
            EventMarketEvidenceV1(
                "spot", "XYZ", pre_close, pre_close, pre_close, pre_close,
                Decimal("100"), "fixture", f"spot-{expiry_ns}",
            ),
            EventMarketEvidenceV1(
                "straddle", "XYZ", pre_close, pre_close, pre_close, pre_close,
                Decimal("1"), "fixture", f"expired-straddle-{expiry_ns}",
                option_expiry_ns=expiry_ns, strike=Decimal("100"),
                call_bid=Decimal("0.5"), call_ask=Decimal("0.5"),
                put_bid=Decimal("0.5"), put_ask=Decimal("0.5"),
            ),
        )
        result = evaluate_event(
            revisions=(event,), evidence=evidence, sessions=sessions,
            tzdata={"UTC": UTC}, requested_tz="UTC", asof_ns=first_post_close,
        )
        assert result.status == "UNAVAILABLE"
        assert "EXPECTED_MOVE_UNAVAILABLE" in result.reasons
        assert result.expected_abs_move_relative is None
        assert result.expected_abs_move_currency is None
        assert result.surprise is None


def test_exact_matching_one_third_expected_and_realized_move_has_zero_surprise():
    sessions = (
        ExchangeSessionV1(date(2026, 1, 6), _ns(2026, 1, 6, 14), _ns(2026, 1, 6, 21)),
        ExchangeSessionV1(date(2026, 1, 7), _ns(2026, 1, 7, 14), _ns(2026, 1, 7, 21)),
    )
    event_ns = _ns(2026, 1, 6, 22)
    event = _event(start=event_ns, end=event_ns)
    pre_close, post_close = sessions[0].close_ns, sessions[1].close_ns
    evidence = (
        EventMarketEvidenceV1(
            "spot", "XYZ", pre_close, pre_close, pre_close, pre_close,
            Decimal("3"), "fixture", "three-dollar-spot",
        ),
        EventMarketEvidenceV1(
            "adjusted_close", "XYZ", pre_close, pre_close, pre_close, pre_close,
            Decimal("3"), "fixture", "pre-close-three", adjustment_version="split-v1",
        ),
        EventMarketEvidenceV1(
            "adjusted_close", "XYZ", post_close, post_close, post_close, post_close,
            Decimal("4"), "fixture", "post-close-four", adjustment_version="split-v1",
        ),
        EventMarketEvidenceV1(
            "straddle", "XYZ", pre_close, pre_close, pre_close, pre_close,
            Decimal("1"), "fixture", "matched-one-third-straddle",
            option_expiry_ns=post_close + 1, strike=Decimal("3"),
            call_bid=Decimal("0.5"), call_ask=Decimal("0.5"),
            put_bid=Decimal("0.5"), put_ask=Decimal("0.5"),
        ),
    )
    result = evaluate_event(
        revisions=(event,), evidence=evidence, sessions=sessions,
        tzdata={"UTC": UTC}, requested_tz="UTC", asof_ns=post_close,
    )
    assert result.expected_window == ExpectedMoveWindowV1(date(2026, 1, 6), date(2026, 1, 7))
    assert result.realized_window == ExpectedMoveWindowV1(date(2026, 1, 6), date(2026, 1, 7))
    with localcontext() as context:
        context.prec = 34
        assert result.expected_abs_move_relative == Decimal(1) / Decimal(3)
        assert result.signed_simple_percent == Decimal(100) / Decimal(3)
    assert result.surprise == Decimal(0)


def test_sealed_result_rejects_semantic_content_or_result_version_replace():
    sessions = (
        ExchangeSessionV1(date(2026, 1, 6), _ns(2026, 1, 6, 14), _ns(2026, 1, 6, 21)),
        ExchangeSessionV1(date(2026, 1, 7), _ns(2026, 1, 7, 14), _ns(2026, 1, 7, 21)),
    )
    event_ns = _ns(2026, 1, 6, 22)
    event = _event(start=event_ns, end=event_ns)
    pre_close, post_close = sessions[0].close_ns, sessions[1].close_ns
    evidence = (
        EventMarketEvidenceV1(
            "spot", "XYZ", pre_close, pre_close, pre_close, pre_close,
            Decimal("3"), "fixture", "seal-three-dollar-spot",
        ),
        EventMarketEvidenceV1(
            "adjusted_close", "XYZ", pre_close, pre_close, pre_close, pre_close,
            Decimal("3"), "fixture", "seal-pre-close", adjustment_version="split-v1",
        ),
        EventMarketEvidenceV1(
            "adjusted_close", "XYZ", post_close, post_close, post_close, post_close,
            Decimal("4"), "fixture", "seal-post-close", adjustment_version="split-v1",
        ),
        EventMarketEvidenceV1(
            "straddle", "XYZ", pre_close, pre_close, pre_close, pre_close,
            Decimal("1"), "fixture", "seal-matched-straddle",
            option_expiry_ns=post_close + 1, strike=Decimal("3"),
            call_bid=Decimal("0.5"), call_ask=Decimal("0.5"),
            put_bid=Decimal("0.5"), put_ask=Decimal("0.5"),
        ),
    )
    result = evaluate_event(
        revisions=(event,), evidence=evidence, sessions=sessions,
        tzdata={"UTC": UTC}, requested_tz="UTC", asof_ns=post_close,
    )
    assert result.expected_abs_move_currency == Decimal("1")
    for field, value in (("expected_abs_move_currency", Decimal("999")),
                         ("result_version", "forged-result-version")):
        with pytest.raises(SealedResultError) as exc:
            replace(result, **{field: value})
        assert exc.value.code == "RESULT_CONTENT_MISMATCH"

    for forged_seal in (result._seal, result.content_hash):
        with pytest.raises((TypeError, ValueError)):
            replace(result, expected_abs_move_currency=Decimal("999"), _seal=forged_seal)

    public_fields = {
        item.name: getattr(result, item.name)
        for item in fields(EventMetricsV1)
        if item.init
    }
    with pytest.raises(SealedResultError) as construction_error:
        EventMetricsV1(**public_fields)
    assert construction_error.value.code == "RESULT_CONTENT_MISMATCH"


def test_copy_deepcopy_and_pickle_are_forbidden_for_public_frozen_records():
    event = _event()
    evidence = EventMarketEvidenceV1(
        "spot", "XYZ", 200, 200, 200, 200, Decimal("100"), "fixture", "spot",
    )
    session = ExchangeSessionV1(date(2026, 3, 6), 100, 200)
    policy = EventMetricPolicyV1()
    action = CorporateActionSnapshotV1("action-v1", "actions", 300, "basis-v1",
                                       (("v1", Decimal("1")),))
    flow = FlowOverlayEvidenceV1(
        "XYZ", 200, 200, 200, 200, Decimal("1"), "flow", "flow-1",
    )
    dp = DpOverlayEvidenceV1(
        "XYZ", 200, 200, 200, 200, Decimal("1"), "dp", "dp-1",
    )
    window = ExpectedMoveWindowV1(date(2026, 3, 6), date(2026, 3, 9))
    snapshot = EventSnapshotV1(
        "pre", date(2026, 3, 6), 200, None, 0, None, None, "MISSING", (), (),
    )
    overlay = EventOverlayV1(
        "flow", 200, None, False, 0, "MISSING", None, "flow:flow-1:1", "evt-v1",
        Decimal("1"), 200,
    )
    alert = AlertCandidateV1("evt:state", "state_change", 200, event.event_id, 200, 200)
    output = evaluate_event(
        revisions=(event,), evidence=(), sessions=(), tzdata={"UTC": UTC},
        requested_tz="UTC", asof_ns=300,
    )
    public_records = (
        event, evidence, session, policy, action, flow, dp, window,
        snapshot, overlay, alert, output,
    )
    for record in public_records:
        for operation in (copy.copy, copy.deepcopy, pickle.dumps):
            with pytest.raises((TypeError, ValueError)):
                operation(record)
