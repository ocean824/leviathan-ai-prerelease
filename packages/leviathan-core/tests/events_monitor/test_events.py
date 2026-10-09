"""Focused unit tests for the pure EVT-001 kernel."""

import copy
import pickle
from dataclasses import fields, replace
from datetime import UTC, date, datetime, timedelta, timezone, tzinfo
from decimal import Decimal, localcontext
from hashlib import sha256

import pytest

from leviathan_core.events_monitor import (
    AmbiguousEventIdentityError,
    CorporateActionSnapshotV1,
    CorporateEventRevisionV1,
    DpOverlayEvidenceV1,
    EventMarketEvidenceV1,
    EventMetricPolicyV1,
    EventMetricsV1,
    EventOverlayV1,
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


def ns(day: int, hour: int = 0) -> int:
    value = datetime(2026, 1, day, hour, tzinfo=UTC)
    return int(value.timestamp()) * 1_000_000_000


def event(**changes: object) -> CorporateEventRevisionV1:
    data: dict[str, object] = {
        "event_id": "event-1", "issuer_id": "issuer-1", "ticker": "ABC",
        "event_type": "earnings", "state": "confirmed", "source": "fixture",
        "native_id": "native-1", "vendor_revision": 1,
        "event_start_ns": ns(6, 22), "event_end_ns": ns(6, 22),
        "precision": "exact", "session": "post", "exchange_tz": "UTC",
        "published_ns": ns(1), "received_ns": ns(1), "available_ns": ns(1),
        "fiscal_year": 2025, "fiscal_quarter": 4,
    }
    data.update(changes)
    return CorporateEventRevisionV1(**data)  # type: ignore[arg-type]


def market(kind: str, day: int, value: str, *, revision: int = 1,
           available_ns: int | None = None) -> EventMarketEvidenceV1:
    observed_ns = ns(day, 20)
    return EventMarketEvidenceV1(
        kind=kind, ticker="ABC", observed_ns=observed_ns, published_ns=observed_ns,
        received_ns=observed_ns, available_ns=available_ns or observed_ns,
        value=Decimal(value), source="fixture", native_id=f"{kind}-{day}",
        revision=revision,
        adjustment_version="split-v1" if kind == "adjusted_close" else None,
        option_expiry_ns=(ns(7, 21) if kind == "straddle" else
                          ns(7, 20) if kind == "iv30d" else None),
        strike=Decimal(100) if kind == "straddle" else None,
        call_bid=Decimal(2) if kind == "straddle" else None,
        call_ask=Decimal(3) if kind == "straddle" else None,
        put_bid=Decimal(2) if kind == "straddle" else None,
        put_ask=Decimal(3) if kind == "straddle" else None,
    )  # type: ignore[arg-type]


def sessions() -> tuple[ExchangeSessionV1, ...]:
    return tuple(ExchangeSessionV1(date(2026, 1, d), ns(d, 14), ns(d, 20))
                 for d in (2, 5, 6, 7))


def evidence() -> tuple[EventMarketEvidenceV1, ...]:
    return (
        market("iv30d", 2, ".2"), market("iv30d", 5, ".25"),
        market("iv30d", 6, ".3"), market("iv30d", 7, ".1"),
        market("adjusted_close", 6, "100"), market("adjusted_close", 7, "110"),
        market("spot", 6, "100"), market("straddle", 6, "5"),
    )


def test_revision_is_asof_and_alert_key_survives_time_change() -> None:
    first = event()
    second = event(vendor_revision=2, state="revised", correction_of_revision=1,
                   event_start_ns=ns(7, 22), event_end_ns=ns(7, 22),
                   published_ns=ns(6, 23), received_ns=ns(6, 23), available_ns=ns(6, 23))
    assert select_revision((second, first), ns(6, 22)) == first
    assert select_revision((first, second), ns(7)) == second
    policy = EventMetricPolicyV1(min_iv_samples=2)
    before = evaluate_event(revisions=(first, second), evidence=evidence(), sessions=sessions(),
                            tzdata={"UTC": UTC}, requested_tz="UTC", asof_ns=ns(6, 22),
                            policy=policy)
    after = evaluate_event(revisions=(first, second), evidence=evidence(), sessions=sessions(),
                           tzdata={"UTC": UTC}, requested_tz="UTC", asof_ns=ns(7, 23),
                           policy=policy)
    assert before.vendor_revision == 1
    assert after.vendor_revision == 2
    assert "event-1:upcoming:24h" in {x.key for x in before.alert_candidates}
    assert "event-1:upcoming:24h" in {x.key for x in after.alert_candidates}


def test_metrics_keep_log_and_simple_moves_distinct() -> None:
    result = evaluate_event(
        revisions=(event(),), evidence=evidence(), sessions=sessions(),
        tzdata={"UTC": UTC}, requested_tz="UTC", asof_ns=ns(8),
        policy=EventMetricPolicyV1(
            min_iv_samples=2,
            expected_window=ExpectedMoveWindowV1(date(2026, 1, 6), date(2026, 1, 7)),
        ),
    )
    assert result.status == "OK"
    assert result.pre is not None and result.post is not None
    assert result.pre.iv_rank == Decimal(100)
    assert result.pre.iv_sample_count == 3
    assert result.expected_abs_move_relative == Decimal("0.05")
    assert result.expected_abs_move_currency == Decimal(5)
    assert result.signed_simple_percent == Decimal(10)
    assert result.signed_dollar_move == Decimal(10)
    with localcontext() as context:
        context.prec = 34
        assert result.realized_abs_log_move == (Decimal("1.1").ln()).copy_abs()
    assert result.surprise == Decimal("0.05")
    assert result.surprise_unit == "relative"


def test_straddle_must_outlive_first_post_event_session_close() -> None:
    expired = replace(market("straddle", 6, "5"), option_expiry_ns=ns(7, 20))
    items = (*(x for x in evidence() if x.kind != "straddle"), expired)
    result = evaluate_event(
        revisions=(event(),), evidence=items, sessions=sessions(),
        tzdata={"UTC": UTC}, requested_tz="UTC", asof_ns=ns(8),
        policy=EventMetricPolicyV1(min_iv_samples=2),
    )
    assert result.status == "UNAVAILABLE"
    assert result.expected_abs_move_relative is None
    assert "EXPECTED_MOVE_UNAVAILABLE" in result.reasons


def test_surprise_uses_exact_rational_move_before_display_rounding() -> None:
    quote = replace(
        market("straddle", 6, "5"), value=Decimal(1), strike=Decimal(3),
        call_bid=Decimal("0.5"), call_ask=Decimal("0.5"),
        put_bid=Decimal("0.5"), put_ask=Decimal("0.5"),
    )
    items = (
        *(x for x in evidence() if x.kind not in ("straddle", "spot", "adjusted_close")),
        market("spot", 6, "3"), market("adjusted_close", 6, "3"),
        market("adjusted_close", 7, "4"), quote,
    )
    result = evaluate_event(
        revisions=(event(),), evidence=items, sessions=sessions(),
        tzdata={"UTC": UTC}, requested_tz="UTC", asof_ns=ns(8),
        policy=EventMetricPolicyV1(min_iv_samples=2),
    )
    assert result.expected_abs_move_relative is not None
    assert result.surprise == Decimal(0)


def test_result_seal_binds_all_fields_and_result_version() -> None:
    result = evaluate_event(
        revisions=(event(),), evidence=evidence(), sessions=sessions(),
        tzdata={"UTC": UTC}, requested_tz="UTC", asof_ns=ns(8),
        policy=EventMetricPolicyV1(min_iv_samples=2),
    )
    assert len(result.content_hash) == 64
    with pytest.raises(SealedResultError, match="RESULT_CONTENT_MISMATCH"):
        replace(result, expected_abs_move_currency=Decimal(999))
    with pytest.raises(SealedResultError, match="RESULT_CONTENT_MISMATCH"):
        replace(result, result_version="forged")
    altered = tuple(
        (item.name, Decimal(999) if item.name == "expected_abs_move_currency"
         else getattr(result, item.name))
        for item in fields(result) if item.name != "_seal"
    )
    forged_hash = sha256(repr(altered).encode("utf-8")).hexdigest()
    with pytest.raises(TypeError, match="init=False"):
        replace(result, expected_abs_move_currency=Decimal(999),
                _seal=type(result._seal)(forged_hash))
    values = {item.name: getattr(result, item.name)
              for item in fields(result) if item.name != "_seal"}
    with pytest.raises(SealedResultError, match="RESULT_CONTENT_MISMATCH"):
        EventMetricsV1(**values)  # type: ignore[arg-type]


def test_uncertain_clock_and_cancellation_do_not_generate_upcoming_alert() -> None:
    uncertain = event(precision="session", session="pre", event_start_ns=ns(6, 12),
                      event_end_ns=ns(6, 14), state="canceled")
    result = evaluate_event(
        revisions=(uncertain,), evidence=(), sessions=sessions(),
        tzdata={"UTC": UTC}, requested_tz="UTC", asof_ns=ns(8),
    )
    assert result.status == "CANCELED"
    assert result.event_start_exchange_local != result.event_end_exchange_local
    assert [candidate.kind for candidate in result.alert_candidates] == ["state_change"]


def test_unstable_identity_is_quarantined() -> None:
    unstable = event(native_id=None)
    with pytest.raises(AmbiguousEventIdentityError):
        select_revision((unstable,), ns(8))
    result = evaluate_event(revisions=(unstable,), evidence=(), sessions=(),
                            tzdata={"UTC": UTC}, requested_tz="UTC", asof_ns=ns(8))
    assert result.status == "QUARANTINED"


def test_stale_spot_is_labelled() -> None:
    stale_spot = market("spot", 5, "100")
    items = (*tuple(x for x in evidence() if x.kind != "spot"), stale_spot)
    result = evaluate_event(
        revisions=(event(),), evidence=items, sessions=sessions(),
        tzdata={"UTC": UTC}, requested_tz="UTC", asof_ns=ns(8),
        policy=EventMetricPolicyV1(min_iv_samples=2, max_evidence_age_ns=1),
    )
    assert result.status == "STALE"
    assert "STALE_SPOT" in result.reasons
    assert result.expected_abs_move_relative is None


def test_calendar_window_uses_injected_local_date_boundaries() -> None:
    start, end = calendar_window(now_ns=ns(7, 23), exchange_tz="UTC",
                                 tzdata={"UTC": UTC})
    assert start == int(datetime(2025, 12, 31, tzinfo=UTC).timestamp()) * 1_000_000_000
    assert end == ns(10)
    with pytest.raises(ValueError, match="not injected"):
        calendar_window(now_ns=ns(7), exchange_tz="America/New_York",
                        tzdata={"UTC": UTC})


def test_late_close_correction_is_append_only_asof() -> None:
    old = market("adjusted_close", 7, "110")
    corrected = market("adjusted_close", 7, "105", revision=2, available_ns=ns(8))
    items = (*(x for x in evidence() if x != old), old, corrected)
    policy = EventMetricPolicyV1(min_iv_samples=2)
    early = evaluate_event(revisions=(event(),), evidence=items, sessions=sessions(),
                           tzdata={"UTC": UTC}, requested_tz="UTC", asof_ns=ns(7, 23),
                           policy=policy)
    late = evaluate_event(revisions=(event(),), evidence=items, sessions=sessions(),
                          tzdata={"UTC": UTC}, requested_tz="UTC", asof_ns=ns(8),
                          policy=policy)
    assert early.signed_dollar_move == Decimal(10)
    assert late.signed_dollar_move == Decimal(5)
    assert early.result_version != late.result_version


def test_no_system_clock_is_needed_for_timezone_conversion() -> None:
    offset = timezone(timedelta(hours=-5))
    result = evaluate_event(revisions=(event(),), evidence=(), sessions=(),
                            tzdata={"UTC": UTC, "requested": offset},
                            requested_tz="requested", asof_ns=ns(8))
    assert result.event_start_requested_local is not None
    assert result.event_start_requested_local.endswith("-05:00 [requested]")


def test_unentitled_market_feed_is_excluded_and_labelled() -> None:
    unentitled = EventMarketEvidenceV1(
        kind="spot", ticker="ABC", observed_ns=ns(6, 20), published_ns=ns(6, 20),
        received_ns=ns(6, 20), available_ns=ns(6, 20), value=Decimal(100),
        source="unlicensed", native_id="spot-secret", feed_state="UNENTITLED",
    )
    items = (*tuple(x for x in evidence() if x.kind != "spot"), unentitled)
    result = evaluate_event(
        revisions=(event(),), evidence=items, sessions=sessions(),
        tzdata={"UTC": UTC}, requested_tz="UTC", asof_ns=ns(8),
        policy=EventMetricPolicyV1(min_iv_samples=2),
    )
    assert result.expected_abs_move_relative is None
    assert "UNENTITLED_OR_UNVERIFIED_MARKET_FEED" in result.reasons
    assert "MISSING_SPOT" in result.reasons


def test_flow_overlay_uses_only_prior_sessions_and_available_correction() -> None:
    def feb(day: int, hour: int) -> int:
        return int(datetime(2026, 2, day, hour, tzinfo=UTC).timestamp()) * 1_000_000_000

    calendar = tuple(ExchangeSessionV1(date(2026, 2, day), feb(day, 14), feb(day, 20))
                     for day in range(1, 23))

    def flow(day: int, value: int, *, revision: int = 1,
             available_ns: int | None = None) -> FlowOverlayEvidenceV1:
        observed = feb(day, 19)
        return FlowOverlayEvidenceV1(
            ticker="ABC", observed_ns=observed, published_ns=observed,
            received_ns=observed, available_ns=available_ns or observed,
            metric_value=Decimal(value), source="fixture", native_id=f"flow-{day}",
            revision=revision,
        )

    baseline = tuple(flow(day, day) for day in range(1, 21))
    initial = flow(21, 40)
    correction = flow(21, 10, revision=2, available_ns=feb(22, 22))
    revised_event = event(event_start_ns=feb(21, 22), event_end_ns=feb(21, 22))
    kwargs = {"revisions": (revised_event,), "evidence": (), "sessions": calendar,
              "tzdata": {"UTC": UTC}, "requested_tz": "UTC",
              "policy": EventMetricPolicyV1(min_overlay_samples=20)}
    early = evaluate_event(**kwargs, flow_evidence=(*baseline, initial, correction),
                           asof_ns=feb(22, 21))  # type: ignore[arg-type]
    late = evaluate_event(**kwargs, flow_evidence=(*baseline, initial, correction),
                          asof_ns=feb(22, 23))  # type: ignore[arg-type]
    early_target = next(x for x in early.overlays if x.observed_ns == feb(21, 19))
    late_target = next(x for x in late.overlays if x.observed_ns == feb(21, 19))
    assert early_target.baseline_count == 20
    assert early_target.threshold_crossed
    assert not late_target.threshold_crossed
    assert early_target.metric_value == Decimal(40)
    assert late_target.metric_value == Decimal(10)


def test_decimal_context_cannot_change_replay_result() -> None:
    kwargs = {"revisions": (event(),), "evidence": evidence(), "sessions": sessions(),
              "tzdata": {"UTC": UTC}, "requested_tz": "UTC", "asof_ns": ns(8),
              "policy": EventMetricPolicyV1(min_iv_samples=2, expected_method="iv")}
    default = evaluate_event(**kwargs)  # type: ignore[arg-type]
    with localcontext() as context:
        context.prec = 6
        changed_context = evaluate_event(**kwargs)  # type: ignore[arg-type]
    assert default.expected_abs_move_currency == changed_context.expected_abs_move_currency
    assert default.realized_abs_log_move == changed_context.realized_abs_log_move
    assert default.result_version == changed_context.result_version


class _InjectedEastern2026(tzinfo):
    """Fixture rules for one IANA-labelled zone without a host timezone database."""

    def utcoffset(self, dt: datetime | None) -> timedelta:
        if dt is None:
            return timedelta(hours=-5)
        local = dt.replace(tzinfo=None)
        spring = datetime(2026, 3, 8, 3)
        fall = datetime(2026, 11, 1, 2)
        return timedelta(hours=-4 if spring <= local < fall else -5)

    def dst(self, dt: datetime | None) -> timedelta:
        return self.utcoffset(dt) - timedelta(hours=-5)

    def tzname(self, dt: datetime | None) -> str:
        return "EDT" if self.dst(dt) else "EST"

    def fromutc(self, dt: datetime) -> datetime:
        utc = dt.replace(tzinfo=UTC)
        spring = datetime(2026, 3, 8, 7, tzinfo=UTC)
        fall = datetime(2026, 11, 1, 6, tzinfo=UTC)
        offset = timedelta(hours=-4 if spring <= utc < fall else -5)
        return (dt + offset).replace(tzinfo=self)


def test_calendar_window_obeys_injected_dst_transition() -> None:
    zone = _InjectedEastern2026()
    now_ns = int(datetime(2026, 3, 9, 16, tzinfo=UTC).timestamp()) * 1_000_000_000
    start, end = calendar_window(now_ns=now_ns, exchange_tz="America/New_York",
                                 tzdata={"America/New_York": zone},
                                 before_days=1, after_days=0)
    assert start == int(datetime(2026, 3, 8, 5, tzinfo=UTC).timestamp()) * 1_000_000_000
    assert end == int(datetime(2026, 3, 10, 4, tzinfo=UTC).timestamp()) * 1_000_000_000
    assert end - start == 47 * 3_600_000_000_000


def test_equal_time_iv_conflict_is_permutation_stable_and_priority_resolves() -> None:
    base = tuple(x for x in evidence() if not (x.kind == "iv30d" and x.observed_ns == ns(6, 20)))
    first = replace(market("iv30d", 6, ".2"), source="source-a")
    second = replace(market("iv30d", 6, ".4"), source="source-b")
    kwargs = {"revisions": (event(),), "sessions": sessions(), "tzdata": {"UTC": UTC},
              "requested_tz": "UTC", "asof_ns": ns(8),
              "policy": EventMetricPolicyV1(expected_method="iv", min_iv_samples=2)}
    left = evaluate_event(**kwargs, evidence=(*base, first, second))  # type: ignore[arg-type]
    right = evaluate_event(**kwargs, evidence=(*base, second, first))  # type: ignore[arg-type]
    assert left == right
    assert left.result_version == right.result_version
    assert left.expected_abs_move_relative is None
    assert "QUOTE_CONFLICT" in left.reasons
    resolved = evaluate_event(
        revisions=(event(),), evidence=(*base, first, second), sessions=sessions(),
        tzdata={"UTC": UTC}, requested_tz="UTC", asof_ns=ns(8),
        policy=EventMetricPolicyV1(expected_method="iv", min_iv_samples=2,
                                   source_priority=("source-b", "source-a")),
    )
    assert resolved.pre is not None and resolved.pre.iv_value == Decimal(".4")
    assert resolved.expected_abs_move_relative is not None


def test_expected_window_and_expiry_are_derived_from_evidence() -> None:
    quote = market("straddle", 6, "5")
    without_expiry = replace(quote, option_expiry_ns=None)
    items = tuple(x for x in evidence() if x.kind != "straddle")
    missing = evaluate_event(revisions=(event(),), evidence=(*items, without_expiry),
                             sessions=sessions(), tzdata={"UTC": UTC}, requested_tz="UTC",
                             asof_ns=ns(8), policy=EventMetricPolicyV1(min_iv_samples=2))
    assert missing.expected_abs_move_relative is None
    assert missing.status == "UNAVAILABLE"
    assert "EXPECTED_MOVE_UNAVAILABLE" in missing.reasons
    assert missing.surprise_reason == "WINDOW_MISMATCH"
    mismatched = evaluate_event(
        revisions=(event(),), evidence=evidence(), sessions=sessions(),
        tzdata={"UTC": UTC}, requested_tz="UTC", asof_ns=ns(8),
        policy=EventMetricPolicyV1(
            min_iv_samples=2,
            expected_window=ExpectedMoveWindowV1(date(2026, 1, 5), date(2026, 1, 6)),
        ),
    )
    assert mismatched.expected_abs_move_relative == Decimal(".05")
    assert mismatched.surprise is None and mismatched.surprise_reason == "WINDOW_MISMATCH"
    assert mismatched.days_to_window is not None
    assert Decimal(1) < mismatched.days_to_window < Decimal(2)
    with pytest.raises(TypeError):
        EventMetricPolicyV1(iv_tenor_days=60)  # type: ignore[call-arg]


def test_adjustment_basis_requires_match_or_visible_common_snapshot() -> None:
    changed = tuple(replace(x, adjustment_version="other")
                    if x.kind == "adjusted_close" and x.observed_ns == ns(7, 20) else x
                    for x in evidence())
    actions = (CorporateActionSnapshotV1(
        "action-1", "fixture", ns(9), "common-v1",
        (("split-v1", Decimal(1)), ("other", Decimal(1))),
    ),)
    kwargs = {"revisions": (event(),), "evidence": changed, "sessions": sessions(),
              "tzdata": {"UTC": UTC}, "requested_tz": "UTC",
              "policy": EventMetricPolicyV1(min_iv_samples=2)}
    before = evaluate_event(**kwargs, corporate_actions=actions,
                            asof_ns=ns(8))  # type: ignore[arg-type]
    after = evaluate_event(**kwargs, corporate_actions=actions,
                           asof_ns=ns(10))  # type: ignore[arg-type]
    assert before.realized_abs_log_move is None
    assert "ADJUSTMENT_VERSION_MISMATCH" in before.reasons
    assert after.signed_simple_percent == Decimal(10)
    assert after.result_version != before.result_version
    without_versions = tuple(replace(x, adjustment_version=None)
                             if x.kind == "adjusted_close" else x for x in evidence())
    no_basis = evaluate_event(revisions=(event(),), evidence=without_versions,
                              sessions=sessions(), tzdata={"UTC": UTC}, requested_tz="UTC",
                              asof_ns=ns(8), policy=EventMetricPolicyV1(min_iv_samples=2))
    assert no_basis.realized_abs_log_move is None
    assert "ADJUSTMENT_VERSION_MISMATCH" in no_basis.reasons


def test_frozen_aliases_and_canonical_decimal_survive_validated_replace() -> None:
    aliases = ["ABC.A"]
    revision = event(related_tickers=aliases)
    aliases.append("BAD")
    assert revision.related_tickers == ("ABC.A",)
    assert replace(revision).related_tickers == ("ABC.A",)
    factors = [["split-v1", Decimal(1)]]
    action = CorporateActionSnapshotV1("action", "fixture", ns(8), "basis", factors)
    factors[0][0] = "changed"
    assert action.factors == (("split-v1", Decimal(1)),)
    assert replace(action).factors == action.factors
    priority = ["fixture"]
    policy = EventMetricPolicyV1(source_priority=priority)
    priority.append("changed")
    assert replace(policy).source_priority == ("fixture",)
    alternate = tuple(replace(x, value=Decimal("100.0"))
                      if x.kind == "spot" else x for x in evidence())
    kwargs = {"revisions": (event(),), "sessions": sessions(), "tzdata": {"UTC": UTC},
              "requested_tz": "UTC", "asof_ns": ns(8),
              "policy": EventMetricPolicyV1(min_iv_samples=2)}
    first = evaluate_event(**kwargs, evidence=evidence())  # type: ignore[arg-type]
    second = evaluate_event(**kwargs, evidence=alternate)  # type: ignore[arg-type]
    assert first.result_version == second.result_version
    with pytest.raises(SealedResultError):
        replace(first, overlays=list(first.overlays))
    assert first.pre is not None
    assert isinstance(replace(first.pre, reasons=list(first.pre.reasons)).reasons, tuple)
    with pytest.raises(ValueError, match="decimal bounds"):
        replace(market("spot", 6, "100"), value=Decimal("1e1000000"))
    with pytest.raises(PrecisionExceededError, match="PRECISION_EXCEEDED"):
        replace(market("spot", 6, "100"), value=Decimal("9" * 50 + "e-11"))


def test_all_public_frozen_records_reject_copy_deepcopy_and_pickle() -> None:
    result = evaluate_event(
        revisions=(event(),), evidence=evidence(), sessions=sessions(),
        tzdata={"UTC": UTC}, requested_tz="UTC", asof_ns=ns(8),
        policy=EventMetricPolicyV1(min_iv_samples=2),
    )
    assert result.pre is not None and result.post is not None
    assert result.expected_window is not None and result.alert_candidates
    overlay = EventOverlayV1(
        kind="flow", observed_ns=ns(6, 20), z_score=None,
        threshold_crossed=False, baseline_count=0, status="PARTIAL",
        reason="INSUFFICIENT_OVERLAY_BASELINE", source_id="fixture:flow",
        policy_version="evt-v1", metric_value=Decimal(1), available_ns=ns(6, 20),
    )
    flow = FlowOverlayEvidenceV1(
        "ABC", ns(6, 20), ns(6, 20), ns(6, 20), ns(6, 20),
        Decimal(1), "fixture", "flow",
    )
    dp = DpOverlayEvidenceV1(
        "ABC", ns(6, 20), ns(6, 20), ns(6, 20), ns(6, 20),
        Decimal(1), "fixture", "dp",
    )
    records = (
        result.expected_window, CorporateActionSnapshotV1(
            "action", "fixture", ns(8), "basis", (("split-v1", Decimal(1)),)
        ), event(), sessions()[0], market("spot", 6, "100"),
        EventMetricPolicyV1(), flow, dp, result.pre, result.post, overlay,
        result.alert_candidates[0], result,
    )
    for record in records:
        if record is result:
            with pytest.raises(SealedResultError):
                replace(record)
        else:
            assert replace(record) == record
        with pytest.raises(FrozenRecordReconstructionError):
            copy.copy(record)
        with pytest.raises(FrozenRecordReconstructionError):
            copy.deepcopy(record)
        with pytest.raises(FrozenRecordReconstructionError):
            pickle.dumps(record)


def test_decimal_input_precision_cannot_hide_same_source_quote_conflict() -> None:
    with pytest.raises(PrecisionExceededError, match="PRECISION_EXCEEDED"):
        replace(market("iv30d", 6, ".2"),
                value=Decimal("0.20000000000000000000000000000000000000000000000001"))
    normal = market("iv30d", 6, ".2")
    distinct = replace(normal, value=Decimal("0.2" + "0" * 32 + "1"))
    assert distinct.value != normal.value
    items = tuple(x for x in evidence() if x.kind != "iv30d" or x.observed_ns != ns(6, 20))
    result = evaluate_event(
        revisions=(event(),), evidence=(*items, normal, distinct), sessions=sessions(),
        tzdata={"UTC": UTC}, requested_tz="UTC", asof_ns=ns(8),
        policy=EventMetricPolicyV1(min_iv_samples=2, expected_method="iv"),
    )
    assert result.status == "QUARANTINED"
    assert "QUOTE_CONFLICT" in result.reasons


def test_bool_rejected_for_integer_policy_evidence_and_result_fields() -> None:
    for change in ({"min_iv_samples": True}, {"max_evidence_age_ns": True},
                   {"day_count_basis": True}, {"overlay_baseline_days": True}):
        with pytest.raises(IntegerFieldTypeError):
            EventMetricPolicyV1(**change)  # type: ignore[arg-type]
    base_market = market("spot", 6, "100")
    for change in ({"revision": True}, {"observed_ns": True},
                   {"available_ns": True}, {"correction_of_revision": True}):
        with pytest.raises(IntegerFieldTypeError):
            replace(base_market, **change)
    with pytest.raises(IntegerFieldTypeError):
        replace(event(), vendor_revision=True)
    with pytest.raises(IntegerFieldTypeError):
        replace(sessions()[0], close_ns=True)
    with pytest.raises(IntegerFieldTypeError):
        replace(CorporateActionSnapshotV1("action", "fixture", ns(8), "basis",
                                          (("v1", Decimal(1)),)), available_ns=True)
    result = evaluate_event(revisions=(event(),), evidence=evidence(), sessions=sessions(),
                            tzdata={"UTC": UTC}, requested_tz="UTC", asof_ns=ns(8))
    assert result.pre is not None and result.alert_candidates
    with pytest.raises(IntegerFieldTypeError):
        replace(result, asof_ns=True)
    with pytest.raises(IntegerFieldTypeError):
        replace(result.pre, iv_sample_count=True)
    with pytest.raises(IntegerFieldTypeError):
        replace(result.alert_candidates[0], due_ns=True)


def test_cross_source_overlay_baseline_cannot_emit_anomaly() -> None:
    def feb(day: int, hour: int) -> int:
        return int(datetime(2026, 2, day, hour, tzinfo=UTC).timestamp()) * 1_000_000_000

    calendar = tuple(ExchangeSessionV1(date(2026, 2, day), feb(day, 14), feb(day, 20))
                     for day in range(1, 23))
    baseline = tuple(FlowOverlayEvidenceV1(
        "ABC", feb(day, 19), feb(day, 19), feb(day, 19), feb(day, 19),
        Decimal(day), "source-a", f"a-{day}",
    ) for day in range(1, 21))
    target = FlowOverlayEvidenceV1(
        "ABC", feb(21, 19), feb(21, 19), feb(21, 19), feb(22, 22),
        Decimal(100), "source-b", "b-21",
    )
    result = evaluate_event(
        revisions=(event(event_start_ns=feb(21, 22), event_end_ns=feb(21, 22)),),
        evidence=(), sessions=calendar, tzdata={"UTC": UTC}, requested_tz="UTC",
        asof_ns=feb(22, 23),
        policy=EventMetricPolicyV1(min_overlay_samples=20,
                                   flow_window_before_days=20),
        flow_evidence=(*baseline, target),
    )
    candidate = next(x for x in result.overlays if x.source_id.endswith("b-21:1"))
    assert candidate.reason == "SOURCE_MISMATCH"
    assert candidate.z_score is None and not candidate.threshold_crossed
    assert all(x.kind != "anomaly" for x in result.alert_candidates)


def test_late_anomaly_due_time_never_precedes_evidence_availability() -> None:
    def feb(day: int, hour: int) -> int:
        return int(datetime(2026, 2, day, hour, tzinfo=UTC).timestamp()) * 1_000_000_000

    calendar = tuple(ExchangeSessionV1(date(2026, 2, day), feb(day, 14), feb(day, 20))
                     for day in range(1, 23))
    baseline = tuple(FlowOverlayEvidenceV1(
        "ABC", feb(day, 19), feb(day, 19), feb(day, 19), feb(day, 19),
        Decimal(day), "source-a", f"a-{day}",
    ) for day in range(1, 21))
    target = FlowOverlayEvidenceV1(
        "ABC", feb(21, 19), feb(21, 19), feb(21, 19), feb(22, 22),
        Decimal(100), "source-a", "a-21",
    )
    result = evaluate_event(
        revisions=(event(event_start_ns=feb(21, 22), event_end_ns=feb(21, 22)),),
        evidence=(), sessions=calendar, tzdata={"UTC": UTC}, requested_tz="UTC",
        asof_ns=feb(22, 23),
        policy=EventMetricPolicyV1(min_overlay_samples=20,
                                   flow_window_before_days=20),
        flow_evidence=(*baseline, target),
    )
    anomaly = next(x for x in result.alert_candidates if x.kind == "anomaly")
    assert anomaly.scheduled_ns == feb(21, 19)
    assert anomaly.available_ns == feb(22, 22)
    assert anomaly.due_ns == feb(22, 22)


def test_exact_overlay_threshold_does_not_use_rounded_display_z() -> None:
    def feb(day: int, hour: int) -> int:
        return int(datetime(2026, 2, day, hour, tzinfo=UTC).timestamp()) * 1_000_000_000

    calendar = tuple(ExchangeSessionV1(date(2026, 2, day), feb(day, 14), feb(day, 20))
                     for day in range(1, 5))
    flow = tuple(FlowOverlayEvidenceV1(
        "ABC", feb(day, 19), feb(day, 19), feb(day, 19), feb(day, 19),
        Decimal(value), "fixture", f"flow-{day}",
    ) for day, value in ((1, 0), (2, 1), (3, 2), (4, 2)))
    threshold = Decimal("1.224744871391589049098642037352946")
    result = evaluate_event(
        revisions=(event(event_start_ns=feb(4, 22), event_end_ns=feb(4, 22)),),
        evidence=(), sessions=calendar, tzdata={"UTC": UTC}, requested_tz="UTC",
        asof_ns=feb(5, 0), flow_evidence=flow,
        policy=EventMetricPolicyV1(overlay_baseline_days=3, min_overlay_samples=3,
                                   overlay_z_threshold=threshold),
    )
    candidate = next(x for x in result.overlays if x.source_id.endswith("flow-4:1"))
    assert candidate.z_score == threshold
    assert candidate.threshold_crossed is False
    assert all(x.kind != "anomaly" for x in result.alert_candidates)


def test_exact_atm_comparison_rejects_rounded_one_third_boundary() -> None:
    spot = replace(market("spot", 6, "100"), value=Decimal(3))
    straddle = replace(
        market("straddle", 6, "5"), value=Decimal(1), strike=Decimal(2),
        call_bid=Decimal(".25"), call_ask=Decimal(".25"),
        put_bid=Decimal(".25"), put_ask=Decimal(".25"),
    )
    items = tuple(x for x in evidence() if x.kind not in ("spot", "straddle"))
    result = evaluate_event(
        revisions=(event(),), evidence=(*items, spot, straddle), sessions=sessions(),
        tzdata={"UTC": UTC}, requested_tz="UTC", asof_ns=ns(8),
        policy=EventMetricPolicyV1(
            min_iv_samples=2,
            atm_tolerance_relative=Decimal(".3333333333333333333333333333333333"),
        ),
    )
    assert result.expected_abs_move_relative is None
    assert "NOT_ATM" in result.reasons


def test_action_product_and_signed_dollar_move_never_round() -> None:
    changed = tuple(
        replace(x, value=Decimal("9" * 34), adjustment_version="pre")
        if x.kind == "adjusted_close" and x.observed_ns == ns(6, 20)
        else replace(x, value=Decimal(2), adjustment_version="post")
        if x.kind == "adjusted_close" and x.observed_ns == ns(7, 20)
        else x for x in evidence()
    )
    action = CorporateActionSnapshotV1(
        "action", "fixture", ns(8), "basis", (("pre", Decimal(3)),
                                               ("post", Decimal(1))),
    )
    with pytest.raises(PrecisionExceededError, match="PRECISION_EXCEEDED"):
        evaluate_event(
            revisions=(event(),), evidence=changed, sessions=sessions(),
            tzdata={"UTC": UTC}, requested_tz="UTC", asof_ns=ns(9),
            policy=EventMetricPolicyV1(min_iv_samples=2),
            corporate_actions=(action,),
        )


def test_result_replace_validates_decimals_and_trailing_zero_input() -> None:
    assert market("spot", 6, "1." + "0" * 50).value == Decimal(1)
    result = evaluate_event(revisions=(event(),), evidence=evidence(),
                            sessions=sessions(), tzdata={"UTC": UTC},
                            requested_tz="UTC", asof_ns=ns(8),
                            policy=EventMetricPolicyV1(min_iv_samples=2))
    assert result.pre is not None
    for invalid in (Decimal("1E+1000000"), Decimal("NaN"), 1.25):
        with pytest.raises(ValueError):
            replace(result, expected_abs_move_relative=invalid)
        with pytest.raises(ValueError):
            replace(result.pre, iv_rank=invalid)


def test_two_snapshot_quote_conflicts_return_result_without_mutable_reason_state() -> None:
    conflicting_iv = replace(market("iv30d", 6, ".4"), native_id="iv-second")
    conflicting_close = replace(market("adjusted_close", 6, "99"),
                                native_id="close-second")
    items = (*evidence(), conflicting_iv, conflicting_close)
    result = evaluate_event(
        revisions=(event(),), evidence=items, sessions=sessions(),
        tzdata={"UTC": UTC}, requested_tz="UTC", asof_ns=ns(8),
        policy=EventMetricPolicyV1(min_iv_samples=2),
    )
    assert result.pre is not None
    assert result.pre.reasons == ("QUOTE_CONFLICT", "QUOTE_CONFLICT")
    assert result.reasons.count("QUOTE_CONFLICT") == 1
    assert result.expected_abs_move_relative is not None
    assert result.realized_abs_log_move is None


def test_front_week_straddle_uses_earliest_expiry_before_quote_tiebreak() -> None:
    later = replace(
        market("straddle", 6, "10"), native_id="later-expiry",
        option_expiry_ns=ns(8, 20), call_bid=Decimal(4), call_ask=Decimal(6),
        put_bid=Decimal(4), put_ask=Decimal(6),
    )
    calendar = (*sessions(), ExchangeSessionV1(date(2026, 1, 8), ns(8, 14), ns(8, 20)))
    result = evaluate_event(
        revisions=(event(),), evidence=(*evidence(), later), sessions=calendar,
        tzdata={"UTC": UTC}, requested_tz="UTC", asof_ns=ns(9),
        policy=EventMetricPolicyV1(min_iv_samples=2),
    )
    assert result.expected_abs_move_currency == Decimal(5)
    assert result.expected_window == ExpectedMoveWindowV1(date(2026, 1, 6),
                                                           date(2026, 1, 7))
