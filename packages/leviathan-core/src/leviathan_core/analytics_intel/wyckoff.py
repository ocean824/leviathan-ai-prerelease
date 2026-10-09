"""Session-aware, evidence-linked Wyckoff labels from finalized bars."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass
from decimal import Decimal, localcontext
from fractions import Fraction
from itertools import pairwise
from typing import Literal

from .read_model import (
    POLICY_VERSION,
    AnalyticsError,
    AnalyticsTileV1,
    CalendarPort,
    FrozenValue,
    PolicyV1,
    checked_decimal,
    checked_int,
    checked_text,
    decimal_context,
    decimal_string,
    require_policy,
)


@dataclass(frozen=True, slots=True)
class WyckoffPolicyV1(FrozenValue):
    policy_version: str
    volume_window: int
    atr_window: int
    climax_volume_multiple: Decimal
    climax_range_atr_multiple: Decimal
    false_break_atr_multiple: Decimal
    false_break_return_bars: int
    strength_volume_multiple: Decimal
    secondary_test_atr_multiple: Decimal
    phase_c_hold_bars: int
    phase_e_break_bars: int
    ar_pivot_bars: int
    ar_max_bars: int

    def __post_init__(self) -> None:
        if self.policy_version != POLICY_VERSION:
            raise AnalyticsError("UNSUPPORTED_POLICY")
        expected_ints = {
            "volume_window": 20,
            "atr_window": 14,
            "false_break_return_bars": 3,
            "phase_c_hold_bars": 3,
            "phase_e_break_bars": 3,
            "ar_pivot_bars": 2,
            "ar_max_bars": 20,
        }
        expected_decimals = {
            "climax_volume_multiple": Decimal("2"),
            "climax_range_atr_multiple": Decimal("1.5"),
            "false_break_atr_multiple": Decimal("0.5"),
            "strength_volume_multiple": Decimal("1.5"),
            "secondary_test_atr_multiple": Decimal("0.5"),
        }
        if any(
            type(getattr(self, name)) is not int or getattr(self, name) != expected
            for name, expected in expected_ints.items()
        ):
            raise AnalyticsError("POLICY_OUT_OF_BOUNDS")
        if any(
            checked_decimal(getattr(self, name)) != expected
            for name, expected in expected_decimals.items()
        ):
            raise AnalyticsError("POLICY_OUT_OF_BOUNDS")


@dataclass(frozen=True, slots=True)
class WyckoffEvidenceV1(FrozenValue):
    evidence_id: str
    instrument_id: str
    venue: str
    event_ns: int
    availability_ns: int
    finalized: bool
    session: str
    calendar_version: str
    timeframe: str
    source_version: str
    adjustment_version: str
    dataset_version: str
    revision: str
    corrects_id: str | None
    quality: str
    high: Decimal
    low: Decimal
    close: Decimal
    volume: Decimal

    def __post_init__(self) -> None:
        for name in (
            "evidence_id",
            "instrument_id",
            "venue",
            "session",
            "calendar_version",
            "timeframe",
            "source_version",
            "adjustment_version",
            "dataset_version",
            "revision",
            "quality",
        ):
            checked_text(getattr(self, name))
        if self.corrects_id is not None:
            checked_text(self.corrects_id)
        checked_int(self.event_ns)
        checked_int(self.availability_ns)
        if self.availability_ns < self.event_ns:
            raise AnalyticsError("INVALID_TIMESTAMP")
        if type(self.finalized) is not bool:
            raise AnalyticsError("INVALID_BOOLEAN")
        for name in ("high", "low", "close", "volume"):
            object.__setattr__(self, name, checked_decimal(getattr(self, name), nonnegative=True))
        if self.high < self.low or not self.low <= self.close <= self.high:
            raise AnalyticsError("INVALID_BAR")


@dataclass(frozen=True, slots=True)
class WyckoffLabelV1(FrozenValue):
    label: str
    phase: Literal["A", "B", "C", "D", "E"] | None
    confidence: Decimal
    status: str
    event_ns: int
    asof_ns: int
    evidence_ids: tuple[str, ...]
    event_markers: tuple[str, ...]
    conflicts: tuple[str, ...]
    revision: str
    tombstone_of: str | None
    policy_version: str
    tile: AnalyticsTileV1

    def __post_init__(self) -> None:
        if not isinstance(self.tile, AnalyticsTileV1):
            raise AnalyticsError("INVALID_RESULT")
        if self.phase not in (None, "A", "B", "C", "D", "E"):
            raise AnalyticsError("INVALID_RESULT")
        checked_text(self.revision)
        if self.tombstone_of is not None:
            checked_text(self.tombstone_of)
        if self.label not in (
            "ACCUMULATION",
            "DISTRIBUTION",
            "SPRING",
            "UPTHRUST",
            "SOS",
            "SOW",
            "UNDETERMINED",
        ):
            raise AnalyticsError("INVALID_RESULT")
        if self.status not in ("READY", "INSUFFICIENT_DATA", "UNDETERMINED"):
            raise AnalyticsError("INVALID_RESULT")
        if self.tile.kind != "wyckoff":
            raise AnalyticsError("INVALID_RESULT")
        if self.status == "READY" and (self.label == "UNDETERMINED" or self.phase is None):
            raise AnalyticsError("INVALID_RESULT")
        if self.status != "READY" and self.label != "UNDETERMINED":
            raise AnalyticsError("INVALID_RESULT")
        if any(
            type(getattr(self, name)) is not tuple
            for name in ("evidence_ids", "event_markers", "conflicts")
        ):
            raise AnalyticsError("INVALID_RESULT")
        for value in (*self.evidence_ids, *self.event_markers, *self.conflicts):
            checked_text(value)
        checked_int(self.event_ns)
        checked_int(self.asof_ns)
        if self.event_ns > self.asof_ns:
            raise AnalyticsError("INVALID_RESULT")
        checked_decimal(self.confidence, nonnegative=True)
        if self.confidence > 1 or self.policy_version != POLICY_VERSION:
            raise AnalyticsError("INVALID_RESULT")


def _atr(bars: list[WyckoffEvidenceV1], window: int) -> list[Fraction | None]:
    results: list[Fraction | None] = []
    true_ranges: list[Fraction] = []
    previous: WyckoffEvidenceV1 | None = None
    current: Fraction | None = None
    for bar in bars:
        tr = Fraction(bar.high) - Fraction(bar.low)
        if previous is not None:
            tr = max(
                tr,
                abs(Fraction(bar.high) - Fraction(previous.close)),
                abs(Fraction(bar.low) - Fraction(previous.close)),
            )
        true_ranges.append(tr)
        if len(true_ranges) == window:
            current = sum(true_ranges, Fraction(0)) / window
        elif len(true_ranges) > window and current is not None:
            current = (current * (window - 1) + tr) / window
        results.append(current)
        previous = bar
    return results


def evaluate_wyckoff(
    bars: Iterable[WyckoffEvidenceV1],
    asof_ns: int,
    policy: PolicyV1,
    calendar: CalendarPort,
) -> WyckoffLabelV1:
    """Return the latest confirmed label; never backdate pending events."""
    domain = require_policy(policy, "wyckoff", WyckoffPolicyV1)
    assert isinstance(domain, WyckoffPolicyV1)
    checked_int(asof_ns)
    visible_revisions: dict[int, list[WyckoffEvidenceV1]] = {}
    known_slots: set[int] = set()
    for bar in bars:
        if not isinstance(bar, WyckoffEvidenceV1):
            raise AnalyticsError("INVALID_BAR")
        if bar.event_ns > asof_ns or bar.availability_ns > asof_ns:
            continue
        # Only as-of-known evidence can establish a bar slot or its cadence.
        known_slots.add(bar.event_ns)
        if not bar.finalized:
            continue
        visible_revisions.setdefault(bar.event_ns, []).append(bar)
    visible: dict[int, WyckoffEvidenceV1] = {}
    for event_ns, revisions in visible_revisions.items():
        revisions.sort(key=lambda item: (item.availability_ns, item.revision))
        prior: WyckoffEvidenceV1 | None = None
        for bar in revisions:
            if prior is not None and (
                bar.availability_ns,
                bar.revision,
            ) == (prior.availability_ns, prior.revision):
                if bar != prior:
                    raise AnalyticsError("HISTORY_CONFLICT")
                continue
            if (prior is None and bar.corrects_id is not None) or (
                prior is not None and bar.corrects_id != prior.evidence_id
            ):
                raise AnalyticsError("UNLINKED_CORRECTION")
            prior = bar
        assert prior is not None
        visible[event_ns] = prior
    slot_times = sorted(known_slots)
    cadence = min((later - earlier for earlier, later in pairwise(slot_times)), default=0)
    ordered: list[WyckoffEvidenceV1] = []
    for position, event_ns in enumerate(slot_times):
        if position and cadence and event_ns - slot_times[position - 1] > cadence:
            previous_session = calendar.session_for_ns(slot_times[position - 1])
            if calendar.session_for_ns(event_ns) == previous_session:
                break
        slot_bar = visible.get(event_ns)
        if slot_bar is None:
            break
        ordered.append(slot_bar)
    if not ordered:
        raise AnalyticsError("INSUFFICIENT_DATA")
    first = ordered[0]
    for bar in ordered:
        if (
            bar.instrument_id != first.instrument_id
            or bar.venue != first.venue
            or bar.timeframe != first.timeframe
            or bar.calendar_version != first.calendar_version
        ):
            raise AnalyticsError("SCOPE_MISMATCH")
        if calendar.session_for_ns(bar.event_ns) != bar.session:
            raise AnalyticsError("CALENDAR_MISMATCH")
    atr_values = _atr(ordered, domain.atr_window)
    phase: Literal["A", "B", "C", "D", "E"] | None = None
    direction: Literal["ACCUMULATION", "DISTRIBUTION"] | None = None
    label = "UNDETERMINED"
    status = "INSUFFICIENT_DATA"
    conflicts: list[str] = []
    markers: list[str] = []
    linked: list[str] = []
    climax: WyckoffEvidenceV1 | None = None
    ar: WyckoffEvidenceV1 | None = None
    range_low: Decimal | None = None
    range_high: Decimal | None = None
    pending_break: tuple[int, str] | None = None
    inside_hold = 0
    beyond_count = 0
    st_seen = False
    spring_seen = False
    strength_seen = False
    lps_seen = False
    hold_confirmed = False
    climax_index: int | None = None
    last_event_ns = first.event_ns
    for i, bar in enumerate(ordered):
        atr = atr_values[i]
        if i < domain.volume_window or atr is None:
            continue
        volume_average = (
            sum(
                (Fraction(item.volume) for item in ordered[i - domain.volume_window : i]),
                Fraction(0),
            )
            / domain.volume_window
        )
        extremes = ordered[i - domain.volume_window + 1 : i + 1]
        is_sc = (
            volume_average > 0
            and Fraction(bar.volume) >= Fraction(domain.climax_volume_multiple) * volume_average
            and Fraction(bar.high) - Fraction(bar.low)
            >= Fraction(domain.climax_range_atr_multiple) * atr
            and bar.low <= min(item.low for item in extremes)
        )
        is_bc = (
            volume_average > 0
            and Fraction(bar.volume) >= Fraction(domain.climax_volume_multiple) * volume_average
            and Fraction(bar.high) - Fraction(bar.low)
            >= Fraction(domain.climax_range_atr_multiple) * atr
            and bar.high >= max(item.high for item in extremes)
        )
        if climax is not None and ar is None and climax_index is not None and i > climax_index:
            superseded = (
                bar.low < climax.low if direction == "ACCUMULATION" else bar.high > climax.high
            )
            if superseded:
                conflicts = ["CLIMAX_SUPERSEDED"]
                status = "UNDETERMINED"
                label = "UNDETERMINED"
                phase = None
                last_event_ns = bar.event_ns
                break
        if is_sc and is_bc:
            conflicts = ["SC", "BC"]
            status = "UNDETERMINED"
            label = "UNDETERMINED"
            phase = None
            last_event_ns = bar.event_ns
            continue
        if is_sc or is_bc:
            climax = bar
            climax_index = i
            ar = None
            direction = "ACCUMULATION" if is_sc else "DISTRIBUTION"
            phase = "A"
            label = direction
            status = "READY"
            markers = ["SC" if is_sc else "BC"]
            linked = [bar.evidence_id]
            range_low = range_high = None
            pending_break = None
            inside_hold = beyond_count = 0
            st_seen = spring_seen = strength_seen = lps_seen = False
            hold_confirmed = False
            last_event_ns = bar.event_ns
            continue
        if climax is None or direction is None:
            continue
        if ar is None:
            assert climax_index is not None
            candidate_index = i - domain.ar_pivot_bars
            if climax_index < candidate_index <= climax_index + domain.ar_max_bars:
                candidate = ordered[candidate_index]
                neighbor_indexes = (
                    candidate_index - 2,
                    candidate_index - 1,
                    candidate_index + 1,
                    candidate_index + 2,
                )
                neighbors = [ordered[j] for j in neighbor_indexes if j >= climax_index]
                pivot = (
                    all(candidate.high > neighbor.high for neighbor in neighbors)
                    if direction == "ACCUMULATION"
                    else all(candidate.low < neighbor.low for neighbor in neighbors)
                )
            else:
                candidate = None
                pivot = False
            if pivot and candidate is not None:
                ar = candidate
                phase = "A"
                range_low = climax.low if direction == "ACCUMULATION" else ar.low
                range_high = ar.high if direction == "ACCUMULATION" else climax.high
                markers.append("AR")
                linked.extend((ar.evidence_id, bar.evidence_id))
                conflicts.clear()
                status = "READY"
                label = direction
                last_event_ns = bar.event_ns
            elif i >= climax_index + domain.ar_max_bars + domain.ar_pivot_bars:
                conflicts = ["AR_NOT_FOUND"]
                status = "UNDETERMINED"
                label = "UNDETERMINED"
                phase = None
                last_event_ns = bar.event_ns
                break
            else:
                conflicts = ["AR_UNCONFIRMED"]
                status = "UNDETERMINED"
                label = "UNDETERMINED"
                phase = None
                last_event_ns = bar.event_ns
            continue
        assert range_low is not None and range_high is not None
        if not st_seen:
            retest = (
                abs(Fraction(bar.low) - Fraction(climax.low))
                <= Fraction(domain.secondary_test_atr_multiple) * atr
                if direction == "ACCUMULATION"
                else abs(Fraction(bar.high) - Fraction(climax.high))
                <= Fraction(domain.secondary_test_atr_multiple) * atr
            )
            if retest and bar.volume < climax.volume:
                st_seen = True
                phase = "B"
                markers.append("ST")
                linked.append(bar.evidence_id)
                last_event_ns = bar.event_ns
            continue
        if phase == "B":
            false_break = (
                bar.low < range_low
                and Fraction(range_low) - Fraction(bar.low)
                <= Fraction(domain.false_break_atr_multiple) * atr
                if direction == "ACCUMULATION"
                else bar.high > range_high
                and Fraction(bar.high) - Fraction(range_high)
                <= Fraction(domain.false_break_atr_multiple) * atr
            )
            if false_break:
                pending_break = (i, bar.evidence_id)
            if pending_break is not None:
                break_index, break_id = pending_break
                if i - break_index > domain.false_break_return_bars:
                    pending_break = None
                elif range_low <= bar.close <= range_high:
                    phase = "C"
                    spring_seen = True
                    label = "SPRING" if direction == "ACCUMULATION" else "UPTHRUST"
                    markers.append(label)
                    linked.extend((break_id, bar.evidence_id))
                    last_event_ns = bar.event_ns
                    inside_hold = 1
                    hold_confirmed = False
                    pending_break = None
            continue
        if phase == "C":
            if range_low <= bar.close <= range_high:
                inside_hold += 1
            else:
                inside_hold = 0
            if inside_hold >= domain.phase_c_hold_bars and not hold_confirmed:
                hold_confirmed = True
                markers.append("C_HOLD")
                linked.append(bar.evidence_id)
                last_event_ns = bar.event_ns
            strong = (
                bar.close > range_high if direction == "ACCUMULATION" else bar.close < range_low
            )
            if (
                hold_confirmed
                and strong
                and Fraction(bar.volume)
                >= Fraction(domain.strength_volume_multiple) * volume_average
            ):
                phase = "D"
                strength_seen = True
                label = "SOS" if direction == "ACCUMULATION" else "SOW"
                markers.append(label)
                linked.append(bar.evidence_id)
                last_event_ns = bar.event_ns
            continue
        if phase in ("D", "E"):
            outside = (
                bar.close > range_high if direction == "ACCUMULATION" else bar.close < range_low
            )
            if phase == "D":
                # A pullback that stays on the breakout side is LPS/LPSY.
                if (
                    not lps_seen
                    and outside
                    and (
                        bar.low < ordered[i - 1].low
                        if direction == "ACCUMULATION"
                        else bar.high > ordered[i - 1].high
                    )
                ):
                    lps_seen = True
                    markers.append("LPS" if direction == "ACCUMULATION" else "LPSY")
                    linked.append(bar.evidence_id)
                    last_event_ns = bar.event_ns
                    beyond_count = 0
                    continue
                if lps_seen:
                    beyond_count = beyond_count + 1 if outside else 0
                if beyond_count >= domain.phase_e_break_bars:
                    phase = "E"
                    label = direction
                    markers.append("E_CONFIRM")
                    linked.append(bar.evidence_id)
                    last_event_ns = bar.event_ns
    definitions = {"A": 3, "B": 2, "C": 2, "D": 2, "E": 3}
    observed = {
        "A": int(climax is not None) + int(ar is not None) + int(st_seen),
        "B": int(ar is not None and st_seen) + int(spring_seen),
        "C": int(spring_seen) + int(hold_confirmed),
        "D": int(strength_seen) + int(lps_seen),
        "E": min(beyond_count, 3),
    }
    with localcontext(decimal_context()):
        confidence = Decimal(observed[phase]) / Decimal(definitions[phase]) if phase else Decimal(0)
    if status == "UNDETERMINED":
        confidence = Decimal(0)
    elif phase is None:
        conflicts.append("INSUFFICIENT_DATA")
    latest = ordered[-1]
    corrected = next((bar.corrects_id for bar in reversed(ordered) if bar.corrects_id), None)
    revision_input = [
        (
            bar.evidence_id,
            bar.event_ns,
            bar.availability_ns,
            bar.revision,
            bar.corrects_id,
            decimal_string(bar.high),
            decimal_string(bar.low),
            decimal_string(bar.close),
            decimal_string(bar.volume),
        )
        for bar in ordered
    ]
    revision = hashlib.sha256(
        json.dumps(revision_input, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()
    event_index = max(i for i, bar in enumerate(ordered) if bar.event_ns <= last_event_ns)
    volume_window_ids = tuple(
        bar.evidence_id for bar in ordered[max(0, event_index - domain.volume_window) : event_index]
    )
    atr_window_ids = tuple(
        bar.evidence_id
        for bar in ordered[max(0, event_index - domain.atr_window + 1) : event_index + 1]
    )
    linked_ids = tuple(dict.fromkeys(linked))
    source_versions = tuple(sorted({bar.source_version for bar in ordered}))
    dataset_versions = tuple(sorted({bar.dataset_version for bar in ordered}))
    tile = AnalyticsTileV1(
        kind="wyckoff",
        instrument_id=latest.instrument_id,
        venue=latest.venue,
        session=calendar.session_for_ns(last_event_ns) or latest.session,
        event_ns=str(last_event_ns),
        asof_ns=str(asof_ns),
        availability_ns=str(
            max(bar.availability_ns for bar in ordered if bar.event_ns <= last_event_ns)
        ),
        source_version=source_versions[0] if len(source_versions) == 1 else "MIXED",
        dataset_version=dataset_versions[0] if len(dataset_versions) == 1 else "MIXED",
        method_version="wyckoff-v1",
        parameter_version=policy.policy_version,
        calendar_version=latest.calendar_version,
        policy_version=policy.policy_version,
        entitlement="UNVERIFIED",
        quality=status,
        lag_ns=str(asof_ns - last_event_ns),
        stale=True,
        missing_reason=status if status != "READY" else None,
        units="phase",
        sample_count=len(linked_ids),
        confidence=confidence,
        payload={
            "label": label,
            "phase": phase,
            "timeframe": latest.timeframe,
            "evidence_ids": linked_ids,
            "volume_window_ids": volume_window_ids,
            "atr_window_ids": atr_window_ids,
            "source_versions": source_versions,
            "dataset_versions": dataset_versions,
            "event_markers": markers,
            "conflicts": conflicts,
            "revision": revision,
            "tombstone_of": corrected,
            "stale_state": "UNASSESSED",
        },
    )
    return WyckoffLabelV1(
        label=label,
        phase=phase,
        confidence=confidence,
        status=status,
        event_ns=last_event_ns,
        asof_ns=asof_ns,
        evidence_ids=linked_ids,
        event_markers=tuple(markers),
        conflicts=tuple(conflicts),
        revision=revision,
        tombstone_of=corrected,
        policy_version=policy.policy_version,
        tile=tile,
    )
