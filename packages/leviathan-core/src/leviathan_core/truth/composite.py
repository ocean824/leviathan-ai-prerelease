"""CompositeTruthProvider — multi-source evidence synthesis.

Synthesis rules (in priority order):
─────────────────────────────────────────────────────────────────────────────
1. ORDER-FLOW CONTRADICTION → REJECTED
   If an order-flow source is present AND its orderbook_bias contradicts the
   setup direction (bearish bias while setup signal_features contain any
   "msb_up" / "breakout" / "buy" keyword, or bullish bias while features
   contain "msb_down" / "sell"), the result is REJECTED.
   Order-book truth outranks all other evidence.

2. EVENT LOCKOUT → REJECTED (event_risk propagated)
   If an event source is present and returns NO_TRADE, the result is REJECTED
   regardless of other signals. The event_risk field in the result reflects
   this.

3. MISSING ORDER-FLOW → at most MIXED
   If no order-flow source is provided (or the source returns None), the
   best possible status is MIXED, no matter how aligned the remaining
   sources are.

4. ALL SOURCES PRESENT AND ALIGNED → CONFIRMED
   All four sources present, order-flow bias aligns with setup direction,
   no event lockout, options sweep does not contradict: CONFIRMED.

5. PARTIAL ALIGNMENT → MIXED
   Any combination not covered by rules 1-4 above resolves to MIXED.

Sentiment handling:
   - If a sentiment source is absent or returns None, sentiment_modifier is
     set to 0.0 (neutral).
   - Sentiment never promotes status — it is a bounded modifier only.

Options handling:
   - A detected bearish sweep prevents CONFIRMED if setup is directionally
     bullish (msb_up / breakout features present). Status degrades to MIXED.
   - An absent options source alone does not block CONFIRMED (order-flow is
     the harder signal), but it contributes to MIXED when combined with
     other gaps.
─────────────────────────────────────────────────────────────────────────────
"""

from leviathan_core.schemas import CandidateSetup, TruthValidationResult
from leviathan_core.schemas.enums import EventRisk, OrderbookBias, TruthStatus
from leviathan_core.truth.evidence import (
    EventSource,
    OptionsSource,
    OrderFlowSource,
    SentimentSource,
)

# Keywords in signal_features that indicate a bullish setup direction.
_BULLISH_KEYWORDS: frozenset[str] = frozenset(
    {"msb_up", "breakout", "breakout_up", "buy", "long", "opening_range_break"}
)
# Keywords in signal_features that indicate a bearish setup direction.
_BEARISH_KEYWORDS: frozenset[str] = frozenset(
    {"msb_down", "breakout_down", "sell", "short", "breakdown"}
)


def _setup_is_bullish(setup: CandidateSetup) -> bool:
    features = {f.lower() for f in setup.signal_features}
    return bool(features & _BULLISH_KEYWORDS)


def _setup_is_bearish(setup: CandidateSetup) -> bool:
    features = {f.lower() for f in setup.signal_features}
    return bool(features & _BEARISH_KEYWORDS)


class CompositeTruthProvider:
    """Synthesises evidence from up to four domain sources.

    All source arguments are optional so the provider works without live
    API keys — missing sources degrade the result per the doctrine above.
    """

    def __init__(
        self,
        order_flow_source: OrderFlowSource | None = None,
        options_source: OptionsSource | None = None,
        event_source: EventSource | None = None,
        sentiment_source: SentimentSource | None = None,
    ) -> None:
        self._order_flow = order_flow_source
        self._options = options_source
        self._event = event_source
        self._sentiment = sentiment_source

    def validate(self, setup: CandidateSetup) -> TruthValidationResult:
        """Synthesise all available evidence into a TruthValidationResult."""
        notes_parts: list[str] = []

        # --- Collect raw evidence ------------------------------------------
        order_flow_ev = self._order_flow.get_order_flow() if self._order_flow is not None else None
        options_ev = self._options.get_options() if self._options is not None else None
        event_ev = self._event.get_event_risk() if self._event is not None else None
        sentiment_ev = (
            self._sentiment.get_sentiment() if self._sentiment is not None else None
        )

        # --- Extract scalar values -----------------------------------------
        orderbook_bias = (
            order_flow_ev.orderbook_bias if order_flow_ev is not None else OrderbookBias.NEUTRAL
        )
        options_context = options_ev.context if options_ev is not None else "No options data."
        event_risk = event_ev.event_risk if event_ev is not None else EventRisk.SAFE
        sentiment_modifier = sentiment_ev.modifier if sentiment_ev is not None else 0.0

        if order_flow_ev is not None:
            notes_parts.append(f"order_flow={order_flow_ev.notes}")
        if options_ev is not None:
            sweep_label = (
                "bearish_sweep_detected" if options_ev.bearish_sweep_detected else "no_sweep"
            )
            notes_parts.append(f"options={sweep_label}")
        if event_ev is None:
            notes_parts.append("event_source=unavailable(assumed_safe)")
        if sentiment_ev is None:
            notes_parts.append("sentiment_source=unavailable(modifier=0.0)")

        # --- Synthesis rules (priority order) ---------------------------------

        # Rule 1: Event lockout → REJECTED
        if event_risk is EventRisk.NO_TRADE:
            notes_parts.append("REJECTED: event lockout (NO_TRADE)")
            return TruthValidationResult(
                setup_id=setup.setup_id,
                orderbook_bias=orderbook_bias,
                options_context=options_context,
                event_risk=event_risk,
                sentiment_modifier=sentiment_modifier,
                truth_status=TruthStatus.REJECTED,
                notes="; ".join(notes_parts),
            )

        # Rule 2: Order-flow contradiction → REJECTED
        if order_flow_ev is not None:
            bullish_setup = _setup_is_bullish(setup)
            bearish_setup = _setup_is_bearish(setup)
            contradiction = (
                bullish_setup and orderbook_bias is OrderbookBias.BEARISH
            ) or (
                bearish_setup and orderbook_bias is OrderbookBias.BULLISH
            )
            if contradiction:
                notes_parts.append(
                    f"REJECTED: order-flow contradiction "
                    f"(bias={orderbook_bias}, setup_features={list(setup.signal_features)})"
                )
                return TruthValidationResult(
                    setup_id=setup.setup_id,
                    orderbook_bias=orderbook_bias,
                    options_context=options_context,
                    event_risk=event_risk,
                    sentiment_modifier=sentiment_modifier,
                    truth_status=TruthStatus.REJECTED,
                    notes="; ".join(notes_parts),
                )

        # Rule 3: Missing order-flow → at most MIXED
        if order_flow_ev is None:
            notes_parts.append("MIXED: order-flow source absent")
            return TruthValidationResult(
                setup_id=setup.setup_id,
                orderbook_bias=orderbook_bias,
                options_context=options_context,
                event_risk=event_risk,
                sentiment_modifier=sentiment_modifier,
                truth_status=TruthStatus.MIXED,
                notes="; ".join(notes_parts),
            )

        # From here order-flow is present and aligned (no contradiction).

        # Rule 4: Options bearish sweep on a bullish setup → MIXED
        if (
            options_ev is not None
            and options_ev.bearish_sweep_detected
            and _setup_is_bullish(setup)
        ):
            notes_parts.append("MIXED: bearish options sweep detected on bullish setup")
            return TruthValidationResult(
                setup_id=setup.setup_id,
                orderbook_bias=orderbook_bias,
                options_context=options_context,
                event_risk=event_risk,
                sentiment_modifier=sentiment_modifier,
                truth_status=TruthStatus.MIXED,
                notes="; ".join(notes_parts),
            )

        # Rule 5: All sources present and aligned → CONFIRMED
        # (order-flow present and aligned, no event lockout, no bearish sweep)
        all_sources_present = (
            order_flow_ev is not None
            and options_ev is not None
            and event_ev is not None
            and sentiment_ev is not None
        )
        if all_sources_present:
            notes_parts.append("CONFIRMED: all sources present and aligned")
            return TruthValidationResult(
                setup_id=setup.setup_id,
                orderbook_bias=orderbook_bias,
                options_context=options_context,
                event_risk=event_risk,
                sentiment_modifier=sentiment_modifier,
                truth_status=TruthStatus.CONFIRMED,
                notes="; ".join(notes_parts),
            )

        # Rule 6: Partial alignment → MIXED
        notes_parts.append("MIXED: partial source coverage")
        return TruthValidationResult(
            setup_id=setup.setup_id,
            orderbook_bias=orderbook_bias,
            options_context=options_context,
            event_risk=event_risk,
            sentiment_modifier=sentiment_modifier,
            truth_status=TruthStatus.MIXED,
            notes="; ".join(notes_parts),
        )
