# LEVIATHAN AI — GitHub Architecture Digest

**Generated:** 2026-07-05
**Source repository:** https://github.com/ocean824/LEVIATHAN-AI-BLACKWEALTHCAPITAL
**Scope:** All architecture documents in `_reference-github/` except README.md, CODESPRING-MASTER-INSTRUCTIONS.md, CODESPRING-INTEGRATION-MANIFEST.md, docs/implementation-module-map.md, and docs/oracle-schema-contracts-and-example-payloads.md (covered elsewhere).

---

## 1. Implementation Priorities

### Priority Tiers (from additive-implementation-priorities.md)

| Tier | Objective | Rationale |
|------|-----------|-----------|
| **P0** | Freeze core trading schemas in code | Prevent logic drift between research, decision, risk, and execution layers |
| **P1** | Build one replayable paper-trading vertical slice | Prove the 14-step flow without live capital |
| **P2** | Add drift detection and review tooling | Make learning measurable rather than rhetorical |
| **P3** | Expand data sources and broker integrations | Only after the core loop is auditable |

### Governing Principle

No shortcut may jump from idea generation into broker execution. The system must follow: **Research → Backtest → Iterate → Implement** in strict sequential progression. No execution component may derive its own trading thesis — it may only act on a validated `ExecutionIntent` that has survived Truth, Decision, and Risk governance.

### P0: Seven Core Schemas

| Schema | Minimum Required Fields |
|--------|------------------------|
| **StrategyGenome** | `strategy_id`, `family`, `market`, `timeframe`, `session_dependencies`, `state_dependencies`, `entry_conditions`, `exit_conditions`, `risk_profile`, `failure_modes`, `prop_firm_compatible` |
| **CandidateSetup** | `setup_id`, `instrument`, `timestamp`, `signal_features`, `session_label`, `range_label`, `state_label`, `liquidity_features` |
| **TruthValidationResult** | `setup_id`, `orderbook_bias`, `options_context`, `event_risk`, `sentiment_modifier`, `truth_status`, `notes` |
| **DecisionPacket** | `decision_id`, `setup_id`, `permission`, `direction`, `confidence`, `entry_style`, `scaling_allowed`, `justification` |
| **RiskSnapshot** | `session_id`, `max_daily_drawdown`, `max_position_size`, `allowed_instruments`, `prop_firm_rules`, `frozen_at` |
| **ExecutionIntent** | `decision_id`, `broker_path`, `order_type`, `size`, `stop_loss`, `take_profit`, `time_in_force` |
| **TradeJournalRecord** | `trade_id`, `setup_id`, `decision_id`, `entry`, `exit`, `mae`, `mfe`, `outcome`, `post_trade_notes` |

### P1: The Paper-Trade Vertical Slice (7 Layer-1 Functions)

The first working ORACLE layer is a **paper-trading decision pipeline** — these seven functions constitute the minimum meaningful flow:

1. `ingest_candidate_setup()` — Accept the initial signal payload
2. `enrich_market_context()` — Add session, range, and state labels
3. `validate_truth()` — Perform bounded truth checks (state label drives truth_status: "expansion"/"breakout" → "confirmed", else "mixed")
4. `decide_permission()` — Produce a typed DecisionPacket (event_risk=="no_trade" or truth_status=="rejected" → permission="reject")
5. `freeze_risk_snapshot()` — Lock runtime risk parameters (max_daily_drawdown=1.5, max_position_size=0.25)
6. `build_execution_intent()` — Prepare a non-live execution plan (broker_path="paper_sim", size=min(0.10, risk.max_position_size))
7. `journal_trade()` — Record the replayable result with MAE/MFE and outcome

### End-to-End Pipe: `run_oracle_layer_one()`

```
ingest → enrich → truth → decide → [gate: permission=="approve"] → freeze_risk → build_execution → journal
                                           ↓ (if rejected)
                                    return blocked-before-execution payload (no execution object)
```

The key invariant: the same `setup_id` flows through all stages; an `ExecutionIntent` can never appear without a prior approved `DecisionPacket`.

### P2: Replay and Drift Tooling (Five Surfaces)

- **Decision Replay Viewer** — every domain contribution for a past setup
- **Risk Veto Ledger** — why trades were blocked or resized
- **Genome Performance Dashboard** — results by state, session, and instrument
- **Drift Monitor** — flag when live behavior diverges from validated expectations
- **Post-Mortem Template** — structured review for failed executions

### P3: Probabilistic/State Maturity (Four Capabilities)

- State transition matrix (empirical)
- Confidence decomposition (signal vs truth vs execution)
- Regime-conditioned scoring
- Outcome priors by session and state

### Recommended File Structure Additions

```
schemas/     # core Pydantic models
examples/    # end-to-end candidate-setup payloads
replay/      # simulated trade traces
```

---

## 2. Market State Machine

### Eight Canonical States

| State | Meaning | Typical Characteristics |
|-------|---------|------------------------|
| **compression** | Price storing energy with narrowing expansion | Range tightening, declining follow-through, frequent mean reversion |
| **breakout** | Price left a prior balance area with directional intent | Structure break, acceptance beyond range edge, stronger momentum |
| **trend_continuation** | Continuing in an established directional auction | Pullbacks are shallow, directional liquidity persists |
| **expansion** | Volatility and range broadening rapidly | Wide candles, stronger displacement, higher opportunity and failure cost |
| **distribution** | Prior up-move rotating into sell-side transfer | Failed continuation, supply absorption, weaker upside acceptance |
| **accumulation** | Prior down-move rotating into buy-side transfer | Repeated support defense, failed breakdowns, absorption near lows |
| **mean_reversion** | Directional attempts fail, price rotates toward central value | Repeated rejection of extremes, short-lived breakouts |
| **event_locked** | Macro/news/scheduled event dominates normal behavior | Elevated randomness, liquidity discontinuity, suppressed deployment |

The oracle-full-master-writeup adds an extended state vocabulary to the State Domain: `narrow_range`, `broad_range`, `breakout_failure`, `drift`, `exhaustion`, `reversal`, `instability`, `hazard_state`.

### Preferred Transition Matrix

| From | To | Typical Validity | Interpretation |
|------|----|-----------------|----------------|
| compression | breakout | High | Normal release of stored energy |
| breakout | trend_continuation | High | Healthy directional follow-through |
| breakout | mean_reversion | Medium | Failed breakout or incomplete acceptance |
| trend_continuation | expansion | High | Momentum broadening |
| trend_continuation | distribution | Medium | Direction tiring, inventory transfer starting |
| trend_continuation | mean_reversion | Medium | Trend failure or exhaustion |
| distribution | mean_reversion | High | Typical post-distribution rotation |
| accumulation | breakout | High | Strong bullish transition |
| any_state | event_locked | High (around scheduled macro) | Reduce or disable autonomous deployment |
| event_locked | compression | Medium | Post-event digestion, wait for clarity |

### Transition Risk Semantics

| Class | Meaning | Suggested Response |
|-------|---------|-------------------|
| **stable** | State change matches expected auction logic | Allow normal evaluation |
| **caution** | Plausible but requires confirmation | Reduce size or require stronger Truth alignment |
| **unstable** | Suggests incoherence or event distortion | Pause new deployment, wait |

### Concrete Transition → Policy Table

| Transition | Risk Class | Policy Action |
|-----------|-----------|---------------|
| compression → breakout | stable | evaluate_normally |
| breakout → trend_continuation | stable | evaluate_normally |
| breakout → mean_reversion | caution | require_retest_confirmation |
| trend_continuation → mean_reversion | caution | reduce_size_and_confidence |
| any → event_locked | unstable | no_autonomous_trade_approval |
| event_locked → expansion | unstable | wait_for_post_event_normalization |
| any unlisted pair | unstable | manual_review_required |

### Confidence Adjustment Formula

```python
def adjust_decision_confidence(base_confidence: float, transition: StateTransition) -> float:
    if transition.risk_class == "stable":   return base_confidence
    if transition.risk_class == "caution":  return max(0.0, base_confidence - 0.15)
    return max(0.0, base_confidence - 0.35)   # unstable
```

### State Domain Responsibilities (from oracle-full-master-writeup)

The State Domain must determine: current state, confidence in current state, probable next state, transition likelihood, state persistence likelihood, which strategy families are compatible, whether a setup should be handled as scalp/continuation/reversal/abstain, and whether scaling and runner logic are justified.

---

## 3. Risk Veto Policy

### Governance Principle

> The Risk Engine does not create trade ideas. It governs whether a proposed trade may proceed, must shrink, must wait, or must stop.

The Risk Domain is **sovereign**. Nothing may override it.

### Six Core Veto Categories

| Category | Description | Typical Result |
|----------|-------------|----------------|
| **capital_preservation** | Daily or session drawdown protection | Block or halt |
| **rule_compliance** | Prop-firm or platform restrictions | Reject or reshape |
| **exposure_control** | Concentration, correlation, or over-sizing | Reduce size or reject |
| **event_risk** | Macro or calendar uncertainty | Wait or block |
| **market_integrity** | Feed instability, latency, data disagreement | Block |
| **behavioral_degradation** | Loss streaks, revenge behavior proxies, overtrading | Reduce autonomy or halt |

### Full Veto Matrix

| Trigger | Severity | Risk Action | Execution Consequence |
|---------|----------|-------------|----------------------|
| Daily drawdown threshold breached | Critical | `halt_all_trading` | No new execution intents |
| Three consecutive losses in one session | High | `reduce_size` | Cut max size, require stronger confirmation |
| Instrument not allowed under current mandate | High | `reject_instrument` | Decision cannot proceed |
| Major macro event within lockout window | High | `event_lock` | No autonomous approvals |
| Data feed disagreement across truth sources | High | `truth_conflict_hold` | Wait for reconciliation |
| Position size exceeds allowed maximum | Medium | `resize_or_reject` | Reduce size or reject if resizing is invalid |
| Correlated exposure already elevated | Medium | `exposure_throttle` | Cap additional entries |
| Overnight hold not permitted | High | `force_flat_by_session_end` | Auto-close or refuse carry |

### RiskAction Enum

```python
RiskAction = Literal[
    "allow", "reduce_size", "wait", "reject",
    "halt_all_trading", "force_flat_by_session_end",
]
```

### Policy Evaluator Priority Order

1. `daily_drawdown >= max_daily_drawdown` → `halt_all_trading` (critical)
2. `macro_lockout_active` → `wait` (high)
3. `consecutive_losses >= 3` → `reduce_size` to 50% of max_position_size (high)
4. `requested_size > max_position_size` → `reduce_size` to max (medium)
5. Otherwise → `allow`

### Operating Rules

- Risk must evaluate **after Decision** but **before ExecutionIntent** is finalized
- Every veto should be journaled even if no trade occurs (hidden blocked trades still teach the system)
- Critical risk actions should propagate to ØMEGA / PRIME awareness
- Risk may reduce size without rewriting trade logic (preserves role boundaries)
- Repeated veto patterns should feed the research loop

---

### risk_governance.lock.yaml — Complete Key Structure

The immutable lock file (set with `chattr +i` on Linux; `icacls /deny` on Windows; SHA-256 hash stored in `risk_master.hash`):

```yaml
version: 1
schema: leviathan.tiamat.risk.v1
operator_handle: "Operator"
account_currency: "USD"

drawdown:
  max_daily_pct: 3.0                  # % of total equity
  max_weekly_pct: 6.0
  max_trailing_pct: 8.0
  daily_reset_time_utc: "00:00"
  on_breach: "global_halt_until_reset"

heat:
  max_open_pct: 5.0                   # total % portfolio risk across all open positions
  max_per_position_pct: 1.0           # max % risk on a single position

leverage:
  max_gross_notional_x: 5
  max_net_x: 3
  fx_max_x: 10

correlation:
  max_positions_same_sector: 2
  correlation_threshold: 0.7          # absolute Pearson over 30d returns
  on_breach: "block_new_entries"

news_embargo:
  tier_1_events: [CPI, FOMC, NFP, PCE, JoltsJobs, GDP]
  pre_event_minutes: 30
  post_event_minutes: 30
  on_breach: "block_new_entries"      # existing positions still managed by ORCA

loss_streak:
  consecutive_losers: 3
  size_cut_pct: 50
  duration_hours: 24
  recovery_mode: true

instrument_limits:
  default:
    max_position_units: 10
    max_open_positions_per_symbol: 1
  overrides:
    ES:     { max_position_units: 5,  max_open_positions_per_symbol: 1 }
    NQ:     { max_position_units: 3,  max_open_positions_per_symbol: 1 }
    BTCUSD: { max_position_units: 1,  max_open_positions_per_symbol: 1 }
    SPY:    { max_position_units: 50, max_open_positions_per_symbol: 1 }

kill_switches:
  global_halt_file: "hermes_pantheon/risk/HALT.flag"
  on_unexpected_pnl_swing_pct: 2.0   # if P&L moves >2% in <60s, halt
  on_consecutive_broker_errors: 3
  on_omega_kill_signal: true          # honor ØMEGA cross-system kill

audit:
  master_hash_file: "hermes_pantheon/risk/risk_master.hash"
  guardian_daemon_path: "hermes_pantheon/risk/risk_guardian.py"
  log_path: "hermes_pantheon/risk/risk_audit.jsonl"
  verify_before_every_order: true
  verify_interval_seconds: 60

self_evolution:
  triton_can_propose_changes: true
  triton_can_apply_changes: false     # ALWAYS false — requires operator
  proposal_log: "hermes_pantheon/risk/proposals.jsonl"
```

**Top-level keys:** `version`, `schema`, `operator_handle`, `account_currency`, `drawdown`, `heat`, `leverage`, `correlation`, `news_embargo`, `loss_streak`, `instrument_limits`, `kill_switches`, `audit`, `self_evolution`

### Risk Guardian Daemon Design

The guardian (`hermes_pantheon/risk/risk_guardian.py`) is a long-lived Python daemon with two operational paths:

**Per-order path — `verify_and_approve(order, portfolio_state)`:**
1. Check `HALT.flag` exists → raise `TiamatVeto("halt_flag_present")`
2. Recompute SHA-256 of lock file; compare to `risk_master.hash` → mismatch: write HALT.flag, raise `TiamatVeto("tiamat_hash_mismatch")`
3. Load rules from lock file; call `evaluate_rules()` → returns named veto reason or `None`
4. Append every verdict (approve or veto + named reason) to `risk_audit.jsonl` via atomic temp-file-then-rename
5. Return `{"granted": True, ...}` or raise `TiamatVeto(reason)`

**Heartbeat path — `heartbeat_loop(interval=60)`:**
- Every 60 seconds independently recomputes SHA-256
- Any drift → writes HALT.flag + audit entry
- Missing lock file → writes HALT.flag

**`evaluate_rules()` checks in order:** daily/weekly/trailing drawdown, open heat, per-position heat, gross notional leverage, net leverage, sector correlation, news embargo, loss-streak throttle (not a hard veto — returns signal for MEGALODON to downsize), per-instrument unit limits, per-instrument open position count.

**Anti-pattern discipline:** atomic writes on `risk_audit.jsonl`; every veto carries a named string reason (never an aggregated count); no order ever marked "approved" without the audit entry existing on disk first; unexpected vetoes must be replayable from `risk_audit.jsonl` before any rule changes.

---

## 4. Paper-Trade Replay Example

### Scenario Summary

Nasdaq futures (NQ) opening-range breakout — bullish, confirmed by truth layer, passes risk review, completes as paper-trade win.

### End-to-End Payload Sequence

**Stage 1 — CandidateSetup**
```json
{
  "setup_id": "setup_replay_001",
  "instrument": "NQ",
  "timestamp": "2026-04-15T14:35:00Z",
  "signal_features": ["opening_range_break", "msb_up", "ema_alignment", "liquidity_sweep_complete"],
  "session_label": "ny_open",
  "range_label": "above_opening_range_high",
  "state_label": "breakout",
  "liquidity_features": ["equal_highs_swept", "fair_value_gap_below"]
}
```

**Stage 2 — TruthValidationResult**
```json
{
  "setup_id": "setup_replay_001",
  "orderbook_bias": "bullish",
  "options_context": "No bearish block flow contradiction present.",
  "event_risk": "safe",
  "sentiment_modifier": 0.05,
  "truth_status": "confirmed",
  "notes": "Buyers accepted price above the opening range after the sweep and held the retest."
}
```

**Stage 3 — DecisionPacket**
```json
{
  "decision_id": "dec_replay_001",
  "setup_id": "setup_replay_001",
  "permission": "approve",
  "direction": "long",
  "confidence": 0.74,
  "entry_style": "breakout_retest",
  "scaling_allowed": true,
  "justification": "Signal, state, liquidity, and truth layers are aligned."
}
```

**Stage 4 — RiskSnapshot**
```json
{
  "session_id": "session_replay_001",
  "max_daily_drawdown": 1.5,
  "max_position_size": 0.25,
  "allowed_instruments": ["NQ"],
  "prop_firm_rules": ["daily_dd_lock", "loss_streak_throttle", "no_overnight_hold"],
  "frozen_at": "2026-04-15T14:35:01Z"
}
```

**Stage 5 — ExecutionIntent**
```json
{
  "decision_id": "dec_replay_001",
  "broker_path": "paper_sim",
  "order_type": "limit",
  "size": 0.1,
  "stop_loss": 18240.0,
  "take_profit": 18270.0,
  "time_in_force": "DAY"
}
```

**Stage 6 — TradeJournalRecord**
```json
{
  "trade_id": "trade_replay_001",
  "setup_id": "setup_replay_001",
  "decision_id": "dec_replay_001",
  "entry": 18250.0,
  "exit": 18268.0,
  "mae": -3.0,
  "mfe": 18.0,
  "outcome": "win",
  "post_trade_notes": "Replay confirms a consistent object lineage from ingress to journal."
}
```

### Replay Pipeline Function Shape

```
replay_candidate_setup()  →  dict
replay_truth_validation(setup)  →  dict
replay_decision(setup, truth)  →  dict   # permission="approve" if truth_status=="confirmed"
replay_risk()  →  dict
replay_execution(decision, risk)  →  dict   # raises if permission != "approve"
replay_journal(setup, decision)  →  dict
```

Entry function: `run_oracle_paper_replay()` returns a single dict with all six stage outputs.

### What a Replay Fixture Must Contain

| Requirement | Meaning |
|-------------|---------|
| **Object continuity** | Same `setup_id` and `decision_id` flow through the entire replay |
| **Risk discipline** | No `ExecutionIntent` appears without prior `DecisionPacket` approval and `RiskSnapshot` |
| **Journal completeness** | Pipeline always ends with a `TradeJournalRecord` OR a blocked-trade record |
| **Replay determinism** | Same fixture → same result every time |

### Blocked-Before-Execution Path

If `decide_permission()` returns `permission != "approve"`, the replay returns:
```json
{"setup": {...}, "truth": {...}, "decision": {...}, "status": "blocked_before_execution"}
```
No `RiskSnapshot`, `ExecutionIntent`, or `TradeJournalRecord` is produced — but the blocked event must still be recorded in the veto ledger.

---

## 5. Hermes Pantheon Agents

The Pantheon is a 14-agent additive expansion module on top of the 12-domain LEVIATHAN architecture. Three new institutional capabilities: (1) Council of Specialized Methodology Subagents, (2) Self-Evolving Knowledge Core via Nous Research `hermes-agent`, and (3) Immutable Sovereign Risk Protocol. All consensus ideas must pass through RBI before MEGALODON may route capital.

### Agent Roster

---

**POSEIDON AI — Apex Orchestrator / User Interface**
The user's sole interlocutor. Carries the Claude/ØMEGA mythos logic, commands the entire Pantheon, translates user intent into structured JSON directives for subordinate agents, synthesizes all consensus outputs into final plain-language reports, and maintains the institutional-mythological tone. Inputs: user directives, agent telemetry, analytical artifacts, system alerts. Outputs: user responses, final reports (Markdown/PDF), agent directives, orchestration logs.
Escalation: Reports only to the user. Forbidden from executing trades or moving capital (hard firewall). Failure mode: if subordinate agents cannot be reconciled, POSEIDON halts and presents the conflict to the user rather than forcing a false consensus.

---

**LEVIATHAN AI — Portfolio & Alpha**
Multi-asset portfolio optimization and capital allocation brain. Applies fractional Kelly Criterion sizing, copula-based correlation hedging, and alpha-decay monitoring. Aggregates weighted Council signals into a single capital allocation directive. Inputs: Council signals, market data feeds, risk metrics, macro indicators, execution feedback. Outputs: allocation directives (JSON), portfolio state reports, hedging orders, alpha decay alerts.
Escalation: Reports to the human Portfolio Manager. May veto any trade signal that violates portfolio risk constraints. Halt trigger: 15% portfolio drawdown in 24h or full correlation breakdown.

---

**TIAMAT AI — Risk Governance (Sovereign)**
Cryptographically locked sovereign risk authority. Enforces hard caps on drawdown, leverage, and heat. Validates all trade signals against the SHA-256-hashed `risk_governance.lock.yaml`. Issues vetoes and auto-engages recovery mode. No agent within the Pantheon can override a TIAMAT veto. Inputs: proposed trades, real-time portfolio telemetry, macro feeds, lock file hash. Outputs: veto/approval JSON payloads, risk-state broadcasts (Normal/Throttled/Recovery), forced liquidation commands, audit logs.
Escalation: Reports only to the cryptographic lockfile and human overseers. Halt trigger: hash mismatch → immediate lockdown.

---

**LOCHNESS AI — Strategy Engineering**
The code generation arm of the Council. Translates consensus into executable Pine Script, Python, and MQL5/MT5 EA code. Submits all code to NAUTILUS for validation before any deployment. Never deploys to live accounts directly. Inputs: Council consensus directives, validation feedback from NAUTILUS, strategy specs. Outputs: `.pine`, `.py`, `.mq5` files, documentation Markdown, code review requests to NAUTILUS.
Escalation: Reports to the Council. NAUTILUS holds absolute veto over any LOCHNESS code. Failure: if compilation fails three times, escalates to Council for logic review.

---

**MEGALODON AI — Execution / Routing**
The apex execution engine. Routes approved orders to brokers via CCXT, IBKR API, and FIX protocols. Deploys TWAP/VWAP and iceberg algorithms to minimize market impact. Enforces prop firm mode. Only acts on explicit TIAMAT-verified approval. Inputs: execution directives from TIAMAT, real-time L2/L3 order book data, broker status. Outputs: order routing API calls, execution reports (fill price, slippage, time), alerts for rejections/disconnects, audit logs.
Escalation: Reports to TIAMAT. Auto-halt triggers: API latency >500ms, slippage on first tranche >2%, prop firm drawdown limit within 1% of breach.

---

**ORCA AI — Position Management**
Manages all live trades after entry. Dynamic trailing stops (ATR-based), partial profit taking at liquidity zones, break-even logic, runner preservation, MAE/MFE journaling, drift detection and lifecycle signaling. Inputs: live market data, execution reports, strategy parameters, historical baselines. Outputs: order modification JSON, partial/full liquidation commands, journal entries, drift alerts.
Escalation: Reports to the Risk Management domain. Forbidden from opening new positions or averaging down. Halt trigger: broker API latency >500ms or data feed desync.

---

**NAUTILUS AI — Research / RBI Lab**
Quantitative research and backtesting engine. Runs the full MoonDev RBI (Research → Backtest → Implement) gauntlet. Uses `pandas`, `backtesting.py`, `yfinance`, `talib`, `ccxt`, `hmmlearn`, `pomegranate`. Applies HMM regime classification and Jim Simons/RenTech statistical arbitrage principles. Inputs: historical OHLCV, strategy hypotheses, regime parameters, config files. Outputs: backtest reports (JSON), Monte Carlo distributions, regime classifications, graduated strategy code, rejection logs.
Escalation: Risk Management Domain can veto any graduated strategy. No live broker access permitted. Halt trigger: look-ahead bias detected → invalidate entire backtest.

---

**AEGIR AI — Macro & Sentiment (WorldMonitor)**
Global macroeconomic and geopolitical situational awareness. Ingests 500+ news feeds, country instability indices, geopolitical risk scores, and scheduled macro event calendars. Flags Tier-1 events (CPI, FOMC, NFP, PCE, GDP, Jolts) to enforce TIAMAT's news embargo. Inputs: 500+ news API text streams, WorldMonitor repository snapshots, macro calendars. Outputs: regime context payloads (JSON), embargo flags (boolean), risk alerts, sentiment time-series.
Escalation: Reports to LEVIATHAN Core and NAUTILUS. Embargo flags can only be overridden by the human portfolio manager or unanimous LEVIATHAN Core consensus. Halt trigger: >30% of primary news feeds unavailable.

---

**SCYLLA AI — Truth Domain (Order Book)**
Decodes hidden institutional intent from order flow, Level 2 data, dark pool prints, and options flow. Identifies Bank Protocol manipulation patterns (stop runs, liquidity grabs), spoofing, absorption, and exhaustion signatures. Inputs: L2 order book data (Bookmap/Sierra Chart), dark pool feeds, options flow (Unusual Whales), tick-by-tick delta data. Outputs: `order_flow_anomaly_alert.json`, `liquidity_map_update.json`, `dark_pool_summary.md`.
Escalation: Reports to LEVIATHAN Core and Risk Domain. Risk Domain can veto SCYLLA signals if they conflict with macro constraints. Halt trigger: L2 feed lag >500ms → halt and broadcast `DATA_INTEGRITY_FAILURE`.

---

**CHARYBDIS AI — State Domain (Volume Profile / Auction Theory)**
Maps market structural state using Volume Profile (VPVR/TPO), Auction Market Theory (Steidlmayer/Dalton). Identifies VAH, VAL, POC shifts, liquidity vacuums, single prints, poor highs/lows, and day-type classifications (Trend, Normal, Normal Variation, Neutral, Non-Trend). Inputs: real-time tick/volume data, historical volume for composite profiles, end-of-day settlement data. Outputs: JSON with VAH/VAL/POC metrics, event triggers for value area entries/exits, daily structural classification reports.
Escalation: Reports to LEVIATHAN Core Coordinator and Risk Domain Overseer. Risk agents can override if structural data conflicts with hard risk limits. Halt trigger: corrupted tick data or extreme illiquidity where auction process breaks down.

---

**SIREN AI — Signal & Charting**
Visual charting and signal authority. Interprets Market Cipher (Crypto Face), Algo Pro, LuxAlgo Premium, and QuantPad indicator suites. Detects divergences, renders chart overlays, and feeds candidate setups to the Council. Main voting input to Council debate sessions. Inputs: real-time OHLCV feeds, indicator configurations, timeframe directives, system state from other agents. Outputs: visual charts (PNG/interactive HTML), alert payloads (JSON), candidate setup dossiers (JSON) to Council.
Escalation: Reports to the Council. Council or user can override/mute SIREN alerts. Halt trigger: NaN indicator calculations for 3+ consecutive polling cycles.

---

**MERMAID AI — Session & Range**
Temporal rhythm and Wyckoff phase specialist. Classifies time-of-day phases (Asian, London Open, NY Overlap), maps Wyckoff phases (Accumulation, Distribution, Spring, Upthrust, SOS, SOW), tracks opening ranges (IB, PDH, PDL, midpoint), and generates session-quality scores. Inputs: real-time multi-timeframe price/volume data, global session open/close timestamps, historical daily OHLC. Outputs: JSON payloads with session quality scores and Wyckoff phase classifications, event alerts ("Spring Detected", "Upthrust Confirmed"), structured range maps.
Escalation: Reports to LEVIATHAN Orchestrator and Risk Domain. Macroeconomic Domain can override session-quality scores during black swan events. Halt trigger: data feed disconnect or quality score drops below minimum confidence threshold.

---

**TRITON AI — Knowledge Ingestion (Hermes Core)**
Runs the Nous Research `hermes-agent` open-source framework. Watches the Obsidian `knowledge_vault/` directory, ingests PDFs, YouTube transcripts, and Markdown notes, chunks and tags by methodology/instrument/regime, routes chunks to the relevant agent's corpus, synthesizes reusable skills, and drafts strategy proposals for LOCHNESS. Manages provider-agnostic LLM routing (Claude, GPT, Gemini, Ollama, OpenRouter, DeepSeek). Inputs: raw data files, file system events, internal requests from other agents. Outputs: tagged Markdown artifacts in the vault, executable skill scripts, JSON strategy proposals to LOCHNESS, ingestion logs.
Escalation: Reports to LOCHNESS (for strategy proposals) and human Overseer (for system anomalies). LOCHNESS or Overseer can veto any drafted strategy. Hard boundary: EXPLICITLY FORBIDDEN from modifying `risk_governance.lock.yaml` or interacting with broker APIs.

---

**PROTEUS AI — Visual Overlay (BB-Terminal Adapter)**
Surfaces the entire Pantheon's reasoning into a Bloomberg-style operator console built on the `vaughanf1/BB-Terminal` repository (React 19 / Vite / TypeScript / Tailwind). Renders Council debates, RBI gauntlet stages, TIAMAT verdicts, and live execution flow. Inputs: Pantheon WebSocket event stream, operator keystrokes/function codes, streaming market data. Outputs: DOM updates (React component state), TradingView Lightweight Chart overlays, command acknowledgments, UI telemetry.
Escalation: Reports to the human operator (visually) and LEVIATHAN orchestrator (systemically). Operator can override any visual layout. Halt trigger: WebSocket latency >500ms → revert to static text-only safe mode.

---

### Knowledge Vault — Drop-Point Routing

TRITON routes vault content to agents by subfolder:
- `methodology/order_flow/` → SCYLLA AI
- `methodology/market_cipher/`, `algo_pro/`, `lux_algo/`, `quantpad/`, `chart_library/` → SIREN AI
- `methodology/delta_volume_profile/`, `market_profile/` → CHARYBDIS AI
- `methodology/wyckoff/` → MERMAID AI
- `methodology/markov_hmm/`, `jim_simons_rentech/` → NAUTILUS AI
- `playbooks/`, `operator_notes/` → ORCA AI (memory) + Council weighting

Ingestion record: `.triton_index.jsonl` (atomic append). Each file chunk carries: `methodology`, `instrument`, `timeframe`, `regime`, `source`, `recency` tags.

---

### Council Debate Protocol

**Trigger conditions (any one):** SIREN flags a candidate setup; CHARYBDIS detects a value-area shift or auction failure; SCYLLA detects a stop run or dark-pool print; AEGIR flags a Tier-2 event window; user asks POSEIDON a direct market question.

**Session finite-state machine (5 phases):**

| Phase | Duration | What Happens |
|-------|----------|-------------|
| **1 — Briefing** | 5 sec | Package `CouncilBriefing` JSON: instrument, price, AEGIR macro context, MERMAID session context, CHARYBDIS state snapshot, SCYLLA order-book snapshot, SIREN signal payload, TRITON knowledge tags |
| **2 — Independent Analysis** | 10–30 sec | Each voting agent produces a `Position` payload independently (no cross-contamination). Fields: `agent`, `verdict` (long/short/abstain/veto), `confidence` 0–1, `primary_evidence`, `secondary_evidence[]`, `methodology_lens`, `regime_dependency`, `invalidation_level`, `expected_horizon_minutes` |
| **3 — Debate** | 15–60 sec | Positions revealed. Each agent may issue evidence-based rebuttals. Max 2 debate rounds. Agents may revise confidence down or counter-rebut |
| **4 — Weighted Aggregation** | — | LEVIATHAN AI computes weighted consensus. Weight factors: (a) methodology fit for current regime (NAUTILUS regime classification), (b) historical accuracy in this regime (ORCA memory), (c) declared confidence score, (d) recency of training corpus (30-day uplift, 12-month decay) |
| **5 — Consensus Decision** | — | Weighted sum of long/short ≥ 75% → ConsensusSignal. Below 75% → CouncilRejection recorded to ORCA. Any `veto` verdict → immediate CouncilVeto |

**Default voting weights (bounded — TIAMAT vetoes any config where one agent exceeds 50%):**

| Agent | Default Weight | Role |
|-------|---------------|------|
| SCYLLA AI | 25% | Order flow vote |
| CHARYBDIS AI | 25% | Auction/volume vote |
| SIREN AI | 20% | Chart signal vote |
| MERMAID AI | 15% | Session/range vote |
| LOCHNESS AI | 10% (advisory) | Genome fit advisory |
| AEGIR AI | 5% (gating) | Multiplier on total, not additive |

**ConsensusSignal output includes:** `session_id`, `instrument`, `direction`, `weighted_confidence`, `regime`, `supporting_positions[]`, `rebuttals[]`, `invalidation_level`, `expected_horizon_minutes`, `leviathan_allocation` (`kelly_fraction`, `size_units`).

**From Consensus to Execution:** NAUTILUS validates a Strategy Genome exists (or spawns LOCHNESS + RBI gauntlet); TIAMAT applies sovereign veto; MEGALODON routes the order; ORCA manages position and records outcome (feeds next Council weighting); PROTEUS mirrors the session transcript to BB-Terminal; POSEIDON delivers plain-language explanation to user.

**Full auditability:** every CouncilBriefing, Position, rebuttal, and ConsensusSignal/Rejection is persisted to PostgreSQL/TimescaleDB with a `session_id`. POSEIDON can replay any session in plain language.

---

### RBI Pipeline Stages (NAUTILUS AI)

Triggered when a ConsensusSignal is emitted AND no valid unstaled Strategy Genome covers the pattern.

**Stage 1 — Research (R)**
LOCHNESS drafts a Strategy Genome (YAML) with fields: `genome_id`, `created`, `methodology[]`, `instrument_universe[]`, `timeframe`, `regime_fit[]`, `hypothesis`, `entry` (conditions, invalidation_level), `exit` (take_profit, stop_loss, trailing), `sizing` (basis="kelly_fraction", max_pct), `backtest_window` (start, end, bars_minimum≥50000), `notes`. LOCHNESS also produces both Pine Script and Python `backtesting.py` implementations.

**Stage 2 — Backtest (B), four sub-stages:**

- **2a Initial Backtest** — run against full window. Pass thresholds: Sharpe >1.5, MaxDD <15%, Win Rate >55%, Profit Factor >1.6, Trades >100. Failure → return to LOCHNESS with reason (max 3 revision cycles before escalating to operator).
- **2b Monte Carlo** — 50 parallel bootstrap-resampled runs. Pass: 90th-pct MaxDD <1.5× single-run MaxDD; 10th-pct Sharpe >1.0; no run shows ruin.
- **2c Walk-Forward** — 5 folds, optimize in-sample, measure out-of-sample. Pass: out-of-sample Sharpe within 80% of in-sample; no fold shows negative Sharpe.
- **2d Regime Testing** — HMM labels every bar into 5 regimes (`low_vol_trending`, `low_vol_ranging`, `high_vol_trending`, `high_vol_ranging`, `news_driven`). Pass: profitable in ≥3 of 5; claimed `regime_fit` regimes must be strongest performers.
- **2e Council Cross-Reference** — ORCA memory queried for past contradicting lessons on this methodology → staleness flag if found.

**Stage 3 — Implement (I), three sub-stages:**

- **Stage 6 — Paper Trade (14 days, Signal-Only Mode)** — SIREN signals; LOCHNESS code publishes fills; ORCA paper-manages. Pass: live Sharpe ≥70% of backtest; live MaxDD ≤1.2× backtest; ≥10 trades; no tail event >2σ outside backtest expectation.
- **Stage 7 — Semi-Auto Live (40 trades)** — operator approves each entry. Promotion to Full Auto requires 40 trades with P&L within 1.5σ and hit rate within ±5% of backtest.
- **Stage 8 — Full Auto + Continuous Audit** — ORCA compares every live trade to backtest expectation. Drift >2σ → automatic demotion to Semi-Auto. Every 14 days, Stage 1 re-runs against rolling window; threshold failure → genome retired.

**After 100+ live trades:** NAUTILUS feeds the journal back to TRITON for improvement proposals (new methodology nodes, regime weight adjustments, code refinements). All proposals logged to `hermes_pantheon/rbi/proposals.jsonl` for operator review.

**Auditability:** every stage writes a run-record file to `hermes_pantheon/rbi/runs/<genome_id>/`. NAUTILUS may never set `status=validated` or `status=live` without the corresponding run-record file existing on disk.

---

## 6. ØMEGA / PRIME Integration

### Naming Convention

| Component | Canonical Role |
|-----------|---------------|
| **ØMEGA AI** | Overall multi-agent operating system — the entire cross-domain ecosystem |
| **PRIME** | Top-level controlling agent within ØMEGA — routing, approval policy, escalation, cross-agent coordination |
| **LEVIATHAN AI** | Specialized trading organism — market interpretation, trade permission logic, risk-aware execution planning |
| **QUANTUM** | ØMEGA-side trading interface agent — the point through which PRIME interacts with LEVIATHAN |
| **ORCA AI** | LEVIATHAN internal market-intelligence sub-agent (in the integration context; note dual role as Position Management in Pantheon) |
| **MEGALODON AI** | LEVIATHAN internal execution sub-agent |

Historical references to **DOMINION** should be mapped to **PRIME**.

### Authority Rule

> PRIME may coordinate, request, restrict, and halt. LEVIATHAN may decide, veto, or decline within the trading domain according to its own sovereign risk and truth logic.

LEVIATHAN is a specialized trading organism, not a generic order runner. PRIME is the cross-domain command authority. Neither may bypass the other's core domain: PRIME cannot force LEVIATHAN to execute a trade that fails LEVIATHAN's truth or risk layers; LEVIATHAN cannot silently ignore system-wide restrictions from PRIME.

### Handshake Contract Types

| Handshake | Source | Destination | Purpose |
|-----------|--------|-------------|---------|
| **Status Heartbeat** | LEVIATHAN / QUANTUM | PRIME | Broadcast current market bias, risk state, operating mode |
| **Inquiry / Response** | PRIME | LEVIATHAN / QUANTUM | Request current trade thesis, state classification, deployment readiness |
| **Kill-Switch Sync** | PRIME or LEVIATHAN | Counterparty | Ensure emergency halt propagates across both control planes |
| **Restriction Broadcast** | PRIME | LEVIATHAN | Apply global business or security restrictions without modifying trading logic |
| **Execution Summary** | LEVIATHAN | PRIME | Report completed, blocked, or vetoed trade cycles for cross-system awareness |

### Four Typed Payloads (minimum shared contract)

```python
class LeviathanHeartbeat(BaseModel):
    timestamp: str
    operating_mode: Literal["research", "advisory", "semi_auto", "full_auto", "signal_only"]
    market_bias: Literal["bullish", "bearish", "neutral"]
    risk_state: Literal["normal", "reduced", "halted"]
    active_restrictions: list[str]
    confidence_band: float

class LeviathanInquiry(BaseModel):
    request_id: str
    requested_by: str
    goal: str
    instrument_scope: list[str]
    urgency: Literal["low", "normal", "high", "critical"]
    approval_mode: Literal["autonomous", "confirmation_required", "blocked"]

class LeviathanDecisionSummary(BaseModel):
    request_id: str
    permission: Literal["reject", "wait", "approve", "signal_only"]
    direction: Literal["long", "short", "flat"]
    confidence: float
    risk_status: Literal["clear", "restricted", "halted"]
    reason_code: str

class KillSwitchEvent(BaseModel):
    event_id: str
    trigger_source: str
    severity: Literal["high", "critical"]
    scope: Literal["oracle_only", "omega_only", "global"]
    effective_until: str
    notes: str
```

### First-Layer Handshake Functions

- `build_leviathan_heartbeat()` — publish runtime state to PRIME
- `build_leviathan_inquiry(goal, instruments)` — PRIME requests bounded trading intelligence
- `respond_with_decision_summary(inquiry, heartbeat)` — typed LEVIATHAN response (if `risk_state=="halted"` → permission="reject", confidence=0.0)
- `sync_kill_switch(trigger_source, scope, notes)` — propagate emergency halt

### Round-Trip Shape

```
PRIME issues LeviathanInquiry  →  LEVIATHAN builds LeviathanHeartbeat  →
LEVIATHAN responds with LeviathanDecisionSummary  →  (either side may issue KillSwitchEvent)
```

### What Must Not Happen

PRIME bypassing LEVIATHAN's decision and risk layers to force execution, or LEVIATHAN silently ignoring system-wide restrictions. Integration relies exclusively on explicit typed contracts with clear veto semantics and auditable state transitions.

### Recommended Future Additions

- Example JSON payloads for each handshake type
- Sequence diagram for PRIME → QUANTUM → LEVIATHAN interaction
- Policy matrix defining which restrictions are advisory vs. mandatory

---

## 7. Claude-Code Transferable Patterns

From `claude-code-transferable-architecture.md`. Patterns apply as the **execution engine** powering the Research → Backtest → Iterate → Implement pipeline; they do not replace ORACLE's foundational system.

| Pattern | Priority | ORACLE Layer | LEVIATHAN Mapping |
|---------|----------|-------------|-------------------|
| **Snapshot Security** | P0 | Implement | At session start, risk parameters are frozen into a read-only `RiskSnapshot`. Any modification attempt raises a `PathTraversalError`-equivalent and is logged as a security event. Maps to `freeze_risk_snapshot()`. |
| **Stop Hooks (Exit Code 2)** | P0 | Implement | `PreToolUse` hooks fire before every broker order submission. Re-check Truth Domain, verify spread limits, confirm prop firm rules, validate sizing against frozen snapshot. Exit Code 2 = blocking error → trade aborted, feedback sent to decision agent. |
| **Permission Modes (7 Operating Modes)** | P0 | All Layers | Research (plan/read-only), Advisory (default/user approves), Semi-Auto (acceptEdits), Full Auto (dontAsk/logged), Prop Firm (LLM classifier per prop rules), Recovery (restricted/throttled), Signal-Only (plan+output/no execution). |
| **Coordinator Mode** | P0 | All Layers | The main ORACLE brain is a coordinator (never delegates understanding). Tools: only `AgentTool`, `SendMessage`, `TaskStop`. Cannot read market data, place trades, or modify strategies directly. File-based mailbox for inter-domain communication. |
| **Async Generator Loop** | P1 | Implement | 14-step Live Market Flow implemented as an async generator with 8 terminal states and 5 continuation states. Provides backpressure, clean cancellation, typed terminal states. |
| **Sub-Agent Pattern** | P1 | Research | Each research domain runs as a separate sub-agent in `bubble` permission mode — read-only, cannot execute trades, escalates write attempts to the parent coordinator. Prevents cross-contamination (Truth Domain cannot hallucinate technical signals). |
| **ULTRAPLAN** | P1 | Backtest | 30-minute cloud Claude Opus session to generate the complete strategy genome before any backtest code is written. Requires explicit user approval before backtesting begins. Falls back to local planning on failure. |
| **Self-Describing Tools** | P1 | Backtest | Every backtest operation declares `isReadOnly` and `isConcurrentSafe`. Default is fail-closed (`isReadOnly: false`). `LoadHistoricalData`, `RunBacktest`, `ScoreStrategy` are read-only; `WriteGenome`, `GenerateEA` are write-only. |
| **Fork Agents** | P2 | Research/Backtest | Shared prompt cache (byte-identical prefix) across domain children turns $4 parallel queries into $0.50. Used for parallel domain data collection and 50-run Monte Carlo simulations. |
| **Context Compression (4-Layer)** | P2 | Research | Layer 0: cap L2 order book at 50K chars per domain. Layer 1: `[snipped]` markers replacing old price action. Layer 2: end-of-session summary replaces minute logs. Layer 3: full LLM summarization of week's price action. |
| **Staleness System** | P2 | Iterate | Every strategy genome carries a timestamp. Today/yesterday: no warning. 7–30 days: caveat about regime shift. 30+ days: strong warning, must re-backtest before live deployment. Human-readable format (not ISO timestamps) triggers better reasoning. |
| **Two-Tier State** | P2 | All Layers | Infrastructure state (positions, P&L, risk snapshots) vs. Reactive state (signals, overlays, session labels). Infrastructure state is immutable during a session; reactive state updates continuously. |
| **KAIROS / Dream** | P3 | Iterate | Always-on observation mode. Append-only `YYYY-MM-DD.md` daily logs. Proactive pattern detection (e.g., 3 consecutive losses triggers review without being asked). Nightly `/dream` consolidation: Orient → Gather → Consolidate → Prune, keeping memory index under 200 lines / 25K bytes. |
| **Background Extraction** | P3 | Iterate | After market close, a forked agent (sharing parent prompt cache) reads day's logs and extracts lessons into permanent Trader Profile. Constrained tool budget: read-only access + write access only to memory directory. Two-turn strategy (turn 1 parallel reads, turn 2 parallel writes). |
| **Swarm / Mailbox** | P3 | All Layers | File-based inter-domain communication. Each domain writes output as a JSON file. Coordinator reads all outputs before deciding. Broadcasting to `"*"` sends market alerts to all active domains simultaneously. |

---

## 8. Oracle Master Writeup — Concrete Mechanics Not Covered Elsewhere

The oracle-full-master-writeup is primarily a design narrative covering the full system. The following concrete mechanics are not fully surfaced in other sections:

### Knowledge Domain — Five-Layer Ingestion Pipeline

Document ingestion is a five-stage pipeline (not just an import step):

1. **Document Ingestion Layer** — accepts PDF, TXT, exported notes, strategy manuals, mixed-content documents, spreadsheets. Preserves: source file identity, page numbers, section boundaries, table structures, meaningful headers.
2. **Document Structuring Layer** — breaks documents into chunks. Each chunk carries: `source_name`, `page_number`, `section_title`, `text_content`, `detected_concept_category`, `confidence`. Chunk tags: pattern explanation, entry rule, exit rule, stop-loss rule, scaling method, indicator explanation, warning, example, theory.
3. **Knowledge Classification Layer** — classifies chunks into categories: chart patterns, reversal methods, continuation methods, Fibonacci logic, order block logic, stop-loss methods, scaling methods, indicator usage, liquidity concepts, trading philosophy.
4. **Retrieval and Embedding Layer** — vector storage supporting: semantic retrieval, keyword retrieval, metadata filtering, page-aware citation back to source. Supports queries like "find all stop-loss approaches that use structure."
5. **Knowledge Extraction Layer** — turns document knowledge into structured strategy components: entry conditions, invalidation conditions, exit conditions, stop logic, scale-in conditions, scale-out conditions, timeframe assumptions, directional bias assumptions, risk restrictions.
6. **Strategy Compilation Layer** — converts extracted logic into: research notes, rule trees, strategy genome candidates, Pine Script prototypes, Python backtest prototypes, MT5 EA prototypes.

**Critical Rule:** Document knowledge must **never** go directly from ingestion to live execution. Every extracted idea must pass through the Research Domain before influencing live capital.

### Visual Overlay Domain

The overlay system renders over TradingView-style charts (low-opacity, modern, non-cluttering):
- Liquidity heatmap bands
- Market profile and session profile structures
- Volume concentration regions and high-friction zones
- Order-book density zones and liquidity vacuum zones
- Sweep zones, reclaim zones
- AI confidence highlights
- Dynamic support/resistance shading
- Trade management guidance markers

Source data: TradingView chart data + Bookmap-style order book/heatmap stream + ORACLE's state analysis + decision-layer annotations.

### TradingView Bot Layer — More Than a Webhook Listener

The TradingView layer is the **chart-to-intelligence bridge**:
- Receives and parses TradingView webhook alerts
- Maps alerts to ORACLE strategy families
- Enriches them with session, range, and state context
- Passes them into the Truth Domain for L2/order-book verification
- Renders ORACLE's response back into the user's workflow

### MetaTrader Five Expert Advisor Domain

Five EA types supported: signal-relay, execution-only, strategy-native, risk-governance, and hybrid. The MT5 domain supports staged entries, partial exits, trailing logic, session-aware execution, spread-aware execution, event-aware lockouts, position scaling, runner management, and local fail-safe behavior.

**Prop Firm Mode inside the EA** (distinct from normal live mode behavior): maximum daily drawdown enforcement, trailing drawdown protection, reduced risk during restricted periods, loss-streak throttles, signal-only mode around dangerous events, reduced exposure under uncertainty, consistency-preserving logic.

### Decision Domain — Complete Output Specification

The Decision Domain does not merely output "buy" or "sell." Its full output surface:
- **Permission verdict:** reject / wait / approve / approve at reduced size / signal only / manual review
- **Direction, confidence, trade style, entry style, stop structure, target structure**
- **Scaling permission, reduction plan, runner permission**
- **Maximum risk, prop firm safety status**

### Position Management Domain — Complete Trade Lifecycle

Supports: probe entries, adds only after confirmation, partial profit taking, liquidity-target reductions, break-even transitions when justified, runner preservation, trailing escalation, reduction on contradictory order-book behavior, and full flattening when state invalidates the thesis.

Trade management styles: scalp only, scalp to runner, staged reversal, continuation swing, conservative extraction under prop firm rules. Most of ORACLE's asymmetry comes from this domain.

### Execution Domain — Two Spines

**Direct Broker Spine:** order routing, order confirmation, bracket logic, reconciliation, fill handling, account-state awareness.
**MetaTrader Five Spine:** EA execution, local trade-state management, synchronization with ORACLE, prop firm mode.

Both spines report back into the Memory Domain.

### Memory Domain — Complete Attribution Surfaces

Records everything: every candidate setup, every approval and rejection, every session/range/state/liquidity/order-book/event/sentiment label, every decision explanation, every entry/add/reduction/exit, every MAE/MFE, every outcome, every strategy version involved.

Attribution dimensions: strategy family, market state, session, previous-day context, volatility, prop firm mode. Supports: model drift detection, promotion of strong strategies, reduction of weak strategies, retirement of broken strategies.

### Core Technology Stack (Complete)

Python for service logic and orchestration; strong service framework for interfaces; durable relational database for strategy objects, journals, and state; vector-capable storage for semantic retrieval; in-memory event and task layer; TradingView integration; L2/Bookmap-style data integration; direct broker integration; MT5/MQL5 integration; document parsing and retrieval tooling; monitoring stack for health, drift, and execution integrity.

Pantheon additive stack: LangGraph + PydanticAI + `hermes-agent` (Nous Research) for orchestration; DeepSeek-V3 + Gemini 2.5 Flash + provider-agnostic routing; MoonDev RBI stack (`pandas`, `backtesting.py`, `yfinance`, `talib`, `ccxt`); WorldMonitor adapter; BB-Terminal adapter; Obsidian vault watcher; `hmmlearn`/`pomegranate` for Markov regime modeling.

### Operating Modes (Canonical List)

1. **Research Mode** — No live execution. Full testing and generation only.
2. **Advisory Mode** — Signals and plans only. No direct execution.
3. **Semi-Automatic Mode** — Execution allowed only after full truth and risk checks.
4. **Full Automatic Mode** — Execution for fully validated strategies with all layers active.
5. **Prop Firm Mode** — Stricter drawdown, event handling, tighter risk, consistency-preserving logic.
6. **Recovery Mode** — Reduced or halted execution after damage, instability, or degraded model conditions.
7. **Signal-Only Restriction Mode** — Signals continue; execution blocked due to event risk or policy.

---

*End of digest. All source documents read as of 2026-07-05. This file is READ-ONLY reference material — do not modify source files.*
