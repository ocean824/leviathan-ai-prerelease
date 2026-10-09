# LEVIATHAN AI — PRD Digest: Features M–Z (plus Uncategorized)

**Generated:** 2026-07-05  
**Source path:** `C:\Users\XYRASYSTEMS\MASTER TEMPLATE\.codespring\extracted\.codespring\PRDs\`  
**Scope:** 21 feature folders processed; all backend/database/frontend PRD .md files read.  
**Companion file:** `prd-digest-1-features-a-l.md` (features A–L, not produced here).

---

## Executive Summary (Cross-Cutting Patterns)

1. **Shared stack assumptions:** PostgreSQL (time-series with day/week partitioning, BRIN indexes on ts columns) for structured data; Kafka or NATS for event streaming; Redis/in-memory for sub-5s caches; object storage for artifacts with pre-signed URLs; mTLS between all services; OAuth2/JWT with short-lived tokens (≤15m for secrets, ≤5m for ØMEGA bridge tokens).

2. **Universal RBAC:** Every feature defines multi-tier roles (Viewer/Researcher/Operator/Risk/Admin) enforced at API level with row-level security by user_id/org_id. Unauthorized actions are hidden in UI (not merely disabled). Dual-control (two distinct approvers) is required for kill-switches, break-glass, and limit overrides across Risk Safeguards, Risk Limits, Security Hardening, and MCP Co-Agent features.

3. **Append-only audit everywhere:** Every feature writes an immutable, hash-chained audit journal capturing actor, timestamp, before/after payload, and correlation_id. Retention floors: 7 years for compliance-critical events (risk decisions, security actions, trade-adjacent records); shorter hot windows (30–90 days) for high-volume telemetry.

4. **ØMEGA bridge as cross-cutting integration seam:** Fifteen of the 21 features reference the Secure Agent Bridge (mTLS + signed payloads) for ØMEGA AI coordination. Agent actions always pass through policy gates before any OMS or capital-touching operation.

5. **Kill-switch hierarchy appears in four independent features** (Risk Safeguards, Risk Limits & Compliance, Security Compliance Hardening, MCP Co-Agent Control) with overlapping scope definitions — a known architectural tension requiring a single authoritative kill-switch arbiter.

6. **Idempotency-Key is universal:** Every mutating POST across all features requires an Idempotency-Key header with a 24h or 2-minute dedup window to prevent duplicate capital actions from retries.

7. **Feature Store as shared dependency:** Signal Detection, Regime Awareness, Truth Validation, Operator UI, Prediction Markets Controller, and Strategy Portfolio Builder all read from a shared Feature Store. Its schema, SLAs, and versioning are the single biggest implicit dependency in the system.

8. **Desktop-first UI pattern:** All frontend PRDs target ≥1280px as primary, 1024px as compressed layout, and explicitly exclude mobile. WCAG AA contrast (4.5:1), keyboard navigation, and ARIA roles are acceptance criteria in every frontend PRD.

9. **Duplicate/overlapping feature pairs:** research-backtesting-lab (ARCHIVED) vs. research-rbi-lab (active); truth-validation (active) vs. truth-validation-order-flow-options (ARCHIVED); risk-limits-compliance vs. risk-safeguards (significant functional overlap); signal-detection vs. signal-session-state-detection (ARCHIVED). These pairs need architectural consolidation notes in each digest section.

10. **Event topics as contracts:** Streaming topics (Kafka/NATS) are first-class interface contracts defined in backend PRDs. Topics such as `regime.updated`, `risk.decisions`, `audit.events`, `prediction.priors.v1`, `omega.task.lifecycle`, and `signals.v1.rt` form the service mesh backbone and must be versioned independently of HTTP APIs.

---

## Feature Digests

---

### market-intelligence-terminal

- **Purpose:** A tabbed, keyboard-first operator workstation ("evil-Jarvis" dark theme) consolidating real-time market intelligence across 9 specialized tabs (CC, INTEL, QR, GP, HP, OMON, CURV, FXC, WEI) with a global fuzzy-search command bar and ØMEGA bridge integration.

- **Backend:**
  - Backend PRD was unavailable at generation time (model timeout on source read); schema and frontend PRDs were successfully read.
  - Assumed services: workspace/tab state API; WebSocket fanout for per-tab streams; command bar execution (routes to internal APIs or ØMEGA via /omega commands); macro/keybinding CRUD.
  - Stream topics consumed: flow.print, dp.print, feature.update, regime.update, edge.metric (coalesced at 5 Hz per symbol/topic).

- **Data model:**
  - `workspaces` — per-user named layout with theme and default flag (one default per user).
  - `workspace_tabs` — ordered tab instances (tab_key enum: CC/INTEL/QR/GP/HP/OMON/CURV/FXC/WEI) with pin/visibility.
  - `saved_views` — unique per (user_id, tab_key, name); persisted filter/column sets.
  - `macros` — versioned per user, unique by (user_id, name).
  - `keybindings` — unique by (user_id, scope, keystroke); scope: global/workspace/tab.
  - `link_groups` — cross-tab symbol/timeframe sync within a workspace.
  - `command_history` — append-only; stores latency, execution status, ØMEGA bridge target; 180-day retention.
  - `terminal_events` — append-only compliance journal; 365-day retention; payload redacted for restricted roles.

- **Frontend:**
  - 9-tab bar (drag-reorderable, role-locked for unauthorized tabs with "Request access" CTA).
  - Per-tab widgets: INTEL (alerts feed, anomaly tiles, heatmap); QR (factor table, model output chart, drift gauge); GP (exposure/PnL/sector); HP (latency timeline, component grid); OMON (live orders/fills, risk events); CURV (term structure, basis spread, shift heatmap); FXC (pairs matrix, correlation map, regime tag); WEI (liquidity heatmap, slippage chart, venue fees); CC (global filters, ØMEGA status, time controls).
  - Command bar: Cmd/Ctrl+K, slash commands (/tab, /sym, /filter, /omega), permission-gated items shown dimmed.
  - Latency badge (OK <100ms / WARN 100–300ms / HOT >300ms); "Stale" after 3s no update.
  - Time scrub (last 15m) with "Paused" ribbon.

- **Depends on:** Feature Store (QR tab), Decision Engine (edge metrics), OMS/Order Gateway (OMON fills), Risk Guard (OMON risk events), Regime Awareness (FXC regime tag), Signal Detection (INTEL anomalies), Monitoring Telemetry (HP latency data), ØMEGA bridge.

- **External:** None explicitly; assumes all data streams exist via internal pipeline.

- **Notes:** Backend PRD source file was empty/truncated (model timeout). Schema and frontend PRDs were complete. The tab_key ENUM `evil-jarvis` appears in the theme field only — not a tab. Performance target: initial load ≤2.0s, tab switch ≤150ms, stream CPU ≤30%. Role scoping: Trader (CC/INTEL/GP/OMON/FXC/WEI), Researcher (QR/CURV/INTEL), Operator (HP/OMON/CC), Risk (GP/OMON/HP). Near-duplicate overlap with Operator UI feature — MIT covers 9 tabs holistically while Operator UI covers a narrower 3-screen (Today Panel/Symbol View/Strategy View) operator workflow.

---

### mcp-co-agent-control

- **Purpose:** Multi-agent control plane enabling authorized operators to coordinate LEVIATHAN and ØMEGA agents via MCP with scoped tool grants, policy gates, human-in-the-loop overrides, and cryptographically evidenced approvals at HFT-grade latency.

- **Backend:**
  - Agent registration with signed attestation; auto-quarantine on 3 critical violations in 10 minutes.
  - Session lifecycle: draft → pending_approval → running → paused/revoked/completed/failed.
  - Policy gates (ordered): risk limits, market state, data egress/PII, change-mgmt 2-party approval, rate/velocity budgets.
  - Action idempotency via Idempotency-Key; duplicates return original result.
  - Endpoints: POST /mcp/agents/register, /mcp/sessions, /mcp/actions, /mcp/overrides, /mcp/halts; GET /mcp/audit.
  - Events on topic `mcp.events` with exactly-once semantics.
  - SLA: P99 policy evaluation ≤50ms (in-memory cache); synchronous trade path ≤80ms end-to-end.

- **Data model:**
  - `agent_identities` — status: active/disabled/quarantined; mTLS material; attestations.
  - `agent_sessions` — scoped session claims; token_hash (no plaintext); expires_at/revoked_at.
  - `tool_scopes` — per-agent tool permissions with rate caps and parameter schemas.
  - `action_requests` — state machine (pending → risk_blocked → awaiting_approval → approved/denied → executing/executed/failed/expired/canceled); dedupe_key for idempotency.
  - `approvals` — multi-level per action_request; cryptographic signature for high-risk; unique per (request_id, level).
  - `action_events` — append-only hash-chained lifecycle stream per request; tamper-evident.
  - `policies` — versioned with supersedes_id; scope: global/org/agent/tool; deny-by-default.
  - `quotas` — windowed consumption counters with atomic reset.
  - `audit_trail` — WORM; indefinite retention. No UPDATE/DELETE on action_events/audit_trail.

- **Frontend:**
  - Agent Council Panel: real-time agent list with status, latency, last action, risk tier.
  - Session Console: live event stream with level/tag filters, autoscroll, 200-event backfill on mount.
  - Policy Gate Bar: sticky banner showing Green/Amber/Red posture, pending approvals count.
  - Tool Scope Drawer: per-agent Allowed/Prompt/Denied toggles with symbol/time/size args.
  - Override & Approvals Drawer: pending queue, dual-control enforcement, outcome tracking.
  - Audit Timeline: immutable journal with diff view and CSV/JSON export.
  - Roles: Admin (full), Risk Manager (policy edits, emergency stop), Operator (start/stop sessions), Observer (read-only).
  - Emergency Stop requires typed confirmation phrase.

- **Depends on:** ØMEGA AI Integration (Secure Agent Bridge), Risk Limits & Compliance (risk gate inputs), Security Compliance Hardening (mTLS/JWT), Monitoring Telemetry (observability), OMS (trade actions via approved sessions).

- **External:** None directly; ØMEGA peers connect via Secure Agent Bridge.

- **Notes:** Architecturally similar to the ØMEGA AI Integration feature — both implement session-scoped tool grants with dual approval and audit chains. MCP Co-Agent is the general multi-agent control plane; ØMEGA Integration is the specific LEVIATHAN↔ØMEGA protocol. Clear boundary must be drawn to avoid duplicate approval workflows. The quarantine auto-trigger (3 critical violations / 10 min) is a critical safety mechanism that must be tested under load.

---

### mega-ai-integration

- **Purpose:** Provides the secure, auditable, rate-governed protocol bridge for cross-system task handoffs and tool sharing between LEVIATHAN AI and ØMEGA AI, with least-privilege scopes, idempotent task orchestration, and human-in-the-loop kill-switch controls. (Feature name in PRDs is "ØMEGA AI Integration".)

- **Backend:**
  - Mutual TLS + OAuth2 client-credentials JWT (TTL ≤5m); scoped per agent_session_id and capability manifest.
  - Replay protection: nonce + timestamp (±2s skew).
  - Task state machine: pending → in_progress → waiting → succeeded/failed/cancelled/expired; DAG edges for dependencies.
  - Rate limits: 50 rps default, burst 100 per client_id and per agent_session.
  - Circuit breaker: auto-trips on error rate > threshold or risk violation; quarantine queue.
  - Reconciliation job: marks in_progress tasks with stale heartbeats (> SLA) as failed.
  - Endpoints: POST /v1/omega/sessions, /tasks/handoff, /tasks/{id}/accept, /tasks/{id}/update, /tools/use, /control/{session}/{cmd}; GET /tools/manifest, /audit.
  - Stream topics: omega.task.lifecycle, omega.action.invocation, omega.guard.violations, omega.session.state.

- **Data model:**
  - `agents` — mTLS material, status (active/disabled/quarantined), attestations.
  - `agent_tokens` — short-lived, token_hash only, revocable.
  - `tasks` — state machine; parent_task_id for DAG; expires_at for TTL sweeps.
  - `task_edges` — dependency ordering.
  - `tool_registry` — risk level, schema hints; per-agent policy (DENY overrides ALLOW).
  - `actions_log` — append-only; checksum/signature; reason_code required.
  - `traces_sessions` — correlated to actions_log and root task.
  - `approvals` — PENDING blocks task until resolved; link to user IAM externally.
  - `global_controls` — kill-switch; ACTIVE halts new RUNNING transitions.
  - `rate_limits` — circuit_state (OPEN prevents new task starts until cooldown).

- **Frontend:**
  - Persistent status bar: Bridge state (Connected/Degraded/Disconnected), mTLS status, token TTL countdown, clock drift indicator.
  - Handoff Composer: JSON editor with schema validation, tool multi-select from allowlist, risk tier selector, TTL ≤24h.
  - Incoming Requests Queue: columns Time/Agent/Intent/Risk tier/Gate/Status/TTL; Approve/Deny/Escalate actions.
  - Tools Panel: scope badges, rate limit meters, circuit breaker state, last audit hash.
  - Cross-system Timeline: filter by agent/risk/tool/trace ID; decision path with policy checks; JSON/CSV export.
  - Controls Drawer (role-gated): global kill-switch (2-step confirm + reason), pause/resume agent, drain queue, rotate/revoke token.

- **Depends on:** MCP Co-Agent Control (overlapping session/tool scope concepts), Risk Limits & Compliance (risk_guard_ok for trading tools), Security Compliance Hardening (mTLS, secrets), Monitoring Telemetry (OpenTelemetry trace correlation).

- **External:** ØMEGA AI (peer system, external implementation not in scope).

- **Notes:** Near-duplicate with MCP Co-Agent Control — both manage agent sessions, tool scopes, policy gates, and audit trails. Key distinction: MCP Co-Agent is the internal LEVIATHAN control plane for all autonomous agents; ØMEGA AI Integration is the specific bilateral protocol for LEVIATHAN↔ØMEGA interoperability. Shared entities (agent identity, session tokens, action audits) risk data model divergence if not unified. Context payload max 64KB is a hard constraint that downstream systems must respect. TTL 1s–30m is a notable short cap for long-running AI tasks.

---

### monitoring-telemetry-logging

- **Purpose:** End-to-end observability for LEVIATHAN's low-latency trading stack — structured logs, distributed traces, Prometheus-compatible metrics, SLO-based alerting, health probes, and a correlation endpoint linking orders to traces and logs.

- **Backend:**
  - Metrics with consistent labels (service/component/env/region/strategy_id/symbol/venue); SLOs: p99 decision_latency ≤8ms, order_submit ≤12ms, pipeline_lag ≤150ms.
  - Structured JSON logs: required fields include trace_id/span_id (W3C traceparent), correlation_id (persists across async hops and ØMEGA bridge), request_id (per inbound request).
  - Privacy: redact secrets/PII patterns; truncate fields >8KB; log line cap 64KB; CPU overhead ≤2%, buffers ≤50MB per service.
  - Trace sampling: 0.1% baseline; 100% on ERROR or flagged correlation_id; dynamic upsampling during incidents.
  - Health probes: /livez (unauthenticated, event-loop only); /readyz (authenticated; checks DB, cache, streams, OMS connectors, config, risk rules, time sync); /healthz (aggregated with version/uptime/config hash).
  - Correlation endpoint: GET /observability/v1/correlate/{correlation_id} → linked trace_ids, order_ids, strategies.
  - Alert routing: SEV1/SEV2 to on-call via PagerDuty; dedup 60s per service+component+failure_mode; inhibition (venue down inhibits downstream latency alerts).

- **Data model:**
  - `services` — normalized service registry referenced by all telemetry tables.
  - `telemetry_metrics` — append-only time-series; partitioned by day on ts; agg_type for rollups.
  - `logs` — JSON-structured with redacted boolean; partial index for error-level entries.
  - `traces` / `spans` — parent-child self-ref on spans; partitioned by day on start_time.
  - `alert_rules` — with runbook URL, channels (many-to-many via alert_rule_channels), dedupe_key.
  - `incidents` — severity: info/warning/critical; status: open/acknowledged/resolved.
  - `incident_events` — 1:N timeline entries per incident.
  - `health_probes` — per-service instance liveness/readiness reports.

- **Frontend:**
  - Observability hub: Metrics, Logs, Traces, Alerts, Health tabs.
  - Metrics: P50/P95/P99 tiles, stacked throughput charts, crosshair sync across charts, zoom-brush drill to Traces/Logs.
  - Logs: virtualized table (50k+ entries); Lucene-like filters; detail drawer with JSON pretty-print; PII masked for non-DevOps; NDJSON/CSV export (10k row cap).
  - Traces: service map (node size = throughput, color = error rate), waterfall with critical path, compare 2 traces overlay.
  - Alerts: rule editor with metric selector, threshold, mute schedules, runbook; active alert queue with acknowledge/snooze/escalate.
  - Health: fleet grid per component; liveness/readiness indicators; restart/drain controls (DevOps only).

- **Depends on:** All other LEVIATHAN services (consumers of this feature); OMS/connectors for readiness checks; Risk Guard for rule presence check in /readyz.

- **External:** PagerDuty (alerting), OpenTelemetry collector, Prometheus/Grafana compatible scrape targets.

- **Notes:** Foundational cross-cutting service; all other features depend on it. The /readyz check includes "risk rules present" — creating a runtime dependency on Risk Safeguards/Risk Limits that must be carefully managed during startup sequencing. ØMEGA correlation_id propagation via Secure Agent Bridge is explicitly required for cross-system trace continuity. Retention: logs 14d hot / 90d cold; metrics 7d at 5s → 30d at 30s → 90d at 5m.

---

### operator-ui

- **Purpose:** Stream-first, low-latency operator workstation providing intraday situational awareness across three integrated screens: Today Panel (market regime, top flows/DP, earnings, IV rank), Symbol View (price levels, flow, IV profile, catalysts), and Strategy View (active plays, Edge Health metrics, Obsidian update control).

- **Backend:**
  - REST + WebSocket; REST p95 <150ms; WS broadcast within 250ms from ingestion; cache TTL 3s (Today) / 2s (symbol).
  - Today Panel: GET /ui/today; WS topic today.update; returns regime, top_flows, top_dp, earnings (T+5d), iv_rank.
  - Symbol View: GET /ui/symbols/{symbol} with levels (HTF/LTF/vwap/gamma), flow_dp, iv_profile, catalysts; WS topics per symbol.
  - Strategy View: GET /ui/strategies/active with Edge Health object (data_freshness_ms, signal_latency_ms, order_gateway_status, fill_rate_5m, drift_bps, risk_guard_state); POST /ui/strategies/{id}/obsidian/updates (idempotent by key, audited, dry_run supported).
  - Enums: Regime {risk_on, risk_off, neutral, event_risk, illiquid}; EdgeHealth.status {healthy, degraded, at_risk, offline}; Play.state {planned, active, cooling_down, paused, closed}.

- **Data model:**
  - `today_panel` — single latest row per trade_date; references regime_states and iv_metrics.
  - `regime_states` — referenced by today_panel for consistency.
  - `flow_dp_aggregates` — unique(symbol, window_start, window_end); aggregated notional/kind.
  - `iv_metrics` — unique(symbol, as_of); IV rank/percentile and tenor values.
  - `symbol_levels` — unique(symbol, level_type, price, as_of); HTF/LTF/vwap/gamma levels.
  - `symbol_catalysts` — earnings/macro/company events with severity and links.
  - `strategy_plays` — active strategy-symbol intents with risk/targets and status transitions.
  - `edge_health_metrics` — unique(strategy_id, COALESCE(symbol,''), as_of); per-strategy health snapshot.
  - `obsidian_update_controls` — single open request per strategy+update_type; payload_hash for idempotency; signed JSON.

- **Frontend:**
  - Today Panel: ranked flows/DP list (30/90min toggle), regime with confidence, earnings T+5 with IV Rank, IV rank movers.
  - Symbol View: levels, flow tape with aggregated heatmap, IV term structure mini-chart, catalysts with T- countdown.
  - Strategy View: active plays table (PnL, slippage, risk flags, state), Edge Health badges with sub-metric tooltips, Obsidian Update Control (Propose/Dry Run/Promote/Rollback; MFA required).
  - Roles: View (Operator/PM/Risk); Obsidian controls (Strategy Engineer/Admin). ØMEGA bridge offline disables controls.

- **Depends on:** Feature Store (levels, IV, ranks), Time-series DB (flows/DP, ticks), Knowledge/Vector DB (catalysts), Risk Guard (risk_guard_state), OMS/Order Gateway (gateway status, fill rates), Decision Engine (edge metrics), Regime Awareness (regime classification), Signal Detection (flow/anomaly events).

- **External:** None directly; depends on internal data services.

- **Notes:** Overlaps significantly with Market Intelligence Terminal — both provide operator-facing dashboards with streaming market data. Operator UI is narrower (3-screen intraday focus) while MIT is a 9-tab comprehensive workstation. The Obsidian Update Control in Strategy View creates a dependency on the Self-Learning Agent Council's Obsidian vault integration. Edge Health "drift_bps" requires ongoing backtest-vs-live comparison computation not explicitly owned by this feature — assumed from Decision Engine.

---

### prediction-markets-controller

- **Purpose:** Ingests, normalizes, and serves calibrated probability vectors from on-chain (Polymarket) and off-chain (Kalshi) prediction markets to LEVIATHAN's signal engine and regime priors, and optionally places/monitors prediction market hedges subject to risk-guard approval.

- **Backend:**
  - Adapters: Polymarket (on-chain, USDC; REST+WS), Kalshi (off-chain, USD; REST+WS); extensible adapter interface.
  - Normalization: binary and multi-outcome → probability vector p_i ∈ [0,1], sum=1 within ε=1e-6 after fees/mid aggregation; confidence score [0,1] from liquidity depth, spread, volatility.
  - Taxonomy mapping: MarketContract → InternalEvent via keyword/tag/manual priority rules.
  - Hedging: HedgeIntent with side/threshold/max_notional/expiry → RiskGuard approval → venue-specific orders → fill monitoring.
  - Data products: stream topic prediction.priors.v1 {internal_event_id, p_vector, confidence, source_breakdown}; snapshot table prediction_market_quotes; hedge state table prediction_hedges.
  - Poll intervals: 2s active / 30s inactive (Polymarket); 2s order book / 10s quotes (Kalshi).
  - Liquidity floor: depth ≥$5k within 2% of mid required for hedging; else 422.
  - Dispute handling: mark confidence=0; freeze hedging until resolution.

- **Data model:**
  - `pm_sources` — registered on/off-chain providers.
  - `pm_markets` — unique (source_id, external_market_id); state machine draft→open→closed→resolving→resolved/invalid/void.
  - `pm_outcomes` — unique (market_id, external_outcome_id); scalar outcomes support min/max/tick_size.
  - `pm_outcome_quotes` — append-only time-series; unique (outcome_id, ts).
  - `pm_resolutions` — dispute_round and resolution_state; on-chain tx_hash in source_tx.
  - `pm_positions` — outcome or market-scoped for binary/categorical or scalar.
  - `pm_hedge_orders` — reference market/outcome and optionally a position; on-chain tx_hash.
  - `pm_signal_links` — weight/decay params for regime prior contribution; deactivating does not delete historical data.
  - `pm_sync_events` — ingestion/sync/backfill observability and replay.

- **Frontend:**
  - Markets Directory: virtualized list (>1k markets) with filters (venue, category, expiry, liquidity, spread, oracle).
  - Market Detail drawer: real-time probability chart, order book depth, resolution criteria, fees; "Add as Prior" modal with weight/transformation/smoothing params.
  - Hedge Rules: threshold/delta triggers, hedge ratio, order type, max slippage, time-in-force, venue priority.
  - Execution Panel: live OMS status, PnL of hedge leg; on-chain wallet connect with gas estimate; off-chain session status.
  - Audit tab: mapping changes, approvals, automation toggles.
  - Provider connectivity state: Connected/Degraded/Disconnected. Wallet state (on-chain): Not Connected/Connected/Approval Needed.

- **Depends on:** Feature Store (output: prediction.priors.v1 written here, consumed there), Decision Engine (reads priors as regime input), Risk Guard/Limits (approves hedge intents, enforces exposure caps), OMS/Execution (places hedge orders), FX Service (currency conversion at quote_ts), Secrets Manager (venue API keys).

- **External:** Polymarket (on-chain EVM), Kalshi (regulated off-chain platform), EVM-compatible wallet/RPC node.

- **Notes:** Architecturally novel — the only feature that crosses both on-chain and off-chain markets with real capital. KYC/venue eligibility gating for hedging endpoints is a compliance requirement with no clear owner in the PRD. On-chain tx_hash fields in the data model indicate direct blockchain interaction, requiring custody/wallet infrastructure not explicitly specified elsewhere. Dispute handling (confidence=0, freeze hedging) is risk-critical and must integrate with kill-switch mechanisms in Risk Safeguards.

---

### regime-awareness

- **Purpose:** Computes and publishes a composite market regime signal (integer −2 to +2) from dealer positioning, flow, dark pool, and macro tilts using versioned, dual-approved weights; outputs confidence/readiness state to gate playbook execution across the decision engine.

- **Backend:**
  - Composite: weighted sum (default weights: dealer 0.30, flow 0.30, dp 0.20, macro 0.20); winsorize inputs ±4.0; clamp output [−2, +2]; discretize via thresholds.
  - Confidence: windowed stability over N=30 and N=120 bars; persistence factor; readiness: READY (≥0.7), DEGRADED (0.4–0.7), HOLD (<0.4).
  - Weight learning: agent proposals via ØMEGA bridge → ROLE_RESEARCH propose → ROLE_RISK approve → SYSTEM activate. Constraints: each weight [−2, 2], L1 norm ≤3.0, min 2 non-zero components, composite variance ≤2x baseline over 90 days.
  - Late data: if <2 components, carry-forward last regime with carried_forward=true; emit correction for late arrivals within 2 bars.
  - SLA: P99 ≤100ms end-to-end per symbol; throughput ≥50k symbols × 1s bars.
  - Events: regime.updated, regime.weights.versioned.

- **Data model:**
  - `regime_signal_input` — unique(ts, scope_type, scope_id, window_sec, tilt_type, source_version); tilt_type ∈ {dealer, flow, dp, macro}.
  - `regime_composite_score` — composite_bucket INT [−2,+2]; confidence_score [0,1]; readiness_state ∈ {blocked, cautious, ready, aggressive}; weights_set_id FK; carried_forward bool; revision int; inputs_hash for reproducibility.
  - `regime_weight_set` — status ∈ {draft, validated, active, superseded, rejected}; effective_from/to; validation_result_id.
  - `regime_weight_item` — per tilt_type weight; many-to-one to weight_set.
  - `regime_validation_result` — status ∈ {pass, fail, warning}; metrics (Sharpe, corr, stability, hit_rate) and dataset/time bounds.
  - `regime_update_event` — immutable journal of weight lifecycle transitions with ØMEGA bridge correlation.

- **Frontend:**
  - Composite score card: −2..+2 integer with label (Strong Negative → Strong Positive), color (red/gray/green) + icon/arrow, timestamp, "Stale" badge if age >60s.
  - Factor breakdown: standardized score per tilt, applied weight, 60-min sparkline; missing factors marked N/A.
  - Confidence bar: 0–100% with Low/Medium/High label; readiness badge (Ready/Caution/Not Ready).
  - Weight learning panel (Quant PM/Risk Manager only): editable table, sum=1.00 ±0.01 validation, proposal lifecycle (Draft→Submitted→Pending Validation→Passed/Failed); "Apply to Agents" button gated on Passed status.
  - Stream at 1 Hz; disconnect banner after 5s.

- **Depends on:** Signal Detection / Data Pipeline (dealer_z, flow_z, dp_z, macro_z inputs); Feature Store (factor values); Decision Engine (reads regime for playbook gating); Operator UI (displays regime in Today Panel); ØMEGA bridge (weight proposal pathway); Research RBI Lab (validation_ref from backtest results).

- **External:** None.

- **Notes:** The readiness_state enum differs between backend PRD ({READY, DEGRADED, HOLD}) and database PRD ({blocked, cautious, ready, aggressive}) — a direct contradiction that must be resolved before implementation. The weight learning dual-control (PROPOSE via Research/Agent, APPROVE via Risk) mirrors the pattern in MCP Co-Agent but is specific to regime weights. Scope dimension (global/book/sector/instrument) in DB PRD extends the backend PRD's simpler (global/class/symbol) — the DB PRD is more granular.

---

### research-backtesting-lab

> **STATUS: ARCHIVED** — All three PRDs are archived variants (filename prefix: `archived`).

- **Purpose:** Read-only preservation layer for legacy Research & Backtesting Lab runs and artifacts, superseded by research-rbi-lab (active) and strategy-portfolio-builder. Provides safe browsing, WORM-compliant read access, signed artifact URLs, and migration CTAs to successor features.

- **Backend:**
  - All mutating methods (POST/PUT/PATCH/DELETE) return 410 Gone with ARCHIVED_RESOURCE code and migration.redirect_to pointers.
  - GET endpoints: /v1/archived/lab/projects, /experiments, /backtests, /backtests/{id}/results, /artifacts/{id}.
  - Artifacts served via signed, time-limited URLs (≤10min TTL); access re-validated at download.
  - Roles: Admin, Compliance, Risk, Researcher-ReadOnly. Default deny.
  - Pagination: cursor-based; rate limit 120 req/min per user.
  - Data retention: 7 years default; expired resources return 404 with ARCHIVE_EXPIRED.

- **Data model:**
  - `archive_batch` — import provenance groupings with checksum.
  - `archive_run` — immutable; status ∈ {completed, failed, partial, unknown, superseded}; code_hash and engine_version for reproducibility; new_strategy_id/new_backtest_id nullable cross-system links to successors.
  - `archive_run_metric` — aggregates and per-asset metrics.
  - `archive_run_series_point` — time-series equity, PnL, drawdown.
  - `archive_artifact` — files (notebooks, plots, logs, reports); encryption_key_id optional.

- **Frontend:**
  - Legacy routes remain resolvable (/lab, /lab/projects, /lab/runs/:id); page-level "Archived module" banner on all /lab/* pages with CTAs to Backtesting & Simulation and Strategy & Portfolio Builder.
  - All mutating controls hidden/disabled with tooltip "Unavailable in archived module."
  - "Duplicate to…" modal prefills draft in target module with field mapping; unmapped fields surfaced.
  - Export: JSON/CSV/PNG where data exists.
  - Responsive to 360px; WCAG AA.

- **Depends on:** research-rbi-lab (successor), strategy-portfolio-builder (successor), backtesting-simulation (successor — not in the 21-folder scope).

- **External:** None.

- **Notes:** ARCHIVED — do not build new functionality here. This is a near-duplicate/predecessor of research-rbi-lab. The distinction: research-backtesting-lab is the archived legacy system; research-rbi-lab is the active replacement implementing NAUTILUS gating, Monte Carlo, and walk-forward analysis. The migration pointer `migration.redirect_to` in archive API responses must point to research-rbi-lab endpoints. Legal hold (legal_hold=true) overrides purge — compliance must confirm retention policy.

---

### research-rbi-lab

- **Purpose:** Active research and certification lab for trading strategies before paper trading — implements Strategy Genome registration, 50x Monte Carlo robustness testing, walk-forward optimization, regime-stratified testing, and NAUTILUS gate evaluation that enforces objective thresholds before OMS paper-trade enablement.

- **Backend:**
  - Entities: StrategyGenome (immutable spec; unique on code_hash+param_hash+feature_versions), Experiment, MonteCarloRun (50x default, max 500), WalkForwardRun, RegimeTest, GateEvaluation (NAUTILUS).
  - NAUTILUS gate rules: OOS Sharpe ≥1.2 (median WF folds), max DD ≤15% OOS and ≤1.1× IS DD, MC 5th pct CAGR ≥0, no regime Sharpe <0.5, CV of regime performance ≤1.0, OOS trade count ≥300.
  - Leakage checks: disallow future features; cross-verify timestamps; block bootstrap when autocorr > threshold.
  - Endpoints: POST /strategies/genome, /experiments, /experiments/{id}/monte-carlo, /walk-forward, /regime-tests, /gates/nautilus/evaluate, /gates/nautilus/override, /paper-trade/enable.
  - Events: rbi.experiment.started/completed/failed, rbi.nautilus.gate.decided, rbi.papertrade.enabled.
  - Performance: MC 50x must complete <5min for 1-year 1-min bars; max 5 concurrent runs/genome.

- **Data model:**
  - `strategies` / `genome_sets` — parameter snapshots.
  - `research_experiments` — kind ∈ {MONTE_CARLO, WALK_FORWARD, REGIME_TEST, PAPER_TRADE_GATE}.
  - `experiment_runs` — seed + config for determinism; unique reproducibility_hash.
  - `monte_carlo_settings` — num_iterations default 50, max 500; run_index dense [0..N-1].
  - `walk_forward_windows` — non-overlapping folds; in_start < in_end < out_start < out_end.
  - `regime_definitions` / `regime_assignments` — contiguous or gapped labeling per symbol/venue/timeframe.
  - `backtest_results` / `equity_timeseries` / `sim_trades` — per-run outputs.
  - `nautilus_gates` — status PENDING→PASSED/FAILED; PASSED→EXPIRED/REVOKED.
  - `approvals_audit` — immutable gate review actions.

- **Frontend:**
  - Workbench: left Setup Panel (Data/Universe/Strategy/Tests), center Results Canvas (Genome/MC/Walk-Forward/Regimes/Summary tabs), right Run Queue & Logs.
  - Monte Carlo: cap at 50 for non-admin; fan charts, distribution charts (P5/P50/P95).
  - Walk-Forward: max 200 folds; per-fold metrics, parameter drift.
  - Regime tests: built-in or Feature Store labels; coverage warning if regime <10% OOS bars.
  - NAUTILUS gate: criteria form → approval workflow (Risk Manager only) → "Enable Paper Trade" toggle (disabled if OMS/Risk Guard degraded).
  - Export: ZIP with config.json + per-module CSVs + checksum.

- **Depends on:** Feature Store (feature data, regime labels), Backtesting engine (execution), OMS (paper-trade/enable publishes event), Risk Guard (gate condition check), Regime Awareness (regime labels input), research-backtesting-lab (archived predecessor for migration).

- **External:** None.

- **Notes:** Successor to research-backtesting-lab (ARCHIVED). The NAUTILUS gate is the critical capital-protection mechanism before any live/paper trading — the risk_manager override capability must be tightly audited. Monte Carlo cap at 50 in UI (500 at API level) is a deliberate UX safeguard. Walk-forward lookahead detection is a hard requirement for data integrity. Regime test InsufficientData must exclude sparse regimes from gate failure counts unless flagged as critical — this conditional logic needs explicit specification in the gate policy configuration.

---

### risk-limits-compliance

- **Purpose:** Backend services and operator UI for pre-trade risk enforcement, real-time risk/PnL monitoring, immutable audit trail, approval workflows, kill-switches, and post-trade TCA analytics — the primary compliance backbone for LEVIATHAN.

- **Backend:**
  - Pre-trade validation (sync path): validates account ACTIVE, kill-switch OFF, credit, max_order_qty, notional vs gross/net exposure, leverage, order rate; HARD breach → reject; SOFT breach with approvals_required → return approval_token.
  - Real-time Risk/PnL (stream-first): MTM PnL, realized PnL, rolling/max drawdown, VaR-lite (EWMA; 95/99% configurable), exposures by venue/currency, leverage, limit utilization %; update ≤50ms p95 from tick.
  - Kill-switch levels: GLOBAL, FIRM, ACCOUNT, STRATEGY, VENUE; idempotent; cancel open orders if configured.
  - Approvals: type LIMIT_OVERRIDE / KILL_SWITCH_RELEASE / BIG_TRADE; TTL 5 minutes; two-person for big-trade.
  - TCA: T+0/T+1 slippage vs arrival/mid/TWAP, venue quality (fill rate, latency p50/p95, reject rate).
  - Audit Events: hash + sequence_id; WORM; hot 365 days, cold archive 7 years.
  - Alerts: PagerDuty/Slack/Email/Webhook; dedup 60s; escalation tiers Trader→Risk→Admin.
  - gRPC/REST; all responses include audit_id. RBAC roles: TRADER, RISK_OFFICER, ADMIN, VIEWER, OPERATOR, OMEGA_AGENT.

- **Data model:**
  - `risk_policies` / `risk_limit_rules` / `stop_rules` — versioned via immutable records; active = now() BETWEEN effective_at AND expires_at.
  - `pnl_timeseries` / `risk_exposures` / `risk_metrics` — append-only time-series by scope+symbol+venue+ts.
  - `limit_breaches` / `stop_events` — reference originating policy/rule.
  - `kill_switches` — active=true blocks OMS; deactivation requires approval.
  - `approvals` — pending→approved/rejected; expiry invalidates; all transitions audited.
  - `alerts` / `alert_dispatches` — retry capture; per-rule throttle.
  - `tca_fills` / `venue_quality_metrics` — join to trades/venues externally.
  - `audit_logs` — polymorphic target; minimum 7-year retention.

- **Frontend:**
  - Limits Matrix: inline edit with cross-field validation (max order size ≤ net exposure; leverage × NAV ≤ policy cap); bulk edit with diff preview.
  - Real-time Risk Dashboard: PnL tiles, sparklines (1m/5m/1h), position drilldown, VaR-lite gauge.
  - Kill-switch: MFA + reason to arm; 3-step confirm with scope selection and optional TTL auto-release.
  - Compliance Audit Log: filterable/exportable (100k row cap); approvals queue with bulk approve/reject.
  - Alert Rules: triggers on soft/hard breach, PnL drawdown, VaR exceed, data staleness; channels Slack/Email/PagerDuty; test notification button.
  - TCA: slippage distribution charts, venue quality heatmap, strategy-grouped order table; CSV export.

- **Depends on:** OMS/Order Gateway (orders, fills, gateway status), Market Data (marks for MTM), Risk Safeguards (overlapping kill-switch and staleness concepts), Security Compliance Hardening (WORM audit), ØMEGA bridge (OMEGA_AGENT role for approval requests).

- **External:** PagerDuty, Slack, Email (alert delivery).

- **Notes:** Significant functional overlap with risk-safeguards — both implement kill-switches, staleness blocks, exposure caps, and audit trails. Key distinction: Risk Limits & Compliance is the comprehensive compliance-grade system with TCA, VaR, and multi-level approvals; Risk Safeguards is the lightweight, low-latency hard-stop layer. In production, these must share a single authoritative kill-switch state to avoid race conditions where one system allows an order the other has blocked. The OMEGA_AGENT role creating approval requests via the Secure Agent Bridge is an architecturally significant capability that must be tightly scoped.

---

### risk-safeguards

- **Purpose:** Lightweight, hard-stop risk guardrails that block automated order submission when stale data (>5min), kill-switches, exposure cap breaches, Kelly cap violations, or loss circuit breakers are detected — evaluated synchronously before any OMS submission from Decision Engine or ØMEGA.

- **Backend:**
  - Evaluation hierarchy (deny on any): global kill → provider kill → stale-data → exposure cap → Kelly cap → loss/drawdown breaker.
  - Stale-data: freshness > 300,000ms for any required stream → block automation; clock skew >2s → conservative block; unblocks automatically on fresh data.
  - Kill switches: global and per-provider; persistent across restarts; TTL auto-re-enable; stored kill state.
  - Kelly cap: equity snapshot max age 300s; EQUITY_STALE → deny.
  - Loss circuit breakers: realized + unrealized PnL daily and rolling drawdown caps; optional auto-flatten with throttle.
  - Reason codes: GLOBAL_KILL, PROVIDER_KILL, STALE_DATA, EXCEEDS_MAX_NOTIONAL, EXCEEDS_MAX_QTY, EXCEEDS_GROSS, EXCEEDS_NET, EXCEEDS_LEVERAGE, EXCEEDS_KELLY, DRAWDOWN_TRIPPED, EQUITY_STALE, INTERNAL_ERROR.
  - POST /risk/check-order returns {allowed, reasons[], evaluated_limits, freshness_ms, breaker_state}.
  - Events: safeguards.trips, risk.decisions, audit.ai_actions, limits.updated, kills.updated.
  - AI action audit: POST /audit/ai-action with correlation_id and payload_hash; append-only.

- **Data model:**
  - `risk_policies` — scope_type ∈ {GLOBAL, PROVIDER, STRATEGY, ACCOUNT}; most-specific applies; DENY overrides ALLOW.
  - `stale_data_status` — last_seen_at per provider/feed_kind; block flag; clock_skew for diagnostics.
  - `kill_switches` — is_killed bool; expires_at for TTL; historical rows preserved.
  - `circuit_breaker_state` — status ∈ {ARMED, TRIPPED, COOLDOWN}; scope and kind.
  - `exposure_snapshots` — inputs for exposure checks; time-partitioned monthly.
  - `risk_audit_log` — every evaluation and enforcement action; append-only; time-partitioned monthly.

- **Frontend:**
  - Global banner "Automation blocked: Stale data" when any stream >5min stale; per-provider freshness chips.
  - Kill switch toggle: confirmation modal with required reason, optional auto-expiry, impact scope count.
  - Kill-switch states: On/Off/Pending/Error; disabled when stale-data block active.
  - Limits & Circuit Breakers: exposure caps and Kelly fraction as progress bars (green <70%, amber 70–99%, red tripped); loss limits; "Tripped" banner with reset requiring Risk Admin role.
  - Audit Log: filterable by time/actor/action/scope; CSV export with Correlation ID.

- **Depends on:** Decision Engine (check-order calls), ØMEGA AI Integration (agent order intents), Market Data Pipeline (freshness status), OMS (order routing blocked when denied), Risk Limits & Compliance (overlapping scope — see Notes).

- **External:** None.

- **Notes:** Functional overlap with risk-limits-compliance is the primary architectural concern. Risk Safeguards is designed as a fast, in-memory synchronous check (100ms breach detection) sitting in the hot path; Risk Limits & Compliance is the authoritative policy store with VaR, TCA, and compliance-grade audit. These must be designed as a layered system — Safeguards as the fast enforcement layer reading from Limits' policy store — not as two independent systems with separate kill-switch states. The auto-flatten capability (circuit breaker trip → auto-flatten open risk) requires careful OMS integration to avoid cascading market impact.

---

### security-compliance-hardening

- **Purpose:** End-to-end institutional security primitives: KMS/HSM-backed secrets with rotation, RBAC+ABAC policy enforcement, SHA-256 integrity watchdog, policy-as-code gates, global kill-switch (two-person rule), break-glass access, and immutable hash-chained audit journal.

- **Backend:**
  - Secrets: KMS/HSM only; short-lived scoped tokens ≤15m; auto-rotation with configurable grace (default 5m); redaction in logs/metrics.
  - RBAC+ABAC: roles layered with attribute constraints (env, venue, portfolio, strategyId, time window); deny-by-default egress.
  - Break-glass: ≤30m, scope-bounded, ≥2 approvers (security.approver); all actions auto-journaled.
  - Integrity watchdog: SHA-256 hashes binaries, strategy bundles, config; drift raises severity=critical; can auto-trigger kill-switch.
  - Kill-switch: requires 2-person confirmation (unless autoKill=true on policy breach); halts new orders within 1s, cancel in-flight within 3s.
  - Policy-as-code: signed bundles; evaluate allow/deny with explain; all evaluations logged.
  - Audit: append-only hash-link chain (SHA-256(prev_hash ∥ canonical_event)); HSM-detached signatures.
  - Events: security.audit.append, security.kill.stateChanged, security.integrity.drift, security.policy.denied, security.secret.rotated.

- **Data model:**
  - `kms_keys` → `secrets_registry` → `secret_versions` — sealed envelope only; no plaintext.
  - `principals` ↔ `roles` via `principal_roles`; `roles` ↔ `permissions`; `attribute_policies` with ALLOW/DENY effects and priority.
  - `break_glass_requests` — status ∈ {REQUESTED, APPROVED, DENIED, EXPIRED, REVOKED}; expires_at mandatory on APPROVED.
  - `audit_journal` — append-only; hash = SHA-256(prev_hash ∥ canonical_event); sig from HSM; WORM ≥7 years.
  - `integrity_artifacts` — baseline_hash vs observed_hash; drift=true on mismatch.
  - `kill_switch_state` — singleton per scope ∈ {ARMED, ENGAGED, DISENGAGED}; references audit_journal.
  - `policy_artifacts` — SHA-256 of policy bundle; monotonic versioning.
  - `evidence_items` — content-addressed SHA-256 artifacts for regulatory audits.
  - `token_issuances` — expires_at indexed for TTL enforcement.

- **Frontend:**
  - Secrets: always masked (last 4 chars visible); one-time reveal (60s, MFA required, auto-remask).
  - Integrity watchdog panel: monitored items with hash, last check, status (OK/Drift/Unverified), signed bundle status.
  - Policy-as-code gates view: pass/fail per policy with failing rule IDs; blocks deploy/execute controls.
  - Kill-switch: current state (Disarmed/Armed/Engaged); dual approval + MFA + TTL; persistent red banner when Engaged.
  - Break-glass: in-app approval notifications; temporary access badge with expiry countdown; auto-revoke.
  - Audit timeline: immutable (no edit/delete), filterable, exportable; "Evidence Pack" bundle download (policies + approvals + artifacts + checksum).
  - Security dashboard: counters for auth failures, secret reveals/rotations, policy denials, integrity drifts, kill-switch events.

- **Depends on:** All services (consumes this feature for authN/Z); Risk Limits & Compliance (kill-switch coordination); MCP Co-Agent Control (agent attestation); ØMEGA AI Integration (mTLS material); Monitoring Telemetry (audit counter exports).

- **External:** KMS/HSM (vendor not specified); HSM for signature generation.

- **Notes:** The kill-switch in Security Compliance Hardening is the fourth kill-switch implementation across the PRDs (others in Risk Safeguards, Risk Limits, MCP Co-Agent). This one operates at the security/infrastructure layer (can halt OMS and pause decision engine) rather than the trading-risk layer. All four must be architecturally unified under a single kill-switch arbiter service. The SHA-256 watchdog auto-triggering the kill-switch is a critical automated safety mechanism that must be tested with fallback logic to prevent false-positive system halts. Break-glass dual-approval is a high-availability concern — if approvers are unavailable in an emergency, there must be a documented escalation path.

---

### self-learning-agent-council

- **Purpose:** Orchestrates a closed-loop research → experiment → critic → scribe workflow where AI agents continuously test trading hypotheses, validate statistical edges, enforce data-leak checks, and journal outcomes (TL;DR + artifacts) to an Obsidian vault for operator review and ØMEGA coordination.

- **Backend:**
  - Session lifecycle: hypothesis → experiment runs (grid or walk-forward) → leak checks → critic evaluation → scribe publication.
  - Leak check violations (future features, label bleed, train/test overlap, cross-split contamination) block publish with 422.
  - Critic: automated statistical validation vs thresholds/guardrails; quorum policy configurable; reviewer can override.
  - Scribe: composes TL;DR.md, hypothesis.md, critique.md, equity_curve.png, fills.parquet, metrics.json, config.json, checksums.json to Obsidian vault path /Leviathan/Council/{session_id}/; artifact size cap 25MB/file, 200MB/session.
  - Obsidian sync: retry with backoff ×3; conflict policy: append numeric suffix.
  - ØMEGA bridge: summary notification on publish completion (deduped by session_id).
  - Idempotency: same hypothesis hash → return existing session_id.
  - SLA: launch-to-queue <200ms; status updates within 1s via stream; backtest 50k trades/s per worker.

- **Data model:**
  - `council_sessions` — omega_corr_id for ØMEGA bridge traceability.
  - `research_items` → `hypotheses` — with assumptions/priors; link signals via `hypothesis_signal`.
  - `dataset_snapshots` — immutable; hash UNIQUE; holdout integrity enforced.
  - `experiment_runs` — reproducibility_hash UNIQUE; FAILED status captures partial runs.
  - `experiment_metrics` / `experiment_timeseries_ref` — aggregates in DB; large series referenced externally.
  - `critiques` — score and verdict required; reference hypothesis and/or experiment_run.
  - `decision_records` — one final per hypothesis per session; interim drafts allowed.
  - `scribe_entries` — TL;DR required for synced status; sync_status: pending→synced/error.
  - `artifacts` — URI UNIQUE; linked to scribe_entries.

- **Frontend:**
  - Council Session workspace: states Draft→Researching→Experimenting→Critique Pending→Revisions Required→Approved→Published.
  - Research panel: concept fetch, signals preview, hypothesis editor with AI assist.
  - Experiment panel: parameter matrix, live console (Queued/Init/Running/LeakCheck/Complete/Failed), leak check results card.
  - Critic review: metric rollups, robustness grid by regime/symbol/timeframe, Approve/Request Revisions/Attach Risk Notes.
  - Scribe composer: editable TL;DR sections, artifact picker, vault path preview, dry-run diff, Obsidian note link on success.
  - History: side drawer with past sessions, metric diffs, quick clone.

- **Depends on:** Feature Store (signal/feature data for experiments), Backtesting engine (experiment execution), Regime Awareness (regime labels for robustness grid), Research RBI Lab (overlapping experiment/validation patterns), ØMEGA AI Integration (bridge notification), Obsidian vault (external sync target), Security Compliance Hardening (vault path allowlist, artifact size caps).

- **External:** Obsidian vault (user-managed; connected via vault_id/path config).

- **Notes:** Overlaps significantly with research-rbi-lab — both implement strategy experiment workflows with leak checks, critic/gate evaluation, and artifact publication. Key distinction: Self-Learning Agent Council is autonomous (agents propose and run hypotheses without manual researcher initiation); research-rbi-lab is researcher-driven with formal NAUTILUS gating for paper-trade promotion. The two features should share the leak-check engine to prevent divergent implementations. Obsidian vault as an external dependency introduces availability risk for the scribe publication step; the queue-and-retry mechanism is critical.

---

### signal-detection

- **Purpose:** Produces time-synchronized, deduplicated market structure signals (MSB/BOS, trend state, compression/expansion, divergences) and normalizes third-party overlay outputs (Market Cipher, Algo Pro, LuxAlgo, QuantPad) under a unified SIREN schema for downstream decisioning and research.

- **Backend:**
  - Detectors: MSB/BOS (market structure break), trend state (uptrend/downtrend/range/transition), compression/expansion (ATR/bands/volatility percentile), divergences (regular/hidden between price and RSI/MACD/OBV), SIREN overlays (normalized from 4 external providers).
  - Signal schema (ULID id): ts_event, ts_ingest, symbol, venue, timeframe, detector_type, direction, state, label, confidence [0..1], ref_levels, structure_points, oscillator_pair, overlay metadata, quality flags, provenance (input_ids, feature_versions, detector_version), dedupe_key.
  - Time alignment: bar-close computation; intra-bar provisional events allowed; finalized=true at bar close.
  - Watermarking: out-of-order tolerance 2s RT; late events within 2 bars → revision=true; beyond 2 bars → store only, no republish.
  - Exactly-once: dedupe per (symbol+timeframe+detector+pivot_ids) within sliding 1-day window.
  - SLO: P99 detection latency ≤50ms from bar close; throughput 200k signals/min; availability 99.95%.
  - Backfill: POST /signals/backfill → async job; deterministic given same inputs and detector_version.

- **Data model:**
  - `detection_run` — time-bounded, idempotent execution context per instrument+timeframe.
  - `signal_event` — atomic, immutable; dedupe on (instrument_id, timeframe, event_ts, signal_type, state_version); JSONB details for provenance.
  - `signal_state` — rolling state snapshot for efficient Decision Engine reads; unique (instrument_id, timeframe, as_of_ts).
  - `indicator_sample` — normalized indicator/overlay values for provenance and replay.
  - `structure_pivot` — confirmed swing points backing MSB/BOS.
  - `overlay_mapping` — versioned config registry mapping external overlay semantics to SIREN codes.
  - Partitioned by month on event_ts; GIN on JSONB details.

- **Frontend:**
  - Chart canvas with signal overlays: MSB/BOS markers (directional arrows at break candle, color-coded), Trend State band (bottom strip, 4 colors), Compression/Expansion shaded channels (hatch patterns), Divergence dashed lines with oscillator subpane, SIREN preset badges (MC/AP/LA/QP tags on bars).
  - Signal Feed panel: streaming list with filters for type/SIREN preset/side/min confidence/"Only 4-layer confirmed."
  - Inspector tooltip: timestamp, confidence, layer confirmations (Data/Visual/Indicator/Decision), latency, IDs for audit.
  - Status strip: Live/Syncing/Stale/Error with latency and last event timestamp.
  - Performance: ≤16ms per frame; debounce at 60Hz.

- **Depends on:** Market Data Pipeline (OHLCV, trades, quotes), Feature Store (precomputed indicator buffers, swing points, overlay feeds), Decision Engine (primary consumer of signals.v1.rt), Regime Awareness (cross-timeframe context tags), Monitoring Telemetry (detector-level metrics and traces).

- **External:** Market Cipher, Algo Pro, LuxAlgo, QuantPad (overlay signal feeds — normalized to SIREN; vendor-proprietary visuals explicitly excluded from UI).

- **Notes:** The SIREN normalization layer is architecturally significant — it insulates LEVIATHAN from vendor-specific overlay formats and licensing constraints. The UI explicitly states "cannot display vendor-proprietary visuals — only mapped equivalents." Multi-timeframe coherence rule (no back-propagation of higher TF states to lower TF) is a critical correctness constraint for the decision engine. The 4-layer confirmation filter (Data/Visual/Indicator/Decision) is a novel signal quality mechanism not defined in detail in the backend PRD — the mapping between these layers and detector_type must be specified.

---

### signal-session-state-detection

> **STATUS: ARCHIVED** — Only a backend PRD file exists (no database or frontend PRD files in this folder).

- **Purpose:** Legacy compatibility adapter (read-only) for the retired Signal, Session & State Detection feature. Translates legacy signal/session/state API requests to the canonical Indicator State Engine and Signal/State DB, with deprecation headers and migration guidance to successor endpoints.

- **Backend:**
  - Legacy detection logic permanently disabled. No new computations or writes.
  - Read-only adapter: GET /v1/legacy/signals/{id}, /sessions/{id}, /states/{entity_type}/{entity_id}.
  - All mutations return 410 LEGACY_ARCHIVED with successor endpoint Link header.
  - Translation: legacy state enums → canonical via versioned mapping table; unmappable → 422 UNMAPPABLE_STATE or 200 with degraded=true.
  - Deprecation headers on all 2xx: Deprecation: true, Sunset: <ISO8601>, Link: </v2/signals/{id}>; rel="successor".
  - Feature flag ARCHIVED_TRUTH_VALIDATION_LEGACY_READS for hard-sunset mode (all reads → 410).
  - SLA: P50 ≤30ms, P95 ≤120ms; cache canonical lookups 250ms TTL; circuit breaker on upstream failure.
  - Rate limit: 200 RPS per tenant per route.

- **Data model:** No database PRD file present. Reads from canonical Signal/State DB and Indicator State Engine APIs; legacy tables remain read-only for audit and deterministic ID aliasing only.

- **Frontend:** No frontend PRD file present. Migration is handled via deprecation headers and API-level guidance.

- **Depends on:** Signal Detection / Indicator State Engine (canonical data source for translation), Monitoring Telemetry (metrics: legacy_adapter_requests_total, legacy_translation_degraded_total).

- **External:** None.

- **Notes:** ARCHIVED — only a backend adapter. Database and frontend PRDs are absent from the folder (only one file exists). The successor is signal-detection (active). The mapping table (legacy→canonical enum translation) is a critical artifact that must be version-controlled and audited as a config-managed resource. Multi-tenant isolation is explicitly enforced — cross-tenant access returns 404 (not 403) to avoid existence leakage. Architectural note: this adapter must be decommissioned after all consumers migrate to /v2/signals/*.

---

### strategy-ingestion-learning-engine

- **Purpose:** Backend service and UI for ingesting strategy content (URLs, files, audio/video), transcribing/parsing/chunking with lineage, generating deterministic MT4/MT5/Python/Pine strategy code, integrating crypto data feeds and tick archives, bi-directionally syncing with Obsidian (Hermes self-learning core), and providing governed manual execution with risk rails.

- **Backend:**
  - Inputs: URLs (YouTube/Vimeo/HTML, robots-aware crawler), files (PDF/MD/DOCX/CSV/MP4/WAV/ZIP, 2GB max, AV scan required), tick data (CSV/Parquet with [ts,symbol,bid,ask] or [ts,symbol,price,size]).
  - Processing pipeline: transcription (diarization optional, confidence scores) → parsing (clean text, table/code extraction, offset preservation) → chunking (512–2048 token windows, embeddings, tag inference) → lineage recording (origin, transform steps, hash).
  - Codegen: deterministic templates + rule-based transformers; zero external AI calls by default; compile-ready MQL4/5, Python bot scaffold, Pine v5; static analysis + compile check + dry-run import.
  - Backtesting: walk-forward, Monte Carlo, daily parameter sweeps; paper/live parity flags; supports tick archives and provider feeds.
  - Obsidian sync: bi-directional; conflict: last-writer-wins + versioned snapshots; TL;DR, code artifacts, backtest reports, lineage manifests.
  - Manual execution: place/modify/cancel orders via connectors; enforce risk rails (max notional, daily loss, allowed symbols); tag with strategy_ref; full audit.
  - Crypto data adapters: selectable providers; normalize to unified schema; backfill + live stream registration; credentials via secrets manager.

- **Data model:**
  - `ingestion_source` → `document_asset` → `transcription_segment` / `content_chunk`.
  - `tag` ↔ `document_tag` (methodology/asset/timeframe/regime tags).
  - `strategy` → `strategy_version` → `code_artifact`; `codegen_job` ties inputs to artifacts.
  - `strategy_version` → `backtest_run` → `dataset` → `provider`.
  - `tick_ingest_job` → `dataset`; `data_quality_issue` for ordering gaps/duplicates/schema violations.
  - `obsidian_vault` → `obsidian_note`; `obsidian_lineage_link` bridges notes to any entity.
  - `manual_order` + `audit_event` for governance; checksums on code artifacts for reproducibility.
  - `lineage_edge` for end-to-end provenance from source to code to backtest.

- **Frontend:**
  - "New Strategy" wizard: Step 1 Source (URL/file drag-drop), Step 2 Process (transcription/parse progress, chunking summary, auto-tags preview), Step 3 Lineage (checksums, Obsidian sync enable), Step 4 Confirm.
  - Codegen panel: target selector (MT4/MT5/Python/Pine), "Deterministic only" toggle (shows template version/hash/zero-AI badge), code preview with diff vs last build.
  - Data feeds: provider selector with status/API key state, rate-limit indicator, symbol mapping preview.
  - Tick upload: column mapping (auto-detect with confidence %), quality report (ordering errors/duplicates/gaps), approve/halt decision.
  - Backtest: engine target, walk-forward + Monte Carlo config, equity/drawdown/metrics charts, CSV/JSON export.
  - Obsidian sync: vault health, folder picker, auto-sync toggle, conflict diff viewer.
  - Manual execution: "Send to Manual Desk" (Operator only), risk rails displayed and enforced.

- **Depends on:** Feature Store (output: strategy embeddings and chunks), Backtesting engine (run jobs), OMS/connectors (manual execution), Risk Safeguards (risk rails on manual orders), Obsidian vault, Monitoring Telemetry (audit events), Secrets Manager (provider credentials), Self-Learning Agent Council (Obsidian vault shared dependency).

- **External:** YouTube/Vimeo/HTML content sources, crypto data providers (selectable), Obsidian vault, MQL compiler (Windows build-runner).

- **Notes:** The MQL compiler dependency requires a Windows build-runner, which is an unusual infrastructure constraint for an otherwise Linux-likely stack. AV scan requirement on file uploads implies an antivirus service integration not explicitly specified. Obsidian sync (bi-directional with Hermes) creates a shared external dependency with Self-Learning Agent Council — the same vault must be accessible to both features without conflicts. "Zero external AI calls by default" for codegen is an important safety/licensing property that must be enforced at the API gateway level, not just via UI toggle.

---

### strategy-portfolio-builder

- **Purpose:** Enables operators to compose, validate, and activate deployable strategy portfolios by assembling parameterized Playbook templates with Risk Rails (fractional Kelly, per-symbol/sector caps, net gamma caps) and Overlap Guard / de-correlation constraints, producing versioned, hash-signed configurations for the Decision Engine.

- **Backend:**
  - Playbook templates: flow_momentum, dealer_pin_mean_rev, earnings_iv_crush, macro_hedge.
  - Strategy lifecycle: draft → validated → staged → active → archived; immutable once active; new versions create strategy_revision with semantic version and content hash.
  - Portfolio: collection of strategies with weights (sum to 1.0 ±1e-6); same lifecycle.
  - Overlap Guard: pairwise exposure cosine similarity and shared beta/sector overlap; block if ≥ threshold; return conflicting components.
  - De-correlation: portfolio correlation matrix max off-diagonal ≤ configured limit over lookback; reject or auto-reweight.
  - Fractional Kelly: 0 < kelly_fraction ≤ 1; exceeding cap → clamp and log risk_breach event.
  - On activation: publish to Decision Engine and Risk Guard; emit routing config to OMS; signed with revision hash.
  - Synchronous validations (≤500 instruments) p95 ≤500ms.
  - Events: strategy.events, portfolio.events, riskrails.events.

- **Data model:**
  - `strategies` / `strategy_revisions` — spec_json_hash + spec_json; risk_rails_json; exposure_snapshot per revision.
  - `portfolios` / `portfolio_revisions` — parallel lifecycle to strategies.
  - `playbook_templates` — type, schema_json, default_params.
  - `risk_policies` — defaults per org; fractional Kelly, exposure caps, gamma caps.
  - `exposure_snapshots` — time-series vectors (holdings, sectors, Greeks); append-only; tiered retention 30–90 days.
  - `correlation_snapshots` — rolling pairwise correlations; pair-order canonicalized.
  - `evaluation_runs` — periodic/scheduled overlap and correlation checks.
  - `guardrail_events` — policy breach/block with audit details; action=block prevents order submission until resolved.
  - `audits` — entity_type, entity_id, revision_id, actor, action, diff, ts.

- **Frontend:**
  - Builder layout: left Playbook Library (search, filter, tooltip docs), center Builder Canvas (Playbooks/sleeves with expandable parameter forms), right Risk & Correlation Panel.
  - Risk Rails editor: live validation chips; fractional Kelly ≤2 decimal precision; hierarchical consistency check (per-symbol cap ≤ per-sector cap ≤ portfolio cap).
  - Exposure Breakdown: bar charts by symbol/sector/Greek.
  - Correlation Matrix: colorblind-safe heatmap; lookback selector (20/60/120d); enforce toggle and threshold slider.
  - Overlap Guard: conflict list with "Auto-resolve" suggestions; preview updates overlap score in real time.
  - Playbook data prerequisites: Dealer-Pin requires options OI/gamma data; Earnings IV requires earnings dates/IV history; Flow Momentum requires tape/flow features; Macro Hedges requires index/ETF/futures availability.
  - Footer: Save Draft, Validate, Submit for Approval (role-gated), Discard.
  - Roles: Quant PM/Strategy Engineer (create/edit/submit), Risk Manager (edit Rails, approve/reject), Trader/Operator (read-only, propose edits as new Draft).

- **Depends on:** Signal Engine (flow features for Flow Momentum), Decision Engine (receives activated portfolio configs), Risk Guard (receives risk rails; enforces Kelly sizing at execution), OMS (receives routing config on portfolio activation), Feature Store (factor/sector data for overlap computation, options OI/gamma for Dealer-Pin prerequisite), Regime Awareness (macro regime context for Macro Hedges), Research RBI Lab (backtests linked from portfolio builder via link-out).

- **External:** None.

- **Notes:** The activation flow publishing to both Decision Engine and Risk Guard simultaneously introduces a consistency requirement — if the Decision Engine accepts the config but Risk Guard fails, the system is in a split state. A two-phase commit or event-sourced activation pattern is needed. The auto-reweight capability (de-correlation enforcement with auto_reweight=true) is algorithmically significant and its behavior under conflicting Playbook constraints must be specified. Net gamma cap dependency on market data means "missing data → conservative default or block" is a policy decision that must be made explicit per desk.

---

### truth-validation

- **Purpose:** Validates trade intents against multi-source market "truth" (order book microstructure via Rithmic/Bookmap, options flow via Unusual Whales, event embargoes, sentiment bounds via SCYLLA) to yield a deterministic verdict (PASS/SOFT_FAIL/HARD_FAIL/UNKNOWN) before execution, fed to Decision Engine, Risk Guard, and OMS.

- **Backend:**
  - Sources with freshness SLAs: order book ≤50ms stale (Rithmic/Bookmap), options flow ≤5s stale (Unusual Whales), sentiment ≤30s stale (SCYLLA), event calendar O(1) lookup.
  - Policy resolution: strategy_id > instrument_id > asset_class > default; missing policy → SOFT_FAIL (configurable to HARD_FAIL).
  - Core checks (evaluated atomically at evaluation_ts): spread ≤ max_spread_bps, depth ≥ min_depth_qty, no crossed/locked/LULD, book pressure alignment, estimated slippage ≤ max_slippage_bps; options flow directional alignment ≥ min_flow_score and unusual volume ratio ≥ min_uvr (NOT_APPLICABLE if instrument type doesn't support options); event embargo block (EXIT with exit_override=true → PASS with EXIT_DURING_EMBARGO reason); sentiment score within [min,max] bounds.
  - Verdict: any HARD_FAIL → HARD_FAIL; any SOFT_FAIL (no HARD) → SOFT_FAIL; all pass → PASS; required data stale beyond SLA (no allow_degrade) → UNKNOWN.
  - SLA: P99 ≤15ms cached; ≤35ms with options flow and sentiment reads; no call >100ms.
  - Stream topic: stream.truth.verdicts.v1.

- **Data model:**
  - `tv_source_feed` — registered feeds with provenance.
  - `tv_fact` — normalized observations per symbol/source; dedupe on (source_id, source_event_id); append-only.
  - `tv_validation_rule` — parameterized constraints; m:n to validation runs via tv_rule_eval.
  - `tv_validation_run` — time-bounded evaluation per symbol producing truth snapshot.
  - `tv_truth_snapshot` — 1:1 to validation_run; final decision state.
  - `tv_event_embargo` — hard (blocks all) vs soft (downgrades confidence); overlapping embargoes: most restrictive wins.
  - `tv_sentiment_bounds` — min/max bounds per symbol; bounds_violated on deviation.
  - JSONB GIN on payload/params; fact table partitioned by day on observed_at.

- **Frontend:**
  - Symbol-scoped panel (dockable) and full-screen modal.
  - Four data source tiles (Order Book, Options Flow, Sentiment Bounds, Event Embargo), each with real-time metrics and freshness status (Healthy/Stale/Degraded/Missing).
  - Verdict aggregation: Valid (all Healthy/Clear), Degraded (any Degraded), Blocked (any Blocked or Active Embargo).
  - "Why" chips: e.g., "Embargo: CPI T-3m", "SCYLLA: sentiment above max", "Order book stale 7s."
  - Alignment badge: all sources within 500ms window → "In Sync."
  - Trade controls disabled when verdict = Blocked with tooltip linking back to Truth panel.
  - Bypass (Risk Manager, sim only): typed reason + banner + audit log.
  - Update cadence: 1 Hz minimum; burst to 5 Hz for order book in deep-dive.

- **Depends on:** Market Data Pipeline/Rithmic/Bookmap (order book feed), Unusual Whales (options flow feed), SCYLLA (sentiment bounds service), Economic calendar/event feed (embargo windows), Decision Engine (primary caller of /truth/validate), Risk Guard / OMS (enforces HARD_FAIL blocks), Feature Store (data freshness tracking).

- **External:** Rithmic/Bookmap (order book data), Unusual Whales (options flow), SCYLLA (sentiment scoring engine).

- **Notes:** Near-duplicate with truth-validation-order-flow-options (ARCHIVED) — see that entry for details. The 15ms P99 SLA is aggressive given the multi-source aggregation; in-memory caching of order book snapshots and in-memory policy resolution are non-negotiable for compliance. The EXIT_DURING_EMBARGO override is a critical compliance edge case that must be explicitly tested. UNKNOWN verdict on stale data is the correct fail-safe behavior — downstreams must implement the retry-once-then-escalate pattern specified in the backend PRD rather than treating UNKNOWN as PASS.

---

### truth-validation-order-flow-options

> **STATUS: ARCHIVED** — Only a backend PRD file exists (no database or frontend PRD files in this folder).

- **Purpose:** Read-only legacy compatibility layer for order-flow and options truth-validation records, preserved for backtest reproducibility and audit after migration to the active truth-validation feature (backed by Earnings/Flow/DP truth store). Provides deterministic data access with proxy-to-new store translation and explicit sunset signaling.

- **Backend:**
  - No new records created. All mutations return 405 (GET/HEAD only).
  - GET /v1/archived/truth/order-flow: symbol+venue+time range, side, limit+cursor pagination; returns legacy or proxy records with source: "legacy"/"proxy" and schema_version.
  - GET /v1/archived/truth/options: OSI identifier (OCC/OSI format required), event_type filter.
  - ETags for conditional GET (304 on unchanged); checksums stable across legacy and mapped records.
  - Feature flags: ARCHIVED_TRUTH_VALIDATION_LEGACY_READS (default ON); ARCHIVED_TRUTH_VALIDATION_PROXY_TO_NEW (default ON).
  - Proxy: when legacy record absent and proxy enabled, translate from flow_truth_v2 / options_truth_v2.
  - Deprecation headers on all 2xx: Deprecation, Sunset, X-Truth-Schema-Version.
  - 410 when feature flag off; includes migrate_to pointer.
  - SLA: P50 ≤50ms, P95 ≤150ms cached; P95 ≤300ms proxy. Legacy tables retained 18 months post-sunset.
  - Rate limit: 120 req/min per tenant.

- **Data model:** No database PRD file present. Reads from legacy archive tables (truth_validation_order_flow_legacy, truth_validation_options_legacy — read-only) and new store (flow_truth_v2, options_truth_v2) via proxy.

- **Frontend:** No frontend PRD file present.

- **Depends on:** truth-validation (active successor; provides flow_truth_v2 / options_truth_v2 for proxy reads).

- **External:** None.

- **Notes:** ARCHIVED — near-duplicate of truth-validation (active). This adapter is specifically for the order-flow and options sub-domain of the old truth-validation. The active truth-validation covers the same domain but with an expanded multi-source model. The proxy-to-new translation (legacy record absent → serve from new store with source="proxy") is a critical correctness requirement for backtest reproducibility — if the new store's schema diverges, proxied records could silently change values. The 18-month post-sunset retention is shorter than the 7-year audit retention elsewhere — compliance must reconcile this.

---

### uncategorized

This folder contains three distinct sub-features that were not categorized into named feature folders. Each is documented separately below.

---

#### uncategorized / mt4mt5-export-bridge

- **Purpose:** Backend service, database, and UI for exporting LEVIATHAN AI strategies and indicators as signed MT4/MT5 Expert Advisors or Indicators via deterministic MQL codegen, build/packaging (EX4/EX5), and secure remote deployment to registered MT terminal agents via the bridge protocol.

- **Backend:**
  - Codegen inputs: source_strategy_id or indicator_id, artifact_type (EA/INDICATOR), mt_version (MT4/MT5), params_map, symbol_map, timeframe_map, routing_mode (LocalTerminal/RemoteBridge), risk_controls, event_channels.
  - Validation: unique {source_id, artifact_type, mt_version, version_label}; param names [A-Za-z_][A-Za-z0-9_]{0,31}; symbol/timeframe mapping must resolve.
  - Build: deterministic .mq4/.mq5 with embedded metadata → MQL compiler (Windows build-runner) → signed .ex4/.ex5 + SHA256 checksum → ZIP package with manifest.json, README, license.
  - Deploy modes: download-only, staged (upload without reload), activate (upload + chart attach); canary percentage for multiple agents.
  - Bridge agent protocol: agent registers with capabilities, heartbeats every ≤10s, fetches pre-signed artifact URL, verifies checksum, reports install result.
  - Rollback: redeploy previous artifact version.
  - Build SLA: start ≤30s queue; single build ≤3min; concurrent builds 10 per runner pool.
  - Pre-signed artifact URLs: expire 15 minutes; single-use per agent.

- **Data model:**
  - `mt_codegen_templates` — unique (name, version) per platform; with `mt_param_definitions` (strongly typed, constraints, defaults).
  - `strategy_export_jobs` — references template and resolved params; status SUCCEEDED required before build_artifact creation.
  - `build_artifacts` — ex4/ex5/dll/zip with signatures and checksums; same platform as target.
  - `deployment_targets` — MT4/MT5 terminal instances; secret_ref to external secrets manager (no secrets stored here).
  - `deployments` — magic_number unique per (target_id, account_id, mode) while status in {QUEUED, DEPLOYED}.
  - `bridge_channels` — logical comms per target; state ∈ {OPEN, CLOSED, ERROR}.
  - `bridge_events` — append-only time-series; partitioned by day/week.
  - `mt_symbol_map` — per-target logical_symbol ↔ broker_symbol normalization.

- **Frontend:**
  - Export wizard: select strategy/signal snapshot → choose platform/type → auto-map params → review/edit → code preview (read-only, diff vs last build) → run build with live log stream → package → deploy.
  - Bridge status widget: connection, latency, terminals count.
  - Deploy modal: multi-terminal/account select with platform/version; destination folder; auto-reload toggle; per-target progress with checksum verification.
  - Build states: Idle→Generating Code→Compiling→Packaging→Ready/Failed; compiler output with severity badges and line-reference hyperlinks.

- **Depends on:** Strategy Ingestion & Learning Engine (strategy artifacts as codegen source), OMS (RemoteBridge routing mode calls OMS via Secure Agent Bridge), Security Compliance Hardening (code-signing certs, secrets for agent tokens), Monitoring Telemetry (telemetry from agents via bridge_events).

- **External:** MQL compiler (Windows build-runner — significant infrastructure constraint), code-signing certificate authority, MT4/MT5 terminal agents (end-user machines).

- **Notes:** The Windows-only MQL compiler requirement is a major infrastructure constraint — it forces a Windows build-runner in what is otherwise likely a Linux/container-based stack. This should be containerized via a Windows container or hosted Windows VM. The magic_number uniqueness constraint per (target_id, account_id, mode) is a critical MT platform concept preventing EA conflicts on a single chart/account. This feature partially overlaps with strategy-ingestion-learning-engine's codegen capability (which also generates MT4/MT5 code). The two features should share or delegate to the same underlying codegen engine.

---

#### uncategorized / deployment-devops

> **Note:** Only a database PRD file exists for this sub-feature (no backend or frontend PRDs in the uncategorized folder).

- **Purpose:** Database schema for CI/CD pipeline tracking, deterministic container image management, environment promotion with gated approvals, secrets indirection to KMS/Vault, IaC revision state, and deployment/rollback audit for HFT-grade traceability and compliance.

- **Data model:**
  - `services` — deployable units; parent of all pipeline/image/deployment artifacts.
  - `container_images` — digest as canonical identity (UNIQUE); deterministic=true enforced; references producing pipeline_run; SBOMs linked.
  - `pipeline_runs` — status and gate_status; with `run_steps`, `test_summaries`, and `scan_findings`.
  - `environments` — promotion_policy, freeze_until; blocked by open critical/high findings (per policy).
  - `promotions` — multi-approver workflow (min approvers, required roles); source→target environment.
  - `releases` — immutable binding of service+image+config_version; unique(service_id, image_id, config_version).
  - `deployments` — rollout strategy, canary metrics, rollback lineage (rollback_of FK); rollbacks must create audit_events.
  - `secret_refs` — external provider/path/key/version only; no plaintext; requires_restart flag.
  - `iac_revisions` — module+git_ref+plan_hash per environment; drift reports; released may pin iac_revision_id.
  - `audit_events` — approvals, freezes, promotions, rollbacks, config changes.

- **Depends on:** Security Compliance Hardening (KMS/Vault for secret_refs), Monitoring Telemetry (CI/CD pipeline metrics), all services (this feature tracks their deployments).

- **External:** Container registry, KMS/Vault, CI system (GitHub Actions or similar), IaC tool (Terraform or similar).

- **Notes:** Database-only PRD — no backend or frontend specifications in scope. A production deployment gate requires: approved promotion + deterministic image + passing tests + no open disallowed scan findings. This is the DevOps infrastructure's data contract, not a user-facing feature. Critical for HFT compliance: deterministic builds (same commit → same image digest) and freeze windows prevent unauthorized deployments during market hours.

---

#### uncategorized / crypto-flash-loan-arbitrage-engine

> **Note:** Only a frontend PRD file exists for this sub-feature (no backend or database PRDs in the uncategorized folder).

- **Purpose:** Latency-aware operator UI for discovering, simulating, and executing atomic flash-loan arbitrage routes (triangular and cross-DEX on EVM-compatible chains; CEX-DEX labeled as Flash Ineligible) with strict real-time risk locks and live settlement telemetry.

- **Frontend:**
  - Route list (virtualized, ≥500 rows <60ms scroll jank): route type, path preview (Token/venue sequence), est. profit (net), spread%, gas cost, loan size, slippage headroom, latency ETA (ms), data age (ms), MEV risk (Low/Med/High), status badge (Viable/Risk-Locked/Stale/Flash Ineligible/No Liquidity).
  - Filters: chain, base/quote token, min net profit, max gas, max hop count, MEV risk, status, venue includes/excludes.
  - Route details drawer: full path graph with per-hop quotes/depth/reserves, profitability breakdown (gross/gas/relay/flash fee/net), atomicity check and eligibility rationale, risk locks view, Simulate button (dry-run with signed timestamp).
  - Execution console (Flash mode): pre-flight gate → one-click Execute with confirmation modal → live timeline (submitted→included→settled/reverted) with tx hash, block number, gas used.
  - Risk locks (Risk role editable): max notional per token/chain/venue, per-block rate limit, token/venue blocklists, MEV High requires private relay, max slippage/gas, time-of-day window.
  - Roles: Operator (view/simulate/execute if locks permit), Risk Manager (edit locks, approve overrides), Observer (view only).
  - Data refresh target: 250ms; data age color-coded (<250ms green, 250–750ms amber, >750ms red).
  - MEV High routes require Private relay enabled — execution blocked without it.
  - CEX-DEX routes: visible for research; Execute button replaced with "Flash Ineligible" tooltip.

- **Depends on:** (Backend not specified in this PRD) — implied: on-chain routing engine, OMS/execution layer, Risk Safeguards (risk locks), Monitoring Telemetry (journaling of all user actions).

- **External:** EVM-compatible chains (config-driven list), DEX/AMM liquidity pools, private relay networks (e.g., Flashbots Protect for MEV High routes), on-chain flash loan providers.

- **Notes:** Frontend-only PRD — no backend or database specifications in scope. This is an EVM-native feature with unique infrastructure requirements (blockchain RPC nodes, private relay integration, wallet custody) that do not appear in any other LEVIATHAN feature. The MEV risk signal is a real-time input whose computation backend is unspecified. The "non-atomic CEX-DEX" label creates a useful safety guardrail — CEX legs cannot be flash-funded. Post-trade journaling must produce immutable audit entries with correlation IDs consistent with the rest of LEVIATHAN's audit patterns.

---

### visual-intelligence-layer

- **Purpose:** Backend services, database, and frontend for real-time multi-asset market visualization — heatmaps/dashboards, pattern/anomaly overlays (breakouts, volatility spikes, liquidity voids), alerting/watchlists, charting toolkit (OHLCV, indicators, order flow, L2 depth), and session/layout presets for institutional analysts.

- **Backend:**
  - Data sources: normalized market data, indicator states, and pattern detections from Stream-first Data Pipeline and Feature Store.
  - Heatmap: GET /v1/visual/heatmap (≤500 assets; P95 ≤350ms); WS topic visual.heatmap.{tenant}.{segment} (≤200ms end-to-end); refresh cadence default 1s with snapshot+delta.
  - Overlays: streamed detections stored to time-series; served via API and WS visual.overlay.{type}; retractions supported (idempotent update); historical overlay query ≤10k events/page.
  - Alerts: user-defined rule expressions (e.g., "rsi_14 < 30 and vol_spike.confidence > 0.8"); static analysis validates against allowed feature keys; cooldown dedup; delivery via WS/email/webhook (HMAC-SHA256 signed with replay protection).
  - Watchlists: asset groups used to filter heatmaps/alerts.
  - Charting: GET OHLCV (≤100k bars), indicators, order flow (tick prints/imbalance), L2 depth (≤100 levels/side); WS chart.{trades|depth|bars|indicators}.
  - Session/layouts: max 50 per user; payload ≤200KB; widgets ≤50; versioned with 409 on version mismatch.

- **Data model:**
  - `vi_dashboards` — unique(owner_user_id, name) for personal scope; 1:N `vi_panels`.
  - `vi_panels` — config JSON with rendering options; 1:N `vi_panel_data_bindings` (data_type: ohlcv/orderflow/depth/indicator).
  - `vi_heatmap_cells` — aggregated metric snapshots; composite index (symbol, venue, timeframe, ts_bucket).
  - `vi_detected_patterns` — state ∈ {open, confirmed, invalidated}; score/severity/timeframe.
  - `vi_annotations` — drawable overlays.
  - `vi_alert_rules` — expression-based; is_active flag; throttle_seconds; dedupe_hash.
  - `vi_alert_subscriptions` — unique(rule_id, subscriber_user_id, channel, target).
  - `vi_alert_events` — delivery idempotency via dedupe_hash.
  - `vi_watchlists` / `vi_watchlist_items` — unique(watchlist_id, symbol, venue).
  - `vi_chart_layouts` / `vi_sessions` — self-contained JSON snapshots; layout versioning for restore compatibility.

- **Frontend:**
  - Heatmaps: tile-based (≥2000 tiles, virtualized, 5 Hz update rate); configurable metric per tile; click to chart drawer or panel.
  - Pattern/Anomaly Overlays: Breakout Zones (shaded bands), Volatility Spikes (triangles), Liquidity Voids (hatched regions); legend with confidence and source timestamp; z-order adjustable.
  - Alerting: rule builder with condition validation and historical backtest preview ("expected trigger count"); alert inbox with acknowledge/snooze; optional sound.
  - Charting: OHLCV with MA/EMA/RSI/ATR/Volume Profile; cumulative delta; L2 heatmap; execution prints; crosshair sync across linked panels; Live and Replay (scrub bar) modes.
  - Layout presets: drag-resize grid (8px snap), 50-layout max, auto-restore last session, org-share where permitted.
  - Latency badge: green <250ms / amber 250–750ms / red >750ms or stale >2s.
  - Time sync: UTC default with local toggle; exchange TZ for session boundaries; crosshair sync across linked panels within 200ms.

- **Depends on:** Market Data Pipeline (OHLCV, trades, quotes, depth), Feature Store (precomputed indicators), Signal Detection / Indicator State Engine (pattern/anomaly overlay detections), Monitoring Telemetry (health and latency badges), Market Intelligence Terminal (overlapping visualization scope — see Notes).

- **External:** None directly; webhook delivery to user-configured HTTPS endpoints (HMAC-signed).

- **Notes:** Overlaps with Market Intelligence Terminal on visualization — MIT is a unified 9-tab operational workstation; Visual Intelligence Layer is a composable, analyst-centric charting and heatmap platform. They likely share frontend component libraries (chart canvas, heatmap tiles) but serve different user personas (operator vs. analyst). The alert expression language (e.g., "rsi_14 < 30 and vol_spike.confidence > 0.8") is a mini DSL that requires a parser and static analyzer not further specified. The 2000-tile virtualized heatmap at 5 Hz is a significant frontend rendering challenge — this is effectively the highest-demand UI component in the system.

---

## Duplicate and Conflicting PRD Pairs Summary

| Pair | Status | Relationship |
|------|--------|-------------|
| research-backtesting-lab vs. research-rbi-lab | Archived → Active | research-rbi-lab is the active NAUTILUS-gated successor; migration pointers in archived API redirect to rbi-lab endpoints. |
| truth-validation vs. truth-validation-order-flow-options | Active vs. Archived | Active feature is the full multi-source truth system; archived feature is the legacy order-flow/options sub-domain adapter. Proxy-to-new translation bridges the two. |
| signal-detection vs. signal-session-state-detection | Active vs. Archived | signal-session-state-detection is the legacy adapter; signal-detection is the active canonical implementation. Adapter must eventually be decommissioned. |
| risk-limits-compliance vs. risk-safeguards | Both active | Significant functional overlap in kill-switches, staleness blocks, exposure caps, and audit trails. Must be architected as a layered system — Safeguards as the fast enforcement layer reading from Limits' policy store. |
| mcp-co-agent-control vs. mega-ai-integration (ØMEGA) | Both active | Both implement agent sessions, tool scopes, dual approvals, and audit chains. MCP is the general internal control plane; ØMEGA is the specific bilateral LEVIATHAN↔ØMEGA protocol. Shared entity risk if not unified. |
| self-learning-agent-council vs. research-rbi-lab | Both active | Both implement experiment workflows with leak checks and critic/gate evaluation. Self-Learning is autonomous/agent-driven; RBI Lab is researcher-driven with formal paper-trade gating. Should share the leak-check engine. |
| strategy-ingestion-learning-engine vs. mt4mt5-export-bridge | Both active | Both generate MT4/MT5 code — the ingestion engine provides the codegen pipeline while the export bridge adds build/deploy/bridge capabilities. The codegen implementations should be shared or delegated. |
| Kill-switch: 4-way conflict | All active | Risk Safeguards, Risk Limits & Compliance, Security Compliance Hardening, and MCP Co-Agent Control each define independent kill-switch mechanisms. A single authoritative kill-switch arbiter service is required. |

---

*End of digest. Total features processed: 21 folders, 63 PRD files (including archived variants). Generated 2026-07-05.*
