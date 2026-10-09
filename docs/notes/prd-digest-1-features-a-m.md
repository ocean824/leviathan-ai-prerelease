# LEVIATHAN AI — PRD Digest: Features A–M
**Generated:** 2026-07-05
**Source path:** `C:\Users\XYRASYSTEMS\MASTER TEMPLATE\.codespring\extracted\.codespring\PRDs\`
**Features covered:** 20 folders (admin-console-licensing through market-data-pipeline-ingestion)

---

## Executive Summary (Cross-Cutting Patterns)

1. **Unified RBAC / Auth model.** Every feature assumes OAuth2/JWT (RS256) for user tokens plus mTLS for service-to-service calls. Roles recur in almost identical sets: Owner/Admin/Operator/Researcher/Viewer (plus Service/System) — indicating a shared IAM layer that all services must delegate to. Admin Console & Licensing is the canonical source of truth for org, seat, and role records.

2. **Shared instrument / symbol master.** At least six features (Dark Pool Lens, Dealer Positioning, Indicator State Engine, Market Data pipelines, Backtesting, Data Storage) independently reference an `instruments` or `symbol` table. No single PRD claims ownership of this shared catalog — a critical gap that must be resolved before schema design.

3. **Feature Store as platform backbone.** Data Storage & Feature Store is referenced by Backtesting, Indicator State Engine, Dark Pool Lens, and (implicitly) Decision Engine as the canonical read/write layer for computed features. Consistent versioning (semver, immutable once published) and point-in-time correctness are universal expectations.

4. **ØMEGA Secure Agent Bridge recurs throughout.** Decision Engine, Crypto Flash Loan Engine, EA Builder, Earnings Monitor, Execution Routing, and Knowledge Ingestion all cite ØMEGA as the integration bus for headless/agent coordination. This bridge is a hidden critical-path dependency not covered in these 20 PRDs.

5. **Event streaming (Kafka/NATS) is the preferred IPC.** Virtually every feature publishes or consumes named topics. Topic schemas are defined per-feature but there is no cross-feature schema registry PRD in this batch — a governance gap.

6. **Audit-log immutability is universal.** Every feature requires append-only audit logs with actor, timestamp, diff, and trace_id. No shared audit service is defined — each feature creates its own `audit_log` table, risking fragmentation.

7. **Idempotency-Key header is a first-class contract.** All write endpoints require or recommend an idempotency key. This is a platform-level constraint that must be documented in API gateway standards.

8. **Desktop-first frontend assumption.** All UI PRDs specify minimum 1280 px target width, optional 1024 px degraded, and explicitly out-of-scope mobile. Accessibility (WCAG AA, keyboard navigation, ARIA) is universally required.

9. **Latency SLO tiers are consistent.** REST reads: 150–350 ms p95. Streaming: 50–500 ms p95 depending on domain. Execution/Decision: 5–20 ms p99. These form an implicit SLO contract hierarchy.

10. **Two confirmed near-duplicate PRD pairs:** (a) `knowledge-ingestion` is explicitly archived/deprecated, superseded by `knowledge-ingestion-obsidian-sync` plus Market Data Pipeline — not a true duplicate but a deliberate versioning. (b) `market-data-ingestion-pipeline` and `market-data-pipeline-ingestion` describe the same system with different naming conventions, overlapping scope, and slightly different SLOs — a genuine duplication that requires consolidation.

---

## Feature Digests

---

### Admin Console & Licensing

- **Purpose:** Centralised backend for organisation-level subscriptions, seats, RBAC roles, license entitlements, and programmatic auth links (one-time tokens for headless agents such as ØMEGA Secure Agent Bridge).
- **Backend:**
  - License enforcement service: caches positive checks 60 s, negative 5 s; emits 402 on gated endpoint breach.
  - Seat/role management APIs with LastOwnerGuard and SeatLimitExceeded enforcement.
  - ProgramAuthLink service: 256-bit entropy one-time tokens, mTLS-optional exchange, single-use TTL (max 15 min).
  - Token introspection endpoint consumed by all downstream services.
  - Billing webhook receiver (Stripe-like signature validation).
- **Data model:**
  - `organizations` — root tenant entity.
  - `subscriptions` — plan, status, term, seat_limit, feature entitlements.
  - `seats` — user-to-org binding with role and status.
  - `roles` / `role_permissions` — system-global and org-scoped RBAC.
  - `program_auth_links` — single-use agent bootstrap tokens (hash only, never plaintext).
  - `api_keys` — service credentials (hash only).
  - `invitations` — pending seat invitations (hash only).
  - `audit_log` — immutable org-scoped events with IP hash.
  - `org_memberships` — user-to-org M:N join with role assignment.
  - `license_keys` / `license_activations` — offline/desktop scenario; device-fingerprint binding.
- **Frontend:**
  - Left-rail nav: Overview, Subscription, Seats & Roles, Access Policies, Program Auth Links.
  - Subscription state badges (Trial/Active/Past Due/Suspended/Expired) with usage bars.
  - Seat table with invite, role change, suspend, remove actions; ownership guard.
  - Access Policies RBAC builder with conflict resolution and effective-access preview.
  - Program Auth Links panel with QR code, masking, and Revoke/Rotate actions.
  - Inline audit activity feed per tab.
- **Depends on:** None (foundational); all other features depend on this for auth.
- **External:** Payment/billing webhook provider (Stripe-compatible). Vault/KMS for token storage (hash only in DB). mTLS PKI for agent exchange.
- **Notes:** This is the platform's **auth root** — all other services call its introspection endpoint. Downtime here is catastrophic. The frontend explicitly excludes SSO/SCIM, which means enterprise customers needing IdP federation will lack that path. Backend and database PRDs are consistent and complementary.

---

### Backtesting & Simulation

- **Purpose:** Run reproducible, event-driven strategy backtests, walk-forward/out-of-sample tests, parameter sweeps (grid/random/Bayesian), Monte Carlo path analysis, and a paper-trading harness against live price streams.
- **Backend:**
  - Historical Data Loader: tick/bar/L2 ingestion, corporate-action adjustment, survivorship-bias handling via point-in-time symbol lists.
  - Event-driven Simulator: orderbook models (L1 midpoint, synthetic/recorded L2), latency model (constant/distributional/empirical), partial fills, FIFO price-time priority.
  - Walk-forward job: rolling/expanding windows with gap to avoid leakage; per-fold and aggregate metrics.
  - Sweep Orchestrator: grid/random/Bayesian with per-trial constraints; leaderboard.
  - Monte Carlo: bootstrapped return paths or order-arrival permutations; deterministic under seed.
  - Paper trading harness: OMS-compatible execution reports; Risk Guard checks enforced; no real orders.
  - Target throughput: ≥2 M ticks/sec per worker; resumable checkpointing.
- **Data model:**
  - `instruments` — canonical securities.
  - `datasets` / `market_bars` / `market_ticks` / `orderbook_events` / `corporate_actions` — market data lineage.
  - `backtest_experiments` — owns simulation_configs, parameter_sets, walkforward_splits, monte_carlo_scenarios.
  - `backtest_runs` — materialized combination of experiment + config + params + seed.
  - `sim_orders` / `sim_fills` — per-run simulated execution artifacts.
  - `paper_accounts` — paper trading mode boundary.
- **Frontend:**
  - Historical Data Loader config: coverage heatmap, gap list, corporate-action toggle.
  - Event-driven Simulator config: book depth, latency, slippage, partial fill policy.
  - Walk-forward scheme builder: rolling/expanding/anchored with leak-check validation.
  - Parameter Sweep builder: grid/random/Bayesian with live trial matrix and leaderboard.
  - Paper Trading panel: live PnL, positions, orders, risk limits, event log.
  - Results & Visualization: equity curve, drawdown, factor exposures, run comparison (up to 4), audit pane.
- **Depends on:** Data Storage & Feature Store (market data); Configuration & Strategy DSL (strategy versions); Decision Engine / Risk Guard (paper trading); Admin Console (RBAC).
- **External:** None (data assumed pre-loaded; out of scope per backend PRD).
- **Notes:** Backend PRD explicitly out-of-scopes data acquisition — data must pre-exist in the market data store. The reproducibility contract (identical seed + dataset version = identical output) is a hard requirement. Paper trading relies on Risk Guard which is a separate feature not in this batch.

---

### Configuration & Strategy DSL

- **Purpose:** Declarative DSL for defining, versioning, validating, and hot-swapping trading strategy modules with environment-scoped YAML/JSON config profiles, parameter versioning, and experiment tracking.
- **Backend:**
  - Strategy Registry: immutable strategy versions with semver, checksum, signature, ABI compatibility; hot-swap with configurable drain_timeout (default 500 ms) and rollback_window (default 5 s).
  - Config Profile service: YAML/JSON validation against JSON Schema; no plaintext secrets (vault:// refs only); size limit 256 KB.
  - Parameter Management: immutable locked ParameterSets with audit diffs; derived sets via parent+override.
  - Experiment Tracker: per-run metric ingestion (5 k points/min), artifact URIs with checksums, leaderboard.
  - Idempotency-Key on all create/launch endpoints.
- **Data model:**
  - `strategies` / `strategy_versions` — registry with semver, runtime, entrypoints, status.
  - `strategy_deployments` — hot-swap binding: version + config + params → target/mode.
  - `config_profiles` — parsed YAML/JSON with secrets_references, lock state.
  - `parameter_sets` / `parameter_set_versions` — immutable, approval-gated in live mode.
  - `parameter_sweeps` — grid/random/Bayesian sweep definitions.
  - `experiments` / `experiment_metrics` / `experiment_artifacts` — run tracking.
  - `roles` / `role_bindings` / `strategy_permissions` — strategy-level RBAC.
  - `audit_log` — append-only with before/after diffs.
- **Frontend:**
  - Strategy Registry: searchable list with per-env status chips, hot-swap Activate flow with preflight checklist.
  - Config Editor: YAML/JSON with schema-aware linting, secret placeholder masking, diff view.
  - Parameter Manager: typed key/value with version history, diffs, rollback.
  - Sweep Builder: parameter grid/range definition with combination preview.
  - Experiment tracking: runs table, metrics charts, artifacts manifest.
  - Access Control: role matrix per strategy.
  - Audit Log: chronological, filterable.
- **Depends on:** Admin Console & Licensing (RBAC); Deployment & DevOps (artifact signing/promotion); Data Storage & Feature Store (feature refs); Backtesting & Simulation (run execution).
- **External:** Vault/KMS (secret resolution); artifact registry (strategy packages, e.g., S3).
- **Notes:** Hot-swap rollback (5 s window, health check) is a critical path that must be exercised in integration tests. The strategy execution runtime itself is out of scope — only orchestration. The frontend "Resolve Preview" for secrets must never leak values, only confirm resolvability.

---

### Crypto Flash Loan Arbitrage Engine

- **Purpose:** Sub-second discovery, quoting, risk-locking, and atomic execution of flash-loan arbitrage routes across DEX-DEX (triangular/cross-DEX, same chain) and CEX-DEX (when pre-positioned inventory confirmed); prevents insolvency via hard pre-trade risk locks and MEV protection.
- **Backend:**
  - Route Lifecycle: discovered → quoted (expiry ≤ 500 ms) → risk_locked (TTL ≤ 2 s) → executing → settled/failed → released.
  - Risk Lock service: per-asset/pool/venue exposure caps, slippage bounds, oracle sanity vs TWAP, gas ceiling, nonce safety; hard-fail on any violation.
  - MEV protection: private relay required for all on-chain legs; no public mempool submission.
  - Execution: idempotency-key required; atomic DEX-DEX settles or fully reverts; CEX-DEX only with IOC + pre-hedge.
  - Chain reorg handling: re-verify settlement; mark FAILED_REORG, no auto-retry without fresh lock.
  - Target: quote ≤ 75 ms p95; end-to-end decision-to-submit ≤ 150 ms p95.
- **Data model:**
  - `flash_loan_providers` — whitelisted on-chain lenders per chain/asset.
  - `arbitrage_route_template` / `arbitrage_route_leg` — canonical route shapes.
  - `arbitrage_opportunity` — time-stamped detections with dedupe hash.
  - `risk_lock` — per-scope exposure locks with TTL; unique LOCKED per scope+asset.
  - `flash_loan_request` — concrete borrow attempt.
  - `arbitrage_execution` / `execution_leg` — atomic execution record with per-leg fills and gas.
  - `route_latency_stat` — rolling telemetry to bias routing selection.
  - `arbitrage_policy` — runtime risk/ops thresholds by scope.
- **Frontend:**
  - Route Builder: template selection, assets/chain, constraints, pre-flight checks.
  - Opportunity Scanner: live table with freshness badge (Fresh/Warm/Stale; Stale disables Execute).
  - Simulation & Dry-Run: slippage curve, gas model, PnL distribution vs latency ±σ.
  - Execute & Guardrails: 3-step confirm (scope review → guard decision → final sign-off), progress drawer with per-leg status and tx hashes, sticky Kill button.
  - Telemetry & Journal: KPIs, per-leg realized slippage, auto journal note.
- **Depends on:** Admin Console & Licensing (RBAC); Decision Engine (optional strategy routing); Execution Routing (CEX legs); Market Data Pipeline (price feeds, TWAP); Data Storage (opportunity/execution archive).
- **External:** On-chain DEX contracts (Uniswap/Curve etc.); Flash loan providers (Aave etc.); Private relay networks (Flashbots/MEV Blocker); CEX APIs (via CCXT).
- **Notes:** Cross-chain bridging and L1↔L2 atomicity are explicitly out of scope. CEX-DEX mode introduces partial-fill risk that requires zero-tolerance handling (reject before DEX leg if CEX IOC fails). This feature carries the highest regulatory and operational risk in the set — MEV and reorg edge cases must be tested exhaustively.

---

### Dark Pool Lens

- **Purpose:** Transform TRF/ATS (dark pool) prints into actionable analytics — notional bucket rankings, DP-VWAP divergence vs lit markets, and session-time pressure clustering — for operator decision support and signal engine consumption.
- **Backend:**
  - DP Notional Buckets: aggregate by window (1m/5m/15m), bucket by quantile or fixed thresholds, compute buy/sell imbalance.
  - DP-VWAP Divergence: rolling lit-only VWAP, divergence in bps, z-score vs 30-day intraday baseline.
  - Session Clustering: Open/Lunch/Close pressure labels (High Buy/Sell Pressure, Neutral) per symbol.
  - Late data: accept up to 2 min late; recompute impacted aggregates; nightly backfill for z-score baselines.
  - Streaming topic `dp_features` emits on threshold crossings with dedup.
  - p95 latency: single symbol 1-day < 300 ms; up to 100 symbols < 1.5 s.
- **Data model:**
  - `dp_trade_events` — normalized DP prints with condition-code filtering, price in micro-dollars (INT).
  - `lit_vwap_windows` — lit-market VWAP snapshots per rolling window.
  - `dp_notional_buckets` — aggregated DP activity with top-print ranking.
  - `dp_vwap_divergence_windows` — per-window divergence.
  - `dp_session_pressure` — per-session clustering metrics.
  - `symbols` — minimal instrument directory.
- **Frontend:**
  - Symbol & timeframe selection with aggregation window and bucket scheme (log/linear).
  - Panel A: time-bucketed bar chart of DP notional stacked by bucket bands.
  - Panel B: ranked table of individual DP prints (sortable, brush/zoom).
  - DP-VWAP Divergence line chart with optional z-score toggle.
  - Session Clustering heatmap by minute with compare-mode (last N sessions).
  - Cross-panel filtering via global filter chips.
- **Depends on:** Market Data Pipeline (lit trades, DP prints); Data Storage & Feature Store (persistence, z-score baseline); Indicator State Engine (optional regime context); Admin Console (RBAC, symbol entitlements).
- **External:** TRF/ATS data vendor (dark pool prints); exchange lit trade/quote feeds.
- **Notes:** Lit VWAP must exclude off-exchange trades by default — a correctness contract that must be tested explicitly. The integer micro-dollar representation (price_int = price × 1e-6) is unusual and risks confusion with other features using decimal strings. No frontend alerts or strategy execution from this view.

---

### Data Storage & Feature Store

- **Purpose:** High-throughput time-series storage, versioned and immutable feature store for models/indicators, warm snapshots for fast boot/recovery, cold archive for compliance, and governed schemas with lineage.
- **Backend:**
  - Time-series Store: append-only idempotent ingestion; Hot (7 d) / Warm (30 d) / Cold (≥7 yr) retention tiers; late data quarantine; schema registry with compatibility modes.
  - Feature Store: named semver feature sets, online (in-memory + hot store) and offline (parquet) materialization; point-in-time correctness via asof joins; lineage (upstream sources, git SHA, data intervals).
  - Warm Snapshot: periodic checkpoints with WAL offsets; boot in <30 s for 10 M keys; hash integrity.
  - Cold Archive: WORM-capable; idempotent range restore; lineage event on rehydration.
  - Ingestion SLOs: ≥200 k events/s/node; write p99 <15 ms; online read p99 <5 ms cached / <50 ms hot.
- **Data model:**
  - `instruments` — canonical tradables.
  - `datasets` / `retention_policies` / `access_policies` — dataset catalog with governance.
  - `market_ticks` — raw time-series (partitioned by day).
  - `feature_definitions` / `feature_versions` / `feature_values` — immutable versioned feature store.
  - `snapshots` — warm cache state per scope/instrument.
  - `archive_manifests` — cold archive partition tracking (PENDING/COMPLETE/VERIFIED).
  - `ingest_journal` / `lineage_events` — observability and data lineage.
- **Frontend:**
  - Dataset Browser: symbol/exchange filters, retention policy badge, write rate, lag.
  - Series Inspector: sparkline, schema, anomalies, sample export.
  - Feature Catalog: domain/tag search, freshness SLA, version timeline, lineage DAG.
  - Snapshot Manager: create, dry-run diff, restore to staging/live.
  - Archive Browser: restore/export requests, legal hold management.
  - Schema Registry: versioned constraints, PII flags, impact analysis.
- **Depends on:** Admin Console (RBAC); Market Data Pipeline (primary ingest source); Indicator State Engine (write-through features); Deployment & DevOps (lifecycle/retention policy).
- **External:** Object store (S3-compatible) for cold archive and offline parquet; Vault/KMS for encryption keys.
- **Notes:** This is the **data platform backbone** — Backtesting, Indicator State Engine, Dark Pool Lens, and Dealer Positioning all read from it. The instruments table conflict (also defined in Backtesting and Dark Pool Lens) needs a single canonical owner. Feature immutability after publication is a hard constraint — no in-place edits.

---

### Dealer Positioning (Gamma)

- **Purpose:** Compute and serve intraday and EOD dealer gamma levels (gamma flip, call/put walls, max pain), regime labels (positive/negative gamma), and 0DTE pin risk for options-eligible underlyings to inform directional bias and hedging flow analysis.
- **Backend:**
  - Key Levels: gamma flip (sign-change of aggregate net gamma), call/put walls (max OI notional or gamma-weighted), max pain (strike minimising holder P/L); live and settled variants.
  - Regime: positive/negative/neutral label with confidence (0–1) derived from data freshness, coverage, and IV dispersion.
  - 0DTE Pin Risk: pin_probability and magnet levels; only on sessions with same-day expiry.
  - Update cadence: recompute per tick or every 1 s; API p95 <300 ms; stream p95 <500 ms.
  - Idempotent upserts keyed on (symbol, as_of, inputs_version).
  - Requires ≥80% contract coverage or degrades with reduced confidence.
- **Data model:**
  - `gamma_snapshot` — canonical time-stamped aggregate per instrument (headline levels + regime).
  - `gamma_levels` — normalised per-snapshot key levels for ranking and overlays.
  - `live_settled_diff` — materialised deltas between live and settled for "live vs settled" views.
  - `pin_risk_0dte` — pin probability and magnet levels.
- **Frontend:**
  - Instrument selector with Live/Settled toggle (persists per ticker).
  - Key Levels display: gamma flip, call wall, put wall, max pain — with confidence (High/Med/Low) and Primary/Alternate candidates.
  - Regime badge: Positive/Negative/Neutral with Live vs Settled comparison pill.
  - 0DTE Pin Risk card (eligible days only): pin probability % and up to 3 magnet levels.
  - Price chart with overlay toggles for each level; freshness badge (amber >60 s, red >5 m).
  - Copy snapshot to clipboard (plain text for desk communication).
- **Depends on:** Market Data Pipeline (option quotes, IV surface, spot); Data Storage & Feature Store (persistence, backtesting reads); Decision Engine (consumes regime stream); Admin Console (RBAC).
- **External:** Options market data vendor (greeks, OI, IV surface); exchange calendar service.
- **Notes:** Business logic PRD explicitly excludes cross-asset correlation, vanna/charm, and position inference from dealer inventory. Live vs Settled semantics must be carefully tested — regime can flip intraday while settled remains unchanged. The frontend PRD avoids all calculation details (backend-owned), but its staleness thresholds (60 s amber, 5 m red) must match backend's stale-input cutoffs.

---

### Decision Engine

- **Purpose:** Fuse multi-layer signals (L1 data pipeline, L2 visual intelligence, L3 indicator state, L4 decision heuristics), apply risk gates, compute portfolio-aware sizing, and emit deterministic trade intents routed to live or simulation execution paths.
- **Backend:**
  - Signal Fusion: all 4 layers must pass threshold within time window W (e.g., 250 ms); any stale/below-threshold → no intent.
  - Risk Guards: max per-trade loss, daily drawdown, vol cap, position limits, correlation crowding, kill-switches.
  - Sizing: fixed, vol-scaled, risk-parity, or capped-Kelly; round to lot/step; enforce min notional.
  - Routing: `mode ∈ {live, sim}`; ØMEGA bridge failover to sim or block per config.
  - Explainability: reason_codes, contributing signal weights, top-5 feature attributions, delta from prior cycle.
  - Performance: p50 ≤ 5 ms, p99 ≤ 20 ms on warm path; exactly-once intent per idempotency_key.
- **Data model:**
  - `decision_runs` — one evaluation cycle per strategy-symbol-portfolio window.
  - `confirmation_layers` — 4-layer gate records with pass/fail and scores.
  - `risk_evaluations` — per-check outcomes with reason codes.
  - `trade_intents` — sizing, routing, expires_at; linked to decision_run.
  - `intent_attributions` — per-signal contribution weights.
  - `portfolios` / `positions` / `allocations` / `portfolio_constraints` — portfolio state.
  - `risk_limits` — strategy-level risk bounds.
  - `reason_codes` — standardised enum codes for explainability.
- **Frontend:**
  - Decision Console: real-time stream of instruments/strategies with 4-layer gate chips (Pass/Soft Pass/Fail/Stale/Unknown).
  - Config Panel (role-gated): per-layer thresholds, risk caps, sizing constraints.
  - Explainability Drawer: reason codes with weights, signal attributions, "what changed since last cycle" delta view.
  - Intent Review Modal: 2-step live confirmation (requires ØMEGA bridge Connected).
  - Batch rebalance: multi-select, grouped routing, per-item validation.
- **Depends on:** Indicator State Engine (L3); Market Data Pipeline (L1); Visual Intelligence Layer (L2, not in batch); Admin Console (RBAC); Execution Routing / ØMEGA bridge (intent dispatch); Data Storage & Feature Store (portfolio/risk state).
- **External:** ØMEGA Secure Agent Bridge (live routing); exchange kill-switch integration.
- **Notes:** The 4-layer signal model implies L2 (Visual Intelligence Layer) is a real-time dependency not covered in this PRD batch — it is a hidden critical path. The p99 ≤ 20 ms SLO is extremely tight and requires all upstream state to be in-memory/cached. Live routing requires a 2-step confirmation and ØMEGA being Connected — if ØMEGA is down, all live intents are blocked or sim-only.

---

### Deployment & DevOps

- **Purpose:** Deterministic OCI container builds with SBOM and Sigstore/cosign signing, secure CI/CD with SAST/SCA gates, GitOps-driven environment promotion (Dev → Staging → Prod) with canary rollout and auto-rollback, centralised Vault/KMS secrets, and Terraform IaC with drift detection.
- **Backend:**
  - Build pipeline: hermetic builds (pinned base digests, lockfiles, no network in build stage), SLSA-compliant provenance, CycloneDX/SPDX SBOM.
  - Canary policy: 1% → 10% → 50% → 100%; auto-rollback on error_rate >0.5%, p99 latency >+20%, trade reject rate >0.2%, or SLO burn-rate alert.
  - DB migrations: phased (additive → shadow read → feature-flag apply → destructive in maintenance window).
  - Secrets: workload OIDC/JWT for dynamic creds; static rotation ≤30 days; audit all access.
  - Freeze windows: block non-emergency Prod deploys; require incident ticket for hotfix.
  - Read-only API: `GET /ops/env/{env}/release`.
- **Data model:**
  - `services` / `pipelines` / `pipeline_runs` / `job_runs` — CI/CD lineage.
  - `container_images` — digest, SBOM hash, signed flag; unique per digest.
  - `environments` / `deployments` — per-env service state.
  - `promotion_requests` / `approvals` — two-approver gate.
  - `secrets_meta` — Vault/KMS references only (no secret values stored).
  - `secret_access_bindings` — per-service/environment scoped access.
  - `infra_modules` / `infra_changesets` — IaC plan/apply with drift detection flag.
  - `audit_events` — immutable action log.
- **Frontend:**
  - Builds view: digest, SBOM, provenance, determinism badge.
  - Pipeline stages: streamed logs, vulnerability threshold gate with waiver request.
  - Environment cards: current version, commit, SLO health, error budget, rollback action.
  - Secrets panel: masked values, one-time reveal window (120 s), rotation history.
  - IaC Stack view: Plan diff (add/change/destroy) with risk labels; Apply with dual approval for Prod.
- **Depends on:** Admin Console & Licensing (RBAC roles: Developer/Reviewer/Release Manager/DevOps); Monitoring & Telemetry (SLO signals for canary); all other services (consumer of CI/CD).
- **External:** Container registry (e.g., ECR/GCR); Vault/KMS; SLSA/Sigstore; Terraform backend; SAST/SCA tools (e.g., Snyk, Trivy).
- **Notes:** Canary rollback condition "trade reject rate >0.2%" requires OMS metrics to feed into the deployment pipeline — an implicit dependency on Execution Routing. ØMEGA compatibility check in promotion dialog is mentioned in the frontend PRD but undefined in backend — potential gap. DB migration phasing (3-phase) is sound but requires strict coupling with feature flags, which are not fully spec'd.

---

### Desktop App Packaging

- **Purpose:** Signed native desktop installers for Windows (.msi/.exe) and macOS (.dmg/.pkg) with auto-update channels (stable/beta/canary), offline-first operation, delta-update capability, device fleet management, and atomic rollback on failure.
- **Backend:**
  - Channels: stable/beta/canary; phased rollout % via consistent hashing; device bound to single channel.
  - Update check: resolves target version respecting rollout %, min_required_version, and rollback_advisory; returns signed package URL (6-hour expiry).
  - Integrity: SHA-256 + code signing/notarization required before URL returned; INTEGRITY_BLOCKED on failure.
  - Delta: contiguous base version chain required; falls back to full if chain invalid.
  - Fleet: device registration with public key, platform, arch; device_token (scoped, revocable).
  - Telemetry: redacted crash/error with trace_id; no PII; install/update outcomes with Idempotency-Key.
  - Update check p99 <2 s under 10 k RPS.
- **Data model:**
  - `releases` / `release_artifacts` — semver + digest + SBOM + signing attestation per platform/arch.
  - `update_channels` / `channel_releases` — rollout status (draft/promoted/paused/rolled_back/yanked).
  - `devices` — org, platform, channel, current version, health, kill_switch.
  - `device_installations` — atomic swap + rollback history.
  - `update_checks` / `update_actions` / `telemetry_events` — per-device update audit.
  - `approvals` — gate for channel release changes.
  - `watchdog_scans` — SHA-256 of on-disk binaries for integrity monitoring.
  - `signing_keys` / `sbom_documents` — compliance attestations (no secret values stored).
- **Frontend:**
  - Installer: minimal UI (app name, version, publisher, target location, EULA link).
  - First launch: version/channel/update status display; offline banner.
  - Auto-update: silent download, "Restart to update" CTA with snooze; forced-update blocking modal with 15-min countdown.
  - Integrity failure: non-blocking toast; no partial state; remain on current version.
  - Settings: Current version, Channel, Last checked, Update status, Crash reports toggle, View logs.
  - Operator UI: channel promotion board, device fleet table, compliance attestations view.
- **Depends on:** Deployment & DevOps (CI/CD pipeline produces signed artifacts, SBOM); Admin Console & Licensing (device token scoping, org binding); Monitoring & Telemetry (crash/update outcome telemetry).
- **External:** Apple notarization service; Windows code signing CA; CDN for package distribution; KMS for signing keys.
- **Notes:** Delta updates require a contiguous base-version chain — the backend must maintain this chain and never gap it. The "kill_switch" field on devices allows central remote disable of a device fleet, which is a high-risk capability requiring strict access control. Offline-first URL expiry (6 hours) creates a window where stale packages may be cached — the watchdog_scans integrity check is the last line of defence.

---

### EA Builder (MT4/MT5)

- **Purpose:** Visual block-based builder for MT4/MT5 Expert Advisors with node-graph editing, strategy validation/linting, tick-accurate backtesting, WFO optimisation, debugger, template library, and deterministic MQL4/MQL5 code generation for export/deployment via ØMEGA bridge.
- **Backend:**
  - Node graph engine: up to 5 k nodes, 20 k edges; validation <2 s p95; node types cover events, indicators, control flow, trade actions, risk/money management, session/news filters.
  - Validation/Linting: type checks, unbounded-loop detection, DAG validation, warmup insertion, MT4/MT5 compatibility tagging; block-level error vs warning classification.
  - Backtester: tick-accurate with modeled spread/slippage; FIFO/hedging modes; WFO with IS/OOS segmentation; grid/random/Bayesian optimisation.
  - Debugger: deterministic step/run with node output probes, indicator buffer snapshots, trade traces; WebSocket stream.
  - MT4/MT5 Export: deterministic MQL4/MQL5 codegen with parameter mapping; no compiler required (source export); compiled if compiler available.
  - Deploy via ØMEGA bridge to MT4/MT5 terminals; RBAC-gated.
  - Version channels: dev/staging/prod with immutable diffs and rollback.
- **Data model:**
  - `strategy` / `strategy_version` — registry with semver and release channel.
  - `node_block` / `edge` / `variable` / `time_filter` / `risk_profile` — per-version graph artefacts.
  - `block_def` — canonical block type catalog.
  - `validation_issue` — lint errors/warnings per version.
  - `backtest_run` / `backtest_metric` / `optimization_job` / `optimization_result` — testing artefacts.
  - `debugger_trace` / `debugger_event` — microsecond-precision step events.
  - `template` / `template_share` / `template_rating` — community library.
  - `export_build` — MT4/MT5 codegen artefacts and bridge packaging.
- **Frontend:**
  - Node-based canvas: pan/zoom, snap-to-grid, multi-select, align; control vs data connection types; mini-map.
  - Block library: searchable with categories and MT4/MT5 compatibility tags.
  - Properties panel: context-aware, typed controls, MT4/MT5 badges.
  - Backtesting panel: config → run → equity/drawdown/trade list results; up to 3-run comparison.
  - Portfolio Router: multi-strategy allocation with weights/vol targets.
  - Export modal: select MT4/MT5, download archive (.mq4/.mq5 + .set file).
- **Depends on:** Market Data Pipeline (backtest data); Data Storage & Feature Store (historical data); Configuration & Strategy DSL (strategy versioning patterns); Admin Console (RBAC); Execution Routing / ØMEGA bridge (deployment); Decision Engine (optional signal integration).
- **External:** MT4/MT5 terminals (via ØMEGA bridge); optional MQL compiler; news feed API (for embargo windows); Vault (secrets for bridge).
- **Notes:** This is the only feature that explicitly builds MQL4/MQL5 code — a niche but high-value capability. The block graph schema overlaps conceptually with Configuration & Strategy DSL's strategy versioning, but EA Builder's node-graph model is fundamentally different (visual graph vs YAML config). Multi-user real-time collaboration is explicitly out of scope. AI auto-generation of strategies is also out of scope.

---

### Earnings & Events Monitor

- **Purpose:** T−7..T+2 earnings and catalyst event calendar for equities/options with per-ticker schedules, IV rank and expected-vs-realised move metrics, options flow surge overlays, and dark pool cluster signals, supporting pre/post-earnings positioning and post-event assessment.
- **Backend:**
  - Event sources: earnings (primary), guidance calls, analyst days; states: scheduled/confirmed/revised/delayed/canceled/completed; de-dupe by (issuer_id, event_at, type) with highest revision winning.
  - IV Rank: percentile of 30 D IV vs 252-trading-day lookback; snapshots at pre (T−1 close) and post (T+1 close).
  - Expected Move: front-week ATM straddle mid/spot (default) or IV-based EM.
  - Realized Move: abs(log(close_post / close_pre)); close-to-close.
  - Flow overlays: options z-score vs 20-day baseline (threshold z≥2) within T−3..T+1.
  - DP clusters: VWAP-bucketed z-score within T−5..T+1.
  - Alerts: upcoming (T−1h, T−24h), state change, pre/post-metrics ready, anomaly; via internal bus, Operator UI, webhook (HMAC-SHA256), and ØMEGA topic.
  - Calendar query p95 ≤200 ms (cached); metrics/overlays ≤350 ms.
- **Data model:**
  - `events_calendar` — canonical per-ticker events with revision tracking and status lifecycle.
  - `event_metrics` — pre/post IV rank, EM, RM, price references.
  - `iv_snapshots` — time-series IV/IVR context.
  - `flow_overlays` — flow surge and DP cluster overlays time-aligned to events.
  - `event_catalysts` — news/filings/analyst catalysts in event window.
  - `alert_subscriptions` / `alert_notifications` — per-subscriber rules and delivery state.
- **Frontend:**
  - Calendar: T−7..T+2 (adjustable to T−14..T+5) grouped by day with IV rank, EM badges, overlay chips.
  - Detail slide-over with tabs: Overview (prior 4Q sparklines), IV & Moves (expected vs realised), Flow/DP (timeline with z-scores and DP markers).
  - Per-ticker drawer: all events ±90 days with mini timeline.
  - Alert subscriptions: per-ticker/watchlist/global-event-type with threshold controls.
  - AMC/BMO badge logic for session mapping of expected/realised definitions.
- **Depends on:** Market Data Pipeline (prices, IV feeds); Dark Pool Lens (DP cluster data); Institutional Flow Radar (options flow z-scores); Data Storage & Feature Store (historical IV/price); Admin Console (RBAC).
- **External:** Earnings data vendor (event schedules, revisions); options data vendor (IV, greeks, OI); corporate action feed.
- **Notes:** Backend explicitly limits asset classes to equities/options — no futures or crypto. EM computation depends on front-expiry option chain availability; partial data (status=partial) must be surfaced gracefully. The frontend allows configuring "desktop push" notifications — this implies a desktop app integration that depends on Desktop App Packaging.

---

### Execution & Routing

- **Purpose:** Order lifecycle management (OMS), smart venue routing with latency/slippage controls, kill-switches, broker/exchange connectors (IBKR, CCXT, MT5 EA), bracket/algo order types (TWAP/VWAP/Iceberg), prop firm constraint enforcement, and reconciliation with deterministic state and full auditability.
- **Backend:**
  - OMS States: created → risk_pending → risk_rejected | routed → pending_new → working → partially_filled → filled | canceled/rejected/expired.
  - Smart Routing: best_price/best_liquidity/latency_first/custom; venue scoring from NBBO/book/latency/slippage history; fallback within maxVenueHops.
  - Hard slippage cap: orders exceeding cap rejected with RISK_FAIL_SLIPPAGE; never executed.
  - Latency budgets: auto-cancel or reroute per policy if exceeded before ack.
  - Kill-switch: halts new orders within 100 ms; mass-cancels all working within configured timeout.
  - Prop Firm Mode: daily drawdown, consistency variance, size/trade caps, throttle, trading windows — explicit breach codes (DAILY_DD, SIZE_LIMIT, CONSISTENCY).
  - Connector reconciliation: periodic + on-demand; resolve mismatches via correction events.
- **Data model:**
  - `venues` / `connectors` / `accounts` — exchange/broker topology.
  - `oms_orders` — root and child orders (parent_order_id), all order types including tactic (TWAP/VWAP/ICEBERG).
  - `order_events` — append-only state transition log with sequence.
  - `executions` — fills with venue_trade_id, fees, liquidity tags.
  - `routing_decisions` — scored venues and fallback rationale.
  - `order_links` — bracket/OCO/TP/SL relations.
  - `kill_switches` / `circuit_breakers` — scoped safety controls.
  - `prop_firm_rules` / `prop_firm_state` — per-account daily compliance tracking.
  - `ea_sessions` — MT5/EA session state for staged execution.
  - `reconciliation_ledger` — external broker snapshots for audit.
- **Frontend:**
  - Order Ticket: full validation (symbol, qty precision, tick size, TIF compatibility, bracket SL/TP, buying power, prop firm DD).
  - OMS Blotter: live parent-child hierarchy, per-order status, child order fills, TWAP/VWAP/Iceberg progress, venue path.
  - Smart Venue Routing Panel: Auto/Manual mode, venue health (latency p50/p99, rejection rate, liquidity score).
  - Slippage/Latency Controls: breach behaviors (auto-cancel/reroute/degrade to passive).
  - Kill-switch: typed confirmation phrase, mass-cancel progress.
  - Connectors tray: IBKR/CCXT/MT5/FIX health, session state, throttle remaining.
  - MT5 EA Spine: staged entry tiers, per-stage fill tracking.
- **Depends on:** Admin Console (RBAC); Decision Engine (intent consumer — primary order source); Market Data Pipeline (NBBO/book for routing and risk); Data Storage & Feature Store (position state); Risk Limits & Compliance (prop firm rules, circuit breakers — separate feature not in batch); Monitoring & Telemetry (SLO signals).
- **External:** IBKR TWS/Gateway; CCXT-supported CEX APIs; MT5 terminal (via EA bridge); FIX 4.2/4.4 endpoints.
- **Notes:** This is the live-money execution boundary — the highest-risk feature in the platform operationally. The kill-switch 100 ms SLO must be tested under realistic load. Bracket OCO semantics require careful implementation to prevent overfill. Prop firm mode is an explicit target market segment, suggesting the platform is aimed at funded-account/prop-firm traders in addition to institutional desks.

---

### Indicator State Engine

- **Purpose:** Compute, maintain, and serve deterministic technical indicators (SMA, EMA, MACD, RSI, ATR, VWAP, etc.), cross-sectional factors (z-score, rank_pct), and regime states (trend/mean_reversion/chop/illiquid/halt) from time-synced streaming bars with write-through to the Feature Store.
- **Backend:**
  - Indicator library: configurable per symbol/universe; NaN until warmup complete; exactly-once via event_id.
  - Factor engineering: cross-sectional rank_pct [0,1], robust z-score (median/MAD), regime flags.
  - Regime detection: configurable ADX/RSI/EMA-based rules with hysteresis (K bars persistence, Δ confidence margin, D dwell time).
  - Streaming: watermarked bar processing; late data recompute over last R bars; version = formula + params hash.
  - Feature Store sync: write-through p99 read-after-write ≤100 ms; idempotent upserts.
  - Performance: ≥50 k events/s sustained; p99 latency bar→publish ≤50 ms for 1 s bars.
- **Data model:**
  - `feature_definitions` / `feature_instances` — indicator/factor metadata and concrete parameterisation.
  - `computed_features` — time-series values per asset/timeframe; partitioned by event_ts.
  - `regime_states` — detected regimes as intervals with confidence and detection method.
  - `compute_cursors` — per-asset/per-feature streaming watermarks for exactly-once processing.
  - `feature_store_sync` — write-through attempt log for audit/retry.
- **Frontend:**
  - Indicator Catalog: browse/search indicators, factors, regime detectors with parameter constraints.
  - Pipeline Builder: compose per-universe indicator sets, compute cadence, output schema/aliasing; dry-run on delayed stream.
  - Live Monitor: real-time tiles with value, delta, regime badge, latency, warmup progress.
  - Feature Store Sync Panel: per-feature write-through status, last commit ts, retry visibility.
- **Depends on:** Market Data Pipeline (bar/trade/quote input streams); Data Storage & Feature Store (write-through target); Admin Console (RBAC); Decision Engine (L3 signal consumer).
- **External:** None (computation is internal).
- **Notes:** Regime hysteresis logic (K/Δ/D parameters) is configurable but the default values are not specified in any PRD — these need to be defined in the configuration service. The NaN-until-warmup contract is critical for the Decision Engine — if the engine receives warmup=true features it must not produce trade intents. The write-through p99 ≤100 ms SLO is tight given the ≥50 k events/s throughput requirement.

---

### Institutional Flow Radar

- **Purpose:** Detect and surface institutional-scale options flow (sweeps, blocks) in near-real time with composable smart filters (min premium, vol>OI, OTM, near-ask aggression), burst/chaining detection across strikes/expiries, and per-ticker call/put tilt metrics for operator and strategy engine consumption.
- **Backend:**
  - Sweep detection: multi-venue rapid fills or N prints across venues within T seconds for same order.
  - Block detection: single large negotiated print or size ≥ threshold at off-market venue.
  - Filters: min_premium (default $50 k), vol>OI, size>OI, OTM (with ±0.5% buffer), near-ask aggression (configurable epsilon and threshold).
  - Burst/Chaining: sliding 8 s window per underlying/side/expiry; chain when group_count ≥3 OR sum_notional ≥$500 k; stable chain IDs.
  - Tilt Metrics: rolling [1m/5m/30m/session] call/put notional tilt, near-ask share.
  - Performance: ingest-to-availability p95 ≤500 ms events, ≤800 ms bursts, ≤1 s tilt; sustain 20 k msg/s.
  - OI staleness guard: >1 trading day → vol>OI unknown; NBBO staleness >500 ms → near-ask unknown.
- **Data model:**
  - `option_flow_event` — normalised DP/sweep/block prints with computed filter flags (tri-state booleans for unknown).
  - `flow_chain` — detected burst groups with sequence-level stats.
  - `flow_chain_link` — event-to-chain association with sequence position.
  - `ticker_tilt_metric` — interval aggregates for call/put notional tilt.
- **Frontend:**
  - Feed view: real-time paginated table with soft-append (scroll position preserved), stream lag badge (green/amber/red).
  - Composable filter panel: min_premium, vol>OI, size>OI, OTM, near-ask aggression enum, ticker/expiry/side/session/venue. Presets: "High Aggression," "Whale OTM," "OI Crunch."
  - Chains view: burst/sequence timeline with nodes = prints, edges = same-ticker-side links; sequence badges.
  - Tilt view: per-ticker call/put notional tilt with rolling windows (1m/5m/30m), heat coloring by z-score vs 5d baseline.
  - Cross-panel drill: click chain → filter Feed to members; click ticker tilt → pivot Feed.
- **Depends on:** Market Data Pipeline (consolidated options trade/quote feed, NBBO, OI); Dark Pool Lens (conceptually adjacent — DP prints); Data Storage & Feature Store (historical flow for tilt baselines); Admin Console (RBAC with symbol ACLs).
- **External:** Options tape/consolidated feed vendor; NBBO quote feed.
- **Notes:** The tri-state boolean model (TRUE/FALSE/NULL for unknown) for vol>OI, size>OI, and near-ask is a correct design choice that must be propagated consistently to the frontend (shown as "n/a" not "false"). The burst detector uses stable chain IDs — these must be content-addressed or the detector must ensure idempotency across restarts. OI data staleness (>1 trading day) creates a daily gap between market close and next morning's OI refresh.

---

### Knowledge Ingestion (Archived)

- **Purpose:** DEPRECATED/ARCHIVED legacy module — read-only access to historical ingestion configurations and run logs; all write/execute operations return 410 Gone with pointers to replacement features (Market Data Pipeline & Ingestion, EA Builder knowledge components).
- **Backend:**
  - State: archived/immutable; background workers disabled; enqueued tasks dead-lettered.
  - All POST/PUT/PATCH/DELETE endpoints return 410 with LEGACY_ARCHIVED code and replacement docs.
  - Read endpoints retain RBAC, pagination, filtering, and secrets masking.
  - Deprecation/Sunset/Link headers on all archived routes.
  - Data retention: ≥24 months for compliance.
  - Message bus: legacy topics reject publishes; route to `knowledge.ingest.dlq` with error_code=LEGACY_ARCHIVED.
- **Data model:**
  - `archived_sources` / `archived_ingestion_configs` / `archived_ingestion_runs` / `archived_ingestion_items` / `archived_ingestion_errors` — read-only historical records.
  - `archived_crosswalks` — mappings from archived entities to Market Data Pipeline or EA Builder equivalents.
- **Frontend:**
  - Archived page with "Archived" badge in header, dismissible deprecation banner with migration links.
  - All create/edit/re-run actions disabled with explanatory tooltips.
  - Export JSON available for historical audit.
  - Redirect from all legacy routes to `/archive/knowledge-ingestion`.
- **Depends on:** Admin Console (RBAC); Market Data Pipeline (successor feature); EA Builder (successor feature).
- **External:** None (passive read-only).
- **Notes:** **NOT a duplicate of knowledge-ingestion-obsidian-sync.** The archived module is the predecessor of a broadly-scoped "knowledge ingestion from any source" system that was split into (a) the Obsidian/PDF/YouTube-specific research ingestion module and (b) Market Data Pipeline. The archived PRDs are explicitly labelled as such. Crosswalk records are the migration path — they must be populated before the legacy UI is fully decommissioned.

---

### Knowledge Ingestion (Obsidian Sync)

- **Purpose:** Continuously ingest research knowledge from an Obsidian vault (Markdown, PDF, YouTube) into the LEVIATHAN knowledge store with language-aware chunking, methodology/asset/regime tagging, content-hash deduplication, and immutable TRITON lineage for auditability and downstream signal/decision engine use.
- **Backend:**
  - Sources: Obsidian vault via Secure Agent Bridge (local watcher); never reads filesystem directly. Types: md, pdf, youtube.
  - Ingestion workflow: receive → fetch → identify parser → extract text → chunk → tag → persist (SQL + vector store) → emit lineage (TRITON).
  - Tagging: deterministic from MD frontmatter > explicit event metadata > folder path mapping rules.
  - Chunking: target 400 tokens, 60 overlap; PDF layout-aware; YouTube transcript + description.
  - TRITON lineage: vault_id → document_version → chunk → embedding; emit `triton.lineage.v1` on create/update/delete.
  - Idempotency: content_hash + path_hash dedup; existing versions reused on unchanged content.
  - Performance: ≥50 docs/min; md ≤10 s p95, pdf ≤60 s, youtube ≤90 s end-to-ready.
- **Data model:**
  - `vaults` — registered Obsidian vault root metadata.
  - `knowledge_sources` — per-file identity (path_hash); tracks renames.
  - `source_revisions` — append-only content versions with content_hash and parser/chunker version.
  - `chunks` — deterministic sequence per revision with offsets.
  - `embeddings` — one per (chunk, model); replaceable on model change.
  - `tags` / `chunk_tags` — M:N methodology/asset/regime tagging with confidence and provenance.
  - `lineage_edges` — TRITON polymorphic parent→child lineage across all entity types.
  - `ingestion_jobs` — operational tracking per source/revision.
- **Frontend:**
  - Vault connection wizard: folder selection → inclusion rules/ignore list → chunking+tagging config → dry-run preview (≥10 sample chunks with resolved tags + lineage).
  - PDF and YouTube ingestion panels with per-item status counters.
  - Mandatory tag resolution (methodology/asset/regime must resolve before submit).
  - Sync management: pause/resume watcher, partial re-index, force re-index.
  - Lineage detail drawer: TRITON lineage chain, source path/URL, chunk offsets, content hash, parser version.
  - Virtualized list for 10 k+ items with live counters.
- **Depends on:** Admin Console (RBAC); Deployment & DevOps / Desktop App Packaging (local filesystem access via desktop app); Data Storage & Feature Store (vector store backend); Decision Engine (downstream consumer of tagged knowledge).
- **External:** ØMEGA Secure Agent Bridge (local vault watcher relay); Vector database (e.g., pgvector/Pinecone); YouTube transcript API; PDF parsing library.
- **Notes:** The mandatory 3-taxon tagging (methodology/asset/regime) creates a hard gate that could block ingestion of documents that do not fit neatly into these categories — the allowlist configuration must be robust. Semantic search and retrieval are explicitly out of scope for this PRD (separate feature). OCR for scanned PDFs is also out of scope. The TRITON lineage system is referenced across multiple features but has no standalone PRD — it is a cross-cutting infrastructure concern.

---

### Macro Positioning (COT)

- **Purpose:** Normalise and serve weekly CFTC Commitments of Traders (COT) managed-money net positions, week-over-week deltas, and 3-year percentile scores for key futures markets, with contrarian/confirmation tagging and cross-asset market-to-driver mapping, to inform the indicator state engine and decision engine.
- **Backend:**
  - Data source: CFTC Disaggregated Futures (Managed Money); weekly release Sat 00:00 UTC.
  - Normalisation: `net_mm_pct_oi = (mm_long - mm_short) / open_interest_total`.
  - Percentile: 3-year rolling (156 weeks); low_confidence=true until ≥104 weeks.
  - Contrarian tag: ≤10th → contrarian_long; ≥90th → contrarian_short.
  - Confirmation bias: ≤35th → bias_short_cover; ≥65th → bias_trend_follow_long.
  - Market mapping: M:N market ↔ macro driver (Energy/Rates/USD/Metals/Ags/Equities) with weights summing to 1.0 ±0.01.
  - Stream event `feature.cot.updated` emitted within 1 s of recompute.
  - Cache: in-memory keyed by market+report_date; TTL 24 h; cache-bust on new ingest. p95 GET ≤150 ms cached.
- **Data model:**
  - `cot_markets` — CFTC-reportable market registry.
  - `cot_positions_weekly` — time-series fact (one row per market-week-source-revision) with net, WoW delta, percentile, signal tag; partitioned by month/quarter.
  - `macro_drivers` — canonical macro themes.
  - `instrument_universe` — tradable instruments optionally linked to COT markets.
  - `instrument_macro_driver_map` — M:N with weights, sign, confidence, effective date range.
- **Frontend:**
  - Macro Positioning table: rows = markets; columns = Net, WoW Δ, 3y Percentile (bar), Tag (single badge), Driver(s), As-of.
  - Detail drawer: 3y area chart for Net, Percentile line, WoW bars; historical toggle (1y/3y/5y).
  - Driver map panel: filter by macro driver to see impacted markets/equity proxies.
  - Tag priority logic: Extreme > Contrarian > Confirmation > Neutral; colour + icon for accessibility.
  - Export CSV (Operator/PM only).
  - Stale badge when As-of >10 days; "Revised" chip on revisions.
- **Depends on:** Market Data Pipeline (optional spot price for context, though COT is price-agnostic per PRD); Data Storage & Feature Store (historical COT archive); Decision Engine / Indicator State Engine (downstream consumers).
- **External:** CFTC Disaggregated COT reports (public download, weekly); optional vendor for faster/cleaner delivery.
- **Notes:** The frontend tag logic (thresholds: Extreme ≥90/≤10, Contrarian, Confirmation) differs slightly from the backend logic (contrarian ≤10/≥90, confirmation_bias ≤35/≥65) — specifically the frontend adds a "Contrarian Setup" composite tag (extreme percentile + reversal WoW delta). This discrepancy must be reconciled. Non-Managed-Money categories (Producer, Swap Dealer) are explicitly out of scope.

---

### Market Data Ingestion Pipeline

*(Note: This is one of two near-duplicate features. See also "Market Data Pipeline & Ingestion" below. Both cover the same domain. This entry is based on the `market-data-ingestion-pipeline` folder.)*

- **Purpose:** Real-time and historical market data ingestion across multiple exchanges/brokers with unified schemas, deduplication, clock-synchronised timestamps, durable storage, and low-latency streams for downstream engines.
- **Backend:**
  - Supported types: trades, quotes (L1), order book L2/L3 snapshots/deltas, candles (1 s–1 d), reference data, corporate actions.
  - Canonical symbol: `{venue}:{base-quote}:{instrument_type}`.
  - Timestamps: `event_time_ns` (exchange) and `ingest_time_ns` (system) in UTC nanoseconds.
  - Dedup: idempotency key per record type (trade_id, event_time_ns + bid/ask, book level + seq, candle open_time_ns).
  - Late/out-of-order: tolerated up to 2 s; beyond → mark late=true and route to dead-letter.
  - Time sync: NTP/PTP; drift alert >2 ms; stop publishing if drift >10 ms.
  - Gap detection: auto gap-fill jobs within 5 min; idempotent.
  - Stream topics: md.trades.v1, md.quotes.v1, md.book.delta.v1, md.book.snap.v1, md.candles.v1, md.ref.v1.
  - Performance: p99 end-to-end ≤50 ms (US venues), ≤80 ms (global); DLQ rate <10 ppm.
- **Data model:**
  - `exchanges` / `instrument_listings` / `instruments` — venue/instrument topology.
  - `data_feeds` — per venue/channel/depth feed catalog.
  - `raw_market_events` / `market_events_normalized` — two-layer ingest (raw audit + normalised analytics).
  - `stream_offsets` — idempotent checkpoints per feed/instrument/partition.
  - `clock_sync_metrics` — offset/jitter per venue/method.
  - `ordering_anomalies` — gaps, reorders, time jumps for auto-reconciliation.
  - `import_jobs` — backfill job control.
- **Frontend:**
  - Ingestion Dashboard: global status, per-feed tiles, aggregate KPIs.
  - Source Registry: exchange/venue config, symbol universes, obfuscated credentials.
  - Stream Detail: live metrics, normalised sample preview, dedup stats, time-sync status.
  - Backfill Console: schedule/run with dry-run, overlap protection (skip/overwrite/new partition).
  - Schema & Normalisation: per-source field mapping preview (raw vs normalised).
  - Time Sync: clock drift visualisation per source vs NTP reference.
- **Depends on:** Admin Console (RBAC); Data Storage & Feature Store (durable sink); Deployment & DevOps (credential management); Monitoring & Telemetry (health/alerting).
- **External:** Exchange/broker WebSocket/REST APIs; NTP/PTP time servers; historical data vendors (CSV/Parquet).
- **Notes:** **NEAR-DUPLICATE of Market Data Pipeline & Ingestion** (folder: `market-data-pipeline-ingestion`). The two PRD sets describe the same system at different levels of detail and with slightly different SLOs (p99 ≤50 ms here vs ≤15 ms WS in the other). Key differences: this version uses nanosecond timestamps; the other uses milliseconds. This version specifies 10 ppm DLQ rate; the other specifies "zero loss." Both must be reconciled and merged into a single authoritative PRD before implementation.

---

### Market Data Pipeline & Ingestion

*(Note: Near-duplicate of Market Data Ingestion Pipeline above. Based on the `market-data-pipeline-ingestion` folder. See Notes for comparison.)*

- **Purpose:** Real-time acquisition from exchanges, brokers, and news sources with unified schema, precise time alignment, lossless deduplication, WAL-backed resilience, and HFT-grade delivery to downstream consumers.
- **Backend:**
  - All required data types including **news items** (not explicitly covered in the other PRD).
  - Unified schema fields include: `leviathan_symbol`, `processing_time`, `reconstructed` flag, `flags[]` array; event envelope uses UUIDv7 `event_id`.
  - Dedup: composite key `{venue, instrument_id, event_type, sequence|trade_id|provider_id}`; coalesce book deltas in micro-batch.
  - Out-of-order buffer: up to 150 ms or 500 messages (whichever first); re-order by sequence; gap fill on discontinuity.
  - In-memory cache: last trade, NBBO, top-of-book, L2 snapshot (configurable depth), last N=1000 events per instrument.
  - Micro-batching: 500 events or 50 ms threshold; backpressure if lag >1 s (increase batch to 5 k, drop non-critical verbose deltas).
  - WAL: write-ahead log of raw events; restart replays WAL then reconciles with gap fill.
  - Performance: p99 WS ≤15 ms under 200 k ev/s; ≥250 k events/sec per cluster shard; zero loss in steady state.
- **Data model:**
  - `venues` / `connectors` — exchange/broker/news topology.
  - `instruments` / `instrument_mappings` — canonical symbol + venue mappings with validity windows.
  - `raw_events` — all raw events with checksum and dedup flag.
  - `normalized_trades` / `normalized_quotes` / `order_book_updates` / `news_events` — per-type normalised tables.
  - `corporate_actions` — splits/dividends/symbol changes with details JSON.
  - `ingestion_checkpoints` / `gap_fills` / `time_sync_measurements` / `batch_windows` — fault tolerance state.
  - `dedupe_fingerprints` — cross-layer dedup tracking.
- **Frontend:**
  - Connectors Dashboard: status, heartbeat age, msg rate, skew per adapter.
  - Connector Detail: live metrics, unified schema preview, subscription sets, retry/backoff config.
  - Normalization & Time Sync: global and per-connector rules, live skew graph, sample before/after.
  - Reference Data & Symbology: symbol directory, mappings with effective dates, corporate actions.
  - Cache & Batching: hit/miss, TTL, micro-batch config, downstream topic selection.
  - Fault Tolerance & Gaps: reconnect policy, persistence toggle, gap detection timeline, manual gap-fill.
- **Depends on:** Admin Console (RBAC); Data Storage & Feature Store (durable sink); Deployment & DevOps (connector credentials via Vault); Monitoring & Telemetry.
- **External:** Same as above — exchange/broker WebSocket/REST, NTP/PTP, news streaming APIs and webhooks.
- **Notes:** **NEAR-DUPLICATE of Market Data Ingestion Pipeline** (folder: `market-data-ingestion-pipeline`). Key differences from the other version: (1) includes news/alerts as a required data type; (2) uses millisecond-resolution timestamps (not nanoseconds); (3) specifies stricter SLO (p99 ≤15 ms WS vs ≤50 ms); (4) adds WAL for crash recovery; (5) includes micro-batch backpressure with selective delta dropping; (6) uses UUIDv7 for event IDs. These two PRDs must be merged. The recommended canonical is this one (market-data-pipeline-ingestion) given more complete fault tolerance and higher SLO specificity, absorbing the nanosecond timestamp precision from the other.

---

## Duplicate / Conflicting PRD Analysis

### Confirmed Duplicates

1. **`market-data-ingestion-pipeline` vs `market-data-pipeline-ingestion`** — Both describe the same real-time and historical market data ingestion system for the LEVIATHAN AI platform. They overlap in >90% of scope. Key divergences that must be resolved before implementation:
   - **Timestamp precision:** nanoseconds (ingestion-pipeline) vs milliseconds (pipeline-ingestion).
   - **SLO:** p99 ≤50 ms (ingestion-pipeline) vs p99 ≤15 ms WS (pipeline-ingestion).
   - **News data:** included only in pipeline-ingestion.
   - **WAL / micro-batch backpressure:** only in pipeline-ingestion.
   - **Event ID format:** UUID (ingestion-pipeline) vs UUIDv7 (pipeline-ingestion).
   - **Recommended action:** Merge into one canonical PRD. Use pipeline-ingestion as the base; adopt nanosecond timestamps from ingestion-pipeline; reconcile SLO.

### Intentional Non-Duplicates (Flagged for Clarity)

2. **`knowledge-ingestion` vs `knowledge-ingestion-obsidian-sync`** — NOT duplicates. The `knowledge-ingestion` folder contains explicitly **archived/deprecated** PRDs for a legacy general-purpose knowledge ingestion system. The `knowledge-ingestion-obsidian-sync` folder contains the **active replacement** scoped specifically to Obsidian vaults, PDFs, and YouTube transcripts with TRITON lineage. The archived module deliberately cross-references the new system and Market Data Pipeline as successors. No consolidation needed — the archived module should remain read-only.
