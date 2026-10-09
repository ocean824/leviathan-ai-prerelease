/* LEVIATHAN AI — typed API client */

// ── Response shapes ─────────────────────────────────────────────────────────

export interface HealthResponse {
  status: string;
  service: string;
  version: string;
  core_version: string;
  operating_mode: string;
  env: string;
}

export interface RiskPolicy {
  max_daily_dd_pct: string;
  max_open_heat_pct: string;
  consensus_threshold?: number;
}

export interface RiskStatusResponse {
  halted: boolean;
  active_halts: string[];
  operating_mode: string;
  policy: RiskPolicy;
}

export type TradeOutcome = "win" | "loss" | "scratch" | "blocked";

export interface JournalRecord {
  trade_id: string;
  setup_id: string;
  decision_id: string;
  outcome: TradeOutcome;
  entry: string | null;
  exit: string | null;
  mae: string | null;
  mfe: string | null;
  post_trade_notes: string;
  provenance: "route_attempt_terminal_verified" | "route_attempt_terminal_unverified";
}

export interface JournalResponse {
  records: JournalRecord[];
  stats: Record<string, number>;
  unverified_count: number;
  unverified_reasons?: Record<string, number>;
  provenance: "none" | "verified" | "unverified" | "mixed";
}

export interface Genome {
  strategy_id: string;
  family: string;
  market: string;
  timeframe: string;
  stale: boolean;
}

export interface GenomesResponse {
  genomes: Genome[];
}

export interface PipelineDecision {
  permission: string;
  direction: string;
  confidence: string;
  justification: string;
}

export interface PipelineTruth {
  sentiment_modifier: string;
}

export interface PipelineVerdict {
  action: string;
  reason: string;
}

export interface PipelineJournalRecord {
  outcome: string;
  entry: string | null;
  exit: string | null;
  mae: string | null;
  mfe: string | null;
  post_trade_notes: string;
}

export interface PipelineSession {
  label: string;
  quality: string;
}

export interface PipelineResult {
  decision: PipelineDecision & { decision_id: string };
  verdict: PipelineVerdict;
  final_verdict: PipelineVerdict | null;
  journal_record: PipelineJournalRecord | null;
  intent: unknown | null;
  status: "completed" | "blocked" | "incomplete";
  final: boolean;
  audit_sink_failure: boolean;
  failure_reason: string | null;
  session: PipelineSession;
  truth: PipelineTruth;
}

// ── Discriminated result ─────────────────────────────────────────────────────

export type ApiResult<T> = { ok: true; data: T } | { ok: false; error: string; data?: T };

// ── Core fetch wrapper ───────────────────────────────────────────────────────

async function apiFetch<T>(
  path: string,
  init?: RequestInit,
): Promise<ApiResult<T>> {
  try {
    const res = await fetch(`/api${path}`, {
      headers: { "Content-Type": "application/json" },
      ...init,
    });
    const data = (await res.json()) as T;
    if (!res.ok) {
      return { ok: false, error: `HTTP ${res.status} ${res.statusText}`, data };
    }
    return { ok: true, data };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { ok: false, error: message };
  }
}

// ── Endpoint helpers ─────────────────────────────────────────────────────────

export const api = {
  health: () => apiFetch<HealthResponse>("/health"),

  riskStatus: () => apiFetch<RiskStatusResponse>("/risk/status"),

  journalRecords: (limit = 50) =>
    apiFetch<JournalResponse>(`/journal/records?limit=${limit}`),

  genomes: () => apiFetch<GenomesResponse>("/genomes"),

  pipelineReplay: () =>
    apiFetch<PipelineResult>("/pipeline/replay", { method: "POST", body: "{}" }),
};

// Runtime operator credentials are write-only. Keep this API separate from
// the market-data helpers so callers can only receive status metadata.
export type CredentialProvider = "ALPACA" | "IBKR" | "MT5" | "MCP";
export type CredentialEnvironment = "PAPER" | "DEMO" | "LIVE";

export interface CredentialStatusRow {
  provider: CredentialProvider;
  environment: CredentialEnvironment;
  profile: string;
  configured: Record<string, boolean>;
  updated_at: string | null;
  verification: "NOT_TESTED";
  status?: "CORRUPT";
}

export interface CredentialStatusResponse {
  profiles: CredentialStatusRow[];
}

export interface CredentialPutBody {
  key_id?: string;
  secret_key?: string;
  host?: string;
  port?: number;
  client_id?: number;
  account_id?: string;
  server?: string;
  login?: string;
  password?: string;
  server_id?: string;
  token?: string;
  confirm_environment?: "LIVE";
}

export interface CredentialWriteResponse {
  provider: CredentialProvider;
  environment: CredentialEnvironment;
  profile: string;
  revision: number;
  configured: Record<string, boolean>;
  updated_at: string;
}

export interface CredentialDeleteBody {
  confirm_environment?: "LIVE";
}

async function credentialFetch<T>(path: string, init?: RequestInit): Promise<ApiResult<T>> {
  try {
    const response = await fetch(`/api${path}`, {
      headers: { "Content-Type": "application/json" },
      ...init,
    });
    if (!response.ok) return { ok: false, error: `HTTP ${response.status}` };
    if (response.status === 204) return { ok: true, data: undefined as T };
    return { ok: true, data: (await response.json()) as T };
  } catch {
    return { ok: false, error: "Credential API unavailable" };
  }
}

export const credentialApi = {
  status: () => credentialFetch<CredentialStatusResponse>("/live-trading/credentials"),

  putProfile: (
    provider: CredentialProvider,
    environment: CredentialEnvironment,
    profileId: string,
    body: CredentialPutBody,
  ) => credentialFetch<CredentialWriteResponse>(
    `/live-trading/credentials/${encodeURIComponent(provider)}/${encodeURIComponent(environment)}/${encodeURIComponent(profileId)}`,
    { method: "PUT", body: JSON.stringify(body) },
  ),

  deleteProfile: (
    provider: CredentialProvider,
    environment: CredentialEnvironment,
    profileId: string,
    body?: CredentialDeleteBody,
  ) => credentialFetch<void>(
    `/live-trading/credentials/${encodeURIComponent(provider)}/${encodeURIComponent(environment)}/${encodeURIComponent(profileId)}`,
    { method: "DELETE", ...(body ? { body: JSON.stringify(body) } : {}) },
  ),
};
