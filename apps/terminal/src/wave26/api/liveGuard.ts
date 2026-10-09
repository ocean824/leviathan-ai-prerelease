/* LIVE-GUARD-UI-001: GET-only readers for the risk and order-gateway status endpoints.
 *
 * Neither endpoint carries a source timestamp today. Responses are reduced to an
 * allowlist of short codes, booleans and counts. A raw body, policy number, limit
 * or account value is never returned, so nothing downstream can render one.
 */
import type { ApiResult } from "../../api/client";

export const RISK_STATUS_PATH = "/risk/status";
export const ORDER_STATUS_PATH = "/orders/status";
export const UNRECOGNIZED = "UNRECOGNIZED";
export const OPERATING_MODES = [
  "research", "advisory", "semi_auto", "full_auto", "prop_firm", "recovery", "signal_only",
] as const;

// Closed sets of codes the gateway itself defines. Halt reasons were free text, so anything
// outside a set is shown only as UNRECOGNIZED. The halt sets mirror
// packages/leviathan-core/src/leviathan_core/risk/halt_reasons.py exactly (HaltReasonV1
// and HaltReasonPatternV1); a drift test in the unit tests reads that file.
export const KNOWN_HALT_CODES: ReadonlySet<string> = new Set([
  "omega_kill_signal",
  "operator_halt",
  "operator_hold",
  "risk_limit_breach",
  "stale_data",
  "reconciliation_divergence",
  "audit_sink_failure",
  "tiamat_hash_mismatch",
  "daily_drawdown_breach",
  "weekly_drawdown_breach",
  "trailing_drawdown_breach",
  "legacy_state_unknown",
]);
/** Closed prefixes of content-addressed OMEGA HALT keys: `<prefix>:<64 lowercase hex>`. */
export const OMEGA_HALT_PREFIXES: ReadonlySet<string> = new Set([
  "omega_kill",
  "omega_bridge_disconnected",
  "omega_bridge_degraded",
]);
/** What an OMEGA-pattern key is shown as. The hex suffix is never rendered. */
export const OMEGA_HALT = "OMEGA_HALT";
const OMEGA_SUFFIX = /^[0-9a-f]{64}$/;
export const KNOWN_FAULT_CODES: ReadonlySet<string> = new Set(["HALT_STORE_UNAVAILABLE"]);
export const KNOWN_RECOVERY_STATUSES: ReadonlySet<string> = new Set([
  "UNKNOWN", "FAILED", "READY",
]);
export const KNOWN_HTTP_REASONS: ReadonlySet<string> = new Set([
  "ACTIVATION_DENIED", "ACTIVATION_DISABLED", "CREDENTIAL_BINDING_DENIED",
  "EVIDENCE_UNAVAILABLE", "HALT_ACTIVE", "HALT_REASON_NOT_ACTIVE", "HALT_STORE_UNAVAILABLE",
  "INVALID_ENVIRONMENT", "INVALID_HALT_REASON", "INVALID_LIMIT_PRICE", "INVALID_ORDER_REQUEST",
  "INVALID_ORDER_SCOPE", "INVALID_QUANTITY", "LIVE_DISABLED", "NATIVE_CONTRACT_DENIED",
  "NOT_CONFIGURED", "OPERATOR_REQUIRED", "ORDER_BODY_TOO_LARGE", "ORDER_NOT_FOUND",
  "PAPER_EVIDENCE_DENIED", "RECOVERY_FAILED",
]);
export const MAX_HALT_CODES = 50;

export interface RiskGuardReport {
  /** The API's `halted` flag, as reported. Never verified here. */
  haltedReported: boolean;
  haltCodes: string[];
  faultCode: string | null;
  operatingMode: string;
  /** Whether a policy object was present. Its values are deliberately not carried. */
  policyReported: boolean;
  /** Present only when the API supplied a valid source timestamp. */
  as_of?: number | string;
}

export interface OrderGuardReport {
  /** The API's `live_enabled` flag, as reported. The view never trusts it. */
  liveEnabledReported: boolean;
  recoveryStatus: string;
  activationCount: number;
  as_of?: number | string;
}

type UnknownRecord = Record<string, unknown>;

function isRecord(value: unknown): value is UnknownRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function sourceStamp(record: UnknownRecord): { as_of?: number | string } {
  const value = record.as_of ?? record.asOf;
  if (typeof value === "number" && Number.isFinite(value)) return { as_of: value };
  if (typeof value === "string" && value.length > 0 && value.length <= 64) return { as_of: value };
  return {};
}

function known(value: string, allowed: ReadonlySet<string>): string {
  return allowed.has(value) ? value : UNRECOGNIZED;
}

/** A static code as is, an exact OMEGA key as OMEGA_HALT, anything else UNRECOGNIZED. */
export function displayHaltCode(value: string): string {
  if (KNOWN_HALT_CODES.has(value)) return value;
  const separator = value.indexOf(":");
  if (separator === -1) return UNRECOGNIZED;
  const prefix = value.slice(0, separator);
  const suffix = value.slice(separator + 1);
  return OMEGA_HALT_PREFIXES.has(prefix) && OMEGA_SUFFIX.test(suffix) ? OMEGA_HALT : UNRECOGNIZED;
}

export function parseRiskGuard(value: unknown): RiskGuardReport | null {
  if (!isRecord(value)) return null;
  const { halted, active_halts: activeHalts, fault_code: faultCode, operating_mode: mode } = value;
  if (typeof halted !== "boolean" || !Array.isArray(activeHalts) || typeof mode !== "string") {
    return null;
  }
  // Fail closed on a hostile size before scanning; never show a partial reason set.
  if (activeHalts.length > MAX_HALT_CODES) return null;
  if (!activeHalts.every((item) => typeof item === "string")) return null;
  if (faultCode !== undefined && faultCode !== null && typeof faultCode !== "string") return null;
  const policy = value.policy;
  if (policy !== undefined && policy !== null && !isRecord(policy)) return null;
  return {
    haltedReported: halted,
    haltCodes: (activeHalts as string[]).map(displayHaltCode),
    faultCode: typeof faultCode === "string" ? known(faultCode, KNOWN_FAULT_CODES) : null,
    operatingMode: (OPERATING_MODES as readonly string[]).includes(mode) ? mode : UNRECOGNIZED,
    policyReported: isRecord(policy),
    ...sourceStamp(value),
  };
}

export function parseOrderGuard(value: unknown): OrderGuardReport | null {
  if (!isRecord(value)) return null;
  const { live_enabled: liveEnabled, recovery_status: recovery, activation_count: count } = value;
  if (typeof liveEnabled !== "boolean" || typeof recovery !== "string") return null;
  if (typeof count !== "number" || !Number.isSafeInteger(count) || count < 0) return null;
  return {
    liveEnabledReported: liveEnabled,
    recoveryStatus: known(recovery, KNOWN_RECOVERY_STATUSES),
    activationCount: count,
    ...sourceStamp(value),
  };
}

function httpCode(status: number, body: unknown): string {
  if (!Number.isInteger(status) || status < 100 || status > 599) return "HTTP_ERROR";
  const detail = isRecord(body) ? body.detail : undefined;
  return typeof detail === "string" && KNOWN_HTTP_REASONS.has(detail)
    ? `HTTP_${status}:${detail}`
    : `HTTP_${status}`;
}

async function getReport<T>(
  path: string,
  parse: (value: unknown) => T | null,
): Promise<ApiResult<T>> {
  let response: Response;
  try {
    response = await fetch(`/api${path}`, { method: "GET", headers: { Accept: "application/json" } });
  } catch {
    return { ok: false, error: "NETWORK_ERROR" };
  }
  let body: unknown;
  try {
    body = await response.json();
  } catch {
    body = undefined;
  }
  if (!response.ok) return { ok: false, error: httpCode(response.status, body) };
  const report = parse(body);
  return report === null ? { ok: false, error: "MALFORMED_RESPONSE" } : { ok: true, data: report };
}

export const fetchRiskGuard = (): Promise<ApiResult<RiskGuardReport>> =>
  getReport(RISK_STATUS_PATH, parseRiskGuard);

export const fetchOrderGuard = (): Promise<ApiResult<OrderGuardReport>> =>
  getReport(ORDER_STATUS_PATH, parseOrderGuard);
