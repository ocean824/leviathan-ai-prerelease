export const HALT_STATUS_PATH = "/api/risk/status";
export const HALT_ENGAGE_PATH = "/api/risk/halt";
export const HALT_LIFT_PATH = "/api/risk/halt/lift";

export const HALT_REASON_OPTIONS = [
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
] as const;

export type StaticHaltReason = (typeof HALT_REASON_OPTIONS)[number];
export type KnownHaltReason =
  | StaticHaltReason
  | `omega_kill:${string}`
  | `omega_bridge_disconnected:${string}`
  | `omega_bridge_degraded:${string}`;

export interface HaltStatusV1 {
  halted: boolean;
  active_halts: KnownHaltReason[];
  fault_code: "HALT_STORE_UNAVAILABLE" | null;
  operating_mode: string;
}

export type HaltApiError =
  | "NETWORK_ERROR"
  | "TIMEOUT"
  | "INVALID_RESPONSE"
  | "INVALID_HALT_REASON"
  | "HALT_REASON_NOT_ACTIVE"
  | "HALT_STORE_UNAVAILABLE"
  | "HTTP_ERROR";

export type ApiResult<T> = { ok: true; data: T } | { ok: false; error: HaltApiError };

export interface HaltReceiptV1 {
  halted: boolean;
  active_halts: KnownHaltReason[];
}

export interface PaperHaltApi {
  getStatus(): Promise<ApiResult<HaltStatusV1>>;
  engage(reason: StaticHaltReason): Promise<ApiResult<HaltReceiptV1>>;
  lift(reason: KnownHaltReason): Promise<ApiResult<HaltReceiptV1>>;
}

export type PaperHaltFetcher = typeof fetch;

const OMEGA_REASON_PATTERN =
  /^(?:omega_kill|omega_bridge_disconnected|omega_bridge_degraded):[0-9a-f]{64}$/;
const OPERATING_MODES = new Set([
  "research",
  "advisory",
  "semi_auto",
  "full_auto",
  "prop_firm",
  "recovery",
  "signal_only",
]);
const REQUEST_TIMEOUT_MS = 5_000;
const HALT_STORE_FAULT_REASON = "__halt_store_unavailable__";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isStaticReason(value: unknown): value is StaticHaltReason {
  return typeof value === "string" && (HALT_REASON_OPTIONS as readonly string[]).includes(value);
}

function isKnownReason(value: unknown): value is KnownHaltReason {
  return isStaticReason(value) || (typeof value === "string" && OMEGA_REASON_PATTERN.test(value));
}

function parseReasonList(value: unknown): KnownHaltReason[] | null {
  if (!Array.isArray(value) || value.length > 50 || !value.every(isKnownReason)) return null;
  return [...new Set(value)];
}

function parseStatus(value: unknown): HaltStatusV1 | null {
  if (!isRecord(value) || typeof value.halted !== "boolean") return null;
  const activeInput = value.active_halts;
  if (!Array.isArray(activeInput) || activeInput.length > 50) return null;
  const faultReasonPresent = activeInput.includes(HALT_STORE_FAULT_REASON);
  const activeHalts = parseReasonList(activeInput.filter((reason) => reason !== HALT_STORE_FAULT_REASON));
  if (
    activeHalts === null ||
    (value.fault_code !== null && value.fault_code !== "HALT_STORE_UNAVAILABLE") ||
    faultReasonPresent !== (value.fault_code === "HALT_STORE_UNAVAILABLE") ||
    typeof value.operating_mode !== "string" ||
    !OPERATING_MODES.has(value.operating_mode)
  ) {
    return null;
  }
  return {
    halted: value.halted,
    active_halts: activeHalts,
    fault_code: value.fault_code,
    operating_mode: value.operating_mode,
  };
}

function parseReceipt(value: unknown): HaltReceiptV1 | null {
  if (!isRecord(value) || typeof value.halted !== "boolean") return null;
  const activeHalts = parseReasonList(value.active_halts);
  return activeHalts === null ? null : { halted: value.halted, active_halts: activeHalts };
}

function errorForStatus(status: number): HaltApiError {
  if (status === 409) return "HALT_REASON_NOT_ACTIVE";
  if (status === 422) return "INVALID_HALT_REASON";
  if (status === 503) return "HALT_STORE_UNAVAILABLE";
  return "HTTP_ERROR";
}

async function requestJson<T>(
  fetcher: PaperHaltFetcher,
  path: string,
  init: RequestInit,
  parse: (value: unknown) => T | null,
): Promise<ApiResult<T>> {
  const controller = new AbortController();
  let timedOut = false;
  let timeoutHandle: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_resolve, reject) => {
    timeoutHandle = setTimeout(() => {
      timedOut = true;
      controller.abort();
      reject(new Error("request timeout"));
    }, REQUEST_TIMEOUT_MS);
  });

  const request = async (): Promise<ApiResult<T>> => {
    const response = await fetcher(path, {
      ...init,
      credentials: "same-origin",
      cache: "no-store",
      signal: controller.signal,
    });
    if (!response.ok) return { ok: false, error: errorForStatus(response.status) };
    let body: unknown;
    try {
      body = await response.json();
    } catch {
      return { ok: false, error: "INVALID_RESPONSE" };
    }
    const data = parse(body);
    return data === null ? { ok: false, error: "INVALID_RESPONSE" } : { ok: true, data };
  };

  try {
    return await Promise.race([request(), timeout]);
  } catch {
    return { ok: false, error: timedOut ? "TIMEOUT" : "NETWORK_ERROR" };
  } finally {
    if (timeoutHandle !== undefined) clearTimeout(timeoutHandle);
  }
}

function read<T>(
  fetcher: PaperHaltFetcher,
  path: string,
  parse: (value: unknown) => T | null,
): Promise<ApiResult<T>> {
  return requestJson(fetcher, path, { method: "GET", headers: { Accept: "application/json" } }, parse);
}

function mutate(
  fetcher: PaperHaltFetcher,
  path: string,
  reason: unknown,
): Promise<ApiResult<HaltReceiptV1>> {
  if (!isKnownReason(reason)) {
    return Promise.resolve({ ok: false, error: "INVALID_HALT_REASON" });
  }
  if (path === HALT_ENGAGE_PATH && !isStaticReason(reason)) {
    return Promise.resolve({ ok: false, error: "INVALID_HALT_REASON" });
  }
  return requestJson(
    fetcher,
    path,
    {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify({ reason }),
    },
    parseReceipt,
  );
}

export function createPaperHaltApi(fetcher: PaperHaltFetcher = fetch): PaperHaltApi {
  return {
    getStatus: () => read(fetcher, HALT_STATUS_PATH, parseStatus),
    engage: (reason) => mutate(fetcher, HALT_ENGAGE_PATH, reason),
    lift: (reason) => mutate(fetcher, HALT_LIFT_PATH, reason),
  };
}
