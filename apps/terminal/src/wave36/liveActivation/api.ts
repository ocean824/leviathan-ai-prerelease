import { isSafeIdentifier } from "../../shared/safeLabel";

export const LIVE_ACTIVATION_STATUS_PATH = "/api/live-activation/status";
export const LIVE_ACTIVATION_ENABLE_PATH = "/api/live-activation/enable";
export const LIVE_ACTIVATION_DISABLE_PATH = "/api/live-activation/disable";
export const LIVE_CONFIRMATION_PREFIX = "ENABLE LIVE" as const;

export const LIVE_ACTIVATION_ERROR_CODES = [
  "NETWORK_UNAVAILABLE",
  "AUTH_REQUIRED",
  "ACTION_FORBIDDEN",
  "ACCOUNT_NOT_FOUND",
  "FEATURE_UNAVAILABLE",
  "INVALID_ACCOUNT_ID",
  "INVALID_QUERY",
  "INVALID_REQUEST",
  "CONFIRMATION_REQUIRED",
  "OWNER_REQUIRED",
  "HALT_ACTIVE",
  "HALT_STATUS_UNAVAILABLE",
  "ENTITLEMENT_UNVERIFIED",
  "ENTITLEMENT_CHANGED",
  "SUBSCRIPTION_INACTIVE",
  "LIVE_FEATURE_NOT_ENTITLED",
  "LIVE_ACCOUNT_LIMIT_REACHED",
  "MFA_UNVERIFIED",
  "MFA_STALE",
  "BROKER_BINDING_UNVERIFIED",
  "BROKER_EVIDENCE_STALE",
  "RISK_ACK_MISMATCH",
  "RISK_POLICY_CHANGED",
  "RISK_ACK_STALE",
  "RECOVERY_NOT_READY",
  "FAULT_ACTIVE",
  "FEED_EVIDENCE_STALE",
  "ACCOUNT_EVIDENCE_STALE",
  "ACCOUNT_BINDING_CHANGED",
  "ACCOUNT_EVIDENCE_UNAVAILABLE",
  "EVIDENCE_UNAVAILABLE",
  "STORE_UNAVAILABLE",
  "HTTP_ERROR",
  "INVALID_RESPONSE",
] as const;
export type LiveActivationErrorCode = (typeof LIVE_ACTIVATION_ERROR_CODES)[number];

export const LIVE_ACTIVATION_BLOCKER_CODES = [
  "ACCOUNT_NOT_SELECTED",
  "HALT_ACTIVE",
  "OWNER_REQUIRED",
  "ENTITLEMENT_UNVERIFIED",
  "ENTITLEMENT_CHANGED",
  "SUBSCRIPTION_INACTIVE",
  "LIVE_FEATURE_NOT_ENTITLED",
  "LIVE_ACCOUNT_LIMIT_REACHED",
  "MFA_UNVERIFIED",
  "MFA_STALE",
  "BROKER_BINDING_UNVERIFIED",
  "BROKER_EVIDENCE_STALE",
  "RISK_ACK_MISMATCH",
  "RISK_POLICY_CHANGED",
  "RISK_ACK_STALE",
  "RECOVERY_NOT_READY",
  "FAULT_ACTIVE",
  "FEED_EVIDENCE_STALE",
  "ACCOUNT_EVIDENCE_STALE",
  "EVIDENCE_UNAVAILABLE",
  "HALT_STATUS_UNAVAILABLE",
] as const;
export type LiveActivationBlockerCode = (typeof LIVE_ACTIVATION_BLOCKER_CODES)[number];

export const LIVE_OPEN_ORDER_STATUSES = [
  "CREATED", "RISK_PENDING", "READY", "SUBMITTING", "DISPATCH_IN_FLIGHT", "WORKING",
  "PARTIALLY_FILLED", "CANCEL_PENDING", "CANCEL_REQUESTED_UNCONFIRMED", "UNKNOWN_SUBMIT",
  "UNKNOWN_CANCEL", "RECONCILE_REQUIRED",
] as const;

export interface LiveOpenOrderV1 {
  order_id: string;
  instrument_id: string;
  side: "BUY" | "SELL";
  quantity: string;
  status: (typeof LIVE_OPEN_ORDER_STATUSES)[number];
  verified_at_ns: number;
}

export interface LiveActivationStatusV1 {
  effective_state: "LIVE" | "OFF";
  verified: boolean;
  preconditions_verified: boolean;
  account_id: string | null;
  activation_revision: number;
  activated_at_ns: number | null;
  last_verified_at_ns: number | null;
  risk_policy_sha256: string | null;
  blockers: LiveActivationBlockerCode[];
  startup_state: "OFF";
  open_orders_state: "VERIFIED" | "UNAVAILABLE";
  open_orders?: LiveOpenOrderV1[];
}

export interface LiveActivationReceiptV1 {
  accepted: true;
  effective_state: "LIVE" | "OFF";
  activation_revision: number;
}

export type LiveActivationApiResult<T> =
  | { ok: true; data: T }
  | { ok: false; error: LiveActivationErrorCode };

export interface LiveActivationApi {
  getStatus(accountId?: string): Promise<LiveActivationApiResult<LiveActivationStatusV1>>;
  enable(accountId: string, confirmation: string): Promise<LiveActivationApiResult<LiveActivationReceiptV1>>;
  disable(accountId: string): Promise<LiveActivationApiResult<LiveActivationReceiptV1>>;
}

export type LiveActivationFetcher = typeof fetch;

type UnknownRecord = Record<string, unknown>;

function isRecord(value: unknown): value is UnknownRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasOnlyKeys(value: UnknownRecord, allowed: readonly string[]): boolean {
  return Object.keys(value).every((key) => allowed.includes(key));
}

function isTimestamp(value: unknown): value is number | null {
  // Epoch nanoseconds exceed JS's safe integer range; the UI displays them only.
  return value === null || (typeof value === "number" && Number.isInteger(value) && value >= 0);
}

function isDigest(value: unknown): value is string | null {
  return value === null || (typeof value === "string" && /^[0-9a-f]{64}$/.test(value));
}

function parseOpenOrder(value: unknown): LiveOpenOrderV1 | null {
  if (!isRecord(value) || !hasOnlyKeys(value, [
    "order_id", "instrument_id", "side", "quantity", "status", "verified_at_ns",
  ])) return null;
  if (typeof value.order_id !== "string" || !isSafeIdentifier(value.order_id)) return null;
  if (typeof value.instrument_id !== "string" || !isSafeIdentifier(value.instrument_id)) return null;
  if (value.side !== "BUY" && value.side !== "SELL") return null;
  if (typeof value.quantity !== "string" || value.quantity.length > 128 ||
      !/^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:E[+-]?[0-9]+)?$/.test(value.quantity) ||
      value.quantity.split("E", 1)[0]!.replace(/[.0]/g, "").length === 0) return null;
  if (typeof value.status !== "string" || !LIVE_OPEN_ORDER_STATUSES.includes(value.status as LiveOpenOrderV1["status"])) return null;
  if (typeof value.verified_at_ns !== "number" || !Number.isInteger(value.verified_at_ns) || value.verified_at_ns < 0) return null;
  return value as unknown as LiveOpenOrderV1;
}

function parseStatus(value: unknown): LiveActivationStatusV1 | null {
  if (!isRecord(value) || !hasOnlyKeys(value, [
    "effective_state", "verified", "preconditions_verified", "account_id", "activation_revision",
    "activated_at_ns", "last_verified_at_ns", "risk_policy_sha256", "blockers", "startup_state",
    "open_orders_state", "open_orders",
  ])) return null;
  if (value.effective_state !== "LIVE" && value.effective_state !== "OFF") return null;
  if (typeof value.verified !== "boolean" || typeof value.preconditions_verified !== "boolean") return null;
  if (value.account_id !== null && (typeof value.account_id !== "string" || !isSafeIdentifier(value.account_id))) return null;
  if (typeof value.activation_revision !== "number" || !Number.isSafeInteger(value.activation_revision) || value.activation_revision < 0) return null;
  if (!isTimestamp(value.activated_at_ns) || !isTimestamp(value.last_verified_at_ns) || !isDigest(value.risk_policy_sha256)) return null;
  if (!Array.isArray(value.blockers) || !value.blockers.every((item) =>
    typeof item === "string" && LIVE_ACTIVATION_BLOCKER_CODES.includes(item as LiveActivationBlockerCode))) return null;
  if (value.startup_state !== "OFF") return null;
  if (value.open_orders_state === "VERIFIED") {
    if (!Array.isArray(value.open_orders) || value.open_orders.length > 200) return null;
    const rows = value.open_orders.map(parseOpenOrder);
    if (rows.some((row) => row === null)) return null;
    if (new Set(rows.map((row) => row!.order_id)).size !== rows.length) return null;
  } else if (value.open_orders_state === "UNAVAILABLE") {
    if (Object.hasOwn(value, "open_orders")) return null;
  } else return null;
  // A LIVE state is only accepted when the API explicitly marks the evidence verified.
  if (value.effective_state === "LIVE" && (value.verified !== true || value.preconditions_verified !== true)) return null;
  return value as unknown as LiveActivationStatusV1;
}

function parseReceipt(expected: "LIVE" | "OFF"): (value: unknown) => LiveActivationReceiptV1 | null {
  return (value) => {
    if (!isRecord(value) || !hasOnlyKeys(value, ["accepted", "effective_state", "activation_revision"])) return null;
    return value.accepted === true && value.effective_state === expected &&
      typeof value.activation_revision === "number" && Number.isSafeInteger(value.activation_revision) &&
      value.activation_revision >= 0
      ? value as unknown as LiveActivationReceiptV1
      : null;
  };
}

function errorFromResponse(status: number, body: unknown): LiveActivationErrorCode {
  if (isRecord(body) && isRecord(body.error) && typeof body.error.code === "string" &&
      LIVE_ACTIVATION_ERROR_CODES.includes(body.error.code as LiveActivationErrorCode)) {
    return body.error.code as LiveActivationErrorCode;
  }
  if (status === 401) return "AUTH_REQUIRED";
  if (status === 403) return "ACTION_FORBIDDEN";
  if (status === 404) return "ACCOUNT_NOT_FOUND";
  if (status === 503) return "FEATURE_UNAVAILABLE";
  return "HTTP_ERROR";
}

async function requestJson<T>(
  fetcher: LiveActivationFetcher,
  path: string,
  init: RequestInit,
  parse: (value: unknown) => T | null,
): Promise<LiveActivationApiResult<T>> {
  let response: Response;
  try {
    response = await fetcher(path, { ...init, credentials: "same-origin", cache: "no-store" });
  } catch {
    return { ok: false, error: "NETWORK_UNAVAILABLE" };
  }
  let body: unknown;
  try {
    body = await response.json();
  } catch {
    return { ok: false, error: "INVALID_RESPONSE" };
  }
  if (!response.ok) return { ok: false, error: errorFromResponse(response.status, body) };
  const data = parse(body);
  return data === null ? { ok: false, error: "INVALID_RESPONSE" } : { ok: true, data };
}

export function createLiveActivationApi(fetcher: LiveActivationFetcher = fetch): LiveActivationApi {
  return {
    getStatus: (accountId) => {
      if (accountId !== undefined && !isSafeIdentifier(accountId)) {
        return Promise.resolve({ ok: false, error: "INVALID_ACCOUNT_ID" });
      }
      const query = accountId === undefined ? "" : `?account_id=${encodeURIComponent(accountId)}`;
      return requestJson(
        fetcher,
        `${LIVE_ACTIVATION_STATUS_PATH}${query}`,
        { method: "GET", headers: { Accept: "application/json" } },
        parseStatus,
      );
    },
    enable: (accountId, confirmation) => {
      if (!isSafeIdentifier(accountId)) return Promise.resolve({ ok: false, error: "INVALID_ACCOUNT_ID" });
      if (confirmation !== `${LIVE_CONFIRMATION_PREFIX} ${accountId}`) {
        return Promise.resolve({ ok: false, error: "CONFIRMATION_REQUIRED" });
      }
      return requestJson(
        fetcher,
        LIVE_ACTIVATION_ENABLE_PATH,
        {
          method: "POST",
          headers: { Accept: "application/json", "Content-Type": "application/json" },
          body: JSON.stringify({ account_id: accountId, confirmation }),
        },
        parseReceipt("LIVE"),
      );
    },
    disable: (accountId) => {
      if (!isSafeIdentifier(accountId)) return Promise.resolve({ ok: false, error: "INVALID_ACCOUNT_ID" });
      return requestJson(
        fetcher,
        LIVE_ACTIVATION_DISABLE_PATH,
        {
          method: "POST",
          headers: { Accept: "application/json", "Content-Type": "application/json" },
          body: JSON.stringify({ account_id: accountId }),
        },
        parseReceipt("OFF"),
      );
    },
  };
}
