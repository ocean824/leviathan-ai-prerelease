export const ORDER_MONITOR_STATES = [
  "CREATED",
  "RISK_PENDING",
  "RISK_REJECTED",
  "READY",
  "SUBMITTING",
  "DISPATCH_IN_FLIGHT",
  "WORKING",
  "PARTIALLY_FILLED",
  "FILLED",
  "REJECTED",
  "REJECTED_HALTED",
  "EXPIRED",
  "CANCEL_PENDING",
  "CANCEL_REQUESTED_UNCONFIRMED",
  "CANCELED",
  "UNKNOWN_SUBMIT",
  "UNKNOWN_CANCEL",
  "RECONCILE_REQUIRED",
] as const;

export type OrderMonitorOrderState = (typeof ORDER_MONITOR_STATES)[number];

export interface OrderMonitorStatus {
  live_enabled: false;
  recovery_status: "UNKNOWN" | "READY";
  activation_count: number;
}

export interface OrderMonitorOrder {
  order_id: string;
  state: OrderMonitorOrderState;
  version: number;
  environment: string;
  account_id: string;
  venue: string;
  instrument_id: string;
  strategy_id: string;
  filled_quantity: string;
  venue_order_id: string | null;
  discrepancies: string[];
  submit_attempted: boolean;
  cancel_attempted: boolean;
}

export type OrderMonitorErrorCode =
  | "INVALID_ORDER_ID"
  | "UNAUTHORIZED"
  | "NOT_FOUND"
  | "HTTP_ERROR"
  | "GATEWAY_UNAVAILABLE"
  | "INVALID_RESPONSE";

export type ApiResult<T> =
  | { ok: true; data: T }
  | { ok: false; error: OrderMonitorErrorCode };

export interface OrderMonitorClient {
  getStatus(): Promise<ApiResult<OrderMonitorStatus>>;
  getOrder(orderId: string): Promise<ApiResult<OrderMonitorOrder>>;
}

export type OrderMonitorDisposition = "ACCEPTED" | "FILLED" | "UNKNOWN" | "OTHER";

const BROKER_UNCONFIRMED_STATES = new Set<OrderMonitorOrderState>([
  "SUBMITTING",
  "DISPATCH_IN_FLIGHT",
  "CANCEL_PENDING",
  "CANCEL_REQUESTED_UNCONFIRMED",
  "UNKNOWN_SUBMIT",
  "UNKNOWN_CANCEL",
  "RECONCILE_REQUIRED",
]);

export function classifyOrderDisposition(order: OrderMonitorOrder): OrderMonitorDisposition {
  if (order.state === "FILLED") return "FILLED";
  if (order.state === "WORKING" || order.state === "PARTIALLY_FILLED") return "ACCEPTED";
  if (BROKER_UNCONFIRMED_STATES.has(order.state)) return "UNKNOWN";
  return "OTHER";
}

export const ORDER_ID_PATTERN = /^[0-9a-f]{32}$/;

export function isValidOrderId(value: unknown): value is string {
  return typeof value === "string" && ORDER_ID_PATTERN.test(value);
}
const DISCREPANCY_CODE = /^[A-Z0-9_:-]{1,80}$/;
const DECIMAL_TEXT = /^(?:0|[0-9]+)(?:\.[0-9]+)?(?:[Ee][+-]?[0-9]+)?$/;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 256;
}

function isOrderState(value: unknown): value is OrderMonitorOrderState {
  return typeof value === "string" &&
    (ORDER_MONITOR_STATES as readonly string[]).includes(value);
}

function parseStatus(value: unknown): OrderMonitorStatus | null {
  if (!isRecord(value) || value.live_enabled !== false ||
      (value.recovery_status !== "UNKNOWN" && value.recovery_status !== "READY") ||
      !Number.isSafeInteger(value.activation_count) ||
      (value.activation_count as number) < 0) return null;
  return {
    live_enabled: false,
    recovery_status: value.recovery_status,
    activation_count: value.activation_count as number,
  };
}

function parseOrder(value: unknown, requestedId: string): OrderMonitorOrder | null {
  if (!isRecord(value) || value.order_id !== requestedId || !isOrderState(value.state) ||
      !Number.isSafeInteger(value.version) || (value.version as number) < 0 ||
      (value.environment !== "paper" && value.environment !== "demo") ||
      !isString(value.account_id) || !isString(value.venue) ||
      !isString(value.instrument_id) || !isString(value.strategy_id) ||
      typeof value.filled_quantity !== "string" || value.filled_quantity.length > 128 ||
      !DECIMAL_TEXT.test(value.filled_quantity) ||
      (value.venue_order_id !== null && !isString(value.venue_order_id)) ||
      !Array.isArray(value.discrepancies) ||
      !value.discrepancies.every((item) => typeof item === "string") ||
      typeof value.submit_attempted !== "boolean" || typeof value.cancel_attempted !== "boolean") {
    return null;
  }
  return {
    order_id: value.order_id,
    state: value.state,
    version: value.version as number,
    environment: value.environment,
    account_id: value.account_id,
    venue: value.venue,
    instrument_id: value.instrument_id,
    strategy_id: value.strategy_id,
    filled_quantity: value.filled_quantity,
    venue_order_id: value.venue_order_id,
    discrepancies: value.discrepancies.filter((item): item is string =>
      typeof item === "string" && DISCREPANCY_CODE.test(item)),
    submit_attempted: value.submit_attempted,
    cancel_attempted: value.cancel_attempted,
  };
}

async function getJson<T>(path: string, parse: (value: unknown) => T | null): Promise<ApiResult<T>> {
  let response: Response;
  try {
    response = await fetch(`/api${path}`, {
      method: "GET",
      headers: { Accept: "application/json" },
      credentials: "same-origin",
    });
  } catch {
    return { ok: false, error: "GATEWAY_UNAVAILABLE" };
  }
  if (!response.ok) {
    if (response.status === 401 || response.status === 403) {
      return { ok: false, error: "UNAUTHORIZED" };
    }
    if (response.status === 404) return { ok: false, error: "NOT_FOUND" };
    return { ok: false, error: "HTTP_ERROR" };
  }
  let body: unknown;
  try {
    body = await response.json();
  } catch {
    return { ok: false, error: "INVALID_RESPONSE" };
  }
  const data = parse(body);
  return data === null
    ? { ok: false, error: "INVALID_RESPONSE" }
    : { ok: true, data };
}

export const orderMonitorClient: OrderMonitorClient = {
  getStatus: () => getJson("/orders/status", parseStatus),
  getOrder: (orderId) => {
    if (!isValidOrderId(orderId)) {
      return Promise.resolve({ ok: false, error: "INVALID_ORDER_ID" });
    }
    return getJson(`/orders/${encodeURIComponent(orderId)}`, (value) => parseOrder(value, orderId));
  },
};
