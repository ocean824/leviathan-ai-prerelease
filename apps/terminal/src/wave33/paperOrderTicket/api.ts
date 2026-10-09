export const PAPER_ORDER_CREATE_PATH = "/api/orders";
export const PAPER_ORDER_ENVIRONMENT = "paper" as const;

export type PaperOrderSide = "BUY" | "SELL";
export type PaperOrderType = "MARKET" | "LIMIT";
export type PaperOrderTimeInForce = "DAY" | "GTC" | "GTD";

export interface PaperOrderCreateRequest {
  readonly environment: "paper";
  readonly account_id: string;
  readonly venue: string;
  readonly instrument_id: string;
  readonly native_contract_id: string;
  readonly side: PaperOrderSide;
  readonly quantity: string;
  readonly order_type: PaperOrderType;
  readonly time_in_force: PaperOrderTimeInForce;
  readonly intent_idempotency_key: string;
  readonly attempt: 1;
  readonly strategy_id: string;
  readonly risk_policy_digest: string;
  readonly limit_price?: string | null;
  readonly expires_at?: string | null;
}

export const PAPER_ORDER_STATES = [
  "CREATED", "RISK_PENDING", "RISK_REJECTED", "READY", "SUBMITTING",
  "DISPATCH_IN_FLIGHT", "WORKING", "PARTIALLY_FILLED", "FILLED", "REJECTED",
  "REJECTED_HALTED", "EXPIRED", "CANCEL_PENDING", "CANCEL_REQUESTED_UNCONFIRMED",
  "CANCELED", "UNKNOWN_SUBMIT", "UNKNOWN_CANCEL", "RECONCILE_REQUIRED",
] as const;
export type PaperOrderState = (typeof PAPER_ORDER_STATES)[number];

export interface PaperOrderSnapshot {
  readonly order_id: string;
  readonly state: PaperOrderState;
  readonly version: number;
  readonly environment: "paper";
  readonly account_id: string;
  readonly venue: string;
  readonly instrument_id: string;
  readonly strategy_id: string;
  readonly filled_quantity: string;
  readonly venue_order_id: string | null;
  readonly discrepancies: readonly string[];
  readonly submit_attempted: boolean;
  readonly cancel_attempted: boolean;
}

export const PAPER_ORDER_ERROR_CODES = [
  "NETWORK_UNAVAILABLE", "OPERATOR_REQUIRED", "ACTIVATION_DENIED", "ACTIVATION_DISABLED",
  "LIVE_DISABLED", "CREDENTIAL_BINDING_DENIED", "NATIVE_CONTRACT_DENIED", "HALT_ACTIVE", "EVIDENCE_UNAVAILABLE",
  "PAPER_EVIDENCE_DENIED", "IDEMPOTENCY_CONFLICT", "STALE_BROKER_VIEW", "INVALID_ENVIRONMENT",
  "INVALID_ORDER_SCOPE", "INVALID_ORDER_REQUEST", "INVALID_QUANTITY", "INVALID_LIMIT_PRICE",
  "INVALID_EXPIRY", "INVALID_POLICY_DIGEST", "INVALID_ORDER_IDENTITY", "INVALID_ATTEMPT",
  "POLICY_OUT_OF_BOUNDS", "PRECISION_EXCEEDED", "UNSUPPORTED_ORDER", "UNSUPPORTED_TIF",
  "ORDER_NOT_FOUND", "HTTP_ERROR", "INVALID_RESPONSE",
] as const;
export type PaperOrderErrorCode = (typeof PAPER_ORDER_ERROR_CODES)[number];

export type PaperOrderResult<T> =
  | { readonly ok: true; readonly data: T }
  | { readonly ok: false; readonly error: PaperOrderErrorCode };

export interface PaperOrderTicketApi {
  createOrder(request: PaperOrderCreateRequest): Promise<PaperOrderResult<PaperOrderSnapshot>>;
  submitOrder(
    orderId: string,
    expectedScope?: Pick<PaperOrderCreateRequest, "environment" | "account_id" | "venue" | "instrument_id" | "strategy_id">,
  ): Promise<PaperOrderResult<PaperOrderSnapshot>>;
}

export type PaperOrderTicketFetcher = typeof fetch;

const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/;
const DECIMAL = /^(?:0|[0-9]+)(?:\.[0-9]+)?$/;
const DIGEST = /^[0-9a-f]{64}$/;
const ORDER_ERROR_SET: ReadonlySet<string> = new Set(PAPER_ORDER_ERROR_CODES);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isIdentifier(value: unknown): value is string {
  return typeof value === "string" && IDENTIFIER.test(value);
}

function hasExactKeys(record: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(record).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function validCreateRequest(value: PaperOrderCreateRequest): boolean {
  if (!isRecord(value) || value.environment !== PAPER_ORDER_ENVIRONMENT) return false;
  const required = [
    "environment", "account_id", "venue", "instrument_id", "native_contract_id", "side",
    "quantity", "order_type", "time_in_force", "intent_idempotency_key", "attempt",
    "strategy_id", "risk_policy_digest",
  ];
  const allowed = [...required, "limit_price", "expires_at"];
  if (Object.keys(value).some((key) => !allowed.includes(key)) || required.some((key) => !(key in value))) return false;
  return (
    [value.account_id, value.venue, value.instrument_id, value.native_contract_id,
      value.intent_idempotency_key, value.strategy_id].every(isIdentifier) &&
    (value.side === "BUY" || value.side === "SELL") &&
    typeof value.quantity === "string" && DECIMAL.test(value.quantity) &&
    (value.order_type === "MARKET" || value.order_type === "LIMIT") &&
    (value.time_in_force === "DAY" || value.time_in_force === "GTC" || value.time_in_force === "GTD") &&
    value.attempt === 1 && DIGEST.test(value.risk_policy_digest) &&
    (value.limit_price === undefined || value.limit_price === null ||
      (typeof value.limit_price === "string" && DECIMAL.test(value.limit_price))) &&
    (value.expires_at === undefined || value.expires_at === null ||
      (typeof value.expires_at === "string" && Number.isFinite(Date.parse(value.expires_at))) ) &&
    ((value.order_type === "LIMIT") === (typeof value.limit_price === "string")) &&
    ((value.time_in_force === "GTD") === (typeof value.expires_at === "string"))
  );
}

const SNAPSHOT_KEYS = [
  "order_id", "state", "version", "environment", "account_id", "venue", "instrument_id",
  "strategy_id", "filled_quantity", "venue_order_id", "discrepancies", "submit_attempted",
  "cancel_attempted",
] as const;

type ExpectedScope = Pick<PaperOrderCreateRequest, "environment" | "account_id" | "venue" | "instrument_id" | "strategy_id">;

function parseSnapshot(value: unknown, expected?: ExpectedScope, expectedOrderId?: string): PaperOrderSnapshot | null {
  if (!isRecord(value) || !hasExactKeys(value, SNAPSHOT_KEYS)) return null;
  if (
    !isIdentifier(value.order_id) || (expectedOrderId !== undefined && value.order_id !== expectedOrderId) ||
    typeof value.state !== "string" || !(PAPER_ORDER_STATES as readonly string[]).includes(value.state) ||
    !Number.isSafeInteger(value.version) || (value.version as number) < 0 ||
    value.environment !== PAPER_ORDER_ENVIRONMENT || !isIdentifier(value.account_id) ||
    !isIdentifier(value.venue) || !isIdentifier(value.instrument_id) || !isIdentifier(value.strategy_id) ||
    typeof value.filled_quantity !== "string" ||
    !(value.venue_order_id === null || isIdentifier(value.venue_order_id)) ||
    !Array.isArray(value.discrepancies) || value.discrepancies.length > 128 ||
    !value.discrepancies.every((item) => typeof item === "string" && item.length <= 64) ||
    typeof value.submit_attempted !== "boolean" || typeof value.cancel_attempted !== "boolean"
  ) return null;
  if (expected && (
    value.environment !== expected.environment || value.account_id !== expected.account_id ||
    value.venue !== expected.venue || value.instrument_id !== expected.instrument_id ||
    value.strategy_id !== expected.strategy_id
  )) return null;
  return {
    order_id: value.order_id,
    state: value.state as PaperOrderState,
    version: value.version as number,
    environment: PAPER_ORDER_ENVIRONMENT,
    account_id: value.account_id,
    venue: value.venue,
    instrument_id: value.instrument_id,
    strategy_id: value.strategy_id,
    filled_quantity: value.filled_quantity,
    venue_order_id: value.venue_order_id,
    discrepancies: [...value.discrepancies] as string[],
    submit_attempted: value.submit_attempted,
    cancel_attempted: value.cancel_attempted,
  };
}

function fixedError(status: number, body: unknown): PaperOrderErrorCode {
  const detail = isRecord(body) && typeof body.detail === "string" ? body.detail : "";
  if (status === 503 && detail === "EVIDENCE_UNAVAILABLE") return "EVIDENCE_UNAVAILABLE";
  if (ORDER_ERROR_SET.has(detail)) return detail as PaperOrderErrorCode;
  if (status === 401) return "OPERATOR_REQUIRED";
  if (status === 403) return "ACTIVATION_DENIED";
  if (status === 409) return "IDEMPOTENCY_CONFLICT";
  if (status === 422) return "INVALID_ORDER_REQUEST";
  if (status >= 500) return "NETWORK_UNAVAILABLE";
  return "HTTP_ERROR";
}

async function readJson(response: Response): Promise<unknown> {
  try { return await response.json(); } catch { return undefined; }
}

export function createPaperOrderTicketApi(fetcher: PaperOrderTicketFetcher = fetch): PaperOrderTicketApi {
  async function post(
    path: string,
    body: PaperOrderCreateRequest | undefined,
    expected?: ExpectedScope,
    expectedOrderId?: string,
  ): Promise<PaperOrderResult<PaperOrderSnapshot>> {
    let response: Response;
    try {
      response = await fetcher(path, {
        method: "POST",
        credentials: "same-origin",
        cache: "no-store",
        headers: { Accept: "application/json", ...(body ? { "Content-Type": "application/json" } : {}) },
        ...(body ? { body: JSON.stringify(body) } : {}),
      });
    } catch {
      return { ok: false, error: "NETWORK_UNAVAILABLE" };
    }
    const responseBody = await readJson(response);
    if (!response.ok) return { ok: false, error: fixedError(response.status, responseBody) };
    const snapshot = parseSnapshot(responseBody, expected, expectedOrderId);
    return snapshot ? { ok: true, data: snapshot } : { ok: false, error: "INVALID_RESPONSE" };
  }

  return {
    createOrder(request) {
      if (!validCreateRequest(request)) return Promise.resolve({ ok: false, error: "INVALID_ORDER_REQUEST" });
      const body: PaperOrderCreateRequest = {
        environment: PAPER_ORDER_ENVIRONMENT,
        account_id: request.account_id,
        venue: request.venue,
        instrument_id: request.instrument_id,
        native_contract_id: request.native_contract_id,
        side: request.side,
        quantity: request.quantity,
        order_type: request.order_type,
        time_in_force: request.time_in_force,
        intent_idempotency_key: request.intent_idempotency_key,
        attempt: 1,
        strategy_id: request.strategy_id,
        risk_policy_digest: request.risk_policy_digest,
        ...(request.limit_price === undefined ? {} : { limit_price: request.limit_price }),
        ...(request.expires_at === undefined ? {} : { expires_at: request.expires_at }),
      };
      return post(PAPER_ORDER_CREATE_PATH, body, body);
    },
    submitOrder(orderId, expectedScope) {
      if (!isIdentifier(orderId)) return Promise.resolve({ ok: false, error: "ORDER_NOT_FOUND" });
      return post(`${PAPER_ORDER_CREATE_PATH}/${encodeURIComponent(orderId)}/submit`, undefined, expectedScope, orderId);
    },
  };
}
