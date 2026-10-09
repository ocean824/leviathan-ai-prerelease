export const PAPER_MASS_CANCEL_PATH = "/api/paper/mass-cancel/v1";
export const MAX_MASS_CANCEL_ORDERS = 100;

export const PAPER_MASS_CANCEL_SCOPES = [
  "INSTRUMENT",
  "STRATEGY",
  "ACCOUNT",
] as const;
export type PaperMassCancelScopeV1 = (typeof PAPER_MASS_CANCEL_SCOPES)[number];

export interface PaperMassCancelOrderInputV1 {
  order_id: string;
  client_order_id: string;
  venue_order_id: string;
  instrument_id: string;
  strategy_id: string;
  side: "BUY" | "SELL";
  protective_leg: boolean;
  gtd_expiry_ns: number | string | null;
}

export interface PaperMassCancelPlanV1 {
  environment: "paper" | "live";
  account_id: string;
  venue: string;
  scope: PaperMassCancelScopeV1;
  expected_broker_revision: number;
  requests: readonly PaperMassCancelOrderInputV1[];
}

export interface PaperMassCancelOrderRequestV1 extends PaperMassCancelOrderInputV1 {
  idempotency_key: string;
}

export interface PaperMassCancelRequestV1 {
  account_id: string;
  venue: string;
  scope: PaperMassCancelScopeV1;
  idempotency_key: string;
  expected_broker_revision: number;
  start_index: number;
  requests: readonly PaperMassCancelOrderRequestV1[];
}

export type PaperMassCancelLifecycleStateV1 =
  | "CANCELED"
  | "REJECTED"
  | "CANCEL_REQUESTED_UNCONFIRMED";

export type PaperMassCancelOmsStateV1 = "CANCELED" | "UNKNOWN_CANCEL" | null;

export interface PaperMassCancelOrderResultV1 {
  order_id: string;
  idempotency_key: string;
  lifecycle_state: PaperMassCancelLifecycleStateV1;
  oms_state: PaperMassCancelOmsStateV1;
  reason_code: string;
  child_dispatch_stopped: boolean;
  cancel_sent: boolean;
  reconciled: boolean;
  discrepancy_codes: string[];
  operator_alert_codes: string[];
  fill_execution_ids: string[];
}

export interface PaperMassCancelResponseV1 {
  request_idempotency_key: string;
  start_index: number;
  next_index: number | null;
  complete: boolean;
  results: PaperMassCancelOrderResultV1[];
}

export type PaperMassCancelErrorCode =
  | "OUTCOME_UNKNOWN"
  | "OPERATOR_REQUIRED"
  | "PAPER_SCOPE_REQUIRED"
  | "PAPER_SCOPE_MISMATCH"
  | "PRINCIPAL_VENUE_MISMATCH"
  | "STALE_OR_MISMATCHED_ACCOUNT_VIEW"
  | "ORDER_MISSING_OR_STALE"
  | "AMBIGUOUS_NATIVE_ORDER_MAPPING"
  | "DUPLICATE_ORDER_ID"
  | "DUPLICATE_MASS_CANCEL_ORDER"
  | "INVALID_MASS_CANCEL_CURSOR"
  | "INVALID_MASS_CANCEL_SCOPE"
  | "MASS_CANCEL_SCOPE_MISMATCH"
  | "INVALID_MASS_CANCEL_REQUEST"
  | "MASS_CANCEL_BATCH_LIMIT"
  | "MASS_CANCEL_BODY_TOO_LARGE"
  | "BROKER_OUTCOME_UNKNOWN"
  | "HALT_STATE_UNKNOWN"
  | "MASS_CANCEL_OUTCOME_UNKNOWN"
  | "MASS_CANCEL_RESULT_INVALID"
  | "REQUEST_REJECTED";

export type PaperMassCancelApiResult<T> =
  | { ok: true; data: T }
  | { ok: false; error: PaperMassCancelErrorCode };

export interface PaperMassCancelApi {
  submit(
    request: PaperMassCancelRequestV1,
  ): Promise<PaperMassCancelApiResult<PaperMassCancelResponseV1>>;
}

const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,127}$/;
const RESULT_LIFECYCLE_STATES: readonly string[] = [
  "CANCELED",
  "REJECTED",
  "CANCEL_REQUESTED_UNCONFIRMED",
];
const OMS_STATES: readonly (string | null)[] = [
  "CANCELED",
  "UNKNOWN_CANCEL",
  null,
];
const HTTP_ERROR_CODES = new Set<PaperMassCancelErrorCode>([
  "OPERATOR_REQUIRED",
  "PAPER_SCOPE_REQUIRED",
  "PAPER_SCOPE_MISMATCH",
  "PRINCIPAL_VENUE_MISMATCH",
  "STALE_OR_MISMATCHED_ACCOUNT_VIEW",
  "ORDER_MISSING_OR_STALE",
  "AMBIGUOUS_NATIVE_ORDER_MAPPING",
  "DUPLICATE_ORDER_ID",
  "DUPLICATE_MASS_CANCEL_ORDER",
  "INVALID_MASS_CANCEL_CURSOR",
  "INVALID_MASS_CANCEL_SCOPE",
  "MASS_CANCEL_SCOPE_MISMATCH",
  "INVALID_MASS_CANCEL_REQUEST",
  "MASS_CANCEL_BATCH_LIMIT",
  "MASS_CANCEL_BODY_TOO_LARGE",
  "BROKER_OUTCOME_UNKNOWN",
  "HALT_STATE_UNKNOWN",
  "MASS_CANCEL_OUTCOME_UNKNOWN",
  "MASS_CANCEL_RESULT_INVALID",
]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  return Object.keys(value).length === keys.length && keys.every((key) => key in value);
}

export function isSafeMassCancelIdentifier(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const match = IDENTIFIER.exec(value);
  return match !== null && match[0] === value;
}

function isStringList(value: unknown): value is string[] {
  return Array.isArray(value) &&
    value.length <= 1_000 &&
    value.every(isSafeMassCancelIdentifier) &&
    new Set(value).size === value.length;
}

function isOrderInput(value: unknown): value is PaperMassCancelOrderInputV1 {
  if (!isRecord(value) || !hasExactKeys(value, [
    "order_id",
    "client_order_id",
    "venue_order_id",
    "instrument_id",
    "strategy_id",
    "side",
    "protective_leg",
    "gtd_expiry_ns",
  ])) return false;
  return isSafeMassCancelIdentifier(value.order_id) &&
    isSafeMassCancelIdentifier(value.client_order_id) &&
    isSafeMassCancelIdentifier(value.venue_order_id) &&
    isSafeMassCancelIdentifier(value.instrument_id) &&
    isSafeMassCancelIdentifier(value.strategy_id) &&
    (value.side === "BUY" || value.side === "SELL") &&
    typeof value.protective_leg === "boolean" &&
    isValidExpiryNs(value.gtd_expiry_ns);
}

function isValidExpiryNs(value: unknown): value is number | string | null {
  if (value === null) return true;
  if (typeof value === "number") {
    return Number.isSafeInteger(value) && value >= 0;
  }
  if (typeof value !== "string") return false;
  const match = /^(?:0|[1-9][0-9]{0,18})$/.exec(value);
  if (match === null || match[0] !== value) return false;
  const maxNs = "9223372036854775807";
  return value.length < maxNs.length ||
    (value.length === maxNs.length && value <= maxNs);
}

export function isValidPaperMassCancelPlan(plan: PaperMassCancelPlanV1): boolean {
  if (
    !isRecord(plan) ||
    !hasExactKeys(plan, [
      "environment",
      "account_id",
      "venue",
      "scope",
      "expected_broker_revision",
      "requests",
    ]) ||
    (plan.environment !== "paper" && plan.environment !== "live") ||
    !isSafeMassCancelIdentifier(plan.account_id) ||
    !isSafeMassCancelIdentifier(plan.venue) ||
    !(PAPER_MASS_CANCEL_SCOPES as readonly string[]).includes(plan.scope) ||
    typeof plan.expected_broker_revision !== "number" ||
    !Number.isSafeInteger(plan.expected_broker_revision) ||
    plan.expected_broker_revision < 0 ||
    !Array.isArray(plan.requests) ||
    plan.requests.length < 1 ||
    plan.requests.length > MAX_MASS_CANCEL_ORDERS ||
    !plan.requests.every(isOrderInput)
  ) return false;

  const orderIds = plan.requests.map((item) => item.order_id);
  const clientIds = plan.requests.map((item) => item.client_order_id);
  const venueIds = plan.requests.map((item) => item.venue_order_id);
  if (
    new Set(orderIds).size !== orderIds.length ||
    new Set(clientIds).size !== clientIds.length ||
    new Set(venueIds).size !== venueIds.length
  ) return false;

  const first = plan.requests[0];
  if (first === undefined) return false;
  if (plan.scope === "INSTRUMENT" &&
    plan.requests.some((item) => item.instrument_id !== first.instrument_id)) return false;
  if (plan.scope === "STRATEGY" &&
    plan.requests.some((item) => item.strategy_id !== first.strategy_id)) return false;
  return true;
}

function isOrderResult(
  value: unknown,
  expected: PaperMassCancelOrderRequestV1,
): value is PaperMassCancelOrderResultV1 {
  if (!isRecord(value) || !hasExactKeys(value, [
    "order_id",
    "idempotency_key",
    "lifecycle_state",
    "oms_state",
    "reason_code",
    "child_dispatch_stopped",
    "cancel_sent",
    "reconciled",
    "discrepancy_codes",
    "operator_alert_codes",
    "fill_execution_ids",
  ])) return false;

  const lifecycle = value.lifecycle_state;
  const oms = value.oms_state;
  if (
    value.order_id !== expected.order_id ||
    value.idempotency_key !== expected.idempotency_key ||
    typeof lifecycle !== "string" ||
    !RESULT_LIFECYCLE_STATES.includes(lifecycle) ||
    !OMS_STATES.includes(oms as string | null) ||
    !isSafeMassCancelIdentifier(value.reason_code) ||
    typeof value.child_dispatch_stopped !== "boolean" ||
    typeof value.cancel_sent !== "boolean" ||
    typeof value.reconciled !== "boolean" ||
    !isStringList(value.discrepancy_codes) ||
    !isStringList(value.operator_alert_codes) ||
    !isStringList(value.fill_execution_ids)
  ) return false;

  if (
    (lifecycle === "CANCELED" && oms !== "CANCELED") ||
    (lifecycle === "CANCEL_REQUESTED_UNCONFIRMED" && oms !== "UNKNOWN_CANCEL") ||
    (lifecycle === "REJECTED" && oms !== null)
  ) return false;
  return true;
}

export function parsePaperMassCancelResponse(
  value: unknown,
  request: PaperMassCancelRequestV1,
): PaperMassCancelResponseV1 | null {
  if (!isRecord(value) || !hasExactKeys(value, [
    "request_idempotency_key",
    "start_index",
    "next_index",
    "complete",
    "results",
  ])) return null;
  if (
    value.request_idempotency_key !== request.idempotency_key ||
    value.start_index !== request.start_index ||
    typeof value.complete !== "boolean" ||
    !Array.isArray(value.results) ||
    value.results.length < 1 ||
    value.results.length > MAX_MASS_CANCEL_ORDERS
  ) return null;

  const start = request.start_index;
  const results = value.results;
  if (!results.every((item, offset) => {
    const expected = request.requests[start + offset];
    return expected !== undefined && isOrderResult(item, expected);
  })) return null;

  const next = value.next_index;
  if (value.complete) {
    if (
      next !== null ||
      results.length !== request.requests.length - start
    ) return null;
  } else if (
    typeof next !== "number" ||
    !Number.isSafeInteger(next) ||
    next !== start + results.length ||
    next > request.requests.length
  ) return null;

  return {
    request_idempotency_key: request.idempotency_key,
    start_index: start,
    next_index: next as number | null,
    complete: value.complete,
    results: results as PaperMassCancelOrderResultV1[],
  };
}

function validateRequest(request: PaperMassCancelRequestV1): boolean {
  if (!isRecord(request) || !hasExactKeys(request, [
    "account_id",
    "venue",
    "scope",
    "idempotency_key",
    "expected_broker_revision",
    "start_index",
    "requests",
  ])) return false;
  if (
    !isSafeMassCancelIdentifier(request.account_id) ||
    !isSafeMassCancelIdentifier(request.venue) ||
    !isSafeMassCancelIdentifier(request.idempotency_key) ||
    !(PAPER_MASS_CANCEL_SCOPES as readonly string[]).includes(request.scope) ||
    !Number.isSafeInteger(request.expected_broker_revision) ||
    request.expected_broker_revision < 0 ||
    !Array.isArray(request.requests) ||
    request.requests.length < 1 ||
    request.requests.length > MAX_MASS_CANCEL_ORDERS ||
    !Number.isSafeInteger(request.start_index) ||
    request.start_index < 0 ||
    request.start_index >= request.requests.length
  ) return false;

  const seenOrderIds = new Set<string>();
  const seenClientIds = new Set<string>();
  const seenVenueIds = new Set<string>();
  const seenKeys = new Set<string>();
  for (const item of request.requests) {
    if (!isRecord(item) || !hasExactKeys(item, [
      "order_id",
      "client_order_id",
      "venue_order_id",
      "instrument_id",
      "strategy_id",
      "side",
      "protective_leg",
      "gtd_expiry_ns",
      "idempotency_key",
    ]) || !isOrderInput({
      order_id: item.order_id,
      client_order_id: item.client_order_id,
      venue_order_id: item.venue_order_id,
      instrument_id: item.instrument_id,
      strategy_id: item.strategy_id,
      side: item.side,
      protective_leg: item.protective_leg,
      gtd_expiry_ns: item.gtd_expiry_ns,
    }) || !isSafeMassCancelIdentifier(item.idempotency_key)) return false;
    const checkedItem = item as unknown as PaperMassCancelOrderRequestV1;
    if (seenOrderIds.has(checkedItem.order_id) ||
      seenClientIds.has(checkedItem.client_order_id) ||
      seenVenueIds.has(checkedItem.venue_order_id) ||
      seenKeys.has(checkedItem.idempotency_key)) return false;
    seenOrderIds.add(checkedItem.order_id);
    seenClientIds.add(checkedItem.client_order_id);
    seenVenueIds.add(checkedItem.venue_order_id);
    seenKeys.add(checkedItem.idempotency_key);
  }
  return true;
}

function errorFromHttp(status: number, body: unknown): PaperMassCancelErrorCode {
  if (status >= 500) return "OUTCOME_UNKNOWN";
  if (isRecord(body) && typeof body.detail === "string" &&
    HTTP_ERROR_CODES.has(body.detail as PaperMassCancelErrorCode)) {
    return body.detail as PaperMassCancelErrorCode;
  }
  if (status === 401) return "OPERATOR_REQUIRED";
  return "REQUEST_REJECTED";
}

export function createPaperMassCancelApi(
  fetcher: typeof fetch = fetch,
): PaperMassCancelApi {
  return {
    async submit(request) {
      if (!validateRequest(request)) return { ok: false, error: "INVALID_MASS_CANCEL_REQUEST" };
      let response: Response;
      try {
        response = await fetcher(PAPER_MASS_CANCEL_PATH, {
          method: "POST",
          headers: { Accept: "application/json", "Content-Type": "application/json" },
          credentials: "same-origin",
          cache: "no-store",
          body: JSON.stringify(request).replace(
            /("gtd_expiry_ns":)"(0|[1-9][0-9]*)"/g,
            "$1$2",
          ),
        });
      } catch {
        return { ok: false, error: "OUTCOME_UNKNOWN" };
      }

      let body: unknown;
      try {
        body = await response.json();
      } catch {
        body = undefined;
      }
      if (!response.ok) return { ok: false, error: errorFromHttp(response.status, body) };
      const data = parsePaperMassCancelResponse(body, request);
      return data === null
        ? { ok: false, error: "OUTCOME_UNKNOWN" }
        : { ok: true, data };
    },
  };
}

export function createMassCancelIdempotencyKey(): string {
  const cryptoApi = globalThis.crypto;
  if (!cryptoApi || typeof cryptoApi.getRandomValues !== "function") {
    throw new Error("IDEMPOTENCY_KEY_UNAVAILABLE");
  }
  const bytes = cryptoApi.getRandomValues(new Uint8Array(16));
  const suffix = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  return `pmc-${suffix}`;
}
