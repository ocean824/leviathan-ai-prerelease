import { parseOrderGuard, parseRiskGuard } from "../../wave26/api/liveGuard";
import type {
  OrderGuardReport,
  RiskGuardReport,
} from "../../wave26/api/liveGuard";

export const PAPER_ACTIVITY_PATH = "/api/orders/activity";
export const PAPER_ORDER_STATUS_PATH = "/api/orders/status";
export const PAPER_RISK_STATUS_PATH = "/api/risk/status";
export const DEFAULT_ACTIVITY_LIMIT = 50;
export const MAX_ACTIVITY_LIMIT = 100;
export const MAX_ACTIVITY_CURSOR_LENGTH = 512;
export const MAX_LEDGER_HIGH_WATER = Number.MAX_SAFE_INTEGER;
export const MAX_NET_FILLED_GROUPS = 100;
export const MAX_DECIMAL_TEXT_LENGTH = 128;

export const ORDER_STATES = [
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
export type OrderStateV1 = (typeof ORDER_STATES)[number];

export const DISCREPANCY_CODES = [
  "OVERFILL",
  "FILL_AFTER_GTD",
  "FILL_AFTER_TERMINAL",
  "CANCEL_STATUS_UNCONFIRMED",
  "FILL_CORRECTION",
  "MISSING_EXECUTIONS",
  "BROKER_STATE_DIVERGENCE",
  "REJECT_AFTER_FILL",
  "BROKER_SCOPE_MISMATCH",
  "POST_DISPATCH_CONFLICT",
  "GATE_DENIED_CANCEL",
  "BROKER_EXECUTION_CONFLICT",
  "VENUE_MISMATCH",
  "VENUE_ACCOUNT_CONFLICT",
  "VENUE_ACCOUNT_CONFLICT_RESOLVED",
] as const;
export type DiscrepancyCodeV1 = (typeof DISCREPANCY_CODES)[number];

export interface PaperOrderV1 {
  order_id: string;
  venue: string;
  instrument_id: string;
  side: "BUY" | "SELL";
  state: OrderStateV1;
  quantity: string;
  filled_quantity: string;
  discrepancies: DiscrepancyCodeV1[];
  created_at_utc: string;
}

export interface PaperFillV1 {
  order_id: string;
  execution_id: string;
  venue: string;
  instrument_id: string;
  side: "BUY" | "SELL";
  quantity: string;
  price: string;
  commission: string;
  occurred_at_utc: string;
}

export interface PaperFillCorrectionV1 {
  order_id: string;
  execution_id: string;
  correction_id: string;
  revision: number;
  revised_quantity: string;
  revised_price: string | null;
  revised_commission: string;
  occurred_at_utc: string;
}

export type PaperActivityItemV1 =
  | { kind: "ORDER"; ledger_sequence: number; order: PaperOrderV1 }
  | { kind: "FILL"; ledger_sequence: number; fill: PaperFillV1 }
  | {
      kind: "FILL_CORRECTION";
      ledger_sequence: number;
      correction: PaperFillCorrectionV1;
    };

export interface PaperNetFilledUnitsV1 {
  venue: string;
  instrument_id: string;
  quantity: string;
}

export interface PaperActivityPageV1 {
  schema_version: 1;
  evidence_label: "OMS ledger evidence";
  environment: "paper";
  account_id: string;
  high_water_sequence: number;
  items: PaperActivityItemV1[];
  next_cursor: string | null;
  net_filled_units: PaperNetFilledUnitsV1[];
}

export type PaperActivityErrorCode =
  | "PRINCIPAL_UNTRUSTED"
  | "PAPER_ACTIVITY_FORBIDDEN"
  | "PAPER_SCOPE_REQUIRED"
  | "INVALID_ACTIVITY_QUERY"
  | "INVALID_ACTIVITY_CURSOR"
  | "PAPER_ACTIVITY_UNAVAILABLE"
  | "ACTIVITY_TOO_LARGE"
  | "OPERATOR_SESSION_UNAVAILABLE"
  | "NETWORK_UNAVAILABLE"
  | "HTTP_ERROR"
  | "INVALID_RESPONSE";

export type ApiResult<T, E extends string = PaperActivityErrorCode> =
  { ok: true; data: T } | { ok: false; error: E };

export type PaperActivityFetcher = typeof fetch;

const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/;
const FIXED_DECIMAL = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]*[1-9])?$/;
const UTC_TIMESTAMP =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(?:Z|\+00:00)$/;
const CURSOR = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$/;
const ACTIVITY_ERRORS = new Set<PaperActivityErrorCode>([
  "PRINCIPAL_UNTRUSTED",
  "PAPER_ACTIVITY_FORBIDDEN",
  "PAPER_SCOPE_REQUIRED",
  "INVALID_ACTIVITY_QUERY",
  "INVALID_ACTIVITY_CURSOR",
  "PAPER_ACTIVITY_UNAVAILABLE",
  "ACTIVITY_TOO_LARGE",
]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isIdentifier(value: unknown): value is string {
  return typeof value === "string" && IDENTIFIER.test(value);
}

function decimalFacts(
  value: unknown,
): { text: string; zero: boolean; negative: boolean } | null {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > MAX_DECIMAL_TEXT_LENGTH ||
    !FIXED_DECIMAL.test(value)
  ) {
    return null;
  }
  const negative = value.startsWith("-");
  const unsigned = negative ? value.slice(1) : value;
  const [integer, fraction = ""] = unsigned.split(".");
  const digits = `${integer}${fraction}`;
  const significant = digits.replace(/^0+/, "");
  const zero = significant.length === 0;
  if (zero && value !== "0") return null;
  if (!zero && significant.length > 34) return null;
  if (!zero) {
    const firstNonZero = digits.search(/[1-9]/);
    const adjustedExponent = integer.length - firstNonZero - 1;
    if (Math.abs(adjustedExponent) > 38) return null;
  }
  if (negative && zero) return null;
  return { text: value, zero, negative };
}

function isUtcTimestamp(value: unknown): value is string {
  if (typeof value !== "string" || value.length > 40) return false;
  const match = UTC_TIMESTAMP.exec(value);
  if (!match) return false;
  const [
    ,
    yearText,
    monthText,
    dayText,
    hourText,
    minuteText,
    secondText,
    fraction,
  ] = match;
  if (fraction && fraction.length > 9) return false;
  const year = Number(yearText);
  const month = Number(monthText);
  const day = Number(dayText);
  const hour = Number(hourText);
  const minute = Number(minuteText);
  const second = Number(secondText);
  const leapYear = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const monthDays = [
    31,
    leapYear ? 29 : 28,
    31,
    30,
    31,
    30,
    31,
    31,
    30,
    31,
    30,
    31,
  ];
  return (
    month >= 1 &&
    month <= 12 &&
    day >= 1 &&
    day <= (monthDays[month - 1] ?? 0) &&
    hour <= 23 &&
    minute <= 59 &&
    second <= 59
  );
}

function isNonNegativeSafeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function isPositiveSafeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

function isSide(value: unknown): value is "BUY" | "SELL" {
  return value === "BUY" || value === "SELL";
}

function isDisplayableSourceTime(value: number | string | undefined): boolean {
  if (value === undefined) return true;
  if (typeof value === "number") {
    return Number.isFinite(value) && Math.abs(value) <= 8_640_000_000_000_000;
  }
  return value.length <= 64 && Number.isFinite(Date.parse(value));
}

function parseOrder(value: unknown): PaperOrderV1 | null {
  if (
    !isRecord(value) ||
    !isIdentifier(value.order_id) ||
    !isIdentifier(value.venue) ||
    !isIdentifier(value.instrument_id) ||
    !isSide(value.side) ||
    typeof value.state !== "string" ||
    !(ORDER_STATES as readonly string[]).includes(value.state) ||
    decimalFacts(value.quantity)?.negative !== false ||
    decimalFacts(value.quantity)?.zero !== false ||
    decimalFacts(value.filled_quantity)?.negative !== false ||
    !Array.isArray(value.discrepancies) ||
    value.discrepancies.length > DISCREPANCY_CODES.length ||
    !value.discrepancies.every(
      (code) =>
        typeof code === "string" &&
        (DISCREPANCY_CODES as readonly string[]).includes(code),
    ) ||
    !isUtcTimestamp(value.created_at_utc)
  )
    return null;
  return {
    order_id: value.order_id,
    venue: value.venue,
    instrument_id: value.instrument_id,
    side: value.side,
    state: value.state as OrderStateV1,
    quantity: value.quantity as string,
    filled_quantity: value.filled_quantity as string,
    discrepancies: value.discrepancies as DiscrepancyCodeV1[],
    created_at_utc: value.created_at_utc,
  };
}

function parseFill(value: unknown): PaperFillV1 | null {
  if (
    !isRecord(value) ||
    !isIdentifier(value.order_id) ||
    !isIdentifier(value.execution_id) ||
    !isIdentifier(value.venue) ||
    !isIdentifier(value.instrument_id) ||
    !isSide(value.side) ||
    decimalFacts(value.quantity)?.negative !== false ||
    decimalFacts(value.quantity)?.zero !== false ||
    decimalFacts(value.price)?.negative !== false ||
    decimalFacts(value.price)?.zero !== false ||
    decimalFacts(value.commission)?.negative !== false ||
    !isUtcTimestamp(value.occurred_at_utc)
  )
    return null;
  return {
    order_id: value.order_id,
    execution_id: value.execution_id,
    venue: value.venue,
    instrument_id: value.instrument_id,
    side: value.side,
    quantity: value.quantity as string,
    price: value.price as string,
    commission: value.commission as string,
    occurred_at_utc: value.occurred_at_utc,
  };
}

function parseCorrection(value: unknown): PaperFillCorrectionV1 | null {
  const revisedQuantity = isRecord(value)
    ? decimalFacts(value.revised_quantity)
    : null;
  const revisedPrice =
    isRecord(value) && value.revised_price !== null
      ? decimalFacts(value.revised_price)
      : null;
  const revisedCommission = isRecord(value)
    ? decimalFacts(value.revised_commission)
    : null;
  if (
    !isRecord(value) ||
    !isIdentifier(value.order_id) ||
    !isIdentifier(value.execution_id) ||
    !isIdentifier(value.correction_id) ||
    !isPositiveSafeInteger(value.revision) ||
    !revisedQuantity ||
    revisedQuantity.negative ||
    !revisedCommission ||
    revisedCommission.negative ||
    (revisedQuantity.zero
      ? value.revised_price !== null
      : !revisedPrice || revisedPrice.negative || revisedPrice.zero) ||
    !isUtcTimestamp(value.occurred_at_utc)
  )
    return null;
  return {
    order_id: value.order_id,
    execution_id: value.execution_id,
    correction_id: value.correction_id,
    revision: value.revision,
    revised_quantity: revisedQuantity.text,
    revised_price: revisedPrice?.text ?? null,
    revised_commission: revisedCommission.text,
    occurred_at_utc: value.occurred_at_utc,
  };
}

function parseItem(
  value: unknown,
  highWater: number,
  priorSequence: number,
): PaperActivityItemV1 | null {
  if (
    !isRecord(value) ||
    !isPositiveSafeInteger(value.ledger_sequence) ||
    value.ledger_sequence > highWater ||
    value.ledger_sequence <= priorSequence
  )
    return null;
  if (value.kind === "ORDER") {
    const order = parseOrder(value.order);
    return order
      ? { kind: "ORDER", ledger_sequence: value.ledger_sequence, order }
      : null;
  }
  if (value.kind === "FILL") {
    const fill = parseFill(value.fill);
    return fill
      ? { kind: "FILL", ledger_sequence: value.ledger_sequence, fill }
      : null;
  }
  if (value.kind === "FILL_CORRECTION") {
    const correction = parseCorrection(value.correction);
    return correction
      ? {
          kind: "FILL_CORRECTION",
          ledger_sequence: value.ledger_sequence,
          correction,
        }
      : null;
  }
  return null;
}

export function parsePaperActivityPage(
  value: unknown,
  requestedLimit = DEFAULT_ACTIVITY_LIMIT,
): PaperActivityPageV1 | null {
  if (
    !isRecord(value) ||
    value.schema_version !== 1 ||
    value.evidence_label !== "OMS ledger evidence" ||
    value.environment !== "paper" ||
    !isIdentifier(value.account_id) ||
    !isNonNegativeSafeInteger(value.high_water_sequence) ||
    value.high_water_sequence > MAX_LEDGER_HIGH_WATER ||
    !Array.isArray(value.items) ||
    value.items.length > Math.min(requestedLimit, MAX_ACTIVITY_LIMIT) ||
    (value.next_cursor !== null &&
      (typeof value.next_cursor !== "string" ||
        value.next_cursor.length > MAX_ACTIVITY_CURSOR_LENGTH ||
        !CURSOR.test(value.next_cursor))) ||
    !Array.isArray(value.net_filled_units) ||
    value.net_filled_units.length > MAX_NET_FILLED_GROUPS
  )
    return null;

  const items: PaperActivityItemV1[] = [];
  let priorSequence = 0;
  for (const rawItem of value.items) {
    const item = parseItem(rawItem, value.high_water_sequence, priorSequence);
    if (!item) return null;
    items.push(item);
    priorSequence = item.ledger_sequence;
  }
  const netFilledUnits: PaperNetFilledUnitsV1[] = [];
  const seenNetKeys = new Set<string>();
  for (const rawNet of value.net_filled_units) {
    if (
      !isRecord(rawNet) ||
      !isIdentifier(rawNet.venue) ||
      !isIdentifier(rawNet.instrument_id)
    )
      return null;
    const quantity = decimalFacts(rawNet.quantity);
    if (!quantity) return null;
    const key = `${rawNet.venue}\u0000${rawNet.instrument_id}`;
    if (seenNetKeys.has(key)) return null;
    seenNetKeys.add(key);
    netFilledUnits.push({
      venue: rawNet.venue,
      instrument_id: rawNet.instrument_id,
      quantity: quantity.text,
    });
  }
  return {
    schema_version: 1,
    evidence_label: "OMS ledger evidence",
    environment: "paper",
    account_id: value.account_id,
    high_water_sequence: value.high_water_sequence,
    items,
    next_cursor: value.next_cursor as string | null,
    net_filled_units: netFilledUnits,
  };
}

export function parseActivityError(
  value: unknown,
): PaperActivityErrorCode | null {
  if (
    !isRecord(value) ||
    !isRecord(value.error) ||
    typeof value.error.code !== "string"
  )
    return null;
  return ACTIVITY_ERRORS.has(value.error.code as PaperActivityErrorCode)
    ? (value.error.code as PaperActivityErrorCode)
    : null;
}

async function fetchJson<T>(
  path: string,
  fetcher: PaperActivityFetcher,
  parse: (value: unknown) => T | null,
): Promise<ApiResult<T>> {
  let response: Response;
  try {
    response = await fetcher(path, {
      method: "GET",
      headers: { Accept: "application/json" },
      credentials: "same-origin",
      cache: "no-store",
    });
  } catch {
    return { ok: false, error: "NETWORK_UNAVAILABLE" };
  }
  let body: unknown;
  try {
    body = await response.json();
  } catch {
    body = undefined;
  }
  if (!response.ok) {
    if (path.split("?", 1)[0] === PAPER_ACTIVITY_PATH) {
      const fixedCode = parseActivityError(body);
      if (fixedCode) return { ok: false, error: fixedCode };
      if (response.status === 401)
        return { ok: false, error: "PRINCIPAL_UNTRUSTED" };
      if (response.status === 403)
        return { ok: false, error: "PAPER_ACTIVITY_FORBIDDEN" };
      if (response.status === 400)
        return { ok: false, error: "INVALID_ACTIVITY_QUERY" };
      if (response.status === 503)
        return { ok: false, error: "PAPER_ACTIVITY_UNAVAILABLE" };
    } else if (response.status === 401) {
      return { ok: false, error: "OPERATOR_SESSION_UNAVAILABLE" };
    }
    return { ok: false, error: "HTTP_ERROR" };
  }
  const data = parse(body);
  return data === null
    ? { ok: false, error: "INVALID_RESPONSE" }
    : { ok: true, data };
}

export interface PaperStatusV1 {
  liveEnabledReported: boolean;
  recoveryStatus: string;
  activationCount: number;
  as_of?: number | string;
}

export interface PaperRiskV1 {
  haltedReported: boolean;
  haltCodes: string[];
  faultCode: string | null;
  operatingMode: string;
  policyReported: boolean;
  as_of?: number | string;
}

function parseStatus(value: unknown): PaperStatusV1 | null {
  const report = parseOrderGuard(value);
  return report && isDisplayableSourceTime(report.as_of)
    ? {
        liveEnabledReported: report.liveEnabledReported,
        recoveryStatus: report.recoveryStatus,
        activationCount: report.activationCount,
        ...(report.as_of !== undefined ? { as_of: report.as_of } : {}),
      }
    : null;
}

function parseRisk(value: unknown): PaperRiskV1 | null {
  const report = parseRiskGuard(value);
  return report && isDisplayableSourceTime(report.as_of)
    ? {
        haltedReported: report.haltedReported,
        haltCodes: report.haltCodes,
        faultCode: report.faultCode,
        operatingMode: report.operatingMode,
        policyReported: report.policyReported,
        ...(report.as_of !== undefined ? { as_of: report.as_of } : {}),
      }
    : null;
}

export interface PaperActivityClient {
  getActivity(options?: {
    limit?: number;
    cursor?: string | null;
  }): Promise<ApiResult<PaperActivityPageV1>>;
  getStatus(): Promise<ApiResult<PaperStatusV1>>;
  getRisk(): Promise<ApiResult<PaperRiskV1>>;
}

export function createPaperActivityClient(
  fetcher: PaperActivityFetcher = fetch,
): PaperActivityClient {
  return {
    getActivity: (options = {}) => {
      const limit = options.limit ?? DEFAULT_ACTIVITY_LIMIT;
      if (!Number.isInteger(limit) || limit < 1 || limit > MAX_ACTIVITY_LIMIT) {
        return Promise.resolve({ ok: false, error: "INVALID_ACTIVITY_QUERY" });
      }
      if (
        options.cursor != null &&
        (options.cursor.length > MAX_ACTIVITY_CURSOR_LENGTH ||
          !CURSOR.test(options.cursor))
      ) {
        return Promise.resolve({ ok: false, error: "INVALID_ACTIVITY_CURSOR" });
      }
      const query = new URLSearchParams({ limit: String(limit) });
      if (options.cursor) query.set("cursor", options.cursor);
      return fetchJson(
        `${PAPER_ACTIVITY_PATH}?${query.toString()}`,
        fetcher,
        (value) => parsePaperActivityPage(value, limit),
      );
    },
    getStatus: () => fetchJson(PAPER_ORDER_STATUS_PATH, fetcher, parseStatus),
    getRisk: () => fetchJson(PAPER_RISK_STATUS_PATH, fetcher, parseRisk),
  };
}

export type { OrderGuardReport, RiskGuardReport };
