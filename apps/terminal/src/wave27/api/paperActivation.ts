import { isSafeIdentifier } from "../../shared/safeLabel";
import {
  parseOrderGuard,
  parseRiskGuard,
} from "../../wave26/api/liveGuard";
import type {
  OrderGuardReport,
  RiskGuardReport,
} from "../../wave26/api/liveGuard";

export const PAPER_ORDER_STATUS_PATH = "/api/orders/status";
export const PAPER_RISK_STATUS_PATH = "/api/risk/status";
export const PAPER_ACTIVATE_PATH = "/api/orders/activations";
export const PAPER_REVOKE_PATH = "/api/orders/activations/revoke";
export const PAPER_ENVIRONMENT = "paper" as const;

export const PAPER_ACTIVATION_ERROR_CODES = [
  "NETWORK_UNAVAILABLE",
  "OPERATOR_SESSION_UNAVAILABLE",
  "ACTION_FORBIDDEN",
  "ACTION_CONFLICT",
  "INVALID_SCOPE",
  "SERVICE_UNAVAILABLE",
  "HTTP_ERROR",
  "INVALID_RESPONSE",
] as const;
export type PaperActivationErrorCode = (typeof PAPER_ACTIVATION_ERROR_CODES)[number];

export type PaperActivationApiResult<T> =
  | { ok: true; data: T }
  | { ok: false; error: PaperActivationErrorCode };

export interface PaperActivationScope {
  account_id: string;
  venue: string;
  instrument_id: string;
  strategy_id: string;
}

export interface PaperOrderStatusV1 extends OrderGuardReport {
  /** A successful status read proves the mounted order runtime is configured. */
  configured: true;
}

export interface PaperActivationReceiptV1 {
  active: boolean;
}

export interface PaperActivationApi {
  getOrderStatus(): Promise<PaperActivationApiResult<PaperOrderStatusV1>>;
  getRiskStatus(): Promise<PaperActivationApiResult<RiskGuardReport>>;
  activate(scope: PaperActivationScope): Promise<PaperActivationApiResult<PaperActivationReceiptV1>>;
  revoke(scope: PaperActivationScope): Promise<PaperActivationApiResult<PaperActivationReceiptV1>>;
}

export type PaperActivationFetcher = typeof fetch;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isSafeScope(scope: PaperActivationScope): boolean {
  return (
    isSafeIdentifier(scope.account_id) &&
    isSafeIdentifier(scope.venue) &&
    isSafeIdentifier(scope.instrument_id) &&
    isSafeIdentifier(scope.strategy_id)
  );
}

function fixedHttpError(status: number): PaperActivationErrorCode {
  if (status === 401) return "OPERATOR_SESSION_UNAVAILABLE";
  if (status === 403) return "ACTION_FORBIDDEN";
  if (status === 409) return "ACTION_CONFLICT";
  if (status === 422) return "INVALID_SCOPE";
  if (status === 503) return "SERVICE_UNAVAILABLE";
  return "HTTP_ERROR";
}

async function requestJson<T>(
  fetcher: PaperActivationFetcher,
  path: string,
  init: RequestInit,
  parse: (value: unknown) => T | null,
): Promise<PaperActivationApiResult<T>> {
  let response: Response;
  try {
    response = await fetcher(path, {
      ...init,
      credentials: "same-origin",
      cache: "no-store",
    });
  } catch {
    return { ok: false, error: "NETWORK_UNAVAILABLE" };
  }
  if (!response.ok) return { ok: false, error: fixedHttpError(response.status) };
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

function parseOrderStatus(value: unknown): PaperOrderStatusV1 | null {
  const report = parseOrderGuard(value);
  return report === null ? null : { ...report, configured: true };
}

function parseActivationReceipt(
  expectedActive: boolean,
): (value: unknown) => PaperActivationReceiptV1 | null {
  return (value) =>
    isRecord(value) && value.active === expectedActive
      ? { active: expectedActive }
      : null;
}

export function createPaperActivationApi(
  fetcher: PaperActivationFetcher = fetch,
): PaperActivationApi {
  const get = <T,>(
    path: string,
    parse: (value: unknown) => T | null,
  ): Promise<PaperActivationApiResult<T>> =>
    requestJson(
      fetcher,
      path,
      { method: "GET", headers: { Accept: "application/json" } },
      parse,
    );

  const mutate = (
    path: string,
    scope: PaperActivationScope,
    expectedActive: boolean,
  ): Promise<PaperActivationApiResult<PaperActivationReceiptV1>> => {
    if (!isSafeScope(scope)) return Promise.resolve({ ok: false, error: "INVALID_SCOPE" });
    const body = {
      environment: PAPER_ENVIRONMENT,
      account_id: scope.account_id,
      venue: scope.venue,
      instrument_id: scope.instrument_id,
      strategy_id: scope.strategy_id,
    };
    return requestJson(
      fetcher,
      path,
      {
        method: "POST",
        headers: { Accept: "application/json", "Content-Type": "application/json" },
        body: JSON.stringify(body),
      },
      parseActivationReceipt(expectedActive),
    );
  };

  return {
    getOrderStatus: () => get(PAPER_ORDER_STATUS_PATH, parseOrderStatus),
    getRiskStatus: () => get(PAPER_RISK_STATUS_PATH, parseRiskGuard),
    activate: (scope) => mutate(PAPER_ACTIVATE_PATH, scope, true),
    revoke: (scope) => mutate(PAPER_REVOKE_PATH, scope, false),
  };
}
