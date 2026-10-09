import {
  createPaperActivityClient,
  ORDER_STATES,
} from "../../wave28/api/paperActivity";
import type {
  ApiResult,
  OrderStateV1,
  PaperActivityClient,
  PaperActivityErrorCode,
} from "../../wave28/api/paperActivity";
import { isValidOrderId } from "../../wave26/api/orderMonitor";

export const PAPER_ORDER_PATH = "/api/orders";
export const CANCELLABLE_PAPER_STATES = [
  "WORKING",
  "PARTIALLY_FILLED",
] as const;

export interface PaperSelectedOrderV1 {
  order_id: string;
  state: OrderStateV1;
  version: number;
  environment: "paper";
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

export type PaperBlotterErrorCode =
  | PaperActivityErrorCode
  | "INVALID_ORDER_ID"
  | "ORDER_NOT_CANCELLABLE"
  | "ORDER_UNAVAILABLE";

export type PaperBlotterResult<T> = ApiResult<T, PaperBlotterErrorCode>;

export interface PaperBlotterClient extends PaperActivityClient {
  getSelectedOrder(orderId: string): Promise<PaperBlotterResult<PaperSelectedOrderV1>>;
  cancelOrder(order: PaperSelectedOrderV1): Promise<PaperBlotterResult<PaperSelectedOrderV1>>;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseSelectedOrder(value: unknown, orderId: string): PaperSelectedOrderV1 | null {
  if (
    !isRecord(value) ||
    value.order_id !== orderId ||
    !isValidOrderId(value.order_id) ||
    typeof value.state !== "string" ||
    !(ORDER_STATES as readonly string[]).includes(value.state) ||
    !Number.isSafeInteger(value.version) ||
    (value.version as number) < 0 ||
    value.environment !== "paper" ||
    typeof value.account_id !== "string" ||
    typeof value.venue !== "string" ||
    typeof value.instrument_id !== "string" ||
    typeof value.strategy_id !== "string" ||
    typeof value.filled_quantity !== "string" ||
    !(value.venue_order_id === null || typeof value.venue_order_id === "string") ||
    !Array.isArray(value.discrepancies) ||
    !value.discrepancies.every((code) => typeof code === "string") ||
    typeof value.submit_attempted !== "boolean" ||
    typeof value.cancel_attempted !== "boolean"
  ) return null;
  return {
    order_id: orderId,
    state: value.state as OrderStateV1,
    version: value.version as number,
    environment: "paper",
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

async function readJson(response: Response): Promise<unknown> {
  try { return await response.json(); } catch { return undefined; }
}

function errorForStatus(status: number): PaperBlotterErrorCode {
  if (status === 401) return "OPERATOR_SESSION_UNAVAILABLE";
  if (status === 403) return "PAPER_ACTIVITY_FORBIDDEN";
  if (status === 404) return "ORDER_UNAVAILABLE";
  return "HTTP_ERROR";
}

export function createPaperBlotterClient(fetcher: typeof fetch = fetch): PaperBlotterClient {
  const activity = createPaperActivityClient(fetcher);
  async function getSelectedOrder(orderId: string): Promise<PaperBlotterResult<PaperSelectedOrderV1>> {
    if (!isValidOrderId(orderId)) return { ok: false, error: "INVALID_ORDER_ID" };
    let response: Response;
    try {
      response = await fetcher(`${PAPER_ORDER_PATH}/${encodeURIComponent(orderId)}`, {
        method: "GET", headers: { Accept: "application/json" }, credentials: "same-origin", cache: "no-store",
      });
    } catch { return { ok: false, error: "NETWORK_UNAVAILABLE" }; }
    const body = await readJson(response);
    if (!response.ok) return { ok: false, error: errorForStatus(response.status) };
    const data = parseSelectedOrder(body, orderId);
    return data ? { ok: true, data } : { ok: false, error: "INVALID_RESPONSE" };
  }

  async function cancelOrder(order: PaperSelectedOrderV1): Promise<PaperBlotterResult<PaperSelectedOrderV1>> {
    if (!isCancellablePaperOrder(order)) return { ok: false, error: "ORDER_NOT_CANCELLABLE" };
    let response: Response;
    try {
      response = await fetcher(`${PAPER_ORDER_PATH}/${encodeURIComponent(order.order_id)}/cancel`, {
        method: "POST", headers: { Accept: "application/json" }, credentials: "same-origin", cache: "no-store",
      });
    } catch { return { ok: false, error: "NETWORK_UNAVAILABLE" }; }
    const body = await readJson(response);
    if (!response.ok) return { ok: false, error: errorForStatus(response.status) };
    const data = parseSelectedOrder(body, order.order_id);
    return data ? { ok: true, data } : { ok: false, error: "INVALID_RESPONSE" };
  }

  return { ...activity, getSelectedOrder, cancelOrder };
}

export function isCancellablePaperOrder(order: PaperSelectedOrderV1): boolean {
  return order.environment === "paper" &&
    (CANCELLABLE_PAPER_STATES as readonly string[]).includes(order.state) &&
    !order.cancel_attempted && order.discrepancies.length === 0;
}
