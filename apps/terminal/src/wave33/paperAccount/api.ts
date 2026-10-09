export const PAPER_ACCOUNT_SNAPSHOT_PATH = "/api/paper/accounts";
export const PAPER_ACCOUNT_STALE_AFTER_MS = 5 * 60 * 1000;

export interface PaperAccountBalanceV1 {
  currency: string;
  amount: string;
}

export interface PaperAccountPositionV1 {
  instrument_id: string;
  quantity: string;
}

export interface PaperAccountEquityV1 {
  currency: string;
  amount: string;
  kind: "NET_LIQUIDATION" | "TOTAL_EQUITY";
  broker_observed_at_ns: number;
}

export interface PaperAccountSnapshotV1 {
  account_id: string;
  environment: "paper";
  broker_revision: number;
  broker_observed_at: string;
  balances: PaperAccountBalanceV1[] | null;
  positions: PaperAccountPositionV1[];
  equity: PaperAccountEquityV1 | null;
}

export type PaperAccountSnapshotError =
  | "INVALID_ACCOUNT_ID"
  | "NETWORK_UNAVAILABLE"
  | "OPERATOR_SESSION_UNAVAILABLE"
  | "PAPER_SCOPE_REQUIRED"
  | "PAPER_ACCOUNT_SNAPSHOT_UNAVAILABLE"
  | "HTTP_ERROR"
  | "INVALID_RESPONSE";

export type PaperAccountSnapshotResult =
  | { ok: true; data: PaperAccountSnapshotV1 }
  | { ok: false; error: PaperAccountSnapshotError };

export interface PaperAccountSnapshotClient {
  getSnapshot(accountId: string): Promise<PaperAccountSnapshotResult>;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isIdentifier(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/.test(value);
}

function isCanonicalDecimal(value: unknown): value is string {
  return typeof value === "string" && value !== "-0" && /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]*[1-9])?$/.test(value);
}

function parseBalance(value: unknown): PaperAccountBalanceV1 | null {
  if (!isRecord(value) || !/^[A-Z]{3}$/.test(String(value.currency)) || !isCanonicalDecimal(value.amount)) {
    return null;
  }
  return { currency: value.currency as string, amount: value.amount };
}

function parsePosition(value: unknown): PaperAccountPositionV1 | null {
  if (!isRecord(value) || !isIdentifier(value.instrument_id) || !isCanonicalDecimal(value.quantity)) {
    return null;
  }
  return { instrument_id: value.instrument_id, quantity: value.quantity };
}

function parseEquity(value: unknown): PaperAccountEquityV1 | null | undefined {
  if (value === null) return null;
  if (
    !isRecord(value) ||
    !/^[A-Z]{3}$/.test(String(value.currency)) ||
    !isCanonicalDecimal(value.amount) ||
    (value.kind !== "NET_LIQUIDATION" && value.kind !== "TOTAL_EQUITY") ||
    !Number.isInteger(value.broker_observed_at_ns) ||
    (value.broker_observed_at_ns as number) < 0
  ) return undefined;
  return {
    currency: value.currency as string,
    amount: value.amount,
    kind: value.kind,
    broker_observed_at_ns: value.broker_observed_at_ns as number,
  };
}

function parseSnapshot(value: unknown, requestedAccountId: string): PaperAccountSnapshotV1 | null {
  if (
    !isRecord(value) ||
    value.account_id !== requestedAccountId ||
    value.environment !== "paper" ||
    !Number.isSafeInteger(value.broker_revision) ||
    (value.broker_revision as number) < 0 ||
    typeof value.broker_observed_at !== "string" ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/.test(value.broker_observed_at) ||
    !Number.isFinite(Date.parse(value.broker_observed_at)) ||
    !Array.isArray(value.positions) ||
    value.positions.length > 10_000 ||
    !(value.balances === null || (Array.isArray(value.balances) && value.balances.length <= 1_000))
  ) return null;

  const positions = value.positions.map(parsePosition);
  if (positions.some((position) => position === null)) return null;
  const balances = value.balances === null ? null : value.balances.map(parseBalance);
  if (balances?.some((balance) => balance === null)) return null;
  if (new Set((positions as PaperAccountPositionV1[]).map((position) => position.instrument_id)).size !== positions.length) return null;
  if (balances !== null && new Set((balances as PaperAccountBalanceV1[]).map((balance) => balance.currency)).size !== balances.length) return null;
  const equity = parseEquity(value.equity);
  if (equity === undefined) return null;

  return {
    account_id: requestedAccountId,
    environment: "paper",
    broker_revision: value.broker_revision as number,
    broker_observed_at: value.broker_observed_at,
    balances: balances as PaperAccountBalanceV1[] | null,
    positions: positions as PaperAccountPositionV1[],
    equity,
  };
}

function errorForStatus(status: number): PaperAccountSnapshotError {
  if (status === 401) return "OPERATOR_SESSION_UNAVAILABLE";
  if (status === 403) return "PAPER_SCOPE_REQUIRED";
  if (status === 503 || status === 404) return "PAPER_ACCOUNT_SNAPSHOT_UNAVAILABLE";
  return "HTTP_ERROR";
}

export function createPaperAccountSnapshotClient(
  fetcher: typeof fetch = fetch,
): PaperAccountSnapshotClient {
  return {
    async getSnapshot(accountId: string): Promise<PaperAccountSnapshotResult> {
      if (!isIdentifier(accountId)) return { ok: false, error: "INVALID_ACCOUNT_ID" };

      let response: Response;
      try {
        response = await fetcher(
          `${PAPER_ACCOUNT_SNAPSHOT_PATH}/${encodeURIComponent(accountId)}/snapshot`,
          {
            method: "GET",
            headers: { Accept: "application/json" },
            credentials: "same-origin",
            cache: "no-store",
          },
        );
      } catch {
        return { ok: false, error: "NETWORK_UNAVAILABLE" };
      }

      if (!response.ok) return { ok: false, error: errorForStatus(response.status) };
      let body: unknown;
      try {
        body = await response.json();
      } catch {
        return { ok: false, error: "INVALID_RESPONSE" };
      }
      const data = parseSnapshot(body, accountId);
      return data ? { ok: true, data } : { ok: false, error: "INVALID_RESPONSE" };
    },
  };
}
