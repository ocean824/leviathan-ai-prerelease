import type {
  ApiResult,
  ConnectInitiateV1,
  ConnectionActionResultV1,
  ConnectionAuthMethod,
  ConnectionCapability,
  ConnectionEnvironment,
  ConnectionProviderId,
  ConnectionState,
  ConnectionsApi,
  ConnectionsCatalogV1,
  ConnectionsErrorCode,
  ConnectionsStatusV1,
} from "./model";

export type ConnectionsFetch = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

const providers = new Set<ConnectionProviderId>([
  "ibkr", "alpaca", "mt5", "mcp", "snaptrade", "tastytrade", "ctrader", "coinbase",
  "kraken", "binance_us", "forex_com_mt5", "rithmic", "kalshi", "anthropic", "openai", "openai_compatible",
]);
const environments = new Set<ConnectionEnvironment>(["DEVELOPMENT", "TEST", "PAPER", "DEMO", "TESTNET", "LIVE"]);
const authMethods = new Set<ConnectionAuthMethod>(["oauth", "api_key", "mt5_login"]);
const capabilities = new Set<ConnectionCapability>([
  "ACCOUNT_READ", "BALANCE_READ", "POSITION_READ", "QUOTE_READ", "HISTORICAL_DATA_READ", "ORDER_SUBMIT",
  "ORDER_CANCEL", "ORDER_STATUS", "STREAMING", "OAUTH_CONNECT", "API_KEY_CONNECT", "MT5_LOGIN_CONNECT", "AI_INFERENCE",
]);
const states = new Set<ConnectionState>(["DISCONNECTED", "PENDING", "CONNECTED", "ERROR"]);


function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isStringArray<T extends string>(value: unknown, allowed: ReadonlySet<T>): value is T[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string" && allowed.has(item as T));
}

function validCatalog(value: unknown): value is ConnectionsCatalogV1 {
  return isRecord(value) && Array.isArray(value.providers) && value.providers.every((entry) =>
    isRecord(entry) && typeof entry.provider_id === "string" && providers.has(entry.provider_id as ConnectionProviderId) &&
    isStringArray(entry.capabilities, capabilities) && isStringArray(entry.environments, environments) &&
    typeof entry.auth_method === "string" && authMethods.has(entry.auth_method as ConnectionAuthMethod) &&
    typeof entry.default_route === "boolean");
}

function validStatus(value: unknown): value is ConnectionsStatusV1 {
  return isRecord(value) && Array.isArray(value.connections) && value.connections.every((entry) =>
    isRecord(entry) && typeof entry.provider_id === "string" && providers.has(entry.provider_id as ConnectionProviderId) &&
    typeof entry.environment === "string" && environments.has(entry.environment as ConnectionEnvironment) &&
    typeof entry.state === "string" && states.has(entry.state as ConnectionState) && typeof entry.configured === "boolean");
}

function hasOnlyKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const keys = Object.keys(value);
  return keys.length === expected.length && keys.every((key) => expected.includes(key));
}
function validConnect(value: unknown, provider: ConnectionProviderId): value is ConnectInitiateV1 {
  if (!isRecord(value) || value.provider_id !== provider || typeof value.environment !== "string" ||
      !environments.has(value.environment as ConnectionEnvironment) || typeof value.auth_method !== "string") return false;
  if (value.auth_method === "oauth") {
    return hasOnlyKeys(value, ["provider_id", "environment", "auth_method", "authorization_url", "authorization_host", "redirect_uri", "state", "expires_at_ns", "single_use", "request_id"]) &&
      typeof value.authorization_url === "string" && typeof value.authorization_host === "string" &&
      typeof value.redirect_uri === "string" && typeof value.state === "string" &&
      typeof value.expires_at_ns === "string" && value.single_use === true && typeof value.request_id === "string";
  }
  return (value.auth_method === "api_key" || value.auth_method === "mt5_login") &&
    hasOnlyKeys(value, ["provider_id", "environment", "auth_method", "credential_entry_handle"]) &&
    typeof value.credential_entry_handle === "string";
}

function validAction(value: unknown, provider: ConnectionProviderId): value is ConnectionActionResultV1 {
  return isRecord(value) && value.provider_id === provider && typeof value.environment === "string" &&
    environments.has(value.environment as ConnectionEnvironment) && typeof value.result === "string" &&
    ["CANCELLED", "DISCONNECTED", "ALREADY_DISCONNECTED"].includes(value.result);
}

function fixedApiError(status: number, payload: unknown): ConnectionsErrorCode {
  if (status === 401) return "PRINCIPAL_UNTRUSTED";
  if (status === 403) return "CONNECTION_FORBIDDEN";
  if (status === 404) return "PROVIDER_NOT_FOUND";
  if (status === 503) return "CONNECTIONS_UNAVAILABLE";
  if (status === 400 && isRecord(payload) && payload.detail === "INVALID_PROVIDER") return "INVALID_PROVIDER";
  if (status === 400 && isRecord(payload) && payload.detail === "UNSUPPORTED_BODY") return "UNSUPPORTED_BODY";
  return "INVALID_RESPONSE";
}

export function createConnectionsApi(fetcher: ConnectionsFetch = fetch): ConnectionsApi {
  async function request<T>(
    path: string,
    init: RequestInit | undefined,
    validate: (value: unknown) => value is T,
  ): Promise<ApiResult<T>> {
    try {
      const response = await fetcher(`/api${path}`, {
        ...init,
        headers: { Accept: "application/json", ...init?.headers },
      });
      let body: unknown;
      try {
        body = await response.json();
      } catch {
        body = undefined;
      }
      if (!response.ok) return { ok: false, error: fixedApiError(response.status, body) };
      return validate(body) ? { ok: true, data: body } : { ok: false, error: "INVALID_RESPONSE" };
    } catch {
      return { ok: false, error: "NETWORK_UNAVAILABLE" };
    }
  }

  return {
    getCatalog: () => request("/connections/catalog", undefined, validCatalog),
    getStatus: () => request("/connections/status", undefined, validStatus),
    connect: (provider) => request(
      `/connections/${encodeURIComponent(provider)}/connect`,
      { method: "POST" },
      (value): value is ConnectInitiateV1 => validConnect(value, provider),
    ),
    cancel: (provider) => request(
      `/connections/${encodeURIComponent(provider)}/cancel`,
      { method: "POST" },
      (value): value is ConnectionActionResultV1 => validAction(value, provider),
    ),
    disconnect: (provider) => request(
      `/connections/${encodeURIComponent(provider)}/disconnect`,
      { method: "POST" },
      (value): value is ConnectionActionResultV1 => validAction(value, provider),
    ),
  };
}

export const connectionsApi = createConnectionsApi();