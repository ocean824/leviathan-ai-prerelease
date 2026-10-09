export type ConnectionProviderId =
  | "ibkr"
  | "alpaca"
  | "mt5"
  | "mcp"
  | "snaptrade"
  | "tastytrade"
  | "ctrader"
  | "coinbase"
  | "kraken"
  | "binance_us"
  | "forex_com_mt5"
  | "rithmic"
  | "kalshi"
  | "anthropic"
  | "openai"
  | "openai_compatible";

export type ConnectionEnvironment = "DEVELOPMENT" | "TEST" | "PAPER" | "DEMO" | "TESTNET" | "LIVE";
export type ConnectionAuthMethod = "oauth" | "api_key" | "mt5_login";
export type ConnectionState = "DISCONNECTED" | "PENDING" | "CONNECTED" | "ERROR";
export type ConnectionCapability =
  | "ACCOUNT_READ"
  | "BALANCE_READ"
  | "POSITION_READ"
  | "QUOTE_READ"
  | "HISTORICAL_DATA_READ"
  | "ORDER_SUBMIT"
  | "ORDER_CANCEL"
  | "ORDER_STATUS"
  | "STREAMING"
  | "OAUTH_CONNECT"
  | "API_KEY_CONNECT"
  | "MT5_LOGIN_CONNECT"
  | "AI_INFERENCE";
export type ConnectionsErrorCode =
  | "PRINCIPAL_UNTRUSTED"
  | "CONNECTION_FORBIDDEN"
  | "INVALID_PROVIDER"
  | "UNSUPPORTED_BODY"
  | "PROVIDER_NOT_FOUND"
  | "CONNECTIONS_UNAVAILABLE"
  | "NETWORK_UNAVAILABLE"
  | "INVALID_RESPONSE";

export interface ProviderCatalogEntryV1 {
  provider_id: ConnectionProviderId;
  capabilities: readonly ConnectionCapability[];
  environments: readonly ConnectionEnvironment[];
  auth_method: ConnectionAuthMethod;
  default_route: boolean;
}

export interface ConnectionsCatalogV1 {
  providers: readonly ProviderCatalogEntryV1[];
}

export interface ProviderConnectionV1 {
  provider_id: ConnectionProviderId;
  environment: ConnectionEnvironment;
  state: ConnectionState;
  configured: boolean;
}

export interface ConnectionsStatusV1 {
  connections: readonly ProviderConnectionV1[];
}

export interface ConnectOAuthInitiateV1 {
  provider_id: ConnectionProviderId;
  environment: ConnectionEnvironment;
  auth_method: "oauth";
  authorization_url: string;
  authorization_host: string;
  redirect_uri: string;
  state: string;
  expires_at_ns: string;
  single_use: true;
  request_id: string;
}

export interface ConnectCredentialInitiateV1 {
  provider_id: ConnectionProviderId;
  environment: ConnectionEnvironment;
  auth_method: "api_key" | "mt5_login";
  credential_entry_handle: string;
}

export type ConnectInitiateV1 = ConnectOAuthInitiateV1 | ConnectCredentialInitiateV1;

export interface ConnectionActionResultV1 {
  provider_id: ConnectionProviderId;
  environment: ConnectionEnvironment;
  result: "CANCELLED" | "DISCONNECTED" | "ALREADY_DISCONNECTED";
}

export type ApiResult<T> = { ok: true; data: T } | { ok: false; error: ConnectionsErrorCode };

export interface ConnectionsApi {
  getCatalog(): Promise<ApiResult<ConnectionsCatalogV1>>;
  getStatus(): Promise<ApiResult<ConnectionsStatusV1>>;
  connect(provider: ConnectionProviderId): Promise<ApiResult<ConnectInitiateV1>>;
  cancel(provider: ConnectionProviderId): Promise<ApiResult<ConnectionActionResultV1>>;
  disconnect(provider: ConnectionProviderId): Promise<ApiResult<ConnectionActionResultV1>>;
}

export interface ExternalUrlOpenerPort {
  open(url: URL): Promise<"opened" | "unavailable">;
}

export type Clock = () => number;

export function providerLabel(provider: ConnectionProviderId): string {
  const labels: Record<ConnectionProviderId, string> = {
    ibkr: "Interactive Brokers (IBKR)",
    alpaca: "Alpaca",
    mt5: "MetaTrader 5",
    mcp: "Model Context Protocol",
    snaptrade: "SnapTrade",
    tastytrade: "tastytrade",
    ctrader: "cTrader",
    coinbase: "Coinbase",
    kraken: "Kraken",
    binance_us: "Binance.US",
    forex_com_mt5: "FOREX.com MT5",
    rithmic: "Rithmic",
    kalshi: "Kalshi",
    anthropic: "Anthropic",
    openai: "OpenAI",
    openai_compatible: "OpenAI-compatible provider",
  };
  return labels[provider];
}

export function validateOAuthUrl(value: string, allowedHost: string): URL | null {
  try {
    const url = new URL(value);
    if (url.protocol !== "https:" || url.username || url.password || url.hash) return null;
    if (!allowedHost || url.host !== allowedHost || allowedHost !== allowedHost.toLowerCase()) return null;
    return url;
  } catch {
    return null;
  }
}

export function validateLoopbackRedirect(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "http:" && url.hostname === "127.0.0.1" &&
      url.port.length > 0 && Number(url.port) >= 1 && Number(url.port) <= 65535 &&
      url.pathname === "/callback" && !url.username && !url.password && !url.search && !url.hash;
  } catch {
    return false;
  }
}

export function isValidOAuthState(value: string): boolean {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) return false;
  try {
    const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - value.length % 4) % 4);
    const decoded = atob(padded);
    const canonical = btoa(decoded).replace(/=/g, "").split("+").join("-").split("/").join("_");
    return decoded.length >= 32 && canonical === value;
  } catch {
    return false;
  }
}

export function isValidOAuthExpiry(expiresAtNs: string, nowMs: number): boolean {
  if (!/^(0|[1-9][0-9]*)$/.test(expiresAtNs) || !Number.isSafeInteger(nowMs) || nowMs < 0) return false;
  try {
    const expiry = BigInt(expiresAtNs);
    const now = BigInt(nowMs) * 1_000_000n;
    const ttl = expiry - now;
    return ttl > 0n && ttl <= 600_000_000_000n;
  } catch {
    return false;
  }
}

export function createFailClosedExternalUrlOpener(): ExternalUrlOpenerPort {
  return { open: async () => "unavailable" };
}

export function formatExpiry(expiresAtNs: string): string {
  try {
    const date = new Date(Number(BigInt(expiresAtNs) / 1_000_000n));
    return Number.isNaN(date.getTime()) ? "soon" : date.toLocaleTimeString(undefined, { timeZoneName: "short" });
  } catch {
    return "soon";
  }
}