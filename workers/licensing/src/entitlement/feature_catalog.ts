/** Closed feature vocabulary used to mint and interpret LIC-001 snapshots. */
export const FEATURE_CATALOG_VERSION_V1 = 1 as const;

export const FEATURE_KEYS_V1 = Object.freeze([
  "paper_trading", "live_trading", "data_sources", "strategy_lab", "ea_hosting",
  "chat_terminal", "charts", "connections", "admin_console", "user_settings",
] as const);

export type FeatureKeyV1 = (typeof FEATURE_KEYS_V1)[number];
export type FeatureAccessClassV1 = "READ" | "WRITE" | "SAFETY_OFF";

export interface NavigationFeatureBindingV1 {
  readonly navigation_code: string;
  readonly feature_key: FeatureKeyV1;
}

export interface ApiFeatureActionV1 {
  /** Stable identifier is METHOD + the registered route template. */
  readonly action_id: string;
  readonly method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  readonly path: string;
  readonly feature_key: FeatureKeyV1;
  readonly classification: FeatureAccessClassV1;
  /** A defined router can be dormant until explicitly mounted. */
  readonly registration: "MOUNTED" | "DEFINED_NOT_MOUNTED" | "PLANNED" | "WORKER_ROUTE";
}

export interface FeatureDefinitionV1 {
  readonly feature_key: FeatureKeyV1;
  readonly requirement_ids: readonly string[];
  readonly navigation_codes: readonly string[];
  readonly api_actions: readonly ApiFeatureActionV1[];
  readonly deny_behavior: "HIDE_DESTINATION_AND_DENY_ACTION";
}

export type FeatureCatalogErrorCodeV1 =
  | "UNKNOWN_FEATURE" | "DUPLICATE_FEATURE" | "INCOMPLETE_FEATURE_MAP"
  | "INVALID_FEATURE_VALUE" | "UNKNOWN_NAVIGATION" | "UNKNOWN_API_ACTION";

export class FeatureCatalogErrorV1 extends Error {
  constructor(readonly code: FeatureCatalogErrorCodeV1) {
    super(code);
    this.name = "FeatureCatalogErrorV1";
  }
}

/** One stable catalog map for every terminal navigation destination. */
export const NAVIGATION_FEATURES_V1: readonly NavigationFeatureBindingV1[] = Object.freeze(([
  { navigation_code: "CC", feature_key: "chat_terminal" },
  { navigation_code: "INTEL", feature_key: "data_sources" },
  { navigation_code: "QR", feature_key: "strategy_lab" },
  { navigation_code: "GP", feature_key: "charts" },
  { navigation_code: "HP", feature_key: "strategy_lab" },
  { navigation_code: "OMON", feature_key: "paper_trading" },
  { navigation_code: "CURV", feature_key: "charts" },
  { navigation_code: "FXC", feature_key: "charts" },
  { navigation_code: "WEI", feature_key: "live_trading" },
  { navigation_code: "JRNL", feature_key: "paper_trading" },
  { navigation_code: "RISK", feature_key: "live_trading" },
  { navigation_code: "GENOME", feature_key: "strategy_lab" },
  { navigation_code: "LIVE", feature_key: "live_trading" },
  { navigation_code: "KNOW", feature_key: "strategy_lab" },
  { navigation_code: "LGD", feature_key: "live_trading" },
  { navigation_code: "PACT", feature_key: "paper_trading" },
  { navigation_code: "PAPR", feature_key: "paper_trading" },
  { navigation_code: "EAC", feature_key: "ea_hosting" },
  { navigation_code: "FLR", feature_key: "live_trading" },
  { navigation_code: "PIPE", feature_key: "strategy_lab" },
  { navigation_code: "HELP", feature_key: "chat_terminal" },
  { navigation_code: "TODAY", feature_key: "chat_terminal" },
  { navigation_code: "SYMBOL", feature_key: "charts" },
  { navigation_code: "STRATEGY", feature_key: "strategy_lab" },
  { navigation_code: "DATA", feature_key: "data_sources" },
  { navigation_code: "CHRT", feature_key: "charts" },
  { navigation_code: "PORD", feature_key: "paper_trading" },
  { navigation_code: "CONN", feature_key: "connections" },
  { navigation_code: "APPR", feature_key: "user_settings" },
  { navigation_code: "CHAT", feature_key: "chat_terminal" },
] satisfies NavigationFeatureBindingV1[]).map((binding) => Object.freeze(binding)));

/** Frozen Python API action inventory and pre-registered route bindings; unknown actions default-deny. */
export const API_FEATURE_ACTIONS_V1: readonly ApiFeatureActionV1[] = Object.freeze(([ 
  { action_id: "PUT /live-trading/credentials/{provider}/{environment}/{profile_id}", method: "PUT", path: "/live-trading/credentials/{provider}/{environment}/{profile_id}", feature_key: "connections", classification: "WRITE", registration: "MOUNTED" },
  { action_id: "DELETE /live-trading/credentials/{provider}/{environment}/{profile_id}", method: "DELETE", path: "/live-trading/credentials/{provider}/{environment}/{profile_id}", feature_key: "connections", classification: "WRITE", registration: "MOUNTED" },
  { action_id: "POST /ingest/backfill", method: "POST", path: "/ingest/backfill", feature_key: "data_sources", classification: "WRITE", registration: "DEFINED_NOT_MOUNTED" },
  { action_id: "POST /mcp/agents/register", method: "POST", path: "/mcp/agents/register", feature_key: "chat_terminal", classification: "WRITE", registration: "MOUNTED" },
  { action_id: "POST /mcp/tools/grant", method: "POST", path: "/mcp/tools/grant", feature_key: "admin_console", classification: "WRITE", registration: "MOUNTED" },
  { action_id: "POST /mcp/sessions", method: "POST", path: "/mcp/sessions", feature_key: "chat_terminal", classification: "WRITE", registration: "MOUNTED" },
  { action_id: "PATCH /mcp/sessions/{session_id}", method: "PATCH", path: "/mcp/sessions/{session_id}", feature_key: "chat_terminal", classification: "WRITE", registration: "MOUNTED" },
  { action_id: "POST /mcp/actions", method: "POST", path: "/mcp/actions", feature_key: "chat_terminal", classification: "WRITE", registration: "MOUNTED" },
  { action_id: "POST /mcp/actions/dry-run", method: "POST", path: "/mcp/actions/dry-run", feature_key: "chat_terminal", classification: "WRITE", registration: "MOUNTED" },
  { action_id: "POST /mcp/overrides", method: "POST", path: "/mcp/overrides", feature_key: "admin_console", classification: "WRITE", registration: "MOUNTED" },
  { action_id: "POST /mcp/halts", method: "POST", path: "/mcp/halts", feature_key: "live_trading", classification: "SAFETY_OFF", registration: "MOUNTED" },
  { action_id: "POST /omega/inquiry", method: "POST", path: "/omega/inquiry", feature_key: "chat_terminal", classification: "WRITE", registration: "MOUNTED" },
  { action_id: "POST /omega/kill", method: "POST", path: "/omega/kill", feature_key: "live_trading", classification: "SAFETY_OFF", registration: "MOUNTED" },
  { action_id: "POST /v1/omega/tasks/handoff", method: "POST", path: "/v1/omega/tasks/handoff", feature_key: "chat_terminal", classification: "WRITE", registration: "MOUNTED" },
  { action_id: "POST /v1/omega/tasks/{task_id}/accept", method: "POST", path: "/v1/omega/tasks/{task_id}/accept", feature_key: "chat_terminal", classification: "WRITE", registration: "MOUNTED" },
  { action_id: "POST /v1/omega/tasks/{task_id}/update", method: "POST", path: "/v1/omega/tasks/{task_id}/update", feature_key: "chat_terminal", classification: "WRITE", registration: "MOUNTED" },
  { action_id: "POST /v1/omega/tasks/{task_id}/cancel", method: "POST", path: "/v1/omega/tasks/{task_id}/cancel", feature_key: "chat_terminal", classification: "WRITE", registration: "MOUNTED" },
  { action_id: "POST /v1/omega/tools/use", method: "POST", path: "/v1/omega/tools/use", feature_key: "chat_terminal", classification: "WRITE", registration: "MOUNTED" },
  { action_id: "POST /orders/recover", method: "POST", path: "/orders/recover", feature_key: "paper_trading", classification: "WRITE", registration: "MOUNTED" },
  { action_id: "POST /orders/activations", method: "POST", path: "/orders/activations", feature_key: "live_trading", classification: "WRITE", registration: "MOUNTED" },
  { action_id: "POST /orders/activations/revoke", method: "POST", path: "/orders/activations/revoke", feature_key: "live_trading", classification: "SAFETY_OFF", registration: "MOUNTED" },
  { action_id: "POST /orders", method: "POST", path: "/orders", feature_key: "paper_trading", classification: "WRITE", registration: "MOUNTED" },
  { action_id: "POST /orders/{order_id}/submit", method: "POST", path: "/orders/{order_id}/submit", feature_key: "paper_trading", classification: "WRITE", registration: "MOUNTED" },
  { action_id: "POST /orders/{order_id}/cancel", method: "POST", path: "/orders/{order_id}/cancel", feature_key: "paper_trading", classification: "WRITE", registration: "MOUNTED" },
  { action_id: "POST /orders/{order_id}/reconcile", method: "POST", path: "/orders/{order_id}/reconcile", feature_key: "paper_trading", classification: "WRITE", registration: "MOUNTED" },
  { action_id: "POST /paper/mass-cancel/v1", method: "POST", path: "/paper/mass-cancel/v1", feature_key: "paper_trading", classification: "WRITE", registration: "DEFINED_NOT_MOUNTED" },
  { action_id: "POST /paper/risk/assessment/v1/preview", method: "POST", path: "/paper/risk/assessment/v1/preview", feature_key: "paper_trading", classification: "READ", registration: "DEFINED_NOT_MOUNTED" },
  { action_id: "POST /pipeline/replay", method: "POST", path: "/pipeline/replay", feature_key: "strategy_lab", classification: "WRITE", registration: "MOUNTED" },
  { action_id: "POST /mt5/ea-host/v1/install", method: "POST", path: "/mt5/ea-host/v1/install", feature_key: "ea_hosting", classification: "WRITE", registration: "MOUNTED" },
  { action_id: "GET /mt5/ea-host/v1/sessions/{session_id}", method: "GET", path: "/mt5/ea-host/v1/sessions/{session_id}", feature_key: "ea_hosting", classification: "READ", registration: "MOUNTED" },
  { action_id: "POST /mt5/ea-host/v1/sessions/{session_id}/kill", method: "POST", path: "/mt5/ea-host/v1/sessions/{session_id}/kill", feature_key: "ea_hosting", classification: "WRITE", registration: "MOUNTED" },
  { action_id: "GET /api/preferences/{namespace}", method: "GET", path: "/api/preferences/{namespace}", feature_key: "user_settings", classification: "READ", registration: "MOUNTED" },
  { action_id: "PUT /api/preferences/{namespace}", method: "PUT", path: "/api/preferences/{namespace}", feature_key: "user_settings", classification: "WRITE", registration: "MOUNTED" },
  { action_id: "DELETE /api/preferences/{namespace}", method: "DELETE", path: "/api/preferences/{namespace}", feature_key: "user_settings", classification: "WRITE", registration: "MOUNTED" },
  { action_id: "GET /chat/history/conversations", method: "GET", path: "/chat/history/conversations", feature_key: "chat_terminal", classification: "READ", registration: "MOUNTED" },
  { action_id: "POST /chat/history/conversations", method: "POST", path: "/chat/history/conversations", feature_key: "chat_terminal", classification: "WRITE", registration: "MOUNTED" },
  { action_id: "POST /chat/history/conversations/{conversation_id}/messages", method: "POST", path: "/chat/history/conversations/{conversation_id}/messages", feature_key: "chat_terminal", classification: "WRITE", registration: "MOUNTED" },
  { action_id: "GET /chat/history/conversations/{conversation_id}/messages", method: "GET", path: "/chat/history/conversations/{conversation_id}/messages", feature_key: "chat_terminal", classification: "READ", registration: "MOUNTED" },
  { action_id: "DELETE /chat/history/conversations/{conversation_id}", method: "DELETE", path: "/chat/history/conversations/{conversation_id}", feature_key: "chat_terminal", classification: "WRITE", registration: "MOUNTED" },
  { action_id: "GET /chat/history/conversations/{conversation_id}/export", method: "GET", path: "/chat/history/conversations/{conversation_id}/export", feature_key: "chat_terminal", classification: "READ", registration: "MOUNTED" },
  { action_id: "GET /chat/models", method: "GET", path: "/chat/models", feature_key: "chat_terminal", classification: "READ", registration: "MOUNTED" },
  { action_id: "POST /chat/complete", method: "POST", path: "/chat/complete", feature_key: "chat_terminal", classification: "WRITE", registration: "MOUNTED" },
  { action_id: "POST /chat/stream", method: "POST", path: "/chat/stream", feature_key: "chat_terminal", classification: "WRITE", registration: "MOUNTED" },
  { action_id: "GET /chat/tools/registry", method: "GET", path: "/chat/tools/registry", feature_key: "chat_terminal", classification: "READ", registration: "PLANNED" },
  { action_id: "POST /chat/tools/plan", method: "POST", path: "/chat/tools/plan", feature_key: "chat_terminal", classification: "WRITE", registration: "PLANNED" },
  { action_id: "POST /chat/tools/confirm", method: "POST", path: "/chat/tools/confirm", feature_key: "chat_terminal", classification: "WRITE", registration: "PLANNED" },
  { action_id: "POST /chat/tools/read", method: "POST", path: "/chat/tools/read", feature_key: "chat_terminal", classification: "READ", registration: "PLANNED" },
  { action_id: "GET /connections/catalog", method: "GET", path: "/connections/catalog", feature_key: "connections", classification: "READ", registration: "MOUNTED" },
  { action_id: "GET /connections/status", method: "GET", path: "/connections/status", feature_key: "connections", classification: "READ", registration: "MOUNTED" },
  { action_id: "POST /connections/{provider}/connect", method: "POST", path: "/connections/{provider}/connect", feature_key: "connections", classification: "WRITE", registration: "MOUNTED" },
  { action_id: "POST /connections/{provider}/cancel", method: "POST", path: "/connections/{provider}/cancel", feature_key: "connections", classification: "WRITE", registration: "MOUNTED" },
  { action_id: "POST /connections/{provider}/disconnect", method: "POST", path: "/connections/{provider}/disconnect", feature_key: "connections", classification: "WRITE", registration: "MOUNTED" },
  { action_id: "GET /live-activation/status", method: "GET", path: "/live-activation/status", feature_key: "live_trading", classification: "READ", registration: "PLANNED" },
  { action_id: "POST /live-activation/enable", method: "POST", path: "/live-activation/enable", feature_key: "live_trading", classification: "WRITE", registration: "PLANNED" },
  { action_id: "POST /live-activation/disable", method: "POST", path: "/live-activation/disable", feature_key: "live_trading", classification: "WRITE", registration: "PLANNED" },
  { action_id: "POST /v1/signup/checkout", method: "POST", path: "/v1/signup/checkout", feature_key: "admin_console", classification: "WRITE", registration: "WORKER_ROUTE" },
  { action_id: "POST /v1/signup/webhook", method: "POST", path: "/v1/signup/webhook", feature_key: "admin_console", classification: "WRITE", registration: "WORKER_ROUTE" },
  { action_id: "POST /md/chart/ticket", method: "POST", path: "/md/chart/ticket", feature_key: "charts", classification: "READ", registration: "MOUNTED" },
  { action_id: "GET /data-sources", method: "GET", path: "/data-sources", feature_key: "data_sources", classification: "READ", registration: "MOUNTED" },
  { action_id: "POST /risk/halt", method: "POST", path: "/risk/halt", feature_key: "live_trading", classification: "SAFETY_OFF", registration: "MOUNTED" },
  { action_id: "POST /risk/halt/lift", method: "POST", path: "/risk/halt/lift", feature_key: "admin_console", classification: "WRITE", registration: "MOUNTED" },
] satisfies ApiFeatureActionV1[]).map((action) => Object.freeze(action)));

const REQUIREMENTS: Readonly<Record<FeatureKeyV1, readonly string[]>> = Object.freeze({
  paper_trading: Object.freeze(["LEV-REQ-001", "LEV-REQ-013", "LEV-REQ-021", "LEV-REQ-025", "LEV-REQ-031"]),
  live_trading: Object.freeze(["LEV-REQ-001", "LEV-REQ-004", "LEV-REQ-013", "LEV-REQ-030", "LEV-REQ-031", "LEV-REQ-032"]),
  data_sources: Object.freeze(["LEV-REQ-001", "LEV-REQ-019", "LEV-REQ-020"]),
  strategy_lab: Object.freeze(["LEV-REQ-001", "LEV-REQ-002", "LEV-REQ-003", "LEV-REQ-008", "LEV-REQ-014", "LEV-REQ-016", "LEV-REQ-028", "LEV-REQ-029", "LEV-REQ-033", "LEV-REQ-034", "LEV-REQ-035", "LEV-REQ-036", "LEV-REQ-037"]),
  ea_hosting: Object.freeze(["LEV-REQ-001", "LEV-REQ-011"]),
  chat_terminal: Object.freeze(["LEV-REQ-001", "LEV-REQ-022", "LEV-REQ-023", "LEV-REQ-X007"]),
  charts: Object.freeze(["LEV-REQ-001", "LEV-REQ-007", "LEV-REQ-014", "LEV-REQ-018", "LEV-REQ-021", "LEV-REQ-027", "LEV-REQ-040"]),
  connections: Object.freeze(["LEV-REQ-001", "LEV-REQ-013", "LEV-REQ-019", "LEV-REQ-020", "LEV-REQ-032"]),
  admin_console: Object.freeze(["LEV-REQ-001", "LEV-REQ-030", "LEV-REQ-032"]),
  user_settings: Object.freeze(["LEV-REQ-001"]),
});

export const FEATURE_CATALOG_V1: readonly FeatureDefinitionV1[] = Object.freeze(
  FEATURE_KEYS_V1.map((feature_key) => Object.freeze({
    feature_key,
    requirement_ids: REQUIREMENTS[feature_key],
    navigation_codes: Object.freeze(NAVIGATION_FEATURES_V1
      .filter((binding) => binding.feature_key === feature_key)
      .map((binding) => binding.navigation_code)),
    api_actions: Object.freeze(API_FEATURE_ACTIONS_V1
      .filter((action) => action.feature_key === feature_key)),
    deny_behavior: "HIDE_DESTINATION_AND_DENY_ACTION" as const,
  })),
);

export function isFeatureKeyV1(value: unknown): value is FeatureKeyV1 {
  return typeof value === "string" && (FEATURE_KEYS_V1 as readonly string[]).includes(value);
}

export function featureForNavigationCodeV1(code: string): FeatureKeyV1 | null {
  return NAVIGATION_FEATURES_V1.find((binding) => binding.navigation_code === code)?.feature_key ?? null;
}

export function featureForApiActionV1(method: string, routeTemplate: string): FeatureKeyV1 | null {
  return API_FEATURE_ACTIONS_V1.find((action) => action.method === method && action.path === routeTemplate)
    ?.feature_key ?? null;
}

/** Normalize exact entries while rejecting duplicates, unknowns, invalid values and omissions. */
export function completeFeatureMapV1(
  entries: readonly (readonly [unknown, unknown])[],
): Readonly<Record<FeatureKeyV1, boolean>> {
  if (!Array.isArray(entries)) throw new FeatureCatalogErrorV1("INCOMPLETE_FEATURE_MAP");
  const copy: Partial<Record<FeatureKeyV1, boolean>> = Object.create(null) as Partial<Record<FeatureKeyV1, boolean>>;
  for (const entry of entries) {
    if (!Array.isArray(entry) || entry.length !== 2) {
      throw new FeatureCatalogErrorV1("INVALID_FEATURE_VALUE");
    }
    const [key, value] = entry;
    if (!isFeatureKeyV1(key)) throw new FeatureCatalogErrorV1("UNKNOWN_FEATURE");
    if (Object.hasOwn(copy, key)) throw new FeatureCatalogErrorV1("DUPLICATE_FEATURE");
    if (typeof value !== "boolean") throw new FeatureCatalogErrorV1("INVALID_FEATURE_VALUE");
    copy[key] = value;
  }
  if (FEATURE_KEYS_V1.some((key) => !Object.hasOwn(copy, key))) {
    throw new FeatureCatalogErrorV1("INCOMPLETE_FEATURE_MAP");
  }
  return Object.freeze(copy as Record<FeatureKeyV1, boolean>);
}

/** A record boundary cannot represent duplicate JSON keys; it still rejects extra/missing keys. */
export function validateFeatureRecordV1(value: unknown): value is Readonly<Record<FeatureKeyV1, boolean>> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) return false;
  const keys = Reflect.ownKeys(value);
  if (keys.length !== FEATURE_KEYS_V1.length || keys.some((key) => typeof key !== "string"
      || !isFeatureKeyV1(key))) return false;
  return FEATURE_KEYS_V1.every((key) => Object.hasOwn(value, key)
    && typeof (value as Record<string, unknown>)[key] === "boolean");
}

export function catalogCompletenessErrorV1(
  currentNavigationCodes: readonly string[],
): "NAVIGATION_DUPLICATE" | "NAVIGATION_MISSING" | "NAVIGATION_UNKNOWN" | null {
  const expected = new Set(currentNavigationCodes);
  const actual = NAVIGATION_FEATURES_V1.map((binding) => binding.navigation_code);
  if (new Set(actual).size !== actual.length) return "NAVIGATION_DUPLICATE";
  if (actual.some((code) => !expected.has(code))) return "NAVIGATION_UNKNOWN";
  if (expected.size !== actual.length || [...expected].some((code) => !actual.includes(code))) {
    return "NAVIGATION_MISSING";
  }
  return null;
}
