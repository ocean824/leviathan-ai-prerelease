export type ProviderAuthInjectionV1 =
  | { readonly kind: "header"; readonly name: string; readonly prefix: string; readonly encoding?: "basic_username" }
  | { readonly kind: "query"; readonly name: string };

export interface ProviderRouteV1 {
  readonly path_prefix: string;
  readonly methods: readonly ("GET" | "POST")[];
  readonly query_keys: readonly string[];
  readonly form_keys?: readonly string[];
}

export interface ProviderPolicyV1 {
  readonly provider_id: string;
  readonly origin: string;
  readonly credential_name: string;
  readonly secret_binding: string;
  readonly auth: ProviderAuthInjectionV1;
  readonly credential_query_keys: readonly string[];
  readonly routes: readonly ProviderRouteV1[];
}

const route = (
  path_prefix: string,
  query_keys: readonly string[],
  methods: readonly ("GET" | "POST")[] = ["GET"],
  form_keys?: readonly string[],
): ProviderRouteV1 => Object.freeze({
  path_prefix,
  methods: Object.freeze([...methods]),
  query_keys: Object.freeze([...query_keys]),
  ...(form_keys ? { form_keys: Object.freeze([...form_keys]) } : {}),
});

const keyQuery = [
  "api_key",
  "apikey",
  "apiKey",
  "api-key",
  "x-api-key",
  "key",
  "token",
  "access_token",
  "client_secret",
  "secret",
  "authorization",
  "UserID",
] as const;

export const DATA_GATEWAY_PROVIDERS_V1: Readonly<Record<string, ProviderPolicyV1>> = Object.freeze({
  databento: Object.freeze({
    provider_id: "databento", origin: "https://hist.databento.com",
    credential_name: "databento_api_key", secret_binding: "PROVIDER__DATABENTO__API_KEY",
    auth: Object.freeze({ kind: "header", name: "Authorization", prefix: "Basic ", encoding: "basic_username" }),
    credential_query_keys: Object.freeze([...keyQuery]),
    routes: Object.freeze([
      route("/v0/metadata.get_cost", ["dataset", "symbols", "schema", "start", "end", "stype_in", "limit"]),
      route("/v0/timeseries.get_range", [], ["POST"], ["dataset", "symbols", "schema", "start", "end", "stype_in", "limit"]),
    ]),
  }),
  massive: Object.freeze({
    provider_id: "massive", origin: "https://api.massive.com",
    credential_name: "massive_api_key", secret_binding: "PROVIDER__MASSIVE__API_KEY",
    auth: Object.freeze({ kind: "header", name: "Authorization", prefix: "Bearer " }),
    credential_query_keys: Object.freeze([...keyQuery]),
    routes: Object.freeze([
      route("/v3/trades/", ["timestamp.gte", "timestamp.lte", "limit", "sort", "order"]),
      route("/v3/quotes/", ["timestamp.gte", "timestamp.lte", "limit", "sort", "order"]),
      route("/v2/aggs/ticker/", ["adjusted", "sort", "limit"]),
      route("/benzinga/v2/news", ["tickers", "published.gte", "published.lte", "limit", "sort"]),
    ]),
  }),
  fred: Object.freeze({
    provider_id: "fred", origin: "https://api.stlouisfed.org",
    credential_name: "fred_api_key", secret_binding: "PROVIDER__FRED__API_KEY",
    auth: Object.freeze({ kind: "query", name: "api_key" }),
    credential_query_keys: Object.freeze([...keyQuery]),
    routes: Object.freeze([
      route("/fred/series/observations", ["series_id", "file_type", "limit", "sort_order", "realtime_start", "realtime_end"]),
    ]),
  }),
  bea: Object.freeze({
    provider_id: "bea", origin: "https://apps.bea.gov",
    credential_name: "bea_api_key", secret_binding: "PROVIDER__BEA__API_KEY",
    auth: Object.freeze({ kind: "query", name: "UserID" }),
    credential_query_keys: Object.freeze([...keyQuery]),
    routes: Object.freeze([
      route("/api/data/", ["method", "ResultFormat", "datasetname", "TableName", "Frequency", "Year", "GeoFIPS", "GeoName", "LineNumber", "Statistic", "UnitOfMeasure", "Industry" ]),
    ]),
  }),
  eia: Object.freeze({
    provider_id: "eia", origin: "https://api.eia.gov",
    credential_name: "eia_api_key", secret_binding: "PROVIDER__EIA__API_KEY",
    auth: Object.freeze({ kind: "query", name: "api_key" }),
    credential_query_keys: Object.freeze([...keyQuery]),
    routes: Object.freeze([
      route("/v2/", ["frequency", "data[]", "facets[]", "start", "end", "length", "offset", "sort[0][column]", "sort[0][direction]"]),
    ]),
  }),
  unusual_whales: Object.freeze({
    provider_id: "unusual_whales", origin: "https://api.unusualwhales.com",
    credential_name: "unusual_whales_api_key", secret_binding: "PROVIDER__UNUSUAL_WHALES__API_KEY",
    auth: Object.freeze({ kind: "header", name: "Authorization", prefix: "Bearer " }),
    credential_query_keys: Object.freeze([...keyQuery]),
    routes: Object.freeze([
      route("/api/option-trades", ["ticker", "limit", "older_than", "expirations[]"]),
      route("/api/stock/", ["expirations[]", "date", "limit", "page"]),
    ]),
  }),
});

export function findProviderV1(providerId: string): ProviderPolicyV1 | null {
  return Object.hasOwn(DATA_GATEWAY_PROVIDERS_V1, providerId)
    ? DATA_GATEWAY_PROVIDERS_V1[providerId] ?? null
    : null;
}
