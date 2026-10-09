export type CredentialRoute = "vault_ref" | "gateway";

export type DataSourceStatus =
  | "NOT_CONFIGURED"
  | "READY"
  | "DEGRADED"
  | "EXTERNAL_GATE"
  | "DISABLED";

export type DataSourceErrorCode =
  | "AUTH_REJECTED"
  | "NETWORK_UNAVAILABLE"
  | "PROVIDER_ERROR"
  | "QUOTA_EXHAUSTED"
  | "RATE_LIMITED"
  | "SCHEMA_MISMATCH"
  | "SOURCE_STALE"
  | "UNKNOWN";

export interface DataSourceRow {
  provider_id: string;
  display_name: string;
  capabilities: string[];
  requires_credentials: boolean;
  credential_route: CredentialRoute | null;
  status: DataSourceStatus;
  source_time_ns: number | null;
  received_time_ns: number | null;
  error_code: DataSourceErrorCode | null;
}

export interface DataSourcesResponse {
  schema_version: "leviathan.data-sources/1";
  sources: DataSourceRow[];
}

export type DataSourcesApiResult =
  | { ok: true; data: DataSourcesResponse }
  | { ok: false; error: string };

export type DataSourcesLoader = () => Promise<DataSourcesApiResult>;
