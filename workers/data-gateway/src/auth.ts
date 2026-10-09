export interface DeviceEntitlementV1 {
  readonly device_id: string;
  readonly licence_id: string;
}

export interface LicenceEntitlementPortV1 {
  authenticateDeviceBearer(token: string): Promise<DeviceEntitlementV1 | null>;
}

export interface GatewayRateLimitRequestV1 {
  readonly device_id: string;
  readonly provider_id: string;
}

export interface GatewayRateLimiterV1 {
  consume(input: GatewayRateLimitRequestV1): Promise<boolean>;
}

export type GatewayLogEventV1 = "request" | "denied" | "upstream_error";

export interface GatewayLogEntryV1 {
  readonly event: GatewayLogEventV1;
  readonly code: string;
  readonly provider_id: string | null;
  readonly method: string;
  readonly path: string;
  readonly status: number;
}

export interface GatewayLoggerV1 {
  log(entry: GatewayLogEntryV1): void;
}

export interface GatewayFetchResponseV1 {
  readonly status: number;
  readonly headers: Headers;
  readonly body: Uint8Array;
}

export interface GatewayFetchV1 {
  (input: RequestInfo | URL, init?: RequestInit): Promise<Response>;
}

export interface GatewayDependenciesV1 {
  readonly entitlement: LicenceEntitlementPortV1;
  readonly rateLimiter: GatewayRateLimiterV1;
  readonly upstreamFetch: GatewayFetchV1;
  readonly logger: GatewayLoggerV1;
}

export type GatewayEnvV1 = Readonly<Record<string, string | undefined>>;

export interface LicenseWorkerBindingV1 {
  fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response>;
}

export interface GatewayKvBindingV1 {
  get(key: string): Promise<string | null>;
  put(key: string, value: string, options?: { readonly expirationTtl?: number }): Promise<void>;
}

export interface GatewayDurableObjectBindingV1 {
  idFromName(name: string): object | string;
  get(id: object | string): { fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> };
}

export interface DataGatewayWorkerEnvV1 {
  readonly LICENSE_WORKER?: LicenseWorkerBindingV1;
  readonly RATE_LIMIT?: GatewayKvBindingV1 | GatewayDurableObjectBindingV1;
  readonly LICENSE_VERIFY_PUBLIC_KEY_JWK?: string;
  readonly [name: string]: unknown;
}

export const DEVICE_ID_PATTERN_V1 = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;

export function isDeviceEntitlementV1(value: unknown): value is DeviceEntitlementV1 {
  if (typeof value !== "object" || value === null) return false;
  const candidate = value as Record<string, unknown>;
  return typeof candidate.device_id === "string"
    && DEVICE_ID_PATTERN_V1.test(candidate.device_id)
    && typeof candidate.licence_id === "string"
    && DEVICE_ID_PATTERN_V1.test(candidate.licence_id);
}
