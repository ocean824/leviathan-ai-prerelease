import {
  DEVICE_ID_PATTERN_V1,
  isDeviceEntitlementV1,
  type DataGatewayWorkerEnvV1,
  type GatewayDependenciesV1,
  type GatewayEnvV1,
  type GatewayLogEntryV1,
} from "./auth.js";
import { findProviderV1, type ProviderPolicyV1, type ProviderRouteV1 } from "./providers.js";

const MAX_TOKEN_CHARS = 4_096;
const MAX_PATH_CHARS = 2_048;
const MAX_QUERY_ENTRIES = 128;
const MAX_BODY_BYTES = 65_536;
const MAX_RESPONSE_BYTES = 2_097_152;
const REQUEST_TIMEOUT_MS = 15_000;
const REDACTED = "[REDACTED]";
const SAFE_PATH = /^\/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*$/;
const ENCODED_PATH_TRAVERSAL = /%(?:25)*(?:2e|2f|5c)/i;
const SAFE_HEADER = /^[\x20-\x7e]+$/;
const RATE_WINDOW_SECONDS = 60;
const RATE_LIMIT_PER_WINDOW = 60;
const LICENSE_VERIFY_URL = "https://license-worker.internal/v1/internal/device-entitlement/verify";
const DEVICE_TOKEN_AUDIENCE = "leviathan-data-gateway";
const DEVICE_TOKEN_ISSUER = "leviathan-licensing";

export interface DataGatewayRuntimeV1 {
  fetch(request: Request): Promise<Response>;
}

export interface DataGatewayOptionsV1 extends GatewayDependenciesV1 {
  readonly env: GatewayEnvV1;
}

export interface DataGatewayWorkerV1 {
  fetch(request: Request, env: DataGatewayWorkerEnvV1): Promise<Response>;
}

function errorResponse(status: number, code: string): Response {
  return Response.json({ schema_version: 1, error: { code } }, { status, headers: { "cache-control": "no-store" } });
}

function decodeBase64Url(value: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]+$/.test(value) || value.length > 8_192) return null;
  try {
    const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
    const binary = atob(base64 + "=".repeat((4 - base64.length % 4) % 4));
    const output = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) output[index] = binary.charCodeAt(index);
    return output;
  } catch {
    return null;
  }
}

function asArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

function decodeJsonSegment(value: string): unknown {
  const bytes = decodeBase64Url(value);
  if (!bytes) return null;
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) as unknown;
  } catch {
    return null;
  }
}

async function verifyLocalDeviceToken(token: string, jwkJson: string): Promise<{ device_id: string; licence_id: string } | null> {
  if (token.length > MAX_TOKEN_CHARS || jwkJson.length > 8_192) return null;
  const parts = token.split(".");
  if (parts.length !== 3 || !parts[0] || !parts[1] || !parts[2]) return null;
  const header = decodeJsonSegment(parts[0]);
  const claims = decodeJsonSegment(parts[1]);
  if (typeof header !== "object" || header === null || typeof claims !== "object" || claims === null) return null;
  const headerRecord = header as Record<string, unknown>;
  const claimRecord = claims as Record<string, unknown>;
  if (headerRecord.alg !== "ES256" || (headerRecord.typ !== undefined && headerRecord.typ !== "JWT")) return null;
  const nowSeconds = Math.floor(Date.now() / 1_000);
  if (
    claimRecord.iss !== DEVICE_TOKEN_ISSUER
    || claimRecord.aud !== DEVICE_TOKEN_AUDIENCE
    || claimRecord.entitled !== true
    || typeof claimRecord.device_id !== "string"
    || claimRecord.sub !== claimRecord.device_id
    || typeof claimRecord.licence_id !== "string"
    || typeof claimRecord.exp !== "number"
    || !Number.isSafeInteger(claimRecord.exp)
    || claimRecord.exp <= nowSeconds
    || typeof claimRecord.iat !== "number"
    || !Number.isSafeInteger(claimRecord.iat)
    || claimRecord.iat > nowSeconds + 120
    || claimRecord.iat < nowSeconds - 86_400
    || claimRecord.exp <= claimRecord.iat
    || claimRecord.exp > nowSeconds + 86_400
    || claimRecord.exp - claimRecord.iat > 86_400
    || (claimRecord.nbf !== undefined && (typeof claimRecord.nbf !== "number" || !Number.isSafeInteger(claimRecord.nbf) || claimRecord.nbf > nowSeconds))
  ) return null;
  const signature = decodeBase64Url(parts[2]);
  if (!signature) return null;
  let jwk: JsonWebKey;
  try {
    const parsed = JSON.parse(jwkJson) as unknown;
    if (typeof parsed !== "object" || parsed === null) throw new Error("INVALID_JWK");
    jwk = parsed as JsonWebKey;
    if (jwk.kty !== "EC" || jwk.crv !== "P-256" || typeof jwk.x !== "string" || typeof jwk.y !== "string") {
      throw new Error("INVALID_JWK");
    }
  } catch {
    throw new Error("TOKEN_VERIFY_UNAVAILABLE");
  }
  let key: CryptoKey;
  try {
    key = await crypto.subtle.importKey(
      "jwk",
      jwk,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
  } catch {
    throw new Error("TOKEN_VERIFY_UNAVAILABLE");
  }
  try {
    const valid = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      asArrayBuffer(signature),
      asArrayBuffer(new TextEncoder().encode(`${parts[0]}.${parts[1]}`)),
    );
    if (!valid) return null;
    const candidate = { device_id: claimRecord.device_id, licence_id: claimRecord.licence_id };
    return isDeviceEntitlementV1(candidate) ? candidate : null;
  } catch {
    throw new Error("TOKEN_VERIFY_UNAVAILABLE");
  }
}

async function entitlementFromBindings(env: DataGatewayWorkerEnvV1, token: string): Promise<{ device_id: string; licence_id: string } | null> {
  const binding = env.LICENSE_WORKER;
  if (binding && typeof binding.fetch === "function") {
    const response = await binding.fetch(LICENSE_VERIFY_URL, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({ schema_version: 1, device_token: token }),
      redirect: "manual",
    });
    if (response.status === 401 || response.status === 403) {
      try { await response.body?.cancel(); } catch { /* ignored */ }
      return null;
    }
    if (response.status !== 200) {
      try { await response.body?.cancel(); } catch { /* ignored */ }
      throw new Error("ENTITLEMENT_UNAVAILABLE");
    }
    const bytes = await readCappedResponse(response, 4_096);
    if (!bytes) throw new Error("ENTITLEMENT_UNAVAILABLE");
    try {
      const body = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) as unknown;
      if (typeof body !== "object" || body === null) return null;
      const record = body as Record<string, unknown>;
      const data = typeof record.data === "object" && record.data !== null ? record.data as Record<string, unknown> : record;
      if (record.schema_version !== 1 || data.active !== true) return null;
      const candidate = { device_id: data.device_id, licence_id: data.licence_id };
      return isDeviceEntitlementV1(candidate) ? candidate : null;
    } catch {
      return null;
    }
  }
  if (typeof env.LICENSE_VERIFY_PUBLIC_KEY_JWK !== "string" || env.LICENSE_VERIFY_PUBLIC_KEY_JWK.length === 0) {
    throw new Error("ENTITLEMENT_UNAVAILABLE");
  }
  return verifyLocalDeviceToken(token, env.LICENSE_VERIFY_PUBLIC_KEY_JWK);
}

class InIsolateRateLimiterV1 {
  private readonly buckets = new Map<string, { readonly window: number; count: number }>();

  async consume(input: { readonly device_id: string; readonly provider_id: string }): Promise<boolean> {
    const nowWindow = Math.floor(Date.now() / (RATE_WINDOW_SECONDS * 1_000));
    const key = `${input.device_id}:${input.provider_id}`;
    let bucket = this.buckets.get(key);
    if (!bucket || bucket.window !== nowWindow) {
      if (this.buckets.size >= 10_000) {
        for (const [oldKey, old] of this.buckets) {
          if (old.window < nowWindow) this.buckets.delete(oldKey);
          if (this.buckets.size < 9_000) break;
        }
        if (this.buckets.size >= 10_000) this.buckets.delete(this.buckets.keys().next().value as string);
      }
      bucket = { window: nowWindow, count: 0 };
      this.buckets.set(key, bucket);
    }
    bucket.count += 1;
    return bucket.count <= RATE_LIMIT_PER_WINDOW;
  }
}

const isolateRateLimiter = new InIsolateRateLimiterV1();

function isKvBinding(value: unknown): value is { get(key: string): Promise<string | null>; put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void> } {
  return typeof value === "object" && value !== null
    && typeof (value as { get?: unknown }).get === "function"
    && typeof (value as { put?: unknown }).put === "function";
}

function isDurableObjectBinding(value: unknown): value is {
  idFromName(name: string): object | string;
  get(id: object | string): { fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> };
} {
  return typeof value === "object" && value !== null
    && typeof (value as { idFromName?: unknown }).idFromName === "function"
    && typeof (value as { get?: unknown }).get === "function";
}

class BoundRateLimiterV1 {
  constructor(private readonly binding: unknown) {}

  async consume(input: { readonly device_id: string; readonly provider_id: string }): Promise<boolean> {
    if (isKvBinding(this.binding)) {
      const window = Math.floor(Date.now() / (RATE_WINDOW_SECONDS * 1_000));
      const key = `gateway:v1:${input.provider_id}:${encodeURIComponent(input.device_id)}:${window}`;
      const current = await this.binding.get(key);
      const count = current === null ? 0 : Number(current);
      if (!Number.isSafeInteger(count) || count < 0 || count >= RATE_LIMIT_PER_WINDOW) return false;
      await this.binding.put(key, String(count + 1), { expirationTtl: RATE_WINDOW_SECONDS * 2 });
      return true;
    }
    if (isDurableObjectBinding(this.binding)) {
      const objectId = this.binding.idFromName(`${input.provider_id}:${input.device_id}`);
      const response = await this.binding.get(objectId).fetch("https://gateway-rate-limit.internal/v1/consume", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ window_seconds: RATE_WINDOW_SECONDS, limit: RATE_LIMIT_PER_WINDOW }),
      });
      if (response.status === 429) return false;
      if (response.status !== 200) throw new Error("RATE_LIMIT_UNAVAILABLE");
      const body = await response.json() as unknown;
      return typeof body === "object" && body !== null && (body as Record<string, unknown>).allowed === true;
    }
    throw new Error("RATE_LIMIT_UNAVAILABLE");
  }
}

function bearerFrom(request: Request): string | null {
  const value = request.headers.get("authorization");
  if (typeof value !== "string" || value.length > MAX_TOKEN_CHARS + 16) return null;
  const match = /^Bearer ([^\s]+)$/i.exec(value);
  if (!match || match[1] === undefined || match[1].length < 8 || match[1].length > MAX_TOKEN_CHARS) return null;
  return match[1];
}

function getRoute(policy: ProviderPolicyV1, path: string): ProviderRouteV1 | null {
  for (const candidate of policy.routes) {
    if (path === candidate.path_prefix || (candidate.path_prefix.endsWith("/") && path.startsWith(candidate.path_prefix))) {
      return candidate;
    }
    if (!candidate.path_prefix.endsWith("/") && path.startsWith(`${candidate.path_prefix}/`)) return candidate;
  }
  return null;
}

function isSafePath(path: string): boolean {
  if (path.length > MAX_PATH_CHARS || !SAFE_PATH.test(path) || path.includes("\\") || ENCODED_PATH_TRAVERSAL.test(path)) return false;
  const segments = path.split("/");
  return segments.every((segment) => segment !== "." && segment !== ".." && !/[\u0000-\u001f\u007f]/.test(segment));
}

function secretValue(env: GatewayEnvV1, policy: ProviderPolicyV1): string | null {
  const value = env[policy.secret_binding];
  if (typeof value !== "string" || value.length < 1 || value.length > 4_096 || /[\r\n\u0000]/.test(value)) return null;
  return value;
}

function logSafe(options: DataGatewayOptionsV1, entry: GatewayLogEntryV1, deviceToken = ""): void {
  try {
    const method = redact(
      new Set(["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
        .has(entry.method) ? entry.method : "OTHER",
      options.env,
      deviceToken,
    );
    options.logger.log(Object.freeze({
      ...entry,
      method,
      path: redact(entry.path, options.env, deviceToken),
    }));
  } catch {
    // Logging failure does not change gateway control flow, and inputs are never exposed here.
  }
}

function reject(
  options: DataGatewayOptionsV1,
  request: Request,
  status: number,
  code: string,
  providerId: string | null,
  pathname: string,
  event: GatewayLogEntryV1["event"] = "denied",
): Response {
  logSafe(
    options,
    { event, code, provider_id: providerId, method: request.method, path: pathname, status },
    bearerFrom(request) ?? "",
  );
  return errorResponse(status, code);
}

async function readCapped(request: Request, cap: number): Promise<Uint8Array | null> {
  if (!request.body) return new Uint8Array();
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const next = await reader.read();
      if (next.done) break;
      total += next.value.byteLength;
      if (total > cap) {
        await reader.cancel();
        return null;
      }
      chunks.push(next.value);
    }
  } catch {
    return null;
  }
  const result = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return result;
}

async function readCappedResponse(response: Response, cap: number): Promise<Uint8Array | null> {
  if (!response.body) return new Uint8Array();
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const next = await reader.read();
      if (next.done) break;
      total += next.value.byteLength;
      if (total > cap) {
        await reader.cancel();
        return null;
      }
      chunks.push(next.value);
    }
  } catch {
    return null;
  }
  const result = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return result;
}

function redact(text: string, env: GatewayEnvV1, deviceToken: string): string {
  let safe = text;
  const values = [deviceToken, ...Object.entries(env)
    .filter(([name, value]) => name.startsWith("PROVIDER__") && typeof value === "string" && value.length > 0)
    .map(([, value]) => value as string)];
  for (const value of values) {
    if (value.length === 0) continue;
    const encodedValues = new Set([value, encodeURIComponent(value), JSON.stringify(value).slice(1, -1)]);
    try {
      const bytes = new TextEncoder().encode(value);
      let binary = "";
      for (const byte of bytes) binary += String.fromCharCode(byte);
      encodedValues.add(btoa(binary));
      encodedValues.add(new URLSearchParams({ value }).toString().slice("value=".length));
    } catch {
      // Raw and JSON-safe forms are still redacted if optional encodings fail.
    }
    for (const encoded of encodedValues) {
      if (encoded.length > 0) safe = safe.split(encoded).join(REDACTED);
    }
  }
  return safe;
}

function includesSensitive(value: string, env: GatewayEnvV1, deviceToken: string): boolean {
  const secrets = [deviceToken, ...Object.entries(env)
    .filter(([name, secret]) => name.startsWith("PROVIDER__") && typeof secret === "string" && secret.length > 0)
    .map(([, secret]) => secret as string)];
  return secrets.some((secret) => {
    if (!secret) return false;
    let base64 = "";
    try {
      const bytes = new TextEncoder().encode(secret);
      let binary = "";
      for (const byte of bytes) binary += String.fromCharCode(byte);
      base64 = btoa(binary);
    } catch {
      // Other encodings are still checked.
    }
    return [secret, encodeURIComponent(secret), JSON.stringify(secret).slice(1, -1), base64]
      .some((candidate) => candidate.length > 0 && value.includes(candidate));
  });
}

function parsedProviderPath(url: URL): { providerId: string | null; path: string | null } {
  const match = /^\/v1\/([a-z][a-z0-9_]{0,63})(\/.*)$/.exec(url.pathname);
  if (!match) return { providerId: null, path: null };
  return { providerId: match[1] ?? null, path: match[2] ?? null };
}

function queryParameters(
  requestUrl: URL,
  policy: ProviderPolicyV1,
  route: ProviderRouteV1,
): URLSearchParams | null {
  const incoming = new URLSearchParams(requestUrl.search);
  let entries = 0;
  incoming.forEach(() => { entries += 1; });
  if (entries > MAX_QUERY_ENTRIES) return null;
  const allowed = new Set(route.query_keys);
  const credentialKeys = new Set(policy.credential_query_keys.map((key) => key.toLowerCase()));
  const output = new URLSearchParams();
  let invalid = false;
  incoming.forEach((value, key) => {
    if (credentialKeys.has(key.toLowerCase())) return;
    if (!allowed.has(key) || key.length > 128 || value.length > 4_096) {
      invalid = true;
      return;
    }
    output.append(key, value);
  });
  if (invalid) return null;
  return output;
}

export function createDataGatewayV1(options: DataGatewayOptionsV1): DataGatewayRuntimeV1 {
  return Object.freeze({
    async fetch(request: Request): Promise<Response> {
      let requestUrl: URL;
      try {
        requestUrl = new URL(request.url);
      } catch {
        return errorResponse(400, "PATH_NOT_ALLOWED");
      }
      const routeBits = parsedProviderPath(requestUrl);
      const safeLogPath = requestUrl.pathname.slice(0, MAX_PATH_CHARS);
      const token = bearerFrom(request);
      if (!token) return reject(options, request, 401, "UNAUTHENTICATED", routeBits.providerId, safeLogPath);

      let entitlement: unknown;
      try {
        entitlement = await options.entitlement.authenticateDeviceBearer(token);
      } catch {
        return reject(options, request, 503, "NOT_CONFIGURED", routeBits.providerId, safeLogPath);
      }
      if (!isDeviceEntitlementV1(entitlement)) {
        return reject(options, request, 401, "UNAUTHENTICATED", routeBits.providerId, safeLogPath);
      }
      if (!routeBits.providerId || !routeBits.path || !isSafePath(routeBits.path)) {
        return reject(options, request, 403, "PATH_NOT_ALLOWED", routeBits.providerId, safeLogPath);
      }
      const policy = findProviderV1(routeBits.providerId);
      if (!policy) return reject(options, request, 404, "PROVIDER_NOT_FOUND", routeBits.providerId, safeLogPath);
      const matchedRoute = getRoute(policy, routeBits.path);
      if (!matchedRoute) return reject(options, request, 403, "PATH_NOT_ALLOWED", policy.provider_id, safeLogPath);
      if (!matchedRoute.methods.includes(request.method as "GET" | "POST")) {
        return reject(options, request, 405, "METHOD_NOT_ALLOWED", policy.provider_id, safeLogPath);
      }

      let allowed: boolean;
      try {
        allowed = await options.rateLimiter.consume({ device_id: entitlement.device_id, provider_id: policy.provider_id });
      } catch {
        return reject(options, request, 503, "NOT_CONFIGURED", policy.provider_id, safeLogPath);
      }
      if (allowed !== true) return reject(options, request, 429, "RATE_LIMITED", policy.provider_id, safeLogPath);
      const secret = secretValue(options.env, policy);
      if (!secret) return reject(options, request, 503, "NOT_CONFIGURED", policy.provider_id, safeLogPath);

      const params = queryParameters(requestUrl, policy, matchedRoute);
      if (!params) return reject(options, request, 403, "PATH_NOT_ALLOWED", policy.provider_id, safeLogPath);
      const upstreamPath = routeBits.path;
      const upstreamUrl = new URL(upstreamPath, policy.origin);
      if (upstreamUrl.origin !== policy.origin || upstreamUrl.username || upstreamUrl.password) {
        return reject(options, request, 403, "PATH_NOT_ALLOWED", policy.provider_id, safeLogPath);
      }
      upstreamUrl.search = params.toString();

      let body: Uint8Array | undefined;
      const headers = new Headers();
      const accept = request.headers.get("accept");
      if (accept && SAFE_HEADER.test(accept) && accept.length <= 256) headers.set("accept", accept);
      if (request.method === "POST") {
        const contentType = request.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
        if (contentType !== "application/x-www-form-urlencoded" || !matchedRoute.form_keys) {
          return reject(options, request, 403, "PATH_NOT_ALLOWED", policy.provider_id, safeLogPath);
        }
        const bytes = await readCapped(request, MAX_BODY_BYTES);
        if (!bytes) return reject(options, request, 403, "PATH_NOT_ALLOWED", policy.provider_id, safeLogPath);
        const decoded = new TextDecoder("utf-8", { fatal: true });
        let form: URLSearchParams;
        try {
          form = new URLSearchParams(decoded.decode(bytes));
        } catch {
          return reject(options, request, 403, "PATH_NOT_ALLOWED", policy.provider_id, safeLogPath);
        }
        const allowedForm = new Set(matchedRoute.form_keys);
        const credentialKeys = new Set(policy.credential_query_keys.map((key) => key.toLowerCase()));
        const cleaned = new URLSearchParams();
        let formCount = 0;
        form.forEach(() => { formCount += 1; });
        if (formCount > MAX_QUERY_ENTRIES) return reject(options, request, 403, "PATH_NOT_ALLOWED", policy.provider_id, safeLogPath);
        let invalidForm = false;
        form.forEach((value, key) => {
          if (credentialKeys.has(key.toLowerCase())) return;
          if (!allowedForm.has(key) || value.length > 4_096) {
            invalidForm = true;
            return;
          }
          cleaned.append(key, value);
        });
        if (invalidForm) return reject(options, request, 403, "PATH_NOT_ALLOWED", policy.provider_id, safeLogPath);
        body = new TextEncoder().encode(cleaned.toString());
        headers.set("content-type", "application/x-www-form-urlencoded");
      }
      for (const key of policy.credential_query_keys) upstreamUrl.searchParams.delete(key);
      if (policy.auth.kind === "query") {
        upstreamUrl.searchParams.set(policy.auth.name, secret);
      } else {
        let injected = secret;
        if (policy.auth.encoding === "basic_username") {
          try {
            injected = btoa(`${secret}:`);
          } catch {
            return reject(options, request, 503, "NOT_CONFIGURED", policy.provider_id, safeLogPath);
          }
        }
        headers.set(policy.auth.name, `${policy.auth.prefix}${injected}`);
      }

      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
      let upstream: Response;
      try {
        upstream = await options.upstreamFetch(upstreamUrl, {
          method: request.method,
          headers,
          ...(body ? { body: new TextDecoder().decode(body) } : {}),
          redirect: "manual",
          signal: controller.signal,
        });
      } catch {
        return reject(options, request, 502, "UPSTREAM_ERROR", policy.provider_id, safeLogPath, "upstream_error");
      } finally {
        clearTimeout(timeout);
      }
      if (upstream.status >= 300 && upstream.status < 400) {
        try { await upstream.body?.cancel(); } catch { /* ignored */ }
        return reject(options, request, 502, "UPSTREAM_REDIRECT_DENIED", policy.provider_id, safeLogPath, "upstream_error");
      }
      if (upstream.status < 200 || upstream.status >= 300) {
        try { await upstream.body?.cancel(); } catch { /* ignored */ }
        return reject(options, request, 502, "UPSTREAM_ERROR", policy.provider_id, safeLogPath, "upstream_error");
      }
      const responseBytes = await readCappedResponse(upstream, MAX_RESPONSE_BYTES);
      if (!responseBytes) return reject(options, request, 502, "UPSTREAM_ERROR", policy.provider_id, safeLogPath, "upstream_error");
      let responseText: string;
      try {
        responseText = new TextDecoder("utf-8", { fatal: true }).decode(responseBytes);
      } catch {
        return reject(options, request, 502, "UPSTREAM_ERROR", policy.provider_id, safeLogPath, "upstream_error");
      }
      responseText = redact(responseText, options.env, token);
      const responseHeaders = new Headers({ "cache-control": "no-store" });
      const contentType = upstream.headers.get("content-type");
      if (contentType && SAFE_HEADER.test(contentType) && contentType.length <= 128 && !includesSensitive(contentType, options.env, token)) {
        responseHeaders.set("content-type", contentType);
      }
      logSafe(options, { event: "request", code: "OK", provider_id: policy.provider_id, method: request.method, path: safeLogPath, status: upstream.status }, token);
      if (upstream.status === 204 || upstream.status === 205) return new Response(null, { status: upstream.status, headers: responseHeaders });
      return new Response(responseText, { status: upstream.status, headers: responseHeaders });
    },
  });
}

function bindingSecretEnv(env: DataGatewayWorkerEnvV1): GatewayEnvV1 {
  const secrets: Record<string, string | undefined> = {};
  for (const providerId of ["databento", "massive", "fred", "bea", "eia", "unusual_whales"] as const) {
    const binding = `PROVIDER__${providerId.toUpperCase()}__API_KEY`;
    const value = env[binding];
    secrets[binding] = typeof value === "string" ? value : undefined;
  }
  return Object.freeze(secrets);
}

function runtimeLogger(): { log(entry: GatewayLogEntryV1): void } {
  return { log: (entry) => console.log(JSON.stringify(entry)) };
}

export const workerV1: DataGatewayWorkerV1 = Object.freeze({
  async fetch(request: Request, env: DataGatewayWorkerEnvV1): Promise<Response> {
    try {
      if (typeof env !== "object" || env === null) return errorResponse(503, "NOT_CONFIGURED");
      const hasLicenseWorker = typeof env.LICENSE_WORKER?.fetch === "function";
      const hasPublicKey = typeof env.LICENSE_VERIFY_PUBLIC_KEY_JWK === "string" && env.LICENSE_VERIFY_PUBLIC_KEY_JWK.length > 0;
      if (!hasLicenseWorker && !hasPublicKey) return errorResponse(503, "NOT_CONFIGURED");
      const entitlement = {
        authenticateDeviceBearer: (token: string) => entitlementFromBindings(env, token),
      };
      const rateLimiter = env.RATE_LIMIT === undefined || env.RATE_LIMIT === null
        ? isolateRateLimiter
        : new BoundRateLimiterV1(env.RATE_LIMIT);
      const upstreamFetch: GatewayDependenciesV1["upstreamFetch"] = async (input, init) => fetch(input, init);
      const runtime = createDataGatewayV1({
        env: bindingSecretEnv(env),
        entitlement,
        rateLimiter,
        upstreamFetch,
        logger: runtimeLogger(),
      });
      return await runtime.fetch(request);
    } catch {
      return errorResponse(503, "NOT_CONFIGURED");
    }
  },
});

export default workerV1;
