import {
  canonicalLicenseSnapshotV1,
  evaluateEntitlementV1,
} from "../entitlement/decision.js";
import type {
  EntitlementOutcomeV1,
  EntitlementResultV1,
  LicenseSnapshotV1,
} from "../entitlement/models.js";
import { LicenseDecisionCacheV1 } from "./cache.js";
import { PerLicenseRateLimiterV1 } from "./rate_limit.js";
import { adminApiRoutes } from "../admin_api/routes.js";
import type { AdminApiDependenciesV1 } from "../admin_api/models.js";
import { signupRoutes } from "../signup/routes.js";
import type { SignupDependenciesV1 } from "../signup/models.js";
import { authApiRoutes } from "../auth_api/routes.js";
import type { AuthApiDependenciesV1 } from "../auth_api/routes.js";

const ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
const UINT = /^(0|[1-9][0-9]{0,63})$/;
const ALLOWED_ACTIONS = new Set(["license:read", "auth:introspect"]);
const NS_PER_MS = 1_000_000n;
const POSITIVE_TTL_MS = 60_000;

export type LicenseWorkerActionV1 = "license:read" | "auth:introspect";

/** This record may only be returned by the injected SEC-003 verification adapter. */
export interface TrustedPrincipalV1 {
  readonly schemaVersion: 1;
  readonly principalId: string;
  readonly orgId: string;
  readonly audience: string;
  readonly deviceId: string;
  readonly scopes: readonly string[];
  readonly roles: readonly string[];
}

export interface PrincipalResolverPortV1 {
  /** Verify the presented credential through SEC-003; never infer claims from body/query. */
  resolve(request: Request, signal?: AbortSignal): Promise<TrustedPrincipalV1 | null>;
}

export interface LicenseAuthorizationPortV1 {
  /** Apply the SEC-002 default-deny policy to this already trusted principal. */
  authorize(
    principal: TrustedPrincipalV1,
    action: LicenseWorkerActionV1,
    nowUtcNs: string,
    signal?: AbortSignal,
  ): Promise<boolean>;
}

export interface LicenseReadPortV1 {
  /** Project-scoped read of the current LIC-002 head, projected as a LIC-001 signed snapshot. */
  readCurrent(orgId: string, signal?: AbortSignal): Promise<LicenseSnapshotV1 | null>;
  /** Optional device-bound projection used by production composition. */
  readForDevice?(orgId: string, deviceId: string, signal?: AbortSignal): Promise<LicenseSnapshotV1 | null>;
}

export interface WorkerClockV1 {
  nowMonotonicMs(): number;
  nowUtcNs(): string;
}

export interface BackgroundEligibilityLeaseV1 {
  readonly schemaVersion: 1;
  readonly orgId: string;
  readonly audience: string;
  readonly deviceId: string;
  readonly licenseId: string | null;
  readonly eligible: boolean;
  /** Null revokes eligibility immediately; finite leases fail closed at expiry. */
  readonly expiresAtMonotonicMs: number | null;
  readonly reason: "VERIFIED_ONLINE" | "DENIED" | "UNKNOWN";
}

export interface BackgroundEligibilityPortV1 {
  /** A fake/adapter sink; consumers must treat an expired lease as ineligible. */
  publishLease(lease: BackgroundEligibilityLeaseV1, signal?: AbortSignal): Promise<void>;
}

export type WorkerDeadlineOperationV1 =
  | "principal-resolution" | "authorization" | "introspection-body"
  | "license-read" | "entitlement-evaluation" | "eligibility-publish";

export type WorkerDeadlineOutcomeV1<T> =
  | { readonly status: "COMPLETED"; readonly value: T }
  | { readonly status: "TIMED_OUT" };

/** The runtime adapter must abort the supplied signal when its deadline expires. */
export interface WorkerDeadlinePortV1 {
  run<T>(
    operation: WorkerDeadlineOperationV1,
    timeoutMs: number,
    invoke: (signal: AbortSignal) => Promise<T>,
  ): Promise<WorkerDeadlineOutcomeV1<T>>;
}

export interface LicenseWorkerServerPolicyV1 {
  /** Lowest-tier API request rate, used when the signed snapshot omits the limit. */
  readonly lowestTierApiRateLimitRps: string;
}

export interface LicenseWorkerMetricsPortV1 {
  /** Content-free metric/audit event; must not include identifiers or payload data. */
  recordRatePolicyDefaulted(): void;
}

export interface LicenseWorkerDependenciesV1 {
  readonly principals: PrincipalResolverPortV1;
  readonly authorization: LicenseAuthorizationPortV1;
  readonly licenses: LicenseReadPortV1;
  readonly signingKeys: ReadonlyMap<string, CryptoKey>;
  readonly clock: WorkerClockV1;
  readonly requestIdFactory: () => string;
  readonly cache: LicenseDecisionCacheV1;
  readonly rateLimiter: PerLicenseRateLimiterV1;
  readonly backgroundEligibility: BackgroundEligibilityPortV1;
  readonly serverPolicy: LicenseWorkerServerPolicyV1;
  readonly metrics: LicenseWorkerMetricsPortV1;
  readonly deadlines: WorkerDeadlinePortV1;
  /** Optional additive route set; existing Worker constructions remain unchanged. */
  readonly adminApi?: AdminApiDependenciesV1;
  /** Optional additive checkout/webhook route set; missing dependencies fail closed. */
  readonly signupApi?: SignupDependenciesV1;
  /** Optional role-agnostic desktop session routes; missing ports fail closed. */
  readonly authApi?: AuthApiDependenciesV1;
}

export type LicenseWorkerErrorCodeV1 =
  | "INVALID_REQUEST" | "UNAUTHENTICATED" | "FORBIDDEN" | "LICENSE_REQUIRED"
  | "RATE_LIMITED" | "NOT_FOUND" | "METHOD_NOT_ALLOWED";

export interface LicenseWorkerErrorV1 {
  readonly schema_version: 1;
  readonly code: LicenseWorkerErrorCodeV1;
  readonly request_id: string;
  readonly observed_at_ns: string;
}

export interface LicenseResponseV1 {
  readonly schema_version: 1;
  readonly license: LicenseSnapshotV1;
  readonly observed_at_ns: string;
  readonly request_id: string;
  readonly entitlement_state: EntitlementOutcomeV1;
}

export interface IntrospectionResponseV1 extends LicenseResponseV1 {
  readonly active: true;
  readonly org_id: string;
  readonly subject_id: string;
  readonly scopes: readonly string[];
}

export interface LicenseWorkerV1 {
  fetch(request: Request): Promise<Response>;
}

function safeId(value: unknown): value is string {
  return typeof value === "string" && ID.test(value);
}

function safeUtcNs(value: unknown): value is string {
  return typeof value === "string" && value.length <= 64 && UINT.test(value);
}

function plainRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const keys = Reflect.ownKeys(value);
  return keys.length === expected.length && keys.every(
    (key) => typeof key === "string" && expected.includes(key),
  );
}

function snapshotMap(value: unknown, isValue: (item: unknown) => boolean): Readonly<Record<string, unknown>> | null {
  try {
    if (!plainRecord(value) || Object.getOwnPropertySymbols(value).length !== 0) return null;
    const keys = Object.keys(value);
    if (keys.length > 256 || keys.some((key) => key.length === 0 || key.length > 256
        || /[\u0000-\u001f\u007f]/.test(key))) return null;
    const copy: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
    for (const key of keys) {
      if (!isValue(value[key])) return null;
      copy[key] = value[key];
    }
    return Object.freeze(copy);
  } catch { return null; }
}

function snapshotCopy(value: unknown): LicenseSnapshotV1 | null {
  try {
    if (!plainRecord(value) || !exactKeys(value, [
      "schemaVersion", "orgId", "licenseId", "subscriptionRevision", "status",
      "termStartUtcNs", "termEndUtcNs", "issuedAtUtcNs", "lastOnlineVerifiedUtcNs",
      "features", "limits", "audience", "deviceId", "signingKeyId", "signature",
    ])) return null;
    const features = snapshotMap(value.features, (item) => typeof item === "boolean");
    const limits = snapshotMap(value.limits,
      (item) => typeof item === "string" && item.length <= 64);
    if (!features || !limits || !plainRecord(value.signature)
        || !exactKeys(value.signature, ["algorithm", "value"])) return null;
    return Object.freeze({
      schemaVersion: value.schemaVersion as 1,
      orgId: value.orgId as string,
      licenseId: value.licenseId as string,
      subscriptionRevision: value.subscriptionRevision as string,
      status: value.status as LicenseSnapshotV1["status"],
      termStartUtcNs: value.termStartUtcNs as string,
      termEndUtcNs: value.termEndUtcNs as string,
      issuedAtUtcNs: value.issuedAtUtcNs as string,
      lastOnlineVerifiedUtcNs: value.lastOnlineVerifiedUtcNs as string,
      features: features as Readonly<Record<string, boolean>>,
      limits: limits as Readonly<Record<string, string>>,
      audience: value.audience as string,
      deviceId: value.deviceId as string,
      signingKeyId: value.signingKeyId as string,
      signature: Object.freeze({
        algorithm: value.signature.algorithm as "ECDSA_P256_SHA256",
        value: value.signature.value as string,
      }),
    });
  } catch { return null; }
}

function principalCopy(value: unknown): TrustedPrincipalV1 | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const candidate = value as Partial<TrustedPrincipalV1>;
  if (candidate.schemaVersion !== 1 || !safeId(candidate.principalId)
      || !safeId(candidate.orgId) || !safeId(candidate.audience)
      || !safeId(candidate.deviceId) || !Array.isArray(candidate.scopes)
      || !Array.isArray(candidate.roles) || candidate.scopes.length > 128
      || candidate.roles.length > 64
      || candidate.scopes.some((item) => !safeId(item))
      || candidate.roles.some((item) => !safeId(item))) return null;
  return Object.freeze({
    schemaVersion: 1,
    principalId: candidate.principalId,
    orgId: candidate.orgId,
    audience: candidate.audience,
    deviceId: candidate.deviceId,
    scopes: Object.freeze([...candidate.scopes]),
    roles: Object.freeze([...candidate.roles]),
  });
}

function toArrayBuffer(value: Uint8Array): ArrayBuffer {
  const copy = new ArrayBuffer(value.byteLength);
  new Uint8Array(copy).set(value);
  return copy;
}

/** Fingerprints all canonical signed fields and the signature before cache lookup. */
export async function licenseSnapshotFingerprintV1(
  snapshot: LicenseSnapshotV1,
): Promise<string | null> {
  try {
    const payload = canonicalLicenseSnapshotV1(snapshot);
    const signature = new TextEncoder().encode(snapshot.signature.value);
    const input = new Uint8Array(payload.byteLength + signature.byteLength);
    input.set(payload, 0);
    input.set(signature, payload.byteLength);
    const digest = new Uint8Array(await globalThis.crypto.subtle.digest(
      "SHA-256", toArrayBuffer(input),
    ));
    return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
  } catch {
    return null;
  }
}

function response(
  body: LicenseWorkerErrorV1 | LicenseResponseV1 | IntrospectionResponseV1,
  status: number,
  retryAfterSeconds?: number,
): Response {
  const headers = new Headers({ "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" });
  if (retryAfterSeconds !== undefined) headers.set("Retry-After", String(retryAfterSeconds));
  return new Response(JSON.stringify(body), { status, headers });
}

function errorResponse(
  code: LicenseWorkerErrorCodeV1,
  requestId: string,
  observedAtUtcNs: string,
  status: number,
  retryAfterSeconds?: number,
): Response {
  return response(Object.freeze({
    schema_version: 1,
    code,
    request_id: requestId,
    observed_at_ns: observedAtUtcNs,
  }), status, retryAfterSeconds);
}

function cacheScope(principal: TrustedPrincipalV1): string {
  return JSON.stringify([principal.orgId, principal.audience, principal.deviceId]);
}

async function publishIneligible(
  port: BackgroundEligibilityPortV1,
  deadlines: WorkerDeadlinePortV1,
  principal: TrustedPrincipalV1,
  licenseId: string | null,
  reason: "DENIED" | "UNKNOWN",
): Promise<PortRunResultV1<void>> {
  return runWithDeadline(deadlines, "eligibility-publish", (signal) =>
    port.publishLease(Object.freeze({
      schemaVersion: 1,
      orgId: principal.orgId,
      audience: principal.audience,
      deviceId: principal.deviceId,
      licenseId: licenseId !== null && safeId(licenseId) ? licenseId : null,
      eligible: false,
      expiresAtMonotonicMs: null,
      reason,
    }), signal));
}

function positive(result: EntitlementResultV1, nowUtcNs: string): boolean {
  if (result.decision.outcome !== "VERIFIED_ONLINE"
      || result.decision.authorizesGatedEffects !== true
      || result.decision.expiresAtUtcNs === null) return false;
  try { return BigInt(nowUtcNs) < BigInt(result.decision.expiresAtUtcNs); }
  catch { return false; }
}

function ineligibilityReason(result: EntitlementResultV1): "DENIED" | "UNKNOWN" {
  return result.decision.reason === "LICENSE_INACTIVE"
      || result.decision.reason === "TERM_EXPIRED" ? "DENIED" : "UNKNOWN";
}

const MAX_INTROSPECTION_BODY_BYTES = 1024;
export const LICENSE_WORKER_PORT_DEADLINE_MS_V1 = 5_000;
export const LICENSE_WORKER_SCOPE_QUEUE_CAP_V1 = 32;

async function parseEmptyIntrospectionBody(request: Request, signal: AbortSignal): Promise<boolean> {
  let reader: ReadableStreamDefaultReader<Uint8Array> | null = null;
  let abortRead: (() => void) | null = null;
  try {
    reader = request.body?.getReader() ?? null;
    if (!reader) return true;
    abortRead = () => { if (reader) void reader.cancel().catch(() => undefined); };
    signal.addEventListener("abort", abortRead, { once: true });
    const chunks: Uint8Array[] = [];
    let total = 0;
    while (true) {
      const item = await reader.read();
      if (item.done) break;
      total += item.value.byteLength;
      if (total > MAX_INTROSPECTION_BODY_BYTES) {
        await reader.cancel();
        return false;
      }
      chunks.push(item.value);
    }
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    const body = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    if (bytes.byteLength === 0) return true;
    if (!request.headers.get("content-type")?.toLowerCase().startsWith("application/json")) return false;
    const parsed: unknown = JSON.parse(body);
    return parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)
      && Object.keys(parsed).length === 0;
  } catch { return false; }
  finally { if (abortRead) signal.removeEventListener("abort", abortRead); }
}

interface SampledWorkerTimeV1 {
  readonly monotonicMs: number;
  readonly wallUtcNs: string;
}

function sampleWallUtcNs(clock: WorkerClockV1): string | null {
  try {
    const value = clock.nowUtcNs();
    return safeUtcNs(value) ? value : null;
  } catch { return null; }
}

function sampleWorkerTime(clock: WorkerClockV1): SampledWorkerTimeV1 | null {
  try {
    const wallUtcNs = clock.nowUtcNs();
    const monotonicMs = clock.nowMonotonicMs();
    if (!safeUtcNs(wallUtcNs) || !Number.isSafeInteger(monotonicMs) || monotonicMs < 0) return null;
    return Object.freeze({ monotonicMs, wallUtcNs });
  } catch { return null; }
}

/** Process-wide serialization prevents stale handles from entering LIC-001 out of clock order. */
const scopeEvaluationTails = new Map<string, Promise<void>>();
const scopeEvaluationQueueDepth = new Map<string, number>();
const scopeHighestEvaluatedRevision = new Map<string, bigint>();
const MAX_HIGH_WATER_SCOPES = 4096;

async function unverifiedScopeRateLimitKeyV1(scope: string): Promise<string | null> {
  try {
    const input = new TextEncoder().encode(`LIC004_SCOPE_RATE_LIMIT_V1\0${scope}`);
    const digest = new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", toArrayBuffer(input)));
    return `scope-v1-${Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
  } catch { return null; }
}

type ScopeLockResultV1<T> =
  | { readonly status: "COMPLETED"; readonly value: T }
  | { readonly status: "QUEUE_FULL" };

type LockedEvaluationResultV1 =
  | { readonly status: "RESPONSE"; readonly response: Response }
  | {
    readonly status: "RATE_CHECK";
    readonly snapshot: LicenseSnapshotV1;
    readonly evaluated: EntitlementResultV1;
    readonly authorizes: boolean;
    readonly verifiedSnapshot: boolean;
    readonly limiterKey: string;
    readonly rate: string;
    readonly observedAtUtcNs: string;
    readonly principal: TrustedPrincipalV1;
    readonly isLicense: boolean;
  };

async function withScopeEvaluationLock<T>(scope: string, operation: () => Promise<T>): Promise<ScopeLockResultV1<T>> {
  const depth = scopeEvaluationQueueDepth.get(scope) ?? 0;
  if (depth >= LICENSE_WORKER_SCOPE_QUEUE_CAP_V1) return { status: "QUEUE_FULL" };
  scopeEvaluationQueueDepth.set(scope, depth + 1);
  const predecessor = scopeEvaluationTails.get(scope) ?? Promise.resolve();
  let release = (): void => {};
  const gate = new Promise<void>((resolve) => { release = resolve; });
  const tail = predecessor.then(() => gate);
  scopeEvaluationTails.set(scope, tail);
  try {
    await predecessor;
    return { status: "COMPLETED", value: await operation() };
  }
  finally {
    release();
    if (scopeEvaluationTails.get(scope) === tail) scopeEvaluationTails.delete(scope);
    const remaining = (scopeEvaluationQueueDepth.get(scope) ?? 1) - 1;
    if (remaining === 0) scopeEvaluationQueueDepth.delete(scope);
    else scopeEvaluationQueueDepth.set(scope, remaining);
  }
}

type PortRunResultV1<T> =
  | { readonly status: "COMPLETED"; readonly value: T }
  | { readonly status: "TIMED_OUT" }
  | { readonly status: "FAILED" };

async function runWithDeadline<T>(
  deadlines: WorkerDeadlinePortV1,
  operation: WorkerDeadlineOperationV1,
  invoke: (signal: AbortSignal) => Promise<T>,
): Promise<PortRunResultV1<T>> {
  try {
    const result = await deadlines.run(operation, LICENSE_WORKER_PORT_DEADLINE_MS_V1, invoke);
    return result.status === "COMPLETED"
      ? { status: "COMPLETED", value: result.value }
      : { status: "TIMED_OUT" };
  } catch {
    return { status: "FAILED" };
  }
}

/**
 * Construct the JSON V1 worker boundary. All network, Neon, trust, authorization,
 * time, ID and rate-limit behavior is injected so unit/acceptance tests stay fake-only.
 */
export function createLicenseWorkerV1(dependencies: LicenseWorkerDependenciesV1): LicenseWorkerV1 {
  const policyCheck = new PerLicenseRateLimiterV1().check(
    "worker-policy-validation", dependencies.serverPolicy.lowestTierApiRateLimitRps, 0,
  );
  if (policyCheck.outcome !== "ALLOW") throw new TypeError("invalid worker policy");
  return Object.freeze({
    async fetch(request: Request): Promise<Response> {
      let requestId = "request-unavailable";
      try {
        const suppliedId = dependencies.requestIdFactory();
        if (safeId(suppliedId)) requestId = suppliedId;
      } catch { /* A safe fixed fallback keeps the public envelope content-free. */ }
      let observedAtUtcNs = "0";
      const currentObservedAt = (): string => sampleWallUtcNs(dependencies.clock) ?? observedAtUtcNs;
      let url: URL;
      try { url = new URL(request.url); }
      catch { return errorResponse("INVALID_REQUEST", requestId, currentObservedAt(), 400); }
      // Admin owns a path prefix: resource IDs and session subroutes are matched
      // by adminApiRoutes. The LIC-004 license route and unimplemented admin
      // webhook path stay on the core 404/license dispatch. Signup and auth are
      // exact route surfaces; unknown nested paths remain 404s.
      const delegated = /^\/v1\/(?:(admin)(?!\/(?:license|webhook)(?:\/|$))(?:\/|$)|(signup\/(?:checkout|webhook|success|cancel))$|(auth\/session(?:\/totp\/(?:enroll|confirm))?)$)/.exec(url.pathname);
      if (delegated?.[3]) {
        return (await authApiRoutes(request, dependencies.authApi))
          ?? errorResponse("NOT_FOUND", requestId, currentObservedAt(), 404);
      }
      if (delegated?.[2]) {
        return (await signupRoutes(request, dependencies.signupApi))
          ?? errorResponse("NOT_FOUND", requestId, currentObservedAt(), 404);
      }
      if (delegated?.[1]) {
        return adminApiRoutes(request, dependencies.adminApi);
      }
      const isLicense = url.pathname === "/v1/admin/license";
      const isIntrospect = url.pathname === "/v1/auth/introspect";
      if (!isLicense && !isIntrospect) {
        return errorResponse("NOT_FOUND", requestId, currentObservedAt(), 404);
      }
      if ((isLicense && request.method !== "GET") || (isIntrospect && request.method !== "POST")) {
        return errorResponse("METHOD_NOT_ALLOWED", requestId, currentObservedAt(), 405);
      }

      const resolvedPrincipal = await runWithDeadline(
        dependencies.deadlines,
        "principal-resolution",
        (signal) => dependencies.principals.resolve(request, signal),
      );
      const principal = resolvedPrincipal.status === "COMPLETED"
        ? principalCopy(resolvedPrincipal.value) : null;
      if (!principal) return errorResponse("UNAUTHENTICATED", requestId, currentObservedAt(), 401);
      const action: LicenseWorkerActionV1 = isLicense ? "license:read" : "auth:introspect";
      const scope = cacheScope(principal);
      const authorizationTime = sampleWallUtcNs(dependencies.clock);
      if (authorizationTime === null) {
        return errorResponse("INVALID_REQUEST", requestId, observedAtUtcNs, 400);
      }
      observedAtUtcNs = authorizationTime;
      const authorization = await runWithDeadline(
        dependencies.deadlines,
        "authorization",
        (signal) => dependencies.authorization.authorize(
          principal, action, authorizationTime, signal,
        ),
      );
      if (authorization.status === "COMPLETED" && !authorization.value) {
        // A 403 concerns this principal, not the shared org/audience/device lease.
        return errorResponse("FORBIDDEN", requestId, observedAtUtcNs, 403);
      }
      if (authorization.status !== "COMPLETED") {
        const uncertain = await withScopeEvaluationLock(scope, async () => {
          const sampled = sampleWorkerTime(dependencies.clock);
          if (sampled) {
            observedAtUtcNs = sampled.wallUtcNs;
            await publishIneligible(
              dependencies.backgroundEligibility, dependencies.deadlines, principal,
              null, "UNKNOWN",
            );
          }
          return errorResponse("FORBIDDEN", requestId, observedAtUtcNs, 403);
        });
        if (uncertain.status === "QUEUE_FULL") {
          return errorResponse("RATE_LIMITED", requestId, currentObservedAt(), 429, 1);
        }
        return uncertain.value;
      }

      if (isIntrospect) {
        const body = await runWithDeadline(
          dependencies.deadlines,
          "introspection-body",
          (signal) => parseEmptyIntrospectionBody(request, signal),
        );
        if (body.status !== "COMPLETED" || !body.value) {
          return errorResponse("INVALID_REQUEST", requestId, observedAtUtcNs, 400);
        }
      }

      let snapshot: LicenseSnapshotV1 | null = null;
      let readStatus: PortRunResultV1<LicenseSnapshotV1 | null>;
      const source = await runWithDeadline(
        dependencies.deadlines,
        "license-read",
        (signal) => dependencies.licenses.readForDevice
          ? dependencies.licenses.readForDevice(principal.orgId, principal.deviceId, signal)
          : dependencies.licenses.readCurrent(principal.orgId, signal),
      );
      if (source.status === "TIMED_OUT") {
        // A timeout leaves the existing lease unchanged and cannot hold the scope lock.
        return errorResponse("LICENSE_REQUIRED", requestId, observedAtUtcNs, 402);
      }
      readStatus = source.status === "COMPLETED"
        ? { status: "COMPLETED", value: snapshotCopy(source.value) }
        : { status: "FAILED" };
      snapshot = readStatus.status === "COMPLETED" ? readStatus.value : null;

      let fingerprint: string | null = null;
      if (snapshot && snapshot.orgId === principal.orgId) {
        fingerprint = await licenseSnapshotFingerprintV1(snapshot);
      }

      const lockResult = await withScopeEvaluationLock(scope, async (): Promise<LockedEvaluationResultV1> => {
        let sampled = sampleWorkerTime(dependencies.clock);
        if (!sampled) {
          return { status: "RESPONSE", response: errorResponse("LICENSE_REQUIRED", requestId, observedAtUtcNs, 402) };
        }
        observedAtUtcNs = sampled.wallUtcNs;

        if (readStatus.status !== "COMPLETED") {
          await publishIneligible(
            dependencies.backgroundEligibility, dependencies.deadlines, principal,
            null, "UNKNOWN",
          );
          return { status: "RESPONSE", response: errorResponse("LICENSE_REQUIRED", requestId, observedAtUtcNs, 402) };
        }
        if (!snapshot || snapshot.orgId !== principal.orgId || fingerprint === null) {
          dependencies.cache.invalidate(scope);
          await publishIneligible(
            dependencies.backgroundEligibility, dependencies.deadlines, principal,
            null, "UNKNOWN",
          );
          return { status: "RESPONSE", response: errorResponse("LICENSE_REQUIRED", requestId, observedAtUtcNs, 402) };
        }

        const evaluatedHighWater = scopeHighestEvaluatedRevision.get(scope);
        if (evaluatedHighWater !== undefined
            && BigInt(snapshot.subscriptionRevision) < evaluatedHighWater) {
          const refreshed = await runWithDeadline(
            dependencies.deadlines,
            "license-read",
            (signal) => dependencies.licenses.readForDevice
              ? dependencies.licenses.readForDevice(principal.orgId, principal.deviceId, signal)
              : dependencies.licenses.readCurrent(principal.orgId, signal),
          );
          const refreshedSnapshot = refreshed.status === "COMPLETED"
            ? snapshotCopy(refreshed.value) : null;
          const refreshedFingerprint = refreshedSnapshot
            && refreshedSnapshot.orgId === principal.orgId
            ? await licenseSnapshotFingerprintV1(refreshedSnapshot) : null;
          if (refreshedSnapshot && refreshedFingerprint !== null
              && BigInt(refreshedSnapshot.subscriptionRevision) >= evaluatedHighWater) {
            snapshot = refreshedSnapshot;
            fingerprint = refreshedFingerprint;
            // The reread is an awaited port. Resample both clocks immediately
            // before cache access or LIC-001 evaluation.
            sampled = sampleWorkerTime(dependencies.clock);
            if (!sampled) {
              return { status: "RESPONSE", response: errorResponse("LICENSE_REQUIRED", requestId, observedAtUtcNs, 402) };
            }
            observedAtUtcNs = sampled.wallUtcNs;
            if (BigInt(refreshedSnapshot.subscriptionRevision) === evaluatedHighWater) {
              const latest = dependencies.cache.getLatest(scope, sampled.monotonicMs);
              if (latest?.revision === evaluatedHighWater.toString() && latest.snapshot) {
                snapshot = latest.snapshot;
                fingerprint = latest.snapshotFingerprint;
                const evaluated = latest.result;
                const authorizes = positive(evaluated, observedAtUtcNs);
                const verifiedSnapshot = new Set([
                  "ONLINE_ACTIVE", "POSITIVE_CACHE", "LICENSE_INACTIVE", "BINDING_MISMATCH",
                  "REVISION_ROLLBACK", "TERM_INVALID", "TERM_EXPIRED", "ONLINE_ANCHOR_STALE",
                ]).has(evaluated.decision.reason);
                let rate = snapshot.limits.api_rate_limit_rps;
                let limiterKey = snapshot.licenseId;
                if (!verifiedSnapshot || rate === undefined) {
                  rate = dependencies.serverPolicy.lowestTierApiRateLimitRps;
                  if (!verifiedSnapshot) {
                    const fallbackKey = await unverifiedScopeRateLimitKeyV1(scope);
                    if (!fallbackKey) {
                      return { status: "RESPONSE", response: errorResponse("LICENSE_REQUIRED", requestId, observedAtUtcNs, 402) };
                    }
                    limiterKey = fallbackKey;
                  }
                  try { dependencies.metrics.recordRatePolicyDefaulted(); }
                  catch { /* Telemetry failure cannot change entitlement or lease state. */ }
                }
                return {
                  status: "RATE_CHECK", snapshot, evaluated, authorizes, verifiedSnapshot,
                  limiterKey, rate, observedAtUtcNs, principal, isLicense,
                };
              }
            }
          } else {
            // A stale read must never reach LIC-001 after a newer revision was
            // observed. Reuse only the still-live high-water decision, without
            // publishing a lease or changing authority state.
            const latest = dependencies.cache.getLatest(scope, sampled.monotonicMs);
            if (!latest || latest.revision !== evaluatedHighWater.toString() || !latest.snapshot) {
              return { status: "RESPONSE", response: errorResponse("LICENSE_REQUIRED", requestId, observedAtUtcNs, 402) };
            }
            snapshot = latest.snapshot;
            fingerprint = latest.snapshotFingerprint;
            const evaluated = latest.result;
            const authorizes = positive(evaluated, observedAtUtcNs);
            const verifiedSnapshot = new Set([
              "ONLINE_ACTIVE", "POSITIVE_CACHE", "LICENSE_INACTIVE", "BINDING_MISMATCH",
              "REVISION_ROLLBACK", "TERM_INVALID", "TERM_EXPIRED", "ONLINE_ANCHOR_STALE",
            ]).has(evaluated.decision.reason);
            let rate = snapshot.limits.api_rate_limit_rps;
            let limiterKey = snapshot.licenseId;
            if (!verifiedSnapshot || rate === undefined) {
              rate = dependencies.serverPolicy.lowestTierApiRateLimitRps;
              if (!verifiedSnapshot) {
                const fallbackKey = await unverifiedScopeRateLimitKeyV1(scope);
                if (!fallbackKey) {
                  return { status: "RESPONSE", response: errorResponse("LICENSE_REQUIRED", requestId, observedAtUtcNs, 402) };
                }
                limiterKey = fallbackKey;
              }
              try { dependencies.metrics.recordRatePolicyDefaulted(); }
              catch { /* Telemetry failure cannot change entitlement or lease state. */ }
            }
            return {
              status: "RATE_CHECK", snapshot, evaluated, authorizes, verifiedSnapshot,
              limiterKey, rate, observedAtUtcNs, principal, isLicense,
            };
          }
        }

        const cached = dependencies.cache.get(
          scope, snapshot.subscriptionRevision, fingerprint, sampled.monotonicMs,
        );
        let evaluated: EntitlementResultV1;
        let reserved = false;
        try {
          if (cached?.decision.authorizesGatedEffects === true) {
            // This bounded local Web Crypto decision must complete before the
            // scope lock releases; unlike injected I/O ports it cannot be aborted.
            evaluated = await evaluateEntitlementV1({
              mode: "OFFLINE",
              state: cached.state,
              expectedOrgId: principal.orgId,
              expectedAudience: principal.audience,
              expectedDeviceId: principal.deviceId,
              signingKeys: dependencies.signingKeys,
              nowMonotonicMs: sampled.monotonicMs,
              nowWallUtcNs: sampled.wallUtcNs,
            });
          } else if (cached) {
            evaluated = cached;
          } else {
            if (evaluatedHighWater === undefined && scopeHighestEvaluatedRevision.size >= MAX_HIGH_WATER_SCOPES) {
              await publishIneligible(
                dependencies.backgroundEligibility, dependencies.deadlines, principal,
                snapshot.licenseId, "UNKNOWN",
              );
              return { status: "RESPONSE", response: errorResponse("LICENSE_REQUIRED", requestId, observedAtUtcNs, 402) };
            }
            reserved = dependencies.cache.reserve(scope, sampled.monotonicMs);
            if (!reserved) {
              await publishIneligible(
                dependencies.backgroundEligibility, dependencies.deadlines, principal,
                snapshot.licenseId, "UNKNOWN",
              );
              return { status: "RESPONSE", response: errorResponse("LICENSE_REQUIRED", requestId, observedAtUtcNs, 402) };
            }
            evaluated = await evaluateEntitlementV1({
              mode: "ONLINE",
              snapshot,
              expectedOrgId: principal.orgId,
              expectedAudience: principal.audience,
              expectedDeviceId: principal.deviceId,
              signingKeys: dependencies.signingKeys,
              nowMonotonicMs: sampled.monotonicMs,
              nowWallUtcNs: sampled.wallUtcNs,
            });
            if (!dependencies.cache.put(
              scope, snapshot.subscriptionRevision, fingerprint, evaluated, sampled.monotonicMs, snapshot,
            )) {
              dependencies.cache.releaseReservation(scope);
              reserved = false;
              await publishIneligible(
                dependencies.backgroundEligibility, dependencies.deadlines, principal,
                snapshot.licenseId, "UNKNOWN",
              );
              return { status: "RESPONSE", response: errorResponse("LICENSE_REQUIRED", requestId, observedAtUtcNs, 402) };
            }
            reserved = false;
            if (new Set([
              "ONLINE_ACTIVE", "LICENSE_INACTIVE", "TERM_INVALID", "TERM_EXPIRED", "ONLINE_ANCHOR_STALE",
            ]).has(evaluated.decision.reason)) {
              const revision = BigInt(snapshot.subscriptionRevision);
              const current = scopeHighestEvaluatedRevision.get(scope);
              if (current === undefined || revision > current) scopeHighestEvaluatedRevision.set(scope, revision);
            }
          }
        } catch {
          if (reserved) dependencies.cache.releaseReservation(scope);
          return { status: "RESPONSE", response: errorResponse("LICENSE_REQUIRED", requestId, observedAtUtcNs, 402) };
        }

        const authorizes = positive(evaluated, observedAtUtcNs);
        const verifiedSnapshot = new Set([
          "ONLINE_ACTIVE", "POSITIVE_CACHE", "LICENSE_INACTIVE", "BINDING_MISMATCH",
          "REVISION_ROLLBACK", "TERM_INVALID", "TERM_EXPIRED", "ONLINE_ANCHOR_STALE",
        ]).has(evaluated.decision.reason);

        if (!authorizes) {
          const publish = await publishIneligible(
            dependencies.backgroundEligibility, dependencies.deadlines, principal,
            verifiedSnapshot ? snapshot.licenseId : null,
            ineligibilityReason(evaluated),
          );
          if (publish.status !== "COMPLETED") {
            return { status: "RESPONSE", response: errorResponse("LICENSE_REQUIRED", requestId, observedAtUtcNs, 402) };
          }
        } else {
          const cacheExpiry = dependencies.cache.expiresAtMonotonicMs(
            scope, snapshot.subscriptionRevision, fingerprint,
          );
          let leaseExpiry: number | null = null;
          try {
            const termRemainingMs = (BigInt(snapshot.termEndUtcNs) - BigInt(observedAtUtcNs)) / NS_PER_MS;
            if (termRemainingMs > 0n && cacheExpiry !== null) {
              const maxTermRemaining = termRemainingMs > BigInt(POSITIVE_TTL_MS)
                ? BigInt(POSITIVE_TTL_MS) : termRemainingMs;
              const termExpiry = sampled.monotonicMs + Number(maxTermRemaining);
              leaseExpiry = Math.min(cacheExpiry, sampled.monotonicMs + POSITIVE_TTL_MS, termExpiry);
            }
          } catch { leaseExpiry = null; }
          if (leaseExpiry === null || leaseExpiry <= sampled.monotonicMs
              || !Number.isSafeInteger(leaseExpiry)) {
            return { status: "RESPONSE", response: errorResponse("LICENSE_REQUIRED", requestId, observedAtUtcNs, 402) };
          }
          const publish = await runWithDeadline(
            dependencies.deadlines,
            "eligibility-publish",
            (signal) => dependencies.backgroundEligibility.publishLease(Object.freeze({
              schemaVersion: 1,
              orgId: principal.orgId,
              audience: principal.audience,
              deviceId: principal.deviceId,
              licenseId: snapshot!.licenseId,
              eligible: true,
              expiresAtMonotonicMs: leaseExpiry,
              reason: "VERIFIED_ONLINE",
            }), signal),
          );
          if (publish.status !== "COMPLETED") {
            return { status: "RESPONSE", response: errorResponse("LICENSE_REQUIRED", requestId, observedAtUtcNs, 402) };
          }
        }

        let rate = snapshot.limits.api_rate_limit_rps;
        let limiterKey = snapshot.licenseId;
        if (!verifiedSnapshot || rate === undefined) {
          rate = dependencies.serverPolicy.lowestTierApiRateLimitRps;
          if (!verifiedSnapshot) {
            const fallbackKey = await unverifiedScopeRateLimitKeyV1(scope);
            if (!fallbackKey) {
              return { status: "RESPONSE", response: errorResponse("LICENSE_REQUIRED", requestId, observedAtUtcNs, 402) };
            }
            limiterKey = fallbackKey;
          }
          try { dependencies.metrics.recordRatePolicyDefaulted(); }
          catch { /* Telemetry failure cannot change entitlement or lease state. */ }
        }
        return {
          status: "RATE_CHECK",
          snapshot,
          evaluated,
          authorizes,
          verifiedSnapshot,
          limiterKey,
          rate,
          observedAtUtcNs,
          principal,
          isLicense,
        };
      });
      if (lockResult.status === "QUEUE_FULL") {
        return errorResponse("RATE_LIMITED", requestId, currentObservedAt(), 429, 1);
      }
      if (lockResult.value.status === "RESPONSE") return lockResult.value.response;
      const locked = lockResult.value;
      const rateDecision = dependencies.rateLimiter.checkWithClock(
        locked.limiterKey, locked.rate, dependencies.clock,
      );
      if (rateDecision.outcome === "RATE_LIMITED") {
        return errorResponse("RATE_LIMITED", requestId, locked.observedAtUtcNs, 429,
          rateDecision.retryAfterSeconds ?? 1);
      }
      if (rateDecision.outcome !== "ALLOW" || !locked.authorizes) {
        return errorResponse("LICENSE_REQUIRED", requestId, locked.observedAtUtcNs, 402);
      }
      const common = Object.freeze({
        schema_version: 1 as const,
        license: locked.snapshot,
        observed_at_ns: locked.observedAtUtcNs,
        request_id: requestId,
        entitlement_state: locked.evaluated.decision.outcome,
      });
      if (locked.isLicense) return response(common, 200);
      return response(Object.freeze({
        ...common,
        active: true as const,
        org_id: locked.principal.orgId,
        subject_id: locked.principal.principalId,
        scopes: locked.principal.scopes,
      }), 200);
    },
  });
}
