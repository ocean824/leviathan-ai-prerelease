import { describe, expect, it } from "vitest";
import {
  canonicalLicenseSnapshotV1,
  createEntitlementStateV1,
} from "../src/entitlement/decision.js";
import type {
  EntitlementResultV1,
  LicenseSnapshotV1,
} from "../src/entitlement/models.js";
import {
  createLicenseWorkerV1,
  type BackgroundEligibilityLeaseV1,
  type LicenseWorkerDependenciesV1,
  type WorkerDeadlineOperationV1,
  LICENSE_WORKER_SCOPE_QUEUE_CAP_V1,
  type TrustedPrincipalV1,
} from "../src/worker/handler.js";
import { LicenseDecisionCacheV1 } from "../src/worker/cache.js";
import { PerLicenseRateLimiterV1 } from "../src/worker/rate_limit.js";

const BASE_NS = 1_800_000_000_000_000_000n;
const NS_PER_MS = 1_000_000n;
const NS_PER_SECOND = 1_000_000_000n;

type Harness = ReturnType<typeof makeHarness>;

function deferred<T = void>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}

function ownBuffer(bytes: Uint8Array): ArrayBuffer {
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  return buffer;
}

async function createKeyPair() {
  return globalThis.crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
}

async function signedSnapshot(
  privateKey: CryptoKey,
  changes: Partial<LicenseSnapshotV1> = {},
): Promise<LicenseSnapshotV1> {
  const defaults: LicenseSnapshotV1 = {
    schemaVersion: 1,
    orgId: `org-lic004-test-${globalThis.crypto.randomUUID()}`,
    licenseId: "license-lic004-test",
    subscriptionRevision: "1",
    status: "ACTIVE",
    termStartUtcNs: (BASE_NS - 10n * NS_PER_SECOND).toString(),
    termEndUtcNs: (BASE_NS + 3_600n * NS_PER_SECOND).toString(),
    issuedAtUtcNs: (BASE_NS - 2n * NS_PER_SECOND).toString(),
    lastOnlineVerifiedUtcNs: BASE_NS.toString(),
    features: { decisioning: true, background_jobs: true },
    limits: { seats: "3", api_rate_limit_rps: "1000" },
    audience: "leviathan-desktop",
    deviceId: "lic004-synthetic-device",
    signingKeyId: "lic004-test-key",
    signature: { algorithm: "ECDSA_P256_SHA256", value: "" },
  };
  const unsigned: LicenseSnapshotV1 = { ...defaults, ...changes, signature: defaults.signature };
  const signatureBytes = await globalThis.crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    privateKey,
    ownBuffer(canonicalLicenseSnapshotV1(unsigned)),
  );
  const signature = btoa(String.fromCharCode(...new Uint8Array(signatureBytes)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  return {
    ...unsigned,
    signature: { algorithm: "ECDSA_P256_SHA256", value: signature },
  };
}

function principal(orgId: string): TrustedPrincipalV1 {
  return {
    schemaVersion: 1,
    principalId: `principal-${orgId}`,
    orgId,
    audience: "leviathan-desktop",
    deviceId: "lic004-synthetic-device",
    scopes: ["license:read", "auth:introspect"],
    roles: ["Owner"],
  };
}

function scopedPrincipal(
  orgId: string,
  audience: string,
  deviceId: string,
): TrustedPrincipalV1 {
  return {
    ...principal(orgId),
    audience,
    deviceId,
  };
}

function makeHarness(
  initialSnapshots: LicenseSnapshotV1[],
  signingKey: CryptoKey,
  options: {
    principal?: TrustedPrincipalV1 | null;
    authorized?: boolean;
    principalResolveDelayMs?: number;
    authorizationDelayMs?: number;
    readDelayMs?: number;
    monotonicAdvanceMs?: number;
    lowestTierApiRateLimitRps?: string;
    deadlineTimeouts?: Partial<Record<WorkerDeadlineOperationV1, number>>;
    hangReadCalls?: number;
    publishGate?: { deviceId: string; entered: () => void; release: Promise<void> };
    readFirstGate?: { entered: () => void; release: Promise<void> };
    monotonicClock?: () => number;
    rateLimiter?: PerLicenseRateLimiterV1;
  } = {},
) {
  let monotonicMs = 10_000;
  let nowNs = BASE_NS;
  let currentPrincipal = options.principal === undefined
    ? principal(initialSnapshots[0]?.orgId ?? "org-lic004-test")
    : options.principal;
  let authorized = options.authorized ?? true;
  let authorizationError: Error | null = null;
  let readError: Error | null = null;
  const snapshots = new Map(initialSnapshots.map((snapshot) => [snapshot.orgId, snapshot]));
  const readOrgs: string[] = [];
  const authorizationCalls: Array<{ orgId: string; action: string }> = [];
  const leases: BackgroundEligibilityLeaseV1[] = [];
  const readSignals: AbortSignal[] = [];
  let requestSequence = 0;
  let principalResolutionCount = 0;
  let readCount = 0;
  let hangReadCalls = options.hangReadCalls ?? 0;
  let ratePolicyDefaultedCount = 0;
  const principalCountWaiters: Array<{ count: number; resolve: () => void }> = [];
  const deadlineTimeouts = new Map<WorkerDeadlineOperationV1, number>(
    Object.entries(options.deadlineTimeouts ?? {}) as Array<[WorkerDeadlineOperationV1, number]>,
  );
  const pause = async (durationMs: number | undefined): Promise<void> => {
    if (durationMs && durationMs > 0) {
      await new Promise<void>((resolve) => setTimeout(resolve, durationMs));
    }
  };
  const dependencies: LicenseWorkerDependenciesV1 = {
    principals: {
      resolve: async (_request) => {
        await pause(options.principalResolveDelayMs);
        principalResolutionCount += 1;
        for (const waiter of [...principalCountWaiters]) {
          if (principalResolutionCount >= waiter.count) {
            waiter.resolve();
            principalCountWaiters.splice(principalCountWaiters.indexOf(waiter), 1);
          }
        }
        return currentPrincipal;
      },
    },
    authorization: {
      authorize: async (trusted, action, _nowUtcNs) => {
        authorizationCalls.push({ orgId: trusted.orgId, action });
        await pause(options.authorizationDelayMs);
        if (authorizationError) throw authorizationError;
        return authorized;
      },
    },
    licenses: {
      readCurrent: async (orgId, signal) => {
        readOrgs.push(orgId);
        readCount += 1;
        if (signal) readSignals.push(signal);
        const snapshot = snapshots.get(orgId) ?? null;
        if (readCount === 1 && options.readFirstGate) {
          options.readFirstGate.entered();
          await options.readFirstGate.release;
        }
        await pause(options.readDelayMs);
        if (readCount <= hangReadCalls) {
          return await new Promise<LicenseSnapshotV1 | null>(() => {});
        }
        if (readError) throw readError;
        return snapshot;
      },
    },
    backgroundEligibility: {
      publishLease: async (lease) => {
        if (options.publishGate?.deviceId === lease.deviceId && lease.eligible) {
          options.publishGate.entered();
          await options.publishGate.release;
        }
        leases.push({ ...lease });
      },
    },
    signingKeys: new Map([["lic004-test-key", signingKey]]),
    clock: {
      nowMonotonicMs: () => {
        if (options.monotonicClock) return options.monotonicClock();
        const current = monotonicMs;
        monotonicMs += options.monotonicAdvanceMs ?? 0;
        return current;
      },
      nowUtcNs: () => nowNs.toString(),
    },
    requestIdFactory: () => `lic004-request-${++requestSequence}`,
    cache: new LicenseDecisionCacheV1(),
    rateLimiter: options.rateLimiter ?? new PerLicenseRateLimiterV1(),
    serverPolicy: {
      lowestTierApiRateLimitRps: options.lowestTierApiRateLimitRps ?? "100",
    },
    metrics: {
      recordRatePolicyDefaulted: () => { ratePolicyDefaultedCount += 1; },
    },
    deadlines: {
      run: async (operation, _timeoutMs, invoke) => {
        const timeoutCount = deadlineTimeouts.get(operation) ?? 0;
        if (timeoutCount > 0) {
          deadlineTimeouts.set(operation, timeoutCount - 1);
          const controller = new AbortController();
          const pending = invoke(controller.signal);
          void pending.catch(() => undefined);
          controller.abort();
          return { status: "TIMED_OUT" };
        }
        const controller = new AbortController();
        return { status: "COMPLETED", value: await invoke(controller.signal) };
      },
    },
  };
  const worker = createLicenseWorkerV1(dependencies);
  return {
    worker,
    readOrgs,
    authorizationCalls,
    leases,
    readSignals,
    setDeadlineTimeoutCount: (operation: WorkerDeadlineOperationV1, count: number) => {
      deadlineTimeouts.set(operation, count);
    },
    setHangReadCalls: (count: number) => { hangReadCalls = count; },
    waitForPrincipalResolutions: (count: number) => principalResolutionCount >= count
      ? Promise.resolve()
      : new Promise<void>((resolve) => principalCountWaiters.push({ count, resolve })),
    ratePolicyDefaultedCount: () => ratePolicyDefaultedCount,
    snapshots,
    setPrincipal: (next: TrustedPrincipalV1 | null) => { currentPrincipal = next; },
    setAuthorized: (next: boolean) => { authorized = next; },
    setAuthorizationError: (error: Error | null) => { authorizationError = error; },
    setTime: (elapsedMs: number) => {
      monotonicMs = 10_000 + elapsedMs;
      nowNs = BASE_NS + BigInt(elapsedMs) * NS_PER_MS;
    },
    setReadError: (error: Error | null) => { readError = error; },
  };
}

async function send(
  harness: Harness,
  path: string,
  method = "GET",
  body?: unknown,
): Promise<Response> {
  const request = new Request(`https://license-worker.test${path}`, {
    method,
    headers: body === undefined ? undefined : { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return harness.worker.fetch(request);
}

async function responseBody(response: Response): Promise<Record<string, unknown>> {
  return await response.json() as Record<string, unknown>;
}

function expectContentFreeDenial(body: Record<string, unknown>): void {
  expect(Object.keys(body).sort()).toEqual([
    "code", "observed_at_ns", "request_id", "schema_version",
  ]);
  expect(body.schema_version).toBe(1);
  expect(typeof body.code).toBe("string");
  expect(typeof body.request_id).toBe("string");
  expect(typeof body.observed_at_ns).toBe("string");
}

describe("LIC-004 independent worker acceptance", () => {
  it("uses the trusted principal org for both JSON V1 snapshots", async () => {
    const keys = await createKeyPair();
    const orgA = await signedSnapshot(keys.privateKey, { orgId: "org-a" });
    const orgB = await signedSnapshot(keys.privateKey, {
      orgId: "org-b",
      licenseId: "license-b-private",
      subscriptionRevision: "8",
      deviceId: "lic004-synthetic-device",
    });
    const harness = makeHarness([orgA, orgB], keys.publicKey, {
      principal: principal("org-a"),
    });

    const licenseResponse = await send(harness, "/v1/admin/license?org_id=org-b");
    expect(licenseResponse.status).toBe(200);
    const license = await responseBody(licenseResponse);
    expect((license.license as LicenseSnapshotV1).orgId).toBe("org-a");
    expect(harness.readOrgs).toEqual(["org-a"]);

    harness.setTime(10);
    const introspectResponse = await send(harness, "/v1/auth/introspect", "POST", {});
    expect(introspectResponse.status).toBe(200);
    const introspection = await responseBody(introspectResponse);
    expect(introspection).toMatchObject({
      active: true,
      org_id: "org-a",
      subject_id: "principal-org-a",
      scopes: ["license:read", "auth:introspect"],
    });
    expect((introspection.license as LicenseSnapshotV1).orgId).toBe("org-a");
    expect(harness.readOrgs.at(-1)).toBe("org-a");
    expect(harness.authorizationCalls.map((call) => call.action)).toEqual([
      "license:read", "auth:introspect",
    ]);
  });

  it("returns content-free 401 and 403 denials before reading license data", async () => {
    const keys = await createKeyPair();
    const unauthenticated = makeHarness([], keys.publicKey, { principal: null });
    const noIdentityResponse = await send(unauthenticated, "/v1/admin/license");
    expect(noIdentityResponse.status).toBe(401);
    expectContentFreeDenial(await responseBody(noIdentityResponse));
    expect(unauthenticated.readOrgs).toEqual([]);
    expect(unauthenticated.authorizationCalls).toEqual([]);

    const snapshot = await signedSnapshot(keys.privateKey);
    const forbidden = makeHarness([snapshot], keys.publicKey, { authorized: false });
    const forbiddenResponse = await send(forbidden, "/v1/admin/license");
    expect(forbiddenResponse.status).toBe(403);
    expectContentFreeDenial(await responseBody(forbiddenResponse));
    expect(forbidden.readOrgs).toEqual([]);
    expect(forbidden.authorizationCalls).toHaveLength(1);
    expect(forbidden.leases).toEqual([]);

    const sharedBinding = makeHarness([snapshot], keys.publicKey);
    expect((await send(sharedBinding, "/v1/admin/license")).status).toBe(200);
    const existingLease = sharedBinding.leases[0];
    sharedBinding.setAuthorized(false);
    const deniedOwnerBinding = await send(sharedBinding, "/v1/admin/license");
    expect(deniedOwnerBinding.status).toBe(403);
    expectContentFreeDenial(await responseBody(deniedOwnerBinding));
    expect(sharedBinding.leases).toEqual([existingLease]);
  });

  it("rejects body-supplied tokens and selectors without echoing them", async () => {
    const sentinel = "lic004-sensitive-token-sentinel";
    const keys = await createKeyPair();
    const harness = makeHarness([], keys.publicKey);
    for (const body of [{ token: sentinel }, { org_id: "org-other" }, { extra: "selector" }]) {
      const response = await send(harness, "/v1/auth/introspect", "POST", body);
      expect(response.status).toBe(400);
      const denial = await responseBody(response);
      expectContentFreeDenial(denial);
      expect(JSON.stringify(denial)).not.toContain(sentinel);
    }
    expect(harness.readOrgs).toEqual([]);
  });

  it("revokes background eligibility when authorization state is uncertain", async () => {
    const keys = await createKeyPair();
    const snapshot = await signedSnapshot(keys.privateKey);
    const harness = makeHarness([snapshot], keys.publicKey);
    harness.setAuthorizationError(new Error("authorization-port-secret-sentinel"));

    const response = await send(harness, "/v1/admin/license");

    expect(response.status).toBe(403);
    expectContentFreeDenial(await responseBody(response));
    expect(harness.leases.at(-1)).toMatchObject({
      orgId: snapshot.orgId,
      eligible: false,
      expiresAtMonotonicMs: null,
      reason: "UNKNOWN",
    });
  });

  it("returns only a content-free 402 for inactive or unavailable licenses", async () => {
    const keys = await createKeyPair();
    const suspended = await signedSnapshot(keys.privateKey, { status: "SUSPENDED" });
    const inactive = makeHarness([suspended], keys.publicKey);
    const response = await send(inactive, "/v1/admin/license");
    expect(response.status).toBe(402);
    const denial = await responseBody(response);
    expectContentFreeDenial(denial);
    expect(JSON.stringify(denial)).not.toContain(suspended.orgId);
    expect(JSON.stringify(denial)).not.toContain(suspended.licenseId);

    const unavailable = makeHarness([await signedSnapshot(keys.privateKey)], keys.publicKey);
    unavailable.setReadError(new Error("private-neon-error-sentinel"));
    const unavailableResponse = await send(unavailable, "/v1/auth/introspect", "POST", {});
    expect(unavailableResponse.status).toBe(402);
    const unavailableBody = await responseBody(unavailableResponse);
    expectContentFreeDenial(unavailableBody);
    expect(JSON.stringify(unavailableBody)).not.toContain("private-neon-error-sentinel");
  });

  it("fails closed after the 60-second positive age until a higher signed revision", async () => {
    const keys = await createKeyPair();
    const active = await signedSnapshot(keys.privateKey);
    const harness = makeHarness([active], keys.publicKey);
    expect((await send(harness, "/v1/admin/license")).status).toBe(200);

    harness.setTime(59_999);
    expect((await send(harness, "/v1/admin/license")).status).toBe(200);

    harness.setTime(60_000);
    const expired = await send(harness, "/v1/admin/license");
    expect(expired.status).toBe(402);
    expectContentFreeDenial(await responseBody(expired));

    const refreshed = await signedSnapshot(keys.privateKey, {
      orgId: active.orgId,
      licenseId: active.licenseId,
      audience: active.audience,
      deviceId: active.deviceId,
      subscriptionRevision: "2",
      issuedAtUtcNs: (BASE_NS + 60_001n * NS_PER_MS - 2n * NS_PER_SECOND).toString(),
      lastOnlineVerifiedUtcNs: (BASE_NS + 60_001n * NS_PER_MS).toString(),
      termStartUtcNs: (BASE_NS - 10n * NS_PER_SECOND).toString(),
      termEndUtcNs: (BASE_NS + 3_600n * NS_PER_SECOND).toString(),
    });
    harness.snapshots.set(refreshed.orgId, refreshed);
    harness.setTime(60_001);
    const newer = await send(harness, "/v1/admin/license");
    expect(newer.status).toBe(200);
    expect((await responseBody(newer)).license).toMatchObject({
      subscriptionRevision: "2",
    });
  });

  it("invalidates a cached positive immediately on a higher suspended revision", async () => {
    const keys = await createKeyPair();
    const initial = await signedSnapshot(keys.privateKey, { subscriptionRevision: "1" });
    const harness = makeHarness([initial], keys.publicKey);
    expect((await send(harness, "/v1/admin/license")).status).toBe(200);
    expect(harness.leases.at(-1)).toMatchObject({
      eligible: true,
      reason: "VERIFIED_ONLINE",
    });

    const suspended = await signedSnapshot(keys.privateKey, {
      orgId: initial.orgId,
      licenseId: initial.licenseId,
      audience: initial.audience,
      deviceId: initial.deviceId,
      subscriptionRevision: "2",
      status: "SUSPENDED",
      issuedAtUtcNs: (BASE_NS + 10n * NS_PER_MS - 2n * NS_PER_SECOND).toString(),
      lastOnlineVerifiedUtcNs: (BASE_NS + 10n * NS_PER_MS).toString(),
    });
    harness.snapshots.set(suspended.orgId, suspended);
    harness.setTime(10);
    const response = await send(harness, "/v1/auth/introspect", "POST", {});
    expect(response.status).toBe(402);
    expectContentFreeDenial(await responseBody(response));
    expect(harness.leases.at(-1)).toMatchObject({
      orgId: suspended.orgId,
      eligible: false,
      expiresAtMonotonicMs: null,
      reason: "DENIED",
    });

    harness.snapshots.set(initial.orgId, initial);
    harness.setTime(20);
    const replayed = await send(harness, "/v1/admin/license");
    expect(replayed.status).toBe(402);

    const restored = await signedSnapshot(keys.privateKey, {
      orgId: initial.orgId,
      licenseId: initial.licenseId,
      audience: initial.audience,
      deviceId: initial.deviceId,
      subscriptionRevision: "3",
      issuedAtUtcNs: (BASE_NS + 30n * NS_PER_MS - 2n * NS_PER_SECOND).toString(),
      lastOnlineVerifiedUtcNs: (BASE_NS + 30n * NS_PER_MS).toString(),
    });
    harness.snapshots.set(restored.orgId, restored);
    harness.setTime(30);
    expect((await send(harness, "/v1/admin/license")).status).toBe(200);
  });

  it("bounds eligible background leases by the term and clears them on expiry or uncertainty", async () => {
    const keys = await createKeyPair();
    const termBound = await signedSnapshot(keys.privateKey, {
      termEndUtcNs: (BASE_NS + 30n * NS_PER_SECOND).toString(),
    });
    const harness = makeHarness([termBound], keys.publicKey);
    expect((await send(harness, "/v1/admin/license")).status).toBe(200);
    expect(harness.leases.at(-1)).toMatchObject({
      eligible: true,
      reason: "VERIFIED_ONLINE",
    });
    expect(harness.leases.at(-1)?.expiresAtMonotonicMs).toBeGreaterThan(10_000);
    expect(harness.leases.at(-1)?.expiresAtMonotonicMs).toBeLessThanOrEqual(40_000);

    harness.setTime(30_000);
    const expired = await send(harness, "/v1/admin/license");
    expect(expired.status).toBe(402);
    expect(harness.leases.at(-1)).toMatchObject({
      eligible: false,
      expiresAtMonotonicMs: null,
      reason: "DENIED",
    });

    harness.setReadError(new Error("uncertain-neon-state-sentinel"));
    const uncertain = await send(harness, "/v1/admin/license");
    expect(uncertain.status).toBe(402);
    expect(harness.leases.at(-1)).toMatchObject({
      eligible: false,
      expiresAtMonotonicMs: null,
      reason: "UNKNOWN",
    });
  });

  it("does not let a changed signed payload hit a cache keyed only by signature", async () => {
    const keys = await createKeyPair();
    const snapshot = await signedSnapshot(keys.privateKey);
    const harness = makeHarness([snapshot], keys.publicKey);
    expect((await send(harness, "/v1/admin/license")).status).toBe(200);
    harness.setTime(10);

    const altered = {
      ...snapshot,
      features: { decisioning: false, background_jobs: true },
    } as LicenseSnapshotV1;
    harness.snapshots.set(snapshot.orgId, altered);
    const response = await send(harness, "/v1/admin/license");
    expect(response.status).toBe(402);
    expectContentFreeDenial(await responseBody(response));
  });

  it("enforces per-license rate limiting with a Retry-After header", async () => {
    const keys = await createKeyPair();
    const limited = await signedSnapshot(keys.privateKey, {
      limits: { seats: "3", api_rate_limit_rps: "1" },
    });
    const harness = makeHarness([limited], keys.publicKey);
    expect((await send(harness, "/v1/admin/license")).status).toBe(200);

    const throttled = await send(harness, "/v1/admin/license");
    expect(throttled.status).toBe(429);
    expect(Number(throttled.headers.get("Retry-After"))).toBeGreaterThanOrEqual(1);
    const denial = await responseBody(throttled);
    expectContentFreeDenial(denial);
  });

  it("serializes cold same-scope overlaps and serves the following warm request", async () => {
    const keys = await createKeyPair();
    const snapshot = await signedSnapshot(keys.privateKey);
    const harness = makeHarness([snapshot], keys.publicKey, {
      principalResolveDelayMs: 1,
      authorizationDelayMs: 1,
      readDelayMs: 1,
      monotonicAdvanceMs: 2,
    });

    const coldResponses = await Promise.all(
      Array.from({ length: 4 }, () => send(harness, "/v1/admin/license")),
    );
    expect(coldResponses.map((response) => response.status)).toEqual([200, 200, 200, 200]);
    expect((await send(harness, "/v1/admin/license")).status).toBe(200);
    expect(harness.leases.at(-1)).toMatchObject({
      orgId: snapshot.orgId,
      audience: "leviathan-desktop",
      deviceId: "lic004-synthetic-device",
      eligible: true,
      reason: "VERIFIED_ONLINE",
    });
  });

  it("times out a hung license port without lease mutation and releases the scope lock", async () => {
    const keys = await createKeyPair();
    const snapshot = await signedSnapshot(keys.privateKey);
    const harness = makeHarness([snapshot], keys.publicKey, {
      deadlineTimeouts: { "license-read": 1 },
      hangReadCalls: 1,
    });

    const timedOut = await send(harness, "/v1/admin/license");
    expect(timedOut.status).toBe(402);
    const timeoutBody = await responseBody(timedOut);
    expectContentFreeDenial(timeoutBody);
    expect(timeoutBody.code).toBe("LICENSE_REQUIRED");
    expect(harness.readSignals).toHaveLength(1);
    expect(harness.readSignals[0]?.aborted).toBe(true);
    expect(harness.leases).toEqual([]);

    const following = await send(harness, "/v1/admin/license");
    expect(following.status).toBe(200);
    expect(harness.leases.at(-1)).toMatchObject({ eligible: true, reason: "VERIFIED_ONLINE" });

    const existingLease = harness.leases.at(-1);
    harness.setDeadlineTimeoutCount("license-read", 1);
    harness.setHangReadCalls(3);
    const warmTimeout = await send(harness, "/v1/admin/license");
    expect(warmTimeout.status).toBe(402);
    expectContentFreeDenial(await responseBody(warmTimeout));
    expect(harness.readSignals.at(-1)?.aborted).toBe(true);
    expect(harness.leases).toEqual([existingLease]);

    harness.setTime(2);
    expect((await send(harness, "/v1/admin/license")).status).toBe(200);
  });

  it("maps same-scope queue overflow to 429 and releases queued requests", async () => {
    const keys = await createKeyPair();
    const snapshot = await signedSnapshot(keys.privateKey);
    const publishEntered = deferred<void>();
    const publishRelease = deferred<void>();
    const harness = makeHarness([snapshot], keys.publicKey, {
      publishGate: {
        deviceId: snapshot.deviceId,
        entered: () => publishEntered.resolve(),
        release: publishRelease.promise,
      },
      monotonicAdvanceMs: 2,
    });

    const holder = send(harness, "/v1/admin/license");
    await publishEntered.promise;
    const queued = Array.from(
      { length: LICENSE_WORKER_SCOPE_QUEUE_CAP_V1 - 1 },
      () => send(harness, "/v1/admin/license"),
    );
    await harness.waitForPrincipalResolutions(LICENSE_WORKER_SCOPE_QUEUE_CAP_V1);
    // Let each resolved principal enqueue behind the held in-scope operation.
    await Promise.resolve();
    await Promise.resolve();

    const overflow = await send(harness, "/v1/admin/license");
    const overflowBody = await responseBody(overflow);
    publishRelease.resolve();
    expect(overflow.status).toBe(429);
    expectContentFreeDenial(overflowBody);
    expect(overflowBody.code).toBe("RATE_LIMITED");

    const accepted = await Promise.all([holder, ...queued]);
    expect(accepted.map((response) => response.status)).toEqual(
      Array(LICENSE_WORKER_SCOPE_QUEUE_CAP_V1).fill(200),
    );
  });

  it("uses fresh limiter stamps for overlapping device bindings of one license", async () => {
    const keys = await createKeyPair();
    const orgId = "org-lic004-multi-device";
    const licenseId = "license-lic004-multi-device";
    const snapshotA = await signedSnapshot(keys.privateKey, {
      orgId,
      licenseId,
      deviceId: "lic004-device-a",
      limits: { seats: "3", api_rate_limit_rps: "1000" },
    });
    const snapshotB = await signedSnapshot(keys.privateKey, {
      orgId,
      licenseId,
      deviceId: "lic004-device-b",
      limits: { seats: "3", api_rate_limit_rps: "1000" },
    });
    const publishEntered = deferred<void>();
    const publishRelease = deferred<void>();
    let monotonicMs = 10_000;
    const monotonicClock = (): number => monotonicMs++;
    const limiter = new PerLicenseRateLimiterV1();
    const deviceA = makeHarness([snapshotA], keys.publicKey, {
      principal: scopedPrincipal(orgId, snapshotA.audience, snapshotA.deviceId),
      publishGate: {
        deviceId: snapshotA.deviceId,
        entered: () => publishEntered.resolve(),
        release: publishRelease.promise,
      },
      monotonicClock,
      rateLimiter: limiter,
    });
    const deviceB = makeHarness([snapshotB], keys.publicKey, {
      principal: scopedPrincipal(orgId, snapshotB.audience, snapshotB.deviceId),
      monotonicClock,
      rateLimiter: limiter,
    });

    const delayedA = send(deviceA, "/v1/admin/license");
    await publishEntered.promise;
    const responseB = await send(deviceB, "/v1/admin/license");
    publishRelease.resolve();
    const responseA = await delayedA;

    expect(responseA.status).toBe(200);
    expect(responseB.status).toBe(200);
    expect(deviceA.leases.at(-1)).toMatchObject({ deviceId: snapshotA.deviceId, eligible: true });
    expect(deviceB.leases.at(-1)).toMatchObject({ deviceId: snapshotB.deviceId, eligible: true });
  });

  it("does not let an unverified head throttle another organization", async () => {
    const keys = await createKeyPair();
    const licenseId = "license-lic004-shared-victim";
    const forgedBase = await signedSnapshot(keys.privateKey, {
      orgId: "org-lic004-forged-head",
      licenseId,
      limits: { seats: "3", api_rate_limit_rps: "1" },
    });
    const forgedHead: LicenseSnapshotV1 = {
      ...forgedBase,
      signature: { ...forgedBase.signature, value: "invalid-signature" },
    };
    const genuineHead = await signedSnapshot(keys.privateKey, {
      orgId: "org-lic004-genuine-head",
      licenseId,
      limits: { seats: "3", api_rate_limit_rps: "1000" },
    });
    const limiter = new PerLicenseRateLimiterV1();
    const forged = makeHarness([forgedHead], keys.publicKey, {
      principal: principal(forgedHead.orgId),
      rateLimiter: limiter,
    });
    const genuine = makeHarness([genuineHead], keys.publicKey, {
      principal: principal(genuineHead.orgId),
      rateLimiter: limiter,
    });

    const rejectedHead = await send(forged, "/v1/admin/license");
    expect(rejectedHead.status).toBe(402);
    const genuineOrg = await send(genuine, "/v1/admin/license");
    expect(genuineOrg.status).toBe(200);
  });

  it("does not latch rollback when a delayed older read straddles a newer evaluation", async () => {
    const keys = await createKeyPair();
    const orgId = "org-lic004-straddling-revision";
    const revisionOne = await signedSnapshot(keys.privateKey, {
      orgId,
      licenseId: "license-lic004-straddling-revision",
      subscriptionRevision: "1",
      limits: { seats: "3", api_rate_limit_rps: "1000" },
    });
    const readEntered = deferred<void>();
    const readRelease = deferred<void>();
    const harness = makeHarness([revisionOne], keys.publicKey, {
      readFirstGate: { entered: () => readEntered.resolve(), release: readRelease.promise },
      monotonicAdvanceMs: 2,
    });

    const delayedRevisionOne = send(harness, "/v1/admin/license");
    await readEntered.promise;
    const revisionTwo = await signedSnapshot(keys.privateKey, {
      orgId,
      licenseId: revisionOne.licenseId,
      audience: revisionOne.audience,
      deviceId: revisionOne.deviceId,
      subscriptionRevision: "2",
      status: "SUSPENDED",
      issuedAtUtcNs: (BASE_NS + NS_PER_MS - 2n * NS_PER_SECOND).toString(),
      lastOnlineVerifiedUtcNs: (BASE_NS + NS_PER_MS).toString(),
      termStartUtcNs: revisionOne.termStartUtcNs,
      termEndUtcNs: revisionOne.termEndUtcNs,
      limits: { seats: "3", api_rate_limit_rps: "1000" },
    });
    harness.snapshots.set(orgId, revisionTwo);
    harness.setTime(1);
    const revisionTwoResponse = await send(harness, "/v1/admin/license");
    expect(revisionTwoResponse.status).toBe(402);
    const revisionTwoBody = await responseBody(revisionTwoResponse);
    expectContentFreeDenial(revisionTwoBody);
    const leasesAtRevisionTwo = [...harness.leases];

    readRelease.resolve();
    const delayedResponse = await delayedRevisionOne;
    expect(harness.readOrgs).toHaveLength(3);
    expect(delayedResponse.status).toBe(revisionTwoResponse.status);
    expect(await responseBody(delayedResponse)).toMatchObject({ code: revisionTwoBody.code });
    expect(harness.leases).toEqual(leasesAtRevisionTwo);

    const revisionThree = await signedSnapshot(keys.privateKey, {
      orgId,
      licenseId: revisionOne.licenseId,
      audience: revisionOne.audience,
      deviceId: revisionOne.deviceId,
      subscriptionRevision: "3",
      issuedAtUtcNs: (BASE_NS + 10n * NS_PER_MS - 2n * NS_PER_SECOND).toString(),
      lastOnlineVerifiedUtcNs: (BASE_NS + 10n * NS_PER_MS).toString(),
      termStartUtcNs: revisionOne.termStartUtcNs,
      termEndUtcNs: revisionOne.termEndUtcNs,
      limits: { seats: "3", api_rate_limit_rps: "1000" },
    });
    harness.snapshots.set(orgId, revisionThree);
    harness.setTime(10);
    const revisionThreeResponse = await send(harness, "/v1/admin/license");
    expect(revisionThreeResponse.status).toBe(200);
    expect((await responseBody(revisionThreeResponse)).license).toMatchObject({
      subscriptionRevision: "3",
    });
  });

  it("rate limits unverified requests by their own scope fallback key", async () => {
    const keys = await createKeyPair();
    const licenseId = "license-lic004-unverified-shared";
    const signedA = await signedSnapshot(keys.privateKey, {
      orgId: "org-lic004-unverified-a",
      licenseId,
      limits: { seats: "3", api_rate_limit_rps: "1000" },
    });
    const signedB = await signedSnapshot(keys.privateKey, {
      orgId: "org-lic004-unverified-b",
      licenseId,
      limits: { seats: "3", api_rate_limit_rps: "1000" },
    });
    const unverifiedA: LicenseSnapshotV1 = {
      ...signedA,
      signature: { ...signedA.signature, value: "invalid-signature-a" },
    };
    const unverifiedB: LicenseSnapshotV1 = {
      ...signedB,
      signature: { ...signedB.signature, value: "invalid-signature-b" },
    };
    const limiter = new PerLicenseRateLimiterV1();
    const scopeA = makeHarness([unverifiedA], keys.publicKey, {
      principal: principal(unverifiedA.orgId),
      lowestTierApiRateLimitRps: "1",
      rateLimiter: limiter,
    });
    const scopeB = makeHarness([unverifiedB], keys.publicKey, {
      principal: principal(unverifiedB.orgId),
      lowestTierApiRateLimitRps: "1",
      rateLimiter: limiter,
    });

    const firstA = await send(scopeA, "/v1/admin/license");
    expect(firstA.status).toBe(402);
    expectContentFreeDenial(await responseBody(firstA));
    scopeA.setTime(2);
    const secondA = await send(scopeA, "/v1/admin/license");
    expect(secondA.status).toBe(429);
    expectContentFreeDenial(await responseBody(secondA));

    const firstB = await send(scopeB, "/v1/admin/license");
    expect(firstB.status).toBe(402);
    expectContentFreeDenial(await responseBody(firstB));
  });

  it("scopes a web-device denial without revoking the desktop eligibility lease", async () => {
    const keys = await createKeyPair();
    const snapshot = await signedSnapshot(keys.privateKey);
    const harness = makeHarness([snapshot], keys.publicKey);
    expect((await send(harness, "/v1/admin/license")).status).toBe(200);
    const desktopLease = harness.leases.at(-1);
    expect(desktopLease).toMatchObject({
      audience: "leviathan-desktop",
      deviceId: "lic004-synthetic-device",
      eligible: true,
      reason: "VERIFIED_ONLINE",
    });

    harness.setPrincipal(scopedPrincipal(snapshot.orgId, "web", "lic004-web-device"));
    harness.setTime(1);
    const webResponse = await send(harness, "/v1/admin/license");
    expect(webResponse.status).toBe(402);
    expectContentFreeDenial(await responseBody(webResponse));
    expect(harness.leases.at(-1)).toMatchObject({
      orgId: snapshot.orgId,
      audience: "web",
      deviceId: "lic004-web-device",
      eligible: false,
      expiresAtMonotonicMs: null,
      reason: "UNKNOWN",
    });
    expect(desktopLease).toMatchObject({
      audience: "leviathan-desktop",
      deviceId: "lic004-synthetic-device",
      eligible: true,
      reason: "VERIFIED_ONLINE",
    });
    expect(harness.leases.filter((lease) =>
      lease.audience === "leviathan-desktop" && lease.deviceId === "lic004-synthetic-device",
    )).toHaveLength(1);
  });

  it("authorizes introspection before touching its body and cancels oversized bodies at the cap", async () => {
    const keys = await createKeyPair();
    const unauthorized = makeHarness([], keys.publicKey, { authorized: false });
    let bodyAccesses = 0;
    const unreadRequest = {
      url: "https://license-worker.test/v1/auth/introspect",
      method: "POST",
      headers: new Headers({ "content-type": "application/json" }),
      get body() {
        bodyAccesses += 1;
        return new ReadableStream<Uint8Array>();
      },
    } as unknown as Request;
    const forbidden = await unauthorized.worker.fetch(unreadRequest);
    expect(forbidden.status).toBe(403);
    expect(bodyAccesses).toBe(0);

    const snapshot = await signedSnapshot(keys.privateKey);
    const authorized = makeHarness([snapshot], keys.publicKey);
    let consumedBytes = 0;
    let cancelled = false;
    const oversizedBody = new ReadableStream<Uint8Array>({
      pull(controller) {
        if (consumedBytes >= 10_000) {
          controller.close();
          return;
        }
        controller.enqueue(new Uint8Array([0x20]));
        consumedBytes += 1;
      },
      cancel() {
        cancelled = true;
      },
    }, { highWaterMark: 0 });
    const tooLargeRequest = {
      url: "https://license-worker.test/v1/auth/introspect",
      method: "POST",
      headers: new Headers({ "content-type": "application/json" }),
      body: oversizedBody,
    } as unknown as Request;
    const rejected = await authorized.worker.fetch(tooLargeRequest);
    expect(rejected.status).toBe(400);
    expect(consumedBytes).toBe(1025);
    expect(cancelled).toBe(true);
    expect(authorized.readOrgs).toEqual([]);
  });

  it("uses the configured default rate for snapshots without a rate key", async () => {
    const keys = await createKeyPair();
    const snapshot = await signedSnapshot(keys.privateKey, { limits: { seats: "3" } });
    const harness = makeHarness([snapshot], keys.publicKey, {
      lowestTierApiRateLimitRps: "10",
    });

    const response = await send(harness, "/v1/admin/license");
    expect(response.status).toBe(200);
    expect((await responseBody(response)).entitlement_state).toBe("VERIFIED_ONLINE");
    expect(harness.ratePolicyDefaultedCount()).toBe(1);
    expect(harness.leases.at(-1)).toMatchObject({
      eligible: true,
      reason: "VERIFIED_ONLINE",
    });
  });

  it("applies per-license rate limiting to cached negative decisions", async () => {
    const keys = await createKeyPair();
    const inactive = await signedSnapshot(keys.privateKey, {
      status: "SUSPENDED",
      limits: { seats: "3", api_rate_limit_rps: "1" },
    });
    const harness = makeHarness([inactive], keys.publicKey);

    const denied = await send(harness, "/v1/admin/license");
    expect(denied.status).toBe(402);
    expectContentFreeDenial(await responseBody(denied));
    expect(harness.leases.at(-1)).toMatchObject({
      eligible: false,
      expiresAtMonotonicMs: null,
      reason: "DENIED",
    });

    const limited = await send(harness, "/v1/admin/license");
    expect(limited.status).toBe(429);
    expect(Number(limited.headers.get("Retry-After"))).toBeGreaterThanOrEqual(1);
    expectContentFreeDenial(await responseBody(limited));
  });

  it("returns no webhook mutation route in this fake-only slice", async () => {
    const keys = await createKeyPair();
    const snapshot = await signedSnapshot(keys.privateKey);
    const harness = makeHarness([snapshot], keys.publicKey);
    const response = await send(harness, "/v1/admin/license/webhook", "POST", {
      event: "subscription.updated",
      signature: "synthetic-only",
    });
    expect(response.status).toBe(404);
    expect(harness.readOrgs).toEqual([]);
    expect(harness.authorizationCalls).toEqual([]);
  });

  it("observes exact positive and negative cache ceilings and identity invalidation", () => {
    const cache = new LicenseDecisionCacheV1();
    const result = (
      outcome: EntitlementResultV1["decision"]["outcome"],
      authorizesGatedEffects: boolean,
    ): EntitlementResultV1 => ({
      decision: {
        schemaVersion: 1,
        outcome,
        reason: outcome === "VERIFIED_ONLINE" ? "ONLINE_ACTIVE" : "LICENSE_INACTIVE",
        expiresAtUtcNs: null,
        authorizesGatedEffects,
      },
      state: createEntitlementStateV1(),
    });
    const fingerprint = "a".repeat(64);
    cache.put("scope-positive", "1", fingerprint, result("VERIFIED_ONLINE", true), 100);
    expect(cache.get("scope-positive", "1", fingerprint, 60_099)).not.toBeNull();
    expect(cache.get("scope-positive", "1", fingerprint, 60_100)).toBeNull();

    cache.put("scope-negative", "2", fingerprint, result("DENIED", false), 100);
    expect(cache.get("scope-negative", "2", fingerprint, 5_099)).not.toBeNull();
    expect(cache.get("scope-negative", "2", fingerprint, 5_100)).toBeNull();

    cache.put("scope-revision", "3", fingerprint, result("VERIFIED_ONLINE", true), 100);
    expect(cache.get("scope-revision", "4", fingerprint, 101)).toBeNull();
    cache.put("scope-fingerprint", "1", fingerprint, result("VERIFIED_ONLINE", true), 100);
    expect(cache.get("scope-fingerprint", "1", "b".repeat(64), 101)).toBeNull();
  });
});
