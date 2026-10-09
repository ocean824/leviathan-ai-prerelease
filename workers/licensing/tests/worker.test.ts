import { describe, expect, it } from "vitest";
import {
  canonicalLicenseSnapshotV1,
} from "../src/entitlement/decision.js";
import type { EntitlementResultV1, LicenseSnapshotV1 } from "../src/entitlement/models.js";
import { LicenseDecisionCacheV1 } from "../src/worker/cache.js";
import {
  createLicenseWorkerV1,
  type BackgroundEligibilityLeaseV1,
  type LicenseWorkerDependenciesV1,
  type TrustedPrincipalV1,
  type WorkerDeadlineOperationV1,
} from "../src/worker/handler.js";
import { PerLicenseRateLimiterV1 } from "../src/worker/rate_limit.js";

const BASE_NS = 1_800_000_000_000_000_000n;
const NS_PER_MS = 1_000_000n;
const NS_PER_SECOND = 1_000_000_000n;

function arrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  return buffer;
}

function fakeResult(
  outcome: EntitlementResultV1["decision"]["outcome"],
  authorizesGatedEffects: boolean,
): EntitlementResultV1 {
  return {
    decision: {
      schemaVersion: 1,
      outcome,
      reason: outcome === "VERIFIED_ONLINE" ? "ONLINE_ACTIVE" : "LICENSE_INACTIVE",
      expiresAtUtcNs: null,
      authorizesGatedEffects,
    },
    state: { schemaVersion: 1 },
  };
}

async function signedSnapshot(
  privateKey: CryptoKey,
  changes: Partial<LicenseSnapshotV1> = {},
): Promise<LicenseSnapshotV1> {
  const base: LicenseSnapshotV1 = {
    schemaVersion: 1,
    orgId: `org-lic004-unit-${globalThis.crypto.randomUUID()}`,
    licenseId: `license-lic004-unit-${globalThis.crypto.randomUUID()}`,
    subscriptionRevision: "1",
    status: "ACTIVE",
    termStartUtcNs: (BASE_NS - 10n * NS_PER_SECOND).toString(),
    termEndUtcNs: (BASE_NS + 3_600n * NS_PER_SECOND).toString(),
    issuedAtUtcNs: (BASE_NS - 2n * NS_PER_SECOND).toString(),
    lastOnlineVerifiedUtcNs: BASE_NS.toString(),
    features: { decisioning: true },
    limits: { api_rate_limit_rps: "10" },
    audience: "licensing-worker",
    deviceId: `unit-device-${globalThis.crypto.randomUUID()}`,
    signingKeyId: "unit-key",
    signature: { algorithm: "ECDSA_P256_SHA256", value: "" },
  };
  const unsigned: LicenseSnapshotV1 = { ...base, ...changes, signature: base.signature };
  const signatureBytes = await globalThis.crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" }, privateKey,
    arrayBuffer(canonicalLicenseSnapshotV1(unsigned)),
  );
  const signature = btoa(String.fromCharCode(...new Uint8Array(signatureBytes)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return { ...unsigned, signature: { algorithm: "ECDSA_P256_SHA256", value: signature } };
}

function principal(orgId: string, deviceId: string): TrustedPrincipalV1 {
  return Object.freeze({
    schemaVersion: 1,
    principalId: `lic004-unit-principal-${globalThis.crypto.randomUUID()}`,
    orgId,
    audience: "licensing-worker",
    deviceId,
    scopes: Object.freeze(["license:read", "auth:introspect"]),
    roles: Object.freeze(["Admin"]),
  });
}

function harness(
  snapshot: LicenseSnapshotV1,
  publicKey: CryptoKey,
  sharedRateLimiter = new PerLicenseRateLimiterV1(),
) {
  let monotonicMs = 1_000;
  let wallNs = BASE_NS;
  let currentSnapshot: LicenseSnapshotV1 | null = snapshot;
  let currentPrincipal = principal(snapshot.orgId, snapshot.deviceId);
  let readHook: ((current: LicenseSnapshotV1 | null) => Promise<LicenseSnapshotV1 | null>) | null = null;
  const leases: BackgroundEligibilityLeaseV1[] = [];
  let readFails = false;
  let readStalls = false;
  let authFails = false;
  let authAllowed = true;
  let tickingClock = false;
  let ratePolicyDefaultedCount = 0;
  const timedOutOperations = new Set<WorkerDeadlineOperationV1>();
  let requestId = 0;
  let holdLeasePublish = false;
  let releaseLease: (() => void) | null = null;
  let leasePublishStarted = false;
  let leasePublishStartedWaiter: (() => void) | null = null;
  let leasePublishDelayMs = 0;
  const dependencies: LicenseWorkerDependenciesV1 = {
    principals: {
      resolve: async (request) => {
        const delayMs = Number(request.headers.get("x-test-resolve-delay-ms") ?? "0");
        if (Number.isSafeInteger(delayMs) && delayMs > 0) {
          await new Promise((resolve) => setTimeout(resolve, delayMs));
        }
        return currentPrincipal;
      },
    },
    authorization: {
      authorize: async () => {
        if (authFails) throw new Error("synthetic-auth-failure");
        return authAllowed;
      },
    },
    licenses: {
      readCurrent: async () => {
        if (readStalls) return await new Promise<LicenseSnapshotV1 | null>(() => undefined);
        if (readFails) throw new Error("synthetic-neon-failure");
        if (readHook) return readHook(currentSnapshot);
        return currentSnapshot;
      },
    },
    signingKeys: new Map([["unit-key", publicKey]]),
    clock: {
      nowMonotonicMs: () => {
        if (tickingClock) monotonicMs += 1;
        return monotonicMs;
      },
      nowUtcNs: () => {
        if (tickingClock) wallNs += NS_PER_MS;
        return wallNs.toString();
      },
    },
    requestIdFactory: () => `unit-request-${++requestId}`,
    cache: new LicenseDecisionCacheV1(),
    rateLimiter: sharedRateLimiter,
    backgroundEligibility: { publishLease: async (lease) => {
      if (holdLeasePublish) {
        leasePublishStarted = true;
        leasePublishStartedWaiter?.();
        await new Promise<void>((resolve) => { releaseLease = resolve; });
      }
      if (leasePublishDelayMs > 0) {
        await new Promise<void>((resolve) => setTimeout(resolve, leasePublishDelayMs));
      }
      leases.push(lease);
    } },
    serverPolicy: { lowestTierApiRateLimitRps: "1" },
    metrics: { recordRatePolicyDefaulted: () => { ratePolicyDefaultedCount += 1; } },
    deadlines: {
      run: async <T>(operation: WorkerDeadlineOperationV1, _timeoutMs: number,
        invoke: (signal: AbortSignal) => Promise<T>) => {
        const controller = new AbortController();
        if (timedOutOperations.delete(operation)) {
          void invoke(controller.signal).catch(() => undefined);
          controller.abort();
          return { status: "TIMED_OUT" as const };
        }
        return { status: "COMPLETED" as const, value: await invoke(controller.signal) };
      },
    },
  };
  return {
    worker: createLicenseWorkerV1(dependencies),
    cache: dependencies.cache,
    leases,
    setSnapshot: (value: LicenseSnapshotV1 | null) => { currentSnapshot = value; },
    setReadHook: (value: ((current: LicenseSnapshotV1 | null) => Promise<LicenseSnapshotV1 | null>) | null) => {
      readHook = value;
    },
    setTime: (elapsedMs: number) => {
      monotonicMs = 1_000 + elapsedMs;
      wallNs = BASE_NS + BigInt(elapsedMs) * NS_PER_MS;
    },
    setReadFails: (value: boolean) => { readFails = value; },
    setReadStalls: (value: boolean) => { readStalls = value; },
    setAuthFails: (value: boolean) => { authFails = value; },
    setAuthAllowed: (value: boolean) => { authAllowed = value; },
    setPrincipal: (value: TrustedPrincipalV1) => { currentPrincipal = value; },
    setTickingClock: (value: boolean) => { tickingClock = value; },
    ratePolicyDefaultedCount: () => ratePolicyDefaultedCount,
    timeoutNext: (operation: WorkerDeadlineOperationV1) => { timedOutOperations.add(operation); },
    holdLeasePublish: (value: boolean) => { holdLeasePublish = value; },
    waitForLeasePublishStarted: async () => {
      if (leasePublishStarted) return;
      await new Promise<void>((resolve) => { leasePublishStartedWaiter = resolve; });
    },
    releaseLeasePublish: () => { holdLeasePublish = false; releaseLease?.(); releaseLease = null; },
    setLeasePublishDelay: (value: number) => { leasePublishDelayMs = value; },
  };
}

function getLicense(
  worker: ReturnType<typeof createLicenseWorkerV1>,
  resolveDelayMs = 0,
): Promise<Response> {
  const headers = resolveDelayMs > 0 ? { "x-test-resolve-delay-ms": String(resolveDelayMs) } : undefined;
  return worker.fetch(new Request("https://licensing-worker.test/v1/admin/license", { headers }));
}

describe("LIC-004 package worker primitives", () => {
  it("delegates all admin subpaths while keeping signup and auth routes exact", async () => {
    const pair = await globalThis.crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"],
    );
    const snapshot = await signedSnapshot(pair.privateKey);
    const { worker } = harness(snapshot, pair.publicKey);
    const fetchPath = (path: string) => worker.fetch(new Request(`https://licensing-worker.test${path}`));

    expect((await fetchPath("/v1/admin/license")).status).toBe(200);
    expect((await fetchPath("/v1/admin/accounts/org-a/users")).status).toBe(503);
    expect((await fetchPath("/v1/admin/session/enrollment/confirm")).status).toBe(503);
    expect((await fetchPath("/v1/admin/webhook")).status).toBe(404);
    expect((await fetchPath("/v1/adminish/accounts/org-a")).status).toBe(404);
    expect((await fetchPath("/v1/signup/checkout/extra")).status).toBe(404);
    expect((await fetchPath("/v1/auth/session/totp/enroll/extra")).status).toBe(404);
  });

  it("enforces exact canonical decimal per-license GCRA limits", () => {
    const limiter = new PerLicenseRateLimiterV1();
    expect(limiter.check("license-a", "2.5", 100).outcome).toBe("ALLOW");
    expect(limiter.check("license-a", "2.5", 100)).toMatchObject({
      outcome: "RATE_LIMITED", retryAfterSeconds: 1,
    });
    expect(limiter.check("license-b", "0.5", 100).outcome).toBe("ALLOW");
    expect(limiter.check("license-b", "0.5", 1_000).outcome).toBe("RATE_LIMITED");
    expect(limiter.check("license-b", "0.5", 2_100).outcome).toBe("ALLOW");
    expect(limiter.check("license-c", "1.0", 0).outcome).toBe("INVALID_POLICY");
    expect(limiter.check("license-c", "0", 0).outcome).toBe("INVALID_POLICY");
  });

  it("fails closed on a monotonic rollback without resetting the license bucket", () => {
    const limiter = new PerLicenseRateLimiterV1();
    expect(limiter.check("license-a", "1", 1_000).outcome).toBe("ALLOW");
    expect(limiter.check("license-a", "1", 999)).toMatchObject({
      outcome: "RATE_LIMITED", retryAfterSeconds: 1,
    });
    expect(limiter.check("license-a", "1", 2_000).outcome).toBe("ALLOW");
  });

  it("caps positive and negative cached decisions and invalidates changed identity", () => {
    const cache = new LicenseDecisionCacheV1();
    const fingerprint = "a".repeat(64);
    cache.put("org/audience/device", "1", fingerprint, fakeResult("VERIFIED_ONLINE", true), 100);
    expect(cache.get("org/audience/device", "1", fingerprint, 60_099)).not.toBeNull();
    expect(cache.get("org/audience/device", "1", fingerprint, 60_100)).toBeNull();

    cache.put("org/audience/device", "2", fingerprint, fakeResult("DENIED", false), 100);
    expect(cache.get("org/audience/device", "2", fingerprint, 5_099)).not.toBeNull();
    expect(cache.get("org/audience/device", "2", fingerprint, 5_100)).toBeNull();

    cache.put("org/audience/device", "3", fingerprint, fakeResult("VERIFIED_ONLINE", true), 100);
    expect(cache.get("org/audience/device", "4", fingerprint, 101)).toBeNull();
    cache.put("org/audience/device", "5", fingerprint, fakeResult("VERIFIED_ONLINE", true), 100);
    expect(cache.get("org/audience/device", "5", "b".repeat(64), 101)).toBeNull();
  });

  it("accepts LIC-001 revisions through its full 64-digit wire limit", () => {
    const cache = new LicenseDecisionCacheV1();
    const revision = "1234567890123456789012345678901234567890";
    const fingerprint = "e".repeat(64);
    expect(cache.reserve("long-revision", 100)).toBe(true);
    expect(cache.put("long-revision", revision, fingerprint,
      fakeResult("VERIFIED_ONLINE", true), 100)).toBe(true);
    expect(cache.get("long-revision", revision, fingerprint, 101)).not.toBeNull();
  });

  it("reserves bounded cache capacity before a new online decision", () => {
    const cache = new LicenseDecisionCacheV1();
    const fingerprint = "c".repeat(64);
    for (let index = 0; index < 4_096; index += 1) {
      const scope = `capacity-${index}`;
      expect(cache.reserve(scope, 100)).toBe(true);
      expect(cache.put(scope, "1", fingerprint, fakeResult("VERIFIED_ONLINE", true), 100)).toBe(true);
    }
    expect(cache.reserve("capacity-overflow", 100)).toBe(false);
    cache.invalidate("capacity-0");
    expect(cache.reserve("capacity-overflow", 100)).toBe(true);
    cache.releaseReservation("capacity-overflow");
  });

  it("does not advance LIC-001 when the decision cache is full, so a retry can succeed", async () => {
    const pair = await globalThis.crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"],
    );
    const snapshot = await signedSnapshot(pair.privateKey);
    const test = harness(snapshot, pair.publicKey);
    const fingerprint = "d".repeat(64);
    for (let index = 0; index < 4_096; index += 1) {
      const scope = `capacity-full-${index}`;
      test.cache.reserve(scope, 1_000);
      test.cache.put(scope, "1", fingerprint, fakeResult("VERIFIED_ONLINE", true), 1_000);
    }
    expect((await getLicense(test.worker)).status).toBe(402);
    expect(test.leases.at(-1)).toMatchObject({ eligible: false, expiresAtMonotonicMs: null });

    test.cache.invalidate("capacity-full-0");
    expect((await getLicense(test.worker)).status).toBe(200);
    expect(test.leases.at(-1)).toMatchObject({ eligible: true, reason: "VERIFIED_ONLINE" });
  });

  it("serializes overlapping cold and warm evaluations per identity scope", async () => {
    const pair = await globalThis.crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"],
    );
    const snapshot = await signedSnapshot(pair.privateKey, {
      limits: { api_rate_limit_rps: "1000" },
    });
    const test = harness(snapshot, pair.publicKey);
    test.setTickingClock(true);

    const cold = await Promise.all([
      getLicense(test.worker, 30),
      getLicense(test.worker, 0),
    ]);
    expect(cold.map((item) => item.status)).toEqual([200, 200]);
    expect((await getLicense(test.worker)).status).toBe(200);

    const warm = await Promise.all([
      getLicense(test.worker, 30),
      getLicense(test.worker, 0),
    ]);
    expect(warm.map((item) => item.status)).toEqual([200, 200]);
    expect((await getLicense(test.worker)).status).toBe(200);
  });

  it("times out a stalled read without changing a lease and releases the scope for retry", async () => {
    const pair = await globalThis.crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"],
    );
    const snapshot = await signedSnapshot(pair.privateKey, {
      limits: { api_rate_limit_rps: "1000" },
    });
    const test = harness(snapshot, pair.publicKey);
    expect((await getLicense(test.worker)).status).toBe(200);
    const priorLeaseCount = test.leases.length;

    test.setReadStalls(true);
    test.timeoutNext("license-read");
    expect((await getLicense(test.worker)).status).toBe(402);
    expect(test.leases).toHaveLength(priorLeaseCount);

    test.setReadStalls(false);
    test.setTime(10);
    expect((await getLicense(test.worker)).status).toBe(200);
  });

  it("bounds a stalled introspection body before locking so later same-scope reads proceed", async () => {
    const pair = await globalThis.crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"],
    );
    const snapshot = await signedSnapshot(pair.privateKey, {
      limits: { api_rate_limit_rps: "1000" },
    });
    const test = harness(snapshot, pair.publicKey);
    let cancelled = false;
    const body = new ReadableStream<Uint8Array>({
      pull(controller) { controller.enqueue(new TextEncoder().encode("{")); },
      cancel() { cancelled = true; },
    }, { highWaterMark: 0 });
    const request = new Request("https://licensing-worker.test/v1/auth/introspect", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body,
      duplex: "half",
    } as RequestInit & { duplex: "half" });
    test.timeoutNext("introspection-body");
    expect((await test.worker.fetch(request)).status).toBe(400);
    expect(cancelled).toBe(true);
    expect((await getLicense(test.worker)).status).toBe(200);
  });

  it("caps queued work per scope and releases the lock in finally", async () => {
    const pair = await globalThis.crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"],
    );
    const snapshot = await signedSnapshot(pair.privateKey, {
      limits: { api_rate_limit_rps: "1000" },
    });
    const test = harness(snapshot, pair.publicKey);
    test.holdLeasePublish(true);
    const active = getLicense(test.worker);
    await test.waitForLeasePublishStarted();
    const queued = Array.from({ length: 31 }, () => getLicense(test.worker));
    const overflow = getLicense(test.worker);
    const overflowStatus = await Promise.race([
      overflow.then((result) => result.status),
      new Promise<number>((resolve) => setTimeout(() => resolve(0), 3_000)),
    ]);
    expect(overflowStatus).toBe(429);
    test.releaseLeasePublish();
    await active;
    await Promise.all(queued);
    test.setTime(1_000);
    expect((await getLicense(test.worker)).status).toBe(200);
  });

  it("scopes ineligible leases to org, audience and device", async () => {
    const pair = await globalThis.crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"],
    );
    const snapshot = await signedSnapshot(pair.privateKey, {
      limits: { api_rate_limit_rps: "1000" },
    });
    const test = harness(snapshot, pair.publicKey);
    const desktop = principal(snapshot.orgId, snapshot.deviceId);
    expect((await getLicense(test.worker)).status).toBe(200);

    test.setTime(10);
    test.setPrincipal({ ...desktop, deviceId: "different-device" });
    expect((await getLicense(test.worker)).status).toBe(402);
    test.setTime(20);
    test.setPrincipal({ ...desktop, audience: "web", deviceId: "web-device" });
    expect((await getLicense(test.worker)).status).toBe(402);
    test.setTime(30);
    test.setPrincipal(desktop);
    expect((await getLicense(test.worker)).status).toBe(200);

    const desktopLeases = test.leases.filter((lease) => lease.audience === desktop.audience
      && lease.deviceId === desktop.deviceId);
    expect(desktopLeases.length).toBe(2);
    expect(desktopLeases.every((lease) => lease.eligible)).toBe(true);
    expect(test.leases).toContainEqual(expect.objectContaining({
      audience: "licensing-worker", deviceId: "different-device", eligible: false,
    }));
    expect(test.leases).toContainEqual(expect.objectContaining({
      audience: "web", deviceId: "web-device", eligible: false,
    }));
  });

  it("authenticates before reading an introspection body and stops at its byte cap", async () => {
    const pair = await globalThis.crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"],
    );
    const snapshot = await signedSnapshot(pair.privateKey);
    const test = harness(snapshot, pair.publicKey);
    let unauthorizedPulls = 0;
    const unauthorizedBody = new ReadableStream<Uint8Array>({
      pull(controller) {
        unauthorizedPulls += 1;
        controller.enqueue(new Uint8Array(1024));
      },
    }, { highWaterMark: 0 });
    test.setAuthAllowed(false);
    const unauthorizedRequest = new Request("https://licensing-worker.test/v1/auth/introspect", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: unauthorizedBody,
      duplex: "half",
    } as RequestInit & { duplex: "half" });
    expect((await test.worker.fetch(unauthorizedRequest)).status).toBe(403);
    expect(unauthorizedPulls).toBe(0);

    test.setAuthAllowed(true);
    let authorizedPulls = 0;
    let cancelled = false;
    const oversizedBody = new ReadableStream<Uint8Array>({
      pull(controller) {
        authorizedPulls += 1;
        controller.enqueue(new Uint8Array(1024));
      },
      cancel() { cancelled = true; },
    }, { highWaterMark: 0 });
    const oversizedRequest = new Request("https://licensing-worker.test/v1/auth/introspect", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: oversizedBody,
      duplex: "half",
    } as RequestInit & { duplex: "half" });
    expect((await test.worker.fetch(oversizedRequest)).status).toBe(400);
    expect(authorizedPulls).toBe(2);
    expect(cancelled).toBe(true);
  });

  it("defaults an omitted rate policy without denying entitlement and limits negative outcomes", async () => {
    const pair = await globalThis.crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"],
    );
    const active = await signedSnapshot(pair.privateKey, { limits: { connectors: "3" } });
    const activeTest = harness(active, pair.publicKey);
    const activeResponse = await getLicense(activeTest.worker);
    expect(activeResponse.status).toBe(200);
    expect(activeTest.ratePolicyDefaultedCount()).toBe(1);
    expect(activeTest.leases.at(-1)).toMatchObject({ eligible: true, reason: "VERIFIED_ONLINE" });
    expect((await getLicense(activeTest.worker)).status).toBe(429);
    expect(activeTest.leases.at(-1)).toMatchObject({ eligible: true, reason: "VERIFIED_ONLINE" });

    const paused = await signedSnapshot(pair.privateKey, {
      status: "PAUSED", limits: { api_rate_limit_rps: "1" },
    });
    const pausedTest = harness(paused, pair.publicKey);
    expect((await getLicense(pausedTest.worker)).status).toBe(402);
    const throttledNegative = await getLicense(pausedTest.worker);
    expect(throttledNegative.status).toBe(429);
    expect(throttledNegative.headers.get("Retry-After")).toBe("1");
    expect(pausedTest.leases.at(-1)).toMatchObject({ eligible: false });

    const badRatePolicy = await signedSnapshot(pair.privateKey, {
      limits: { api_rate_limit_rps: "1.0" },
    });
    const badRateTest = harness(badRatePolicy, pair.publicKey);
    expect((await getLicense(badRateTest.worker)).status).toBe(402);
    expect(badRateTest.leases.at(-1)).toMatchObject({ eligible: true, reason: "VERIFIED_ONLINE" });
  });

  it("publishes an eligibility lease bounded by cache age and term end", async () => {
    const pair = await globalThis.crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"],
    );
    const snapshot = await signedSnapshot(pair.privateKey, {
      termEndUtcNs: (BASE_NS + 10n * NS_PER_MS).toString(),
    });
    const test = harness(snapshot, pair.publicKey);
    const response = await getLicense(test.worker);
    expect(response.status).toBe(200);
    expect(test.leases.at(-1)).toMatchObject({
      schemaVersion: 1,
      orgId: snapshot.orgId,
      licenseId: snapshot.licenseId,
      eligible: true,
      expiresAtMonotonicMs: 1_010,
      reason: "VERIFIED_ONLINE",
    });
  });

  it("revokes the background lease on uncertain reads and after the positive ceiling", async () => {
    const pair = await globalThis.crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"],
    );
    const snapshot = await signedSnapshot(pair.privateKey);
    const test = harness(snapshot, pair.publicKey);
    expect((await getLicense(test.worker)).status).toBe(200);
    test.setReadFails(true);
    expect((await getLicense(test.worker)).status).toBe(402);
    expect(test.leases.at(-1)).toMatchObject({ eligible: false, expiresAtMonotonicMs: null, reason: "UNKNOWN" });

    test.setReadFails(false);
    test.setTime(100);
    expect((await getLicense(test.worker)).status).toBe(200);
    test.setTime(60_000);
    expect((await getLicense(test.worker)).status).toBe(402);
    expect(test.leases.at(-1)).toMatchObject({ eligible: false, expiresAtMonotonicMs: null });
  });

  it("publishes false on authorization uncertainty and never echoes upstream errors", async () => {
    const pair = await globalThis.crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"],
    );
    const snapshot = await signedSnapshot(pair.privateKey);
    const test = harness(snapshot, pair.publicKey);
    test.setAuthFails(true);
    const response = await getLicense(test.worker);
    expect(response.status).toBe(403);
    expect(await response.text()).not.toContain("synthetic-auth-failure");
    expect(test.leases.at(-1)).toMatchObject({ eligible: false, reason: "UNKNOWN" });
  });

  it("does not revoke a shared binding lease for an explicit authorization denial", async () => {
    const pair = await globalThis.crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"],
    );
    const snapshot = await signedSnapshot(pair.privateKey, {
      limits: { api_rate_limit_rps: "1000" },
    });
    const test = harness(snapshot, pair.publicKey);
    expect((await getLicense(test.worker)).status).toBe(200);
    const priorLeaseCount = test.leases.length;
    test.setTime(10);
    test.setAuthAllowed(false);
    expect((await getLicense(test.worker)).status).toBe(403);
    expect(test.leases).toHaveLength(priorLeaseCount);
    expect(test.leases.at(-1)).toMatchObject({ eligible: true, reason: "VERIFIED_ONLINE" });
  });

  it("samples the limiter clock after a slow lease publish across bindings", async () => {
    const pair = await globalThis.crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"],
    );
    const licenseId = `shared-license-${globalThis.crypto.randomUUID()}`;
    const orgId = `shared-org-${globalThis.crypto.randomUUID()}`;
    const deviceA = `device-a-${globalThis.crypto.randomUUID()}`;
    const deviceB = `device-b-${globalThis.crypto.randomUUID()}`;
    const snapshotA = await signedSnapshot(pair.privateKey, {
      orgId, licenseId, deviceId: deviceA, limits: { api_rate_limit_rps: "1000" },
    });
    const snapshotB = await signedSnapshot(pair.privateKey, {
      orgId, licenseId, deviceId: deviceB, limits: { api_rate_limit_rps: "1000" },
    });
    const sharedLimiter = new PerLicenseRateLimiterV1();
    const testA = harness(snapshotA, pair.publicKey, sharedLimiter);
    const testB = harness(snapshotB, pair.publicKey, sharedLimiter);
    testA.holdLeasePublish(true);
    const responseA = getLicense(testA.worker);
    await testA.waitForLeasePublishStarted();
    expect((await getLicense(testB.worker)).status).toBe(200);
    testA.setTime(40);
    testA.releaseLeasePublish();
    expect((await responseA).status).toBe(200);
  });

  it("uses only verified snapshot policy and identifiers for shared rate limiting", async () => {
    const trustedKeys = await globalThis.crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"],
    );
    const attackerKeys = await globalThis.crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"],
    );
    const licenseId = `victim-license-${globalThis.crypto.randomUUID()}`;
    const victim = await signedSnapshot(trustedKeys.privateKey, {
      licenseId, limits: { api_rate_limit_rps: "1000" },
    });
    const sharedLimiter = new PerLicenseRateLimiterV1();
    const victimTest = harness(victim, trustedKeys.publicKey, sharedLimiter);
    expect((await getLicense(victimTest.worker)).status).toBe(200);

    const forged = await signedSnapshot(attackerKeys.privateKey, {
      licenseId,
      orgId: `attacker-org-${globalThis.crypto.randomUUID()}`,
      limits: { api_rate_limit_rps: "0.000001" },
    });
    const attackerTest = harness(forged, trustedKeys.publicKey, sharedLimiter);
    expect((await getLicense(attackerTest.worker)).status).toBe(402);
    expect((await getLicense(attackerTest.worker)).status).toBe(429);
    victimTest.setTime(1);
    expect((await getLicense(victimTest.worker)).status).toBe(200);
  });

  it("rereads a stale straddling revision without latching rollback or changing its lease", async () => {
    const pair = await globalThis.crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"],
    );
    const revisionOne = await signedSnapshot(pair.privateKey, {
      limits: { api_rate_limit_rps: "1000" },
    });
    const revisionTwo = await signedSnapshot(pair.privateKey, {
      ...revisionOne,
      subscriptionRevision: "2",
      signature: revisionOne.signature,
    });
    const test = harness(revisionOne, pair.publicKey);
    const readGate: { release?: () => void; signalStarted?: () => void } = {};
    const slowReadStarted = new Promise<void>((resolve) => { readGate.signalStarted = resolve; });
    const slowReadGate = new Promise<void>((resolve) => { readGate.release = resolve; });
    let readNumber = 0;
    test.setReadHook(async (current) => {
      readNumber += 1;
      if (readNumber === 1) {
        readGate.signalStarted?.();
        await slowReadGate;
        return revisionOne;
      }
      return current;
    });

    const staleRequest = getLicense(test.worker);
    await slowReadStarted;
    test.setSnapshot(revisionTwo);
    const newerResponse = await getLicense(test.worker);
    expect(newerResponse.status).toBe(200);
    expect((await newerResponse.json() as { license: LicenseSnapshotV1 }).license.subscriptionRevision).toBe("2");
    const leasesAfterNewerEvaluation = test.leases.length;

    test.setTime(10);
    readGate.release?.();
    const staleResponse = await staleRequest;
    expect(staleResponse.status).toBe(200);
    expect((await staleResponse.json() as { license: LicenseSnapshotV1 }).license.subscriptionRevision).toBe("2");
    expect(readNumber).toBe(3);
    expect(test.leases).toHaveLength(leasesAfterNewerEvaluation);
    test.setTime(20);
    expect((await getLicense(test.worker)).status).toBe(200);
  });

  it("rejects unsigned extension fields before serializing a snapshot", async () => {
    const pair = await globalThis.crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"],
    );
    const signed = await signedSnapshot(pair.privateKey);
    const secretSentinel = "unsigned-secret-field-sentinel";
    const extended = { ...signed, internalBillingKey: secretSentinel } as LicenseSnapshotV1;
    const test = harness(extended, pair.publicKey);
    const response = await getLicense(test.worker);
    expect(response.status).toBe(402);
    const body = await response.text();
    expect(body).not.toContain(secretSentinel);
    expect(body).not.toContain("internalBillingKey");
  });
});
