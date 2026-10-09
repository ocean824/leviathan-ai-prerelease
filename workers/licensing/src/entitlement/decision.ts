import type {
  EntitlementDecisionV1, EntitlementInputV1, EntitlementReasonV1,
  EntitlementResultV1, EntitlementStateV1, GracePolicyV1,
  LicenseSnapshotV1,
} from "./models.js";

const NS_PER_MS = 1_000_000n;
const NS_PER_SECOND = 1_000_000_000n;
const POSITIVE_CACHE_MS = 60_000;
const NEGATIVE_CACHE_MS = 5_000;
const unsignedDecimal = /^(0|[1-9][0-9]*)$/;
const exactNonnegativeDecimal = /^(0|[1-9][0-9]*)(\.[0-9]+)?$/;
const base64url = /^[A-Za-z0-9_-]+$/;
const statuses = new Set([
  "ACTIVE", "PAST_DUE", "PAUSED", "SUSPENDED", "CANCELED", "EXPIRED",
]);

interface InternalState {
  readonly scope: string | null;
  readonly generation: number;
  readonly highestRevision: bigint | null;
  readonly positiveSnapshot: LicenseSnapshotV1 | null;
  readonly onlineAtMs: number | null;
  readonly onlineWallUtcNs: bigint | null;
  readonly negativeUntilMs: number | null;
  readonly lastMonotonicMs: number | null;
  readonly lastWallUtcNs: bigint | null;
}

const internals = new WeakMap<EntitlementStateV1, InternalState>();
interface Authority {
  generation: number;
  highestRevision: bigint | null;
  lastMonotonicMs: number | null;
  lastWallUtcNs: bigint | null;
  latched: boolean;
}
/** Process-wide within one Worker isolate; no old handle can bypass a later observation. */
const authorities = new Map<string, Authority>();
function authorityFor(scope: string): Authority {
  let authority = authorities.get(scope);
  if (!authority) {
    authority = { generation: 0, highestRevision: null,
      lastMonotonicMs: null, lastWallUtcNs: null, latched: false };
    authorities.set(scope, authority);
  }
  return authority;
}
function scopeOf(input: EntitlementInputV1): string {
  return JSON.stringify([input.expectedOrgId, input.expectedAudience, input.expectedDeviceId]);
}
function observe(authority: Authority, nowMs: number, nowNs: bigint): void {
  if (authority.lastMonotonicMs === null || nowMs > authority.lastMonotonicMs) {
    authority.lastMonotonicMs = nowMs;
  }
  if (authority.lastWallUtcNs === null || nowNs > authority.lastWallUtcNs) {
    authority.lastWallUtcNs = nowNs;
  }
}
function latch(authority: Authority, revision: bigint | null = null): void {
  if (revision !== null && (authority.highestRevision === null
      || revision > authority.highestRevision)) authority.highestRevision = revision;
  authority.generation++;
  authority.latched = true;
}
const empty: InternalState = Object.freeze({
  scope: null,
  generation: 0,
  highestRevision: null,
  positiveSnapshot: null,
  onlineAtMs: null,
  onlineWallUtcNs: null,
  negativeUntilMs: null,
  lastMonotonicMs: null,
  lastWallUtcNs: null,
});

function stateOf(value: InternalState): EntitlementStateV1 {
  const handle: EntitlementStateV1 = Object.freeze({ schemaVersion: 1 });
  internals.set(handle, Object.freeze(value));
  return handle;
}

export function createEntitlementStateV1(): EntitlementStateV1 {
  return stateOf(empty);
}

function decimal(value: unknown, maxLength = 64): value is string {
  return typeof value === "string" && value.length <= maxLength && unsignedDecimal.test(value);
}

function label(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 256
    && !/[\u0000-\u001f\u007f]/.test(value);
}

function entries<T>(value: unknown, isValue: (item: unknown) => item is T): [string, T][] {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError("Invalid entitlement map");
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new TypeError("Invalid entitlement map prototype");
  }
  const pairs = Object.entries(value);
  if (pairs.length > 256 || pairs.some(([key, item]) => !label(key) || !isValue(item))) {
    throw new TypeError("Invalid entitlement map entry");
  }
  return (pairs as [string, T][]).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0);
}

/** Canonical UTF-8 bytes for signing. The signature value itself is excluded. */
export function canonicalLicenseSnapshotV1(snapshot: LicenseSnapshotV1): Uint8Array<ArrayBuffer> {
  if (!snapshot || snapshot.schemaVersion !== 1 || !label(snapshot.orgId)
      || !label(snapshot.licenseId) || !decimal(snapshot.subscriptionRevision)
      || !statuses.has(snapshot.status)
      || !decimal(snapshot.termStartUtcNs) || !decimal(snapshot.termEndUtcNs)
      || !decimal(snapshot.issuedAtUtcNs) || !decimal(snapshot.lastOnlineVerifiedUtcNs)
      || !label(snapshot.audience) || !label(snapshot.deviceId)
      || !label(snapshot.signingKeyId)
      || !snapshot.signature || snapshot.signature.algorithm !== "ECDSA_P256_SHA256") {
    throw new TypeError("Invalid LicenseSnapshotV1");
  }
  const features = entries(snapshot.features, (item): item is boolean => typeof item === "boolean");
  const limits = entries(snapshot.limits, (item): item is string =>
    typeof item === "string" && item.length <= 64 && exactNonnegativeDecimal.test(item));
  const payload = [
    1, snapshot.orgId, snapshot.licenseId, snapshot.subscriptionRevision,
    snapshot.status, snapshot.termStartUtcNs, snapshot.termEndUtcNs,
    snapshot.issuedAtUtcNs, snapshot.lastOnlineVerifiedUtcNs,
    features, limits, snapshot.audience, snapshot.deviceId,
    snapshot.signingKeyId, snapshot.signature.algorithm,
  ];
  return new Uint8Array(ownBuffer(new TextEncoder().encode(JSON.stringify(payload))));
}

function cloneSnapshot(snapshot: LicenseSnapshotV1): LicenseSnapshotV1 {
  return Object.freeze({
    ...snapshot,
    features: Object.freeze(Object.fromEntries(entries(snapshot.features,
      (item): item is boolean => typeof item === "boolean"))),
    limits: Object.freeze(Object.fromEntries(entries(snapshot.limits,
      (item): item is string => typeof item === "string"))),
    signature: Object.freeze({ ...snapshot.signature }),
  });
}

function signatureBytes(value: string): Uint8Array | null {
  if (!base64url.test(value) || value.length !== 86) return null;
  try {
    const binary = atob(value.replace(/-/g, "+").replace(/_/g, "/") + "==");
    if (binary.length !== 64) return null;
    return Uint8Array.from(binary, (char) => char.charCodeAt(0));
  } catch {
    return null;
  }
}

function ownBuffer(bytes: Uint8Array): ArrayBuffer {
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  return buffer;
}

async function verifySnapshot(
  snapshot: LicenseSnapshotV1,
  signingKeys: ReadonlyMap<string, CryptoKey>,
): Promise<EntitlementReasonV1 | null> {
  let bytes: Uint8Array;
  try {
    bytes = canonicalLicenseSnapshotV1(snapshot);
  } catch {
    return "INVALID_SNAPSHOT";
  }
  let key: CryptoKey | undefined;
  try {
    key = signingKeys.get(snapshot.signingKeyId);
    if (!key || key.type !== "public" || key.algorithm.name !== "ECDSA"
        || (key.algorithm as EcKeyAlgorithm).namedCurve !== "P-256") {
      return "TRUST_KEY_UNAVAILABLE";
    }
  } catch {
    return "TRUST_KEY_UNAVAILABLE";
  }
  const signature = signatureBytes(snapshot.signature.value);
  if (!signature) return "INVALID_SIGNATURE";
  try {
    return await globalThis.crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" }, key, ownBuffer(signature), ownBuffer(bytes),
    ) ? null : "INVALID_SIGNATURE";
  } catch {
    return "INVALID_SIGNATURE";
  }
}

function decision(
  outcome: EntitlementDecisionV1["outcome"],
  reason: EntitlementReasonV1,
  expiresAtUtcNs: bigint | null = null,
): EntitlementDecisionV1 {
  return Object.freeze({
    schemaVersion: 1,
    outcome,
    reason,
    expiresAtUtcNs: expiresAtUtcNs?.toString() ?? null,
    authorizesGatedEffects: outcome === "VERIFIED_ONLINE",
  });
}

function result(
  verdict: EntitlementDecisionV1,
  internal: InternalState,
): EntitlementResultV1 {
  return Object.freeze({ decision: verdict, state: stateOf(internal) });
}

function blocked(
  reason: EntitlementReasonV1,
  prior: InternalState,
  nowMs: number | null = null,
  nowNs: bigint | null = null,
): EntitlementResultV1 {
  const authority = prior.scope === null ? null : authorityFor(prior.scope);
  if (authority) {
    observe(authority, nowMs ?? authority.lastMonotonicMs ?? 0,
      nowNs ?? authority.lastWallUtcNs ?? 0n);
    if (reason === "CLOCK_ROLLBACK" || reason === "INVALID_SIGNATURE"
        || reason === "REVISION_ROLLBACK" || reason === "TERM_INVALID"
        || reason === "TERM_EXPIRED" || reason === "TRUST_KEY_UNAVAILABLE"
        || reason === "ONLINE_ANCHOR_STALE") {
      latch(authority, prior.highestRevision);
    }
  }
  return result(decision("DENIED", reason), {
    scope: prior.scope,
    generation: authority?.generation ?? prior.generation,
    highestRevision: authority?.highestRevision ?? prior.highestRevision,
    positiveSnapshot: null,
    onlineAtMs: null,
    onlineWallUtcNs: null,
    negativeUntilMs: null,
    lastMonotonicMs: nowMs,
    lastWallUtcNs: nowNs,
  });
}

function superseded(scope: string, authority: Authority): EntitlementResultV1 {
  return result(decision("DENIED", "CACHE_CORRUPT"), {
    ...empty,
    scope,
    generation: authority.generation,
    highestRevision: authority.highestRevision,
    lastMonotonicMs: authority.lastMonotonicMs,
    lastWallUtcNs: authority.lastWallUtcNs,
  });
}

function validGrace(policy: GracePolicyV1 | undefined): boolean {
  return policy !== undefined && policy !== null && policy.schemaVersion === 1
    && Number.isSafeInteger(policy.maxOfflineSeconds)
    && policy.maxOfflineSeconds > 0;
}

function minimum(a: bigint, b: bigint): bigint { return a < b ? a : b; }
function maximum(a: bigint, b: bigint): bigint { return a > b ? a : b; }

/** Pure decision over signed input, injected clocks, and opaque prior state. */
export async function evaluateEntitlementV1(input: EntitlementInputV1): Promise<EntitlementResultV1> {
  let prior = input?.state === undefined ? empty : internals.get(input.state);
  if (!prior) return blocked("CACHE_CORRUPT", empty);
  if (!input || (input.mode !== "ONLINE" && input.mode !== "OFFLINE")
      || !label(input.expectedOrgId) || !label(input.expectedAudience)
      || !label(input.expectedDeviceId) || !(input.signingKeys instanceof Map)
      || !Number.isSafeInteger(input.nowMonotonicMs) || input.nowMonotonicMs < 0
      || input.nowMonotonicMs > Number.MAX_SAFE_INTEGER - POSITIVE_CACHE_MS
      || !decimal(input.nowWallUtcNs)) {
    return blocked("INVALID_INPUT", prior);
  }
  const nowNs = BigInt(input.nowWallUtcNs);
  const nowMs = input.nowMonotonicMs;
  const scope = scopeOf(input);
  const authority = authorityFor(scope);
  if (prior.scope !== null && prior.scope !== scope) {
    if (input.mode === "OFFLINE") return superseded(scope, authority);
    prior = empty;
  }
  if (prior.scope === null) prior = { ...prior, scope,
    generation: authority.generation, highestRevision: authority.highestRevision };
  if ((authority.lastMonotonicMs !== null && nowMs < authority.lastMonotonicMs)
      || (authority.lastWallUtcNs !== null && nowNs < authority.lastWallUtcNs)) {
    return blocked("CLOCK_ROLLBACK", prior, nowMs, nowNs);
  }
  observe(authority, nowMs, nowNs);
  if (input.mode === "OFFLINE" && prior.generation !== authority.generation) {
    return superseded(scope, authority);
  }
  prior = { ...prior, highestRevision: authority.highestRevision,
    lastMonotonicMs: authority.lastMonotonicMs,
    lastWallUtcNs: authority.lastWallUtcNs };

  if (input.mode === "ONLINE") {
    if (!input.snapshot) return blocked("INVALID_SNAPSHOT", prior, nowMs, nowNs);
    let snapshot: LicenseSnapshotV1;
    try {
      snapshot = cloneSnapshot(input.snapshot);
    } catch {
      return blocked("INVALID_SNAPSHOT", prior, nowMs, nowNs);
    }
    const verification = await verifySnapshot(snapshot, input.signingKeys);
    if (verification) return blocked(verification, prior, nowMs, nowNs);
    if (snapshot.orgId !== input.expectedOrgId
        || snapshot.audience !== input.expectedAudience
        || snapshot.deviceId !== input.expectedDeviceId) {
      return blocked("BINDING_MISMATCH", prior, nowMs, nowNs);
    }
    const revision = BigInt(snapshot.subscriptionRevision);
    const highWater = authority.highestRevision === null
      ? revision : maximum(authority.highestRevision, revision);
    const termStart = BigInt(snapshot.termStartUtcNs);
    const termEnd = BigInt(snapshot.termEndUtcNs);
    const issued = BigInt(snapshot.issuedAtUtcNs);
    const verified = BigInt(snapshot.lastOnlineVerifiedUtcNs);
    if (verified > nowNs) {
      return blocked("CLOCK_ROLLBACK", { ...prior, highestRevision: highWater }, nowMs, nowNs);
    }
    if (termStart >= termEnd || issued > verified || verified < termStart
        || verified >= termEnd) {
      return blocked("TERM_INVALID", { ...prior, highestRevision: highWater }, nowMs, nowNs);
    }
    if (snapshot.status !== "ACTIVE") {
      latch(authority, revision);
      return result(decision("DENIED", "LICENSE_INACTIVE",
        nowNs + BigInt(NEGATIVE_CACHE_MS) * NS_PER_MS), {
        scope,
        generation: authority.generation,
        highestRevision: authority.highestRevision,
        positiveSnapshot: null,
        onlineAtMs: null,
        onlineWallUtcNs: null,
        negativeUntilMs: nowMs + NEGATIVE_CACHE_MS,
        lastMonotonicMs: nowMs,
        lastWallUtcNs: nowNs,
      });
    }
    if (authority.highestRevision !== null && revision <= authority.highestRevision) {
      return blocked("REVISION_ROLLBACK", prior, nowMs, nowNs);
    }
    if (nowNs >= termEnd) {
      return blocked("TERM_EXPIRED", { ...prior, highestRevision: highWater }, nowMs, nowNs);
    }
    if (nowNs < termStart || nowNs - verified >= BigInt(POSITIVE_CACHE_MS) * NS_PER_MS) {
      return blocked("ONLINE_ANCHOR_STALE", { ...prior, highestRevision: highWater }, nowMs, nowNs);
    }
    authority.highestRevision = revision;
    authority.generation++;
    authority.latched = false;
    return result(decision("VERIFIED_ONLINE", "ONLINE_ACTIVE",
      minimum(termEnd, nowNs + BigInt(POSITIVE_CACHE_MS) * NS_PER_MS)), {
      scope,
      generation: authority.generation,
      highestRevision: authority.highestRevision,
      positiveSnapshot: snapshot,
      onlineAtMs: nowMs,
      onlineWallUtcNs: nowNs,
      negativeUntilMs: null,
      lastMonotonicMs: nowMs,
      lastWallUtcNs: nowNs,
    });
  }

  if (prior.negativeUntilMs !== null) {
    if (nowMs < prior.negativeUntilMs) {
      return result(decision("DENIED", "LICENSE_INACTIVE",
        nowNs + BigInt(prior.negativeUntilMs - nowMs) * NS_PER_MS), {
        ...prior, lastMonotonicMs: nowMs, lastWallUtcNs: nowNs,
      });
    }
    return blocked("CACHE_UNAVAILABLE", prior, nowMs, nowNs);
  }
  if (!prior.positiveSnapshot || prior.onlineAtMs === null
      || prior.onlineWallUtcNs === null) {
    return blocked("CACHE_UNAVAILABLE", prior, nowMs, nowNs);
  }
  const snapshot = prior.positiveSnapshot;
  const verification = await verifySnapshot(snapshot, input.signingKeys);
  if (verification) return blocked(verification, prior, nowMs, nowNs);
  if (prior.generation !== authority.generation) return superseded(scope, authority);
  if ((authority.lastMonotonicMs !== null && nowMs < authority.lastMonotonicMs)
      || (authority.lastWallUtcNs !== null && nowNs < authority.lastWallUtcNs)) {
    return blocked("CLOCK_ROLLBACK", prior, nowMs, nowNs);
  }
  if (snapshot.orgId !== input.expectedOrgId
      || snapshot.audience !== input.expectedAudience
      || snapshot.deviceId !== input.expectedDeviceId) {
    return blocked("BINDING_MISMATCH", prior, nowMs, nowNs);
  }
  const elapsedMs = nowMs - prior.onlineAtMs;
  const trustedNow = maximum(nowNs, prior.onlineWallUtcNs + BigInt(elapsedMs) * NS_PER_MS);
  const termEnd = BigInt(snapshot.termEndUtcNs);
  const updated: InternalState = {
    ...prior, lastMonotonicMs: nowMs, lastWallUtcNs: nowNs,
  };
  if (authority.latched) return superseded(scope, authority);
  if (trustedNow >= termEnd) return blocked("TERM_EXPIRED", prior, nowMs, nowNs);
  if (elapsedMs < POSITIVE_CACHE_MS) {
    return result(decision("VERIFIED_ONLINE", "POSITIVE_CACHE",
      minimum(termEnd, prior.onlineWallUtcNs + BigInt(POSITIVE_CACHE_MS) * NS_PER_MS)), updated);
  }
  if (input.gracePolicy === undefined) {
    return result(decision("UNKNOWN", "GRACE_POLICY_MISSING"), updated);
  }
  if (!validGrace(input.gracePolicy)) return blocked("INVALID_INPUT", prior, nowMs, nowNs);
  const graceNs = BigInt(input.gracePolicy.maxOfflineSeconds) * NS_PER_SECOND;
  if (BigInt(elapsedMs) * NS_PER_MS >= graceNs) {
    return blocked("GRACE_EXPIRED", prior, nowMs, nowNs);
  }
  return result(decision("GRACE_OFFLINE", "OFFLINE_GRACE",
    minimum(termEnd, prior.onlineWallUtcNs + graceNs)), updated);
}
