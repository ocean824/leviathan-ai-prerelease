import type { EntitlementResultV1, LicenseSnapshotV1 } from "../entitlement/models.js";

export const POSITIVE_DECISION_CACHE_TTL_MS_V1 = 60_000;
export const NEGATIVE_DECISION_CACHE_TTL_MS_V1 = 5_000;
const MAX_CACHE_ENTRIES = 4096;
// LIC-001 accepts up to 64 decimal digits; the worker cache must not narrow it.
const REVISION = /^(0|[1-9][0-9]{0,63})$/;
const SNAPSHOT_FINGERPRINT = /^[0-9a-f]{64}$/;

interface CacheEntryV1 {
  readonly revision: string;
  readonly snapshotFingerprint: string;
  readonly storedAtMonotonicMs: number;
  readonly expiresAtMonotonicMs: number;
  readonly result: EntitlementResultV1;
  readonly snapshot?: LicenseSnapshotV1;
}

export interface LatestLicenseDecisionV1 {
  readonly revision: string;
  readonly snapshotFingerprint: string;
  readonly result: EntitlementResultV1;
  readonly snapshot?: LicenseSnapshotV1;
}

function validTime(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function validScope(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 512;
}

/**
 * Isolate-local decision memoization. Callers must compare a canonical digest of
 * every signed snapshot field and its signature; the cache never verifies a
 * changed snapshot and never becomes an offline authority by itself.
 */
export class LicenseDecisionCacheV1 {
  readonly #entries = new Map<string, CacheEntryV1>();
  readonly #reservations = new Set<string>();

  /**
   * Reserve admission before an ONLINE evaluation can advance LIC-001's
   * monotonic authority state. Reservations prevent concurrent scopes from
   * overcommitting the bounded cache.
   */
  reserve(scope: string, nowMonotonicMs: number): boolean {
    if (!validScope(scope) || !validTime(nowMonotonicMs)
        || nowMonotonicMs > Number.MAX_SAFE_INTEGER - POSITIVE_DECISION_CACHE_TTL_MS_V1) {
      return false;
    }
    for (const [key, entry] of this.#entries) {
      if (nowMonotonicMs >= entry.expiresAtMonotonicMs) this.#entries.delete(key);
    }
    if (this.#entries.has(scope) || this.#reservations.has(scope)) return true;
    if (this.#entries.size + this.#reservations.size >= MAX_CACHE_ENTRIES) return false;
    this.#reservations.add(scope);
    return true;
  }

  releaseReservation(scope: string): void {
    if (validScope(scope)) this.#reservations.delete(scope);
  }

  get(
    scope: string,
    revision: string,
    snapshotFingerprint: string,
    nowMonotonicMs: number,
  ): EntitlementResultV1 | null {
    if (!validScope(scope) || !REVISION.test(revision)
        || !SNAPSHOT_FINGERPRINT.test(snapshotFingerprint)
        || !validTime(nowMonotonicMs)) return null;
    const entry = this.#entries.get(scope);
    if (!entry) return null;
    if (entry.revision !== revision || entry.snapshotFingerprint !== snapshotFingerprint
        || nowMonotonicMs < entry.storedAtMonotonicMs
        || nowMonotonicMs >= entry.expiresAtMonotonicMs) {
      this.#entries.delete(scope);
      return null;
    }
    return entry.result;
  }

  expiresAtMonotonicMs(
    scope: string,
    revision: string,
    snapshotFingerprint: string,
  ): number | null {
    if (!validScope(scope) || !REVISION.test(revision)
        || !SNAPSHOT_FINGERPRINT.test(snapshotFingerprint)) return null;
    const entry = this.#entries.get(scope);
    if (!entry || entry.revision !== revision
        || entry.snapshotFingerprint !== snapshotFingerprint) return null;
    return entry.expiresAtMonotonicMs;
  }

  /** Returns the current unexpired decision metadata without evaluating it. */
  getLatest(scope: string, nowMonotonicMs: number): LatestLicenseDecisionV1 | null {
    if (!validScope(scope) || !validTime(nowMonotonicMs)) return null;
    const entry = this.#entries.get(scope);
    if (!entry) return null;
    if (nowMonotonicMs < entry.storedAtMonotonicMs
        || nowMonotonicMs >= entry.expiresAtMonotonicMs) {
      this.#entries.delete(scope);
      return null;
    }
    return Object.freeze({
      revision: entry.revision,
      snapshotFingerprint: entry.snapshotFingerprint,
      result: entry.result,
      ...(entry.snapshot ? { snapshot: entry.snapshot } : {}),
    });
  }

  put(
    scope: string,
    revision: string,
    snapshotFingerprint: string,
    result: EntitlementResultV1,
    nowMonotonicMs: number,
    snapshot?: LicenseSnapshotV1,
  ): boolean {
    if (!validScope(scope) || !REVISION.test(revision)
        || !SNAPSHOT_FINGERPRINT.test(snapshotFingerprint)
        || !validTime(nowMonotonicMs)
        || !result || result.decision?.schemaVersion !== 1
        || result.state?.schemaVersion !== 1
        || typeof result.decision.authorizesGatedEffects !== "boolean") return false;

    const positive = result.decision.outcome === "VERIFIED_ONLINE"
      && result.decision.authorizesGatedEffects;
    const ttlMs = positive
      ? POSITIVE_DECISION_CACHE_TTL_MS_V1
      : NEGATIVE_DECISION_CACHE_TTL_MS_V1;
    if (nowMonotonicMs > Number.MAX_SAFE_INTEGER - ttlMs) {
      this.#reservations.delete(scope);
      return false;
    }
    if (!this.#entries.has(scope) && !this.#reservations.has(scope)) {
      if (!this.reserve(scope, nowMonotonicMs)) return false;
    }
    this.#reservations.delete(scope);
    this.#entries.set(scope, Object.freeze({
      revision,
      snapshotFingerprint,
      storedAtMonotonicMs: nowMonotonicMs,
      expiresAtMonotonicMs: nowMonotonicMs + ttlMs,
      result,
      ...(snapshot ? { snapshot } : {}),
    }));
    return true;
  }

  invalidate(scope: string): void {
    if (validScope(scope)) {
      this.#entries.delete(scope);
      this.#reservations.delete(scope);
    }
  }

  clear(): void {
    this.#entries.clear();
    this.#reservations.clear();
  }
}
