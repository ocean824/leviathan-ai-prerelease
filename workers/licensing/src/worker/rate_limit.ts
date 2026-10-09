/** Per-license GCRA rate limiter for the synthetic LIC-004 worker boundary. */

const NS_PER_SECOND = 1_000_000_000n;
const NS_PER_MS = 1_000_000n;
const MAX_RATE_TEXT_LENGTH = 18;
const MAX_RATE_DECIMAL_PLACES = 6;
const MAX_RATE_PER_SECOND = 1_000_000n;
const MAX_TRACKED_LICENSES = 4096;
const CANONICAL_DECIMAL = /^(0|[1-9][0-9]*)(?:\.([0-9]*[1-9]))?$/;

export type RateLimitOutcomeV1 = "ALLOW" | "RATE_LIMITED" | "INVALID_POLICY";

export interface RateLimitDecisionV1 {
  readonly schemaVersion: 1;
  readonly outcome: RateLimitOutcomeV1;
  /** Positive whole seconds for Retry-After when rate limited; otherwise null. */
  readonly retryAfterSeconds: number | null;
}

export interface RateLimitClockV1 {
  nowMonotonicMs(): number;
}

interface LicenseRateState {
  readonly theoreticalArrivalTimeNs: bigint;
  readonly intervalNs: bigint;
  readonly lastObservedMs: number;
}

function decision(
  outcome: RateLimitOutcomeV1,
  retryAfterSeconds: number | null = null,
): RateLimitDecisionV1 {
  return Object.freeze({ schemaVersion: 1, outcome, retryAfterSeconds });
}

function rateIntervalNs(value: unknown): bigint | null {
  if (typeof value !== "string" || value.length === 0 || value.length > MAX_RATE_TEXT_LENGTH) {
    return null;
  }
  const match = CANONICAL_DECIMAL.exec(value);
  if (!match) return null;
  const fractional = match[2] ?? "";
  if (fractional.length > MAX_RATE_DECIMAL_PLACES) return null;
  const scale = 10n ** BigInt(fractional.length);
  const numerator = BigInt(match[1]!) * scale + BigInt(fractional || "0");
  if (numerator <= 0n || numerator > MAX_RATE_PER_SECOND * scale) return null;
  // Ceiling keeps the configured rate an upper bound instead of over-admitting.
  return (NS_PER_SECOND * scale + numerator - 1n) / numerator;
}

/**
 * A one-token GCRA bucket with exact decimal rate parsing. State is isolate-local,
 * keyed by the authoritative license ID, and never read from request data.
 */
export class PerLicenseRateLimiterV1 {
  readonly #states = new Map<string, LicenseRateState>();

  /** Samples the trusted clock at the limiter boundary, after any prior awaits. */
  checkWithClock(
    licenseId: string,
    requestsPerSecond: string,
    clock: RateLimitClockV1,
  ): RateLimitDecisionV1 {
    try { return this.check(licenseId, requestsPerSecond, clock.nowMonotonicMs()); }
    catch { return decision("INVALID_POLICY"); }
  }

  check(licenseId: string, requestsPerSecond: string, nowMonotonicMs: number): RateLimitDecisionV1 {
    if (typeof licenseId !== "string" || !/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(licenseId)
        || !Number.isSafeInteger(nowMonotonicMs) || nowMonotonicMs < 0) {
      return decision("INVALID_POLICY");
    }
    const intervalNs = rateIntervalNs(requestsPerSecond);
    if (intervalNs === null) return decision("INVALID_POLICY");
    const observedState = this.#states.get(licenseId);
    if (observedState !== undefined && nowMonotonicMs < observedState.lastObservedMs) {
      nowMonotonicMs = observedState.lastObservedMs;
    }
    const nowNs = BigInt(nowMonotonicMs) * NS_PER_MS;
    for (const [key, tracked] of this.#states) {
      if (nowMonotonicMs >= tracked.lastObservedMs
          && tracked.theoreticalArrivalTimeNs <= nowNs) this.#states.delete(key);
    }
    let state = this.#states.get(licenseId);
    if (state === undefined) {
      if (this.#states.size >= MAX_TRACKED_LICENSES) return decision("RATE_LIMITED", 1);
      state = {
        theoreticalArrivalTimeNs: 0n,
        intervalNs,
        lastObservedMs: nowMonotonicMs,
      };
    } else if (nowMonotonicMs < state.lastObservedMs) {
      return decision("RATE_LIMITED", 1);
    }

    const nextArrivalNs = state.theoreticalArrivalTimeNs <= nowNs
      ? nowNs + intervalNs
      : state.theoreticalArrivalTimeNs + intervalNs;
    if (state.theoreticalArrivalTimeNs > nowNs) {
      const waitNs = state.theoreticalArrivalTimeNs - nowNs;
      const retry = Number((waitNs + NS_PER_SECOND - 1n) / NS_PER_SECOND);
      this.#states.set(licenseId, {
        theoreticalArrivalTimeNs: state.theoreticalArrivalTimeNs,
        intervalNs,
        lastObservedMs: nowMonotonicMs,
      });
      return decision("RATE_LIMITED", Math.max(1, retry));
    }
    this.#states.set(licenseId, {
      theoreticalArrivalTimeNs: nextArrivalNs,
      intervalNs,
      lastObservedMs: nowMonotonicMs,
    });
    return decision("ALLOW");
  }
}
