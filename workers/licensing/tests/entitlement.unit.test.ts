import { describe, expect, it } from "vitest";
import {
  canonicalLicenseSnapshotV1, createEntitlementStateV1, evaluateEntitlementV1,
} from "../src/entitlement/decision.js";
import type {
  EntitlementInputV1, LicenseSnapshotV1,
} from "../src/entitlement/models.js";

const BASE_NS = 1_800_000_000_000_000_000n;
const SECOND_NS = 1_000_000_000n;

async function fixture() {
  const orgId = `org-${globalThis.crypto.randomUUID()}`;
  const deviceId = `device-${globalThis.crypto.randomUUID()}`;
  const keys = await globalThis.crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"],
  );
  const signingKeys = new Map([["test-key", keys.publicKey]]);
  const base: LicenseSnapshotV1 = {
    schemaVersion: 1,
    orgId,
    licenseId: "license-1",
    subscriptionRevision: "1",
    status: "ACTIVE",
    termStartUtcNs: (BASE_NS - 10n * SECOND_NS).toString(),
    termEndUtcNs: (BASE_NS + 3600n * SECOND_NS).toString(),
    issuedAtUtcNs: (BASE_NS - 2n * SECOND_NS).toString(),
    lastOnlineVerifiedUtcNs: BASE_NS.toString(),
    features: { decisioning: true, risk_guard: true },
    limits: { max_connectors: "3", api_rate_limit_rps: "10.25" },
    audience: "leviathan-desktop",
    deviceId,
    signingKeyId: "test-key",
    signature: { algorithm: "ECDSA_P256_SHA256", value: "" },
  };
  async function signed(changes: Partial<LicenseSnapshotV1> = {}): Promise<LicenseSnapshotV1> {
    const unsigned = { ...base, ...changes, signature: base.signature };
    const bytes = canonicalLicenseSnapshotV1(unsigned);
    const signature = await globalThis.crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" }, keys.privateKey,
      Uint8Array.from(bytes).buffer,
    );
    const text = btoa(String.fromCharCode(...new Uint8Array(signature)))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    return { ...unsigned, signature: { algorithm: "ECDSA_P256_SHA256", value: text } };
  }
  function input(overrides: Partial<EntitlementInputV1> = {}): EntitlementInputV1 {
    return {
      mode: "ONLINE",
      expectedOrgId: orgId,
      expectedAudience: "leviathan-desktop",
      expectedDeviceId: deviceId,
      signingKeys,
      nowMonotonicMs: 1000,
      nowWallUtcNs: BASE_NS.toString(),
      ...overrides,
    };
  }
  return { signed, input, signingKeys };
}

describe("LIC-001 offline entitlement decision", () => {
  it("verifies a signed active snapshot and bounds positive cache to under 60 seconds", async () => {
    const f = await fixture();
    const online = await evaluateEntitlementV1(f.input({ snapshot: await f.signed() }));
    expect(online.decision).toMatchObject({
      outcome: "VERIFIED_ONLINE", reason: "ONLINE_ACTIVE", authorizesGatedEffects: true,
    });
    const cached = await evaluateEntitlementV1(f.input({
      mode: "OFFLINE", state: online.state, nowMonotonicMs: 60_999,
      nowWallUtcNs: (BASE_NS + 59_999_000_000n).toString(),
    }));
    expect(cached.decision.outcome).toBe("VERIFIED_ONLINE");
    const expired = await evaluateEntitlementV1(f.input({
      mode: "OFFLINE", state: cached.state, nowMonotonicMs: 61_000,
      nowWallUtcNs: (BASE_NS + 60n * SECOND_NS).toString(),
    }));
    expect(expired.decision).toMatchObject({
      outcome: "UNKNOWN", reason: "GRACE_POLICY_MISSING", authorizesGatedEffects: false,
    });
  });

  it("makes configured grace informational and ends it at the exact edge", async () => {
    const f = await fixture();
    const online = await evaluateEntitlementV1(f.input({ snapshot: await f.signed() }));
    const gracePolicy = { schemaVersion: 1 as const, maxOfflineSeconds: 120 };
    const grace = await evaluateEntitlementV1(f.input({
      mode: "OFFLINE", state: online.state, gracePolicy,
      nowMonotonicMs: 61_000,
      nowWallUtcNs: (BASE_NS + 60n * SECOND_NS).toString(),
    }));
    expect(grace.decision).toMatchObject({
      outcome: "GRACE_OFFLINE", reason: "OFFLINE_GRACE", authorizesGatedEffects: false,
    });
    const edge = await evaluateEntitlementV1(f.input({
      mode: "OFFLINE", state: grace.state, gracePolicy,
      nowMonotonicMs: 121_000,
      nowWallUtcNs: (BASE_NS + 120n * SECOND_NS).toString(),
    }));
    expect(edge.decision).toMatchObject({ outcome: "DENIED", reason: "GRACE_EXPIRED" });
  });

  it("lets a signed negative server state supersede a positive snapshot", async () => {
    const f = await fixture();
    const online = await evaluateEntitlementV1(f.input({ snapshot: await f.signed() }));
    const revoked = await evaluateEntitlementV1(f.input({
      state: online.state,
      snapshot: await f.signed({ subscriptionRevision: "2", status: "SUSPENDED" }),
      nowMonotonicMs: 1100,
      nowWallUtcNs: (BASE_NS + 100_000_000n).toString(),
    }));
    expect(revoked.decision).toMatchObject({ outcome: "DENIED", reason: "LICENSE_INACTIVE" });
    const beforeFive = await evaluateEntitlementV1(f.input({
      mode: "OFFLINE", state: revoked.state,
      nowMonotonicMs: 6099,
      nowWallUtcNs: (BASE_NS + 5_099_000_000n).toString(),
    }));
    expect(beforeFive.decision.reason).toBe("LICENSE_INACTIVE");
    const atFive = await evaluateEntitlementV1(f.input({
      mode: "OFFLINE", state: beforeFive.state,
      nowMonotonicMs: 6100,
      nowWallUtcNs: (BASE_NS + 5_100_000_000n).toString(),
    }));
    expect(atFive.decision).toMatchObject({ outcome: "DENIED", reason: "CACHE_UNAVAILABLE" });
    const replay = await evaluateEntitlementV1(f.input({
      state: atFive.state, snapshot: await f.signed(),
      nowMonotonicMs: 6101,
      nowWallUtcNs: (BASE_NS + 5_101_000_000n).toString(),
    }));
    expect(replay.decision).toMatchObject({ outcome: "DENIED", reason: "REVISION_ROLLBACK" });
  });

  it("rejects an incoming legacy TRIAL snapshot as invalid instead of treating it as inactive", async () => {
    const f = await fixture();
    const active = await f.signed();
    const legacyTrial = { ...active, status: "TRIAL" } as unknown as LicenseSnapshotV1;
    const result = await evaluateEntitlementV1(f.input({ snapshot: legacyTrial }));
    expect(result.decision).toMatchObject({ outcome: "DENIED", reason: "INVALID_SNAPSHOT" });
    expect(result.decision.authorizesGatedEffects).toBe(false);
  });

  it("denies tampering, wrong binding, missing key, and duplicate revision", async () => {
    const f = await fixture();
    const snapshot = await f.signed();
    const tampered = await evaluateEntitlementV1(f.input({
      snapshot: { ...snapshot, features: { decisioning: false } },
    }));
    expect(tampered.decision.reason).toBe("INVALID_SIGNATURE");
    const wrongDevice = await evaluateEntitlementV1(f.input({
      snapshot, expectedDeviceId: "other-device",
    }));
    expect(wrongDevice.decision.reason).toBe("BINDING_MISMATCH");
    const missingKey = await evaluateEntitlementV1(f.input({
      snapshot, signingKeys: new Map(),
    }));
    expect(missingKey.decision.reason).toBe("TRUST_KEY_UNAVAILABLE");
    const valid = await evaluateEntitlementV1(f.input({ snapshot }));
    const duplicate = await evaluateEntitlementV1(f.input({
      state: valid.state, snapshot,
      nowMonotonicMs: 1001,
      nowWallUtcNs: (BASE_NS + 1_000_000n).toString(),
    }));
    expect(duplicate.decision.reason).toBe("REVISION_ROLLBACK");
  });

  it("denies clock rollback, term expiry, and forged cached state", async () => {
    const f = await fixture();
    const online = await evaluateEntitlementV1(f.input({ snapshot: await f.signed() }));
    const clockRollback = await evaluateEntitlementV1(f.input({
      mode: "OFFLINE", state: online.state,
      nowMonotonicMs: 999,
    }));
    expect(clockRollback.decision.reason).toBe("CLOCK_ROLLBACK");
    const wallRollback = await evaluateEntitlementV1(f.input({
      mode: "OFFLINE", state: online.state,
      nowMonotonicMs: 1001,
      nowWallUtcNs: (BASE_NS - 1n).toString(),
    }));
    expect(wallRollback.decision.reason).toBe("CLOCK_ROLLBACK");
    const term = await fixture();
    const termOnline = await evaluateEntitlementV1(term.input({
      snapshot: await term.signed(),
    }));
    const expired = await evaluateEntitlementV1(term.input({
      mode: "OFFLINE", state: termOnline.state,
      nowMonotonicMs: 3_601_000,
      nowWallUtcNs: (BASE_NS + 3600n * SECOND_NS).toString(),
    }));
    expect(expired.decision.reason).toBe("TERM_EXPIRED");
    const corrupt = await evaluateEntitlementV1(f.input({
      mode: "OFFLINE", state: { schemaVersion: 1 },
    }));
    expect(corrupt.decision.reason).toBe("CACHE_CORRUPT");
    const noCache = await fixture();
    const empty = await evaluateEntitlementV1(noCache.input({
      mode: "OFFLINE", state: createEntitlementStateV1(),
    }));
    expect(empty.decision).toMatchObject({ outcome: "DENIED", reason: "CACHE_UNAVAILABLE" });
  });

  it("invalidates stale and concurrent handles after a signed negative across the process", async () => {
    const f = await fixture();
    const active = await evaluateEntitlementV1(f.input({ snapshot: await f.signed() }));
    const negative = await evaluateEntitlementV1(f.input({
      state: active.state,
      snapshot: await f.signed({ subscriptionRevision: "2", status: "SUSPENDED" }),
      nowMonotonicMs: 1001,
      nowWallUtcNs: (BASE_NS + 1_000_000n).toString(),
    }));
    expect(negative.decision.reason).toBe("LICENSE_INACTIVE");
    const [staleA, staleB] = await Promise.all([1002, 1003].map((nowMonotonicMs) =>
      evaluateEntitlementV1(f.input({
        mode: "OFFLINE", state: active.state, nowMonotonicMs,
        nowWallUtcNs: (BASE_NS + BigInt(nowMonotonicMs - 1000) * 1_000_000n).toString(),
      }))));
    for (const stale of [staleA, staleB]) {
      expect(stale.decision.outcome).toBe("DENIED");
      expect(stale.decision.authorizesGatedEffects).toBe(false);
    }
    const separateRoot = await evaluateEntitlementV1(f.input({
      snapshot: await f.signed(),
      state: createEntitlementStateV1(),
      nowMonotonicMs: 1004,
      nowWallUtcNs: (BASE_NS + 4_000_000n).toString(),
    }));
    expect(separateRoot.decision.outcome).toBe("DENIED");
    const recovered = await evaluateEntitlementV1(f.input({
      snapshot: await f.signed({ subscriptionRevision: "3" }),
      state: separateRoot.state,
      nowMonotonicMs: 1005,
      nowWallUtcNs: (BASE_NS + 5_000_000n).toString(),
    }));
    expect(recovered.decision.outcome).toBe("VERIFIED_ONLINE");
  });

  it("latches invalid signatures and clock rollback against an earlier positive handle", async () => {
    const invalid = await fixture();
    const active = await evaluateEntitlementV1(invalid.input({ snapshot: await invalid.signed() }));
    const signed = await invalid.signed({ subscriptionRevision: "2" });
    const tampered = await evaluateEntitlementV1(invalid.input({
      state: active.state,
      snapshot: { ...signed, limits: { seats: "999" } },
      nowMonotonicMs: 1001,
      nowWallUtcNs: (BASE_NS + 1_000_000n).toString(),
    }));
    expect(tampered.decision.reason).toBe("INVALID_SIGNATURE");
    const stale = await evaluateEntitlementV1(invalid.input({
      mode: "OFFLINE", state: active.state,
      nowMonotonicMs: 1002,
      nowWallUtcNs: (BASE_NS + 2_000_000n).toString(),
    }));
    expect(stale.decision.authorizesGatedEffects).toBe(false);
    const recovered = await evaluateEntitlementV1(invalid.input({
      state: tampered.state, snapshot: signed,
      nowMonotonicMs: 1003,
      nowWallUtcNs: (BASE_NS + 3_000_000n).toString(),
    }));
    expect(recovered.decision.outcome).toBe("VERIFIED_ONLINE");

    const clock = await fixture();
    const first = await evaluateEntitlementV1(clock.input({ snapshot: await clock.signed() }));
    const rollback = await evaluateEntitlementV1(clock.input({
      mode: "OFFLINE", state: first.state, nowMonotonicMs: 999,
    }));
    expect(rollback.decision.reason).toBe("CLOCK_ROLLBACK");
    const old = await evaluateEntitlementV1(clock.input({
      mode: "OFFLINE", state: first.state,
      nowMonotonicMs: 1001,
      nowWallUtcNs: (BASE_NS + 1_000_000n).toString(),
    }));
    expect(old.decision.authorizesGatedEffects).toBe(false);
  });

  it("does not turn an unrelated empty offline lookup into a negative observation", async () => {
    const f = await fixture();
    const active = await evaluateEntitlementV1(f.input({ snapshot: await f.signed() }));
    const emptyLookup = await evaluateEntitlementV1(f.input({
      mode: "OFFLINE", state: createEntitlementStateV1(),
      nowMonotonicMs: 1001,
      nowWallUtcNs: (BASE_NS + 1_000_000n).toString(),
    }));
    expect(emptyLookup.decision.reason).toBe("CACHE_UNAVAILABLE");
    const stillActive = await evaluateEntitlementV1(f.input({
      mode: "OFFLINE", state: active.state,
      nowMonotonicMs: 1002,
      nowWallUtcNs: (BASE_NS + 2_000_000n).toString(),
    }));
    expect(stillActive.decision.outcome).toBe("VERIFIED_ONLINE");
  });

  it("applies a signed negative even when the caller supplied another scope's state", async () => {
    const target = await fixture();
    const other = await fixture();
    const targetActive = await evaluateEntitlementV1(target.input({
      snapshot: await target.signed(),
    }));
    const otherActive = await evaluateEntitlementV1(other.input({
      snapshot: await other.signed(),
    }));
    const negative = await evaluateEntitlementV1(target.input({
      state: otherActive.state,
      snapshot: await target.signed({ subscriptionRevision: "2", status: "SUSPENDED" }),
      nowMonotonicMs: 1001,
      nowWallUtcNs: (BASE_NS + 1_000_000n).toString(),
    }));
    expect(negative.decision.reason).toBe("LICENSE_INACTIVE");
    const stale = await evaluateEntitlementV1(target.input({
      mode: "OFFLINE", state: targetActive.state,
      nowMonotonicMs: 1002,
      nowWallUtcNs: (BASE_NS + 2_000_000n).toString(),
    }));
    expect(stale.decision.authorizesGatedEffects).toBe(false);
  });
});
