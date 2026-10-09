import { describe, expect, it } from "vitest";
import {
  canonicalLicenseSnapshotV1,
  createEntitlementStateV1,
  evaluateEntitlementV1,
} from "../src/entitlement/decision.js";
import type {
  EntitlementInputV1,
  EntitlementStateV1,
  LicenseSnapshotV1,
} from "../src/entitlement/models.js";

const BASE_NS = 1_800_000_000_000_000_000n;
const NS_PER_MS = 1_000_000n;
const NS_PER_SECOND = 1_000_000_000n;

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  return buffer;
}

async function acceptanceFixture() {
  const pair = await globalThis.crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const signingKeys = new Map([["acceptance-key", pair.publicKey]]);
  const defaults: LicenseSnapshotV1 = {
    schemaVersion: 1,
    orgId: `org-acceptance-${globalThis.crypto.randomUUID()}`,
    licenseId: "license-acceptance",
    subscriptionRevision: "1",
    status: "ACTIVE",
    termStartUtcNs: (BASE_NS - 10n * NS_PER_SECOND).toString(),
    termEndUtcNs: (BASE_NS + 3_600n * NS_PER_SECOND).toString(),
    issuedAtUtcNs: (BASE_NS - 2n * NS_PER_SECOND).toString(),
    lastOnlineVerifiedUtcNs: BASE_NS.toString(),
    features: { decisioning: true },
    limits: { seats: "3", risk_budget: "100.25" },
    audience: "leviathan-desktop",
    deviceId: `device-acceptance-${globalThis.crypto.randomUUID()}`,
    signingKeyId: "acceptance-key",
    signature: { algorithm: "ECDSA_P256_SHA256", value: "" },
  };

  async function signed(
    changes: Partial<LicenseSnapshotV1> = {},
  ): Promise<LicenseSnapshotV1> {
    const unsigned = { ...defaults, ...changes, signature: defaults.signature };
    const bytes = canonicalLicenseSnapshotV1(unsigned);
    const signatureBytes = await globalThis.crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      pair.privateKey,
      toArrayBuffer(bytes),
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

  function input(overrides: Partial<EntitlementInputV1> = {}): EntitlementInputV1 {
    return {
      mode: "ONLINE",
      expectedOrgId: defaults.orgId,
      expectedAudience: defaults.audience,
      expectedDeviceId: defaults.deviceId,
      signingKeys,
      nowMonotonicMs: 1_000,
      nowWallUtcNs: BASE_NS.toString(),
      ...overrides,
    };
  }

  async function onlineState(
    snapshot: LicenseSnapshotV1,
  ): Promise<EntitlementStateV1> {
    const result = await evaluateEntitlementV1(input({ snapshot }));
    expect(result.decision.outcome).toBe("VERIFIED_ONLINE");
    return result.state;
  }

  return { input, onlineState, signed, signingKeys };
}

describe("LIC-001 entitlement acceptance", () => {
  it("accepts only a synthetic P-256 signed active snapshot", async () => {
    const fixture = await acceptanceFixture();
    const result = await evaluateEntitlementV1(
      fixture.input({ snapshot: await fixture.signed() }),
    );

    expect(result.decision).toMatchObject({
      outcome: "VERIFIED_ONLINE",
      reason: "ONLINE_ACTIVE",
      authorizesGatedEffects: true,
    });
  });

  it("denies a tampered signature and an unknown signing key id", async () => {
    const fixture = await acceptanceFixture();
    const original = await fixture.signed();
    const tampered = await evaluateEntitlementV1(
      fixture.input({ snapshot: { ...original, features: { decisioning: false } } }),
    );
    expect(tampered.decision).toMatchObject({
      outcome: "DENIED",
      reason: "INVALID_SIGNATURE",
      authorizesGatedEffects: false,
    });

    const unknownKey = await fixture.signed({ signingKeyId: "untrusted-key-id" });
    const unknownKeyResult = await evaluateEntitlementV1(
      fixture.input({ snapshot: unknownKey }),
    );
    expect(unknownKeyResult.decision.reason).toBe("TRUST_KEY_UNAVAILABLE");
    expect(unknownKeyResult.decision.authorizesGatedEffects).toBe(false);
  });

  it.each([
    ["organization", { expectedOrgId: "other-org" }],
    ["audience", { expectedAudience: "other-app" }],
    ["device", { expectedDeviceId: "other-device" }],
  ] as const)("denies a signed snapshot bound to another %s", async (_binding, override) => {
    const fixture = await acceptanceFixture();
    const result = await evaluateEntitlementV1(
      fixture.input({ snapshot: await fixture.signed(), ...override }),
    );
    expect(result.decision.reason).toBe("BINDING_MISMATCH");
    expect(result.decision.authorizesGatedEffects).toBe(false);
  });

  it.each(["same", "older"] as const)(
    "rejects a %s signed subscription revision after the high-water mark",
    async (kind) => {
      const fixture = await acceptanceFixture();
      const state = await fixture.onlineState(
        await fixture.signed({ subscriptionRevision: "5" }),
      );
      const revision = kind === "same" ? "5" : "4";
      const result = await evaluateEntitlementV1(
        fixture.input({
          state,
          snapshot: await fixture.signed({ subscriptionRevision: revision }),
          nowMonotonicMs: 1_001,
          nowWallUtcNs: (BASE_NS + NS_PER_MS).toString(),
        }),
      );
      expect(result.decision.reason).toBe("REVISION_ROLLBACK");
      expect(result.decision.authorizesGatedEffects).toBe(false);
    },
  );

  it("latches a signed negative revision until a higher signed revision arrives", async () => {
    const fixture = await acceptanceFixture();
    const activeState = await fixture.onlineState(await fixture.signed());
    const negative = await evaluateEntitlementV1(
      fixture.input({
        state: activeState,
        snapshot: await fixture.signed({ subscriptionRevision: "2", status: "SUSPENDED" }),
        nowMonotonicMs: 1_500,
        nowWallUtcNs: (BASE_NS + 500n * NS_PER_MS).toString(),
      }),
    );
    expect(negative.decision.reason).toBe("LICENSE_INACTIVE");

    const beforeCacheExpiry = await evaluateEntitlementV1(
      fixture.input({
        mode: "OFFLINE",
        state: negative.state,
        nowMonotonicMs: 6_499,
        nowWallUtcNs: (BASE_NS + 5_499n * NS_PER_MS).toString(),
      }),
    );
    expect(beforeCacheExpiry.decision.reason).toBe("LICENSE_INACTIVE");

    const afterCacheExpiry = await evaluateEntitlementV1(
      fixture.input({
        mode: "OFFLINE",
        state: beforeCacheExpiry.state,
        nowMonotonicMs: 6_500,
        nowWallUtcNs: (BASE_NS + 5_500n * NS_PER_MS).toString(),
      }),
    );
    expect(afterCacheExpiry.decision.reason).toBe("CACHE_UNAVAILABLE");

    const replayedNegativeRevision = await evaluateEntitlementV1(
      fixture.input({
        state: afterCacheExpiry.state,
        snapshot: await fixture.signed({ subscriptionRevision: "2", status: "ACTIVE" }),
        nowMonotonicMs: 6_501,
        nowWallUtcNs: (BASE_NS + 5_501n * NS_PER_MS).toString(),
      }),
    );
    expect(replayedNegativeRevision.decision.reason).toBe("REVISION_ROLLBACK");

    const restored = await evaluateEntitlementV1(
      fixture.input({
        state: replayedNegativeRevision.state,
        snapshot: await fixture.signed({ subscriptionRevision: "3" }),
        nowMonotonicMs: 6_501,
        nowWallUtcNs: (BASE_NS + 5_501n * NS_PER_MS).toString(),
      }),
    );
    expect(restored.decision.reason).toBe("ONLINE_ACTIVE");
    expect(restored.decision.authorizesGatedEffects).toBe(true);
  });

  it("rejects an old ACTIVE handle after a newer signed negative observation", async () => {
    const fixture = await acceptanceFixture();
    const stateA = await fixture.onlineState(await fixture.signed());
    const suspended = await evaluateEntitlementV1(
      fixture.input({
        state: stateA,
        snapshot: await fixture.signed({ subscriptionRevision: "2", status: "SUSPENDED" }),
        nowMonotonicMs: 1_001,
        nowWallUtcNs: (BASE_NS + NS_PER_MS).toString(),
      }),
    );
    expect(suspended.decision.outcome).toBe("DENIED");

    const staleOffline = await evaluateEntitlementV1(
      fixture.input({
        mode: "OFFLINE",
        state: stateA,
        nowMonotonicMs: 1_002,
        nowWallUtcNs: (BASE_NS + 2n * NS_PER_MS).toString(),
      }),
    );
    expect(staleOffline.decision.outcome).toBe("DENIED");
    expect(staleOffline.decision.authorizesGatedEffects).toBe(false);
  });

  it.each(["clock rollback", "invalid signature"] as const)(
    "rejects a stale handle after a %s observation",
    async (observation) => {
      const fixture = await acceptanceFixture();
      const active = await fixture.signed();
      const stateA = await fixture.onlineState(active);

      if (observation === "clock rollback") {
        const rollback = await evaluateEntitlementV1(
          fixture.input({
            mode: "OFFLINE",
            state: stateA,
            nowMonotonicMs: 999,
            nowWallUtcNs: (BASE_NS - 1n).toString(),
          }),
        );
        expect(rollback.decision.reason).toBe("CLOCK_ROLLBACK");
      } else {
        const badSignature = await evaluateEntitlementV1(
          fixture.input({
            state: stateA,
            snapshot: { ...active, features: { decisioning: false } },
            nowMonotonicMs: 1_001,
            nowWallUtcNs: (BASE_NS + NS_PER_MS).toString(),
          }),
        );
        expect(badSignature.decision.reason).toBe("INVALID_SIGNATURE");
      }

      const staleOffline = await evaluateEntitlementV1(
        fixture.input({
          mode: "OFFLINE",
          state: stateA,
          nowMonotonicMs: 1_002,
          nowWallUtcNs: (BASE_NS + 2n * NS_PER_MS).toString(),
        }),
      );
      expect(staleOffline.decision.outcome).toBe("DENIED");
      expect(staleOffline.decision.authorizesGatedEffects).toBe(false);
    },
  );

  it("keeps positive cache for 60 seconds and expires it at the monotonic boundary", async () => {
    const fixture = await acceptanceFixture();
    const state = await fixture.onlineState(await fixture.signed());
    const before = await evaluateEntitlementV1(
      fixture.input({
        mode: "OFFLINE",
        state,
        nowMonotonicMs: 60_999,
        nowWallUtcNs: (BASE_NS + 59_999n * NS_PER_MS).toString(),
      }),
    );
    expect(before.decision).toMatchObject({
      outcome: "VERIFIED_ONLINE",
      reason: "POSITIVE_CACHE",
    });

    const atBoundary = await evaluateEntitlementV1(
      fixture.input({
        mode: "OFFLINE",
        state: before.state,
        nowMonotonicMs: 61_000,
        nowWallUtcNs: (BASE_NS + 60n * NS_PER_SECOND).toString(),
      }),
    );
    expect(atBoundary.decision).toMatchObject({
      outcome: "UNKNOWN",
      reason: "GRACE_POLICY_MISSING",
      authorizesGatedEffects: false,
    });
  });

  it("rejects wall clock rollback, including after a valid online decision", async () => {
    const fixture = await acceptanceFixture();
    const state = await fixture.onlineState(await fixture.signed());
    const result = await evaluateEntitlementV1(
      fixture.input({
        mode: "OFFLINE",
        state,
        nowMonotonicMs: 1_001,
        nowWallUtcNs: (BASE_NS - 1n).toString(),
      }),
    );
    expect(result.decision.reason).toBe("CLOCK_ROLLBACK");
    expect(result.decision.authorizesGatedEffects).toBe(false);
  });

  it("denies at term end even when the snapshot signature is valid", async () => {
    const fixture = await acceptanceFixture();
    const end = BASE_NS + 3_600n * NS_PER_SECOND;
    const result = await evaluateEntitlementV1(
      fixture.input({
        snapshot: await fixture.signed(),
        nowWallUtcNs: end.toString(),
      }),
    );
    expect(result.decision.reason).toBe("TERM_EXPIRED");
    expect(result.decision.authorizesGatedEffects).toBe(false);
  });

  it("returns UNKNOWN without grace policy and never authorizes gated effects in grace", async () => {
    const fixture = await acceptanceFixture();
    const state = await fixture.onlineState(await fixture.signed());
    const missingPolicy = await evaluateEntitlementV1(
      fixture.input({
        mode: "OFFLINE",
        state,
        nowMonotonicMs: 61_000,
        nowWallUtcNs: (BASE_NS + 60n * NS_PER_SECOND).toString(),
      }),
    );
    expect(missingPolicy.decision).toMatchObject({
      outcome: "UNKNOWN",
      reason: "GRACE_POLICY_MISSING",
      authorizesGatedEffects: false,
    });

    const grace = await evaluateEntitlementV1(
      fixture.input({
        mode: "OFFLINE",
        state,
        gracePolicy: { schemaVersion: 1, maxOfflineSeconds: 120 },
        nowMonotonicMs: 61_000,
        nowWallUtcNs: (BASE_NS + 60n * NS_PER_SECOND).toString(),
      }),
    );
    expect(grace.decision).toMatchObject({
      outcome: "GRACE_OFFLINE",
      reason: "OFFLINE_GRACE",
      authorizesGatedEffects: false,
    });
  });

  it("denies ONLINE without a snapshot and does not treat a provider key as entitlement proof", async () => {
    const fixture = await acceptanceFixture();
    const absent = await evaluateEntitlementV1(fixture.input());
    expect(absent.decision.outcome).toBe("DENIED");
    expect(absent.decision.authorizesGatedEffects).toBe(false);

    const providerKeyOnly = {
      providerApiKey: "synthetic-provider-key",
    } as unknown as LicenseSnapshotV1;
    const keyOnly = await evaluateEntitlementV1(
      fixture.input({ snapshot: providerKeyOnly }),
    );
    expect(keyOnly.decision).toMatchObject({
      outcome: "DENIED",
      reason: "INVALID_SNAPSHOT",
      authorizesGatedEffects: false,
    });
  });

  it("does not treat a caller-built cache-shaped object as trusted prior state", async () => {
    const fixture = await acceptanceFixture();
    const result = await evaluateEntitlementV1(
      fixture.input({
        mode: "OFFLINE",
        state: { schemaVersion: 1 } as EntitlementStateV1,
      }),
    );
    expect(result.decision.reason).toBe("CACHE_CORRUPT");
    expect(result.decision.authorizesGatedEffects).toBe(false);
    expect(createEntitlementStateV1()).not.toBe(result.state);
  });
});
