import { readdir, readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import {
  canonicalLicenseSnapshotV1,
  evaluateEntitlementV1,
} from "../src/entitlement/decision.js";
import type {
  EntitlementInputV1,
  LicenseSnapshotV1,
} from "../src/entitlement/models.js";

const BASE_NS = 1_800_000_000_000_000_000n;
const NS_PER_SECOND = 1_000_000_000n;

interface DirectoryEntryV1 {
  readonly name: string;
  isDirectory(): boolean;
  isFile(): boolean;
}

function arrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  return buffer;
}

async function entitlementFixture() {
  const pair = await globalThis.crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"],
  );
  const orgId = `org-no-trial-${globalThis.crypto.randomUUID()}`;
  const deviceId = `device-no-trial-${globalThis.crypto.randomUUID()}`;
  const signingKeys = new Map([["acceptance-key", pair.publicKey]]);
  const base: LicenseSnapshotV1 = {
    schemaVersion: 1,
    orgId,
    licenseId: "license-no-trial",
    subscriptionRevision: "1",
    status: "ACTIVE",
    termStartUtcNs: (BASE_NS - 10n * NS_PER_SECOND).toString(),
    termEndUtcNs: (BASE_NS + 3_600n * NS_PER_SECOND).toString(),
    issuedAtUtcNs: (BASE_NS - 2n * NS_PER_SECOND).toString(),
    lastOnlineVerifiedUtcNs: BASE_NS.toString(),
    features: { decisioning: true },
    limits: { seats: "3" },
    audience: "leviathan-desktop",
    deviceId,
    signingKeyId: "acceptance-key",
    signature: { algorithm: "ECDSA_P256_SHA256", value: "" },
  };

  async function signed(
    status: LicenseSnapshotV1["status"] = "ACTIVE",
  ): Promise<LicenseSnapshotV1> {
    const unsigned = { ...base, status, signature: base.signature };
    const bytes = canonicalLicenseSnapshotV1(unsigned);
    const signatureBytes = await globalThis.crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" }, pair.privateKey, arrayBuffer(bytes),
    );
    const value = btoa(String.fromCharCode(...new Uint8Array(signatureBytes)))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    return { ...unsigned, signature: { algorithm: "ECDSA_P256_SHA256", value } };
  }

  function input(snapshot: LicenseSnapshotV1): EntitlementInputV1 {
    return {
      mode: "ONLINE", snapshot, expectedOrgId: orgId,
      expectedAudience: base.audience, expectedDeviceId: deviceId,
      signingKeys, nowMonotonicMs: 1_000, nowWallUtcNs: BASE_NS.toString(),
    };
  }

  return { base, input, signed };
}

async function sourceFiles(directory: URL): Promise<URL[]> {
  const entries = await readdir(directory, { withFileTypes: true });
  const nested = await Promise.all(entries.map(async (entry) => {
    const url = new URL(`${entry.name}${entry.isDirectory() ? "/" : ""}`, directory);
    if (entry.isDirectory()) return sourceFiles(url);
    return entry.isFile() && entry.name.endsWith(".ts") ? [url] : [];
  }));
  return nested.flat();
}

describe("LIC-NO-TRIAL-001 independent acceptance", () => {
  it("rejects legacy TRIAL snapshots at canonicalization and entitlement evaluation", async () => {
    const fixture = await entitlementFixture();
    const active = await fixture.signed();
    const legacyTrial = {
      ...active,
      status: "TRIAL",
    } as unknown as LicenseSnapshotV1;

    expect(() => canonicalLicenseSnapshotV1(legacyTrial)).toThrow(TypeError);
    const result = await evaluateEntitlementV1(fixture.input(legacyTrial));
    expect(result.decision).toMatchObject({
      outcome: "DENIED", reason: "INVALID_SNAPSHOT", authorizesGatedEffects: false,
    });
  });

  it.each(["PAST_DUE", "PAUSED", "CANCELED", "SUSPENDED", "EXPIRED"] as const)(
    "continues to deny %s as LICENSE_INACTIVE",
    async (status) => {
      const fixture = await entitlementFixture();
      const result = await evaluateEntitlementV1(
        fixture.input(await fixture.signed(status)),
      );
      expect(result.decision).toMatchObject({
        outcome: "DENIED", reason: "LICENSE_INACTIVE", authorizesGatedEffects: false,
      });
    },
  );

  it("excludes the removed status from every migration CHECK and preflights all three tables", async () => {
    const migration = await readFile(new URL("../migrations/002_no_trial.sql", import.meta.url), "utf8");
    const checks = [...migration.matchAll(/CHECK\s*\(([^)]*)\)/gi)].map((match) => match[1] ?? "");
    expect(checks).toHaveLength(3);
    for (const check of checks) expect(check).not.toMatch(/'TRIAL'/i);

    for (const table of [
      "licensing_subscriptions",
      "licensing_subscription_revisions",
      "licensing_subscription_outbox",
    ]) {
      expect(migration).toMatch(new RegExp(
        `FROM\\s+${table}\\s+WHERE\\s+status\\s*=\\s*'TRIAL'`, "i",
      ));
    }
    expect(migration).toMatch(/RAISE\s+EXCEPTION\s+'LIC_NO_TRIAL_MIGRATION_BLOCKED/i);
  });

  it("keeps the removed status out of all licensing TypeScript source", async () => {
    const files = await sourceFiles(new URL("../src/", import.meta.url));
    expect(files.length).toBeGreaterThan(0);
    const matches = await Promise.all(files.map(async (file) => ({
      file: file.pathname,
      content: await readFile(file, "utf8"),
    })));
    expect(matches.filter(({ content }) => content.includes("TRIAL"))).toEqual([]);
  });
});
