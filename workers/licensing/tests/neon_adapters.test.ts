import { describe, expect, it } from "vitest";
import {
  decryptTotpSecretV1, encryptTotpSecretV1, hashPasswordPbkdf2V1,
  verifyPasswordPbkdf2V1, verifyTotpStepV1, createNeonPgDriverV1,
} from "../src/adapters/neon_admin.js";
import { createAdminSessionV1 } from "../src/admin_api/auth.js";
import { AdminApiErrorV1, type AdminApiDependenciesV1 } from "../src/admin_api/models.js";

const KEY = btoa(String.fromCharCode(...new Uint8Array(32).fill(7)));

describe("Worker auth crypto adapters", () => {
  it("persists a versioned PBKDF2-HMAC-SHA-256 hash at the required work factor", async () => {
    const hash = await hashPasswordPbkdf2V1("correct horse battery staple");
    expect(hash).toMatch(/^pbkdf2-sha256\$600000\$[A-Za-z0-9+/]+=*\$[A-Za-z0-9+/]+=*$/);
    await expect(verifyPasswordPbkdf2V1("correct horse battery staple", hash)).resolves.toBe(true);
    await expect(verifyPasswordPbkdf2V1("wrong password here", hash)).resolves.toBe(false);
    await expect(verifyPasswordPbkdf2V1("correct horse battery staple", null)).resolves.toBe(false);
  }, 30_000);

  it("encrypts TOTP seeds with random IVs and binds ciphertext to org/user AAD", async () => {
    const seed = "JBSWY3DPEHPK3PXP";
    const a = await encryptTotpSecretV1(seed, KEY, "org-1", "user-1");
    const b = await encryptTotpSecretV1(seed, KEY, "org-1", "user-1");
    expect(a).toMatch(/^aes256gcm\$[A-Za-z0-9+/]+=*\$[A-Za-z0-9+/]+=*$/);
    expect(a).not.toBe(b);
    await expect(decryptTotpSecretV1(a, KEY, "org-1", "user-1")).resolves.toBe(seed);
    await expect(decryptTotpSecretV1(a, KEY, "org-2", "user-1")).rejects.toThrow();
  });

  it("accepts a fresh code in the RFC 6238 +/- one step window and rejects replay", async () => {
    const secret = "JBSWY3DPEHPK3PXP";
    const seconds = 1_700_000_000;
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    const bits = secret.split("").map((ch) => alphabet.indexOf(ch).toString(2).padStart(5, "0")).join("");
    const raw = new Uint8Array(Math.floor(bits.length / 8));
    for (let i = 0; i < raw.length; i += 1) raw[i] = Number.parseInt(bits.slice(i * 8, i * 8 + 8), 2);
    const key = await crypto.subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
    const step = BigInt(Math.floor(seconds / 30) + 1);
    const msg = new Uint8Array(8); let n = step;
    for (let i = 7; i >= 0; i -= 1) { msg[i] = Number(n & 255n); n >>= 8n; }
    const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, msg));
    const off = digest[digest.length - 1]! & 15;
    const number = ((digest[off]! & 127) << 24) | (digest[off + 1]! << 16) | (digest[off + 2]! << 8) | digest[off + 3]!;
    const code = String(number % 1_000_000).padStart(6, "0");
    const matched = await verifyTotpStepV1(secret, code, seconds, null);
    expect(matched).toBe(step);
    expect(await verifyTotpStepV1(secret, code, seconds, matched)).toBeNull();
  });

  it("returns enrollment-required with a one-time otpauth URI after password-only bootstrap login", async () => {
    const deps = {
      auth: {
        async findOwnerByEmail() { return { org_id: "org-1", user_id: "user-1",
          password_hash_argon2id: "pbkdf2-sha256$600000$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
          active: true, owner: true, totp_enrolled: false }; },
        async isLoginLocked() { return false; }, async recordFailedLogin() { return false; },
        async clearFailedLogins() {}, async verifyArgon2id() { return true; }, async verifyTotp() { return false; },
        async beginTotpEnrollment() { return "otpauth://totp/Leviathan%20AI:owner%40example.test?secret=JBSWY3DPEHPK3PXP"; },
        async confirmTotpEnrollment() { return false; }, async issueSession() { throw new Error("must not issue session"); },
        async resolveSession() { return null; }, async revokeSession() {},
      }, authorization: { async authorize() { return false; } }, store: {} as AdminApiDependenciesV1["store"],
      clock: { nowUtcNs: () => "1700000000000000000" }, ids: { next: (prefix: string) => `${prefix}-1` },
      session_policy: { ttl_seconds: "900", max_failed_attempts: 5, lockout_seconds: 300 },
    } as AdminApiDependenciesV1;
    try {
      await createAdminSessionV1(deps, { owner_email: "owner@example.test", password: "correct horse battery staple", device_id: "device-1" }, "request-1");
      throw new Error("expected enrollment required");
    } catch (error) {
      expect(error).toBeInstanceOf(AdminApiErrorV1);
      expect(error).toMatchObject({ code: "TOTP_ENROLLMENT_REQUIRED", data: { otpauth_uri: expect.stringMatching(/^otpauth:\/\//) } });
    }
  });

  it("uses one fakeable SQL seam and rolls back rejected Neon transactions", async () => {
    const statements: string[] = [];
    const pool = {
      async query<Row>() { return { rows: [] as Row[] }; },
      async end() {},
      async connect() {
        return {
          async query<Row>(sql: string) { statements.push(sql); return { rows: [] as Row[] }; },
          release() { statements.push("RELEASE"); },
        };
      },
    };
    const driver = createNeonPgDriverV1(pool);
    await expect(driver.transaction(async (tx) => {
      await tx.query("SELECT 1", []); throw new Error("expected rollback");
    })).rejects.toThrow("expected rollback");
    expect(statements).toEqual(["BEGIN", "SELECT 1", "ROLLBACK", "RELEASE"]);
  });
});
