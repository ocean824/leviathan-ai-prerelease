import { beforeEach, describe, expect, it } from "vitest";
import { adminApiRoutes } from "../src/admin_api/routes.js";
import { bootstrapOwnerSeat, createAccountV1 } from "../src/admin_api/service.js";
import type { AdminApiDependenciesV1, AdminApiStorePortV1, AdminPrincipalV1, AdminTransactionV1 } from "../src/admin_api/models.js";

const NOW = "1800000000000000000";
const TOKEN = "synthetic-admin-session-token-0123456789";
const OWNER = {
  org_id: "org-1", user_id: "user-owner", password_hash_argon2id: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA",
  active: true, owner: true,
};
const PRINCIPAL: AdminPrincipalV1 = {
  schema_version: 1, org_id: "org-1", user_id: "user-owner", device_id: "device-1", session_id: "session-1",
};

function harness(): { dependencies: AdminApiDependenciesV1; counters: Record<string, number> } {
  const counters: Record<string, number> = { password: 0, totp: 0, authz: 0, transactions: 0 };
  let id = 0;
  const dependencies: AdminApiDependenciesV1 = {
    auth: {
      findOwnerByEmail: async () => OWNER,
      isLoginLocked: async () => false,
      recordFailedLogin: async () => false,
      clearFailedLogins: async () => undefined,
      verifyArgon2id: async (password, hash) => {
        counters.password += 1;
        return hash === OWNER.password_hash_argon2id && password === "safe-test-password";
      },
      verifyTotp: async (_userId, code) => { counters.totp += 1; return code === "123456"; },
      issueSession: async () => TOKEN,
      resolveSession: async () => PRINCIPAL,
      revokeSession: async () => undefined,
    },
    authorization: { authorize: async () => { counters.authz += 1; return true; } },
    store: {
      transaction: async (work) => { counters.transactions += 1; throw new Error("unexpected transaction"); },
      readAccount: async () => ({ org_id: "org-1", display_name: "Test Org", version: "1" }),
      readUser: async () => null,
      listAccounts: async () => ({ items: [], next_cursor: null }),
      listUsers: async () => ({ items: [], next_cursor: null }),
      listSubscriptions: async () => ({ items: [], next_cursor: null }),
      readSubscription: async () => null,
      listDevices: async () => ({ items: [], next_cursor: null }),
      listAudit: async () => ({ items: [], next_cursor: null }),
      decodeCursor: async (cursor) => cursor,
      encodeCursor: async (cursor) => cursor,
    },
    clock: { nowUtcNs: () => NOW },
    ids: { next: (prefix) => `${prefix}-${++id}` },
    session_policy: { ttl_seconds: "300", max_failed_attempts: 5, lockout_seconds: 300 },
  };
  return { dependencies, counters };
}

function accountFixture(options: { secondBootstrap?: boolean; failAccountAudit?: boolean } = {}) {
  const base = harness().dependencies;
  let dependencies: AdminApiDependenciesV1;
  const committed = { orgs: [] as string[], subs: [] as string[], seats: [] as string[], audits: [] as string[] };
  let nextOrg = "";
  let nextOwner = "";
  let capturedSecondBootstrap: unknown = null;
  const idCounts = new Map<string, number>();
  const idPort = { next: (prefix: Parameters<AdminApiDependenciesV1["ids"]["next"]>[0]) => {
    const value = (idCounts.get(prefix) ?? 0) + 1; idCounts.set(prefix, value); return `${prefix}-${value}`;
  } };
  const store: AdminApiStorePortV1 = {
    ...base.store,
    transaction: async (work) => {
      const staged = { orgs: [...committed.orgs], subs: [...committed.subs], seats: [...committed.seats], audits: [...committed.audits] };
      let tx: AdminTransactionV1;
      const pg = {
        query: async <Row>(sql: string, _params: readonly unknown[]) => {
          let rows: unknown[] = [];
          if (sql.includes("LICADMIN_BOOTSTRAP_ORG_LOCK")) rows = [{ active: true }];
          else if (sql.includes("LICADMIN_BOOTSTRAP_ZERO_SEATS")) rows = [{ seat_count: String(staged.seats.length) }];
          else if (sql.includes("LICADMIN_BOOTSTRAP_SUBSCRIPTION")) rows = [{
            subscription_id: "subscription-1", status: "ACTIVE", seat_limit: "5",
            term_start_utc_ns: NOW, term_end_utc_ns: (BigInt(NOW) + 60_000_000_000n).toString(),
          }];
          else if (sql.includes("LICADMIN_BOOTSTRAP_OWNER_ROLE")) rows = [{ role_id: "owner", immutable: true, org_id: null }];
          else if (sql.includes("LICADMIN_BOOTSTRAP_OWNER_SEAT")) {
            staged.seats.push("owner-seat"); rows = [{ seat_id: "seat-1", version: "1" }];
          }
          return { rows: rows as Row[] };
        },
      };
      tx = {
        seat_transactions: { transaction: async (callback) => callback(pg) },
        createOrganization: async ({ org_id }) => { nextOrg = org_id; staged.orgs.push(org_id); return { org_id, display_name: "New Org", version: "1" }; },
        createOwnerIdentity: async ({ user_id }) => { nextOwner = user_id; },
        createSubscription: async ({ org_id, subscription_id, plan_id, term_start_utc_ns, term_end_utc_ns, seats, status }) => {
          staged.subs.push(subscription_id);
          return { org_id, subscription_id, plan_id, term_start_utc_ns, term_end_utc_ns,
            seats, status, version: "1", created_at_utc_ns: NOW, updated_at_utc_ns: NOW };
        },
        createUserIdentity: async () => undefined,
        findCurrentSubscription: async () => null,
        changeSubscription: async ({ org_id, subscription_id, patch, expected_version }) => ({
          org_id, subscription_id, plan_id: "plan-1", term_start_utc_ns: NOW,
          term_end_utc_ns: (BigInt(NOW) + 60_000_000_000n).toString(), seats: "5",
          status: (patch.status ?? "ACTIVE") as "ACTIVE", version: (BigInt(expected_version) + 1n).toString(),
          created_at_utc_ns: NOW, updated_at_utc_ns: NOW,
        }),
        revokeDevice: async () => { throw new Error("unexpected"); },
        appendAudit: async (row) => {
          if (options.failAccountAudit && row.action === "ACCOUNT_CREATED") throw new Error("synthetic audit failure");
          staged.audits.push(row.action);
          if (options.secondBootstrap && row.action === "ASSIGN") {
            try { await bootstrapOwnerSeat(tx, nextOrg, nextOwner); }
            catch (error) { capturedSecondBootstrap = error; }
          }
        },
        saveIdempotency: async ({ receipt }) => receipt,
        readIdempotency: async () => null,
      };
      const result = await work(tx);
      committed.orgs = staged.orgs; committed.subs = staged.subs;
      committed.seats = staged.seats; committed.audits = staged.audits;
      return result;
    },
  };
  dependencies = { ...base, ids: idPort, store };
  return { dependencies, committed, secondBootstrap: () => capturedSecondBootstrap };
}

function request(path: string, method = "GET", body?: unknown, auth = true): Request {
  const headers: Record<string, string> = {};
  if (auth) {
    headers.authorization = `Bearer ${TOKEN}`;
    headers["x-device-id"] = "device-1";
  }
  if (body !== undefined) headers["content-type"] = "application/json";
  if (method !== "GET" && method !== "DELETE") headers["idempotency-key"] = "idem-1";
  return new Request(`https://worker.test${path}`, {
    method, headers, body: body === undefined ? undefined : JSON.stringify(body),
  });
}

async function json(response: Response): Promise<Record<string, unknown>> {
  return await response.json() as Record<string, unknown>;
}

describe("LIC-ADMIN-API-001 fake-port boundary", () => {
  let deps: AdminApiDependenciesV1;
  let counters: Record<string, number>;
  beforeEach(() => { ({ dependencies: deps, counters } = harness()); });

  it("returns a fixed default-deny response when optional Worker wiring is absent", async () => {
    const response = await adminApiRoutes(request("/v1/admin/accounts"), undefined);
    expect(response.status).toBe(503);
    expect(await json(response)).toMatchObject({ error: { code: "NOT_CONFIGURED" } });
    expect(response.headers.get("cache-control")).toBe("no-store");
  });

  it("requires password and TOTP, returns a short-lived device-bound session result", async () => {
    const response = await adminApiRoutes(request("/v1/admin/session", "POST", {
      owner_email: "owner@example.test", password: "safe-test-password", totp_code: "123456", device_id: "device-1",
    }, false), deps);
    expect(response.status).toBe(200);
    expect(await json(response)).toMatchObject({ data: {
      session_token: TOKEN, expires_at_utc_ns: (BigInt(NOW) + 300_000_000_000n).toString(), org_id: "org-1",
    } });
    expect(counters.password).toBe(1);
    expect(counters.totp).toBe(1);
    expect(response.headers.get("cache-control")).toBe("no-store");
  });

  it("denies bad MFA with a generic typed error and never echoes supplied credentials", async () => {
    const secret = "synthetic-bad-password-never-reflect";
    const response = await adminApiRoutes(request("/v1/admin/session", "POST", {
      owner_email: "owner@example.test", password: secret, totp_code: "135791", device_id: "device-1",
    }, false), deps);
    expect(response.status).toBe(401);
    const text = await response.text();
    expect(text).not.toContain(secret);
    expect(text).not.toContain("135791");
    expect(JSON.parse(text)).toMatchObject({ error: { code: "AUTHENTICATION_FAILED" } });
  });

  it("fails session creation closed when the operator-approved TTL is absent", async () => {
    deps = { ...deps, session_policy: { ...deps.session_policy, ttl_seconds: null } };
    const response = await adminApiRoutes(request("/v1/admin/session", "POST", {
      owner_email: "owner@example.test", password: "safe-test-password", totp_code: "123456", device_id: "device-1",
    }, false), deps);
    expect(response.status).toBe(503);
    expect(await json(response)).toMatchObject({ error: { code: "SESSION_POLICY_NOT_CONFIGURED" } });
    expect(counters.password).toBe(0);
  });

  it("makes a fresh SEC-002 decision before a tenant-scoped collection read", async () => {
    const response = await adminApiRoutes(request("/v1/admin/accounts"), deps);
    expect(response.status).toBe(200);
    expect(counters.authz).toBe(1);
    expect(await json(response)).toMatchObject({ data: { items: [], next_cursor: null } });
  });

  it("hides cross-tenant account details as not found", async () => {
    const response = await adminApiRoutes(request("/v1/admin/accounts/org-other"), deps);
    expect(response.status).toBe(404);
    expect(await json(response)).toMatchObject({ error: { code: "NOT_FOUND" } });
  });

  it("rejects unsupported status before opening a transaction", async () => {
    const response = await adminApiRoutes(request("/v1/admin/accounts/org-1/subscriptions", "POST", {
      plan_id: "plan-basic", term_start_utc_ns: NOW,
      term_end_utc_ns: (BigInt(NOW) + 60_000_000_000n).toString(), seats: "5",
      status: "TRIAL", expected_version: "1", reason: "operator request",
    }), deps);
    expect(response.status).toBe(422);
    expect(await json(response)).toMatchObject({ error: { code: "UNSUPPORTED_STATUS" } });
    expect(counters.transactions).toBe(0);
  });

  it("fails closed on unknown row enum values from the store", async () => {
    const badStore = {
      ...deps.store,
      listDevices: async () => ({ items: [{ device_id: "device-x", org_id: "org-1", user_id: "user-x",
        status: "UNKNOWN", created_at_utc_ns: NOW, last_seen_at_utc_ns: null,
        revoked_at_utc_ns: null, version: "1" }], next_cursor: null }),
    } as unknown as AdminApiDependenciesV1["store"];
    deps = { ...deps, store: badStore };
    const response = await adminApiRoutes(request("/v1/admin/accounts/org-1/devices"), deps);
    expect(response.status).toBe(503);
    expect(await json(response)).toMatchObject({ error: { code: "STORE_UNAVAILABLE" } });
  });

  it("allows one initial Owner seat in the newly created account and denies a second call", async () => {
    const fixture = accountFixture({ secondBootstrap: true });
    await createAccountV1(fixture.dependencies, PRINCIPAL, {
      org_name: "New Org", owner_email: "new-owner@example.test", plan_id: "plan-1",
      term_start_utc_ns: NOW, term_end_utc_ns: (BigInt(NOW) + 60_000_000_000n).toString(),
      seats: "5", status: "ACTIVE", expected_version: "0", reason: "approved provisioning",
      idempotency_key: "account-idem", request_id: "request-test",
    }, NOW);
    expect(fixture.committed.orgs).toHaveLength(1);
    expect(fixture.committed.subs).toHaveLength(1);
    expect(fixture.committed.seats).toHaveLength(1);
    expect(fixture.secondBootstrap()).toMatchObject({ code: "BOOTSTRAP_DENIED" });
  });

  it("denies bootstrap against a pre-existing org even with a transaction port", async () => {
    const tx = { seat_transactions: { transaction: async () => undefined } } as unknown as AdminTransactionV1;
    await expect(bootstrapOwnerSeat(tx, "org-existing", "user-existing"))
      .rejects.toMatchObject({ code: "BOOTSTRAP_DENIED" });
  });

  it("rolls back org, subscription and seat when the enclosing account audit fails", async () => {
    const fixture = accountFixture({ failAccountAudit: true });
    await expect(createAccountV1(fixture.dependencies, PRINCIPAL, {
      org_name: "New Org", owner_email: "new-owner@example.test", plan_id: "plan-1",
      term_start_utc_ns: NOW, term_end_utc_ns: (BigInt(NOW) + 60_000_000_000n).toString(),
      seats: "5", status: "ACTIVE", expected_version: "0", reason: "approved provisioning",
      idempotency_key: "account-idem", request_id: "request-test",
    }, NOW)).rejects.toMatchObject({ code: "MUTATION_REJECTED" });
    expect(fixture.committed).toEqual({ orgs: [], subs: [], seats: [], audits: [] });
  });
});
