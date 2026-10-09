import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  createLicenseWorkerV1,
  type LicenseWorkerDependenciesV1,
  type TrustedPrincipalV1,
} from "../../../src/worker/handler.js";
import { LicenseDecisionCacheV1 } from "../../../src/worker/cache.js";
import { PerLicenseRateLimiterV1 } from "../../../src/worker/rate_limit.js";
import { canonicalLicenseSnapshotV1 } from "../../../src/entitlement/decision.js";
import type { LicenseSnapshotV1 } from "../../../src/entitlement/models.js";
import type {
  AdminAccountRowV1,
  AdminApiDependenciesV1,
  AdminApiStorePortV1,
  AdminAuditRowV1,
  AdminDeviceRowV1,
  AdminPrincipalV1,
  AdminSubscriptionRowV1,
  AdminTransactionV1,
  AdminUserRowV1,
  AdminUserSeatRecordV1,
} from "../../../src/admin_api/models.js";

const F = JSON.parse(readFileSync(new URL("./probe_inputs.json", import.meta.url), "utf8")) as {
  now_utc_ns: string; owner_email: string; owner_password: string; wrong_password: string;
  owner_totp: string; wrong_totp: string; device_id: string; other_device_id: string;
  session_token: string; bad_login_canary: string; org_id: string; other_org_id: string;
  owner_user_id: string; subscription_id: string; user_id: string; device_target_id: string;
  plan_id: string; term_start_utc_ns: string; term_end_utc_ns: string; seats: string;
};

const TOKEN = F.session_token;
const PRINCIPAL: AdminPrincipalV1 = {
  schema_version: 1, org_id: F.org_id, user_id: F.owner_user_id,
  device_id: F.device_id, session_id: "session-admin-test-1",
};
const WORKER_PRINCIPAL: TrustedPrincipalV1 = {
  schemaVersion: 1, principalId: F.owner_user_id, orgId: F.org_id,
  audience: "leviathan-desktop", deviceId: F.device_id,
  scopes: ["license:read", "auth:introspect"], roles: ["Owner"],
};
const OWNER = Object.freeze({
  org_id: F.org_id, user_id: F.owner_user_id,
  password_hash_argon2id: "$argon2id$v=19$m=19456,t=2,p=1$c3ludGhldGlj$bm90LXJlYWwtaGFzaA",
  active: true, owner: true,
});
const NOW = F.now_utc_ns;

type IdempotencyValue = {
  readonly fingerprint: string;
  readonly receipt: { readonly resource_id: string; readonly resource_version: string; readonly audit_id: string };
};
interface FakeState {
  accounts: Map<string, AdminAccountRowV1 & { readonly active: boolean }>;
  users: Map<string, AdminUserSeatRecordV1>;
  subscriptions: Map<string, AdminSubscriptionRowV1>;
  devices: Map<string, AdminDeviceRowV1>;
  seats: Map<string, { readonly org_id: string; readonly subscription_id: string; readonly seat_id: string; readonly user_id: string; readonly role_id: string; readonly status: "ACTIVE" | "INVITED" | "REVOKED"; readonly version: string }>;
  audits: AdminAuditRowV1[];
  idempotency: Map<string, IdempotencyValue>;
}
interface AuthEvent {
  readonly audit_id: string;
  readonly action: "SESSION_CREATED" | "SESSION_REVOKED";
  readonly org_id: string;
  readonly actor_user_id: string;
  readonly occurred_at_utc_ns: string;
  readonly correlation_id: string;
  readonly reason: string;
}

function seededState(subscriptionStatus: AdminSubscriptionRowV1["status"] = "ACTIVE"): FakeState {
  const sub: AdminSubscriptionRowV1 = {
    subscription_id: F.subscription_id, org_id: F.org_id, plan_id: F.plan_id,
    term_start_utc_ns: F.term_start_utc_ns, term_end_utc_ns: F.term_end_utc_ns,
    seats: F.seats, status: subscriptionStatus, version: "1",
    created_at_utc_ns: NOW, updated_at_utc_ns: NOW,
  };
  const ownerUser: AdminUserSeatRecordV1 = {
    user_id: F.owner_user_id, role_id: "owner", seat_id: "seat-owner-1",
    status: "ACTIVE", version: "1", subscription_id: F.subscription_id,
  };
  const device: AdminDeviceRowV1 = {
    device_id: F.device_target_id, org_id: F.org_id, user_id: F.owner_user_id,
    status: "ACTIVE", created_at_utc_ns: NOW, last_seen_at_utc_ns: NOW,
    revoked_at_utc_ns: null, version: "1",
  };
  return {
    accounts: new Map([[F.org_id, { org_id: F.org_id, display_name: "Synthetic tenant", version: "1", active: true }]]),
    users: new Map([[`${F.org_id}:${F.owner_user_id}`, ownerUser]]),
    subscriptions: new Map([[`${F.org_id}:${F.subscription_id}`, sub]]),
    devices: new Map([[`${F.org_id}:${F.device_target_id}`, device]]),
    seats: new Map([[`${F.org_id}:seat-owner-1`, {
      org_id: F.org_id, subscription_id: F.subscription_id, seat_id: "seat-owner-1",
      user_id: F.owner_user_id, role_id: "owner", status: "ACTIVE", version: "1",
    }]]),
    audits: [], idempotency: new Map(),
  };
}

function copyState(state: FakeState): FakeState {
  return {
    accounts: new Map(state.accounts), users: new Map(state.users),
    subscriptions: new Map(state.subscriptions), devices: new Map(state.devices),
    seats: new Map(state.seats), audits: [...state.audits],
    idempotency: new Map(state.idempotency),
  };
}

function receiptKey(org: string, actor: string, key: string): string {
  return `${org}\u0000${actor}\u0000${key}`;
}

function makeHarness(options: {
  readonly failStoreAudit?: boolean;
  readonly failAuthAudit?: boolean;
  readonly authorizationAllowed?: boolean;
  readonly subscriptionStatus?: AdminSubscriptionRowV1["status"];
  readonly subscriptionVersion?: string;
  readonly maxFailedAttempts?: number;
  readonly adminConfigured?: boolean;
  readonly seedSession?: boolean;
} = {}) {
  let state = seededState(options.subscriptionStatus);
  const storeCounters = { transactions: 0, organizationCreates: 0, auditAttempts: 0 };
  let authEvents: AuthEvent[] = [];
  const sessions = new Map<string, { readonly principal: AdminPrincipalV1; readonly revoked: boolean }>();
  if (options.seedSession !== false) sessions.set(TOKEN, { principal: PRINCIPAL, revoked: false });
  const failures = new Map<string, number>();
  const actions: string[] = [];
  let nextId = 0;
  const ids: AdminApiDependenciesV1["ids"] = { next: (prefix) => `${prefix}-${++nextId}` };

  if (options.subscriptionVersion) {
    const old = state.subscriptions.get(`${F.org_id}:${F.subscription_id}`)!;
    state.subscriptions.set(`${F.org_id}:${F.subscription_id}`, { ...old, version: options.subscriptionVersion });
  }

  const store: AdminApiStorePortV1 = {
    transaction: async <T>(work: (tx: AdminTransactionV1) => Promise<T>): Promise<T> => {
      storeCounters.transactions += 1;
      const draft = copyState(state);
      const pg = {
        query: async <Row>(sql: string, params: readonly unknown[]) => {
          const tag = /\/\*(LIC(?:ADMIN|003)_[A-Z_]+)\*\//.exec(sql)?.[1] ?? "";
          let rows: unknown[] = [];
          const orgId = params[0] as string | undefined;
          if (tag === "LICADMIN_BOOTSTRAP_ORG_LOCK" || tag === "LIC003_ORG_LOCK") {
            const account = orgId ? draft.accounts.get(orgId) : undefined;
            rows = account ? [{ active: account.active }] : [];
          } else if (tag === "LICADMIN_BOOTSTRAP_ZERO_SEATS") {
            rows = [{ seat_count: String([...draft.seats.values()].filter((seat) => seat.org_id === orgId).length) }];
          } else if (tag === "LICADMIN_BOOTSTRAP_SUBSCRIPTION") {
            const sub = draft.subscriptions.get(`${params[0] as string}:${params[1] as string}`);
            rows = sub ? [{ subscription_id: sub.subscription_id, status: sub.status,
              seat_limit: sub.seats, term_start_utc_ns: sub.term_start_utc_ns, term_end_utc_ns: sub.term_end_utc_ns }] : [];
          } else if (tag === "LICADMIN_BOOTSTRAP_OWNER_ROLE") {
            rows = [{ role_id: "owner", immutable: true, org_id: null }];
          } else if (tag === "LICADMIN_BOOTSTRAP_OWNER_SEAT") {
            const seat = { org_id: params[0] as string, subscription_id: params[1] as string,
              seat_id: params[2] as string, user_id: params[3] as string, role_id: "owner" as const,
              status: "ACTIVE" as const, version: "1" };
            draft.seats.set(`${seat.org_id}:${seat.seat_id}`, seat);
            rows = [{ seat_id: seat.seat_id, version: seat.version }];
          }
          return { rows: rows as Row[] };
        },
      };
      const tx: AdminTransactionV1 = {
        seat_transactions: { transaction: async (callback) => callback(pg) },
        createOrganization: async ({ org_id, display_name, expected_version }) => {
          if (expected_version !== "0" || draft.accounts.has(org_id)) throw new Error("duplicate");
          storeCounters.organizationCreates += 1;
          const row = { org_id, display_name, version: "1", active: true as const };
          draft.accounts.set(org_id, row);
          return row;
        },
        createOwnerIdentity: async ({ org_id, user_id }) => {
          draft.users.set(`${org_id}:${user_id}`, {
            user_id, role_id: "owner", seat_id: null, status: "ACTIVE", version: "1",
            subscription_id: "subscription-pending",
          });
        },
        createSubscription: async (input) => {
          const row: AdminSubscriptionRowV1 = {
            subscription_id: input.subscription_id, org_id: input.org_id, plan_id: input.plan_id,
            term_start_utc_ns: input.term_start_utc_ns, term_end_utc_ns: input.term_end_utc_ns,
            seats: input.seats, status: input.status, version: "1",
            created_at_utc_ns: input.occurred_at_utc_ns, updated_at_utc_ns: input.occurred_at_utc_ns,
          };
          draft.subscriptions.set(`${row.org_id}:${row.subscription_id}`, row);
          return row;
        },
        createUserIdentity: async ({ org_id, user_id }) => {
          draft.users.set(`${org_id}:${user_id}`, {
            user_id, role_id: "member", seat_id: null, status: "INVITED", version: "1",
            subscription_id: "subscription-pending",
          });
        },
        findCurrentSubscription: async (org_id, occurred_at_utc_ns) => {
          const row = [...draft.subscriptions.values()].find((candidate) => candidate.org_id === org_id
            && candidate.status === "ACTIVE" && BigInt(occurred_at_utc_ns) >= BigInt(candidate.term_start_utc_ns)
            && BigInt(occurred_at_utc_ns) < BigInt(candidate.term_end_utc_ns));
          return row ?? null;
        },
        changeSubscription: async ({ org_id, subscription_id, patch, expected_version }) => {
          const key = `${org_id}:${subscription_id}`;
          const current = draft.subscriptions.get(key);
          if (!current || current.version !== expected_version) throw new Error("version conflict");
          const row = { ...current, ...patch, version: (BigInt(current.version) + 1n).toString(), updated_at_utc_ns: NOW } as AdminSubscriptionRowV1;
          draft.subscriptions.set(key, row);
          return row;
        },
        revokeDevice: async ({ org_id, device_id, expected_version, occurred_at_utc_ns }) => {
          const key = `${org_id}:${device_id}`;
          const current = draft.devices.get(key);
          if (!current || current.version !== expected_version) throw new Error("missing or stale device");
          const row: AdminDeviceRowV1 = { ...current, status: "REVOKED", version: (BigInt(current.version) + 1n).toString(), revoked_at_utc_ns: occurred_at_utc_ns };
          draft.devices.set(key, row);
          return row;
        },
        appendAudit: async (row) => {
          storeCounters.auditAttempts += 1;
          if (options.failStoreAudit && row.action === "ACCOUNT_CREATED") {
            throw new Error("synthetic audit sink failure");
          }
          draft.audits.push(row);
        },
        saveIdempotency: async ({ org_id, actor_user_id, idempotency_key, request_fingerprint, receipt }) => {
          const key = receiptKey(org_id, actor_user_id, idempotency_key);
          const old = draft.idempotency.get(key);
          if (old && old.fingerprint !== request_fingerprint) throw new Error("idempotency conflict");
          if (!old) draft.idempotency.set(key, { fingerprint: request_fingerprint, receipt });
          return old?.receipt ?? receipt;
        },
        readIdempotency: async ({ org_id, actor_user_id, idempotency_key, request_fingerprint }) => {
          const old = draft.idempotency.get(receiptKey(org_id, actor_user_id, idempotency_key));
          if (!old) return null;
          if (old.fingerprint !== request_fingerprint) throw new Error("idempotency conflict");
          return old.receipt;
        },
      };
      const result = await work(tx);
      state = draft;
      return result;
    },
    readAccount: async (org_id) => {
      const row = state.accounts.get(org_id);
      return row ? { org_id: row.org_id, display_name: row.display_name, version: row.version } : null;
    },
    readUser: async (org_id, user_id) => state.users.get(`${org_id}:${user_id}`) ?? null,
    listAccounts: async ({ org_id, page_size }) => ({
      items: [...state.accounts.values()].filter((row) => row.org_id === org_id)
        .slice(0, page_size).map(({ org_id: id, display_name, version }) => ({ org_id: id, display_name, version })),
      next_cursor: null,
    }),
    listUsers: async ({ org_id, page_size }) => ({
      items: [...state.users.entries()].filter(([key]) => key.startsWith(`${org_id}:`)).slice(0, page_size).map(([, row]) => ({
        user_id: row.user_id, role_id: row.role_id, seat_id: row.seat_id, status: row.status, version: row.version,
      })), next_cursor: null,
    }),
    listSubscriptions: async ({ org_id, page_size }) => ({ items: [...state.subscriptions.values()].filter((row) => row.org_id === org_id).slice(0, page_size), next_cursor: null }),
    readSubscription: async (org_id, subscription_id) => state.subscriptions.get(`${org_id}:${subscription_id}`) ?? null,
    listDevices: async ({ org_id, page_size }) => ({ items: [...state.devices.values()].filter((row) => row.org_id === org_id).slice(0, page_size), next_cursor: null }),
    listAudit: async ({ org_id, page_size }) => ({ items: state.audits.filter((row) => row.org_id === org_id).slice(0, page_size), next_cursor: null }),
    decodeCursor: async (cursor) => cursor,
    encodeCursor: async (last_key) => last_key,
  };

  const auth: AdminApiDependenciesV1["auth"] = {
    findOwnerByEmail: async (email) => email.toLowerCase() === F.owner_email ? OWNER : null,
    isLoginLocked: async (email, device_id) => (failures.get(`${email}:${device_id}`) ?? 0) >= (options.maxFailedAttempts ?? 3),
    recordFailedLogin: async ({ email, device_id, max_failed_attempts }) => {
      const key = `${email}:${device_id}`;
      const count = (failures.get(key) ?? 0) + 1;
      failures.set(key, count);
      return count >= max_failed_attempts;
    },
    clearFailedLogins: async (email, device_id) => { failures.delete(`${email}:${device_id}`); },
    verifyArgon2id: async (password, hash) => password === F.owner_password && hash === OWNER.password_hash_argon2id,
    verifyTotp: async (_user_id, code) => code === F.owner_totp,
    issueSession: async (input) => {
      if (options.failAuthAudit) throw new Error("synthetic auth audit failure");
      const event: AuthEvent = {
        audit_id: input.audit_id, action: "SESSION_CREATED", org_id: input.org_id,
        actor_user_id: input.user_id, occurred_at_utc_ns: input.issued_at_utc_ns,
        correlation_id: input.correlation_id, reason: input.reason,
      };
      const staged = new Map(sessions);
      staged.set(TOKEN, { principal: {
        schema_version: 1, org_id: input.org_id, user_id: input.user_id,
        device_id: input.device_id, session_id: input.token_id,
      }, revoked: false });
      sessions.clear();
      for (const [key, value] of staged) sessions.set(key, value);
      authEvents = [...authEvents, event];
      return TOKEN;
    },
    resolveSession: async (token, device_id) => {
      const found = sessions.get(token);
      return found && !found.revoked && found.principal.device_id === device_id ? found.principal : null;
    },
    revokeSession: async (input) => {
      if (options.failAuthAudit) throw new Error("synthetic auth audit failure");
      const found = sessions.get(input.token);
      if (!found || found.revoked || found.principal.device_id !== input.device_id) throw new Error("session unavailable");
      const event: AuthEvent = {
        audit_id: input.audit_id, action: "SESSION_REVOKED", org_id: found.principal.org_id,
        actor_user_id: found.principal.user_id, occurred_at_utc_ns: input.now_utc_ns,
        correlation_id: input.correlation_id, reason: input.reason,
      };
      const staged = new Map(sessions);
      staged.set(input.token, { principal: found.principal, revoked: true });
      sessions.clear();
      for (const [key, value] of staged) sessions.set(key, value);
      authEvents = [...authEvents, event];
    },
  };
  const adminApi: AdminApiDependenciesV1 = {
    auth,
    authorization: { authorize: async (_principal, action) => { actions.push(action); return options.authorizationAllowed ?? true; } },
    store,
    clock: { nowUtcNs: () => NOW },
    ids,
    session_policy: { ttl_seconds: "300", max_failed_attempts: options.maxFailedAttempts ?? 3, lockout_seconds: 60 },
  };
  const workerDependencies: LicenseWorkerDependenciesV1 = {
    principals: { resolve: async () => WORKER_PRINCIPAL },
    authorization: { authorize: async () => true },
    licenses: { readCurrent: async () => null },
    signingKeys: new Map(),
    clock: { nowMonotonicMs: () => 10_000, nowUtcNs: () => NOW },
    requestIdFactory: () => `request-${++nextId}`,
    cache: new LicenseDecisionCacheV1(),
    rateLimiter: new PerLicenseRateLimiterV1(),
    backgroundEligibility: { publishLease: async () => undefined },
    serverPolicy: { lowestTierApiRateLimitRps: "100" },
    metrics: { recordRatePolicyDefaulted: () => undefined },
    deadlines: { run: async (_operation, _timeout, invoke) => ({ status: "COMPLETED", value: await invoke(new AbortController().signal) }) },
    ...(options.adminConfigured === false ? {} : { adminApi }),
  };
  return {
    worker: createLicenseWorkerV1(workerDependencies), adminApi, storeCounters,
    authEvents: () => authEvents, actions, state: () => state,
  };
}

function request(path: string, method = "GET", body?: unknown, options: {
  readonly token?: string | null; readonly device?: string; readonly idempotency?: string | null;
} = {}): Request {
  const token = options.token === undefined ? TOKEN : options.token;
  const headers: Record<string, string> = {};
  if (token !== null) {
    headers.authorization = `Bearer ${token}`;
    headers["x-device-id"] = options.device ?? F.device_id;
  }
  if (body !== undefined) headers["content-type"] = "application/json";
  if (options.idempotency !== null && options.idempotency !== undefined) headers["idempotency-key"] = options.idempotency;
  return new Request(`https://licensing-worker.test${path}`, {
    method, headers, body: body === undefined ? undefined : JSON.stringify(body),
  });
}

async function result(response: Response): Promise<{ readonly response: Response; readonly text: string; readonly body: Record<string, unknown> }> {
  const text = await response.text();
  return { response, text, body: JSON.parse(text) as Record<string, unknown> };
}

function sessionBody(overrides: Record<string, unknown> = {}) {
  return { owner_email: F.owner_email, password: F.owner_password, totp_code: F.owner_totp, device_id: F.device_id, ...overrides };
}

function accountCreateBody(overrides: Record<string, unknown> = {}) {
  return {
    org: { name: "Synthetic account" },
    owner: { email: "new-owner@example.test" },
    initial_subscription: { plan_id: F.plan_id, term_start_utc_ns: F.term_start_utc_ns,
      term_end_utc_ns: F.term_end_utc_ns, seats: F.seats, status: "ACTIVE" },
    expected_version: "0", reason: "synthetic account provisioning", ...overrides,
  };
}

function subscriptionBody(overrides: Record<string, unknown> = {}) {
  return { plan_id: F.plan_id, term_start_utc_ns: F.term_start_utc_ns,
    term_end_utc_ns: F.term_end_utc_ns, seats: F.seats, status: "ACTIVE",
    expected_version: "1", reason: "synthetic subscription update", ...overrides };
}

describe("LIC-ADMIN-API-001 independent public Worker acceptance", () => {
  it("denies admin routes when the optional adapter is not configured", async () => {
    const h = makeHarness({ adminConfigured: false });
    const { response, body } = await result(await h.worker.fetch(request("/v1/admin/accounts", "GET", undefined, { token: null })));
    expect(response.status).toBe(503);
    expect(body).toMatchObject({ schema_version: 1, error: { code: "NOT_CONFIGURED" } });
  });

  it("issues a bounded device-bound login session with its audit receipt", async () => {
    const h = makeHarness();
    const { response, body } = await result(await h.worker.fetch(request("/v1/admin/session", "POST", sessionBody(), { token: null })));
    expect(response.status).toBe(200);
    const successText = JSON.stringify(body);
    expect(successText).not.toContain(F.owner_password);
    expect(successText).not.toContain(F.owner_totp);
    expect(body).toMatchObject({ schema_version: 1, data: {
      session_token: TOKEN, expires_at_utc_ns: (BigInt(NOW) + 300_000_000_000n).toString(), org_id: F.org_id,
    } });
    const data = body.data as Record<string, unknown>;
    expect(data.audit_id).toEqual(h.authEvents()[0]?.audit_id);
    expect(h.authEvents()).toHaveLength(1);
    expect(h.authEvents()[0]).toMatchObject({ action: "SESSION_CREATED", correlation_id: body.request_id, reason: "OWNER_MFA_LOGIN" });
    expect(JSON.stringify(h.authEvents())).not.toContain(TOKEN);
    expect(response.headers.get("cache-control")).toBe("no-store");
  });

  it("denies a wrong TOTP with a fixed error and no credential echo", async () => {
    const h = makeHarness();
    const { response, text, body } = await result(await h.worker.fetch(request("/v1/admin/session", "POST", sessionBody({
      totp_code: F.wrong_totp,
    }), { token: null })));
    expect(response.status).toBe(401);
    expect(body).toMatchObject({ error: { code: "AUTHENTICATION_FAILED" } });
    expect(text).not.toContain(F.wrong_totp);
  });

  it("locks a device after bounded failed logins and stays denied", async () => {
    const h = makeHarness({ maxFailedAttempts: 2 });
    for (let i = 0; i < 2; i += 1) {
      const denied = await result(await h.worker.fetch(request("/v1/admin/session", "POST", sessionBody({ totp_code: F.wrong_totp }), { token: null })));
      expect(denied.response.status).toBe(i === 0 ? 401 : 429);
    }
    const locked = await result(await h.worker.fetch(request("/v1/admin/session", "POST", sessionBody(), { token: null })));
    expect(locked.response.status).toBe(429);
    expect(locked.body).toMatchObject({ error: { code: "LOGIN_LOCKED" } });
    expect(h.authEvents()).toHaveLength(0);
  });

  it("rejects a session used from a different device", async () => {
    const h = makeHarness();
    await h.worker.fetch(request("/v1/admin/session", "POST", sessionBody(), { token: null }));
    const denied = await result(await h.worker.fetch(request(`/v1/admin/accounts/${F.org_id}`, "GET", undefined, { device: F.other_device_id })));
    expect(denied.response.status).toBe(401);
    expect(denied.body).toMatchObject({ error: { code: "UNAUTHENTICATED" } });
    expect(denied.text).not.toContain(TOKEN);
  });

  it("revokes a session once and rejects replay of the revoked token", async () => {
    const h = makeHarness();
    await h.worker.fetch(request("/v1/admin/session", "POST", sessionBody(), { token: null }));
    const revoked = await result(await h.worker.fetch(request("/v1/admin/session", "DELETE")));
    expect(revoked.response.status).toBe(200);
    expect(revoked.body).toMatchObject({ data: { revoked: true } });
    expect(revoked.body.audit_id).toEqual(h.authEvents()[1]?.audit_id);
    expect(h.authEvents()[1]).toMatchObject({ action: "SESSION_REVOKED", correlation_id: revoked.body.request_id, reason: "OWNER_SESSION_REVOKED" });
    expect(revoked.text).not.toContain(TOKEN);
    const replayed = await result(await h.worker.fetch(request(`/v1/admin/accounts/${F.org_id}`)));
    expect(replayed.response.status).toBe(401);
    expect(replayed.body).toMatchObject({ error: { code: "UNAUTHENTICATED" } });
    expect(replayed.text).not.toContain(TOKEN);
  });

  it("fails session creation closed when the auth audit transaction fails", async () => {
    const h = makeHarness({ failAuthAudit: true, seedSession: false });
    const denied = await result(await h.worker.fetch(request("/v1/admin/session", "POST", sessionBody(), { token: null })));
    expect(denied.response.status).toBe(503);
    expect(denied.body).toMatchObject({ error: { code: "AUTH_UNAVAILABLE" } });
    const after = await result(await h.worker.fetch(request(`/v1/admin/accounts/${F.org_id}`, "GET")));
    expect(after.response.status).toBe(401);
    expect(h.authEvents()).toHaveLength(0);
  });

  it("makes a fresh SEC-002 decision and denies a false authorization", async () => {
    const h = makeHarness({ authorizationAllowed: false });
    const denied = await result(await h.worker.fetch(request(`/v1/admin/accounts/${F.org_id}`)));
    expect(denied.response.status).toBe(403);
    expect(denied.body).toMatchObject({ error: { code: "FORBIDDEN" } });
    expect(h.actions).toContain("accounts:read");
  });

  it("denies cross-tenant reads and writes without opening a transaction", async () => {
    const h = makeHarness();
    const read = await result(await h.worker.fetch(request(`/v1/admin/accounts/${F.other_org_id}`)));
    const write = await result(await h.worker.fetch(request(`/v1/admin/accounts/${F.other_org_id}/users`, "POST", {
      email: "another@example.test", role_id: "member", expected_version: "0", reason: "synthetic invite",
    }, { idempotency: "cross-tenant-write" })));
    expect(read.response.status).toBe(404);
    expect(write.response.status).toBe(404);
    expect(h.storeCounters.transactions).toBe(0);
    expect(h.state().audits).toHaveLength(0);
  });

  it("creates an account from owner email only and records an audit receipt", async () => {
    const h = makeHarness();
    const body = accountCreateBody();
    expect(Object.keys(body.owner)).toEqual(["email"]);
    const { response, body: resultBody } = await result(await h.worker.fetch(request("/v1/admin/accounts", "POST", body, { idempotency: "account-create-1" })));
    expect(response.status).toBe(200);
    expect(resultBody.audit_id).toEqual(expect.any(String));
    expect((resultBody.data as Record<string, unknown>).resource_id).toEqual(expect.any(String));
    expect(h.state().audits.map((row) => row.action)).toContain("ACCOUNT_CREATED");
    expect(h.state().accounts.size).toBe(2);
    expect(h.state().seats.size).toBe(2);
  });

  it("replays an identical idempotency key as a no-op with the original audit ID", async () => {
    const h = makeHarness();
    const body = accountCreateBody();
    const first = await result(await h.worker.fetch(request("/v1/admin/accounts", "POST", body, { idempotency: "account-idem-same" })));
    const transactionsBeforeReplay = h.storeCounters.transactions;
    const createsBeforeReplay = h.storeCounters.organizationCreates;
    const second = await result(await h.worker.fetch(request("/v1/admin/accounts", "POST", body, { idempotency: "account-idem-same" })));
    expect(second.response.status).toBe(200);
    expect((second.body.data as Record<string, unknown>).resource_id).toBe((first.body.data as Record<string, unknown>).resource_id);
    expect(second.body.audit_id).toBe(first.body.audit_id);
    expect(h.storeCounters.transactions).toBe(transactionsBeforeReplay + 1);
    expect(h.storeCounters.organizationCreates).toBe(createsBeforeReplay);
    expect(h.state().audits.filter((row) => row.action === "ACCOUNT_CREATED")).toHaveLength(1);
  });

  it("rejects an idempotency-key replay with changed content without a partial write", async () => {
    const h = makeHarness();
    const first = await h.worker.fetch(request("/v1/admin/accounts", "POST", accountCreateBody(), { idempotency: "account-idem-conflict" }));
    const before = h.state().accounts.size;
    const second = await result(await h.worker.fetch(request("/v1/admin/accounts", "POST", accountCreateBody({ org: { name: "Changed name" } }), { idempotency: "account-idem-conflict" })));
    expect(first.status).toBe(200);
    expect(second.response.status).toBe(409);
    expect(second.body).toMatchObject({ error: { code: "IDEMPOTENCY_CONFLICT" } });
    expect(h.state().accounts.size).toBe(before);
  });

  it("requires idempotency keys on each account, user, subscription and device mutation", async () => {
    const h = makeHarness();
    const requests: Request[] = [
      request("/v1/admin/accounts", "POST", accountCreateBody(), { idempotency: null }),
      request(`/v1/admin/accounts/${F.org_id}/users`, "POST", { email: "invite@example.test", role_id: "member", expected_version: "0", reason: "invite" }, { idempotency: null }),
      request(`/v1/admin/accounts/${F.org_id}/users/${F.owner_user_id}/role`, "PUT", { role_id: "admin", expected_version: "1", reason: "change role" }, { idempotency: null }),
      request(`/v1/admin/accounts/${F.org_id}/subscriptions`, "POST", subscriptionBody({ expected_version: "1" }), { idempotency: null }),
      request(`/v1/admin/accounts/${F.org_id}/subscriptions/${F.subscription_id}`, "PUT", subscriptionBody(), { idempotency: null }),
      request(`/v1/admin/accounts/${F.org_id}/subscriptions/${F.subscription_id}/extend`, "POST", { term_end_utc_ns: "1800007200000000000", expected_version: "1", reason: "extend" }, { idempotency: null }),
      request(`/v1/admin/accounts/${F.org_id}/subscriptions/${F.subscription_id}/suspend`, "POST", { expected_version: "1", reason: "suspend" }, { idempotency: null }),
      request(`/v1/admin/accounts/${F.org_id}/subscriptions/${F.subscription_id}/resume`, "POST", { target_status: "ACTIVE", expected_version: "1", reason: "resume" }, { idempotency: null }),
      request(`/v1/admin/accounts/${F.org_id}/devices/${F.device_target_id}/revoke`, "POST", { expected_version: "1", reason: "revoke device" }, { idempotency: null }),
    ];
    for (const req of requests) {
      const denied = await result(await h.worker.fetch(req));
      expect(denied.response.status).toBe(400);
      expect(denied.body).toMatchObject({ error: { code: "INVALID_REQUEST" } });
    }
    expect(h.storeCounters.transactions).toBe(0);
    expect(h.state().audits).toHaveLength(0);
  });

  it("rejects TRIAL for account bootstrap and subscription writes before any transaction", async () => {
    const h = makeHarness();
    const account = await result(await h.worker.fetch(request("/v1/admin/accounts", "POST", accountCreateBody({
      initial_subscription: { plan_id: F.plan_id, term_start_utc_ns: F.term_start_utc_ns,
        term_end_utc_ns: F.term_end_utc_ns, seats: F.seats, status: "TRIAL" },
    }), { idempotency: "trial-account" })));
    const sub = await result(await h.worker.fetch(request(`/v1/admin/accounts/${F.org_id}/subscriptions`, "POST", subscriptionBody({ status: "TRIAL" }), { idempotency: "trial-subscription" })));
    expect(account.response.status).toBe(422);
    expect(sub.response.status).toBe(422);
    expect(account.body).toMatchObject({ error: { code: "UNSUPPORTED_STATUS" } });
    expect(sub.body).toMatchObject({ error: { code: "UNSUPPORTED_STATUS" } });
    expect(h.storeCounters.transactions).toBe(0);
    expect(h.state().accounts.size).toBe(1);
    expect(h.state().audits).toHaveLength(0);
  });

  it("rejects an invalid status transition before mutation or audit", async () => {
    const h = makeHarness({ subscriptionStatus: "CANCELED" });
    const denied = await result(await h.worker.fetch(request(`/v1/admin/accounts/${F.org_id}/subscriptions/${F.subscription_id}`, "PUT", subscriptionBody({ status: "ACTIVE" }), { idempotency: "invalid-transition" })));
    expect(denied.response.status).toBe(409);
    expect(denied.body).toMatchObject({ error: { code: "INVALID_STATUS_TRANSITION" } });
    expect(h.storeCounters.transactions).toBe(0);
    expect(h.state().audits).toHaveLength(0);
    expect(h.state().subscriptions.get(`${F.org_id}:${F.subscription_id}`)?.status).toBe("CANCELED");
  });

  it("enforces expected-version CAS on a subscription update", async () => {
    const h = makeHarness({ subscriptionVersion: "2" });
    const denied = await result(await h.worker.fetch(request(`/v1/admin/accounts/${F.org_id}/subscriptions/${F.subscription_id}`, "PUT", subscriptionBody({ expected_version: "1" }), { idempotency: "stale-version" })));
    expect(denied.response.status).toBe(409);
    expect(denied.body).toMatchObject({ error: { code: "VERSION_CONFLICT" } });
    expect(h.storeCounters.transactions).toBe(0);
  });

  it("rolls back the complete account mutation when same-transaction audit fails", async () => {
    const h = makeHarness({ failStoreAudit: true });
    const denied = await result(await h.worker.fetch(request("/v1/admin/accounts", "POST", accountCreateBody(), { idempotency: "audit-rollback" })));
    expect(denied.response.status).toBe(409);
    expect(denied.body).toMatchObject({ error: { code: "MUTATION_REJECTED" } });
    expect(h.state().accounts.size).toBe(1);
    expect(h.state().users.size).toBe(1);
    expect(h.state().subscriptions.size).toBe(1);
    expect(h.state().seats.size).toBe(1);
    expect(h.state().audits).toHaveLength(0);
    expect(h.state().idempotency.size).toBe(0);
  });

  it("keeps credential canaries out of denials, account responses, audits and log capture", async () => {
    const h = makeHarness();
    const logs: string[] = [];
    const original = { log: console.log, warn: console.warn, error: console.error };
    console.log = (...args: unknown[]) => { logs.push(args.map(String).join(" ")); };
    console.warn = (...args: unknown[]) => { logs.push(args.map(String).join(" ")); };
    console.error = (...args: unknown[]) => { logs.push(args.map(String).join(" ")); };
    let outputs = "";
    try {
      const bad = await result(await h.worker.fetch(request("/v1/admin/session", "POST", sessionBody({
        password: F.bad_login_canary, totp_code: F.wrong_totp,
      }), { token: null })));
      outputs += bad.text;
      const created = await result(await h.worker.fetch(request("/v1/admin/accounts", "POST", accountCreateBody(), { idempotency: "redaction-account" })));
      outputs += created.text;
    } finally {
      console.log = original.log; console.warn = original.warn; console.error = original.error;
    }
    const captured = `${outputs}\n${logs.join("\n")}\n${JSON.stringify(h.state().audits)}\n${JSON.stringify(h.authEvents())}`;
    for (const secret of [F.owner_password, F.wrong_password, F.wrong_totp, F.bad_login_canary, TOKEN]) {
      expect(captured).not.toContain(secret);
    }
  });

  it("preserves the existing LIC-004 license route behavior", async () => {
    const keyPair = await globalThis.crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    const unsigned: LicenseSnapshotV1 = {
      schemaVersion: 1, orgId: F.org_id, licenseId: "license-existing-test", subscriptionRevision: "1",
      status: "ACTIVE", termStartUtcNs: (BigInt(NOW) - 10_000_000_000n).toString(),
      termEndUtcNs: (BigInt(NOW) + 3_600_000_000_000n).toString(), issuedAtUtcNs: NOW,
      lastOnlineVerifiedUtcNs: NOW, features: { decisioning: true }, limits: { seats: "5", api_rate_limit_rps: "100" },
      audience: "leviathan-desktop", deviceId: F.device_id, signingKeyId: "lic004-test-key",
      signature: { algorithm: "ECDSA_P256_SHA256", value: "" },
    };
    const bytes = canonicalLicenseSnapshotV1(unsigned);
    const buffer = new ArrayBuffer(bytes.byteLength); new Uint8Array(buffer).set(bytes);
    const signature = await globalThis.crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, keyPair.privateKey, buffer);
    const signatureValue = btoa(String.fromCharCode(...new Uint8Array(signature))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const snapshot: LicenseSnapshotV1 = { ...unsigned, signature: { algorithm: "ECDSA_P256_SHA256", value: signatureValue } };
    const h = makeHarness();
    const originalWorker = createLicenseWorkerV1({
      principals: { resolve: async () => WORKER_PRINCIPAL }, authorization: { authorize: async () => true },
      licenses: { readCurrent: async () => snapshot }, signingKeys: new Map([["lic004-test-key", keyPair.publicKey]]),
      clock: { nowMonotonicMs: () => 10_000, nowUtcNs: () => NOW }, requestIdFactory: () => "lic004-request",
      cache: new LicenseDecisionCacheV1(), rateLimiter: new PerLicenseRateLimiterV1(),
      backgroundEligibility: { publishLease: async () => undefined }, serverPolicy: { lowestTierApiRateLimitRps: "100" },
      metrics: { recordRatePolicyDefaulted: () => undefined },
      deadlines: { run: async (_operation, _timeout, invoke) => ({ status: "COMPLETED", value: await invoke(new AbortController().signal) }) },
      adminApi: h.adminApi,
    });
    const response = await originalWorker.fetch(request("/v1/admin/license", "GET", undefined, { token: null }));
    expect(response.status).toBe(200);
    const body = await response.json() as Record<string, unknown>;
    expect(body.schema_version).toBe(1);
    expect(body.license).toMatchObject({ orgId: F.org_id, status: "ACTIVE" });
  });
});
