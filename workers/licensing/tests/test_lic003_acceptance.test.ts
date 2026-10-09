import { describe, expect, it } from "vitest";
import type { PgQueryV1, SubscriptionTransactionPortV1 } from "../src/db/repository.js";
import {
  SYSTEM_ROLE_ADMIN,
  SYSTEM_ROLE_OWNER,
  type SeatCommandV1,
} from "../src/admin/seat_role_models.js";
import { applySeatCommandV1 } from "../src/admin/seat_role_service.js";

type Row = Record<string, unknown>;
type Seat = {
  orgId: string; subscriptionId: string; seatId: string; userId: string;
  roleId: string; status: string; version: string; assignedAtUtcNs: string;
  updatedAtUtcNs: string; auditEventId: string;
};
type Store = {
  orgs: Map<string, boolean>;
  subs: Map<string, { status: string; seatLimit: string; start: string; end: string }>;
  roles: Map<string, { orgId: string | null; name: string; immutable: boolean }>;
  seats: Map<string, Seat>;
  audits: Map<string, Row>;
  idem: Map<string, { hash: string; result: string }>;
};
const key = (...parts: string[]) => JSON.stringify(parts);
const seatKey = (org: string, seat: string) => key(org, seat);
const idemKey = (org: string, actor: string, idem: string) => key(org, actor, idem);

function clone(store: Store): Store {
  return {
    orgs: new Map(store.orgs),
    subs: new Map([...store.subs].map(([k, v]) => [k, { ...v }])),
    roles: new Map([...store.roles].map(([k, v]) => [k, { ...v }])),
    seats: new Map([...store.seats].map(([k, v]) => [k, { ...v }])),
    audits: new Map([...store.audits].map(([k, v]) => [k, { ...v }])),
    idem: new Map([...store.idem].map(([k, v]) => [k, { ...v }])),
  };
}

/** A serialized transaction fake with private drafts and rollback on rejection. */
class LicensingFake implements SubscriptionTransactionPortV1 {
  private db: Store = {
    orgs: new Map(), subs: new Map(), roles: new Map(), seats: new Map(),
    audits: new Map(), idem: new Map(),
  };
  private tail: Promise<void> = Promise.resolve();
  private readonly observedQueries: Array<{ tag: string | undefined; sql: string }> = [];
  dropNextAudit = false;

  constructor(limit = "4") {
    this.addOrg("org-a");
    this.addSub("org-a", "sub-a", limit);
    this.addRole(SYSTEM_ROLE_OWNER, null, "Owner", true);
    this.addRole(SYSTEM_ROLE_ADMIN, null, "Admin", true);
    this.addRole("role-member", null, "Member", true);
    this.addRole("role-custom", "org-a", "Custom", false);
    this.addSeat({
      orgId: "org-a", subscriptionId: "sub-a", seatId: "seat-owner", userId: "owner-a",
      roleId: SYSTEM_ROLE_OWNER, status: "ACTIVE", version: "1", assignedAtUtcNs: "100",
      updatedAtUtcNs: "100", auditEventId: "seed-owner",
    });
  }

  addOrg(id: string, active = true): void { this.db.orgs.set(id, active); }
  addSub(org: string, id: string, limit = "4", status = "ACTIVE"): void {
    this.db.subs.set(key(org, id), { status, seatLimit: limit, start: "0", end: "999999" });
  }
  addRole(id: string, orgId: string | null, name: string, immutable: boolean): void {
    this.db.roles.set(id, { orgId, name, immutable });
  }
  addSeat(seat: Seat): void { this.db.seats.set(seatKey(seat.orgId, seat.seatId), { ...seat }); }
  seats(): Seat[] { return [...this.db.seats.values()].map((row) => ({ ...row })); }
  audits(): Row[] { return [...this.db.audits.values()].map((row) => ({ ...row })); }
  idempotencyCount(): number { return this.db.idem.size; }
  queries(): Array<{ tag: string | undefined; sql: string }> { return [...this.observedQueries]; }

  async transaction<T>(work: (tx: PgQueryV1) => Promise<T>): Promise<T> {
    const prior = this.tail;
    let release!: () => void;
    this.tail = new Promise<void>((resolve) => { release = resolve; });
    await prior;
    const draft = clone(this.db);
    const tx: PgQueryV1 = {
      query: async <R>(sql: string, params: readonly unknown[]) => ({
        rows: this.run(draft, sql, params) as R[],
      }),
    };
    try {
      const result = await work(tx);
      this.db = draft;
      return result;
    } finally {
      release();
    }
  }

  private run(db: Store, sql: string, p: readonly unknown[]): Row[] {
    const tag = /\/\*(LIC003_[A-Z_]+)\*\//.exec(sql)?.[1];
    this.observedQueries.push({ tag, sql });
    switch (tag) {
      case "LIC003_ORG_LOCK": {
        const active = db.orgs.get(p[0] as string);
        return active === undefined ? [] : [{ active }];
      }
      case "LIC003_IDEMPOTENCY": {
        const found = db.idem.get(idemKey(p[0] as string, p[1] as string, p[2] as string));
        return found ? [{ command_hash: found.hash, result_json: found.result }] : [];
      }
      case "LIC003_ACTOR_ROLE":
        return [...db.seats.values()].flatMap((seat) => {
          const role = db.roles.get(seat.roleId);
          return seat.orgId === p[0] && seat.userId === p[1] && seat.status === "ACTIVE" && role
            ? [{ role_name: role.name, role_id: seat.roleId, role_org_id: role.orgId,
              role_immutable: role.immutable, seat_status: seat.status }] : [];
        });
      case "LIC003_AUDIT_EXISTS":
        return db.audits.has(p[0] as string) ? [{ exists: true }] : [];
      case "LIC003_TARGET_ROLE": {
        const role = db.roles.get(p[0] as string);
        return role && (role.orgId === null || role.orgId === p[1])
          ? [{ role_id: p[0], role_org_id: role.orgId, immutable: role.immutable }] : [];
      }
      case "LIC003_USER_SEAT_EXISTS":
        return [...db.seats.values()].filter((s) => s.orgId === p[0] && s.userId === p[1] &&
          (s.status === "ACTIVE" || s.status === "INVITED")).map((s) => ({ seat_id: s.seatId }));
      case "LIC003_SUBSCRIPTION": {
        const sub = db.subs.get(key(p[0] as string, p[1] as string));
        return sub ? [{ status: sub.status, seat_limit: sub.seatLimit,
          term_start_utc_ns: sub.start, term_end_utc_ns: sub.end }] : [];
      }
      case "LIC003_SEAT_COUNT": {
        const n = [...db.seats.values()].filter((s) => s.orgId === p[0] && s.subscriptionId === p[1] &&
          (s.status === "ACTIVE" || s.status === "INVITED")).length;
        return [{ seats_used: String(n) }];
      }
      case "LIC003_SEAT_LOOKUP": {
        const s = db.seats.get(seatKey(p[0] as string, p[1] as string));
        const role = s && db.roles.get(s.roleId);
        return s && role ? [{ subscription_id: s.subscriptionId, user_id: s.userId,
          role_id: s.roleId, role_org_id: role.orgId, role_immutable: role.immutable,
          status: s.status, version: s.version }] : [];
      }
      case "LIC003_OWNER_COUNT": {
        const where = sql.split(/\bWHERE\b/i)[1] ?? "";
        const requiresGlobalRole = /r\.org_id\s+IS\s+NULL/i.test(where);
        const roleIdParameter = /r\.role_id\s*=\s*\$(\d+)/i.exec(where)?.[1];
        const requiredRoleId = roleIdParameter
          ? p[Number(roleIdParameter) - 1] as string
          : /r\.role_id\s*=\s*['"]owner['"]/i.test(where) ? SYSTEM_ROLE_OWNER : undefined;
        const requiresImmutable = /r\.immutable\s*=\s*TRUE/i.test(where);
        const matchesName = /r\.name\s*=\s*'Owner'/i.test(where);
        const n = [...db.seats.values()].filter((s) => {
          const role = db.roles.get(s.roleId);
          return s.orgId === p[0] && s.status === "ACTIVE" && role !== undefined &&
            (!matchesName || role.name === "Owner") &&
            (!requiresGlobalRole || role.orgId === null) &&
            (!requiredRoleId || s.roleId === requiredRoleId) &&
            (!requiresImmutable || role.immutable);
        }).length;
        return [{ owner_count: String(n) }];
      }
      case "LIC003_SEAT_ROLE_ID": {
        const s = db.seats.get(seatKey(p[0] as string, p[1] as string));
        return s ? [{ role_id: s.roleId }] : [];
      }
      case "LIC003_SEAT_INSERT": {
        const [orgId, subscriptionId, seatId, userId, roleId, status, version, at, auditEventId] = p;
        const k = seatKey(orgId as string, seatId as string);
        if (db.seats.has(k)) return [];
        db.seats.set(k, { orgId: orgId as string, subscriptionId: subscriptionId as string,
          seatId: seatId as string, userId: userId as string, roleId: roleId as string,
          status: status as string, version: version as string, assignedAtUtcNs: at as string,
          updatedAtUtcNs: at as string, auditEventId: auditEventId as string });
        return [{ seat_id: seatId, version }];
      }
      case "LIC003_SEAT_UPDATE": {
        const [org, id, version, roleId, status, nextVersion, at, auditEventId] = p;
        const s = db.seats.get(seatKey(org as string, id as string));
        if (!s || s.version !== version) return [];
        Object.assign(s, { roleId, status, version: nextVersion, updatedAtUtcNs: at, auditEventId });
        return [{ seat_id: id, version: nextVersion }];
      }
      case "LIC003_AUDIT_INSERT": {
        if (this.dropNextAudit) { this.dropNextAudit = false; return []; }
        const [id, orgId, actorUserId, seatId, action, beforeRoleId, afterRoleId,
          beforeStatus, afterStatus, occurredAtUtcNs] = p;
        if (db.audits.has(id as string)) return [];
        db.audits.set(id as string, { orgId, actorUserId, seatId, action, beforeRoleId,
          afterRoleId, beforeStatus, afterStatus, occurredAtUtcNs });
        return [{ audit_event_id: id }];
      }
      case "LIC003_IDEMPOTENCY_INSERT": {
        const [org, actor, idem, hash, result] = p;
        const k = idemKey(org as string, actor as string, idem as string);
        if (db.idem.has(k)) return [];
        db.idem.set(k, { hash: hash as string, result: result as string });
        return [{ idempotency_key: idem }];
      }
      default:
        throw new Error("Unexpected transaction query tag: " + String(tag));
    }
  }
}

function cmd(overrides: Partial<SeatCommandV1> = {}): SeatCommandV1 {
  return {
    schemaVersion: 1, action: "ASSIGN", orgId: "org-a", subscriptionId: "sub-a",
    actorUserId: "owner-a", seatId: "seat-new", targetUserId: "user-new", roleId: "role-member",
    expectedVersion: "0", idempotencyKey: "idem-new", auditEventId: "audit-new",
    occurredAtUtcNs: "200", ...overrides,
  };
}

function expectCode(promise: Promise<unknown>, code: string) {
  return expect(promise).rejects.toMatchObject({ code });
}

async function codeOf(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
    return undefined;
  } catch (error) {
    return (error as { code?: unknown }).code;
  }
}

describe("LIC-003 independent contract acceptance", () => {
  it("commits an assignment and its UTC/audit evidence atomically", async () => {
    const port = new LicensingFake("2");
    const result = await applySeatCommandV1(port, cmd());
    expect(result).toMatchObject({ status: "ACTIVE", version: "1", auditEventId: "audit-new",
      occurredAtUtcNs: "200", userId: "user-new", roleId: "role-member" });
    expect(port.seats().find((s) => s.seatId === "seat-new")?.updatedAtUtcNs).toBe("200");
    expect(port.audits()).toHaveLength(1);
    expect(port.audits()[0]).toMatchObject({ actorUserId: "owner-a", occurredAtUtcNs: "200" });
  });

  it("records invite, role reassignment, and revoke transitions with versions and audit IDs", async () => {
    const port = new LicensingFake("5");
    const invited = await applySeatCommandV1(port, cmd({ action: "INVITE", seatId: "seat-invite",
      targetUserId: "invitee", idempotencyKey: "invite", auditEventId: "audit-invite", occurredAtUtcNs: "201" }));
    expect(invited).toMatchObject({ status: "INVITED", version: "1", occurredAtUtcNs: "201" });
    const changed = await applySeatCommandV1(port, cmd({ action: "CHANGE_ROLE", seatId: "seat-invite",
      targetUserId: null, roleId: "role-custom", expectedVersion: "1", idempotencyKey: "change",
      auditEventId: "audit-change", occurredAtUtcNs: "202" }));
    expect(changed).toMatchObject({ status: "INVITED", roleId: "role-custom", version: "2" });
    const revoked = await applySeatCommandV1(port, cmd({ action: "REVOKE", seatId: "seat-invite",
      targetUserId: null, roleId: null, expectedVersion: "2", idempotencyKey: "revoke",
      auditEventId: "audit-revoke", occurredAtUtcNs: "203" }));
    expect(revoked).toMatchObject({ status: "REVOKED", version: "3", auditEventId: "audit-revoke",
      occurredAtUtcNs: "203" });
    expect(port.audits().map((a) => a.occurredAtUtcNs)).toEqual(["201", "202", "203"]);
  });

  it("serializes N/N+1 assignment so concurrent writes cannot exceed the seat cap", async () => {
    const port = new LicensingFake("2");
    const results = await Promise.allSettled([
      applySeatCommandV1(port, cmd({ seatId: "left", targetUserId: "left-user",
        idempotencyKey: "left", auditEventId: "audit-left" })),
      applySeatCommandV1(port, cmd({ seatId: "right", targetUserId: "right-user",
        idempotencyKey: "right", auditEventId: "audit-right" })),
    ]);
    expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
    const denied = results.find((r) => r.status === "rejected");
    expect(denied?.status).toBe("rejected");
    if (denied?.status === "rejected") expect(denied.reason).toMatchObject({ code: "SeatLimitExceeded" });
    expect(port.seats().filter((s) => s.status === "ACTIVE" || s.status === "INVITED")).toHaveLength(2);
  });

  it("prevents concurrent revoke and demotion of the only active Owner", async () => {
    const port = new LicensingFake();
    const results = await Promise.allSettled([
      applySeatCommandV1(port, cmd({ action: "REVOKE", seatId: "seat-owner",
        targetUserId: null, roleId: null, expectedVersion: "1", idempotencyKey: "owner-revoke",
        auditEventId: "audit-owner-revoke" })),
      applySeatCommandV1(port, cmd({ action: "CHANGE_ROLE", seatId: "seat-owner",
        targetUserId: null, roleId: "role-member", expectedVersion: "1", idempotencyKey: "owner-demote",
        auditEventId: "audit-owner-demote" })),
    ]);
    expect(results.every((r) => r.status === "rejected")).toBe(true);
    for (const result of results) {
      if (result.status === "rejected") expect(result.reason).toMatchObject({ code: "LastOwnerGuard" });
    }
    expect(port.seats().find((s) => s.seatId === "seat-owner")).toMatchObject({
      roleId: SYSTEM_ROLE_OWNER, status: "ACTIVE", version: "1",
    });
  });

  it("prevents Admins from assigning or changing Owner seats and ignores forged role claims", async () => {
    const port = new LicensingFake("5");
    port.addSeat({ orgId: "org-a", subscriptionId: "sub-a", seatId: "seat-admin", userId: "admin-a",
      roleId: SYSTEM_ROLE_ADMIN, status: "ACTIVE", version: "1", assignedAtUtcNs: "100",
      updatedAtUtcNs: "100", auditEventId: "seed-admin" });
    await expectCode(applySeatCommandV1(port, cmd({ actorUserId: "admin-a", action: "CHANGE_ROLE",
      seatId: "seat-owner", targetUserId: null, roleId: "role-member", expectedVersion: "1",
      idempotencyKey: "admin-change", auditEventId: "audit-admin-change" })), "FORBIDDEN");
    await expectCode(applySeatCommandV1(port, cmd({ actorUserId: "admin-a", seatId: "owner-new",
      targetUserId: "owner-new-user", roleId: SYSTEM_ROLE_OWNER, idempotencyKey: "admin-owner",
      auditEventId: "audit-admin-owner" })), "FORBIDDEN");
    await expectCode(applySeatCommandV1(port, { ...cmd(), actorRole: "Owner" } as SeatCommandV1), "INVALID_INPUT");
    expect(port.seats().some((s) => s.seatId === "owner-new")).toBe(false);
  });

  it("uses persisted actor authority, not a caller-selected role", async () => {
    const port = new LicensingFake();
    port.addSeat({ orgId: "org-a", subscriptionId: "sub-a", seatId: "seat-member", userId: "member-a",
      roleId: "role-member", status: "ACTIVE", version: "1", assignedAtUtcNs: "100",
      updatedAtUtcNs: "100", auditEventId: "seed-member" });
    await expectCode(applySeatCommandV1(port, cmd({ actorUserId: "member-a" })), "FORBIDDEN");
  });

  it("replays identical scoped idempotency keys and rejects changed commands", async () => {
    const port = new LicensingFake("5");
    const original = cmd();
    const first = await applySeatCommandV1(port, original);
    expect(await applySeatCommandV1(port, original)).toEqual(first);
    expect(port.audits()).toHaveLength(1);
    expect(port.idempotencyCount()).toBe(1);
    await expectCode(applySeatCommandV1(port, cmd({ targetUserId: "other-user",
      auditEventId: "audit-other" })), "IDEMPOTENCY_CONFLICT");
    expect(port.seats().some((s) => s.userId === "other-user")).toBe(false);
  });

  it("scopes an idempotency key independently by organization and actor", async () => {
    const port = new LicensingFake("6");
    port.addSeat({ orgId: "org-a", subscriptionId: "sub-a", seatId: "seat-admin", userId: "admin-a",
      roleId: SYSTEM_ROLE_ADMIN, status: "ACTIVE", version: "1", assignedAtUtcNs: "100",
      updatedAtUtcNs: "100", auditEventId: "seed-admin" });
    port.addOrg("org-b");
    port.addSub("org-b", "sub-b", "3");
    port.addSeat({ orgId: "org-b", subscriptionId: "sub-b", seatId: "owner-b", userId: "owner-a",
      roleId: SYSTEM_ROLE_OWNER, status: "ACTIVE", version: "1", assignedAtUtcNs: "100",
      updatedAtUtcNs: "100", auditEventId: "seed-b" });
    await applySeatCommandV1(port, cmd({ idempotencyKey: "shared-key", seatId: "owner-write",
      targetUserId: "user-a", auditEventId: "audit-a" }));
    await applySeatCommandV1(port, cmd({ actorUserId: "admin-a", idempotencyKey: "shared-key",
      seatId: "admin-write", targetUserId: "user-admin", auditEventId: "audit-admin" }));
    await applySeatCommandV1(port, cmd({ orgId: "org-b", subscriptionId: "sub-b",
      idempotencyKey: "shared-key", seatId: "org-b-write", targetUserId: "user-b",
      auditEventId: "audit-b" }));
    expect(port.idempotencyCount()).toBe(3);
    expect(port.seats().filter((s) => s.seatId.endsWith("-write"))).toHaveLength(3);
  });

  it("keeps foreign-org identifiers indistinguishable from absent identifiers", async () => {
    const port = new LicensingFake("5");
    port.addOrg("org-b");
    port.addSub("org-b", "sub-b");
    port.addSeat({ orgId: "org-b", subscriptionId: "sub-b", seatId: "foreign-seat",
      userId: "foreign-user", roleId: "role-member", status: "ACTIVE", version: "1",
      assignedAtUtcNs: "100", updatedAtUtcNs: "100", auditEventId: "seed-b" });
    const base = { action: "REVOKE" as const, targetUserId: null, roleId: null, expectedVersion: "1" };
    await expectCode(applySeatCommandV1(port, cmd({ ...base, seatId: "foreign-seat",
      idempotencyKey: "foreign", auditEventId: "audit-foreign" })), "SEAT_NOT_FOUND");
    await expectCode(applySeatCommandV1(port, cmd({ ...base, seatId: "missing-seat",
      idempotencyKey: "missing", auditEventId: "audit-missing" })), "SEAT_NOT_FOUND");
    expect(port.seats().find((s) => s.orgId === "org-b")?.status).toBe("ACTIVE");
  });

  it("rolls back a seat change when audit insertion loses a uniqueness race", async () => {
    const port = new LicensingFake("5");
    port.dropNextAudit = true;
    await expectCode(applySeatCommandV1(port, cmd()), "EVENT_REPLAY");
    expect(port.seats().some((s) => s.seatId === "seat-new")).toBe(false);
    expect(port.audits()).toHaveLength(0);
    expect(port.idempotencyCount()).toBe(0);
  });

  it("rejects unavailable organizations, subscriptions, foreign roles, and noncanonical UTC ns", async () => {
    const port = new LicensingFake("5");
    await expectCode(applySeatCommandV1(port, cmd({ orgId: "missing-org" })), "FORBIDDEN");
    port.addOrg("org-paused", false);
    await expectCode(applySeatCommandV1(port, cmd({ orgId: "org-paused" })), "FORBIDDEN");
    port.addSub("org-a", "sub-paused", "5", "PAUSED");
    await expectCode(applySeatCommandV1(port, cmd({ subscriptionId: "sub-paused" })), "SUBSCRIPTION_UNAVAILABLE");
    port.addRole("foreign-role", "org-b", "Foreign", false);
    await expectCode(applySeatCommandV1(port, cmd({ roleId: "foreign-role" })), "ROLE_NOT_FOUND");
    await expectCode(applySeatCommandV1(port, cmd({ occurredAtUtcNs: "0200" })), "INVALID_INPUT");
    await expectCode(applySeatCommandV1(port, cmd({ expectedVersion: "0.0" })), "INVALID_INPUT");
    const roleDefinitionChange = { ...cmd(), action: "CREATE_ROLE" } as unknown as SeatCommandV1;
    await expectCode(applySeatCommandV1(port, roleDefinitionChange), "INVALID_INPUT");
  });

  it("rejects stale versions without changing the seat or writing audit", async () => {
    const port = new LicensingFake("5");
    port.addSeat({ orgId: "org-a", subscriptionId: "sub-a", seatId: "versioned", userId: "user-v",
      roleId: "role-member", status: "ACTIVE", version: "2", assignedAtUtcNs: "100",
      updatedAtUtcNs: "150", auditEventId: "seed-v" });
    await expectCode(applySeatCommandV1(port, cmd({ action: "CHANGE_ROLE", seatId: "versioned",
      targetUserId: null, roleId: "role-custom", expectedVersion: "1", idempotencyKey: "stale",
      auditEventId: "audit-stale" })), "VERSION_CONFLICT");
    expect(port.seats().find((s) => s.seatId === "versioned")).toMatchObject({
      roleId: "role-member", version: "2", updatedAtUtcNs: "150",
    });
    expect(port.audits()).toHaveLength(0);
  });

  it("returns the same FORBIDDEN for a nonmember of absent, active, and inactive orgs", async () => {
    const port = new LicensingFake("5");
    port.addOrg("org-inactive", false);
    port.addSub("org-inactive", "sub-a");
    const outcomes = await Promise.all([
      codeOf(applySeatCommandV1(port, cmd({ orgId: "org-missing", actorUserId: "visitor" }))),
      codeOf(applySeatCommandV1(port, cmd({ actorUserId: "visitor" }))),
      codeOf(applySeatCommandV1(port, cmd({ orgId: "org-inactive", actorUserId: "visitor" }))),
    ]);
    expect(outcomes).toEqual(["FORBIDDEN", "FORBIDDEN", "FORBIDDEN"]);

    port.addSeat({ orgId: "org-inactive", subscriptionId: "sub-a", seatId: "inactive-member",
      userId: "proven-member", roleId: "role-member", status: "ACTIVE", version: "1",
      assignedAtUtcNs: "100", updatedAtUtcNs: "100", auditEventId: "seed-inactive-member" });
    await expectCode(applySeatCommandV1(port, cmd({
      orgId: "org-inactive", actorUserId: "proven-member",
    })), "ORG_INACTIVE");
  });

  it("does not treat org-scoped custom Owner/Admin names as system authority or Owners", async () => {
    const port = new LicensingFake("6");
    port.addRole("custom-owner", "org-a", "Owner", false);
    port.addRole("custom-admin", "org-a", "Admin", false);
    port.addRole("Owner", "org-a", "TenantOwner", false);
    port.addRole("Admin", "org-a", "TenantAdmin", false);
    for (const [seatId, userId, roleId] of [
      ["custom-owner-seat", "custom-owner-user", "custom-owner"],
      ["custom-admin-seat", "custom-admin-user", "custom-admin"],
      ["owner-id-seat", "owner-id-user", "Owner"],
      ["admin-id-seat", "admin-id-user", "Admin"],
    ]) {
      port.addSeat({ orgId: "org-a", subscriptionId: "sub-a", seatId, userId, roleId,
        status: "ACTIVE", version: "1", assignedAtUtcNs: "100", updatedAtUtcNs: "100",
        auditEventId: "seed-" + seatId });
      await expectCode(applySeatCommandV1(port, cmd({
        actorUserId: userId, seatId: "attempt-" + seatId, targetUserId: "target-" + seatId,
        idempotencyKey: "idem-" + seatId, auditEventId: "audit-" + seatId,
      })), "FORBIDDEN");
    }

    await expectCode(applySeatCommandV1(port, cmd({
      action: "CHANGE_ROLE", seatId: "seat-owner", targetUserId: null, roleId: "role-member",
      expectedVersion: "1", idempotencyKey: "real-owner-demote",
      auditEventId: "audit-real-owner-demote",
    })), "LastOwnerGuard");
    expect(port.seats().find((s) => s.seatId === "seat-owner")).toMatchObject({
      roleId: SYSTEM_ROLE_OWNER, status: "ACTIVE", version: "1",
    });
  });

  it("uses an explicit seat-row lock when reading a seat for mutation", async () => {
    const port = new LicensingFake("5");
    port.addSeat({ orgId: "org-a", subscriptionId: "sub-a", seatId: "lock-target",
      userId: "lock-member", roleId: "role-member", status: "ACTIVE", version: "1",
      assignedAtUtcNs: "100", updatedAtUtcNs: "100", auditEventId: "seed-lock-target" });
    await applySeatCommandV1(port, cmd({
      action: "CHANGE_ROLE", seatId: "lock-target", targetUserId: null, roleId: "role-custom",
      expectedVersion: "1", idempotencyKey: "lock-change", auditEventId: "audit-lock-change",
    }));
    const lookup = port.queries().find((query) => query.tag === "LIC003_SEAT_LOOKUP");
    expect(lookup?.sql).toMatch(/FOR\s+UPDATE\s+OF\s+s\b/i);
  });
});
