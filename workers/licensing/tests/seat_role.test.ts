import { beforeEach, describe, expect, it } from "vitest";
import type { PgQueryV1, SubscriptionTransactionPortV1 } from "../src/db/repository.js";
import { SeatRoleErrorV1, SYSTEM_ROLE_ADMIN, SYSTEM_ROLE_OWNER, type SeatActionV1, type SeatCommandV1 } from "../src/admin/seat_role_models.js";
import { applySeatCommandV1 } from "../src/admin/seat_role_service.js";

type Row = Record<string, unknown>;
type Role = { org_id: string | null; name: string; immutable: boolean };
type Seat = {
  org_id: string; subscription_id: string; seat_id: string; user_id: string; role_id: string;
  status: string; version: string; assigned_at_utc_ns: string; updated_at_utc_ns: string; audit_event_id: string;
};
type Idempotency = { command_hash: string; result_json: string };
type State = {
  seats: Map<string, Seat>;
  audits: Map<string, Row>;
  idempotencies: Map<string, Idempotency>;
};
const tuple = (...xs: string[]) => JSON.stringify(xs);

class FakePort implements SubscriptionTransactionPortV1 {
  readonly organizations = new Map<string, boolean>([["org-a", true], ["org-b", true]]);
  readonly subscriptions = new Map<string, { status: string; seat_limit: string; term_start_utc_ns: string; term_end_utc_ns: string }>();
  readonly roles = new Map<string, Role>();
  readonly calls: Array<{ tag: string; params: readonly unknown[] }> = [];
  readonly statements = new Map<string, string>();
  state: State = { seats: new Map(), audits: new Map(), idempotencies: new Map() };
  failAuditInsert = false;
  readonly revisionAuditIds = new Set<string>();
  private tail: Promise<void> = Promise.resolve();

  constructor() {
    this.subscriptions.set(tuple("org-a", "sub-a"), {
      status: "ACTIVE", seat_limit: "3", term_start_utc_ns: "100", term_end_utc_ns: "999999",
    });
    this.subscriptions.set(tuple("org-b", "sub-b"), {
      status: "ACTIVE", seat_limit: "3", term_start_utc_ns: "100", term_end_utc_ns: "999999",
    });
    this.roles.set(SYSTEM_ROLE_OWNER, { org_id: null, name: "Owner", immutable: true });
    this.roles.set(SYSTEM_ROLE_ADMIN, { org_id: null, name: "Admin", immutable: true });
    this.roles.set("operator", { org_id: null, name: "Operator", immutable: true });
    this.roles.set("readonly", { org_id: null, name: "ReadOnly", immutable: true });
  }

  seedSeat(seat: Seat): void { this.state.seats.set(tuple(seat.org_id, seat.seat_id), { ...seat }); }

  async transaction<T>(work: (tx: PgQueryV1) => Promise<T>): Promise<T> {
    const prior = this.tail;
    let release!: () => void;
    this.tail = new Promise<void>((resolve) => { release = resolve; });
    await prior;
    const draft: State = {
      seats: new Map([...this.state.seats].map(([k, v]) => [k, { ...v }])),
      audits: new Map([...this.state.audits].map(([k, v]) => [k, { ...v }])),
      idempotencies: new Map([...this.state.idempotencies].map(([k, v]) => [k, { ...v }])),
    };
    const tx: PgQueryV1 = {
      query: async <T>(sql: string, params: readonly unknown[]): Promise<{ rows: T[] }> => {
        const match = /^\/\*(LIC003_[A-Z_]+)\*\//.exec(sql);
        const tag = match?.[1] ?? "UNKNOWN";
        this.statements.set(tag, sql);
        this.calls.push({ tag, params: [...params] });
        const rows: Row[] = [];
        const str = (i: number) => params[i] as string;
        if (tag === "LIC003_ORG_LOCK") {
          if (this.organizations.has(str(0))) rows.push({ active: this.organizations.get(str(0)) });
        } else if (tag === "LIC003_ACTOR_ROLE") {
          for (const seat of draft.seats.values()) {
            const role = this.roles.get(seat.role_id);
            if (seat.org_id === str(0) && seat.user_id === str(1) && seat.status === "ACTIVE" &&
                role && (role.org_id === null || role.org_id === seat.org_id)) {
              rows.push({ role_id: seat.role_id, role_org_id: role.org_id,
                role_immutable: role.immutable, seat_status: seat.status });
            }
          }
        } else if (tag === "LIC003_IDEMPOTENCY") {
          const old = draft.idempotencies.get(tuple(str(0), str(1), str(2)));
          if (old) rows.push({ ...old });
        } else if (tag === "LIC003_AUDIT_EXISTS") {
          if (draft.audits.has(str(0)) || this.revisionAuditIds.has(str(0))) rows.push({ exists: true });
        } else if (tag === "LIC003_TARGET_ROLE") {
          const role = this.roles.get(str(0));
          if (role && (role.org_id === null || role.org_id === str(1))) {
            rows.push({ role_id: str(0), role_org_id: role.org_id, immutable: role.immutable });
          }
        } else if (tag === "LIC003_USER_SEAT_EXISTS") {
          for (const seat of draft.seats.values()) {
            if (seat.org_id === str(0) && seat.user_id === str(1) &&
                (seat.status === "ACTIVE" || seat.status === "INVITED")) rows.push({ seat_id: seat.seat_id });
          }
        } else if (tag === "LIC003_SUBSCRIPTION") {
          const subscription = this.subscriptions.get(tuple(str(0), str(1)));
          if (subscription) rows.push({ ...subscription });
        } else if (tag === "LIC003_SEAT_COUNT") {
          const count = [...draft.seats.values()].filter((s) => s.org_id === str(0) &&
            s.subscription_id === str(1) && (s.status === "ACTIVE" || s.status === "INVITED")).length;
          rows.push({ seats_used: String(count) });
        } else if (tag === "LIC003_SEAT_LOOKUP") {
          const seat = draft.seats.get(tuple(str(0), str(1)));
          if (seat) {
            const role = this.roles.get(seat.role_id);
            if (role && (role.org_id === null || role.org_id === seat.org_id)) {
              rows.push({ subscription_id: seat.subscription_id, user_id: seat.user_id, role_id: seat.role_id,
                role_org_id: role.org_id, role_immutable: role.immutable, status: seat.status, version: seat.version });
            }
          }
        } else if (tag === "LIC003_OWNER_COUNT") {
          const owners = [...draft.seats.values()].filter((s) => {
            const role = this.roles.get(s.role_id);
            return s.org_id === str(0) && s.status === "ACTIVE" && s.role_id === SYSTEM_ROLE_OWNER &&
              role?.org_id === null && role.immutable === true;
          }).length;
          rows.push({ owner_count: String(owners) });
        } else if (tag === "LIC003_SEAT_INSERT") {
          const seat: Seat = {
            org_id: str(0), subscription_id: str(1), seat_id: str(2), user_id: str(3),
            role_id: str(4), status: str(5), version: str(6), assigned_at_utc_ns: str(7),
            updated_at_utc_ns: str(7), audit_event_id: str(8),
          };
          const key = tuple(seat.org_id, seat.seat_id);
          if (!draft.seats.has(key)) { draft.seats.set(key, seat); rows.push({ seat_id: seat.seat_id, version: seat.version }); }
        } else if (tag === "LIC003_SEAT_UPDATE") {
          const seat = draft.seats.get(tuple(str(0), str(1)));
          if (seat && seat.version === str(2)) {
            seat.role_id = str(3); seat.status = str(4); seat.version = str(5);
            seat.updated_at_utc_ns = str(6); seat.audit_event_id = str(7);
            rows.push({ seat_id: seat.seat_id, version: seat.version });
          }
        } else if (tag === "LIC003_AUDIT_INSERT") {
          if (this.failAuditInsert) throw new Error("synthetic failure");
          if (!draft.audits.has(str(0))) {
            draft.audits.set(str(0), { org_id: str(1), actor_user_id: str(2), target_id: str(3), action: str(4),
              before_role_id: params[5], after_role_id: str(6), before_status: params[7], after_status: str(8),
              occurred_at_utc_ns: str(9) });
            rows.push({ audit_event_id: str(0) });
          }
        } else if (tag === "LIC003_IDEMPOTENCY_INSERT") {
          const key = tuple(str(0), str(1), str(2));
          if (!draft.idempotencies.has(key)) {
            draft.idempotencies.set(key, { command_hash: str(3), result_json: str(4) });
            rows.push({ idempotency_key: str(2) });
          }
        } else {
          throw new Error("unexpected fake query");
        }
        return { rows: rows as T[] };
      },
    };
    try {
      const result = await work(tx);
      this.state = draft;
      return result;
    } finally {
      release();
    }
  }
}

function seat(org: string, id: string, user: string, role: string, status = "ACTIVE"): Seat {
  return { org_id: org, subscription_id: org === "org-b" ? "sub-b" : "sub-a", seat_id: id,
    user_id: user, role_id: role, status, version: "1", assigned_at_utc_ns: "1000",
    updated_at_utc_ns: "1000", audit_event_id: `audit_${id}` };
}

function deferred(): { promise: Promise<void>; resolve: () => void } {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => { resolve = done; });
  return { promise, resolve };
}

class OrgRowLockModel {
  private readonly tails = new Map<string, Promise<void>>();

  async acquire(orgId: string): Promise<() => void> {
    const prior = this.tails.get(orgId) ?? Promise.resolve();
    const current = deferred();
    this.tails.set(orgId, current.promise);
    await prior;
    return current.resolve;
  }
}

function command(overrides: Partial<SeatCommandV1> = {}): SeatCommandV1 {
  return {
    schemaVersion: 1, action: "ASSIGN", orgId: "org-a", subscriptionId: "sub-a",
    actorUserId: "owner-a", seatId: "seat-new", targetUserId: "user-new", roleId: "operator",
    expectedVersion: "0", idempotencyKey: "idem-001", auditEventId: "audit-new", occurredAtUtcNs: "1000",
    ...overrides,
  };
}

async function code(promise: Promise<unknown>, expected: string): Promise<void> {
  try { await promise; throw new Error("expected rejection"); }
  catch (error) {
    if (error instanceof Error && error.message === "expected rejection") throw error;
    expect(error).toBeInstanceOf(SeatRoleErrorV1);
    expect((error as SeatRoleErrorV1).code).toBe(expected);
    expect(String(error)).not.toContain("user-new");
  }
}

let port: FakePort;
beforeEach(() => {
  port = new FakePort();
  port.seedSeat(seat("org-a", "owner-seat", "owner-a", "owner"));
  port.seedSeat(seat("org-a", "admin-seat", "admin-a", "admin"));
});

describe("LIC-003 synthetic seat and role transactions", () => {
  it("assigns an active seat with an atomic audit and idempotency record", async () => {
    const result = await applySeatCommandV1(port, command());
    expect(result).toMatchObject({ orgId: "org-a", seatId: "seat-new", userId: "user-new",
      roleId: "operator", status: "ACTIVE", version: "1", auditEventId: "audit-new" });
    expect(Object.isFrozen(result)).toBe(true);
    expect(port.state.audits.size).toBe(1);
    expect(port.state.idempotencies.size).toBe(1);
  });

  it("serializes simultaneous final-seat assignments at the subscription cap", async () => {
    port.subscriptions.set(tuple("org-a", "sub-a"), {
      status: "ACTIVE", seat_limit: "4", term_start_utc_ns: "100", term_end_utc_ns: "999999",
    });
    port.seedSeat(seat("org-a", "active-2", "user-2", "operator"));
    const results = await Promise.allSettled([
      applySeatCommandV1(port, command({ seatId: "seat-3a", targetUserId: "user-3a", idempotencyKey: "idem-3a", auditEventId: "audit-3a" })),
      applySeatCommandV1(port, command({ seatId: "seat-3b", targetUserId: "user-3b", idempotencyKey: "idem-3b", auditEventId: "audit-3b" })),
    ]);
    expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
    const rejected = results.find((r) => r.status === "rejected");
    expect(rejected?.status).toBe("rejected");
    expect((rejected as PromiseRejectedResult).reason).toMatchObject({ code: "SeatLimitExceeded" });
    expect([...port.state.seats.values()].filter((s) => s.status === "ACTIVE" || s.status === "INVITED")).toHaveLength(4);
  });

  it("counts invitations against the seat cap", async () => {
    port.subscriptions.set(tuple("org-a", "sub-a"), {
      status: "ACTIVE", seat_limit: "2", term_start_utc_ns: "100", term_end_utc_ns: "999999",
    });
    port.seedSeat(seat("org-a", "invite-1", "invitee-1", "operator", "INVITED"));
    await code(applySeatCommandV1(port, command()), "SeatLimitExceeded");
    expect(port.state.seats.has(tuple("org-a", "seat-new"))).toBe(false);
  });

  it("prevents an Admin from assigning Owner or changing an Owner seat", async () => {
    await code(applySeatCommandV1(port, command({ actorUserId: "admin-a", roleId: "owner" })), "FORBIDDEN");
    await code(applySeatCommandV1(port, command({ action: "CHANGE_ROLE", actorUserId: "admin-a",
      seatId: "owner-seat", targetUserId: null, roleId: "operator", expectedVersion: "1",
      idempotencyKey: "idem-admin-owner", auditEventId: "audit-admin-owner" })), "FORBIDDEN");
    expect(port.state.seats.get(tuple("org-a", "owner-seat"))?.role_id).toBe("owner");
  });

  it("allows a non-final Owner to demote another Owner and blocks demoting the last one", async () => {
    port.seedSeat(seat("org-a", "owner-seat-2", "owner-b", "owner"));
    const result = await applySeatCommandV1(port, command({ action: "CHANGE_ROLE", seatId: "owner-seat-2",
      targetUserId: null, roleId: "readonly", expectedVersion: "1", idempotencyKey: "idem-demote-b",
      auditEventId: "audit-demote-b" }));
    expect(result.status).toBe("ACTIVE");
    expect(result.roleId).toBe("readonly");
    await code(applySeatCommandV1(port, command({ action: "CHANGE_ROLE", seatId: "owner-seat",
      targetUserId: null, roleId: "readonly", expectedVersion: "1", idempotencyKey: "idem-demote-last",
      auditEventId: "audit-demote-last" })), "LastOwnerGuard");
    expect(port.state.seats.get(tuple("org-a", "owner-seat"))?.role_id).toBe("owner");
  });

  it("preserves one Owner across simultaneous demotions", async () => {
    port.seedSeat(seat("org-a", "owner-seat-2", "owner-b", "owner"));
    const changes = [
      applySeatCommandV1(port, command({ action: "CHANGE_ROLE", seatId: "owner-seat-2",
        targetUserId: null, roleId: "readonly", expectedVersion: "1", idempotencyKey: "idem-concurrent-a",
        auditEventId: "audit-concurrent-a" })),
      applySeatCommandV1(port, command({ action: "CHANGE_ROLE", actorUserId: "owner-b", seatId: "owner-seat",
        targetUserId: null, roleId: "readonly", expectedVersion: "1", idempotencyKey: "idem-concurrent-b",
        auditEventId: "audit-concurrent-b" })),
    ];
    const results = await Promise.allSettled(changes);
    expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
    expect(results.filter((r) => r.status === "rejected")).toHaveLength(1);
    expect([...port.state.seats.values()].filter((s) => s.status === "ACTIVE" && s.role_id === "owner")).toHaveLength(1);
  });

  it("treats same-key/same-command as replay and conflicts on command changes", async () => {
    const first = await applySeatCommandV1(port, command());
    const replay = await applySeatCommandV1(port, command());
    expect(replay).toEqual(first);
    expect(port.state.audits.size).toBe(1);
    await code(applySeatCommandV1(port, command({ roleId: "readonly" })), "IDEMPOTENCY_CONFLICT");
  });

  it("rolls back the seat change when audit persistence fails", async () => {
    port.failAuditInsert = true;
    await code(applySeatCommandV1(port, command()), "TRANSACTION_FAILED");
    expect(port.state.seats.has(tuple("org-a", "seat-new"))).toBe(false);
    expect(port.state.audits.size).toBe(0);
    expect(port.state.idempotencies.size).toBe(0);
  });

  it("hides cross-org seat identifiers and rejects non-advancing version", async () => {
    port.seedSeat(seat("org-b", "other-org-seat", "someone", "operator"));
    await code(applySeatCommandV1(port, command({ action: "REVOKE", seatId: "other-org-seat",
      targetUserId: null, roleId: null, expectedVersion: "1" })), "SEAT_NOT_FOUND");
    await code(applySeatCommandV1(port, command({ action: "CHANGE_ROLE", seatId: "admin-seat",
      targetUserId: null, roleId: "operator", expectedVersion: "2" })), "VERSION_CONFLICT");
    expect(port.state.seats.get(tuple("org-b", "other-org-seat"))?.status).toBe("ACTIVE");
  });

  it("rejects changes that would remove the last Owner", async () => {
    await code(applySeatCommandV1(port, command({ action: "REVOKE", seatId: "owner-seat",
      targetUserId: null, roleId: null, expectedVersion: "1" })), "LastOwnerGuard");
    expect(port.state.seats.get(tuple("org-a", "owner-seat"))?.status).toBe("ACTIVE");
  });

  it("does not treat an invited Owner as the last active Owner", async () => {
    port.seedSeat(seat("org-a", "owner-invite", "owner-invitee", "owner", "INVITED"));
    const result = await applySeatCommandV1(port, command({ action: "CHANGE_ROLE", seatId: "owner-invite",
      targetUserId: null, roleId: "operator", expectedVersion: "1", idempotencyKey: "idem-change-invite",
      auditEventId: "audit-change-invite" }));
    expect(result.status).toBe("INVITED");
    expect(result.roleId).toBe("operator");
  });

  it("rejects a globally reused audit event identifier across organizations", async () => {
    port.seedSeat(seat("org-b", "owner-b", "owner-b-user", "owner"));
    port.state.audits.set("audit-global", { org_id: "org-a" });
    await code(applySeatCommandV1(port, command({ orgId: "org-b", subscriptionId: "sub-b",
      actorUserId: "owner-b-user", seatId: "seat-b-new", targetUserId: "new-user-b",
      idempotencyKey: "idem-b-new", auditEventId: "audit-global" })), "EVENT_REPLAY");
    expect(port.state.seats.has(tuple("org-b", "seat-b-new"))).toBe(false);
  });

  it("uses the LIC-002 organization lock before reading or changing seats", async () => {
    await applySeatCommandV1(port, command());
    expect(port.calls[0]).toEqual({ tag: "LIC003_ORG_LOCK", params: ["org-a"] });
    expect(port.calls.map((c) => c.tag)).toContain("LIC003_AUDIT_INSERT");
    expect(port.calls.map((c) => c.tag)).toContain("LIC003_IDEMPOTENCY_INSERT");
  });

  it("returns the same FORBIDDEN for non-members across absent, active, and inactive orgs", async () => {
    port.organizations.set("org-b", false);
    const outsider = command({ actorUserId: "outsider", idempotencyKey: "idem-outsider", auditEventId: "audit-outsider" });
    await code(applySeatCommandV1(port, outsider), "FORBIDDEN");
    await code(applySeatCommandV1(port, command({ ...outsider, orgId: "org-b", subscriptionId: "sub-b" })), "FORBIDDEN");
    await code(applySeatCommandV1(port, command({ ...outsider, orgId: "org-missing", subscriptionId: "sub-missing" })), "FORBIDDEN");
    port.seedSeat(seat("org-b", "inactive-member", "inactive-owner", "owner"));
    await code(applySeatCommandV1(port, command({ actorUserId: "inactive-owner", orgId: "org-b", subscriptionId: "sub-b",
      idempotencyKey: "idem-inactive-member", auditEventId: "audit-inactive-member" })), "ORG_INACTIVE");
  });

  it("does not treat org-scoped custom roles named Owner or Admin as authority", async () => {
    port.roles.set("custom-owner", { org_id: "org-a", name: "Owner", immutable: false });
    port.roles.set("custom-admin", { org_id: "org-a", name: "Admin", immutable: false });
    port.seedSeat(seat("org-a", "custom-owner-seat", "custom-owner-user", "custom-owner"));
    port.seedSeat(seat("org-a", "custom-admin-seat", "custom-admin-user", "custom-admin"));
    await code(applySeatCommandV1(port, command({ actorUserId: "custom-owner-user",
      idempotencyKey: "idem-custom-owner", auditEventId: "audit-custom-owner" })), "FORBIDDEN");
    await code(applySeatCommandV1(port, command({ actorUserId: "custom-admin-user",
      idempotencyKey: "idem-custom-admin", auditEventId: "audit-custom-admin" })), "FORBIDDEN");
    await code(applySeatCommandV1(port, command({ action: "CHANGE_ROLE", seatId: "owner-seat", targetUserId: null,
      roleId: "readonly", expectedVersion: "1", idempotencyKey: "idem-real-owner-demote",
      auditEventId: "audit-real-owner-demote" })), "LastOwnerGuard");

    const idSpoofPort = new FakePort();
    idSpoofPort.roles.set(SYSTEM_ROLE_OWNER, { org_id: "org-a", name: "Member", immutable: false });
    idSpoofPort.seedSeat(seat("org-a", "spoof-id-seat", "spoof-id-user", SYSTEM_ROLE_OWNER));
    await code(applySeatCommandV1(idSpoofPort, command({ actorUserId: "spoof-id-user",
      idempotencyKey: "idem-spoof-id", auditEventId: "audit-spoof-id" })), "FORBIDDEN");
  });

  it("checks audit IDs against subscription revisions and maps duplicate seat IDs consistently", async () => {
    port.revisionAuditIds.add("audit-from-revision");
    await code(applySeatCommandV1(port, command({ auditEventId: "audit-from-revision" })), "EVENT_REPLAY");
    expect(port.statements.get("LIC003_AUDIT_EXISTS")).toContain("licensing_subscription_revisions");
    port.subscriptions.set(tuple("org-a", "sub-a"), {
      status: "ACTIVE", seat_limit: "10", term_start_utc_ns: "100", term_end_utc_ns: "999999",
    });
    port.seedSeat(seat("org-a", "seat-new", "already-there", "operator"));
    await code(applySeatCommandV1(port, command({ idempotencyKey: "idem-duplicate-seat",
      auditEventId: "audit-duplicate-seat" })), "DUPLICATE_SEAT");
  });

  it("uses a seat-only row lock in the joined seat lookup", async () => {
    await applySeatCommandV1(port, command({ action: "REVOKE", seatId: "admin-seat", targetUserId: null,
      roleId: null, expectedVersion: "1", idempotencyKey: "idem-revoke-admin", auditEventId: "audit-revoke-admin" }));
    expect(port.calls.find((call) => call.tag === "LIC003_SEAT_LOOKUP")).toBeDefined();
    expect(port.calls.find((call) => call.tag === "LIC003_SEAT_LOOKUP")?.params).toEqual(["org-a", "admin-seat"]);
    expect(port.statements.get("LIC003_SEAT_LOOKUP")).toContain("FOR UPDATE OF s");
  });

  it("models READ COMMITTED org-lock interleaving without a global transaction mutex", async () => {
    const locks = new OrgRowLockModel();
    const log: string[] = [];
    const firstAtSeatCount = deferred();
    const releaseFirst = deferred();
    const used = new Map([["org-a", 2], ["org-b", 0]]);
    const limits = new Map([["org-a", 3], ["org-b", 3]]);
    const run = async (name: string, orgId: string, pauseAfterRead = false): Promise<string> => {
      log.push(`${name}:LIC003_ORG_LOCK`);
      const release = await locks.acquire(orgId);
      try {
        log.push(`${name}:LIC003_ACTOR_ROLE`);
        log.push(`${name}:LIC003_SEAT_COUNT`);
        const observed = used.get(orgId)!;
        if (pauseAfterRead) {
          firstAtSeatCount.resolve();
          await releaseFirst.promise;
        }
        if (observed >= limits.get(orgId)!) return "SeatLimitExceeded";
        used.set(orgId, observed + 1);
        return "committed";
      } finally {
        release();
      }
    };

    const first = run("first", "org-a", true);
    await firstAtSeatCount.promise;
    const second = run("second", "org-a");
    const otherOrg = run("other-org", "org-b");
    expect(await otherOrg).toBe("committed");
    expect(log).toContain("other-org:LIC003_SEAT_COUNT");
    expect(log).not.toContain("second:LIC003_ACTOR_ROLE");
    releaseFirst.resolve();
    expect(await first).toBe("committed");
    expect(await second).toBe("SeatLimitExceeded");
    expect(used.get("org-a")).toBe(3);
    expect(log.indexOf("second:LIC003_ACTOR_ROLE")).toBeGreaterThan(log.indexOf("first:LIC003_SEAT_COUNT"));
  });
});
