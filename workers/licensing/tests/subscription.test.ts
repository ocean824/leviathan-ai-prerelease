import { describe, expect, it } from "vitest";
import { SubscriptionLedgerErrorV1, type EntitlementSetV1, type SubscriptionRecordV1 } from "../src/db/models.js";
import {
  readEffectiveEntitlementsV1, readSubscriptionV1, writeSubscriptionRevisionV1,
  type PgQueryV1, type SubscriptionTransactionPortV1,
} from "../src/db/repository.js";

type Row = Record<string, unknown>;
type State = { heads: Map<string, Row>; revisions: Row[]; outbox: Row[] };
const key = (org: string, sub: string) => JSON.stringify([org, sub]);

function rowFromParams(p: readonly unknown[]): Row {
  return {
    org_id: p[0], subscription_id: p[1], revision: p[2], status: p[3],
    term_start_utc_ns: p[4], term_end_utc_ns: p[5], seat_limit: p[6],
    features: JSON.parse(p[7] as string) as unknown,
    limits: JSON.parse(p[8] as string) as unknown,
    billing_reference: p[9], billing_amount_decimal: p[10],
    billing_currency: p[11], audit_event_id: p[12],
  };
}

class FakePgPort implements SubscriptionTransactionPortV1 {
  readonly organizations = new Map<string, boolean>();
  private state: State = { heads: new Map(), revisions: [], outbox: [] };
  private tail: Promise<void> = Promise.resolve();
  failOutbox = false;
  get revisionCount(): number { return this.state.revisions.length; }
  get outboxCount(): number { return this.state.outbox.length; }

  async transaction<T>(work: (tx: PgQueryV1) => Promise<T>): Promise<T> {
    const previous = this.tail;
    let release!: () => void;
    this.tail = new Promise<void>((resolve) => { release = resolve; });
    await previous;
    const state: State = {
      heads: new Map(this.state.heads), revisions: [...this.state.revisions],
      outbox: [...this.state.outbox],
    };
    const tx: PgQueryV1 = {
      query: async <RowType>(sql: string, p: readonly unknown[]): Promise<{ rows: RowType[] }> => {
        let rows: Row[] = [];
        if (sql.startsWith("/*LIC002_ORG_LOCK*/")) {
          if (this.organizations.has(p[0] as string)) rows = [{ active: this.organizations.get(p[0] as string) }];
        } else if (sql.startsWith("/*LIC002_EVENT_EXISTS*/")) {
          rows = state.revisions.filter((r) =>
            r.source_event_id === p[0] || r.audit_event_id === p[1]).map(() => ({ exists: 1 }));
        } else if (sql.startsWith("/*LIC002_SOURCE_ORDER*/")) {
          const prior = [...state.revisions].reverse().find((r) => r.org_id === p[0] && r.subscription_id === p[1]);
          if (prior) rows = [{ revision: prior.revision, created_at_utc_ns: prior.created_at_utc_ns }];
        } else if (sql.startsWith("/*LIC002_HEAD_INSERT*/")) {
          const k = key(p[0] as string, p[1] as string);
          if (!state.heads.has(k)) {
            const row = rowFromParams(p); state.heads.set(k, row); rows = [{ revision: row.revision }];
          }
        } else if (sql.startsWith("/*LIC002_HEAD_CAS*/")) {
          const k = key(p[0] as string, p[1] as string);
          if (state.heads.get(k)?.revision === p[13]) {
            const row = rowFromParams(p); state.heads.set(k, row); rows = [{ revision: row.revision }];
          }
        } else if (sql.startsWith("/*LIC002_REVISION_INSERT*/")) {
          const row: Row = { ...rowFromParams(p), source_event_id: p[13], created_at_utc_ns: p[14] };
          if (state.revisions.some((r) =>
            r.source_event_id === row.source_event_id || r.audit_event_id === row.audit_event_id ||
              (r.org_id === row.org_id && r.subscription_id === row.subscription_id && r.revision === row.revision))) {
            throw new Error("synthetic duplicate");
          }
          state.revisions.push(row);
        } else if (sql.startsWith("/*LIC002_OUTBOX_INSERT*/")) {
          if (this.failOutbox) throw new Error("synthetic outbox failure with private contents");
          state.outbox.push({ org_id: p[0], subscription_id: p[1], revision: p[2],
            audit_event_id: p[3], source_event_id: p[4], created_at_utc_ns: p[5], status: p[6] });
        } else if (sql.startsWith("/*LIC002_READ*/")) {
          const row = state.heads.get(key(p[0] as string, p[1] as string));
          if (row) rows = [row];
        } else if (sql.startsWith("/*LIC002_EFFECTIVE*/")) {
          const row = state.heads.get(key(p[0] as string, p[1] as string));
          if (row && this.organizations.get(p[0] as string) === true) rows = [row];
        } else {
          throw new Error("unknown SQL in fake");
        }
        return { rows: rows as RowType[] };
      },
    };
    try {
      const result = await work(tx);
      this.state = state;
      return result;
    } finally { release(); }
  }
}

const START = "9007199254740993";
const END = "9007199254741993";

function subscription(orgId: string, revision = "1", status: SubscriptionRecordV1["status"] = "ACTIVE",
  amount: string | null = null): SubscriptionRecordV1 {
  return {
    schemaVersion: 1, orgId, subscriptionId: "sub_1", revision, status,
    termStartUtcNs: START, termEndUtcNs: END, seatLimit: "2",
    billingReference: "bill_evidence", billingAmountDecimal: amount,
    billingCurrency: amount === null ? null : "USD", auditEventId: `audit_${orgId}_${revision}`,
  };
}

function entitlements(orgId: string): EntitlementSetV1 {
  return { schemaVersion: 1, orgId, subscriptionId: "sub_1",
    features: { research: true }, limits: { maxAgents: "1.25" } };
}

async function write(port: FakePgPort, orgId: string, revision = "1",
  status: SubscriptionRecordV1["status"] = "ACTIVE", amount: string | null = null,
  expectedRevision = (BigInt(revision) - 1n).toString(), sourceEventId = `event_${orgId}_${revision}`,
  createdAtUtcNs = (BigInt(START) + BigInt(revision) - 1n).toString()) {
  return writeSubscriptionRevisionV1(port, {
    expectedRevision, subscription: subscription(orgId, revision, status, amount),
    entitlements: entitlements(orgId), sourceEventId, createdAtUtcNs,
  });
}

describe("LIC-002 synthetic subscription ledger", () => {
  it("keeps org scopes separate and grants only active in-term evidence", async () => {
    const port = new FakePgPort(); port.organizations.set("org_a", true); port.organizations.set("org_b", true);
    await write(port, "org_a"); await write(port, "org_b", "1", "PAST_DUE", "12.34");
    expect(await readSubscriptionV1(port, "org_a", "sub_1")).toMatchObject({ orgId: "org_a", revision: "1" });
    expect(await readSubscriptionV1(port, "org_c", "sub_1")).toBeNull();
    const evidence = await readEffectiveEntitlementsV1(port, "org_a", "sub_1", START);
    expect(evidence).toMatchObject({
      features: { research: true }, limits: { maxAgents: "1.25" },
    });
    expect(Object.isFrozen(evidence)).toBe(true);
    expect(Object.isFrozen(evidence?.features)).toBe(true);
    expect(Reflect.set(evidence!.features, "research", false)).toBe(false);
    expect(Reflect.deleteProperty(evidence!.limits, "maxAgents")).toBe(false);
    expect(await readEffectiveEntitlementsV1(port, "org_b", "sub_1", START)).toBeNull();
    expect(await readEffectiveEntitlementsV1(port, "org_a", "sub_1", END)).toBeNull();
    expect((await readSubscriptionV1(port, "org_b", "sub_1"))?.billingAmountDecimal).toBe("12.34");
    expect((await readSubscriptionV1(port, "org_a", "sub_1"))?.termStartUtcNs).toBe(START);
  });

  it("rejects unordered, duplicate and stale revisions without changing the head", async () => {
    const port = new FakePgPort(); port.organizations.set("org_a", true);
    await write(port, "org_a");
    await expect(write(port, "org_a", "3", "ACTIVE", null, "1")).rejects.toMatchObject({ code: "INVALID_INPUT" });
    await expect(write(port, "org_a", "1")).rejects.toMatchObject({ code: "EVENT_REPLAY" });
    await expect(write(port, "org_a", "2", "ACTIVE", null, "0")).rejects.toMatchObject({ code: "INVALID_INPUT" });
    await expect(write(port, "org_a", "2", "ACTIVE", null, "1", "event_org_a_1")).rejects.toMatchObject({ code: "EVENT_REPLAY" });
    expect((await readSubscriptionV1(port, "org_a", "sub_1"))?.revision).toBe("1");
    expect(port.revisionCount).toBe(1); expect(port.outboxCount).toBe(1);
  });

  it("returns a typed status denial for legacy TRIAL writes before any ledger operation", async () => {
    const port = new FakePgPort(); port.organizations.set("org_a", true);
    const legacyTrial = {
      ...subscription("org_a"), status: "TRIAL",
    } as unknown as SubscriptionRecordV1;
    await expect(writeSubscriptionRevisionV1(port, {
      expectedRevision: "0", subscription: legacyTrial,
      entitlements: entitlements("org_a"), sourceEventId: "event_trial", createdAtUtcNs: START,
    })).rejects.toMatchObject({ code: "STATUS_NOT_ALLOWED" });
    expect(port.revisionCount).toBe(0); expect(port.outboxCount).toBe(0);
  });

  it("rejects a globally replayed provider event or audit ID across organizations", async () => {
    const port = new FakePgPort(); port.organizations.set("org_a", true); port.organizations.set("org_b", true);
    await write(port, "org_a", "1", "ACTIVE", null, "0", "evt_provider_123", "1000");
    await expect(write(port, "org_b", "1", "ACTIVE", null, "0", "evt_provider_123", "1001"))
      .rejects.toMatchObject({ code: "EVENT_REPLAY" });
    await expect(writeSubscriptionRevisionV1(port, {
      expectedRevision: "0", subscription: { ...subscription("org_b"), auditEventId: "audit_org_a_1" },
      entitlements: entitlements("org_b"), sourceEventId: "evt_other", createdAtUtcNs: "1001",
    })).rejects.toMatchObject({ code: "EVENT_REPLAY" });
    expect(await readSubscriptionV1(port, "org_b", "sub_1")).toBeNull();
    expect(port.revisionCount).toBe(1); expect(port.outboxCount).toBe(1);
  });

  it("never re-grants after a later source cancellation", async () => {
    const port = new FakePgPort(); port.organizations.set("org_a", true);
    await write(port, "org_a", "1", "ACTIVE", null, "0", "evt_active", "1000");
    await write(port, "org_a", "2", "CANCELED", null, "1", "evt_cancel", "3000");
    await expect(write(port, "org_a", "3", "ACTIVE", null, "2", "evt_late_active", "2000"))
      .rejects.toMatchObject({ code: "EVENT_STALE" });
    await expect(write(port, "org_a", "3", "ACTIVE", null, "2", "evt_equal", "3000"))
      .rejects.toMatchObject({ code: "EVENT_STALE" });
    expect((await readSubscriptionV1(port, "org_a", "sub_1"))?.revision).toBe("2");
    expect(await readEffectiveEntitlementsV1(port, "org_a", "sub_1", START)).toBeNull();
    expect(port.revisionCount).toBe(2); expect(port.outboxCount).toBe(2);
  });

  it("rolls back head and revision when the outbox write fails", async () => {
    const port = new FakePgPort(); port.organizations.set("org_a", true);
    await write(port, "org_a"); port.failOutbox = true;
    const failure = await write(port, "org_a", "2", "PAUSED").catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(SubscriptionLedgerErrorV1);
    expect(failure).toMatchObject({ code: "TRANSACTION_FAILED" });
    expect(String(failure)).not.toContain("private contents");
    expect(JSON.stringify(failure)).not.toContain("private contents");
    expect((await readSubscriptionV1(port, "org_a", "sub_1"))?.revision).toBe("1");
    expect(port.revisionCount).toBe(1); expect(port.outboxCount).toBe(1);
  });

  it("serializes concurrent last-writer conflict and denies inactive orgs", async () => {
    const port = new FakePgPort(); port.organizations.set("org_a", true);
    await write(port, "org_a");
    const outcomes = await Promise.allSettled([
      write(port, "org_a", "2", "PAUSED", null, "1", "event_left"),
      write(port, "org_a", "2", "CANCELED", null, "1", "event_right"),
    ]);
    expect(outcomes.filter((x) => x.status === "fulfilled")).toHaveLength(1);
    expect(outcomes.filter((x) => x.status === "rejected")).toHaveLength(1);
    expect(port.outboxCount).toBe(2);
    expect(await readEffectiveEntitlementsV1(port, "org_a", "sub_1", START)).toBeNull();
    port.organizations.set("org_a", false);
    expect(await readEffectiveEntitlementsV1(port, "org_a", "sub_1", START)).toBeNull();
    await expect(write(port, "org_a", "3")).rejects.toMatchObject({ code: "ORG_INACTIVE" });
  });

  it("rejects unsafe text and non-exact numeric representations without echo", async () => {
    const port = new FakePgPort(); port.organizations.set("org_a", true);
    const canary = "secret' OR 1=1 --";
    const bad = await writeSubscriptionRevisionV1(port, {
      expectedRevision: "0", subscription: { ...subscription("org_a"), billingReference: canary },
      entitlements: entitlements("org_a"), sourceEventId: "event_1", createdAtUtcNs: START,
    }).catch((error: unknown) => error);
    expect(bad).toMatchObject({ code: "INVALID_INPUT" });
    expect(String(bad)).not.toContain(canary);
    await expect(writeSubscriptionRevisionV1(port, {
      expectedRevision: "0", subscription: { ...subscription("org_a"), seatLimit: "1.0" },
      entitlements: entitlements("org_a"), sourceEventId: "event_1", createdAtUtcNs: START,
    })).rejects.toMatchObject({ code: "INVALID_INPUT" });
    await expect(writeSubscriptionRevisionV1(port, {
      expectedRevision: "0", subscription: { ...subscription("org_a"), billingAmountDecimal: "1E+100000", billingCurrency: "USD" },
      entitlements: entitlements("org_a"), sourceEventId: "event_1", createdAtUtcNs: START,
    })).rejects.toMatchObject({ code: "INVALID_INPUT" });
    for (const amount of ["1.2500", "10.00", "1.0"]) {
      await expect(write(port, "org_a", "1", "ACTIVE", amount))
        .rejects.toMatchObject({ code: "INVALID_INPUT" });
    }
    for (const billingReference of ["sk_live_CANARY", "sk_test_CANARY", "rk_CANARY", "whsec_CANARY"]) {
      await expect(writeSubscriptionRevisionV1(port, {
        expectedRevision: "0", subscription: { ...subscription("org_a"), billingReference },
        entitlements: entitlements("org_a"), sourceEventId: "event_1", createdAtUtcNs: START,
      })).rejects.toMatchObject({ code: "INVALID_INPUT" });
    }
    const hostile = { ...subscription("org_a"), get billingReference(): string { throw new Error(canary); } };
    const hostileError = await writeSubscriptionRevisionV1(port, {
      expectedRevision: "0", subscription: hostile,
      entitlements: entitlements("org_a"), sourceEventId: "event_1", createdAtUtcNs: START,
    }).catch((error: unknown) => error);
    expect(String(hostileError)).not.toContain(canary);
    expect(JSON.stringify(hostileError)).not.toContain(canary);
    expect(port.outboxCount).toBe(0);
  });

  it("rejects orphan subscriptions before writing any row", async () => {
    const port = new FakePgPort();
    await expect(write(port, "missing_org")).rejects.toMatchObject({ code: "ORG_UNKNOWN" });
    expect(port.revisionCount).toBe(0); expect(port.outboxCount).toBe(0);
  });

  it("rejects a port result that crosses the requested tenant scope", async () => {
    const wrong: Row = {
      ...rowFromParams(["org_b", "sub_1", "1", "ACTIVE", START, END, "2",
        '{"research":true}', '{"maxAgents":"1"}', null, null, null, "audit_1"]),
    };
    const port: SubscriptionTransactionPortV1 = {
      transaction: async (work) => work({
        query: async <RowType>() => ({ rows: [wrong as RowType] }),
      }),
    };
    await expect(readSubscriptionV1(port, "org_a", "sub_1"))
      .rejects.toMatchObject({ code: "TRANSACTION_FAILED" });
    await expect(readEffectiveEntitlementsV1(port, "org_a", "sub_1", START))
      .rejects.toMatchObject({ code: "TRANSACTION_FAILED" });
  });
});
