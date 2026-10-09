import { describe, expect, it } from "vitest";
import {
  readEffectiveEntitlementsV1,
  readSubscriptionV1,
  writeSubscriptionRevisionV1,
  type PgQueryV1,
  type SubscriptionTransactionPortV1,
} from "../src/db/repository.js";
import {
  SubscriptionLedgerErrorV1,
  type EntitlementSetV1,
  type SubscriptionRecordV1,
} from "../src/db/models.js";

type DbRow = Record<string, unknown>;
type LedgerState = {
  orgs: Map<string, boolean>;
  heads: Map<string, DbRow>;
  revisions: DbRow[];
  outbox: DbRow[];
};

const cloneState = (state: LedgerState): LedgerState => structuredClone(state);
const tenantKey = (orgId: string, subscriptionId: string): string => `${orgId}/${subscriptionId}`;

/** A tiny transactional Postgres stand-in driven by the public query labels. */
class MemoryLedger implements SubscriptionTransactionPortV1 {
  private state: LedgerState = {
    orgs: new Map(), heads: new Map(), revisions: [], outbox: [],
  };
  failOutboxInsert = false;
  transactionCount = 0;
  private pending: Promise<void> = Promise.resolve();

  setOrg(orgId: string, active: boolean): void {
    this.state.orgs.set(orgId, active);
  }

  get headCount(): number { return this.state.heads.size; }
  get revisionCount(): number { return this.state.revisions.length; }
  get outboxCount(): number { return this.state.outbox.length; }

  async transaction<T>(work: (tx: PgQueryV1) => Promise<T>): Promise<T> {
    this.transactionCount += 1;
    const previous = this.pending;
    let release!: () => void;
    this.pending = new Promise<void>((resolve) => { release = resolve; });
    await previous;
    const draft = cloneState(this.state);
    const tx: PgQueryV1 = {
      query: async <Row>(sql: string, params: readonly unknown[]) => {
        const label = /\/\*([A-Z0-9_]+)\*\//.exec(sql)?.[1];
        const rows = this.execute(label, params, draft);
        return { rows: rows as Row[] };
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

  private execute(label: string | undefined, params: readonly unknown[], state: LedgerState): DbRow[] {
    switch (label) {
      case "LIC002_ORG_LOCK": {
        const orgId = String(params[0]);
        const active = state.orgs.get(orgId);
        return active === undefined ? [] : [{ active }];
      }
      case "LIC002_EVENT_EXISTS": {
        const sourceId = String(params[0]);
        const auditId = String(params[1]);
        return state.revisions.some((row) =>
          row.source_event_id === sourceId || row.audit_event_id === auditId)
          ? [{ exists: 1 }] : [];
      }
      case "LIC002_SOURCE_ORDER": {
        const orgId = String(params[0]);
        const subscriptionId = String(params[1]);
        const latest = state.revisions
          .filter((row) => row.org_id === orgId && row.subscription_id === subscriptionId)
          .sort((left, right) => Number(BigInt(right.revision as string) - BigInt(left.revision as string)))[0];
        return latest ? [{ revision: latest.revision, created_at_utc_ns: latest.created_at_utc_ns }] : [];
      }
      case "LIC002_HEAD_INSERT":
      case "LIC002_HEAD_CAS": {
        const row = this.headFromParams(params);
        const key = tenantKey(String(row.org_id), String(row.subscription_id));
        const current = state.heads.get(key);
        if (label === "LIC002_HEAD_INSERT") {
          if (current) return [];
        } else if (!current || current.revision !== params[13]) {
          return [];
        }
        state.heads.set(key, row);
        return [{ revision: row.revision }];
      }
      case "LIC002_REVISION_INSERT": {
        const row = this.revisionFromParams(params);
        const duplicate = state.revisions.some((existing) =>
          existing.source_event_id === row.source_event_id ||
          existing.audit_event_id === row.audit_event_id);
        if (duplicate) throw new Error("synthetic unique constraint detail");
        state.revisions.push(row);
        return [];
      }
      case "LIC002_OUTBOX_INSERT":
        if (this.failOutboxInsert) {
          this.failOutboxInsert = false;
          throw new Error("synthetic outbox storage detail");
        }
        state.outbox.push({
          org_id: params[0], subscription_id: params[1], revision: params[2],
          audit_event_id: params[3], source_event_id: params[4],
          created_at_utc_ns: params[5], status: params[6],
        });
        return [];
      case "LIC002_READ": {
        const row = state.heads.get(tenantKey(String(params[0]), String(params[1])));
        return row ? [structuredClone(row)] : [];
      }
      case "LIC002_EFFECTIVE": {
        const orgId = String(params[0]);
        const row = state.heads.get(tenantKey(orgId, String(params[1])));
        if (!row || state.orgs.get(orgId) !== true) return [];
        return [{
          org_id: row.org_id, subscription_id: row.subscription_id, status: row.status,
          term_start_utc_ns: row.term_start_utc_ns, term_end_utc_ns: row.term_end_utc_ns,
          features: row.features, limits: row.limits,
        }];
      }
      default:
        throw new Error(`Unexpected synthetic SQL label: ${String(label)}`);
    }
  }

  private headFromParams(params: readonly unknown[]): DbRow {
    return {
      org_id: params[0], subscription_id: params[1], revision: params[2], status: params[3],
      term_start_utc_ns: params[4], term_end_utc_ns: params[5], seat_limit: params[6],
      features: JSON.parse(String(params[7])) as unknown,
      limits: JSON.parse(String(params[8])) as unknown,
      billing_reference: params[9], billing_amount_decimal: params[10],
      billing_currency: params[11], audit_event_id: params[12],
    };
  }

  private revisionFromParams(params: readonly unknown[]): DbRow {
    return {
      ...this.headFromParams(params), source_event_id: params[13], created_at_utc_ns: params[14],
    };
  }
}

const subscription = (
  overrides: Partial<SubscriptionRecordV1> = {},
): SubscriptionRecordV1 => ({
  schemaVersion: 1,
  orgId: "org-a",
  subscriptionId: "sub-1",
  revision: "1",
  status: "ACTIVE",
  termStartUtcNs: "1000",
  termEndUtcNs: "2000",
  seatLimit: "7",
  billingReference: null,
  billingAmountDecimal: null,
  billingCurrency: null,
  auditEventId: "audit-1",
  ...overrides,
});

const entitlements = (
  overrides: Partial<EntitlementSetV1> = {},
): EntitlementSetV1 => ({
  schemaVersion: 1,
  orgId: "org-a",
  subscriptionId: "sub-1",
  features: { replay: true, execution: false },
  limits: { seats: "7", credit: "9007199254740993.00000001" },
  ...overrides,
});

const write = (
  port: SubscriptionTransactionPortV1,
  overrides: Partial<SubscriptionRecordV1> = {},
  grants: Partial<EntitlementSetV1> = {},
  expectedRevision = "0",
  sourceEventId = "event-1",
  createdAtUtcNs = "1500",
) => writeSubscriptionRevisionV1(port, {
  expectedRevision,
  subscription: subscription(overrides),
  entitlements: entitlements(grants),
  sourceEventId,
  createdAtUtcNs,
});

describe("LIC-002 subscription ledger acceptance", () => {
  it("appends one exact v1 revision and matching audit outbox row atomically", async () => {
    const db = new MemoryLedger();
    db.setOrg("org-a", true);

    const result = await write(db);

    expect(result).toEqual({
      schemaVersion: 1, orgId: "org-a", subscriptionId: "sub-1", revision: "1",
      auditEventId: "audit-1", sourceEventId: "event-1", createdAtUtcNs: "1500",
    });
    expect([db.headCount, db.revisionCount, db.outboxCount]).toEqual([1, 1, 1]);
  });

  it("requires org and subscription scope to match and revision to be expected plus one", async () => {
    const db = new MemoryLedger();
    db.setOrg("org-a", true);
    await expect(write(db, { revision: "2" })).rejects.toMatchObject({ code: "INVALID_INPUT" });
    await expect(write(db, {}, { orgId: "org-b" })).rejects.toMatchObject({ code: "INVALID_INPUT" });
    await expect(write(db, {}, { subscriptionId: "sub-other" })).rejects.toMatchObject({ code: "INVALID_INPUT" });
    expect(db.transactionCount).toBe(0);
  });

  it("accepts only schema version 1 records and entitlement sets", async () => {
    const db = new MemoryLedger();
    db.setOrg("org-a", true);
    await expect(write(db, {
      schemaVersion: 2 as unknown as 1,
    })).rejects.toMatchObject({ code: "INVALID_INPUT" });
    await expect(write(db, {}, {
      schemaVersion: 2 as unknown as 1,
    })).rejects.toMatchObject({ code: "INVALID_INPUT" });
    expect([db.headCount, db.revisionCount, db.outboxCount]).toEqual([0, 0, 0]);
  });

  it.each([
    ["unknown", undefined, "ORG_UNKNOWN"],
    ["inactive", false, "ORG_INACTIVE"],
  ] as const)("denies writes for %s organizations", async (kind, active, code) => {
    const db = new MemoryLedger();
    if (active !== undefined) db.setOrg("org-a", active);
    await expect(write(db)).rejects.toMatchObject({ code });
    expect([db.headCount, db.revisionCount, db.outboxCount]).toEqual([0, 0, 0]);
  });

  it("detects repeated source events and audit ids before changing the head", async () => {
    const db = new MemoryLedger();
    db.setOrg("org-a", true);
    await write(db);
    await expect(write(db, { revision: "2", auditEventId: "audit-2" }, {}, "1", "event-1", "2000"))
      .rejects.toMatchObject({ code: "EVENT_REPLAY" });
    await expect(write(db, { revision: "2" }, {}, "1", "event-2", "2000"))
      .rejects.toMatchObject({ code: "EVENT_REPLAY" });
    expect([db.headCount, db.revisionCount, db.outboxCount]).toEqual([1, 1, 1]);
  });

  it("rejects ACTIVE@2000 after CANCELED@3000 and never re-grants", async () => {
    const db = new MemoryLedger();
    db.setOrg("org-a", true);
    await write(db, { status: "CANCELED" }, {}, "0", "cancel-event", "3000");

    await expect(write(
      db,
      { status: "ACTIVE", revision: "2", auditEventId: "audit-2" },
      {},
      "1",
      "late-active-event",
      "2000",
    )).rejects.toMatchObject({ code: "EVENT_STALE" });

    await expect(readSubscriptionV1(db, "org-a", "sub-1"))
      .resolves.toMatchObject({ status: "CANCELED", revision: "1" });
    await expect(readEffectiveEntitlementsV1(db, "org-a", "sub-1", "5000"))
      .resolves.toBeNull();
    expect([db.headCount, db.revisionCount, db.outboxCount]).toEqual([1, 1, 1]);
  });

  it("rejects a backwards createdAt timestamp without changing the head", async () => {
    const db = new MemoryLedger();
    db.setOrg("org-a", true);
    await write(db, {}, {}, "0", "event-1", "3000");
    await expect(write(
      db,
      { revision: "2", auditEventId: "audit-2", status: "PAUSED" },
      {},
      "1",
      "event-2",
      "2000",
    )).rejects.toMatchObject({ code: "EVENT_STALE" });
    await expect(readSubscriptionV1(db, "org-a", "sub-1"))
      .resolves.toMatchObject({ status: "ACTIVE", revision: "1" });
  });

  it("rejects the same provider event ID when replayed for another org", async () => {
    const db = new MemoryLedger();
    db.setOrg("org-a", true);
    db.setOrg("org-b", true);
    await write(db, {}, {}, "0", "provider-event-1", "1000");
    await expect(write(
      db,
      { orgId: "org-b", subscriptionId: "sub-2", auditEventId: "audit-org-b" },
      { orgId: "org-b", subscriptionId: "sub-2" },
      "0",
      "provider-event-1",
      "1100",
    )).rejects.toMatchObject({ code: "EVENT_REPLAY" });
    expect([db.headCount, db.revisionCount, db.outboxCount]).toEqual([1, 1, 1]);
  });

  it("allows one concurrent head compare-and-set and rejects the losing write", async () => {
    const db = new MemoryLedger();
    db.setOrg("org-a", true);
    await write(db);
    const a = write(db, { revision: "2", auditEventId: "audit-2" }, {}, "1", "event-2", "2000");
    const b = write(db, { revision: "2", auditEventId: "audit-3" }, {}, "1", "event-3", "3000");
    const results = await Promise.allSettled([a, b]);

    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    const rejected = results.find((result) => result.status === "rejected");
    expect(rejected).toMatchObject({ reason: { code: "REVISION_CONFLICT" } });
    expect([db.headCount, db.revisionCount, db.outboxCount]).toEqual([1, 2, 2]);
    await expect(readSubscriptionV1(db, "org-a", "sub-1")).resolves.toMatchObject({ revision: "2" });
  });

  it("rolls back head and revision when writing the outbox fails", async () => {
    const db = new MemoryLedger();
    db.setOrg("org-a", true);
    db.failOutboxInsert = true;
    const failure = await write(db).catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(SubscriptionLedgerErrorV1);
    expect(failure).toMatchObject({ code: "TRANSACTION_FAILED" });
    expect([db.headCount, db.revisionCount, db.outboxCount]).toEqual([0, 0, 0]);
  });

  it("reads only the requested tenant and subscription", async () => {
    const db = new MemoryLedger();
    db.setOrg("org-a", true);
    await write(db);
    expect(await readSubscriptionV1(db, "org-a", "sub-1")).toMatchObject({ orgId: "org-a" });
    expect(await readSubscriptionV1(db, "org-b", "sub-1")).toBeNull();
    expect(await readSubscriptionV1(db, "org-a", "sub-other")).toBeNull();
  });

  it("grants an ACTIVE entitlement at term start and denies it at the exclusive end", async () => {
    const db = new MemoryLedger();
    db.setOrg("org-a", true);
    await write(db);

    await expect(readEffectiveEntitlementsV1(db, "org-a", "sub-1", "1000"))
      .resolves.toMatchObject({ features: { replay: true } });
    await expect(readEffectiveEntitlementsV1(db, "org-a", "sub-1", "1999"))
      .resolves.toMatchObject({ orgId: "org-a" });
    await expect(readEffectiveEntitlementsV1(db, "org-a", "sub-1", "2000"))
      .resolves.toBeNull();
    await expect(readEffectiveEntitlementsV1(db, "org-a", "sub-1", "999"))
      .resolves.toBeNull();
  });

  it.each(["PAST_DUE", "PAUSED", "CANCELED"] as const)(
    "does not grant paid effects for %s even with billing evidence",
    async (status) => {
      const db = new MemoryLedger();
      db.setOrg("org-a", true);
      await write(db, {
        status, billingReference: "invoice-99", billingAmountDecimal: "999.99",
        billingCurrency: "USD",
      });
      await expect(readEffectiveEntitlementsV1(db, "org-a", "sub-1", "1500"))
        .resolves.toBeNull();
      await expect(readSubscriptionV1(db, "org-a", "sub-1"))
        .resolves.toMatchObject({ billingReference: "invoice-99" });
    },
  );

  it("rejects a TRIAL write with a typed denial before any ledger row is written", async () => {
    const db = new MemoryLedger();
    db.setOrg("org-a", true);
    const failure = await write(db, { status: "TRIAL" as unknown as SubscriptionRecordV1["status"] })
      .catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(SubscriptionLedgerErrorV1);
    expect(failure).toMatchObject({ code: "STATUS_NOT_ALLOWED" });
    expect(db.transactionCount).toBe(0);
    expect([db.headCount, db.revisionCount, db.outboxCount]).toEqual([0, 0, 0]);
  });

  it("requires an active org for entitlements, independently of the stored active subscription", async () => {
    const db = new MemoryLedger();
    db.setOrg("org-a", true);
    await write(db);
    db.setOrg("org-a", false);
    await expect(readEffectiveEntitlementsV1(db, "org-a", "sub-1", "1500")).resolves.toBeNull();
  });

  it("round-trips UTC nanoseconds and money/limits as exact decimal text", async () => {
    const db = new MemoryLedger();
    db.setOrg("org-a", true);
    const amount = "9007199254740993.00000001";
    const ns = "1700000000123456789";
    await write(db, {
      termStartUtcNs: ns, termEndUtcNs: "1700000000123456799",
      billingAmountDecimal: amount, billingCurrency: "USD",
    });

    const record = await readSubscriptionV1(db, "org-a", "sub-1");
    expect(record).toMatchObject({ termStartUtcNs: ns, billingAmountDecimal: amount, seatLimit: "7" });
    expect(Object.isFrozen(record)).toBe(true);
    const grants = await readEffectiveEntitlementsV1(db, "org-a", "sub-1", "1700000000123456790");
    expect(grants).toMatchObject({ limits: { credit: "9007199254740993.00000001" } });
    expect(Object.isFrozen(grants)).toBe(true);
    expect(Object.isFrozen(grants?.features)).toBe(true);
    expect(Object.isFrozen(grants?.limits)).toBe(true);
  });

  it("rejects floating-point money instead of rounding it", async () => {
    const db = new MemoryLedger();
    db.setOrg("org-a", true);
    await expect(write(db, {
      billingAmountDecimal: 0.1 as unknown as string,
      billingCurrency: "USD",
    })).rejects.toMatchObject({ code: "INVALID_INPUT" });
    await expect(write(db, {}, {
      limits: { credit: 0.1 as unknown as string },
    })).rejects.toMatchObject({ code: "INVALID_INPUT" });
    expect(db.transactionCount).toBe(0);
  });

  it("rejects malformed periods, numeric revisions, and invalid decimal text", async () => {
    const db = new MemoryLedger();
    db.setOrg("org-a", true);
    await expect(write(db, { termStartUtcNs: "2000", termEndUtcNs: "2000" }))
      .rejects.toMatchObject({ code: "INVALID_INPUT" });
    await expect(write(db, { revision: 1 as unknown as string }))
      .rejects.toMatchObject({ code: "INVALID_INPUT" });
    await expect(write(db, { billingAmountDecimal: "-0.01", billingCurrency: "USD" }))
      .rejects.toMatchObject({ code: "INVALID_INPUT" });
    await expect(write(db, { billingAmountDecimal: "1.2500", billingCurrency: "USD" }))
      .rejects.toMatchObject({ code: "INVALID_INPUT" });
    await expect(write(db, { billingReference: "sk_live_1234567890abcdef" }))
      .rejects.toMatchObject({ code: "INVALID_INPUT" });
  });

  it("exposes only a content-free typed error when the transaction driver fails", async () => {
    const port: SubscriptionTransactionPortV1 = {
      transaction: async () => { throw new Error("SQL: billing_reference=private-detail"); },
    };
    const failure = await write(port).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(SubscriptionLedgerErrorV1);
    expect(failure).toMatchObject({ code: "TRANSACTION_FAILED" });
    expect((failure as Error).message).toBe("TRANSACTION_FAILED");
    expect((failure as Error).message).not.toContain("private-detail");
  });
});
