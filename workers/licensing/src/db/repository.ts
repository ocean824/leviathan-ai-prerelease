import {
  SubscriptionLedgerErrorV1,
  type EntitlementSetV1,
  type LicenseRevisionV1,
  type SubscriptionRecordV1,
  type SubscriptionStatusV1,
} from "./models.js";

/** A parameterized PostgreSQL query. BIGINT columns must be returned as text. */
export interface PgQueryV1 {
  query<Row>(sql: string, params: readonly unknown[]): Promise<{ rows: Row[] }>;
}

/** The callback commits atomically on success and rolls back on any rejection. */
export interface SubscriptionTransactionPortV1 {
  transaction<T>(work: (tx: PgQueryV1) => Promise<T>): Promise<T>;
}

export interface WriteSubscriptionRevisionInputV1 {
  readonly expectedRevision: string;
  readonly subscription: SubscriptionRecordV1;
  readonly entitlements: EntitlementSetV1;
  readonly sourceEventId: string;
  /** Synthetic provider occurred-at UTC ns; must strictly advance. */
  readonly createdAtUtcNs: string;
}

const MAX_PG_BIGINT = 9223372036854775807n;
const ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
/** Only synthetic, non-provider-secret billing evidence is accepted in this slice. */
const BILLING_REFERENCE = /^(?:bill_|invoice-)[A-Za-z0-9][A-Za-z0-9_.:-]{0,119}$/;
const FEATURE = /^[A-Za-z][A-Za-z0-9_.:-]{0,63}$/;
const INTEGER = /^(0|[1-9][0-9]*)$/;
const DECIMAL = /^(0|[1-9][0-9]*)(?:\.([0-9]*[1-9]))?$/;
const STATUSES: readonly SubscriptionStatusV1[] =
  ["ACTIVE", "PAST_DUE", "PAUSED", "CANCELED"];

function invalid(): never { throw new SubscriptionLedgerErrorV1("INVALID_INPUT"); }

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function id(value: unknown): string {
  if (typeof value !== "string" || !ID.test(value)) invalid();
  return value;
}

function uint(value: unknown, positive = false): string {
  if (typeof value !== "string" || !INTEGER.test(value) || value.length > 19) invalid();
  const parsed = BigInt(value);
  if (parsed > MAX_PG_BIGINT || (positive && parsed === 0n)) invalid();
  return value;
}

function decimal(value: unknown): string {
  if (typeof value !== "string" || value.length > 60) invalid();
  const match = DECIMAL.exec(value);
  if (!match || (match[2]?.length ?? 0) > 18) invalid();
  if (match[1]!.length > 39) invalid();
  const significant = value.replace(".", "").replace(/^0+/, "").replace(/0+$/, "");
  if (significant.length > 34) invalid();
  return value;
}

function safeInput<T>(normalize: () => T): T {
  try { return normalize(); }
  catch (error) {
    if (error instanceof SubscriptionLedgerErrorV1 && error.code === "STATUS_NOT_ALLOWED") throw error;
    throw new SubscriptionLedgerErrorV1("INVALID_INPUT");
  }
}

function billingReference(value: unknown): string | null {
  if (value === null) return null;
  if (typeof value !== "string" || !BILLING_REFERENCE.test(value)) invalid();
  return value;
}

function values<V>(value: unknown, check: (item: unknown) => V): Readonly<Record<string, V>> {
  if (!isObject(value)) invalid();
  const prototype: unknown = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) invalid();
  const copy: Record<string, V> = Object.create(null) as Record<string, V>;
  for (const key of Object.keys(value)) {
    if (!FEATURE.test(key)) invalid();
    copy[key] = check(value[key]);
  }
  if (Object.getOwnPropertySymbols(value).length !== 0) invalid();
  return Object.freeze(copy);
}

function featureBool(value: unknown): boolean {
  if (typeof value !== "boolean") invalid();
  return value;
}

function record(value: unknown): SubscriptionRecordV1 {
  if (!isObject(value) || value.schemaVersion !== 1) invalid();
  const status = value.status;
  if (typeof status !== "string") invalid();
  if (!STATUSES.includes(status as SubscriptionStatusV1)) {
    throw new SubscriptionLedgerErrorV1("STATUS_NOT_ALLOWED");
  }
  const start = uint(value.termStartUtcNs);
  const end = uint(value.termEndUtcNs);
  if (BigInt(end) <= BigInt(start)) invalid();
  const amount = value.billingAmountDecimal;
  const currency = value.billingCurrency;
  if ((amount === null) !== (currency === null)) invalid();
  if (currency !== null && (typeof currency !== "string" || !/^[A-Z]{3}$/.test(currency))) invalid();
  return Object.freeze({
    schemaVersion: 1, orgId: id(value.orgId), subscriptionId: id(value.subscriptionId),
    revision: uint(value.revision, true), status: status as SubscriptionStatusV1,
    termStartUtcNs: start, termEndUtcNs: end, seatLimit: uint(value.seatLimit),
    billingReference: billingReference(value.billingReference),
    billingAmountDecimal: amount === null ? null : decimal(amount),
    billingCurrency: currency as string | null, auditEventId: id(value.auditEventId),
  });
}

function entitlements(value: unknown): EntitlementSetV1 {
  if (!isObject(value) || value.schemaVersion !== 1) invalid();
  return Object.freeze({
    schemaVersion: 1, orgId: id(value.orgId), subscriptionId: id(value.subscriptionId),
    features: values(value.features, featureBool), limits: values(value.limits, decimal),
  });
}

function rowRecord(row: Record<string, unknown>): SubscriptionRecordV1 {
  return record({
    schemaVersion: 1, orgId: row.org_id, subscriptionId: row.subscription_id,
    revision: row.revision, status: row.status,
    termStartUtcNs: row.term_start_utc_ns, termEndUtcNs: row.term_end_utc_ns,
    seatLimit: row.seat_limit, billingReference: row.billing_reference,
    billingAmountDecimal: row.billing_amount_decimal, billingCurrency: row.billing_currency,
    auditEventId: row.audit_event_id,
  });
}

function rowEntitlements(row: Record<string, unknown>): EntitlementSetV1 {
  return entitlements({
    schemaVersion: 1, orgId: row.org_id, subscriptionId: row.subscription_id,
    features: row.features, limits: row.limits,
  });
}

async function inTransaction<T>(port: SubscriptionTransactionPortV1, work: (tx: PgQueryV1) => Promise<T>): Promise<T> {
  try { return await port.transaction(work); }
  catch (error) {
    if (error instanceof SubscriptionLedgerErrorV1) throw error;
    throw new SubscriptionLedgerErrorV1("TRANSACTION_FAILED");
  }
}

/**
 * Append one synthetic, consecutive revision. The transaction port must provide
 * PostgreSQL atomic commit/rollback semantics; no billing provider is consulted.
 */
export async function writeSubscriptionRevisionV1(
  port: SubscriptionTransactionPortV1, input: WriteSubscriptionRevisionInputV1,
): Promise<LicenseRevisionV1> {
  const { current, expected, sourceEventId, createdAtUtcNs, data } = safeInput(() => {
    if (!isObject(input)) invalid();
    const current = record(input.subscription);
    const grants = entitlements(input.entitlements);
    const expected = uint(input.expectedRevision);
    const sourceEventId = id(input.sourceEventId);
    const createdAtUtcNs = uint(input.createdAtUtcNs);
    if (current.orgId !== grants.orgId || current.subscriptionId !== grants.subscriptionId ||
        BigInt(current.revision) !== BigInt(expected) + 1n) invalid();
    const data: readonly unknown[] = [
      current.orgId, current.subscriptionId, current.revision, current.status,
      current.termStartUtcNs, current.termEndUtcNs, current.seatLimit,
      JSON.stringify(grants.features), JSON.stringify(grants.limits),
      current.billingReference, current.billingAmountDecimal, current.billingCurrency,
      current.auditEventId,
    ];
    return { current, expected, sourceEventId, createdAtUtcNs, data };
  });
  return inTransaction(port, async (tx) => {
    const org = await tx.query<{ active: boolean }>(
      "/*LIC002_ORG_LOCK*/ SELECT active FROM licensing_organizations WHERE org_id = $1 FOR UPDATE",
      [current.orgId],
    );
    if (org.rows.length !== 1) throw new SubscriptionLedgerErrorV1("ORG_UNKNOWN");
    if (org.rows[0]?.active !== true) throw new SubscriptionLedgerErrorV1("ORG_INACTIVE");
    const replay = await tx.query<{ exists: number }>(
      "/*LIC002_EVENT_EXISTS*/ SELECT 1 AS exists FROM licensing_subscription_revisions WHERE source_event_id = $1 OR audit_event_id = $2 LIMIT 1",
      [sourceEventId, current.auditEventId],
    );
    if (replay.rows.length !== 0) throw new SubscriptionLedgerErrorV1("EVENT_REPLAY");
    const sourceOrder = await tx.query<{ revision: string; created_at_utc_ns: string }>(
      "/*LIC002_SOURCE_ORDER*/ SELECT revision::text AS revision, created_at_utc_ns::text AS created_at_utc_ns FROM licensing_subscription_revisions WHERE org_id=$1 AND subscription_id=$2 ORDER BY revision DESC LIMIT 1",
      [current.orgId, current.subscriptionId],
    );
    if (sourceOrder.rows.length > 1 ||
        (expected === "0" && sourceOrder.rows.length !== 0) ||
        (expected !== "0" && (sourceOrder.rows.length !== 1 || sourceOrder.rows[0]?.revision !== expected))) {
      throw new SubscriptionLedgerErrorV1("REVISION_CONFLICT");
    }
    if (sourceOrder.rows.length === 1 && BigInt(createdAtUtcNs) <= BigInt(uint(sourceOrder.rows[0]?.created_at_utc_ns))) {
      throw new SubscriptionLedgerErrorV1("EVENT_STALE");
    }
    const changed = expected === "0"
      ? await tx.query<{ revision: string }>(
        "/*LIC002_HEAD_INSERT*/ INSERT INTO licensing_subscriptions (org_id, subscription_id, revision, status, term_start_utc_ns, term_end_utc_ns, seat_limit, features, limits, billing_reference, billing_amount_decimal, billing_currency, audit_event_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9::jsonb,$10,$11,$12,$13) ON CONFLICT (org_id, subscription_id) DO NOTHING RETURNING revision::text AS revision",
        data,
      )
      : await tx.query<{ revision: string }>(
        "/*LIC002_HEAD_CAS*/ UPDATE licensing_subscriptions SET revision=$3,status=$4,term_start_utc_ns=$5,term_end_utc_ns=$6,seat_limit=$7,features=$8::jsonb,limits=$9::jsonb,billing_reference=$10,billing_amount_decimal=$11,billing_currency=$12,audit_event_id=$13 WHERE org_id=$1 AND subscription_id=$2 AND revision=$14 RETURNING revision::text AS revision",
        [...data, expected],
      );
    if (changed.rows.length !== 1 || changed.rows[0]?.revision !== current.revision) {
      throw new SubscriptionLedgerErrorV1("REVISION_CONFLICT");
    }
    await tx.query(
      "/*LIC002_REVISION_INSERT*/ INSERT INTO licensing_subscription_revisions (org_id,subscription_id,revision,status,term_start_utc_ns,term_end_utc_ns,seat_limit,features,limits,billing_reference,billing_amount_decimal,billing_currency,audit_event_id,source_event_id,created_at_utc_ns) VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9::jsonb,$10,$11,$12,$13,$14,$15)",
      [...data, sourceEventId, createdAtUtcNs],
    );
    await tx.query(
      "/*LIC002_OUTBOX_INSERT*/ INSERT INTO licensing_subscription_outbox (org_id,subscription_id,revision,audit_event_id,source_event_id,created_at_utc_ns,status) VALUES ($1,$2,$3,$4,$5,$6,$7)",
      [current.orgId, current.subscriptionId, current.revision, current.auditEventId,
        sourceEventId, createdAtUtcNs, current.status],
    );
    return Object.freeze({
      schemaVersion: 1, orgId: current.orgId, subscriptionId: current.subscriptionId,
      revision: current.revision, auditEventId: current.auditEventId,
      sourceEventId, createdAtUtcNs,
    });
  });
}

/** Read a scoped ledger record for audit. A record alone is never authorization. */
export async function readSubscriptionV1(
  port: SubscriptionTransactionPortV1, orgId: string, subscriptionId: string,
): Promise<SubscriptionRecordV1 | null> {
  const org = id(orgId); const subscription = id(subscriptionId);
  return inTransaction(port, async (tx) => {
    const result = await tx.query<Record<string, unknown>>(
      "/*LIC002_READ*/ SELECT org_id,subscription_id,revision::text AS revision,status,term_start_utc_ns::text AS term_start_utc_ns,term_end_utc_ns::text AS term_end_utc_ns,seat_limit::text AS seat_limit,billing_reference,billing_amount_decimal,billing_currency,audit_event_id FROM licensing_subscriptions WHERE org_id=$1 AND subscription_id=$2",
      [org, subscription],
    );
    if (result.rows.length === 0) return null;
    if (result.rows.length !== 1) throw new SubscriptionLedgerErrorV1("TRANSACTION_FAILED");
    const found = rowRecord(result.rows[0]!);
    if (found.orgId !== org || found.subscriptionId !== subscription) {
      throw new SubscriptionLedgerErrorV1("TRANSACTION_FAILED");
    }
    return found;
  });
}

/** Advisory entitlement evidence; consumers still need LIC-001 signed authorization. */
export async function readEffectiveEntitlementsV1(
  port: SubscriptionTransactionPortV1, orgId: string, subscriptionId: string, nowUtcNs: string,
): Promise<EntitlementSetV1 | null> {
  const org = id(orgId); const subscription = id(subscriptionId); const now = uint(nowUtcNs);
  return inTransaction(port, async (tx) => {
    const result = await tx.query<Record<string, unknown>>(
      "/*LIC002_EFFECTIVE*/ SELECT s.org_id,s.subscription_id,s.status,s.term_start_utc_ns::text AS term_start_utc_ns,s.term_end_utc_ns::text AS term_end_utc_ns,s.features,s.limits FROM licensing_subscriptions AS s JOIN licensing_organizations AS o ON o.org_id=s.org_id AND o.active=TRUE WHERE s.org_id=$1 AND s.subscription_id=$2",
      [org, subscription],
    );
    if (result.rows.length !== 1) return null;
    const row = result.rows[0]!;
    if (row.org_id !== org || row.subscription_id !== subscription) {
      throw new SubscriptionLedgerErrorV1("TRANSACTION_FAILED");
    }
    if (row.status !== "ACTIVE") return null;
    const start = uint(row.term_start_utc_ns); const end = uint(row.term_end_utc_ns);
    if (BigInt(start) > BigInt(now) || BigInt(now) >= BigInt(end)) return null;
    return rowEntitlements(row);
  });
}
