import { applySeatCommandV1 } from "../admin/seat_role_service.js";
import { SYSTEM_ROLE_OWNER } from "../admin/seat_role_models.js";
import {
  AdminApiErrorV1,
  type AdminApiDependenciesV1,
  type AdminAuditRowV1,
  type AdminDeviceRowV1,
  type AdminMutationContextV1,
  type AdminMutationReceiptV1,
  type AdminPrincipalV1,
  type AdminSubscriptionRowV1,
  type AdminSubscriptionStatusV1,
  type AdminTransactionV1,
  type AdminUserRowV1,
} from "./models.js";

const ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
const UINT = /^(0|[1-9][0-9]{0,63})$/;
const STATUSES: readonly AdminSubscriptionStatusV1[] = [
  "ACTIVE", "PAST_DUE", "PAUSED", "SUSPENDED", "CANCELED", "EXPIRED",
];
const TRANSITIONS: Readonly<Record<AdminSubscriptionStatusV1, readonly AdminSubscriptionStatusV1[]>> = {
  ACTIVE: ["PAST_DUE", "PAUSED", "SUSPENDED", "CANCELED", "EXPIRED"],
  PAST_DUE: ["ACTIVE", "PAUSED", "SUSPENDED", "CANCELED", "EXPIRED"],
  PAUSED: ["ACTIVE", "SUSPENDED", "CANCELED", "EXPIRED"],
  SUSPENDED: ["ACTIVE", "PAST_DUE", "CANCELED", "EXPIRED"],
  CANCELED: ["EXPIRED"],
  EXPIRED: [],
};
interface OwnerBootstrapContextV1 {
  readonly org_id: string;
  readonly owner_user_id: string;
  readonly subscription_id: string;
  readonly seat_id: string;
  readonly actor_user_id: string;
  readonly audit_id: string;
  readonly reason: string;
  readonly occurred_at_utc_ns: string;
  readonly correlation_id: string;
  consumed: boolean;
  active: boolean;
}
const createdOrganizations = new WeakMap<AdminTransactionV1, Set<string>>();
const ownerBootstrapContexts = new WeakMap<AdminTransactionV1, OwnerBootstrapContextV1>();

function invalid(): never { throw new AdminApiErrorV1(400, "INVALID_REQUEST"); }
function notFound(): never { throw new AdminApiErrorV1(404, "NOT_FOUND"); }

export function validId(value: unknown): value is string { return typeof value === "string" && ID.test(value); }
export function validUint(value: unknown): value is string {
  return typeof value === "string" && UINT.test(value) && value.length <= 19
    && BigInt(value) <= 9223372036854775807n;
}
export function validStatus(value: unknown): value is AdminSubscriptionStatusV1 {
  return typeof value === "string" && STATUSES.includes(value as AdminSubscriptionStatusV1);
}

function validSubscriptionRow(value: unknown, orgId: string): value is AdminSubscriptionRowV1 {
  if (!value || typeof value !== "object") return false;
  const row = value as AdminSubscriptionRowV1;
  return row.org_id === orgId && validId(row.subscription_id) && validId(row.plan_id)
    && validUint(row.term_start_utc_ns) && validUint(row.term_end_utc_ns)
    && BigInt(row.term_end_utc_ns) > BigInt(row.term_start_utc_ns) && validUint(row.seats)
    && validStatus(row.status) && validUint(row.version)
    && validUint(row.created_at_utc_ns) && validUint(row.updated_at_utc_ns);
}

export function requireReason(value: unknown): string {
  if (typeof value !== "string" || value.trim().length === 0 || value !== value.trim()
      || [...value].length > 512 || /[\u0000-\u001f\u007f]/.test(value)) invalid();
  return value;
}

export async function authorizeAdminActionV1(
  dependencies: AdminApiDependenciesV1,
  principal: AdminPrincipalV1,
  action: string,
): Promise<string> {
  let now: string;
  try { now = dependencies.clock.nowUtcNs(); }
  catch { throw new AdminApiErrorV1(503, "AUTH_UNAVAILABLE"); }
  if (!validUint(now)) throw new AdminApiErrorV1(503, "AUTH_UNAVAILABLE");
  let allowed: boolean;
  try { allowed = await dependencies.authorization.authorize(principal, action, now); }
  catch { throw new AdminApiErrorV1(503, "AUTH_UNAVAILABLE"); }
  if (allowed !== true) throw new AdminApiErrorV1(403, "FORBIDDEN");
  return now;
}

async function fingerprint(path: string, actor: string, body: Readonly<Record<string, unknown>>): Promise<string> {
  const stable = (value: unknown): unknown => {
    if (Array.isArray(value)) return value.map(stable);
    if (value && typeof value === "object") {
      const row = value as Record<string, unknown>;
      const copy: Record<string, unknown> = {};
      for (const key of Object.keys(row).sort()) {
        if (key !== "request_id" && key !== "idempotency_key") copy[key] = stable(row[key]);
      }
      return copy;
    }
    return value;
  };
  const bytes = new TextEncoder().encode(JSON.stringify([path, actor, stable(body)]));
  const hash = new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", bytes));
  return Array.from(hash, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function auditRow(
  input: AdminMutationContextV1,
  action: string,
  resourceType: string,
  resourceId: string,
  correlationId: string,
): AdminAuditRowV1 {
  return Object.freeze({
    audit_id: input.audit_id,
    org_id: input.org_id,
    actor_user_id: input.actor_user_id,
    action,
    resource_type: resourceType,
    resource_id: resourceId,
    occurred_at_utc_ns: input.occurred_at_utc_ns,
    outcome: "SUCCEEDED",
    reason: input.reason,
    correlation_id: correlationId,
  });
}

async function seatAuditContext(
  tx: AdminTransactionV1,
  principal: AdminPrincipalV1,
  orgId: string,
  subscriptionId: string,
  userId: string,
  seatId: string,
  roleId: string,
  action: "ASSIGN" | "INVITE" | "CHANGE_ROLE",
  expectedVersion: string,
  idempotencyKey: string,
  auditId: string,
  now: string,
) {
  const bytes = new TextEncoder().encode(`LIC_ADMIN_SEAT_V1\0${idempotencyKey}`);
  const digest = new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", bytes));
  const seatIdempotencyKey = `seat-${Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
  return applySeatCommandV1(tx.seat_transactions, {
    schemaVersion: 1,
    action,
    orgId,
    subscriptionId,
    actorUserId: principal.user_id,
    seatId,
    targetUserId: action === "ASSIGN" || action === "INVITE" ? userId : null,
    roleId,
    expectedVersion,
    idempotencyKey: seatIdempotencyKey,
    auditEventId: auditId,
    occurredAtUtcNs: now,
  });
}

function armOwnerBootstrap(tx: AdminTransactionV1, context: OwnerBootstrapContextV1): void {
  const created = createdOrganizations.get(tx);
  if (!created?.has(context.org_id) || ownerBootstrapContexts.has(tx)) {
    throw new AdminApiErrorV1(409, "BOOTSTRAP_DENIED");
  }
  ownerBootstrapContexts.set(tx, context);
}

/**
 * First-owner bootstrap exception, deliberately usable only in the transaction
 * that created the organization. All subsequent seat changes use LIC-003.
 */
export async function bootstrapOwnerSeat(
  tx: AdminTransactionV1,
  org_id: string,
  owner_user_id: string,
): Promise<void> {
  const state = ownerBootstrapContexts.get(tx);
  if (!state || !state.active || state.consumed || state.org_id !== org_id
      || state.owner_user_id !== owner_user_id || !createdOrganizations.get(tx)?.has(org_id)) {
    throw new AdminApiErrorV1(409, "BOOTSTRAP_DENIED");
  }
  state.consumed = true;
  const operation = async (pg: import("../db/repository.js").PgQueryV1): Promise<void> => {
    const org = await pg.query<{ active: boolean }>(
      "/*LICADMIN_BOOTSTRAP_ORG_LOCK*/ SELECT active FROM licensing_organizations WHERE org_id=$1 FOR UPDATE",
      [org_id],
    );
    if (org.rows.length !== 1 || org.rows[0]?.active !== true) throw new AdminApiErrorV1(409, "BOOTSTRAP_DENIED");
    const seats = await pg.query<{ seat_count: string }>(
      "/*LICADMIN_BOOTSTRAP_ZERO_SEATS*/ SELECT COUNT(*)::text AS seat_count FROM licensing_seats WHERE org_id=$1",
      [org_id],
    );
    if (seats.rows.length !== 1 || seats.rows[0]?.seat_count !== "0") throw new AdminApiErrorV1(409, "BOOTSTRAP_DENIED");
    const sub = await pg.query<{ subscription_id: string; status: string; seat_limit: string; term_start_utc_ns: string; term_end_utc_ns: string }>(
      "/*LICADMIN_BOOTSTRAP_SUBSCRIPTION*/ SELECT subscription_id,status,seat_limit::text AS seat_limit,term_start_utc_ns::text AS term_start_utc_ns,term_end_utc_ns::text AS term_end_utc_ns FROM licensing_subscriptions WHERE org_id=$1 AND subscription_id=$2 FOR UPDATE",
      [org_id, state.subscription_id],
    );
    if (sub.rows.length !== 1 || sub.rows[0]?.subscription_id !== state.subscription_id
        || sub.rows[0]?.status !== "ACTIVE" || !validUint(sub.rows[0]?.seat_limit)
        || BigInt(sub.rows[0]!.seat_limit) < 1n
        || !validUint(sub.rows[0]?.term_start_utc_ns) || !validUint(sub.rows[0]?.term_end_utc_ns)
        || BigInt(state.occurred_at_utc_ns) < BigInt(sub.rows[0]!.term_start_utc_ns)
        || BigInt(state.occurred_at_utc_ns) >= BigInt(sub.rows[0]!.term_end_utc_ns)) {
      throw new AdminApiErrorV1(409, "BOOTSTRAP_DENIED");
    }
    const role = await pg.query<{ role_id: string; immutable: boolean; org_id: string | null }>(
      "/*LICADMIN_BOOTSTRAP_OWNER_ROLE*/ SELECT role_id,immutable,org_id FROM licensing_roles WHERE role_id=$1",
      [SYSTEM_ROLE_OWNER],
    );
    if (role.rows.length !== 1 || role.rows[0]?.role_id !== SYSTEM_ROLE_OWNER
        || role.rows[0]?.immutable !== true || role.rows[0]?.org_id !== null) {
      throw new AdminApiErrorV1(409, "BOOTSTRAP_DENIED");
    }
    const inserted = await pg.query<{ seat_id: string; version: string }>(
      "/*LICADMIN_BOOTSTRAP_OWNER_SEAT*/ INSERT INTO licensing_seats (org_id,subscription_id,seat_id,user_id,role_id,status,version,assigned_at_utc_ns,updated_at_utc_ns,audit_event_id) VALUES ($1,$2,$3,$4,$5,'ACTIVE','1',$6,$6,$7) ON CONFLICT (org_id,seat_id) DO NOTHING RETURNING seat_id,version::text AS version",
      [org_id, state.subscription_id, state.seat_id, owner_user_id, SYSTEM_ROLE_OWNER,
        state.occurred_at_utc_ns, state.audit_id],
    );
    if (inserted.rows.length !== 1 || inserted.rows[0]?.seat_id !== state.seat_id
        || inserted.rows[0]?.version !== "1") throw new AdminApiErrorV1(409, "BOOTSTRAP_DENIED");
    await tx.appendAudit(Object.freeze({
      audit_id: state.audit_id, org_id, actor_user_id: state.actor_user_id,
      action: "ASSIGN", resource_type: "seat", resource_id: state.seat_id,
      occurred_at_utc_ns: state.occurred_at_utc_ns, outcome: "SUCCEEDED",
      reason: state.reason, correlation_id: state.correlation_id,
    }));
  };
  try {
    await tx.seat_transactions.transaction(operation);
  } catch {
    // The bootstrap capability is intentionally narrow. Any failure at the
    // LIC-003 seat/audit seam is a denial; the outer account transaction then
    // rolls back the organization, identity, subscription, and seat together.
    throw new AdminApiErrorV1(409, "BOOTSTRAP_DENIED");
  }
}

function context(
  principal: AdminPrincipalV1,
  idempotencyKey: string,
  expectedVersion: string,
  auditId: string,
  reason: string,
  now: string,
): AdminMutationContextV1 {
  return Object.freeze({
    org_id: principal.org_id, actor_user_id: principal.user_id,
    idempotency_key: idempotencyKey, expected_version: expectedVersion,
    audit_id: auditId, reason, occurred_at_utc_ns: now,
  });
}

async function replayReceipt(
  tx: AdminTransactionV1,
  contextValue: AdminMutationContextV1,
  hash: string,
): Promise<AdminMutationReceiptV1 | null> {
  try {
    return await tx.readIdempotency({
      org_id: contextValue.org_id,
      actor_user_id: contextValue.actor_user_id,
      idempotency_key: contextValue.idempotency_key,
      request_fingerprint: hash,
    });
  } catch { throw new AdminApiErrorV1(409, "IDEMPOTENCY_CONFLICT"); }
}

async function commitReceipt(
  tx: AdminTransactionV1,
  contextValue: AdminMutationContextV1,
  hash: string,
  receipt: AdminMutationReceiptV1,
): Promise<AdminMutationReceiptV1> {
  try {
    return await tx.saveIdempotency({
      org_id: contextValue.org_id,
      actor_user_id: contextValue.actor_user_id,
      idempotency_key: contextValue.idempotency_key,
      request_fingerprint: hash,
      receipt,
    });
  } catch { throw new AdminApiErrorV1(409, "IDEMPOTENCY_CONFLICT"); }
}

function checkOrg(principal: AdminPrincipalV1, orgId: string): void {
  if (principal.org_id !== orgId) throw new AdminApiErrorV1(404, "NOT_FOUND");
}

export async function createAccountV1(
  dependencies: AdminApiDependenciesV1,
  principal: AdminPrincipalV1,
  input: {
    readonly org_name: string;
    readonly owner_email: string;
    readonly plan_id: string;
    readonly term_start_utc_ns: string;
    readonly term_end_utc_ns: string;
    readonly seats: string;
    readonly status: "ACTIVE" | "PAUSED";
    readonly expected_version: "0";
    readonly reason: string;
    readonly idempotency_key: string;
    readonly request_id: string;
  },
  now: string,
): Promise<AdminMutationReceiptV1> {
  const hash = await fingerprint("/accounts:POST", principal.user_id, input);
  const ids = dependencies.ids;
  const orgId = ids.next("org");
  const userId = ids.next("user");
  const seatId = ids.next("seat");
  const subscriptionId = ids.next("subscription");
  const accountAuditId = ids.next("audit");
  const mutation = context(principal, input.idempotency_key, input.expected_version,
    accountAuditId, input.reason, now);
  let activeTx: AdminTransactionV1 | null = null;
  try {
    return await dependencies.store.transaction(async (tx) => {
      activeTx = tx;
      const previous = await replayReceipt(tx, mutation, hash);
      if (previous) return previous;
      const account = await tx.createOrganization({
        org_id: orgId, display_name: input.org_name, active: true, expected_version: "0",
      });
      if (account.org_id !== orgId || !validUint(account.version)) throw new AdminApiErrorV1(503, "STORE_UNAVAILABLE");
      createdOrganizations.set(tx, new Set([orgId]));
      await tx.createOwnerIdentity({ org_id: orgId, user_id: userId,
        email: input.owner_email, occurred_at_utc_ns: now });
      const initial = await tx.createSubscription({
        org_id: orgId, subscription_id: subscriptionId, plan_id: input.plan_id,
        term_start_utc_ns: input.term_start_utc_ns, term_end_utc_ns: input.term_end_utc_ns,
        seats: input.seats, status: "ACTIVE", expected_version: account.version,
        audit_id: ids.next("audit"), reason: input.reason, occurred_at_utc_ns: now,
      });
      if (!validSubscriptionRow(initial, orgId)) throw new AdminApiErrorV1(503, "STORE_UNAVAILABLE");
      armOwnerBootstrap(tx, {
        org_id: orgId, owner_user_id: userId, subscription_id: subscriptionId,
        seat_id: seatId, actor_user_id: principal.user_id, audit_id: ids.next("audit"),
        reason: input.reason, occurred_at_utc_ns: now, correlation_id: input.request_id,
        consumed: false, active: true,
      });
      await bootstrapOwnerSeat(tx, orgId, userId);
      if (input.status === "PAUSED") {
        await tx.changeSubscription({
          org_id: orgId, subscription_id: subscriptionId,
          patch: { status: "PAUSED" }, expected_version: initial.version,
          audit_id: ids.next("audit"), reason: input.reason, occurred_at_utc_ns: now,
        });
      }
      await tx.appendAudit(Object.freeze({
        ...auditRow(mutation, "ACCOUNT_CREATED", "account", orgId, input.request_id),
        org_id: orgId,
      }));
      const receipt = Object.freeze({ resource_id: orgId, resource_version: account.version, audit_id: accountAuditId });
      return commitReceipt(tx, mutation, hash, receipt);
    }).finally(() => {
      if (activeTx) {
        const state = ownerBootstrapContexts.get(activeTx);
        if (state) state.active = false;
        ownerBootstrapContexts.delete(activeTx);
        createdOrganizations.delete(activeTx);
      }
    });
  } catch (error) {
    if (error instanceof AdminApiErrorV1) throw error;
    throw new AdminApiErrorV1(409, "MUTATION_REJECTED");
  }
}

export async function createUserV1(
  dependencies: AdminApiDependenciesV1, principal: AdminPrincipalV1,
  input: { readonly email: string; readonly role_id: string; readonly reason: string; readonly expected_version: "0"; readonly idempotency_key: string; readonly request_id: string },
  now: string,
): Promise<AdminMutationReceiptV1> {
  const hash = await fingerprint("/users:POST", principal.user_id, input);
  const userId = dependencies.ids.next("user"); const seatId = dependencies.ids.next("seat");
  const auditId = dependencies.ids.next("audit");
  const mutation = context(principal, input.idempotency_key, input.expected_version, auditId, input.reason, now);
  try {
    return await dependencies.store.transaction(async (tx) => {
      const previous = await replayReceipt(tx, mutation, hash); if (previous) return previous;
      const available = await tx.findCurrentSubscription(principal.org_id, now);
      if (!available) throw new AdminApiErrorV1(409, "SUBSCRIPTION_UNAVAILABLE");
      if (!validSubscriptionRow(available, principal.org_id) || available.status !== "ACTIVE"
          || BigInt(now) < BigInt(available.term_start_utc_ns) || BigInt(now) >= BigInt(available.term_end_utc_ns)) {
        throw new AdminApiErrorV1(503, "STORE_UNAVAILABLE");
      }
      await tx.createUserIdentity({ org_id: principal.org_id, user_id: userId, email: input.email, occurred_at_utc_ns: now });
      const result = await seatAuditContext(tx, principal, principal.org_id, available.subscription_id,
        userId, seatId, input.role_id, "INVITE", "0", input.idempotency_key, dependencies.ids.next("audit"), now);
      await tx.appendAudit(auditRow(mutation, "USER_CREATED", "user", userId, input.request_id));
      return commitReceipt(tx, mutation, hash, Object.freeze({ resource_id: userId, resource_version: result.version, audit_id: auditId }));
    });
  } catch (error) {
    if (error instanceof AdminApiErrorV1) throw error;
    throw new AdminApiErrorV1(409, "MUTATION_REJECTED");
  }
}

export async function setUserRoleV1(
  dependencies: AdminApiDependenciesV1, principal: AdminPrincipalV1, userId: string,
  input: { readonly role_id: string; readonly expected_version: string; readonly reason: string; readonly idempotency_key: string; readonly request_id: string },
  now: string,
): Promise<AdminMutationReceiptV1> {
  checkOrg(principal, principal.org_id);
  const current = await dependencies.store.readUser(principal.org_id, userId);
  if (!current || current.seat_id === null) notFound();
  if (!validId(current.user_id) || !validId(current.subscription_id) || !validId(current.role_id)
      || !validId(current.seat_id) || !["ACTIVE", "INVITED", "REVOKED"].includes(current.status)
      || !validUint(current.version)) throw new AdminApiErrorV1(503, "STORE_UNAVAILABLE");
  if (current.version !== input.expected_version) throw new AdminApiErrorV1(409, "VERSION_CONFLICT");
  const hash = await fingerprint(`/users/${userId}/role:PUT`, principal.user_id, input);
  const auditId = dependencies.ids.next("audit");
  const mutation = context(principal, input.idempotency_key, input.expected_version, auditId, input.reason, now);
  try {
    return await dependencies.store.transaction(async (tx) => {
      const previous = await replayReceipt(tx, mutation, hash); if (previous) return previous;
      const result = await seatAuditContext(tx, principal, principal.org_id, current.subscription_id,
        userId, current.seat_id!, input.role_id, "CHANGE_ROLE", input.expected_version,
        input.idempotency_key, dependencies.ids.next("audit"), now);
      await tx.appendAudit(auditRow(mutation, "USER_ROLE_CHANGED", "user", userId, input.request_id));
      return commitReceipt(tx, mutation, hash, Object.freeze({ resource_id: userId, resource_version: result.version, audit_id: auditId }));
    });
  } catch (error) {
    if (error instanceof AdminApiErrorV1) throw error;
    throw new AdminApiErrorV1(409, "MUTATION_REJECTED");
  }
}

export async function createSubscriptionV1(
  dependencies: AdminApiDependenciesV1, principal: AdminPrincipalV1,
  input: { readonly subscription_id?: string; readonly plan_id: string; readonly term_start_utc_ns: string; readonly term_end_utc_ns: string; readonly seats: string; readonly status: AdminSubscriptionStatusV1; readonly expected_version: string; readonly reason: string; readonly idempotency_key: string; readonly request_id: string },
  now: string,
): Promise<AdminMutationReceiptV1> {
  if (!TRANSITIONS.ACTIVE.includes(input.status) && input.status !== "ACTIVE") throw new AdminApiErrorV1(409, "INVALID_STATUS_TRANSITION");
  const subscriptionId = input.subscription_id ?? dependencies.ids.next("subscription");
  const hash = await fingerprint("/subscriptions:POST", principal.user_id, input);
  const auditId = dependencies.ids.next("audit");
  const mutation = context(principal, input.idempotency_key, input.expected_version, auditId, input.reason, now);
  try {
    return await dependencies.store.transaction(async (tx) => {
      const previous = await replayReceipt(tx, mutation, hash); if (previous) return previous;
      const account = await dependencies.store.readAccount(principal.org_id);
      if (!account) notFound();
      if (account.org_id !== principal.org_id || !validUint(account.version)) throw new AdminApiErrorV1(503, "STORE_UNAVAILABLE");
      if (account.version !== input.expected_version) throw new AdminApiErrorV1(409, "VERSION_CONFLICT");
      const row = await tx.createSubscription({
        org_id: principal.org_id, subscription_id: subscriptionId, plan_id: input.plan_id,
        term_start_utc_ns: input.term_start_utc_ns, term_end_utc_ns: input.term_end_utc_ns,
        seats: input.seats, status: input.status, expected_version: account.version,
        audit_id: dependencies.ids.next("audit"), reason: input.reason, occurred_at_utc_ns: now,
      });
      if (!validSubscriptionRow(row, principal.org_id)) throw new AdminApiErrorV1(503, "STORE_UNAVAILABLE");
      await tx.appendAudit(auditRow(mutation, "SUBSCRIPTION_CREATED", "subscription", subscriptionId, input.request_id));
      return commitReceipt(tx, mutation, hash, Object.freeze({ resource_id: subscriptionId, resource_version: row.version, audit_id: auditId }));
    });
  } catch (error) {
    if (error instanceof AdminApiErrorV1) throw error;
    throw new AdminApiErrorV1(409, "MUTATION_REJECTED");
  }
}

export async function changeSubscriptionV1(
  dependencies: AdminApiDependenciesV1, principal: AdminPrincipalV1, subscriptionId: string,
  operation: "PATCH" | "EXTEND" | "SUSPEND" | "RESUME",
  input: Readonly<Record<string, string>> & { readonly expected_version: string; readonly reason: string; readonly idempotency_key: string; readonly request_id: string },
  now: string,
): Promise<AdminMutationReceiptV1> {
  const current = await dependencies.store.readSubscription(principal.org_id, subscriptionId);
  if (!current) notFound();
  if (!validSubscriptionRow(current, principal.org_id)) throw new AdminApiErrorV1(503, "STORE_UNAVAILABLE");
  if (current.version !== input.expected_version) throw new AdminApiErrorV1(409, "VERSION_CONFLICT");
  let patch: Record<string, string>;
  if (operation === "PATCH") {
    if (!validStatus(input.status) || !TRANSITIONS[current.status].includes(input.status) && input.status !== current.status) {
      throw new AdminApiErrorV1(409, "INVALID_STATUS_TRANSITION");
    }
    patch = {
      plan_id: input.plan_id, term_start_utc_ns: input.term_start_utc_ns,
      term_end_utc_ns: input.term_end_utc_ns, seats: input.seats, status: input.status,
    };
  } else if (operation === "EXTEND") {
    if (!validUint(input.term_end_utc_ns) || BigInt(input.term_end_utc_ns) <= BigInt(current.term_end_utc_ns)) {
      throw new AdminApiErrorV1(400, "INVALID_REQUEST");
    }
    patch = { term_end_utc_ns: input.term_end_utc_ns };
  } else if (operation === "SUSPEND") {
    if (current.status === "CANCELED" || current.status === "EXPIRED" || current.status === "SUSPENDED") {
      throw new AdminApiErrorV1(409, "INVALID_STATUS_TRANSITION");
    }
    patch = { status: "SUSPENDED" };
  } else {
    const target = input.target_status;
    if ((target !== "ACTIVE" && target !== "PAST_DUE") || !TRANSITIONS[current.status].includes(target)) {
      throw new AdminApiErrorV1(409, "INVALID_STATUS_TRANSITION");
    }
    if (BigInt(now) < BigInt(current.term_start_utc_ns) || BigInt(now) >= BigInt(current.term_end_utc_ns)) {
      throw new AdminApiErrorV1(409, "TERM_NOT_ACTIVE");
    }
    patch = { status: target };
  }
  const hash = await fingerprint(`/subscriptions/${subscriptionId}/${operation}`, principal.user_id, input);
  const auditId = dependencies.ids.next("audit");
  const mutation = context(principal, input.idempotency_key, input.expected_version, auditId, input.reason, now);
  try {
    return await dependencies.store.transaction(async (tx) => {
      const previous = await replayReceipt(tx, mutation, hash); if (previous) return previous;
      const row = await tx.changeSubscription({
        org_id: principal.org_id, subscription_id: subscriptionId,
        patch, expected_version: input.expected_version, audit_id: dependencies.ids.next("audit"),
        reason: input.reason, occurred_at_utc_ns: now,
      });
      if (!validSubscriptionRow(row, principal.org_id)) throw new AdminApiErrorV1(503, "STORE_UNAVAILABLE");
      await tx.appendAudit(auditRow(mutation, `SUBSCRIPTION_${operation}`, "subscription", subscriptionId, input.request_id));
      return commitReceipt(tx, mutation, hash, Object.freeze({ resource_id: subscriptionId, resource_version: row.version, audit_id: auditId }));
    });
  } catch (error) {
    if (error instanceof AdminApiErrorV1) throw error;
    throw new AdminApiErrorV1(409, "MUTATION_REJECTED");
  }
}

export async function revokeDeviceV1(
  dependencies: AdminApiDependenciesV1, principal: AdminPrincipalV1, deviceId: string,
  input: { readonly expected_version: string; readonly reason: string; readonly idempotency_key: string; readonly request_id: string },
  now: string,
): Promise<AdminMutationReceiptV1> {
  const hash = await fingerprint(`/devices/${deviceId}/revoke`, principal.user_id, input);
  const auditId = dependencies.ids.next("audit");
  const mutation = context(principal, input.idempotency_key, input.expected_version, auditId, input.reason, now);
  try {
    return await dependencies.store.transaction(async (tx) => {
      const previous = await replayReceipt(tx, mutation, hash); if (previous) return previous;
      const row: AdminDeviceRowV1 = await tx.revokeDevice({ ...mutation, device_id: deviceId });
      if (!isAllowedDeviceRow(row) || row.org_id !== principal.org_id) throw new AdminApiErrorV1(503, "STORE_UNAVAILABLE");
      await tx.appendAudit(auditRow(mutation, "DEVICE_REVOKED", "device", deviceId, input.request_id));
      return commitReceipt(tx, mutation, hash, Object.freeze({ resource_id: deviceId, resource_version: row.version, audit_id: auditId }));
    });
  } catch (error) {
    if (error instanceof AdminApiErrorV1) throw error;
    throw new AdminApiErrorV1(409, "MUTATION_REJECTED");
  }
}

export function assertAdminRows<T>(items: readonly T[], validator: (value: unknown) => boolean): readonly T[] {
  if (!Array.isArray(items) || items.length > 100 || items.some((row) => !validator(row))) {
    throw new AdminApiErrorV1(503, "STORE_UNAVAILABLE");
  }
  return Object.freeze(items.map((row) => Object.freeze({ ...(row as object) }) as T));
}

export function isAllowedUserRow(value: unknown): value is AdminUserRowV1 {
  if (!value || typeof value !== "object") return false;
  const row = value as AdminUserRowV1;
  return validId(row.user_id) && validId(row.role_id) && (row.seat_id === null || validId(row.seat_id))
    && ["ACTIVE", "INVITED", "REVOKED"].includes(row.status) && validUint(row.version);
}

export function isAllowedDeviceRow(value: unknown): value is AdminDeviceRowV1 {
  if (!value || typeof value !== "object") return false;
  const row = value as AdminDeviceRowV1;
  return validId(row.device_id) && validId(row.org_id) && validId(row.user_id)
    && ["ACTIVE", "REVOKED"].includes(row.status) && validUint(row.version)
    && validUint(row.created_at_utc_ns)
    && (row.last_seen_at_utc_ns === null || validUint(row.last_seen_at_utc_ns))
    && (row.revoked_at_utc_ns === null || validUint(row.revoked_at_utc_ns));
}
