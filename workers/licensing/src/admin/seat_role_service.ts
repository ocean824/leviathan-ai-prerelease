import type { PgQueryV1, SubscriptionTransactionPortV1 } from "../db/repository.js";
import {
  SeatRoleErrorV1,
  SYSTEM_ROLE_ADMIN,
  SYSTEM_ROLE_OWNER,
  type SeatActionV1,
  type SeatCommandV1,
  type SeatResultV1,
  type SeatStatusV1,
} from "./seat_role_models.js";

const MAX_PG_BIGINT = 9223372036854775807n;
const ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
const INTEGER = /^(0|[1-9][0-9]*)$/;
const ACTIONS: readonly SeatActionV1[] = ["ASSIGN", "INVITE", "CHANGE_ROLE", "REVOKE"];
const STATUSES: readonly SeatStatusV1[] = ["ACTIVE", "INVITED", "REVOKED"];
const COMMAND_KEYS = [
  "schemaVersion", "action", "orgId", "subscriptionId", "actorUserId", "seatId",
  "targetUserId", "roleId", "expectedVersion", "idempotencyKey", "auditEventId",
  "occurredAtUtcNs",
].sort();

type Row = Record<string, unknown>;
type Query = <T extends Row>(sql: string, params: readonly unknown[]) => Promise<{ rows: T[] }>;

function isSystemRole(roleId: unknown, orgId: unknown, immutable: unknown, expectedId: string): boolean {
  return roleId === expectedId && orgId === null && immutable === true;
}

function fail(code: ConstructorParameters<typeof SeatRoleErrorV1>[0]): never {
  throw new SeatRoleErrorV1(code);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value) as unknown;
  return proto === Object.prototype || proto === null;
}

function id(value: unknown): string {
  if (typeof value !== "string" || !ID.test(value)) fail("INVALID_INPUT");
  return value;
}

function integer(value: unknown, positive = false): string {
  if (typeof value !== "string" || !INTEGER.test(value) || value.length > 19) fail("INVALID_INPUT");
  const n = BigInt(value);
  if (n > MAX_PG_BIGINT || (positive && n === 0n)) fail("INVALID_INPUT");
  return value;
}

function input(value: unknown): SeatCommandV1 {
  try {
    if (!isRecord(value) || Object.getOwnPropertySymbols(value).length !== 0) fail("INVALID_INPUT");
    const keys = Object.keys(value).sort();
    if (keys.length !== COMMAND_KEYS.length || keys.some((key, i) => key !== COMMAND_KEYS[i])) {
      fail("INVALID_INPUT");
    }
    const action = value.action;
    if (value.schemaVersion !== 1 || typeof action !== "string" ||
        !ACTIONS.includes(action as SeatActionV1)) fail("INVALID_INPUT");
    const normalized: SeatCommandV1 = {
      schemaVersion: 1, action: action as SeatActionV1,
      orgId: id(value.orgId), subscriptionId: id(value.subscriptionId),
      actorUserId: id(value.actorUserId), seatId: id(value.seatId),
      targetUserId: value.targetUserId === null ? null : id(value.targetUserId),
      roleId: value.roleId === null ? null : id(value.roleId),
      expectedVersion: integer(value.expectedVersion), idempotencyKey: id(value.idempotencyKey),
      auditEventId: id(value.auditEventId), occurredAtUtcNs: integer(value.occurredAtUtcNs),
    };
    if ((normalized.action === "ASSIGN" || normalized.action === "INVITE") &&
        (normalized.expectedVersion !== "0" || normalized.targetUserId === null || normalized.roleId === null)) {
      fail("INVALID_INPUT");
    }
    if (normalized.action === "CHANGE_ROLE" &&
        (normalized.expectedVersion === "0" || normalized.targetUserId !== null || normalized.roleId === null)) {
      fail("INVALID_INPUT");
    }
    if (normalized.action === "REVOKE" &&
        (normalized.expectedVersion === "0" || normalized.targetUserId !== null || normalized.roleId !== null)) {
      fail("INVALID_INPUT");
    }
    return Object.freeze(normalized);
  } catch (error) {
    if (error instanceof SeatRoleErrorV1) throw error;
    throw new SeatRoleErrorV1("INVALID_INPUT");
  }
}

function contentFreeResult(value: unknown, orgId: string, seatId: string, auditEventId: string): SeatResultV1 {
  try {
    if (!isRecord(value) || value.schemaVersion !== 1 || value.orgId !== orgId ||
        value.seatId !== seatId || value.auditEventId !== auditEventId ||
        typeof value.userId !== "string" || !ID.test(value.userId) ||
        typeof value.roleId !== "string" || !ID.test(value.roleId) ||
        typeof value.status !== "string" || !STATUSES.includes(value.status as SeatStatusV1)) {
      fail("TRANSACTION_FAILED");
    }
    const version = integer(value.version, true);
    const occurredAtUtcNs = integer(value.occurredAtUtcNs);
    return Object.freeze({
      schemaVersion: 1, orgId, seatId, userId: value.userId, roleId: value.roleId,
      status: value.status as SeatStatusV1, version, auditEventId, occurredAtUtcNs,
    });
  } catch (error) {
    if (error instanceof SeatRoleErrorV1) throw error;
    throw new SeatRoleErrorV1("TRANSACTION_FAILED");
  }
}

async function fingerprint(command: SeatCommandV1): Promise<string> {
  const bytes = new TextEncoder().encode(JSON.stringify([
    command.schemaVersion, command.action, command.orgId, command.subscriptionId,
    command.actorUserId, command.seatId, command.targetUserId, command.roleId,
    command.expectedVersion, command.idempotencyKey, command.auditEventId,
    command.occurredAtUtcNs,
  ]));
  const digest = await globalThis.crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function query<T extends Row>(tx: PgQueryV1, tag: string, sql: string, params: readonly unknown[]): Promise<T[]> {
  const result = await tx.query<T>(`/*${tag}*/ ${sql}`, params);
  return result.rows;
}

async function execute(command: SeatCommandV1, commandHash: string, tx: PgQueryV1): Promise<SeatResultV1> {
  const orgRows = await query<{ active: boolean }>(tx, "LIC003_ORG_LOCK",
    "SELECT active FROM licensing_organizations WHERE org_id=$1 FOR UPDATE", [command.orgId]);
  const actorRows = await query<{ role_id: string; role_org_id: string | null; role_immutable: boolean; seat_status: string }>(tx, "LIC003_ACTOR_ROLE",
    "SELECT r.role_id AS role_id,r.org_id AS role_org_id,r.immutable AS role_immutable,s.status AS seat_status FROM licensing_seats s JOIN licensing_roles r ON r.role_id=s.role_id AND (r.org_id=s.org_id OR r.org_id IS NULL) WHERE s.org_id=$1 AND s.user_id=$2 AND s.status='ACTIVE'",
    [command.orgId, command.actorUserId]);
  if (actorRows.length !== 1 || actorRows[0]?.seat_status !== "ACTIVE") fail("FORBIDDEN");
  if (orgRows.length !== 1) fail("ORG_UNKNOWN");
  if (orgRows[0]?.active !== true) fail("ORG_INACTIVE");
  const actorRoleId = actorRows[0]?.role_id;
  const actorIsOwner = isSystemRole(actorRoleId, actorRows[0]?.role_org_id, actorRows[0]?.role_immutable, SYSTEM_ROLE_OWNER);
  const actorIsAdmin = isSystemRole(actorRoleId, actorRows[0]?.role_org_id, actorRows[0]?.role_immutable, SYSTEM_ROLE_ADMIN);
  if (!actorIsOwner && !actorIsAdmin) fail("FORBIDDEN");

  const previous = await query<{ command_hash: string; result_json: string }>(tx, "LIC003_IDEMPOTENCY",
    "SELECT command_hash,result_json FROM licensing_admin_idempotency WHERE org_id=$1 AND actor_user_id=$2 AND idempotency_key=$3",
    [command.orgId, command.actorUserId, command.idempotencyKey]);
  if (previous.length > 1) fail("TRANSACTION_FAILED");
  if (previous.length === 1) {
    if (previous[0]?.command_hash !== commandHash || typeof previous[0]?.result_json !== "string") {
      fail("IDEMPOTENCY_CONFLICT");
    }
    let parsed: unknown;
    try { parsed = JSON.parse(previous[0].result_json) as unknown; }
    catch { fail("TRANSACTION_FAILED"); }
    return contentFreeResult(parsed, command.orgId, command.seatId, command.auditEventId);
  }

  const auditRows = await query<{ exists: boolean }>(tx, "LIC003_AUDIT_EXISTS",
    "SELECT TRUE AS exists FROM licensing_admin_audit WHERE audit_event_id=$1 UNION ALL SELECT TRUE AS exists FROM licensing_subscription_revisions WHERE audit_event_id=$1 LIMIT 1",
    [command.auditEventId]);
  if (auditRows.length !== 0) fail("EVENT_REPLAY");

  const create = command.action === "ASSIGN" || command.action === "INVITE";
  let targetUserId: string;
  let currentRoleId: string | null = null;
  let currentIsOwner = false;
  let currentStatus: SeatStatusV1 | null = null;
  let currentVersion = "0";

  if (create) {
    targetUserId = command.targetUserId!;
    const targetRows = await query<{ role_id: string; role_org_id: string | null; immutable: boolean }>(
      tx, "LIC003_TARGET_ROLE",
      "SELECT role_id,org_id AS role_org_id,immutable FROM licensing_roles WHERE role_id=$1 AND (org_id=$2 OR org_id IS NULL)",
      [command.roleId!, command.orgId]);
    if (targetRows.length !== 1 || typeof targetRows[0]?.role_id !== "string" ||
        typeof targetRows[0]?.immutable !== "boolean") fail("ROLE_NOT_FOUND");
    if (actorIsAdmin && isSystemRole(targetRows[0]?.role_id, targetRows[0]?.role_org_id,
      targetRows[0]?.immutable, SYSTEM_ROLE_OWNER)) fail("FORBIDDEN");
    const duplicates = await query<{ seat_id: string }>(tx, "LIC003_USER_SEAT_EXISTS",
      "SELECT seat_id FROM licensing_seats WHERE org_id=$1 AND user_id=$2 AND status IN ('ACTIVE','INVITED') LIMIT 1",
      [command.orgId, targetUserId]);
    if (duplicates.length !== 0) fail("DUPLICATE_SEAT");
    const subscriptions = await query<{ status: string; seat_limit: string; term_start_utc_ns: string; term_end_utc_ns: string }>(
      tx, "LIC003_SUBSCRIPTION",
      "SELECT status,seat_limit::text AS seat_limit,term_start_utc_ns::text AS term_start_utc_ns,term_end_utc_ns::text AS term_end_utc_ns FROM licensing_subscriptions WHERE org_id=$1 AND subscription_id=$2",
      [command.orgId, command.subscriptionId]);
    if (subscriptions.length !== 1 || subscriptions[0]?.status !== "ACTIVE") fail("SUBSCRIPTION_UNAVAILABLE");
    const seatLimit = BigInt(integer(subscriptions[0]?.seat_limit));
    const termStart = BigInt(integer(subscriptions[0]?.term_start_utc_ns));
    const termEnd = BigInt(integer(subscriptions[0]?.term_end_utc_ns));
    const at = BigInt(command.occurredAtUtcNs);
    if (at < termStart || at >= termEnd) fail("SUBSCRIPTION_UNAVAILABLE");
    const counts = await query<{ seats_used: string }>(tx, "LIC003_SEAT_COUNT",
      "SELECT COUNT(*)::text AS seats_used FROM licensing_seats WHERE org_id=$1 AND subscription_id=$2 AND status IN ('ACTIVE','INVITED')",
      [command.orgId, command.subscriptionId]);
    if (counts.length !== 1) fail("TRANSACTION_FAILED");
    if (BigInt(integer(counts[0]?.seats_used)) >= seatLimit) fail("SeatLimitExceeded");
  } else {
    const existing = await query<{
      subscription_id: string; user_id: string; role_id: string; role_org_id: string | null;
      role_immutable: boolean; status: string; version: string;
    }>(tx, "LIC003_SEAT_LOOKUP",
    "SELECT s.subscription_id,s.user_id,s.role_id,r.org_id AS role_org_id,r.immutable AS role_immutable,s.status,s.version::text AS version FROM licensing_seats s JOIN licensing_roles r ON r.role_id=s.role_id AND (r.org_id=s.org_id OR r.org_id IS NULL) WHERE s.org_id=$1 AND s.seat_id=$2 FOR UPDATE OF s",
    [command.orgId, command.seatId]);
    if (existing.length !== 1) fail("SEAT_NOT_FOUND");
    const row = existing[0]!;
    if (row.subscription_id !== command.subscriptionId) fail("SEAT_NOT_FOUND");
    targetUserId = id(row.user_id);
    if (typeof row.role_id !== "string" || !ID.test(row.role_id)) fail("TRANSACTION_FAILED");
    currentRoleId = row.role_id;
    if (typeof row.role_immutable !== "boolean" ||
        (row.role_org_id !== null && row.role_org_id !== command.orgId)) fail("TRANSACTION_FAILED");
    currentIsOwner = isSystemRole(currentRoleId, row.role_org_id, row.role_immutable, SYSTEM_ROLE_OWNER);
    if (row.status !== "ACTIVE" && row.status !== "INVITED") fail("SEAT_NOT_FOUND");
    currentStatus = row.status as SeatStatusV1;
    currentVersion = integer(row.version, true);
    if (currentVersion !== command.expectedVersion) fail("VERSION_CONFLICT");
    if (actorIsAdmin && currentIsOwner) fail("FORBIDDEN");
  }

  let nextRoleId: string;
  let nextStatus: SeatStatusV1;
  if (command.action === "ASSIGN") {
    nextRoleId = command.roleId!; nextStatus = "ACTIVE";
  } else if (command.action === "INVITE") {
    nextRoleId = command.roleId!; nextStatus = "INVITED";
  } else if (command.action === "CHANGE_ROLE") {
    nextRoleId = command.roleId!; nextStatus = currentStatus!;
    const targetRole = await query<{ role_id: string; role_org_id: string | null; immutable: boolean }>(tx, "LIC003_TARGET_ROLE",
      "SELECT role_id,org_id AS role_org_id,immutable FROM licensing_roles WHERE role_id=$1 AND (org_id=$2 OR org_id IS NULL)",
      [nextRoleId, command.orgId]);
    if (targetRole.length !== 1 || typeof targetRole[0]?.role_id !== "string" ||
        typeof targetRole[0]?.immutable !== "boolean") fail("ROLE_NOT_FOUND");
    const targetIsOwner = isSystemRole(targetRole[0]?.role_id, targetRole[0]?.role_org_id,
      targetRole[0]?.immutable, SYSTEM_ROLE_OWNER);
    if (actorIsAdmin && targetIsOwner) fail("FORBIDDEN");
    if (currentIsOwner && currentStatus === "ACTIVE" && !targetIsOwner) {
      const owners = await query<{ owner_count: string }>(tx, "LIC003_OWNER_COUNT",
        "SELECT COUNT(*)::text AS owner_count FROM licensing_seats s JOIN licensing_roles r ON r.role_id=s.role_id WHERE s.org_id=$1 AND s.status='ACTIVE' AND r.role_id=$2 AND r.org_id IS NULL AND r.immutable=TRUE",
        [command.orgId, SYSTEM_ROLE_OWNER]);
      if (owners.length !== 1) fail("TRANSACTION_FAILED");
      if (BigInt(integer(owners[0]?.owner_count)) <= 1n) fail("LastOwnerGuard");
    }
  } else {
    nextRoleId = currentRoleId!;
    nextStatus = "REVOKED";
    if (currentIsOwner && currentStatus === "ACTIVE") {
      const owners = await query<{ owner_count: string }>(tx, "LIC003_OWNER_COUNT",
        "SELECT COUNT(*)::text AS owner_count FROM licensing_seats s JOIN licensing_roles r ON r.role_id=s.role_id WHERE s.org_id=$1 AND s.status='ACTIVE' AND r.role_id=$2 AND r.org_id IS NULL AND r.immutable=TRUE",
        [command.orgId, SYSTEM_ROLE_OWNER]);
      if (owners.length !== 1) fail("TRANSACTION_FAILED");
      if (BigInt(integer(owners[0]?.owner_count)) <= 1n) fail("LastOwnerGuard");
    }
  }

  if (!actorIsOwner && !actorIsAdmin) fail("FORBIDDEN");
  const nextVersion = (BigInt(currentVersion) + 1n).toString();
  if (BigInt(nextVersion) > MAX_PG_BIGINT) fail("VERSION_CONFLICT");
  const fromRoleId = create ? null : currentRoleId!;
  const changed = create
    ? await query<{ seat_id: string; version: string }>(tx, "LIC003_SEAT_INSERT",
      "INSERT INTO licensing_seats (org_id,subscription_id,seat_id,user_id,role_id,status,version,assigned_at_utc_ns,updated_at_utc_ns,audit_event_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$8,$9) ON CONFLICT (org_id,seat_id) DO NOTHING RETURNING seat_id,version::text AS version",
      [command.orgId, command.subscriptionId, command.seatId, targetUserId, nextRoleId, nextStatus, nextVersion, command.occurredAtUtcNs, command.auditEventId])
    : await query<{ seat_id: string; version: string }>(tx, "LIC003_SEAT_UPDATE",
      "UPDATE licensing_seats SET role_id=$4,status=$5,version=$6,updated_at_utc_ns=$7,audit_event_id=$8 WHERE org_id=$1 AND seat_id=$2 AND version=$3 RETURNING seat_id,version::text AS version",
      [command.orgId, command.seatId, currentVersion, nextRoleId, nextStatus, nextVersion, command.occurredAtUtcNs, command.auditEventId]);
  if (create && changed.length === 0) fail("DUPLICATE_SEAT");
  if (changed.length !== 1 || changed[0]?.seat_id !== command.seatId || changed[0]?.version !== nextVersion) {
    fail("VERSION_CONFLICT");
  }
  const result = contentFreeResult({
    schemaVersion: 1, orgId: command.orgId, seatId: command.seatId, userId: targetUserId,
    roleId: nextRoleId, status: nextStatus, version: nextVersion,
    auditEventId: command.auditEventId, occurredAtUtcNs: command.occurredAtUtcNs,
  }, command.orgId, command.seatId, command.auditEventId);
  const audit = await query<{ audit_event_id: string }>(tx, "LIC003_AUDIT_INSERT",
    "INSERT INTO licensing_admin_audit (audit_event_id,org_id,actor_user_id,target_id,action,before_role_id,after_role_id,before_status,after_status,occurred_at_utc_ns) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT (audit_event_id) DO NOTHING RETURNING audit_event_id",
    [command.auditEventId, command.orgId, command.actorUserId, command.seatId, command.action,
      fromRoleId, nextRoleId, currentStatus, nextStatus, command.occurredAtUtcNs]);
  if (audit.length !== 1 || audit[0]?.audit_event_id !== command.auditEventId) fail("EVENT_REPLAY");
  const stored = await query<{ idempotency_key: string }>(tx, "LIC003_IDEMPOTENCY_INSERT",
    "INSERT INTO licensing_admin_idempotency (org_id,actor_user_id,idempotency_key,command_hash,result_json) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (org_id,actor_user_id,idempotency_key) DO NOTHING RETURNING idempotency_key",
    [command.orgId, command.actorUserId, command.idempotencyKey, commandHash, JSON.stringify(result)]);
  if (stored.length !== 1 || stored[0]?.idempotency_key !== command.idempotencyKey) fail("IDEMPOTENCY_CONFLICT");
  return result;
}

/**
 * Apply one synthetic, org-serialized seat transition. `port` must provide the
 * same transaction and rollback semantics as LIC-002 at READ COMMITTED isolation;
 * the locked organization row is the serialization point for seat-cap and
 * last-Owner checks. The transaction queries are tagged LIC003_* so a fake port
 * can verify the complete write ordering.
 */
export async function applySeatCommandV1(
  port: SubscriptionTransactionPortV1,
  rawCommand: SeatCommandV1,
): Promise<SeatResultV1> {
  const command = input(rawCommand);
  try {
    const commandHash = await fingerprint(command);
    return await port.transaction((tx) => execute(command, commandHash, tx));
  } catch (error) {
    if (error instanceof SeatRoleErrorV1) throw error;
    throw new SeatRoleErrorV1("TRANSACTION_FAILED");
  }
}
