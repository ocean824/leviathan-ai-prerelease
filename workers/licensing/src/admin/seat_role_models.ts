/** Synthetic LIC-003 seat transaction records. Times, counters and versions are decimal text. */

export type SeatStatusV1 = "ACTIVE" | "INVITED" | "REVOKED";

export type SeatActionV1 = "ASSIGN" | "INVITE" | "CHANGE_ROLE" | "REVOKE";

/** Stable system role identifiers; authority never comes from a role name. */
export const SYSTEM_ROLE_OWNER = "owner";
export const SYSTEM_ROLE_ADMIN = "admin";

/**
 * The actor identity must come from a verified SEC-002/003 principal at API wiring.
 * The service loads the actor's actual role from the transaction port; no role claim
 * is accepted here.
 */
export interface SeatCommandV1 {
  readonly schemaVersion: 1;
  readonly action: SeatActionV1;
  readonly orgId: string;
  readonly subscriptionId: string;
  readonly actorUserId: string;
  readonly seatId: string;
  /** Required for ASSIGN/INVITE; null for mutations, which resolve the stored user. */
  readonly targetUserId: string | null;
  /** Required for ASSIGN/INVITE/CHANGE_ROLE; null for REVOKE. */
  readonly roleId: string | null;
  /** Zero for create; current seat version for CHANGE_ROLE/REVOKE. */
  readonly expectedVersion: string;
  readonly idempotencyKey: string;
  readonly auditEventId: string;
  /** Synthetic UTC nanoseconds; production adapters must use trusted server time. */
  readonly occurredAtUtcNs: string;
}

/** A transaction receipt only; this record is not an authorization capability. */
export interface SeatResultV1 {
  readonly schemaVersion: 1;
  readonly orgId: string;
  readonly seatId: string;
  readonly userId: string;
  readonly roleId: string;
  readonly status: SeatStatusV1;
  readonly version: string;
  readonly auditEventId: string;
  readonly occurredAtUtcNs: string;
}

export type SeatRoleErrorCodeV1 =
  | "INVALID_INPUT" | "ORG_UNKNOWN" | "ORG_INACTIVE" | "SUBSCRIPTION_UNAVAILABLE"
  | "SeatLimitExceeded" | "LastOwnerGuard" | "FORBIDDEN" | "SEAT_NOT_FOUND"
  | "DUPLICATE_SEAT" | "ROLE_NOT_FOUND" | "VERSION_CONFLICT"
  | "IDEMPOTENCY_CONFLICT" | "EVENT_REPLAY" | "TRANSACTION_FAILED";

/** Fixed error codes only: no user input, SQL, driver message, or cause is exposed. */
export class SeatRoleErrorV1 extends Error {
  readonly code: SeatRoleErrorCodeV1;

  constructor(code: SeatRoleErrorCodeV1) {
    super(code);
    this.name = "SeatRoleErrorV1";
    this.code = code;
  }
}
