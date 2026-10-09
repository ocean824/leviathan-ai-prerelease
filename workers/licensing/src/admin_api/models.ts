import type { SubscriptionTransactionPortV1 } from "../db/repository.js";
import type { SeatCommandV1, SeatResultV1 } from "../admin/seat_role_models.js";

export type AdminSubscriptionStatusV1 =
  | "ACTIVE" | "PAST_DUE" | "PAUSED" | "SUSPENDED" | "CANCELED" | "EXPIRED";

export interface AdminPrincipalV1 {
  readonly schema_version: 1;
  readonly org_id: string;
  readonly user_id: string;
  readonly device_id: string;
  readonly session_id: string;
}

export interface AdminEnvelopeV1<T> {
  readonly schema_version: 1;
  readonly request_id: string;
  readonly observed_at_ns: string;
  readonly data: T;
}

export interface AdminPageV1<T> {
  readonly items: readonly T[];
  readonly next_cursor: string | null;
}

export interface AdminErrorV1 {
  readonly schema_version: 1;
  readonly request_id: string;
  readonly observed_at_ns: string;
  readonly error: { readonly code: string; readonly message: string };
}

export interface AdminMutationReceiptV1 {
  readonly resource_id: string;
  readonly resource_version: string;
  readonly audit_id: string;
}

export interface AdminAccountRowV1 {
  readonly org_id: string;
  readonly display_name: string | null;
  readonly version: string;
}

export interface AdminUserRowV1 {
  readonly user_id: string;
  readonly role_id: string;
  readonly seat_id: string | null;
  readonly status: "ACTIVE" | "INVITED" | "REVOKED";
  readonly version: string;
}

/** Internal seat linkage for mutation routing; never serialized to the client. */
export interface AdminUserSeatRecordV1 extends AdminUserRowV1 {
  readonly subscription_id: string;
}

export interface AdminSubscriptionRowV1 {
  readonly subscription_id: string;
  readonly org_id: string;
  readonly plan_id: string;
  readonly term_start_utc_ns: string;
  readonly term_end_utc_ns: string;
  readonly seats: string;
  readonly status: AdminSubscriptionStatusV1;
  readonly version: string;
  readonly created_at_utc_ns: string;
  readonly updated_at_utc_ns: string;
}

export interface AdminDeviceRowV1 {
  readonly device_id: string;
  readonly org_id: string;
  readonly user_id: string;
  readonly status: "ACTIVE" | "REVOKED";
  readonly created_at_utc_ns: string;
  readonly last_seen_at_utc_ns: string | null;
  readonly revoked_at_utc_ns: string | null;
  readonly version: string;
}

export interface AdminAuditRowV1 {
  readonly audit_id: string;
  readonly org_id: string;
  readonly actor_user_id: string;
  readonly action: string;
  readonly resource_type: string;
  readonly resource_id: string;
  readonly occurred_at_utc_ns: string;
  readonly outcome: "SUCCEEDED";
  readonly reason: string;
  readonly correlation_id: string;
}

export interface AdminListQueryV1 {
  readonly org_id: string;
  readonly page_size: number;
  readonly cursor: string | null;
}

export interface AdminMutationContextV1 {
  readonly org_id: string;
  readonly actor_user_id: string;
  readonly idempotency_key: string;
  readonly expected_version: string;
  readonly audit_id: string;
  readonly reason: string;
  readonly occurred_at_utc_ns: string;
}

export interface AdminTransactionV1 {
  /** Every method below participates in the caller's single Neon transaction. */
  readonly seat_transactions: SubscriptionTransactionPortV1;
  createOrganization(input: {
    readonly org_id: string;
    readonly display_name: string;
    readonly active: true;
    readonly expected_version: "0";
  }): Promise<AdminAccountRowV1>;
  createOwnerIdentity(input: {
    readonly org_id: string;
    readonly user_id: string;
    readonly email: string;
    readonly occurred_at_utc_ns: string;
  }): Promise<void>;
  createSubscription(input: {
    readonly org_id: string;
    readonly subscription_id: string;
    readonly plan_id: string;
    readonly term_start_utc_ns: string;
    readonly term_end_utc_ns: string;
    readonly seats: string;
    readonly status: AdminSubscriptionStatusV1;
    readonly expected_version: string;
    readonly audit_id: string;
    readonly reason: string;
    readonly occurred_at_utc_ns: string;
  }): Promise<AdminSubscriptionRowV1>;
  createUserIdentity(input: {
    readonly org_id: string;
    readonly user_id: string;
    readonly email: string;
    readonly occurred_at_utc_ns: string;
  }): Promise<void>;
  findCurrentSubscription(org_id: string, occurred_at_utc_ns: string): Promise<AdminSubscriptionRowV1 | null>;
  changeSubscription(input: {
    readonly org_id: string;
    readonly subscription_id: string;
    readonly patch: Readonly<Record<string, string>>;
    readonly expected_version: string;
    readonly audit_id: string;
    readonly reason: string;
    readonly occurred_at_utc_ns: string;
  }): Promise<AdminSubscriptionRowV1>;
  revokeDevice(input: AdminMutationContextV1 & { readonly device_id: string }): Promise<AdminDeviceRowV1>;
  appendAudit(row: AdminAuditRowV1): Promise<void>;
  /** Durable idempotency receipt committed in the same transaction as the mutation. */
  saveIdempotency(input: {
    readonly org_id: string;
    readonly actor_user_id: string;
    readonly idempotency_key: string;
    readonly request_fingerprint: string;
    readonly receipt: AdminMutationReceiptV1;
  }): Promise<AdminMutationReceiptV1>;
  /** Resolve an existing key; null means this command has not committed before. */
  readIdempotency(input: {
    readonly org_id: string;
    readonly actor_user_id: string;
    readonly idempotency_key: string;
    readonly request_fingerprint: string;
  }): Promise<AdminMutationReceiptV1 | null>;
}

export interface AdminApiStorePortV1 {
  transaction<T>(work: (tx: AdminTransactionV1) => Promise<T>): Promise<T>;
  readAccount(org_id: string): Promise<AdminAccountRowV1 | null>;
  readUser(org_id: string, user_id: string): Promise<AdminUserSeatRecordV1 | null>;
  listAccounts(query: AdminListQueryV1): Promise<AdminPageV1<AdminAccountRowV1>>;
  listUsers(query: AdminListQueryV1): Promise<AdminPageV1<AdminUserRowV1>>;
  listSubscriptions(query: AdminListQueryV1): Promise<AdminPageV1<AdminSubscriptionRowV1>>;
  readSubscription(org_id: string, subscription_id: string): Promise<AdminSubscriptionRowV1 | null>;
  listDevices(query: AdminListQueryV1): Promise<AdminPageV1<AdminDeviceRowV1>>;
  listAudit(query: AdminListQueryV1): Promise<AdminPageV1<AdminAuditRowV1>>;
  /** Cursor validation must bind org, resource and filters. */
  decodeCursor(cursor: string, org_id: string, resource: string): Promise<string | null>;
  encodeCursor(last_key: string, org_id: string, resource: string): Promise<string>;
}

export interface AdminOwnerAuthRecordV1 {
  readonly org_id: string;
  readonly user_id: string;
  readonly password_hash_argon2id: string;
  readonly active: boolean;
  readonly owner: boolean;
  /** Missing means a legacy fixture; production rows always carry the persisted state. */
  readonly totp_enrolled?: boolean;
}

export interface AdminAuthenticationPortV1 {
  findOwnerByEmail(email: string): Promise<AdminOwnerAuthRecordV1 | null>;
  isLoginLocked(email: string, device_id: string): Promise<boolean>;
  recordFailedLogin(input: {
    readonly email: string;
    readonly device_id: string;
    readonly occurred_at_utc_ns: string;
    readonly max_failed_attempts: number;
    readonly lockout_seconds: number;
  }): Promise<boolean>;
  clearFailedLogins(email: string, device_id: string): Promise<void>;
  /** A null hash asks the adapter to perform its fixed dummy Argon2id verification. */
  verifyArgon2id(password: string, encoded_hash: string | null): Promise<boolean>;
  verifyTotp(user_id: string, code: string, occurred_at_utc_ns: string): Promise<boolean>;
  beginTotpEnrollment?(user_id: string, email: string): Promise<string>;
  confirmTotpEnrollment?(user_id: string, code: string, occurred_at_utc_ns: string): Promise<boolean>;
  issueSession(input: {
    readonly org_id: string;
    readonly user_id: string;
    readonly device_id: string;
    readonly issued_at_utc_ns: string;
    readonly expires_at_utc_ns: string;
    readonly token_id: string;
    readonly audit_id: string;
    readonly correlation_id: string;
    readonly reason: string;
  }): Promise<string>;
  resolveSession(token: string, device_id: string, now_utc_ns: string): Promise<AdminPrincipalV1 | null>;
  revokeSession(input: {
    readonly token: string;
    readonly device_id: string;
    readonly now_utc_ns: string;
    readonly audit_id: string;
    readonly correlation_id: string;
    readonly reason: string;
  }): Promise<void>;
}

export interface AdminAuthorizationPortV1 {
  /** Fresh SEC-002 decision; request claims never establish authority. */
  authorize(principal: AdminPrincipalV1, action: string, now_utc_ns: string): Promise<boolean>;
}

export interface AdminClockPortV1 {
  nowUtcNs(): string;
}

export interface AdminIdPortV1 {
  next(prefix: "request" | "org" | "user" | "seat" | "subscription" | "audit" | "session"): string;
}

export interface AdminSessionPolicyV1 {
  /** Operator-approved; absent or invalid policy denies session creation. */
  readonly ttl_seconds: string | null;
  readonly max_failed_attempts: number;
  readonly lockout_seconds: number;
}

export interface AdminApiDependenciesV1 {
  readonly auth: AdminAuthenticationPortV1;
  readonly authorization: AdminAuthorizationPortV1;
  readonly store: AdminApiStorePortV1;
  readonly clock: AdminClockPortV1;
  readonly ids: AdminIdPortV1;
  readonly session_policy: AdminSessionPolicyV1;
}

export class AdminApiErrorV1 extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, readonly data?: Readonly<Record<string, unknown>>) {
    super(code);
    this.name = "AdminApiErrorV1";
    this.status = status;
    this.code = code;
  }
}

export type AdminSeatCommandV1 = SeatCommandV1;
export type AdminSeatResultV1 = SeatResultV1;
