/** LIC-002 transport records. All revisions and UTC nanoseconds are exact decimal text. */
export type SubscriptionStatusV1 =
  | "ACTIVE" | "PAST_DUE" | "PAUSED" | "CANCELED";

export interface SubscriptionRecordV1 {
  readonly schemaVersion: 1;
  readonly orgId: string;
  readonly subscriptionId: string;
  readonly revision: string;
  readonly status: SubscriptionStatusV1;
  readonly termStartUtcNs: string;
  readonly termEndUtcNs: string;
  readonly seatLimit: string;
  /** Billing fields are evidence only. They never grant an entitlement. */
  readonly billingReference: string | null;
  readonly billingAmountDecimal: string | null;
  readonly billingCurrency: string | null;
  readonly auditEventId: string;
}

export interface EntitlementSetV1 {
  readonly schemaVersion: 1;
  readonly orgId: string;
  readonly subscriptionId: string;
  readonly features: Readonly<Record<string, boolean>>;
  /** Nonnegative, exact decimal text. */
  readonly limits: Readonly<Record<string, string>>;
}

export interface LicenseRevisionV1 {
  readonly schemaVersion: 1;
  readonly orgId: string;
  readonly subscriptionId: string;
  readonly revision: string;
  readonly auditEventId: string;
  readonly sourceEventId: string;
  /** Synthetic provider occurred-at UTC ns; strict source order per subscription. */
  readonly createdAtUtcNs: string;
}

export type SubscriptionLedgerErrorCodeV1 =
  | "INVALID_INPUT" | "ORG_UNKNOWN" | "ORG_INACTIVE"
  | "STATUS_NOT_ALLOWED"
  | "REVISION_CONFLICT" | "EVENT_REPLAY" | "EVENT_STALE" | "TRANSACTION_FAILED";

/** Deliberately has no input, SQL, cause, or driver diagnostics in its public shape. */
export class SubscriptionLedgerErrorV1 extends Error {
  readonly code: SubscriptionLedgerErrorCodeV1;

  constructor(code: SubscriptionLedgerErrorCodeV1) {
    super(code);
    this.name = "SubscriptionLedgerErrorV1";
    this.code = code;
  }
}
