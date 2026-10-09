/** Public, provider-neutral DTOs for the SIGNUP-001 Worker route slice. */
export type SignupStatusV1 =
  | "ACTIVE" | "PAST_DUE" | "PAUSED" | "SUSPENDED" | "CANCELED" | "EXPIRED";

export type SignupErrorCodeV1 =
  | "NOT_CONFIGURED" | "INVALID_REQUEST" | "CONFIGURATION_UNAVAILABLE" | "CHECKOUT_UNAVAILABLE"
  | "INVALID_SIGNATURE" | "EVENT_NOT_ALLOWED" | "EVENT_REPLAY"
  | "EVENT_OUT_OF_ORDER" | "ACCOUNT_MISMATCH" | "LEDGER_UNAVAILABLE";

export interface SignupClockV1 {
  nowUtcNs(): string;
  nowUnixSeconds(): number;
}

export interface PendingSignupInputV1 {
  readonly org_name: string;
  readonly owner_email: string;
  readonly device_id: string;
  readonly idempotency_key: string;
}

export interface PendingSignupRecordV1 {
  readonly resource_id: string;
  readonly org_id: string;
  readonly device_id: string;
  readonly resource_version: string;
  readonly audit_id: string;
}

/** Adapter atomically persists pending account, owner, device, and its SEC-005 audit. */
export interface PendingSignupPortV1 {
  createPending(input: PendingSignupInputV1): Promise<PendingSignupRecordV1>;
}

export interface StripeCheckoutInputV1 {
  readonly pending_account_id: string;
  readonly org_id: string;
  readonly org_name: string;
  readonly owner_email: string;
  readonly device_id: string;
  readonly idempotency_key: string;
  readonly price_id: string;
  readonly success_url: string;
  readonly cancel_url: string;
}

export interface StripeCheckoutResultV1 {
  readonly session_id: string;
  readonly checkout_url: string;
}

export interface StripeSubscriptionDetailsV1 {
  readonly id: string;
  readonly customer_id: string;
  readonly status: string;
  readonly current_period_start: number;
  readonly current_period_end: number;
  readonly metadata: Readonly<Record<string, unknown>>;
}

export interface StripePortV1 {
  createCheckoutSession(input: StripeCheckoutInputV1): Promise<StripeCheckoutResultV1>;
  /** Used when a signed Checkout Session omits its subscription period fields. */
  getSubscriptionDetails?(subscriptionId: string): Promise<StripeSubscriptionDetailsV1>;
}

export type NormalizedStripeEventV1 = Readonly<{
  event_id: string;
  event_type: "checkout.session.completed" | "invoice.paid"
    | "customer.subscription.updated" | "customer.subscription.deleted";
  event_created_utc_ns: string;
  pending_account_id: string;
  org_id: string;
  subscription_id: string;
  customer_id: string;
  status: SignupStatusV1;
  term_start_utc_ns: string;
  term_end_utc_ns: string;
}>;

export interface SignupMutationResultV1 {
  readonly resource_id: string;
  readonly resource_version: string;
  readonly audit_id: string;
}

/**
 * The implementation must atomically deduplicate/order the provider event,
 * verify the pending-account/customer binding, append LIC-002, and emit SEC-005.
 * It must reject without writes on any failed precondition.
 */
export interface SignupWebhookTransactionPortV1 {
  applyVerifiedEvent(event: NormalizedStripeEventV1): Promise<SignupMutationResultV1>;
}

export interface SignupConfigV1 {
  readonly stripe_price_id: string;
  readonly stripe_webhook_secret: string;
  readonly success_url: string;
  readonly cancel_url: string;
}

export interface SignupDependenciesV1 {
  readonly clock: SignupClockV1;
  readonly request_id: () => string;
  readonly config: SignupConfigV1;
  readonly pending_signups: PendingSignupPortV1;
  readonly stripe: StripePortV1;
  readonly webhook_transactions: SignupWebhookTransactionPortV1;
}

export class SignupDenialV1 extends Error {
  constructor(readonly code: SignupErrorCodeV1) {
    super(code);
    this.name = "SignupDenialV1";
  }
}
