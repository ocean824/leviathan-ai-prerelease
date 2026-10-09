import type { SubscriptionTransactionPortV1 } from "../db/repository.js";
import type {
  NormalizedStripeEventV1, PendingSignupInputV1, PendingSignupPortV1,
  SignupMutationResultV1, SignupWebhookTransactionPortV1, StripeCheckoutInputV1,
  StripeCheckoutResultV1, StripePortV1,
} from "../signup/models.js";
import type { PgDriverV1 } from "./neon_admin.js";

const ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
function makeId(prefix: string): string { return `${prefix}-${crypto.randomUUID()}`; }
function digestText(value: string): Promise<string> {
  return crypto.subtle.digest("SHA-256", new TextEncoder().encode(value))
    .then((buffer) => Array.from(new Uint8Array(buffer), (b) => b.toString(16).padStart(2, "0")).join(""));
}
function dbStatus(status: NormalizedStripeEventV1["status"]): "ACTIVE" | "PAST_DUE" | "PAUSED" | "CANCELED" {
  if (status === "ACTIVE" || status === "PAST_DUE" || status === "PAUSED" || status === "CANCELED") return status;
  return "CANCELED";
}

export interface NeonSignupAdapterV1 {
  readonly pending_signups: PendingSignupPortV1;
  readonly webhook_transactions: SignupWebhookTransactionPortV1;
  readonly stripe: StripePortV1;
}

/** SQL and Stripe fetch ports are injectable; tests never make provider calls. */
export function createNeonSignupAdapterV1(
  driver: PgDriverV1,
  config: { readonly stripe_secret_key: string; readonly stripe_price_id: string; readonly caps_approved?: boolean },
  fetchPort: typeof fetch = fetch,
): NeonSignupAdapterV1 {
  const pending_signups: PendingSignupPortV1 = Object.freeze({
    async createPending(input: PendingSignupInputV1) {
      if (!ID.test(input.device_id) || !/^\S+@\S+\.\S+$/.test(input.owner_email)
          || !input.idempotency_key || input.idempotency_key.length > 255) throw new TypeError("INVALID_REQUEST");
      const pendingId = makeId("pending"); const orgId = makeId("org"); const auditId = makeId("audit");
      const userId = makeId("user");
      const occurred = String(BigInt(Date.now()) * 1_000_000n);
      const digest = await digestText(JSON.stringify([orgId, input.owner_email, input.device_id]));
      return driver.transaction(async (tx) => {
        await tx.query("INSERT INTO licensing_organizations(org_id,active) VALUES ($1,FALSE)", [orgId]);
        await tx.query(
          "INSERT INTO licensing_users(org_id,user_id,email,role_id,password_hash_pbkdf2,active,owner,totp_enrolled,created_at_utc_ns) VALUES ($1,$2,$3,'owner',NULL,FALSE,TRUE,FALSE,$4)",
          [orgId,userId,input.owner_email.toLowerCase(),occurred],
        );
        await tx.query(
          "INSERT INTO licensing_devices(device_id,org_id,user_id,status,created_at_utc_ns) VALUES ($1,$2,$3,'ACTIVE',$4)",
          [input.device_id,orgId,userId,occurred],
        );
        await tx.query(
          "INSERT INTO licensing_pending_signups(pending_account_id,org_id,owner_email,owner_user_id,device_id,status,idempotency_key,created_at_utc_ns) VALUES ($1,$2,$3,$4,$5,'PENDING',$6,$7)",
          [pendingId, orgId, input.owner_email.toLowerCase(), userId, input.device_id, input.idempotency_key, occurred],
        );
        await tx.query(
          "INSERT INTO licensing_audit_events(id,org_id,actor,action,resource,digest,created_at_utc_ns) VALUES ($1,$2,'signup:anonymous','signup.pending.create',$3,$4,$5)",
          [auditId, orgId, `pending_signup:${pendingId}`, digest, occurred],
        );
        return Object.freeze({ resource_id: pendingId, org_id: orgId, device_id: input.device_id,
          resource_version: "1", audit_id: auditId });
      });
    },
  });

  const webhook_transactions: SignupWebhookTransactionPortV1 = Object.freeze({
    async applyVerifiedEvent(event: NormalizedStripeEventV1): Promise<SignupMutationResultV1> {
      if (!ID.test(event.event_id) || !ID.test(event.pending_account_id) || !ID.test(event.org_id)
          || !ID.test(event.subscription_id)) throw new TypeError("EVENT_NOT_ALLOWED");
      const auditId = makeId("audit"); const revisionAuditId = makeId("audit");
      const occurred = String(BigInt(Date.now()) * 1_000_000n);
      const digest = await digestText(JSON.stringify([event.event_id, event.org_id, event.status]));
      return driver.transaction(async (tx) => {
        const pending = await tx.query<{ org_id: string; status: string; owner_email: string; device_id: string }>(
          "SELECT org_id,status,owner_email,device_id FROM licensing_pending_signups WHERE pending_account_id=$1 FOR UPDATE",
          [event.pending_account_id],
        );
        const row = pending.rows[0];
        if (!row || row.org_id !== event.org_id) throw new TypeError("ACCOUNT_MISMATCH");
        const prior = await tx.query("SELECT 1 FROM licensing_subscription_revisions WHERE source_event_id=$1", [event.event_id]);
        if (prior.rows.length) throw new TypeError("EVENT_REPLAY");
        const latest = await tx.query<{ revision: string }>(
          "SELECT revision::text AS revision FROM licensing_subscriptions WHERE org_id=$1 AND subscription_id=$2 FOR UPDATE",
          [event.org_id, event.subscription_id],
        );
        const expected = latest.rows[0]?.revision ?? "0";
        const revision = (BigInt(expected) + 1n).toString();
        const status = dbStatus(event.status);
        const enabled = config.caps_approved === true;
        const features = JSON.stringify({ desktop_app: enabled, market_data: enabled, analytics: enabled, admin_api: enabled });
        const limits = JSON.stringify({ api_rate_limit_rps: "1000", seats: "1000" });
        await tx.query(
          "INSERT INTO licensing_subscriptions(org_id,subscription_id,revision,status,term_start_utc_ns,term_end_utc_ns,seat_limit,features,limits,billing_reference,billing_amount_decimal,billing_currency,audit_event_id) VALUES ($1,$2,$3,$4,$5,$6,1000,$7::jsonb,$8::jsonb,$9,NULL,NULL,$10) ON CONFLICT(org_id,subscription_id) DO UPDATE SET revision=EXCLUDED.revision,status=EXCLUDED.status,term_start_utc_ns=EXCLUDED.term_start_utc_ns,term_end_utc_ns=EXCLUDED.term_end_utc_ns,audit_event_id=EXCLUDED.audit_event_id WHERE licensing_subscriptions.revision=$11",
          [event.org_id,event.subscription_id,revision,status,event.term_start_utc_ns,event.term_end_utc_ns,
            features,limits,`invoice-${event.event_id}`,revisionAuditId,expected],
        );
        await tx.query(
          "INSERT INTO licensing_subscription_revisions(org_id,subscription_id,revision,status,term_start_utc_ns,term_end_utc_ns,seat_limit,features,limits,billing_reference,billing_amount_decimal,billing_currency,audit_event_id,source_event_id,created_at_utc_ns) VALUES ($1,$2,$3,$4,$5,$6,1000,$7::jsonb,$8::jsonb,$9,NULL,NULL,$10,$11,$12)",
          [event.org_id,event.subscription_id,revision,status,event.term_start_utc_ns,event.term_end_utc_ns,
            features,limits,`invoice-${event.event_id}`,revisionAuditId,event.event_id,occurred],
        );
        await tx.query(
          "INSERT INTO licensing_subscription_outbox(org_id,subscription_id,revision,audit_event_id,source_event_id,created_at_utc_ns,status) VALUES ($1,$2,$3,$4,$5,$6,$7)",
          [event.org_id,event.subscription_id,revision,revisionAuditId,event.event_id,occurred,status],
        );
        await tx.query("UPDATE licensing_organizations SET active=TRUE WHERE org_id=$1", [event.org_id]);
        await tx.query("UPDATE licensing_users SET active=TRUE WHERE org_id=$1 AND user_id=(SELECT owner_user_id FROM licensing_pending_signups WHERE pending_account_id=$2)",
          [event.org_id,event.pending_account_id]);
        await tx.query("UPDATE licensing_pending_signups SET status='ACTIVE',stripe_customer_id=$2,version=version+1 WHERE pending_account_id=$1",
          [event.pending_account_id,event.customer_id]);
        await tx.query("INSERT INTO licensing_audit_events(id,org_id,actor,action,resource,digest,created_at_utc_ns) VALUES ($1,$2,'stripe:webhook',$3,$4,$5,$6)",
          [auditId,event.org_id,`signup.${event.event_type}`,`subscription:${event.subscription_id}`,digest,occurred]);
        return Object.freeze({ resource_id: event.subscription_id, resource_version: revision, audit_id: auditId });
      });
    },
  });

  const stripe: StripePortV1 = Object.freeze({
    async createCheckoutSession(input: StripeCheckoutInputV1): Promise<StripeCheckoutResultV1> {
      if (!config.stripe_secret_key.startsWith("sk_test_") || input.price_id !== config.stripe_price_id) {
        throw new Error("CHECKOUT_UNAVAILABLE");
      }
      const form = new URLSearchParams({ mode: "subscription", success_url: input.success_url,
        cancel_url: input.cancel_url, customer_email: input.owner_email,
        client_reference_id: input.pending_account_id,
        "line_items[0][price]": input.price_id, "line_items[0][quantity]": "1",
        "metadata[pending_account_id]": input.pending_account_id, "metadata[org_id]": input.org_id,
      });
      const response = await fetchPort("https://api.stripe.com/v1/checkout/sessions", {
        method: "POST", headers: { Authorization: `Bearer ${config.stripe_secret_key}`,
          "Content-Type": "application/x-www-form-urlencoded", "Idempotency-Key": input.idempotency_key }, body: form,
      });
      if (!response.ok) throw new Error("CHECKOUT_UNAVAILABLE");
      const value = await response.json() as { id?: unknown; url?: unknown };
      if (typeof value.id !== "string" || !value.id.startsWith("cs_test_") || typeof value.url !== "string"
          || !value.url.startsWith("https://")) throw new Error("CHECKOUT_UNAVAILABLE");
      return Object.freeze({ session_id: value.id, checkout_url: value.url });
    },
  });
  return Object.freeze({ pending_signups, webhook_transactions, stripe });
}

export function createSubscriptionTransactionAdapterV1(driver: PgDriverV1): SubscriptionTransactionPortV1 {
  return Object.freeze({
    transaction<T>(work: (tx: import("../db/repository.js").PgQueryV1) => Promise<T>): Promise<T> {
      return driver.transaction(work);
    },
  });
}
