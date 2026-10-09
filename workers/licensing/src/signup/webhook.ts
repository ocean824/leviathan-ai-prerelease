import type {
  NormalizedStripeEventV1, SignupDependenciesV1, SignupErrorCodeV1, SignupStatusV1,
} from "./models.js";
import { SignupDenialV1 } from "./models.js";
import { signupErrorResponse } from "./handler.js";

const MAX_WEBHOOK_BYTES = 256 * 1024;
const ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
const STRIPE_ID = /^[A-Za-z][A-Za-z0-9_]{2,127}$/;
const SIGNATURE_TOLERANCE_SECONDS = 300;

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
}

function utf8(value: string): Uint8Array { return new TextEncoder().encode(value); }

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(copy).set(bytes);
  return copy;
}

function fromHex(value: string): Uint8Array | null {
  if (!/^(?:[0-9a-f]{2}){32}$/i.test(value)) return null;
  const bytes = new Uint8Array(32);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

/** Verify the Stripe HMAC signature on the untouched request bytes. */
export async function verifyStripeSignatureV1(
  raw: Uint8Array,
  signatureHeader: string | null,
  secret: string,
  nowUnixSeconds: number,
): Promise<boolean> {
  if (!signatureHeader || !/^whsec_[A-Za-z0-9_-]{8,}$/.test(secret)
      || !Number.isSafeInteger(nowUnixSeconds) || nowUnixSeconds < 0) return false;
  const fields = signatureHeader.split(",");
  let timestamp: number | null = null;
  const signatures: Uint8Array[] = [];
  for (const field of fields) {
    const split = field.indexOf("=");
    if (split <= 0) return false;
    const name = field.slice(0, split);
    const value = field.slice(split + 1);
    if (name === "t") {
      if (timestamp !== null || !/^(0|[1-9][0-9]{0,15})$/.test(value)) return false;
      timestamp = Number(value);
    } else if (name === "v1") {
      const decoded = fromHex(value);
      if (!decoded) return false;
      signatures.push(decoded);
    }
  }
  if (timestamp === null || !Number.isSafeInteger(timestamp) || signatures.length === 0
      || Math.abs(nowUnixSeconds - timestamp) > SIGNATURE_TOLERANCE_SECONDS) return false;
  const signedPayload = new Uint8Array(utf8(`${timestamp}.`).byteLength + raw.byteLength);
  signedPayload.set(utf8(`${timestamp}.`), 0);
  signedPayload.set(raw, utf8(`${timestamp}.`).byteLength);
  try {
    const key = await globalThis.crypto.subtle.importKey(
      "raw", toArrayBuffer(utf8(secret)), { name: "HMAC", hash: "SHA-256" }, false, ["verify"],
    );
    for (const signature of signatures) {
      if (await globalThis.crypto.subtle.verify("HMAC", key,
        toArrayBuffer(signature), toArrayBuffer(signedPayload))) return true;
    }
  } catch { return false; }
  return false;
}

function requiredId(value: unknown, stripe = false): string {
  if (typeof value !== "string" || !(stripe ? STRIPE_ID : ID).test(value)) {
    throw new SignupDenialV1("EVENT_NOT_ALLOWED");
  }
  return value;
}

function secondsToNs(value: unknown): string {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new SignupDenialV1("EVENT_NOT_ALLOWED");
  }
  return (BigInt(value) * 1_000_000_000n).toString();
}

function metadata(value: unknown): Record<string, unknown> {
  return isRecord(value) ? value : Object.create(null) as Record<string, unknown>;
}

function statusFor(
  eventType: string, object: Record<string, unknown>, nowUnixSeconds: number,
): SignupStatusV1 {
  if (eventType === "checkout.session.completed" || eventType === "invoice.paid") return "ACTIVE";
  if (eventType === "customer.subscription.deleted") {
    const end = object.current_period_end;
    return typeof end === "number" && Number.isSafeInteger(end) && end <= nowUnixSeconds
      ? "EXPIRED" : "CANCELED";
  }
  const status = object.status;
  if (status === "active") return "ACTIVE";
  if (status === "past_due" || status === "unpaid" || status === "incomplete") return "PAST_DUE";
  if (status === "paused") return "PAUSED";
  if (status === "canceled") return "CANCELED";
  if (status === "incomplete_expired") return "EXPIRED";
  throw new SignupDenialV1("EVENT_NOT_ALLOWED");
}

async function normalizeEvent(
  value: unknown, deps: SignupDependenciesV1, nowUnixSeconds: number,
): Promise<NormalizedStripeEventV1> {
  if (!isRecord(value) || typeof value.type !== "string" || !isRecord(value.data)
      || !isRecord(value.data.object)) throw new SignupDenialV1("EVENT_NOT_ALLOWED");
  const eventType = value.type;
  if (eventType !== "checkout.session.completed" && eventType !== "invoice.paid"
      && eventType !== "customer.subscription.updated"
      && eventType !== "customer.subscription.deleted") throw new SignupDenialV1("EVENT_NOT_ALLOWED");
  const object = value.data.object;
  const objectMetadata = metadata(object.metadata);
  const parent = metadata(object.parent);
  const subscriptionDetails = metadata(parent.subscription_details);
  let detailMetadata = metadata(subscriptionDetails.metadata);
  const subscriptionValue = eventType.startsWith("customer.subscription.")
    ? object.id : object.subscription ?? subscriptionDetails.subscription;
  let subscriptionSnapshot: Record<string, unknown> | null = null;
  if ((object.current_period_start === undefined || object.current_period_end === undefined)
      && deps.stripe.getSubscriptionDetails && typeof subscriptionValue === "string") {
    const details = await deps.stripe.getSubscriptionDetails(subscriptionValue);
    subscriptionSnapshot = {
      id: details.id, customer: details.customer_id, status: details.status,
      current_period_start: details.current_period_start, current_period_end: details.current_period_end,
      metadata: details.metadata,
    };
    detailMetadata = metadata(details.metadata);
  }
  const pendingId = object.client_reference_id ?? objectMetadata.pending_account_id
    ?? detailMetadata.pending_account_id;
  const orgId = objectMetadata.org_id ?? detailMetadata.org_id;
  const subscriptionId = subscriptionValue;
  const periods = Array.isArray(metadata(object.lines).data)
    ? (metadata(object.lines).data as unknown[])[0] : null;
  const linePeriod = isRecord(periods) ? metadata(periods.period) : Object.create(null) as Record<string, unknown>;
  const periodObject = subscriptionSnapshot ?? object;
  const start = periodObject.current_period_start ?? linePeriod.start;
  const end = periodObject.current_period_end ?? linePeriod.end;
  const customer = typeof object.customer === "string" ? object.customer
    : isRecord(object.customer) ? object.customer.id : subscriptionSnapshot?.customer;
  const eventCreated = value.created;
  const eventTypeAllowed = eventType as NormalizedStripeEventV1["event_type"];
  if (eventType === "checkout.session.completed" && object.payment_status !== "paid") {
    throw new SignupDenialV1("EVENT_NOT_ALLOWED");
  }
  const nowNs = deps.clock.nowUtcNs();
  const startNs = start === undefined ? nowNs : secondsToNs(start);
  const endNs = end === undefined ? "0" : secondsToNs(end);
  if (BigInt(endNs) <= BigInt(startNs)) throw new SignupDenialV1("EVENT_NOT_ALLOWED");
  if (typeof eventCreated !== "number" || !Number.isSafeInteger(eventCreated) || eventCreated < 0) {
    throw new SignupDenialV1("EVENT_NOT_ALLOWED");
  }
  return Object.freeze({
    event_id: requiredId(value.id, true), event_type: eventTypeAllowed,
    event_created_utc_ns: secondsToNs(eventCreated),
    pending_account_id: requiredId(pendingId), org_id: requiredId(orgId),
    subscription_id: requiredId(subscriptionId, true), customer_id: requiredId(customer, true),
    status: statusFor(eventType, periodObject, nowUnixSeconds),
    term_start_utc_ns: startNs, term_end_utc_ns: endNs,
  });
}

function codeFor(error: unknown): SignupErrorCodeV1 {
  if (error instanceof SignupDenialV1) return error.code;
  const code = (error as { code?: unknown } | null)?.code;
  if (code === "EVENT_REPLAY") return "EVENT_REPLAY";
  if (code === "EVENT_OUT_OF_ORDER" || code === "EVENT_STALE") return "EVENT_OUT_OF_ORDER";
  if (code === "ACCOUNT_MISMATCH") return "ACCOUNT_MISMATCH";
  return "LEDGER_UNAVAILABLE";
}

export async function signupWebhookRoute(
  request: Request, deps: SignupDependenciesV1,
): Promise<Response> {
  let requestId = "request-unavailable";
  let observedAtNs = "0";
  try {
    requestId = deps.request_id();
    observedAtNs = deps.clock.nowUtcNs();
    if (request.method !== "POST") throw new SignupDenialV1("INVALID_REQUEST");
    const declaredLength = request.headers.get("content-length");
    if (declaredLength !== null && (!/^\d{1,8}$/.test(declaredLength)
        || Number(declaredLength) > MAX_WEBHOOK_BYTES)) throw new SignupDenialV1("INVALID_REQUEST");
    const raw = new Uint8Array(await request.arrayBuffer());
    if (raw.byteLength > MAX_WEBHOOK_BYTES) throw new SignupDenialV1("INVALID_REQUEST");
    if (!await verifyStripeSignatureV1(raw, request.headers.get("stripe-signature"),
      deps.config.stripe_webhook_secret, deps.clock.nowUnixSeconds())) {
      throw new SignupDenialV1("INVALID_SIGNATURE");
    }
    let parsed: unknown;
    try { parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw)); }
    catch { throw new SignupDenialV1("EVENT_NOT_ALLOWED"); }
    if (!isRecord(parsed) || typeof parsed.livemode !== "boolean"
        || parsed.livemode !== (deps.config.stripe_mode === "live")) {
      throw new SignupDenialV1("STRIPE_MODE_MISMATCH");
    }
    const event = await normalizeEvent(parsed, deps, deps.clock.nowUnixSeconds());
    const applied = await deps.webhook_transactions.applyVerifiedEvent(event);
    return new Response(JSON.stringify({ schema_version: 1, request_id: requestId,
      observed_at_ns: observedAtNs, audit_id: applied.audit_id,
      data: { resource_id: applied.resource_id, resource_version: applied.resource_version } }), {
      status: 200, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
    });
  } catch (error) {
    if (error instanceof SignupDenialV1 && error.code === "STRIPE_MODE_MISMATCH") {
      try { console.warn("STRIPE_MODE_MISMATCH"); } catch { /* logging must not change rejection */ }
    }
    return signupErrorResponse(codeFor(error), requestId, observedAtNs);
  }
}
