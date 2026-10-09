import type {
  PendingSignupInputV1, SignupDependenciesV1, SignupErrorCodeV1,
  StripeCheckoutInputV1, StripePortV1,
} from "./models.js";
import { SignupDenialV1 } from "./models.js";

const MAX_CHECKOUT_BODY_BYTES = 4096;
const ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
const EMAIL = /^[^\s@]{1,128}@[^\s@.]{1,63}(?:\.[^\s@.]{1,63})+$/;
const SAFE_MESSAGE = "Request could not be completed.";

function response(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
  });
}

function errorCode(error: unknown): SignupErrorCodeV1 {
  if (error instanceof SignupDenialV1) return error.code;
  return "CHECKOUT_UNAVAILABLE";
}

function errorStatus(code: SignupErrorCodeV1): number {
  switch (code) {
    case "NOT_CONFIGURED": return 503;
    case "INVALID_REQUEST": return 400;
    case "INVALID_SIGNATURE": return 400;
    case "EVENT_NOT_ALLOWED": return 422;
    case "STRIPE_MODE_MISMATCH": return 422;
    case "EVENT_REPLAY": return 409;
    case "EVENT_OUT_OF_ORDER": return 409;
    case "ACCOUNT_MISMATCH": return 409;
    case "CONFIGURATION_UNAVAILABLE": return 503;
    case "CHECKOUT_UNAVAILABLE": return 503;
    case "LEDGER_UNAVAILABLE": return 503;
  }
}

export function signupErrorResponse(
  code: SignupErrorCodeV1, requestId: string, observedAtNs: string,
): Response {
  return response({ schema_version: 1, request_id: requestId, observed_at_ns: observedAtNs,
    error: { code, message: SAFE_MESSAGE } }, errorStatus(code));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
}

function checkoutInput(value: unknown): PendingSignupInputV1 {
  if (!isRecord(value) || Object.getOwnPropertySymbols(value).length !== 0
      || Object.keys(value).sort().join(",") !== "device_id,idempotency_key,org_name,owner_email") {
    throw new SignupDenialV1("INVALID_REQUEST");
  }
  const { org_name, owner_email, device_id, idempotency_key } = value;
  if (typeof org_name !== "string" || org_name.trim().length < 1 || org_name.length > 120
      || /[\u0000-\u001f\u007f]/.test(org_name)
      || typeof owner_email !== "string" || owner_email.length > 254 || !EMAIL.test(owner_email)
      || typeof device_id !== "string" || !ID.test(device_id)
      || typeof idempotency_key !== "string" || !ID.test(idempotency_key)) {
    throw new SignupDenialV1("INVALID_REQUEST");
  }
  return Object.freeze({ org_name: org_name.trim(), owner_email: owner_email.toLowerCase(),
    device_id, idempotency_key });
}

function validHttpsUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "https:" && url.username === "" && url.password === ""
      && url.hostname.length > 0;
  } catch { return false; }
}

export async function signupCheckoutRoute(request: Request, deps: SignupDependenciesV1): Promise<Response> {
  let requestId = "request-unavailable";
  let observedAtNs = "0";
  try {
    requestId = deps.request_id();
    observedAtNs = deps.clock.nowUtcNs();
    if (request.method !== "POST") throw new SignupDenialV1("INVALID_REQUEST");
    if (!/^application\/json(?:\s*;|$)/i.test(request.headers.get("content-type") ?? "")) {
      throw new SignupDenialV1("INVALID_REQUEST");
    }
    const declaredLength = request.headers.get("content-length");
    if (declaredLength !== null && (!/^\d{1,8}$/.test(declaredLength)
        || Number(declaredLength) > MAX_CHECKOUT_BODY_BYTES)) {
      throw new SignupDenialV1("INVALID_REQUEST");
    }
    const raw = await request.arrayBuffer();
    if (raw.byteLength > MAX_CHECKOUT_BODY_BYTES) throw new SignupDenialV1("INVALID_REQUEST");
    let parsed: unknown;
    try { parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw)); }
    catch { throw new SignupDenialV1("INVALID_REQUEST"); }
    const input = checkoutInput(parsed);
    if (!/^price_[A-Za-z0-9_]{3,127}$/.test(deps.config.stripe_price_id)
        || !validHttpsUrl(deps.config.success_url) || !validHttpsUrl(deps.config.cancel_url)) {
      throw new SignupDenialV1("CONFIGURATION_UNAVAILABLE");
    }
    const pending = await deps.pending_signups.createPending(input);
    const stripeInput: StripeCheckoutInputV1 = Object.freeze({
      pending_account_id: pending.resource_id, org_id: pending.org_id,
      org_name: input.org_name, owner_email: input.owner_email, device_id: input.device_id,
      idempotency_key: input.idempotency_key, price_id: deps.config.stripe_price_id,
      success_url: deps.config.success_url, cancel_url: deps.config.cancel_url,
    });
    const session = await deps.stripe.createCheckoutSession(stripeInput);
    return response({ schema_version: 1, request_id: requestId, observed_at_ns: observedAtNs,
      audit_id: pending.audit_id,
      data: { resource_id: pending.resource_id, resource_version: pending.resource_version,
        checkout_session_id: session.session_id, checkout_url: session.checkout_url } }, 201);
  } catch (error) {
    return signupErrorResponse(errorCode(error), requestId, observedAtNs);
  }
}

/** Create a Stripe TEST-mode Checkout adapter using a Worker secret, never source. */
export function createStripeTestPortV1(
  secretKey: string,
  fetcher: typeof fetch = fetch,
): StripePortV1 {
  if (!/^sk_test_[A-Za-z0-9_]{8,}$/.test(secretKey)) {
    throw new SignupDenialV1("CONFIGURATION_UNAVAILABLE");
  }
  return Object.freeze({
    async createCheckoutSession(input: StripeCheckoutInputV1) {
      const form = new URLSearchParams({
        mode: "subscription", customer_email: input.owner_email,
        client_reference_id: input.pending_account_id,
        success_url: input.success_url, cancel_url: input.cancel_url,
        "line_items[0][price]": input.price_id, "line_items[0][quantity]": "1",
        "metadata[pending_account_id]": input.pending_account_id,
        "metadata[org_id]": input.org_id, "metadata[device_id]": input.device_id,
        "subscription_data[metadata][pending_account_id]": input.pending_account_id,
        "subscription_data[metadata][org_id]": input.org_id,
      });
      let result: Response;
      try {
        result = await fetcher("https://api.stripe.com/v1/checkout/sessions", {
          method: "POST", headers: {
            Authorization: `Bearer ${secretKey}`,
            "Content-Type": "application/x-www-form-urlencoded",
            "Idempotency-Key": input.idempotency_key,
          }, body: form,
        });
      } catch { throw new SignupDenialV1("CHECKOUT_UNAVAILABLE"); }
      if (!result.ok) throw new SignupDenialV1("CHECKOUT_UNAVAILABLE");
      let body: unknown;
      try { body = await result.json(); } catch { throw new SignupDenialV1("CHECKOUT_UNAVAILABLE"); }
      if (!isRecord(body) || typeof body.id !== "string" || !/^cs_test_[A-Za-z0-9_]+$/.test(body.id)
          || typeof body.url !== "string" || !/^https:\/\/checkout\.stripe\.com\//.test(body.url)) {
        throw new SignupDenialV1("CHECKOUT_UNAVAILABLE");
      }
      return Object.freeze({ session_id: body.id, checkout_url: body.url });
    },
    async getSubscriptionDetails(subscriptionId: string) {
      if (!/^sub_[A-Za-z0-9_]+$/.test(subscriptionId)) {
        throw new SignupDenialV1("EVENT_NOT_ALLOWED");
      }
      let result: Response;
      try {
        result = await fetcher(`https://api.stripe.com/v1/subscriptions/${encodeURIComponent(subscriptionId)}`, {
          method: "GET", headers: { Authorization: `Bearer ${secretKey}` },
        });
      } catch { throw new SignupDenialV1("LEDGER_UNAVAILABLE"); }
      if (!result.ok) throw new SignupDenialV1("LEDGER_UNAVAILABLE");
      let body: unknown;
      try { body = await result.json(); } catch { throw new SignupDenialV1("LEDGER_UNAVAILABLE"); }
      if (!isRecord(body) || body.id !== subscriptionId || typeof body.customer !== "string"
          || typeof body.status !== "string" || typeof body.current_period_start !== "number"
          || typeof body.current_period_end !== "number" || !isRecord(body.metadata)) {
        throw new SignupDenialV1("LEDGER_UNAVAILABLE");
      }
      return Object.freeze({ id: subscriptionId, customer_id: body.customer, status: body.status,
        current_period_start: body.current_period_start, current_period_end: body.current_period_end,
        metadata: Object.freeze({ ...body.metadata }) });
    },
  });
}
