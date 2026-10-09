import { describe, expect, it, vi } from "vitest";
import { createStripeTestPortV1 } from "../src/signup/handler.js";
import type { SignupDependenciesV1, NormalizedStripeEventV1 } from "../src/signup/models.js";
import { signupRoutes } from "../src/signup/routes.js";

const NOW_SECONDS = 1_800_000_000;
const SECRET = "whsec_test_secret_123456789";

function deps(overrides: Partial<SignupDependenciesV1> = {}) {
  const calls: { pending: unknown[]; stripe: unknown[]; events: NormalizedStripeEventV1[] } = {
    pending: [], stripe: [], events: [],
  };
  const base: SignupDependenciesV1 = {
    clock: { nowUtcNs: () => "1800000000000000000", nowUnixSeconds: () => NOW_SECONDS },
    request_id: () => "req_signup_001",
    config: { stripe_mode: "test", stripe_price_id: "price_test_monthly", stripe_webhook_secret: SECRET,
      success_url: "https://product.example/success", cancel_url: "https://product.example/cancel" },
    pending_signups: { async createPending(input) {
      calls.pending.push(input);
      return { resource_id: "pending_1", org_id: "org_1", device_id: input.device_id,
        resource_version: "1", audit_id: "audit_pending_1" };
    } },
    stripe: {
      async createCheckoutSession(input) {
        calls.stripe.push(input);
        return { session_id: "cs_test_session_1", checkout_url: "https://checkout.stripe.com/c/pay/cs_test_session_1" };
      },
      async getSubscriptionDetails(id) {
        return { id, customer_id: "cus_1", status: "active", current_period_start: NOW_SECONDS,
          current_period_end: NOW_SECONDS + 30 * 86400,
          metadata: { pending_account_id: "pending_1", org_id: "org_1" } };
      },
    },
    webhook_transactions: { async applyVerifiedEvent(event) {
      calls.events.push(event);
      return { resource_id: "sub_internal_1", resource_version: "1", audit_id: "audit_event_1" };
    } },
  };
  return { deps: { ...base, ...overrides }, calls };
}

async function signedRequest(path: string, value: unknown, secret = SECRET, timestamp = NOW_SECONDS) {
  const payload = JSON.stringify(value);
  const signed = new TextEncoder().encode(`${timestamp}.${payload}`);
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signature = new Uint8Array(await crypto.subtle.sign("HMAC", key, signed));
  const hex = Array.from(signature, (byte) => byte.toString(16).padStart(2, "0")).join("");
  return new Request(`https://worker.example${path}`, { method: "POST", body: payload,
    headers: { "Stripe-Signature": `t=${timestamp},v1=${hex}` } });
}

function completedSession(overrides: Record<string, unknown> = {}) {
  return {
    id: "evt_checkout_1", type: "checkout.session.completed", created: NOW_SECONDS, livemode: false,
    data: { object: { id: "cs_test_1", client_reference_id: "pending_1", customer: "cus_1",
      subscription: "sub_1", payment_status: "paid", metadata: { org_id: "org_1" }, ...overrides } },
  };
}

describe("SIGNUP-001 standalone routes", () => {
  it("creates an unentitled pending signup and test checkout with shared mutation envelope", async () => {
    const { deps: dependencies, calls } = deps();
    const response = await signupRoutes(new Request("https://worker.example/v1/signup/checkout", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ org_name: "Acme", owner_email: "Owner@Example.com",
        device_id: "device_1", idempotency_key: "checkout_key_1" }),
    }), dependencies);
    expect(response?.status).toBe(201);
    const body = await response!.json();
    expect(body).toMatchObject({ schema_version: 1, request_id: "req_signup_001",
      audit_id: "audit_pending_1", data: { resource_id: "pending_1", resource_version: "1",
        checkout_session_id: "cs_test_session_1" } });
    expect(body.data.checkout_url).toMatch(/^https:\/\/checkout\.stripe\.com\//);
    expect(calls.pending).toHaveLength(1);
    expect(calls.stripe).toHaveLength(1);
    expect(calls.pending[0]).toMatchObject({ owner_email: "owner@example.com", org_name: "Acme" });
  });

  it("rejects malformed checkout input before any pending or provider write", async () => {
    const { deps: dependencies, calls } = deps();
    const response = await signupRoutes(new Request("https://worker.example/v1/signup/checkout", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: "{}",
    }), dependencies);
    expect(response?.status).toBe(400);
    expect(await response!.json()).toMatchObject({ error: { code: "INVALID_REQUEST" } });
    expect(calls.pending).toHaveLength(0);
    expect(calls.stripe).toHaveLength(0);
  });

  it("returns null for paths not owned by the standalone signup router", async () => {
    const { deps: dependencies } = deps();
    expect(await signupRoutes(new Request("https://worker.example/v1/admin/accounts"), dependencies)).toBeNull();
  });

  it("returns a fixed typed denial for owned routes when dependencies are not configured", async () => {
    const response = await signupRoutes(new Request("https://worker.example/v1/signup/checkout", {
      method: "POST",
    }));
    expect(response?.status).toBe(503);
    expect(await response!.json()).toEqual({ schema_version: 1, request_id: "not-configured",
      observed_at_ns: "0", error: { code: "NOT_CONFIGURED", message: "Request could not be completed." } });
  });

  it("uses a test secret, sends Stripe REST form data and refuses live keys", async () => {
    const fetcher = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      expect(new Headers(init?.headers).get("Authorization")).toBe("Bearer sk_test_abcdefgh12345678");
      expect(new Headers(init?.headers).get("Idempotency-Key")).toBe("idem_1");
      const form = new URLSearchParams(String(init?.body));
      expect(form.get("mode")).toBe("subscription");
      expect(form.get("line_items[0][price]")).toBe("price_1");
      return Response.json({ id: "cs_test_123", url: "https://checkout.stripe.com/c/pay/cs_test_123" });
    });
    const port = createStripeTestPortV1("sk_test_abcdefgh12345678", fetcher);
    await expect(port.createCheckoutSession({ pending_account_id: "pending_1", org_id: "org_1",
      org_name: "Acme", owner_email: "owner@example.com", device_id: "device_1",
      idempotency_key: "idem_1", price_id: "price_1", success_url: "https://a.test/success",
      cancel_url: "https://a.test/cancel" })).resolves.toEqual({ session_id: "cs_test_123",
        checkout_url: "https://checkout.stripe.com/c/pay/cs_test_123" });
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(() => createStripeTestPortV1("sk_live_abcdefgh12345678", fetcher)).toThrow();
  });

  it("verifies a signed paid checkout event and applies a normalized ACTIVE ledger event", async () => {
    const { deps: dependencies, calls } = deps();
    const request = await signedRequest("/v1/signup/webhook", completedSession());
    const response = await signupRoutes(request, dependencies);
    expect(response?.status).toBe(200);
    expect(await response!.json()).toMatchObject({ audit_id: "audit_event_1",
      data: { resource_id: "sub_internal_1", resource_version: "1" } });
    expect(calls.events).toHaveLength(1);
    expect(calls.events[0]).toMatchObject({ event_type: "checkout.session.completed",
      status: "ACTIVE", pending_account_id: "pending_1", org_id: "org_1",
      subscription_id: "sub_1", customer_id: "cus_1" });
  });

  it("binds signed webhook livemode to the configured Stripe key mode before ledger writes", async () => {
    const audit = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    try {
      const test = deps();
      const liveEvent = await signedRequest("/v1/signup/webhook", { ...completedSession(), livemode: true });
      const testResponse = await signupRoutes(liveEvent, test.deps);
      expect(testResponse?.status).toBe(422);
      expect(await testResponse!.json()).toMatchObject({ error: { code: "STRIPE_MODE_MISMATCH" } });
      expect(test.calls.events).toHaveLength(0);

      const liveDependencies: SignupDependenciesV1 = {
        ...test.deps, config: { ...test.deps.config, stripe_mode: "live" },
      };
      const acceptedLive = await signedRequest("/v1/signup/webhook", { ...completedSession(), livemode: true });
      expect((await signupRoutes(acceptedLive, liveDependencies))?.status).toBe(200);
      const rejectedTest = await signedRequest("/v1/signup/webhook", completedSession());
      const rejected = await signupRoutes(rejectedTest, liveDependencies);
      expect(rejected?.status).toBe(422);
      expect(await rejected!.json()).toMatchObject({ error: { code: "STRIPE_MODE_MISMATCH" } });
      expect(test.calls.events).toHaveLength(1);
      expect(audit).toHaveBeenCalledTimes(2);
      expect(audit).toHaveBeenNthCalledWith(1, "STRIPE_MODE_MISMATCH");
      expect(audit).toHaveBeenNthCalledWith(2, "STRIPE_MODE_MISMATCH");
    } finally { audit.mockRestore(); }
  });

  it("rejects bad signatures, stale signed requests and unknown events before any ledger writes", async () => {
    const { deps: dependencies, calls } = deps();
    const unsigned = new Request("https://worker.example/v1/signup/webhook", {
      method: "POST", body: JSON.stringify(completedSession()),
    });
    expect((await signupRoutes(unsigned, dependencies))?.status).toBe(400);
    const stale = await signedRequest("/v1/signup/webhook", completedSession(), SECRET, NOW_SECONDS - 301);
    expect((await signupRoutes(stale, dependencies))?.status).toBe(400);
    const unknown = await signedRequest("/v1/signup/webhook", { ...completedSession(),
      type: "customer.created" });
    const unknownResponse = await signupRoutes(unknown, dependencies);
    expect(unknownResponse?.status).toBe(422);
    expect(await unknownResponse!.json()).toMatchObject({ error: { code: "EVENT_NOT_ALLOWED" } });
    expect(calls.events).toHaveLength(0);
  });

  it("maps subscription status events and gives typed replay/order denials", async () => {
    const seen: NormalizedStripeEventV1[] = [];
    const { deps: base } = deps();
    const dependencies: SignupDependenciesV1 = { ...base, webhook_transactions: {
      async applyVerifiedEvent(event) {
        seen.push(event);
        if (event.event_id === "evt_duplicate") throw Object.assign(new Error(), { code: "EVENT_REPLAY" });
        if (event.event_id === "evt_stale") throw Object.assign(new Error(), { code: "EVENT_STALE" });
        return { resource_id: "sub_internal_1", resource_version: "2", audit_id: "audit_event_2" };
      },
    } };
    const update = (eventId: string, status: string) => ({ id: eventId,
      type: "customer.subscription.updated", created: NOW_SECONDS, livemode: false,
      data: { object: { id: "sub_1", customer: "cus_1", status,
        current_period_start: NOW_SECONDS, current_period_end: NOW_SECONDS + 86400,
        metadata: { pending_account_id: "pending_1", org_id: "org_1" } } },
    });
    const pastDue = await signedRequest("/v1/signup/webhook", update("evt_update", "past_due"));
    expect((await signupRoutes(pastDue, dependencies))?.status).toBe(200);
    expect(seen[0]?.status).toBe("PAST_DUE");
    for (const [eventId, code] of [["evt_duplicate", "EVENT_REPLAY"], ["evt_stale", "EVENT_OUT_OF_ORDER"]]) {
      const req = await signedRequest("/v1/signup/webhook", update(eventId!, "active"));
      const response = await signupRoutes(req, dependencies);
      expect(response?.status).toBe(409);
      expect(await response!.json()).toMatchObject({ error: { code } });
    }
  });

  it("rejects account mismatch and unsupported provider status without exposing provider errors", async () => {
    const { deps: base, calls } = deps();
    const dependencies: SignupDependenciesV1 = { ...base, webhook_transactions: {
      async applyVerifiedEvent(event) {
        if (event.org_id !== "org_1") throw Object.assign(new Error(), { code: "ACCOUNT_MISMATCH" });
        calls.events.push(event);
        return { resource_id: "sub_internal_1", resource_version: "1", audit_id: "audit_event_1" };
      },
    } };
    const mismatch = await signedRequest("/v1/signup/webhook", completedSession({
      metadata: { org_id: "different_org" },
    }));
    const mismatchResponse = await signupRoutes(mismatch, dependencies);
    expect(mismatchResponse?.status).toBe(409);
    expect(await mismatchResponse!.json()).toMatchObject({ error: { code: "ACCOUNT_MISMATCH" } });
    expect(calls.events).toHaveLength(0);
    const unsupported = await signedRequest("/v1/signup/webhook", {
      id: "evt_unsupported", type: "customer.subscription.updated", created: NOW_SECONDS,
      data: { object: { id: "sub_1", customer: "cus_1", status: "unknown_status",
        current_period_start: NOW_SECONDS, current_period_end: NOW_SECONDS + 86400,
        metadata: { pending_account_id: "pending_1", org_id: "org_1" } } },
    });
    const { deps: fresh, calls: freshCalls } = deps();
    const unsupportedResponse = await signupRoutes(unsupported, fresh);
    expect(unsupportedResponse?.status).toBe(422);
    expect(await unsupportedResponse!.text()).not.toContain("unknown_status");
    expect(freshCalls.events).toHaveLength(0);
  });
});
