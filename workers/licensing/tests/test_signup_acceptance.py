from __future__ import annotations

import json
import os
import shutil
import subprocess
import uuid
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
FIXTURES = PACKAGE / "tests" / "fixtures" / "signup"

FORBIDDEN_TERMS = ("trial" + "_period_days", "TR" + "IAL")

VITEST_SOURCE = r"""
import { afterAll, describe, expect, it, vi } from "vitest";
import { readFileSync } from "node:fs";
import { createStripeTestPortV1 } from "../src/signup/handler.js";
import type {
  NormalizedStripeEventV1,
  SignupDependenciesV1,
  StripeCheckoutInputV1,
} from "../src/signup/models.js";
import { signupRoutes } from "../src/signup/routes.js";

const NOW = 1_800_000_000;
const WEBHOOK_SECRET = "whsec_synthetic_acceptance_001";
const STRIPE_SECRET = "sk_test_synthetic_acceptance_001";
const forbiddenTerms = ["trial" + "_period_days", ["TR", "IAL"].join("")];
const responseTexts: string[] = [];
const logSpies = [
  vi.spyOn(console, "log").mockImplementation(() => undefined),
  vi.spyOn(console, "info").mockImplementation(() => undefined),
  vi.spyOn(console, "warn").mockImplementation(() => undefined),
  vi.spyOn(console, "error").mockImplementation(() => undefined),
  vi.spyOn(console, "debug").mockImplementation(() => undefined),
];
const actualFetch = vi.fn(async () => { throw new Error("unexpected real network call"); });
vi.stubGlobal("fetch", actualFetch);

function fixture(name: string): string {
  return readFileSync(new URL(`../tests/fixtures/signup/${name}`, import.meta.url), "utf8");
}

function assertNoTrial(value: string): void {
  for (const token of forbiddenTerms) {
    expect(value.toLowerCase()).not.toContain(token.toLowerCase());
  }
}

async function body(response: Response): Promise<Record<string, unknown>> {
  const text = await response.text();
  responseTexts.push(text);
  return JSON.parse(text) as Record<string, unknown>;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function signature(raw: string, secret = WEBHOOK_SECRET, timestamp = NOW): Promise<string> {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signed = new TextEncoder().encode(`${timestamp}.${raw}`);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, signed));
  return `t=${timestamp},v1=${toHex(mac)}`;
}

async function webhook(raw: string, signatureHeader?: string): Promise<Request> {
  return new Request("https://worker.example/v1/signup/webhook", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(signatureHeader ? { "Stripe-Signature": signatureHeader } : {}),
    },
    body: raw,
  });
}

async function signedWebhook(
  raw: string, secret = WEBHOOK_SECRET, timestamp = NOW,
): Promise<Request> {
  return webhook(raw, await signature(raw, secret, timestamp));
}

function failure(code: string): (error: unknown) => boolean {
  return (error) => error instanceof Error && "code" in error
    && (error as Error & { code: string }).code === code;
}

function harness() {
  let requestNumber = 0;
  const calls: {
    pending: unknown[];
    checkout: StripeCheckoutInputV1[];
    attempted: NormalizedStripeEventV1[];
    committed: string[];
    subscriptions: Map<string, { status: string }>;
    audits: string[];
  } = {
    pending: [], checkout: [], attempted: [], committed: [],
    subscriptions: new Map(), audits: [],
  };
  const acceptedIds = new Set<string>();
  const lastCreated = new Map<string, bigint>();
  const deps: SignupDependenciesV1 = {
    clock: { nowUtcNs: () => "1800000000000000000", nowUnixSeconds: () => NOW },
    request_id: () => `req_signup_${++requestNumber}`,
    config: {
      stripe_mode: "test",
      stripe_price_id: "price_synthetic_monthly",
      stripe_webhook_secret: WEBHOOK_SECRET,
      success_url: "https://product.example.test/signup/success",
      cancel_url: "https://product.example.test/signup/cancel",
    },
    pending_signups: {
      async createPending(input) {
        calls.pending.push(structuredClone(input));
        return {
          resource_id: "pending_001", org_id: "org_001", device_id: input.device_id,
          resource_version: "1", audit_id: "audit_pending_001",
        };
      },
    },
    stripe: {
      async createCheckoutSession(input) {
        calls.checkout.push(structuredClone(input));
        return {
          session_id: "cs_test_session_001",
          checkout_url: "https://checkout.stripe.com/c/pay/cs_test_session_001",
        };
      },
    },
    webhook_transactions: {
      async applyVerifiedEvent(event) {
        calls.attempted.push(event);
        if (event.org_id !== "org_001" || event.pending_account_id !== "pending_001") {
          throw Object.assign(
            new Error("synthetic account mismatch detail"), { code: "ACCOUNT_MISMATCH" },
          );
        }
        if (acceptedIds.has(event.event_id)) {
          throw Object.assign(new Error("synthetic duplicate detail"), { code: "EVENT_REPLAY" });
        }
        const created = BigInt(event.event_created_utc_ns);
        const prior = lastCreated.get(event.subscription_id);
        if (prior !== undefined && created < prior) {
          throw Object.assign(
            new Error("synthetic ordering detail"), { code: "EVENT_OUT_OF_ORDER" },
          );
        }
        acceptedIds.add(event.event_id);
        lastCreated.set(event.subscription_id, created);
        calls.committed.push(event.event_id);
        if (!calls.subscriptions.has(event.subscription_id)) {
          calls.subscriptions.set(event.subscription_id, { status: event.status });
          calls.audits.push(`audit_${event.subscription_id}`);
        } else {
          calls.subscriptions.set(event.subscription_id, { status: event.status });
        }
        return {
          resource_id: event.subscription_id,
          resource_version: String(calls.committed.length),
          audit_id: `audit_${event.subscription_id}`,
        };
      },
    },
  };
  return { deps, calls };
}

afterAll(() => {
  const output = [
    ...responseTexts,
    ...logSpies.flatMap((spy) => spy.mock.calls.flatMap((args) => args.map(String))),
  ].join("\n");
  expect(output).not.toContain(STRIPE_SECRET);
  expect(output).not.toContain(WEBHOOK_SECRET);
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("SIGNUP-001 independent acceptance", () => {
  it("creates a test Checkout Session for a pending, unentitled account", async () => {
    const { deps, calls } = harness();
    const input = {
      org_name: "Synthetic Research Group",
      owner_email: "Owner@Example.test",
      device_id: "device_001",
      idempotency_key: "idem_checkout_001",
    };
    const requestBody = JSON.stringify(input);
    assertNoTrial(requestBody);
    const response = await signupRoutes(new Request("https://worker.example/v1/signup/checkout", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: requestBody,
    }), deps);
    expect(response?.status).toBe(201);
    const result = await body(response!);
    expect(result).toMatchObject({
      schema_version: 1, request_id: "req_signup_1", observed_at_ns: "1800000000000000000",
      audit_id: "audit_pending_001",
      data: {
        resource_id: "pending_001", resource_version: "1",
        checkout_session_id: "cs_test_session_001",
      },
    });
    const data = result.data as Record<string, unknown>;
    expect(data.checkout_url).toMatch(/^https:\/\/checkout\.stripe\.com\//);
    expect(calls.pending).toHaveLength(1);
    expect(calls.checkout).toHaveLength(1);
    expect(calls.subscriptions.size).toBe(0);
    assertNoTrial(JSON.stringify(calls.checkout));
  });

  it(
    "accepts paid Checkout and invoice events once, then ignores duplicate delivery",
    async () => {
    const { deps, calls } = harness();
    const checkoutRaw = fixture("checkout.session.completed.json");
    const invoiceRaw = fixture("invoice.paid.json");
    assertNoTrial(checkoutRaw);
    assertNoTrial(invoiceRaw);

    const checkoutResponse = await signupRoutes(await signedWebhook(checkoutRaw), deps);
    expect(checkoutResponse?.status).toBe(200);
    expect(await body(checkoutResponse!)).toMatchObject({
      schema_version: 1, audit_id: "audit_sub_test_001",
      data: { resource_id: "sub_test_001", resource_version: "1" },
    });

    const invoiceResponse = await signupRoutes(await signedWebhook(invoiceRaw), deps);
    expect(invoiceResponse?.status).toBe(200);
    expect(await body(invoiceResponse!)).toMatchObject({
      schema_version: 1, audit_id: "audit_sub_test_001",
      data: { resource_id: "sub_test_001", resource_version: "2" },
    });
    expect(calls.subscriptions.size).toBe(1);
    expect([...calls.subscriptions.values()]).toEqual([{ status: "ACTIVE" }]);
    expect(calls.audits).toEqual(["audit_sub_test_001"]);
    expect(calls.committed).toEqual(["evt_checkout_001", "evt_invoice_paid_001"]);

    const beforeDuplicate = {
      committed: calls.committed.length,
      subscriptions: calls.subscriptions.size,
      audits: calls.audits.length,
    };
    const duplicateResponse = await signupRoutes(await signedWebhook(invoiceRaw), deps);
    expect(duplicateResponse?.status).toBe(409);
    expect(await body(duplicateResponse!)).toMatchObject({ error: { code: "EVENT_REPLAY" } });
    expect({
      committed: calls.committed.length,
      subscriptions: calls.subscriptions.size,
      audits: calls.audits.length,
    }).toEqual(beforeDuplicate);
  });

  it(
    "denies wrong secret, modified payload, and timestamps outside tolerance",
    async () => {
    const { deps, calls } = harness();
    const raw = fixture("checkout.session.completed.json");

    const wrongSecret = await signupRoutes(
      await signedWebhook(raw, "whsec_wrong_synthetic_secret_001"), deps,
    );
    expect(wrongSecret?.status).toBe(400);
    expect(await body(wrongSecret!)).toMatchObject({ error: { code: "INVALID_SIGNATURE" } });

    const changed = JSON.parse(raw) as Record<string, any>;
    changed.data.object.payment_status = "no_payment_required";
    const tamperedRaw = JSON.stringify(changed);
    const tampered = await signupRoutes(await webhook(tamperedRaw,
      await signature(raw)), deps);
    expect(tampered?.status).toBe(400);
    expect(await body(tampered!)).toMatchObject({ error: { code: "INVALID_SIGNATURE" } });

    for (const timestamp of [NOW - 301, NOW + 301]) {
      const outside = await signupRoutes(await signedWebhook(raw, WEBHOOK_SECRET, timestamp), deps);
      expect(outside?.status).toBe(400);
      expect(await body(outside!)).toMatchObject({ error: { code: "INVALID_SIGNATURE" } });
    }
    expect(calls.committed).toHaveLength(0);
    expect(calls.subscriptions.size).toBe(0);
    expect(calls.audits).toHaveLength(0);
  });

  it("types unknown-event and account-binding denials and performs no writes", async () => {
    const { deps, calls } = harness();
    const unknownRaw = fixture("unknown.event.json");
    const unknown = await signupRoutes(await signedWebhook(unknownRaw), deps);
    expect(unknown?.status).toBe(422);
    expect(await body(unknown!)).toMatchObject({ error: { code: "EVENT_NOT_ALLOWED" } });

    const mismatchRaw = fixture("account.mismatch.json");
    const mismatch = await signupRoutes(await signedWebhook(mismatchRaw), deps);
    expect(mismatch?.status).toBe(409);
    expect(await body(mismatch!)).toMatchObject({ error: { code: "ACCOUNT_MISMATCH" } });
    expect(calls.committed).toHaveLength(0);
    expect(calls.subscriptions.size).toBe(0);
    expect(calls.audits).toHaveLength(0);
  });

  it("redacts provider failures that contain Stripe credentials", async () => {
    const { deps: base, calls } = harness();
    const deps: SignupDependenciesV1 = {
      ...base,
      stripe: {
        async createCheckoutSession() {
          throw new Error(`provider diagnostic ${STRIPE_SECRET} ${WEBHOOK_SECRET}`);
        },
      },
    };
    const response = await signupRoutes(new Request("https://worker.example/v1/signup/checkout", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        org_name: "Synthetic Group", owner_email: "owner@example.test",
        device_id: "device_001", idempotency_key: "idem_checkout_redaction",
      }),
    }), deps);
    expect(response?.status).toBe(503);
    const result = await body(response!);
    expect(result).toMatchObject({ error: { code: "CHECKOUT_UNAVAILABLE" } });
    expect(JSON.stringify(result)).not.toContain(STRIPE_SECRET);
    expect(JSON.stringify(result)).not.toContain(WEBHOOK_SECRET);
    expect(calls.subscriptions.size).toBe(0);
    expect(calls.audits).toHaveLength(0);
  });

  it(
    "uses only an injected fake Stripe fetch and accepts only test-mode checkout IDs",
    async () => {
    const fakeFetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      expect(String(input)).toBe("https://api.stripe.com/v1/checkout/sessions");
      expect(init?.method).toBe("POST");
      expect(new Headers(init?.headers).get("Authorization")).toBe(`Bearer ${STRIPE_SECRET}`);
      const formText = String(init?.body);
      assertNoTrial(formText);
      const form = new URLSearchParams(formText);
      expect(form.get("mode")).toBe("subscription");
      expect(form.get("line_items[0][price]")).toBe("price_synthetic_monthly");
      return Response.json({
        id: "cs_test_fake_001",
        url: "https://checkout.stripe.com/c/pay/cs_test_fake_001",
      });
    });
    const port = createStripeTestPortV1(STRIPE_SECRET, fakeFetch);
    const result = await port.createCheckoutSession({
      pending_account_id: "pending_001", org_id: "org_001",
      org_name: "Synthetic Research Group", owner_email: "owner@example.test",
      device_id: "device_001", idempotency_key: "idem_checkout_001",
      price_id: "price_synthetic_monthly",
      success_url: "https://product.example.test/success",
      cancel_url: "https://product.example.test/cancel",
    });
    expect(result.session_id).toMatch(/^cs_test_/);
    expect(fakeFetch).toHaveBeenCalledTimes(1);
    expect(actualFetch).not.toHaveBeenCalled();
    expect(() => createStripeTestPortV1("sk_live_synthetic_disabled_001", fakeFetch))
      .toThrow();
  });
});
"""


def test_signup_acceptance_through_pinned_vitest() -> None:
    """Exercise the Worker route boundary with synthetic Stripe events and fake ports."""
    package_json = json.loads((PACKAGE / "package.json").read_text(encoding="utf-8"))
    assert package_json["devDependencies"]["vitest"] == "4.1.11"
    assert (PACKAGE / "node_modules" / "vitest" / "vitest.mjs").is_file()
    assert (PACKAGE / "src" / "signup" / "routes.ts").is_file()

    fixture_files = sorted(FIXTURES.glob("*.json"))
    assert {path.name for path in fixture_files} == {
        "account.mismatch.json",
        "checkout.session.completed.json",
        "invoice.paid.json",
        "unknown.event.json",
    }
    for path in fixture_files:
        content = path.read_text(encoding="utf-8")
        json.loads(content)
        folded = content.lower()
        assert all(term.lower() not in folded for term in FORBIDDEN_TERMS), path.name

    generated_dir = PACKAGE / f"signup_acceptance_{os.getpid()}_{uuid.uuid4().hex}"
    generated_dir.mkdir()
    generated = generated_dir / "signup_acceptance_generated.test.ts"
    generated.write_text(VITEST_SOURCE, encoding="utf-8")
    config = generated_dir / "vitest.acceptance.config.ts"
    generated_include = json.dumps(generated.relative_to(PACKAGE).as_posix())
    config.write_text(
        f'import {{ defineConfig }} from "vitest/config";\n'
        f"export default defineConfig({{ root: {json.dumps(str(PACKAGE))}, "
        f'test: {{ include: [{generated_include}], environment: "node" }} }});\n',
        encoding="utf-8",
    )
    try:
        result = subprocess.run(
            [
                "node",
                "node_modules/vitest/vitest.mjs",
                "run",
                "--config",
                str(config),
            ],
            cwd=PACKAGE,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=180,
            check=False,
        )
    finally:
        shutil.rmtree(generated_dir, ignore_errors=True)

    assert result.returncode == 0, (
        f"Vitest acceptance failed. stdout={result.stdout} stderr={result.stderr}"
    )
    assert "Test Files" in result.stdout and "Tests" in result.stdout
    assert "sk_test_synthetic_acceptance_001" not in result.stdout + result.stderr
    assert "whsec_synthetic_acceptance_001" not in result.stdout + result.stderr
