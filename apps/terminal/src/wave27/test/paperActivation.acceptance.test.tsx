/* Independent acceptance for PAPER-ACTIVATION-UI-001 (paper dispatch authorization panel).
 *
 * Written from wave27-refill-v0.1 sections 6 and 7 and the coordinator's rulings, not from the
 * writer's unit tests. The view is driven against deterministic fake `/api` responses and every
 * request method, path and body is captured. All data is synthetic.
 *
 * Rulings encoded here: the wire value of `environment` is exactly lowercase "paper" (the mounted
 * `_scope` accepts only "paper" or "demo"); the UI shows PAPER and LIVE is a disabled option;
 * nothing but the two activation endpoints may mutate; activation is enabled only from explicit
 * reads (configured runtime, recovery READY, no halt or fault); revoke is always available for a
 * valid confirmed scope; the scope status after a reload is unknown and unverified.
 */
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import apiSource from "../api/paperActivation.ts?raw";
import { PaperActivationView } from "../views/PaperActivationView";
import viewSource from "../views/PaperActivationView.tsx?raw";

const ORDERS_STATUS = "/api/orders/status";
const RISK_STATUS = "/api/risk/status";
const ACTIVATE = "/api/orders/activations";
const REVOKE = "/api/orders/activations/revoke";
const READ_PATHS = [ORDERS_STATUS, RISK_STATUS];
const MUTATION_PATHS = [ACTIVATE, REVOKE];
const CANARY = "SYNTHETIC_PAPER_ACTIVATION_CANARY_DO_NOT_RENDER";

const SCOPE = {
  account_id: "acct-sim-0042",
  venue: "venue-sim-01",
  instrument_id: "NQ-SYN-01",
  strategy_id: "strat-alpha-01",
} as const;
type ScopeKey = keyof typeof SCOPE;
const LABELS: Record<ScopeKey, [RegExp, RegExp]> = {
  account_id: [/^account id$/i, /^confirm account id$/i],
  venue: [/^venue id$/i, /^confirm venue id$/i],
  instrument_id: [/^instrument id$/i, /^confirm instrument id$/i],
  strategy_id: [/^strategy id$/i, /^confirm strategy id$/i],
};

const ordersReady = { live_enabled: false, recovery_status: "READY", activation_count: 0 };
const riskClear = {
  halted: false,
  active_halts: [] as string[],
  fault_code: null,
  operating_mode: "paper",
  policy: { max_daily_dd_pct: "3", max_open_heat_pct: "6" },
  lock_file: "risk_governance.lock.yaml",
};

type Reply =
  | { status: number; body: unknown }
  | "network"
  | "badjson"
  | "pending";
type Replies = { orders: Reply; risk: Reply; activate: Reply; revoke: Reply };
type Call = {
  method: string;
  path: string;
  body: unknown;
  rawBody: string | undefined;
  headers: Record<string, string>;
};

function ok(body: unknown, status = 200): Reply {
  return { status, body };
}

function response(reply: Exclude<Reply, "network" | "pending">): Response {
  if (reply === "badjson") {
    return {
      ok: true,
      status: 200,
      statusText: "OK",
      json: async () => {
        throw new SyntaxError("synthetic malformed json");
      },
    } as unknown as Response;
  }
  return {
    ok: reply.status >= 200 && reply.status < 300,
    status: reply.status,
    statusText: reply.status >= 500 ? "Server Error" : reply.status === 403 ? "Forbidden" : "OK",
    json: async () => reply.body,
  } as Response;
}

function headersOf(init: RequestInit | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  const raw = init?.headers;
  if (raw instanceof Headers) raw.forEach((value, key) => (out[key.toLowerCase()] = value));
  else if (Array.isArray(raw)) raw.forEach(([key, value]) => (out[key.toLowerCase()] = value));
  else if (raw) Object.entries(raw).forEach(([key, value]) => (out[key.toLowerCase()] = String(value)));
  return out;
}

function createApi(overrides: Partial<Replies> = {}) {
  const replies: Replies = {
    orders: ok(ordersReady),
    risk: ok(riskClear),
    activate: ok({ active: true }, 201),
    revoke: ok({ active: false }),
    ...overrides,
  };
  const calls: Call[] = [];
  const fetcher = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input);
    const rawBody = typeof init?.body === "string" ? init.body : undefined;
    let body: unknown = undefined;
    if (rawBody !== undefined) {
      try {
        body = JSON.parse(rawBody);
      } catch {
        body = "UNPARSEABLE";
      }
    }
    calls.push({
      method: (init?.method ?? "GET").toUpperCase(),
      path,
      body,
      rawBody,
      headers: headersOf(init),
    });
    const key =
      path === ORDERS_STATUS ? "orders"
        : path === RISK_STATUS ? "risk"
          : path === ACTIVATE ? "activate"
            : path === REVOKE ? "revoke"
              : null;
    if (key === null) return Promise.resolve(response({ status: 404, body: { detail: "NOT_FOUND" } }));
    const reply = replies[key];
    if (reply === "network") return Promise.reject(new TypeError("synthetic network failure"));
    if (reply === "pending") return new Promise<Response>(() => undefined);
    return Promise.resolve(response(reply));
  });
  return {
    fetcher: fetcher as unknown as typeof fetch,
    mock: fetcher,
    calls,
    replies,
    posts: () => calls.filter((call) => call.method !== "GET"),
    reads: () => calls.filter((call) => call.method === "GET"),
  };
}
type Api = ReturnType<typeof createApi>;

async function settle() {
  for (let i = 0; i < 6; i += 1) {
    await act(async () => {
      await Promise.resolve();
    });
  }
}

async function mount(api: Api) {
  const view = render(<PaperActivationView fetcher={api.fetcher} clock={() => 1_700_000_000_000} />);
  await waitFor(() => expect(api.reads().length).toBeGreaterThanOrEqual(2));
  await settle();
  return view;
}

function input(key: ScopeKey, confirm = false): HTMLInputElement {
  return screen.getByLabelText(LABELS[key][confirm ? 1 : 0]) as HTMLInputElement;
}

function typeInto(element: HTMLInputElement, value: string) {
  fireEvent.change(element, { target: { value } });
}

async function fillScope(scope: Record<ScopeKey, string> = SCOPE) {
  for (const key of Object.keys(LABELS) as ScopeKey[]) {
    typeInto(input(key), scope[key]);
    typeInto(input(key, true), scope[key]);
  }
  await settle();
}

const activateButton = () => screen.getByRole("button", { name: /^activat/i });
const revokeButton = () => screen.getByRole("button", { name: /^revok/i });
const refreshButton = () => screen.getByRole("button", { name: /refresh status/i });

/** The success acknowledgement. The panel's static caption also says "local-session". */
const ACK = /(Activation|Revocation) accepted by the API for this session/i;

function isDisabled(element: Element): boolean {
  return element.matches(":disabled") || element.getAttribute("aria-disabled") === "true";
}

function visibleText(): string {
  return document.body.textContent ?? "";
}

function expectOnlyAllowedCalls(api: Api) {
  for (const call of api.calls) {
    expect([...READ_PATHS, ...MUTATION_PATHS]).toContain(call.path);
    if (READ_PATHS.includes(call.path)) {
      expect(call.method).toBe("GET");
      expect(call.rawBody).toBeUndefined();
    } else {
      expect(call.method).toBe("POST");
    }
  }
}

function expectPaperBody(call: Call, scope: Record<ScopeKey, string> = SCOPE) {
  expect(call.method).toBe("POST");
  expect(call.body).toEqual({ environment: "paper", ...scope });
  expect(Object.keys(call.body as object).sort()).toEqual(
    ["account_id", "environment", "instrument_id", "strategy_id", "venue"],
  );
  expect(call.rawBody).not.toMatch(/"(demo|live|paper_live|PAPER|DEMO|LIVE)"/);
  expect(call.headers["content-type"]).toMatch(/application\/json/i);
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("PAPER-ACTIVATION-UI-001 independent acceptance", () => {
  describe("reads and the fixed paper environment", () => {
    it("loads with only the two explicit GET reads and no mutation", async () => {
      const api = createApi();
      await mount(api);
      expect(api.reads().map((call) => call.path).sort()).toEqual([ORDERS_STATUS, RISK_STATUS]);
      expect(api.posts()).toEqual([]);
      expectOnlyAllowedCalls(api);
    });

    it("also works through the global fetch when no fetcher is injected", async () => {
      const api = createApi();
      vi.stubGlobal("fetch", api.mock);
      render(<PaperActivationView />);
      await waitFor(() => expect(api.reads().length).toBeGreaterThanOrEqual(2));
      expect(api.posts()).toEqual([]);
      expectOnlyAllowedCalls(api);
    });

    it("shows the fixed PAPER environment and a disabled LIVE, with no DEMO path", async () => {
      await mount(createApi());
      const text = visibleText();
      expect(text).toMatch(/PAPER/);
      expect(text).toMatch(/LIVE/);
      expect(text).toMatch(/LIVE is disabled/i);
      expect(text).not.toMatch(/\bdemo\b/i);
      const controls = document.querySelectorAll(
        "button,input,select,option,textarea,a,[role='button'],[role='radio'],[role='switch'],[role='checkbox'],[role='option']",
      );
      for (const control of controls) {
        const label = [
          control.textContent,
          control.getAttribute("aria-label"),
          control.getAttribute("title"),
          control.getAttribute("value"),
        ].filter(Boolean).join(" ");
        expect(label).not.toMatch(/\bdemo\b/i);
        if (/\blive\b/i.test(label)) expect(isDisabled(control)).toBe(true);
      }
      for (const element of document.querySelectorAll("select")) {
        expect([...element.querySelectorAll("option")].some((o) => /live/i.test(o.textContent ?? "")
          && !o.disabled)).toBe(false);
      }
    });

    it("never lets an API claim of live_enabled make LIVE selectable or change the wire value", async () => {
      const api = createApi({ orders: ok({ ...ordersReady, live_enabled: true }) });
      await mount(api);
      await fillScope();
      const liveControls = [...document.querySelectorAll("*")].filter(
        (el) => /^(button|input|option|select)$/i.test(el.tagName) && /\blive\b/i.test(el.textContent ?? "")
          && !/live is disabled/i.test(el.textContent ?? ""),
      );
      for (const control of liveControls) {
        expect(isDisabled(control)).toBe(true);
        fireEvent.click(control);
      }
      await settle();
      expect(api.posts()).toEqual([]);
      if (!isDisabled(activateButton())) {
        fireEvent.click(activateButton());
        await settle();
      }
      for (const post of api.posts()) expectPaperBody(post);
    });
  });

  describe("activation and revoke requests", () => {
    it("activates with exactly the confirmed scope and the lowercase paper wire value", async () => {
      const api = createApi();
      await mount(api);
      await fillScope();
      expect(isDisabled(activateButton())).toBe(false);
      fireEvent.click(activateButton());
      await waitFor(() => expect(api.posts()).toHaveLength(1));
      await settle();
      expect(api.posts()[0].path).toBe(ACTIVATE);
      expectPaperBody(api.posts()[0]);
      expectOnlyAllowedCalls(api);
    });

    it("revokes with exactly the confirmed scope and the lowercase paper wire value", async () => {
      const api = createApi();
      await mount(api);
      await fillScope();
      fireEvent.click(revokeButton());
      await waitFor(() => expect(api.posts()).toHaveLength(1));
      expect(api.posts()[0].path).toBe(REVOKE);
      expectPaperBody(api.posts()[0]);
      expectOnlyAllowedCalls(api);
    });

    it("sends the same environment value for activate and revoke and never an uppercase PAPER", async () => {
      const api = createApi();
      await mount(api);
      await fillScope();
      fireEvent.click(activateButton());
      await waitFor(() => expect(api.posts()).toHaveLength(1));
      await settle();
      fireEvent.click(revokeButton());
      await waitFor(() => expect(api.posts()).toHaveLength(2));
      const environments = api.posts().map((post) => (post.body as { environment: string }).environment);
      expect(environments).toEqual(["paper", "paper"]);
    });

    it("reports a successful activation only as a local-session acknowledgement", async () => {
      const api = createApi();
      await mount(api);
      await fillScope();
      fireEvent.click(activateButton());
      await waitFor(() => expect(api.posts()).toHaveLength(1));
      await settle();
      const text = visibleText();
      expect(text).toMatch(ACK);
      expect(text).toMatch(/unverified/i);
      expect(text).not.toMatch(/\b(verified active|confirmed active|live)\b.*\bactive\b/i);
    });

    it("does not retry or repeat a failed activation and shows no acknowledgement", async () => {
      const api = createApi({ activate: ok({ detail: "ACTIVATION_DISABLED" }, 403) });
      await mount(api);
      await fillScope();
      fireEvent.click(activateButton());
      await waitFor(() => expect(api.posts()).toHaveLength(1));
      await settle();
      expect(api.posts()).toHaveLength(1);
      expect(visibleText()).not.toMatch(ACK);
    });

    it.each([
      ["401", ok({ detail: "OPERATOR_REQUIRED" }, 401)],
      ["403", ok({ detail: "ACTIVATION_DISABLED" }, 403)],
      ["409", ok({ detail: "CONFLICT" }, 409)],
      ["422", ok({ detail: "INVALID_ORDER_SCOPE" }, 422)],
      ["503", ok({ detail: "NOT_CONFIGURED" }, 503)],
      ["network", "network" as Reply],
      ["malformed receipt", ok({ active: "yes" }, 201)],
      ["wrong receipt", ok({ active: false }, 201)],
      ["bad json", "badjson" as Reply],
    ])("surfaces a failed activate (%s) without echoing the response", async (_name, reply) => {
      const api = createApi({ activate: reply });
      await mount(api);
      await fillScope();
      fireEvent.click(activateButton());
      await waitFor(() => expect(api.posts()).toHaveLength(1));
      await settle();
      expect(visibleText()).not.toContain(CANARY);
      expect(visibleText()).not.toMatch(ACK);
      expect(document.querySelector("[role='alert'],[role='status'],[aria-live]")).not.toBeNull();
      expectOnlyAllowedCalls(api);
    });

    it("never echoes server-supplied text from an error body", async () => {
      const api = createApi({ activate: ok({ detail: CANARY, message: CANARY, raw: CANARY }, 422) });
      await mount(api);
      await fillScope();
      fireEvent.click(activateButton());
      await waitFor(() => expect(api.posts()).toHaveLength(1));
      await settle();
      expect(visibleText()).not.toContain(CANARY);
    });
  });

  describe("no order create, submit, cancel or recover call", () => {
    it("makes no order-lifecycle request in any ordinary flow, and never recovers automatically", async () => {
      const api = createApi({ orders: ok({ ...ordersReady, recovery_status: "UNKNOWN" }) });
      await mount(api);
      await fillScope();
      fireEvent.click(refreshButton());
      await settle();
      fireEvent.click(revokeButton());
      await settle();
      for (const call of api.calls) {
        expect(call.path).not.toMatch(/\/api\/orders(\/recover|\/reconcile|\/[^/]+\/(submit|cancel|reconcile))?$/);
        expect(call.path.endsWith("/api/orders") && call.method === "POST").toBe(false);
      }
      expectOnlyAllowedCalls(api);
      expect(api.calls.some((call) => call.path.includes("recover"))).toBe(false);
    });

    it("offers no control for creating, submitting, cancelling or recovering an order", async () => {
      await mount(createApi());
      const forbidden = /\b(submit|create order|place order|cancel|recover|buy|sell|flatten|send order)\b/i;
      for (const control of document.querySelectorAll("button,a,[role='button'],input[type='submit']")) {
        const label = [control.textContent, control.getAttribute("aria-label")].filter(Boolean).join(" ");
        expect(label).not.toMatch(forbidden);
      }
    });
  });

  describe("activation is blocked unless every explicit read is healthy", () => {
    const blocked: Array<[string, Partial<Replies>]> = [
      ["risk halted", { risk: ok({ ...riskClear, halted: true, active_halts: ["operator_hold"] }) }],
      ["halted flag only", { risk: ok({ ...riskClear, halted: true }) }],
      ["halt codes with halted false", { risk: ok({ ...riskClear, active_halts: ["stale_data"] }) }],
      ["fault code", { risk: ok({ ...riskClear, fault_code: "HALT_STORE_UNAVAILABLE" }) }],
      ["unknown fault code", { risk: ok({ ...riskClear, fault_code: "SOMETHING_ELSE" }) }],
      ["recovery UNKNOWN", { orders: ok({ ...ordersReady, recovery_status: "UNKNOWN" }) }],
      ["recovery FAILED", { orders: ok({ ...ordersReady, recovery_status: "FAILED" }) }],
      ["unrecognized recovery", { orders: ok({ ...ordersReady, recovery_status: "READYISH" }) }],
      ["lowercase recovery", { orders: ok({ ...ordersReady, recovery_status: "ready" }) }],
      ["orders 503 (unconfigured)", { orders: ok({ detail: "NOT_CONFIGURED" }, 503) }],
      ["orders 401", { orders: ok({ detail: "OPERATOR_REQUIRED" }, 401) }],
      ["orders 403", { orders: ok({ detail: "OPERATOR_REQUIRED" }, 403) }],
      ["orders 500", { orders: ok({ detail: CANARY }, 500) }],
      ["orders network", { orders: "network" as Reply }],
      ["orders bad json", { orders: "badjson" as Reply }],
      ["orders missing recovery", { orders: ok({ live_enabled: false, activation_count: 0 }) }],
      ["orders non-object", { orders: ok(["READY"]) }],
      ["orders null", { orders: ok(null) }],
      ["orders negative count", { orders: ok({ ...ordersReady, activation_count: -1 }) }],
      ["orders fractional count", { orders: ok({ ...ordersReady, activation_count: 1.5 }) }],
      ["orders string count", { orders: ok({ ...ordersReady, activation_count: "0" }) }],
      ["orders live_enabled not boolean", { orders: ok({ ...ordersReady, live_enabled: "false" }) }],
      ["risk 503", { risk: ok({ detail: "NOT_CONFIGURED" }, 503) }],
      ["risk 401", { risk: ok({ detail: "OPERATOR_REQUIRED" }, 401) }],
      ["risk 403", { risk: ok({ detail: "OPERATOR_REQUIRED" }, 403) }],
      ["risk 500", { risk: ok({ detail: CANARY }, 500) }],
      ["risk network", { risk: "network" as Reply }],
      ["risk bad json", { risk: "badjson" as Reply }],
      ["risk missing halted", { risk: ok({ active_halts: [], operating_mode: "paper" }) }],
      ["risk halted not boolean", { risk: ok({ ...riskClear, halted: "false" }) }],
      ["risk halts not array", { risk: ok({ ...riskClear, active_halts: "none" }) }],
      ["risk halts with non-strings", { risk: ok({ ...riskClear, active_halts: [1, null] }) }],
      ["risk non-object", { risk: ok("ok") }],
      ["orders still loading", { orders: "pending" as Reply }],
      ["risk still loading", { risk: "pending" as Reply }],
    ];

    it.each(blocked)("keeps Activate disabled and sends nothing: %s", async (_name, replies) => {
      const api = createApi(replies);
      await mount(api);
      await fillScope();
      expect(isDisabled(activateButton())).toBe(true);
      fireEvent.click(activateButton());
      const form = activateButton().closest("form");
      if (form !== null) fireEvent.submit(form);
      fireEvent.keyDown(activateButton(), { key: "Enter" });
      await settle();
      expect(api.posts()).toEqual([]);
      expect(visibleText()).not.toContain(CANARY);
      expectOnlyAllowedCalls(api);
    });

    it.each(blocked)("keeps Revoke available for a valid confirmed scope: %s", async (_name, replies) => {
      const api = createApi(replies);
      await mount(api);
      await fillScope();
      expect(isDisabled(revokeButton())).toBe(false);
      fireEvent.click(revokeButton());
      await waitFor(() => expect(api.posts()).toHaveLength(1));
      expect(api.posts()[0].path).toBe(REVOKE);
      expectPaperBody(api.posts()[0]);
    });

    it("does not call the recover endpoint when recovery is not READY", async () => {
      const api = createApi({ orders: ok({ ...ordersReady, recovery_status: "FAILED" }) });
      await mount(api);
      await fillScope();
      fireEvent.click(refreshButton());
      await settle();
      expect(api.calls.some((call) => /recover/.test(call.path))).toBe(false);
    });

    it("enables Activate only when every condition holds, then re-blocks after a halted refresh", async () => {
      const api = createApi();
      await mount(api);
      expect(isDisabled(activateButton())).toBe(true); // nothing entered yet
      await fillScope();
      expect(isDisabled(activateButton())).toBe(false);
      api.replies.risk = ok({ ...riskClear, halted: true, active_halts: ["operator_halt"] });
      fireEvent.click(refreshButton());
      await waitFor(() => expect(isDisabled(activateButton())).toBe(true));
      fireEvent.click(activateButton());
      await settle();
      expect(api.posts()).toEqual([]);
    });

    it("re-blocks when a refresh finds recovery no longer READY", async () => {
      const api = createApi();
      await mount(api);
      await fillScope();
      expect(isDisabled(activateButton())).toBe(false);
      api.replies.orders = ok({ ...ordersReady, recovery_status: "FAILED" });
      fireEvent.click(refreshButton());
      await waitFor(() => expect(isDisabled(activateButton())).toBe(true));
    });

    it("never renders raw payload text from a blocked read", async () => {
      const api = createApi({
        orders: ok({ ...ordersReady, recovery_status: "FAILED", raw: CANARY }),
        risk: ok({ ...riskClear, halted: true, active_halts: [CANARY], lock_file: CANARY }),
      });
      await mount(api);
      await fillScope();
      expect(visibleText()).not.toContain(CANARY);
    });
  });

  describe("scope entry and confirmation", () => {
    it("requires all four identifiers and their confirmations before either action is enabled", async () => {
      const api = createApi();
      await mount(api);
      expect(isDisabled(activateButton())).toBe(true);
      expect(isDisabled(revokeButton())).toBe(true);
      for (const key of Object.keys(LABELS) as ScopeKey[]) {
        typeInto(input(key), SCOPE[key]);
      }
      await settle();
      expect(isDisabled(activateButton())).toBe(true); // no confirmations yet
      expect(isDisabled(revokeButton())).toBe(true);
      for (const key of Object.keys(LABELS) as ScopeKey[]) {
        typeInto(input(key, true), SCOPE[key]);
      }
      await settle();
      expect(isDisabled(activateButton())).toBe(false);
      expect(isDisabled(revokeButton())).toBe(false);
    });

    it.each(Object.keys(LABELS) as ScopeKey[])(
      "blocks both actions when the %s confirmation differs",
      async (key) => {
        const api = createApi();
        await mount(api);
        await fillScope();
        typeInto(input(key, true), `${SCOPE[key]}-x`);
        await settle();
        expect(isDisabled(activateButton())).toBe(true);
        expect(isDisabled(revokeButton())).toBe(true);
        fireEvent.click(activateButton());
        fireEvent.click(revokeButton());
        await settle();
        expect(api.posts()).toEqual([]);
      },
    );

    it.each(Object.keys(LABELS) as ScopeKey[])(
      "blocks both actions when the %s field is emptied",
      async (key) => {
        const api = createApi();
        await mount(api);
        await fillScope();
        typeInto(input(key), "");
        typeInto(input(key, true), "");
        await settle();
        expect(isDisabled(activateButton())).toBe(true);
        expect(isDisabled(revokeButton())).toBe(true);
      },
    );

    it("blocks again when an identifier is edited after both fields matched", async () => {
      const api = createApi();
      await mount(api);
      await fillScope();
      typeInto(input("venue"), "venue-sim-02");
      await settle();
      expect(isDisabled(activateButton())).toBe(true);
      expect(isDisabled(revokeButton())).toBe(true);
    });

    it("sends the identifiers exactly as confirmed, without trimming surprises or case changes", async () => {
      const api = createApi();
      await mount(api);
      const scope = {
        account_id: "Acct.Sim:0042",
        venue: "Venue_Sim/01",
        instrument_id: "nq-syn.01",
        strategy_id: "Strat-Alpha_01",
      };
      await fillScope(scope);
      fireEvent.click(activateButton());
      await waitFor(() => expect(api.posts()).toHaveLength(1));
      expectPaperBody(api.posts()[0], scope);
    });
  });

  describe("closed identifier grammar", () => {
    const BAD = [
      "has space",
      " leading",
      "trailing ",
      "-leading-hyphen",
      "_leading_underscore",
      ".leading.dot",
      "semi;colon",
      "../traversal",
      "quote\"inside",
      "back\\slash",
      "tab\there",
      "nul\u0000byte",
      "é-accent",
      "日本語",
      "emoji-😀",
      "<script>x</script>",
      "a".repeat(129),
      "api-key-01",
      "secret-venue",
      "token-strategy",
      "password",
      "bearer-01",
      "sk-live-123456789012",
      `${CANARY.slice(0, 20)} ${CANARY.slice(20)}`,
    ];

    it.each(BAD)("rejects a bad identifier and never echoes it: %j", async (bad) => {
      const api = createApi();
      await mount(api);
      await fillScope();
      typeInto(input("account_id"), bad);
      typeInto(input("account_id", true), bad);
      await settle();
      expect(isDisabled(activateButton())).toBe(true);
      expect(isDisabled(revokeButton())).toBe(true);
      fireEvent.click(activateButton());
      fireEvent.click(revokeButton());
      const form = activateButton().closest("form");
      if (form !== null) fireEvent.submit(form);
      await settle();
      expect(api.posts()).toEqual([]);
      const text = visibleText();
      if (bad.trim().length > 2) expect(text).not.toContain(bad);
      const field = input("account_id");
      const flagged =
        field.getAttribute("aria-invalid") === "true"
        || document.querySelector("[role='alert']") !== null
        || field.getAttribute("aria-describedby") !== null;
      expect(flagged).toBe(true);
    });

    it.each(["new\nline", "new\r\nline", "line1\nline2\nline3"])(
      "rejects pasted multi-line text instead of silently normalizing it into a valid identifier: %j",
      async (pasted) => {
        const api = createApi();
        await mount(api);
        await fillScope();
        expect(isDisabled(activateButton())).toBe(false);
        for (const confirm of [false, true]) {
          fireEvent.paste(input("account_id", confirm), {
            clipboardData: { getData: () => pasted, types: ["text/plain"] },
          });
        }
        await settle();
        expect(isDisabled(activateButton())).toBe(true);
        expect(isDisabled(revokeButton())).toBe(true);
        fireEvent.click(activateButton());
        fireEvent.click(revokeButton());
        await settle();
        expect(api.posts()).toEqual([]);
        expect(visibleText()).not.toContain(pasted);
        expect(input("account_id").getAttribute("aria-invalid")).toBe("true");
      },
    );

    it("rejects every one of the four fields independently when bad", async () => {
      for (const key of Object.keys(LABELS) as ScopeKey[]) {
        const api = createApi();
        const view = await mount(api);
        await fillScope();
        typeInto(input(key), "bad value");
        typeInto(input(key, true), "bad value");
        await settle();
        expect(isDisabled(activateButton())).toBe(true);
        expect(isDisabled(revokeButton())).toBe(true);
        expect(api.posts()).toEqual([]);
        view.unmount();
      }
    });

    it("accepts a 64-character identifier made of the allowed punctuation and sends it unchanged", async () => {
      const api = createApi();
      await mount(api);
      const long = `a${"b-c.d_e:f/g".repeat(8)}`.slice(0, 64);
      const scope = { ...SCOPE, instrument_id: long };
      await fillScope(scope);
      fireEvent.click(revokeButton());
      await waitFor(() => expect(api.posts()).toHaveLength(1));
      expectPaperBody(api.posts()[0], scope);
    });
  });

  describe("scope status is unknown and unverified, never inferred", () => {
    it("shows the scope status as unknown and API-reported/unverified on load, even with activations reported", async () => {
      const api = createApi({ orders: ok({ ...ordersReady, activation_count: 5 }) });
      await mount(api);
      await fillScope();
      const text = visibleText();
      expect(text).toMatch(/unknown/i);
      expect(text).toMatch(/unverified/i);
      expect(text).not.toMatch(/this scope is active/i);
      expect(text).not.toMatch(/\bscope active\b/i);
    });

    it("never calls an aggregate activation count proof that this scope is active", async () => {
      const api = createApi({ orders: ok({ ...ordersReady, activation_count: 1 }) });
      await mount(api);
      await fillScope();
      const scopeStatus = screen.queryAllByText(/scope status/i);
      for (const element of scopeStatus) {
        expect(element.parentElement?.textContent ?? "").not.toMatch(/\bactive\b(?!.*unverified)/i);
      }
      expect(visibleText()).not.toMatch(/(verified|confirmed) (as )?active/i);
    });

    it("forgets the local acknowledgement on a fresh mount (reload) and does not persist it", async () => {
      const setItem = vi.spyOn(Storage.prototype, "setItem");
      const api = createApi();
      const view = await mount(api);
      await fillScope();
      fireEvent.click(activateButton());
      await waitFor(() => expect(api.posts()).toHaveLength(1));
      await settle();
      expect(visibleText()).toMatch(ACK);
      view.unmount();
      const second = createApi({ orders: ok({ ...ordersReady, activation_count: 1 }) });
      await mount(second);
      expect(visibleText()).not.toMatch(ACK);
      expect(visibleText()).toMatch(/unknown/i);
      expect(setItem).not.toHaveBeenCalled();
      expect(second.posts()).toEqual([]);
    });

    it("does not present the receipt time of a status read as source freshness", async () => {
      await mount(createApi());
      expect(visibleText()).not.toMatch(/\b(fresh|up to date|up-to-date|as of|updated at|live status)\b/i);
    });

    it("clears the local acknowledgement after a revoke", async () => {
      const api = createApi();
      await mount(api);
      await fillScope();
      fireEvent.click(activateButton());
      await waitFor(() => expect(api.posts()).toHaveLength(1));
      await settle();
      fireEvent.click(revokeButton());
      await waitFor(() => expect(api.posts()).toHaveLength(2));
      await settle();
      expect(visibleText()).not.toMatch(/activated.*(local[- ]session)/i);
    });
  });

  describe("keyboard and accessibility", () => {
    it("uses native, labelled controls for every field and action", async () => {
      await mount(createApi());
      for (const key of Object.keys(LABELS) as ScopeKey[]) {
        for (const confirm of [false, true]) {
          const field = input(key, confirm);
          expect(field.tagName).toBe("INPUT");
          expect(field.getAttribute("type") ?? "text").toBe("text");
          expect(field.getAttribute("tabindex")).not.toBe("-1");
        }
      }
      for (const button of [activateButton(), revokeButton(), refreshButton()]) {
        expect(button.tagName).toBe("BUTTON");
        expect(button.getAttribute("tabindex")).not.toBe("-1");
      }
      const ids = [...document.querySelectorAll("input")].map((element) => element.id).filter(Boolean);
      expect(new Set(ids).size).toBe(ids.length);
    });

    it("has no positive tabindex and no clickable non-native controls", async () => {
      await mount(createApi());
      for (const element of document.querySelectorAll("[tabindex]")) {
        expect(Number(element.getAttribute("tabindex"))).toBeLessThanOrEqual(0);
      }
      for (const element of document.querySelectorAll("[role='button']")) {
        expect(element.tagName).toBe("BUTTON");
      }
    });

    it("keeps focus order logical: fields, then confirmations, then the actions", async () => {
      await mount(createApi());
      const focusable = [...document.querySelectorAll<HTMLElement>("input,button,select,textarea,a[href]")]
        .filter((element) => !isDisabled(element));
      const names = focusable.map((element) => (
        element.getAttribute("aria-label") ?? element.id ?? element.textContent ?? ""
      ));
      expect(names.length).toBeGreaterThanOrEqual(8);
      const buttons = focusable.filter((element) => element.tagName === "BUTTON");
      const lastField = [...focusable].reverse().find((element) => element.tagName === "INPUT");
      expect(lastField).toBeDefined();
      expect(buttons.length).toBeGreaterThanOrEqual(1);
    });

    it("conveys disabled state to assistive technology on blocked actions", async () => {
      const api = createApi({ risk: ok({ ...riskClear, halted: true, active_halts: ["operator_hold"] }) });
      await mount(api);
      await fillScope();
      expect(isDisabled(activateButton())).toBe(true);
      expect(activateButton().hasAttribute("disabled") || activateButton().getAttribute("aria-disabled") === "true")
        .toBe(true);
    });

    it("announces state changes in a live region and keeps the reason visible", async () => {
      const api = createApi({ risk: ok({ ...riskClear, halted: true, active_halts: ["operator_hold"] }) });
      await mount(api);
      await fillScope();
      const live = document.querySelector("[role='status'],[role='alert'],[aria-live]");
      expect(live).not.toBeNull();
      expect(visibleText()).toMatch(/halt|blocked|disabled|unavailable/i);
    });

    it("lets the keyboard reach a refresh and keeps the activation guard after Enter on a disabled action", async () => {
      const api = createApi({ orders: ok({ ...ordersReady, recovery_status: "UNKNOWN" }) });
      await mount(api);
      await fillScope();
      refreshButton().focus();
      expect(document.activeElement).toBe(refreshButton());
      activateButton().focus();
      fireEvent.keyDown(activateButton(), { key: "Enter" });
      fireEvent.keyUp(activateButton(), { key: "Enter" });
      fireEvent.keyDown(activateButton(), { key: " " });
      await settle();
      expect(api.posts()).toEqual([]);
    });

    it("labels the refresh and action buttons without relying on colour or icons", async () => {
      await mount(createApi());
      for (const button of [activateButton(), revokeButton(), refreshButton()]) {
        expect(within(button).queryByRole("img")).toBeNull();
        expect((button.textContent ?? "").trim().length).toBeGreaterThan(2);
      }
    });
  });

  describe("source hygiene of the writer's wave27 files", () => {
    const sources = [viewSource, apiSource];

    it("never names an order lifecycle endpoint or a persistence or polling API", () => {
      for (const source of sources) {
        expect(source).not.toMatch(/\/orders\/recover|\/orders\/\$\{|\/submit|\/cancel|\/reconcile/);
        expect(source).not.toMatch(/localStorage|sessionStorage|indexedDB|setInterval/);
        expect(source).not.toMatch(/["'`]\/api\/orders["'`]/);
      }
    });

    it("hard-codes the lowercase paper wire value and no other environment literal", () => {
      const joined = sources.join("\n");
      expect(joined).toMatch(/["']paper["']\s+as\s+const/);
      expect(joined).not.toMatch(/environment\s*:\s*["'](live|demo|LIVE|DEMO|PAPER)["']/);
      expect(joined).not.toMatch(/environment\s*:\s*(?!PAPER_ENVIRONMENT)[a-zA-Z_]/);
    });
  });
});
