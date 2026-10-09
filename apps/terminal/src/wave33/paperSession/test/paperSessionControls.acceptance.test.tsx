/* Independent acceptance for PAPER-SESSION-CONTROLS-UI-001 (post-activation paper session controls).
 *
 * Written from wave33-build-phase1-v0.1 section 6 and the coordinator's rulings, not from the
 * writer's unit tests. The view is driven with deterministic fake `/api` responses and every
 * request method, path and body is captured. All data is synthetic.
 *
 * Contract encoded here: pause and resume are exactly revoke and activate for one confirmed
 * paper scope (wire `environment` is lowercase "paper"); nothing else is ever sent (no order
 * cancel, recover, create or submit); the copy never claims working orders are cancelled; unknown,
 * HALT or recovery-not-ready state blocks resume; errors are non-optimistic; one double-click
 * sends one POST; an API-reported `live_enabled: true` disables Resume but never Pause; LIVE is disabled;
 * a SIM / PAPER watermark is always visible.
 */
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import apiSource from "../api.ts?raw";
import { PaperSessionControlsView } from "../PaperSessionControlsView";
import viewSource from "../PaperSessionControlsView.tsx?raw";

const ORDERS_STATUS = "/api/orders/status";
const RISK_STATUS = "/api/risk/status";
const ACTIVATE = "/api/orders/activations";
const REVOKE = "/api/orders/activations/revoke";
const READ_PATHS = [ORDERS_STATUS, RISK_STATUS];
const MUTATION_PATHS = [ACTIVATE, REVOKE];
const CANARY = "SYNTHETIC_PAPER_SESSION_CANARY_DO_NOT_RENDER";

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

const ordersReady = { live_enabled: false, recovery_status: "READY", activation_count: 2 };
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
  const held: Array<() => void> = [];
  let holdMutations = false;
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
    if (holdMutations && (key === "activate" || key === "revoke")) {
      return new Promise<Response>((resolve) => {
        held.push(() => resolve(response(reply)));
      });
    }
    return Promise.resolve(response(reply));
  });
  return {
    fetcher: fetcher as unknown as typeof fetch,
    mock: fetcher,
    calls,
    replies,
    hold: () => {
      holdMutations = true;
    },
    release: async () => {
      holdMutations = false;
      for (const resolve of held.splice(0)) resolve();
      for (let i = 0; i < 6; i += 1) {
        await act(async () => {
          await Promise.resolve();
        });
      }
    },
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
  const view = render(<PaperSessionControlsView fetcher={api.fetcher} />);
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

const pauseButton = () => screen.getByRole("button", { name: /^paus/i });
const resumeButton = () => screen.getByRole("button", { name: /^resum/i });
const refreshButton = () => screen.getByRole("button", { name: /refresh status/i });

function isDisabled(element: Element): boolean {
  return element.matches(":disabled") || element.getAttribute("aria-disabled") === "true";
}

function visibleText(): string {
  return document.body.textContent ?? "";
}

/** The success acknowledgement is the only sentence that says the API accepted an action. */
const ACK = /accepted by the API/i;

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

/** Every sentence mentioning cancellation must negate it. */
function expectNoCancelClaims() {
  const sentences = visibleText().split(/(?<=[.!?])\s+|(?<=[a-z])(?=[A-Z][a-z]+ [a-z])/);
  for (const sentence of sentences) {
    if (/cancel/i.test(sentence)) {
      expect(sentence).toMatch(/\b(not|never|without|no|doesn't|does not)\b/i);
    }
  }
  expect(visibleText()).not.toMatch(
    /\b(orders? (is|are|were|was|have been|has been) (cancel(l)?ed|closed|flattened)|all orders cancel(l)?ed|positions? (closed|flattened))\b/i,
  );
}

async function pause(api: Api, scope: Record<ScopeKey, string> = SCOPE) {
  await fillScope(scope);
  const before = api.posts().length;
  fireEvent.click(pauseButton());
  await waitFor(() => expect(api.posts().length).toBe(before + 1));
  await settle();
}

async function resume(api: Api, scope: Record<ScopeKey, string> = SCOPE) {
  await fillScope(scope);
  const before = api.posts().length;
  fireEvent.click(resumeButton());
  await waitFor(() => expect(api.posts().length).toBe(before + 1));
  await settle();
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("PAPER-SESSION-CONTROLS-UI-001 independent acceptance", () => {
  describe("watermark, LIVE and the fixed paper environment", () => {
    it("shows a SIM / PAPER watermark immediately, while loading, and in every fault state", async () => {
      const states: Array<Partial<Replies>> = [
        {},
        { orders: "pending" },
        { risk: "pending" },
        { orders: ok({ detail: "NOT_CONFIGURED" }, 503) },
        { orders: "network" },
        { risk: ok({ ...riskClear, halted: true, active_halts: ["operator_hold"] }) },
        { orders: ok({ ...ordersReady, live_enabled: true }) },
        { orders: ok(["READY"]) },
        { risk: "badjson" },
      ];
      for (const state of states) {
        const api = createApi(state);
        const view = render(<PaperSessionControlsView fetcher={api.fetcher} />);
        expect(visibleText()).toMatch(/SIM\s*\/\s*PAPER/);
        await settle();
        expect(visibleText()).toMatch(/SIM\s*\/\s*PAPER/);
        view.unmount();
      }
    });

    it("keeps the watermark visible to assistive technology and on every state change", async () => {
      const api = createApi();
      await mount(api);
      const marker = screen.getAllByText(/SIM\s*\/\s*PAPER/)[0];
      expect(marker.closest("[aria-hidden='true']")).toBeNull();
      expect(marker.closest("[hidden]")).toBeNull();
      await pause(api);
      expect(visibleText()).toMatch(/SIM\s*\/\s*PAPER/);
      await fillScope();
      fireEvent.click(refreshButton());
      await settle();
      expect(visibleText()).toMatch(/SIM\s*\/\s*PAPER/);
    });

    it("renders LIVE as a disabled control with no DEMO path and no way to select it", async () => {
      const api = createApi();
      await mount(api);
      expect(visibleText()).toMatch(/LIVE[^.]*disabled/i);
      expect(visibleText()).not.toMatch(/\bdemo\b/i);
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
        if (/\blive\b/i.test(label)) {
          expect(isDisabled(control)).toBe(true);
          fireEvent.click(control);
        }
      }
      await settle();
      expect(api.posts()).toEqual([]);
    });

    it("sends exactly the lowercase paper wire value for pause and resume, never anything else", async () => {
      const api = createApi();
      await mount(api);
      await pause(api);
      await resume(api);
      const posts = api.posts();
      expect(posts.map((post) => post.path)).toEqual([REVOKE, ACTIVATE]);
      for (const post of posts) expectPaperBody(post);
      expect(posts.map((post) => (post.body as { environment: string }).environment)).toEqual([
        "paper",
        "paper",
      ]);
      expectOnlyAllowedCalls(api);
    });
  });

  describe("pause and resume map exactly to revoke and activate", () => {
    it("loads with only the two explicit GET reads and sends no mutation", async () => {
      const api = createApi();
      await mount(api);
      expect(api.reads().map((call) => call.path).sort()).toEqual([ORDERS_STATUS, RISK_STATUS]);
      expect(api.posts()).toEqual([]);
      expectOnlyAllowedCalls(api);
    });

    it("pause sends one revoke POST for the confirmed scope and nothing else", async () => {
      const api = createApi();
      await mount(api);
      await pause(api);
      const posts = api.posts();
      expect(posts).toHaveLength(1);
      expect(posts[0].path).toBe(REVOKE);
      expectPaperBody(posts[0]);
      expectOnlyAllowedCalls(api);
    });

    it("resume re-reads both statuses and then sends one activate POST for the confirmed scope", async () => {
      const api = createApi();
      await mount(api);
      const readsAfterMount = api.reads().length;
      await resume(api);
      const posts = api.posts();
      expect(posts).toHaveLength(1);
      expect(posts[0].path).toBe(ACTIVATE);
      expectPaperBody(posts[0]);
      const indexOfPost = api.calls.indexOf(posts[0]);
      const before = api.calls.slice(0, indexOfPost).filter((call) => call.method === "GET");
      expect(before.length - readsAfterMount).toBeGreaterThanOrEqual(2);
      expect(new Set(before.slice(readsAfterMount).map((call) => call.path))).toEqual(
        new Set(READ_PATHS),
      );
      expectOnlyAllowedCalls(api);
    });

    it("re-reads both statuses after a successful mutation and shows only API-reported state", async () => {
      const api = createApi();
      await mount(api);
      await pause(api);
      const after = api.calls.slice(api.calls.indexOf(api.posts()[0]) + 1);
      expect(new Set(after.filter((call) => call.method === "GET").map((call) => call.path))).toEqual(
        new Set(READ_PATHS),
      );
    });

    it("sends no order cancel, recover, create, submit or reconcile request in any flow", async () => {
      const api = createApi({ orders: ok({ ...ordersReady, recovery_status: "UNKNOWN" }) });
      await mount(api);
      await pause(api);
      fireEvent.click(refreshButton());
      await settle();
      fireEvent.click(resumeButton());
      await settle();
      for (const call of api.calls) {
        expect(call.path).not.toMatch(/\/recover|\/reconcile|\/submit|\/cancel/);
        expect(call.path === "/api/orders" && call.method === "POST").toBe(false);
      }
      expectOnlyAllowedCalls(api);
    });

    it("offers no control for cancelling, flattening, submitting or recovering orders", async () => {
      await mount(createApi());
      const forbidden = /\b(submit order|create order|place order|cancel|recover|buy|sell|flatten|close position|kill)\b/i;
      for (const control of document.querySelectorAll("button,a,[role='button'],input[type='submit']")) {
        const label = [control.textContent, control.getAttribute("aria-label")].filter(Boolean).join(" ");
        expect(label).not.toMatch(forbidden);
      }
    });
  });

  describe("honest copy about what pause does", () => {
    it("states that pause stops new submissions and does not cancel working orders", async () => {
      await mount(createApi());
      const text = visibleText();
      expect(text).toMatch(/new submissions/i);
      expect(text).toMatch(/does not cancel working orders/i);
      expectNoCancelClaims();
    });

    it("never claims working orders are cancelled before, during or after pause and resume", async () => {
      const api = createApi();
      await mount(api);
      expectNoCancelClaims();
      await pause(api);
      expectNoCancelClaims();
      await resume(api);
      expectNoCancelClaims();
    });

    it("does not claim to pause a simulator or a market feed", async () => {
      const api = createApi();
      await mount(api);
      await pause(api);
      const text = visibleText();
      expect(text).not.toMatch(/simulator (is |has been )?(paused|stopped)/i);
      expect(text).not.toMatch(/(market|price) (feed|data) (is |has been )?(paused|stopped)/i);
      expect(text).toMatch(/does not[^.]*pause the simulator/i);
    });
  });

  describe("resume is blocked unless every explicit read is healthy", () => {
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
      ["orders string count", { orders: ok({ ...ordersReady, activation_count: "2" }) }],
      ["orders live_enabled not boolean", { orders: ok({ ...ordersReady, live_enabled: "false" }) }],
      ["orders live_enabled true", { orders: ok({ ...ordersReady, live_enabled: true }) }],
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

    it.each(blocked)("keeps Resume disabled and sends nothing: %s", async (_name, replies) => {
      const api = createApi(replies);
      await mount(api);
      await fillScope();
      expect(isDisabled(resumeButton())).toBe(true);
      fireEvent.click(resumeButton());
      const form = resumeButton().closest("form");
      if (form !== null) fireEvent.submit(form);
      fireEvent.keyDown(resumeButton(), { key: "Enter" });
      fireEvent.keyDown(resumeButton(), { key: " " });
      await settle();
      expect(api.posts()).toEqual([]);
      expect(visibleText()).not.toContain(CANARY);
      expectOnlyAllowedCalls(api);
    });

    it.each(blocked)(
      "keeps Pause available for a valid confirmed scope: %s",
      async (_name, replies) => {
        const api = createApi(replies);
        await mount(api);
        await fillScope();
        expect(isDisabled(pauseButton())).toBe(false);
        fireEvent.click(pauseButton());
        await waitFor(() => expect(api.posts()).toHaveLength(1));
        expect(api.posts()[0].path).toBe(REVOKE);
        expectPaperBody(api.posts()[0]);
      },
    );

    it("never recovers on its own when recovery is not READY", async () => {
      const api = createApi({ orders: ok({ ...ordersReady, recovery_status: "FAILED" }) });
      await mount(api);
      await fillScope();
      fireEvent.click(refreshButton());
      await settle();
      expect(api.calls.some((call) => /recover/.test(call.path))).toBe(false);
    });

    it("enables Resume only when every condition holds and re-blocks after a halted refresh", async () => {
      const api = createApi();
      await mount(api);
      expect(isDisabled(resumeButton())).toBe(true);
      await fillScope();
      expect(isDisabled(resumeButton())).toBe(false);
      api.replies.risk = ok({ ...riskClear, halted: true, active_halts: ["operator_halt"] });
      fireEvent.click(refreshButton());
      await waitFor(() => expect(isDisabled(resumeButton())).toBe(true));
      fireEvent.click(resumeButton());
      await settle();
      expect(api.posts()).toEqual([]);
    });

    it("blocks a resume whose pre-POST re-read finds a halt, without sending the POST", async () => {
      const api = createApi();
      await mount(api);
      await fillScope();
      expect(isDisabled(resumeButton())).toBe(false);
      api.replies.risk = ok({ ...riskClear, halted: true, active_halts: ["operator_hold"] });
      fireEvent.click(resumeButton());
      await settle();
      expect(api.posts()).toEqual([]);
      expect(document.querySelector("[role='alert'],[role='status']")).not.toBeNull();
    });

    it("blocks a resume whose pre-POST re-read finds recovery no longer READY", async () => {
      const api = createApi();
      await mount(api);
      await fillScope();
      api.replies.orders = ok({ ...ordersReady, recovery_status: "FAILED" });
      fireEvent.click(resumeButton());
      await settle();
      expect(api.posts()).toEqual([]);
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

  describe("an API-reported live_enabled of true disables Resume but never Pause", () => {
    it("disables Resume, keeps Pause enabled for a valid confirmed scope, and Resume sends nothing", async () => {
      const api = createApi({ orders: ok({ ...ordersReady, live_enabled: true }) });
      await mount(api);
      await fillScope();
      expect(isDisabled(resumeButton())).toBe(true);
      expect(isDisabled(pauseButton())).toBe(false);
      fireEvent.click(resumeButton());
      for (const form of document.querySelectorAll("form")) fireEvent.submit(form);
      await settle();
      expect(api.posts()).toEqual([]);
      expect(visibleText()).toMatch(/LIVE[^.]*disabled/i);
    });

    it("lets Pause send its revoke POST while live_enabled is reported true", async () => {
      const api = createApi({ orders: ok({ ...ordersReady, live_enabled: true }) });
      await mount(api);
      await pause(api);
      expect(api.posts()).toHaveLength(1);
      expect(api.posts()[0].path).toBe(REVOKE);
      expectPaperBody(api.posts()[0]);
      expectOnlyAllowedCalls(api);
    });

    it("keeps that split across refreshes and lifts the Resume block only when live is no longer reported", async () => {
      const api = createApi({ orders: ok({ ...ordersReady, live_enabled: true }) });
      await mount(api);
      await fillScope();
      fireEvent.click(refreshButton());
      await settle();
      expect(isDisabled(pauseButton())).toBe(false);
      expect(isDisabled(resumeButton())).toBe(true);
      api.replies.orders = ok(ordersReady);
      fireEvent.click(refreshButton());
      await waitFor(() => expect(isDisabled(resumeButton())).toBe(false));
      expect(isDisabled(pauseButton())).toBe(false);
    });

    it("still keeps Pause available when live is reported together with a halt or a failed recovery", async () => {
      const api = createApi({
        orders: ok({ ...ordersReady, live_enabled: true, recovery_status: "FAILED" }),
        risk: ok({ ...riskClear, halted: true, active_halts: ["operator_hold"] }),
      });
      await mount(api);
      await fillScope();
      expect(isDisabled(pauseButton())).toBe(false);
      expect(isDisabled(resumeButton())).toBe(true);
    });
  });

  describe("Enter in an input never invokes Resume", () => {
    const inputs: Array<[string, ScopeKey, boolean]> = (Object.keys(LABELS) as ScopeKey[]).flatMap(
      (key) => [
        [`${key} field`, key, false] as [string, ScopeKey, boolean],
        [`${key} confirmation`, key, true] as [string, ScopeKey, boolean],
      ],
    );

    it.each(inputs)("pressing Enter in the %s sends no POST in a healthy state", async (_name, key, confirm) => {
      const api = createApi();
      await mount(api);
      await fillScope();
      expect(isDisabled(resumeButton())).toBe(false);
      const field = input(key, confirm);
      field.focus();
      fireEvent.keyDown(field, { key: "Enter", code: "Enter", charCode: 13 });
      fireEvent.keyPress(field, { key: "Enter", code: "Enter", charCode: 13 });
      fireEvent.keyUp(field, { key: "Enter", code: "Enter", charCode: 13 });
      const form = field.closest("form");
      if (form !== null) {
        // A browser clicks the form's default submit button on Enter; there must be none, and a
        // submit event itself must never start a resume.
        expect(form.querySelector("button[type='submit'],input[type='submit'],button:not([type])")).toBeNull();
        fireEvent.submit(form);
      }
      await settle();
      expect(api.posts()).toEqual([]);
    });

    it("only an explicit click on the Resume button resumes", async () => {
      const api = createApi();
      await mount(api);
      await fillScope();
      for (const form of document.querySelectorAll("form")) fireEvent.submit(form);
      await settle();
      expect(api.posts()).toEqual([]);
      fireEvent.click(resumeButton());
      await waitFor(() => expect(api.posts()).toHaveLength(1));
      expect(api.posts()[0].path).toBe(ACTIVATE);
      expectPaperBody(api.posts()[0]);
    });

    it("never turns Enter into a pause either", async () => {
      const api = createApi();
      await mount(api);
      await fillScope();
      const field = input("venue");
      fireEvent.keyDown(field, { key: "Enter", code: "Enter", charCode: 13 });
      const form = field.closest("form");
      if (form !== null) fireEvent.submit(form);
      await settle();
      expect(api.posts()).toEqual([]);
    });
  });

  describe("Resume explains itself", () => {
    it("says what Resume does and what it does not do, without promising any order action", async () => {
      await mount(createApi());
      const text = visibleText();
      expect(text).toMatch(/resume[^.]*new (paper )?submissions/i);
      expect(text).not.toMatch(/resume[^.]*\b(replay|re-?submit|restore orders|restart the simulator|recover)/i);
      expectNoCancelClaims();
    });

    it("keeps the explanation visible when Resume is blocked and says why it is blocked", async () => {
      const api = createApi({ risk: ok({ ...riskClear, halted: true, active_halts: ["operator_hold"] }) });
      await mount(api);
      await fillScope();
      expect(visibleText()).toMatch(/resume[^.]*new (paper )?submissions/i);
      expect(visibleText()).toMatch(/blocks? resume|resume is (blocked|disabled)/i);
      expect(visibleText()).toMatch(/halt|fault|READY|not verified/i);
    });
  });

  describe("the local acknowledgement is timestamped and cleared by an adverse later read", () => {
    const FIXED = "2026-10-07T12:34:56";

    it("timestamps the acknowledgement with the time the API accepted the action", async () => {
      vi.useFakeTimers({ toFake: ["Date"] });
      vi.setSystemTime(new Date(`${FIXED}.000Z`));
      const api = createApi();
      await mount(api);
      await pause(api);
      expect(visibleText()).toMatch(ACK);
      // Either an ISO rendering or the runtime locale rendering of the accepted time is a timestamp.
      const locale = new Date(`${FIXED}.000Z`).toLocaleString();
      expect(visibleText().includes(FIXED) || visibleText().includes(locale)).toBe(true);
    });

    it.each([
      ["a halted flag", { risk: ok({ ...riskClear, halted: true, active_halts: ["operator_hold"] }) }],
      ["halt codes only", { risk: ok({ ...riskClear, active_halts: ["stale_data"] }) }],
      ["a fault code", { risk: ok({ ...riskClear, fault_code: "HALT_STORE_UNAVAILABLE" }) }],
      ["recovery UNKNOWN", { orders: ok({ ...ordersReady, recovery_status: "UNKNOWN" }) }],
      ["recovery FAILED", { orders: ok({ ...ordersReady, recovery_status: "FAILED" }) }],
      ["an unrecognized recovery value", { orders: ok({ ...ordersReady, recovery_status: "SOMETHING" }) }],
    ] as Array<[string, Partial<Replies>]>)(
      "clears the acknowledgement when a later status read reports %s",
      async (_name, adverse) => {
        const api = createApi();
        await mount(api);
        await pause(api);
        expect(visibleText()).toMatch(ACK);
        Object.assign(api.replies, adverse);
        fireEvent.click(refreshButton());
        await waitFor(() => expect(visibleText()).not.toMatch(ACK));
        expect(api.posts()).toHaveLength(1);
      },
    );

    it("clears a resume acknowledgement when a later read reports a halt", async () => {
      const api = createApi();
      await mount(api);
      await resume(api);
      expect(visibleText()).toMatch(/Resume accepted by the API/i);
      api.replies.risk = ok({ ...riskClear, halted: true, active_halts: ["operator_halt"] });
      fireEvent.click(refreshButton());
      await waitFor(() => expect(visibleText()).not.toMatch(ACK));
    });

    it("keeps the acknowledgement through a later read that shows nothing adverse", async () => {
      const api = createApi();
      await mount(api);
      await pause(api);
      expect(visibleText()).toMatch(ACK);
      fireEvent.click(refreshButton());
      await settle();
      expect(visibleText()).toMatch(ACK);
    });

    it("never offers an acknowledgement for a failed action, with or without a timestamp", async () => {
      const api = createApi({ revoke: ok({ detail: "X" }, 503) });
      await mount(api);
      await pause(api);
      expect(visibleText()).not.toMatch(ACK);
      expect(visibleText()).not.toMatch(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/);
    });
  });

  describe("errors are non-optimistic", () => {
    const failures: Array<[string, Reply]> = [
      ["401", ok({ detail: "OPERATOR_REQUIRED" }, 401)],
      ["403", ok({ detail: "ACTIVATION_DISABLED" }, 403)],
      ["409", ok({ detail: "CONFLICT" }, 409)],
      ["422", ok({ detail: "INVALID_ORDER_SCOPE" }, 422)],
      ["503", ok({ detail: "NOT_CONFIGURED" }, 503)],
      ["network", "network"],
      ["malformed receipt", ok({ active: "yes" }, 200)],
      ["wrong receipt", ok({ active: true }, 200)],
      ["bad json", "badjson"],
    ];

    it.each(failures)("a failed pause (%s) shows an error and no acknowledgement", async (_name, reply) => {
      const api = createApi({ revoke: reply });
      await mount(api);
      await pause(api);
      expect(api.posts()).toHaveLength(1);
      expect(visibleText()).not.toMatch(ACK);
      expect(document.querySelector("[role='alert']")).not.toBeNull();
      expect(visibleText()).not.toContain(CANARY);
      expectOnlyAllowedCalls(api);
    });

    it.each(failures)("a failed resume (%s) shows an error and no acknowledgement", async (_name, reply) => {
      const api = createApi({ activate: _name === "wrong receipt" ? ok({ active: false }, 201) : reply });
      await mount(api);
      await resume(api);
      expect(api.posts()).toHaveLength(1);
      expect(visibleText()).not.toMatch(ACK);
      expect(document.querySelector("[role='alert']")).not.toBeNull();
      expect(visibleText()).not.toContain(CANARY);
      expectOnlyAllowedCalls(api);
    });

    it("does not retry a failed mutation by itself", async () => {
      const api = createApi({ revoke: ok({ detail: "X" }, 503) });
      await mount(api);
      await pause(api);
      await settle();
      expect(api.posts()).toHaveLength(1);
    });

    it("never echoes server-supplied text from an error body", async () => {
      const api = createApi({ revoke: ok({ detail: CANARY, message: CANARY, raw: CANARY }, 422) });
      await mount(api);
      await pause(api);
      expect(visibleText()).not.toContain(CANARY);
    });

    it("shows an acknowledgement only after the API accepted the action, and says nothing of this scope's state", async () => {
      const api = createApi();
      await mount(api);
      expect(visibleText()).not.toMatch(ACK);
      await pause(api);
      expect(visibleText()).toMatch(ACK);
      expect(visibleText()).not.toMatch(/\b(this scope is (now )?(paused|active|resumed)|scope (is )?(paused|active)|confirmed (paused|active))\b/i);
    });

    it("does not optimistically change the reported aggregate state before the POST completes", async () => {
      const api = createApi();
      await mount(api);
      await fillScope();
      const before = visibleText();
      api.hold();
      fireEvent.click(pauseButton());
      await waitFor(() => expect(api.posts()).toHaveLength(1));
      expect(visibleText()).not.toMatch(ACK);
      const duringNumbers = (visibleText().match(/\b\d+\b/g) ?? []).join(",");
      const beforeNumbers = (before.match(/\b\d+\b/g) ?? []).join(",");
      expect(duringNumbers).toBe(beforeNumbers);
      await api.release();
    });

    it("keeps the previously reported status when the post-mutation re-read fails", async () => {
      const api = createApi();
      await mount(api);
      await fillScope();
      api.replies.orders = "network";
      fireEvent.click(pauseButton());
      await waitFor(() => expect(api.posts()).toHaveLength(1));
      await settle();
      expect(visibleText()).not.toContain(CANARY);
      expect(isDisabled(resumeButton())).toBe(true); // an unreadable status blocks resume
    });
  });

  describe("one double-click sends one POST", () => {
    it.each([
      ["pause", REVOKE],
      ["resume", ACTIVATE],
    ])("a synchronous double-click on %s sends one POST", async (action, path) => {
      const api = createApi();
      await mount(api);
      await fillScope();
      api.hold();
      const button = action === "pause" ? pauseButton() : resumeButton();
      fireEvent.click(button);
      fireEvent.click(button);
      await settle();
      await waitFor(() => expect(api.posts().length).toBeGreaterThanOrEqual(1));
      expect(api.posts()).toHaveLength(1);
      expect(api.posts()[0].path).toBe(path);
      await api.release();
      expect(api.posts()).toHaveLength(1);
    });

    it("a triple click and an Enter submit while pending still send one POST", async () => {
      const api = createApi();
      await mount(api);
      await fillScope();
      api.hold();
      fireEvent.click(resumeButton());
      fireEvent.click(resumeButton());
      fireEvent.click(resumeButton());
      for (const form of document.querySelectorAll("form")) fireEvent.submit(form);
      await settle();
      expect(api.posts()).toHaveLength(1);
      await api.release();
      expect(api.posts()).toHaveLength(1);
    });

    it.each([
      ["pause", REVOKE],
      ["resume", ACTIVATE],
    ])(
      "two %s clicks delivered before React re-renders still send one POST",
      async (action, path) => {
        const api = createApi();
        await mount(api);
        await fillScope();
        api.hold();
        const button = action === "pause" ? pauseButton() : resumeButton();
        // Both clicks run inside one batch, so the disabled state of the first cannot help:
        // only a guard set synchronously before the first await can stop the second.
        act(() => {
          button.click();
          button.click();
        });
        await settle();
        await waitFor(() => expect(api.posts().length).toBeGreaterThanOrEqual(1));
        await api.release();
        expect(api.posts().filter((post) => post.path === path)).toHaveLength(1);
        expect(api.posts()).toHaveLength(1);
      },
    );

    it("blocks the opposite action while one is pending and reports busy", async () => {
      const api = createApi();
      await mount(api);
      await fillScope();
      api.hold();
      fireEvent.click(pauseButton());
      await waitFor(() => expect(api.posts()).toHaveLength(1));
      fireEvent.click(resumeButton());
      await settle();
      expect(api.posts()).toHaveLength(1);
      expect(isDisabled(pauseButton())).toBe(true);
      expect(isDisabled(resumeButton())).toBe(true);
      const busy = document.querySelector("[aria-busy='true'],[role='status']");
      expect(busy).not.toBeNull();
      await api.release();
    });

    it("accepts a new action after the pending one finishes", async () => {
      const api = createApi();
      await mount(api);
      await fillScope();
      api.hold();
      fireEvent.click(pauseButton());
      await waitFor(() => expect(api.posts()).toHaveLength(1));
      await api.release();
      await waitFor(() => expect(isDisabled(pauseButton())).toBe(false));
      fireEvent.click(pauseButton());
      await waitFor(() => expect(api.posts()).toHaveLength(2));
    });

    it("sends one POST even when the same failure repeats on a double-click", async () => {
      const api = createApi({ revoke: ok({ detail: "X" }, 503) });
      await mount(api);
      await fillScope();
      api.hold();
      fireEvent.click(pauseButton());
      fireEvent.click(pauseButton());
      await api.release();
      expect(api.posts()).toHaveLength(1);
    });
  });

  describe("scope entry, confirmation and the closed identifier grammar", () => {
    it("requires all four identifiers and confirmations before either action is enabled", async () => {
      const api = createApi();
      await mount(api);
      expect(isDisabled(pauseButton())).toBe(true);
      expect(isDisabled(resumeButton())).toBe(true);
      for (const key of Object.keys(LABELS) as ScopeKey[]) typeInto(input(key), SCOPE[key]);
      await settle();
      expect(isDisabled(pauseButton())).toBe(true);
      expect(isDisabled(resumeButton())).toBe(true);
      for (const key of Object.keys(LABELS) as ScopeKey[]) typeInto(input(key, true), SCOPE[key]);
      await settle();
      expect(isDisabled(pauseButton())).toBe(false);
      expect(isDisabled(resumeButton())).toBe(false);
    });

    it.each(Object.keys(LABELS) as ScopeKey[])(
      "blocks both actions when the %s confirmation differs or the field is emptied",
      async (key) => {
        const api = createApi();
        await mount(api);
        await fillScope();
        typeInto(input(key, true), `${SCOPE[key]}-x`);
        await settle();
        expect(isDisabled(pauseButton())).toBe(true);
        expect(isDisabled(resumeButton())).toBe(true);
        typeInto(input(key), "");
        typeInto(input(key, true), "");
        await settle();
        expect(isDisabled(pauseButton())).toBe(true);
        expect(isDisabled(resumeButton())).toBe(true);
        fireEvent.click(pauseButton());
        fireEvent.click(resumeButton());
        await settle();
        expect(api.posts()).toEqual([]);
      },
    );

    it("blocks again when an identifier is edited after both fields matched", async () => {
      const api = createApi();
      await mount(api);
      await fillScope();
      typeInto(input("venue"), "venue-sim-02");
      await settle();
      expect(isDisabled(pauseButton())).toBe(true);
      expect(isDisabled(resumeButton())).toBe(true);
    });

    it("sends the identifiers exactly as confirmed, mixed case and allowed punctuation preserved", async () => {
      const api = createApi();
      await mount(api);
      const scope = {
        account_id: "Acct.Sim:0042",
        venue: "Venue_Sim/01",
        instrument_id: "nq-syn.01",
        strategy_id: "Strat-Alpha_01",
      };
      await pause(api, scope);
      expectPaperBody(api.posts()[0], scope);
    });

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
    ];

    it.each(BAD)("rejects a bad identifier and never echoes it: %j", async (bad) => {
      const api = createApi();
      await mount(api);
      await fillScope();
      typeInto(input("account_id"), bad);
      typeInto(input("account_id", true), bad);
      await settle();
      expect(isDisabled(pauseButton())).toBe(true);
      expect(isDisabled(resumeButton())).toBe(true);
      fireEvent.click(pauseButton());
      fireEvent.click(resumeButton());
      for (const form of document.querySelectorAll("form")) fireEvent.submit(form);
      await settle();
      expect(api.posts()).toEqual([]);
      if (bad.trim().length > 2) expect(visibleText()).not.toContain(bad);
      const field = input("account_id");
      const flagged =
        field.getAttribute("aria-invalid") === "true"
        || document.querySelector("[role='alert']") !== null
        || field.getAttribute("aria-describedby") !== null;
      expect(flagged).toBe(true);
    });

    it.each(["new\nline", "new\r\nline", "line1\nline2\nline3"])(
      "rejects pasted multi-line text instead of normalizing it into a valid identifier: %j",
      async (pasted) => {
        const api = createApi();
        await mount(api);
        await fillScope();
        expect(isDisabled(pauseButton())).toBe(false);
        for (const confirm of [false, true]) {
          fireEvent.paste(input("account_id", confirm), {
            clipboardData: { getData: () => pasted, types: ["text/plain"] },
          });
        }
        await settle();
        expect(isDisabled(pauseButton())).toBe(true);
        expect(isDisabled(resumeButton())).toBe(true);
        fireEvent.click(pauseButton());
        await settle();
        expect(api.posts()).toEqual([]);
        expect(visibleText()).not.toContain(pasted);
      },
    );

    it("rejects each of the four fields independently when bad", async () => {
      for (const key of Object.keys(LABELS) as ScopeKey[]) {
        const api = createApi();
        const view = await mount(api);
        await fillScope();
        typeInto(input(key), "bad value");
        typeInto(input(key, true), "bad value");
        await settle();
        expect(isDisabled(pauseButton())).toBe(true);
        expect(isDisabled(resumeButton())).toBe(true);
        expect(api.posts()).toEqual([]);
        view.unmount();
      }
    });
  });

  describe("reported state is aggregate and never inferred for this scope", () => {
    it("labels the activation count and recovery state as aggregate and API-reported", async () => {
      const api = createApi({ orders: ok({ ...ordersReady, activation_count: 7 }) });
      await mount(api);
      const text = visibleText();
      expect(text).toMatch(/aggregate/i);
      expect(text).toMatch(/API-reported/i);
      expect(text).toMatch(/\b7\b/);
      expect(text).toMatch(/READY/);
      expect(text).toMatch(/scope-specific state unavailable|scope-specific state is unavailable/i);
    });

    it("never calls an aggregate activation count proof that this scope is active or paused", async () => {
      const api = createApi({ orders: ok({ ...ordersReady, activation_count: 1 }) });
      await mount(api);
      await fillScope();
      expect(visibleText()).not.toMatch(/\b(this scope|your scope|selected scope)\b[^.]*\b(is )?(active|paused|running)\b/i);
      expect(visibleText()).not.toMatch(/(verified|confirmed) (as )?(active|paused)/i);
    });

    it("shows an unrecognized recovery value as unrecognized rather than ready", async () => {
      const api = createApi({ orders: ok({ ...ordersReady, recovery_status: CANARY }) });
      await mount(api);
      expect(visibleText()).not.toContain(CANARY);
      expect(visibleText()).toMatch(/UNRECOGNIZED/i);
    });

    it("forgets the acknowledgement on a fresh mount and persists nothing", async () => {
      const setItem = vi.spyOn(Storage.prototype, "setItem");
      const api = createApi();
      const view = await mount(api);
      await pause(api);
      expect(visibleText()).toMatch(ACK);
      view.unmount();
      const second = createApi();
      await mount(second);
      expect(visibleText()).not.toMatch(ACK);
      expect(setItem).not.toHaveBeenCalled();
      expect(second.posts()).toEqual([]);
    });

    it("does not present the receipt time of a status read as source freshness", async () => {
      await mount(createApi());
      expect(visibleText()).not.toMatch(/\b(fresh|up to date|up-to-date|as of|updated at|live status)\b/i);
    });
  });

  describe("keyboard and accessibility", () => {
    it("uses native labelled controls for every field and action", async () => {
      await mount(createApi());
      for (const key of Object.keys(LABELS) as ScopeKey[]) {
        for (const confirm of [false, true]) {
          const field = input(key, confirm);
          expect(field.tagName).toBe("INPUT");
          expect(field.getAttribute("tabindex")).not.toBe("-1");
        }
      }
      for (const button of [pauseButton(), resumeButton(), refreshButton()]) {
        expect(button.tagName).toBe("BUTTON");
        expect(button.getAttribute("tabindex")).not.toBe("-1");
        expect((button.textContent ?? "").trim().length).toBeGreaterThan(2);
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

    it("conveys the disabled state of blocked actions to assistive technology", async () => {
      const api = createApi({ risk: ok({ ...riskClear, halted: true, active_halts: ["operator_hold"] }) });
      await mount(api);
      await fillScope();
      expect(isDisabled(resumeButton())).toBe(true);
      expect(resumeButton().hasAttribute("disabled") || resumeButton().getAttribute("aria-disabled") === "true").toBe(true);
    });

    it("announces state and errors in live regions and keeps the blocking reason visible", async () => {
      const api = createApi({ risk: ok({ ...riskClear, halted: true, active_halts: ["operator_hold"] }) });
      await mount(api);
      await fillScope();
      expect(document.querySelector("[role='status'],[role='alert'],[aria-live]")).not.toBeNull();
      expect(visibleText()).toMatch(/halt|blocked|disabled|unavailable/i);
    });

    it("keeps focus reachable on the refresh and pause controls and ignores keys on blocked actions", async () => {
      const api = createApi({ orders: ok({ ...ordersReady, recovery_status: "UNKNOWN" }) });
      await mount(api);
      await fillScope();
      refreshButton().focus();
      expect(document.activeElement).toBe(refreshButton());
      pauseButton().focus();
      expect(document.activeElement).toBe(pauseButton());
      resumeButton().focus();
      fireEvent.keyDown(resumeButton(), { key: "Enter" });
      fireEvent.keyUp(resumeButton(), { key: "Enter" });
      fireEvent.keyDown(resumeButton(), { key: " " });
      await settle();
      expect(api.posts()).toEqual([]);
    });

    it("marks the busy state with aria-busy or a status message while a POST is pending", async () => {
      const api = createApi();
      await mount(api);
      await fillScope();
      api.hold();
      fireEvent.click(pauseButton());
      await waitFor(() => expect(api.posts()).toHaveLength(1));
      const busyMarked =
        document.querySelector("[aria-busy='true']") !== null
        || /pausing|working|pending|sending|please wait/i.test(visibleText());
      expect(busyMarked).toBe(true);
      await api.release();
    });
  });

  describe("source hygiene of the writer's wave33 files", () => {
    const sources = [viewSource, apiSource];

    it("never names an order lifecycle endpoint or a persistence or polling API", () => {
      for (const source of sources) {
        expect(source).not.toMatch(/\/orders\/recover|\/orders\/\$\{|\/submit|\/cancel|\/reconcile/);
        expect(source).not.toMatch(/localStorage|sessionStorage|indexedDB|setInterval/);
        expect(source).not.toMatch(/["'`]\/api\/orders["'`]/);
      }
    });

    it("never writes an environment literal other than the imported paper constant", () => {
      const joined = sources.join("\n");
      expect(joined).not.toMatch(/environment\s*:\s*["'](live|demo|LIVE|DEMO|PAPER)["']/);
      expect(joined).not.toMatch(/["'](live|demo)["']\s*as\s*const/);
    });
  });
});
