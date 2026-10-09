/* Independent acceptance for PAPER-ORDER-TICKET-UI-001.
 *
 * Every request is captured through fake fetch. The risk-review component is mounted as shipped,
 * so only its immediate fresh ALLOW can reach order creation and dispatch.
 */
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { PaperOrderTicketView, type PaperOrderTicketViewProps } from "../PaperOrderTicketView";

const RISK_PATH = "/api/paper/risk/assessment/v1/preview";
const CREATE_PATH = "/api/orders";
const SUBMIT_PATH = "/api/orders/order-paper-0042/submit";
const CANARY = "private-provider-error-must-not-render";

const SCOPE = {
  environment: "paper",
  account_id: "acct-paper-0042",
  venue: "venue-sim-01",
  instrument_id: "ES-202612",
  strategy_id: "strategy-alpha",
  active: true,
} as const;

const INSTRUMENT = {
  native_contract_id: "ES-202612-native",
  contract_multiplier: "50",
  currency: "USD",
} as const;

const PRICE_EVIDENCE = {
  price: "100.25",
  price_source_ns: 1_700_000_000_000_000,
  price_ingest_ns: 1_700_000_000_000_010,
  price_source_id: "synthetic-mark-0042",
} as const;

const DEFAULT_PROPS: PaperOrderTicketViewProps = {
  trustedOperator: true,
  activePaperScope: SCOPE,
  instrument: INSTRUMENT,
  priceEvidence: PRICE_EVIDENCE,
};

const ALLOW = {
  scope: "paper",
  assessment_kind: "preview",
  decision: "ALLOW",
  assessment_time_ns: 1_700_000_000_020_000_000,
  policy_version: 1,
  policy_revisions: ["paper-policy-v1"],
  policy_digest: "a1".repeat(32),
  reason_codes: ["within_hard_limits"],
  evidence_digest: "b2".repeat(32),
  approval_issued: false,
  order_submitted: false,
} as const;

type HttpReply = { readonly status: number; readonly body: unknown };
type Reply = HttpReply | "network" | "badjson" | "pending";
type RequestCapture = {
  readonly path: string;
  readonly method: string;
  readonly rawBody: string | undefined;
  readonly body: unknown;
  readonly headers: Record<string, string>;
};

function snapshot(overrides: Record<string, unknown> = {}) {
  return {
    order_id: "order-paper-0042",
    state: "CREATED",
    version: 1,
    environment: "paper",
    account_id: SCOPE.account_id,
    venue: SCOPE.venue,
    instrument_id: SCOPE.instrument_id,
    strategy_id: SCOPE.strategy_id,
    filled_quantity: "0",
    venue_order_id: null,
    discrepancies: [],
    submit_attempted: false,
    cancel_attempted: false,
    ...overrides,
  };
}

function jsonResponse(reply: HttpReply): Response {
  return {
    ok: reply.status >= 200 && reply.status < 300,
    status: reply.status,
    statusText: reply.status >= 500 ? "Server Error" : reply.status === 403 ? "Forbidden" : "OK",
    json: async () => reply.body,
  } as unknown as Response;
}

function response(reply: Reply): Promise<Response> | Response {
  if (reply === "network") return Promise.reject(new TypeError(CANARY));
  if (reply === "pending") return new Promise<Response>(() => undefined);
  if (reply === "badjson") {
    return {
      ok: true,
      status: 200,
      statusText: "OK",
      json: async () => { throw new SyntaxError(CANARY); },
    } as unknown as Response;
  }
  return jsonResponse(reply);
}

type PendingReply = (value: Reply) => void;

function createFetch(options: {
  readonly risk?: readonly Reply[];
  readonly create?: readonly Reply[];
  readonly submit?: readonly Reply[];
} = {}) {
  const queues = {
    risk: [...(options.risk ?? [{ status: 200, body: ALLOW }])],
    create: [...(options.create ?? [{ status: 201, body: snapshot() }])],
    submit: [...(options.submit ?? [{ status: 200, body: snapshot({ state: "WORKING", version: 2, submit_attempted: true }) }])],
  } satisfies Record<string, Reply[]>;
  const calls: RequestCapture[] = [];
  const pending: PendingReply[] = [];
  const fetcher = vi.fn((input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const path = String(input);
    const rawBody = typeof init?.body === "string" ? init.body : undefined;
    let body: unknown;
    if (rawBody !== undefined) {
      try { body = JSON.parse(rawBody); } catch { body = "UNPARSEABLE"; }
    }
    const headers: Record<string, string> = {};
    const rawHeaders = init?.headers;
    if (rawHeaders instanceof Headers) rawHeaders.forEach((value, key) => { headers[key.toLowerCase()] = value; });
    else if (Array.isArray(rawHeaders)) rawHeaders.forEach(([key, value]) => { headers[key.toLowerCase()] = value; });
    else if (rawHeaders) Object.entries(rawHeaders).forEach(([key, value]) => { headers[key.toLowerCase()] = String(value); });
    calls.push({ path, method: (init?.method ?? "GET").toUpperCase(), rawBody, body, headers });

    const queue = path === RISK_PATH
      ? queues.risk
      : path === CREATE_PATH
        ? queues.create
        : path === SUBMIT_PATH
          ? queues.submit
          : null;
    if (queue === null) return Promise.resolve(jsonResponse({ status: 404, body: { detail: "NOT_FOUND" } }));
    const reply = queue.shift() ?? { status: 200, body: ALLOW };
    if (reply === "pending") {
      return new Promise<Response>((resolve) => {
        pending.push((next) => {
          const result = response(next);
          if (result instanceof Promise) void result.then(resolve);
          else resolve(result);
        });
      });
    }
    const result = response(reply);
    return result instanceof Promise ? result : Promise.resolve(result);
  });

  return {
    fetcher: fetcher as unknown as typeof fetch,
    calls,
    riskCalls: () => calls.filter((call) => call.path === RISK_PATH),
    orderMutations: () => calls.filter((call) => call.path === CREATE_PATH || call.path.startsWith("/api/orders/")),
    resolvePending: (reply: Reply) => pending.shift()?.(reply),
  };
}

type FakeFetch = ReturnType<typeof createFetch>;

async function mountTicket(api: FakeFetch, props: PaperOrderTicketViewProps = DEFAULT_PROPS) {
  vi.stubGlobal("fetch", api.fetcher);
  const view = render(<PaperOrderTicketView {...props} />);
  await screen.findByRole("region", { name: /paper order ticket/i });
  return view;
}

function fillQuantity(quantity = "2") {
  fireEvent.change(screen.getByLabelText(/quantity/i), { target: { value: quantity } });
}

async function openRiskReview(api: FakeFetch) {
  fillQuantity();
  const review = screen.getByRole("button", { name: /review paper order/i });
  expect((review as HTMLButtonElement).disabled).toBe(false);
  fireEvent.click(review);
  await screen.findByRole("dialog", { name: /paper risk review/i });
  await waitFor(() => expect(api.riskCalls()).toHaveLength(2));
}

function expectOnlyTicketMutations(api: FakeFetch) {
  const mutations = api.calls.filter((call) => call.method !== "GET");
  expect(mutations.every((call) =>
    call.path === RISK_PATH || call.path === CREATE_PATH || call.path === SUBMIT_PATH,
  )).toBe(true);
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("PAPER-ORDER-TICKET-UI-001 independent acceptance", () => {
  it.each([
    ["missing trusted-operator assertion", { ...DEFAULT_PROPS, trustedOperator: undefined }],
    ["untrusted operator", { ...DEFAULT_PROPS, trustedOperator: false }],
    ["missing active scope", { ...DEFAULT_PROPS, activePaperScope: null }],
    ["inactive paper scope", { ...DEFAULT_PROPS, activePaperScope: { ...SCOPE, active: false } }],
    ["non-paper scope", { ...DEFAULT_PROPS, activePaperScope: { ...SCOPE, environment: "demo" } }],
    ["incomplete scope", { ...DEFAULT_PROPS, activePaperScope: { ...SCOPE, instrument_id: "" } }],
  ] as const)("hides the ticket and CTA for %s", async (_name, props) => {
    const api = createFetch();
    vi.stubGlobal("fetch", api.fetcher);
    render(<PaperOrderTicketView {...(props as unknown as PaperOrderTicketViewProps)} />);
    expect(screen.queryByRole("region", { name: /paper order ticket/i })).toBeNull();
    expect(screen.queryByRole("button", { name: /review paper order/i })).toBeNull();
    expect(api.calls).toHaveLength(0);
  });

  it("shows an enabled review CTA only for the trusted operator's exact active PAPER scope", async () => {
    const api = createFetch();
    await mountTicket(api);
    fillQuantity();
    expect((screen.getByRole("button", { name: /review paper order/i }) as HTMLButtonElement).disabled).toBe(false);
    expect(screen.getByText(/environment: PAPER \(fixed\)/i)).toBeTruthy();
    expectOnlyTicketMutations(api);
  });

  it("hard-binds the exact paper order payload and permits no provider, URL, or environment override", async () => {
    const maliciousProps = {
      ...DEFAULT_PROPS,
      activePaperScope: { ...SCOPE, environment: "paper", provider: "live-broker", base_url: "https://evil.invalid" },
      instrument: { ...INSTRUMENT, environment: "live", provider: "other-provider", endpoint: "https://evil.invalid" },
    } as unknown as PaperOrderTicketViewProps;
    const api = createFetch();
    await mountTicket(api, maliciousProps);
    fillQuantity();

    const selects = [...document.querySelectorAll("select")];
    expect(selects.map((select) => [...select.options].map((option) => option.value)).flat())
      .not.toContain("live");
    expect(selects.flatMap((select) => [...select.options].map((option) => option.value)))
      .not.toContain("demo");
    expect(screen.queryByLabelText(/environment|provider|endpoint|url/i)).toBeNull();

    fireEvent.click(screen.getByRole("button", { name: /review paper order/i }));
    await screen.findByRole("dialog", { name: /paper risk review/i });
    await waitFor(() => expect(api.riskCalls()).toHaveLength(2));
    fireEvent.click(screen.getByRole("button", { name: /^submit$/i }));
    await waitFor(() => expect(api.orderMutations()).toHaveLength(2));

    const create = api.calls.find((call) => call.method === "POST" && call.path === CREATE_PATH);
    expect(create?.body).toEqual({
      environment: "paper",
      account_id: SCOPE.account_id,
      venue: SCOPE.venue,
      instrument_id: SCOPE.instrument_id,
      native_contract_id: INSTRUMENT.native_contract_id,
      side: "BUY",
      quantity: "2",
      order_type: "MARKET",
      time_in_force: "DAY",
      intent_idempotency_key: expect.any(String),
      attempt: 1,
      strategy_id: SCOPE.strategy_id,
      risk_policy_digest: ALLOW.policy_digest,
    });
    expect(Object.keys(create?.body as object).sort()).toEqual([
      "account_id", "attempt", "environment", "instrument_id", "intent_idempotency_key",
      "native_contract_id", "order_type", "quantity", "risk_policy_digest", "side",
      "strategy_id", "time_in_force", "venue",
    ].sort());
    expect(JSON.stringify(create?.body)).not.toMatch(/live|demo|provider|https?:/i);
    expectOnlyTicketMutations(api);
  });

  it.each([
    ["stale assessment", { ...ALLOW, decision: "DENY", reason_codes: ["price_stale"] }],
    ["hard denial", { ...ALLOW, decision: "DENY", reason_codes: ["max_daily_loss_exceeded"] }],
    ["ALLOW paired with a hard-denial reason", { ...ALLOW, reason_codes: ["max_daily_loss_exceeded"] }],
    ["ALLOW with an empty reason list", { ...ALLOW, reason_codes: [] }],
    ["ALLOW with a duplicate reason", { ...ALLOW, reason_codes: ["within_hard_limits", "within_hard_limits"] }],
    ["unknown decision", { ...ALLOW, decision: "UNKNOWN" }],
  ] as const)("does not create or dispatch an order without a fresh valid ALLOW: %s", async (_case, freshReply) => {
    const api = createFetch({ risk: [
      { status: 200, body: ALLOW },
      { status: 200, body: ALLOW },
      { status: 200, body: freshReply },
    ] });
    await mountTicket(api);
    await openRiskReview(api);
    fireEvent.click(screen.getByRole("button", { name: /^submit$/i }));
    await waitFor(() => expect(api.riskCalls()).toHaveLength(3));
    await waitFor(() => expect((screen.getByRole("button", { name: /^submit$/i }) as HTMLButtonElement).disabled).toBe(true));
    expect(api.orderMutations()).toHaveLength(0);
    expect(api.calls.some((call) => call.path === CREATE_PATH)).toBe(false);
    expectOnlyTicketMutations(api);
  });

  it.each([
    [403, "ACTIVATION_DENIED", "Paper dispatch is not authorized for this scope. Verify the active paper scope."],
    [409, "IDEMPOTENCY_CONFLICT", "This order key conflicts with a recorded request. Review order status before retrying."],
    [422, "INVALID_QUANTITY", "Enter a positive quantity within the supported precision and range."],
  ] as const)("maps HTTP %s to a fixed actionable field message", async (status, detail, expected) => {
    const api = createFetch({
      risk: [
        { status: 200, body: ALLOW },
        { status: 200, body: ALLOW },
        { status: 200, body: ALLOW },
      ],
      create: [{ status, body: { detail, provider_message: CANARY } }],
    });
    await mountTicket(api);
    await openRiskReview(api);
    fireEvent.click(screen.getByRole("button", { name: /^submit$/i }));
    await waitFor(() => expect(api.calls.some((call) => call.path === CREATE_PATH)).toBe(true));

    expect(screen.getByRole("alert").textContent).toBe(expected);
    expect(document.body.textContent).not.toContain(CANARY);
    expect(api.calls.some((call) => call.path === SUBMIT_PATH)).toBe(false);
    expectOnlyTicketMutations(api);
  });

  it("does not dispatch when the post-create risk recheck returns DENY", async () => {
    const api = createFetch({ risk: [
      { status: 200, body: ALLOW },
      { status: 200, body: ALLOW },
      { status: 200, body: ALLOW },
      { status: 200, body: { ...ALLOW, decision: "DENY", reason_codes: ["max_daily_loss_exceeded"] } },
    ] });
    await mountTicket(api);
    await openRiskReview(api);
    fireEvent.click(screen.getByRole("button", { name: /^submit$/i }));

    await waitFor(() => expect(api.calls.filter((call) => call.path === CREATE_PATH)).toHaveLength(1));
    await waitFor(() => expect(api.riskCalls()).toHaveLength(4));
    expect(api.calls.filter((call) => call.path === SUBMIT_PATH)).toHaveLength(0);
    expect(api.orderMutations()).toHaveLength(1);
    expectOnlyTicketMutations(api);
  });

  it("single-flights a double click into one create and one dispatch after the fresh ALLOW", async () => {
    const api = createFetch({ risk: [
      { status: 200, body: ALLOW },
      { status: 200, body: ALLOW },
      "pending",
    ] });
    await mountTicket(api);
    await openRiskReview(api);

    const submit = screen.getByRole("button", { name: /^submit$/i });
    fireEvent.click(submit);
    await waitFor(() => expect(api.riskCalls()).toHaveLength(3));
    fireEvent.click(submit);
    fireEvent.click(submit);
    expect(api.riskCalls()).toHaveLength(3);
    expect(api.orderMutations()).toHaveLength(0);

    api.resolvePending({ status: 200, body: ALLOW });
    await waitFor(() => expect(api.calls.filter((call) => call.path === CREATE_PATH)).toHaveLength(1));
    await waitFor(() => expect(api.calls.filter((call) => call.path === SUBMIT_PATH)).toHaveLength(1));
    expect(api.calls.find((call) => call.path.startsWith("/api/orders/"))?.path)
      .toBe("/api/orders/" + snapshot().order_id + "/submit");
    const calls = api.calls.map((call) => call.path);
    const createIndex = calls.findIndex((path) => path === CREATE_PATH);
    const riskIndices = calls.flatMap((path, index) => path === RISK_PATH ? [index] : []);
    const submitIndex = calls.findIndex((path) => path === SUBMIT_PATH);
    const preCreateRiskIndex = riskIndices.filter((index) => index < createIndex).at(-1);
    const postCreateRiskIndex = riskIndices.find((index) => index > createIndex);
    expect(preCreateRiskIndex).toBe(createIndex - 1);
    expect(postCreateRiskIndex).toBe(createIndex + 1);
    expect(submitIndex).toBe(postCreateRiskIndex! + 1);
    expectOnlyTicketMutations(api);
  });
});
