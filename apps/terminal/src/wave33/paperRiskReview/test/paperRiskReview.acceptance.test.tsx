/* Independent acceptance for PAPER-RISK-REVIEW-UI-001.
 *
 * The fake fetch uses the frozen PAPER-RISK-ASSESSMENT-API-001 preview schema. The
 * view is tested as an isolated component; no navigation or live execution is mounted.
 * OPEN CONTRACT GAP: the frozen API has no soft-breach field or reason code. These tests
 * require an honest hard-limit-only disclosure and do not synthesize a soft-risk warning.
 */
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { PaperRiskReviewView } from "../PaperRiskReviewView";

const ASSESSMENT_PATH = "/paper/risk/assessment/v1/preview";
const REQUEST = {
  scope: "paper",
  account_id: "acct-paper-0042",
  request_id: "request-paper-0042",
  attempt_id: "attempt-paper-0042",
  strategy_id: "strategy-alpha",
  venue_id: "venue-sim-01",
  instrument_id: "ES-202612",
  side: "BUY",
  quantity: "2",
  price: "100.25",
  contract_multiplier: "50",
  currency: "USD",
  price_source_ns: 1_700_000_000_000_000_000,
  price_ingest_ns: 1_700_000_000_010_000_000,
  price_source_id: "synthetic-mark-0042",
} as const;

const SUCCESS = {
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

const HARD_BREACH_CODES = [
  "buying_power_exceeded",
  "max_order_quantity_exceeded",
  "max_order_notional_exceeded",
  "max_projected_position_exceeded",
  "max_gross_exposure_exceeded",
  "max_net_exposure_exceeded",
  "max_leverage_exceeded",
  "max_daily_loss_exceeded",
] as const;

const INVALID_ALLOW_REASON_MESSAGE =
  "The assessment response could not be verified. Submission is blocked.";

type HttpReply = { status: number; body: unknown };
type Reply = HttpReply | "network" | "pending";
type Call = {
  path: string;
  method: string;
  body: unknown;
  rawBody: string | undefined;
};

function jsonResponse(reply: HttpReply): Response {
  return {
    ok: reply.status >= 200 && reply.status < 300,
    status: reply.status,
    statusText: reply.status >= 500 ? "Server Error" : "OK",
    json: async () => reply.body,
  } as unknown as Response;
}

function createFetch(replies: Reply[] = [{ status: 200, body: SUCCESS }]) {
  const calls: Call[] = [];
  const pending: Array<(response: Response) => void> = [];
  const fetcher = vi.fn((input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const path = String(input);
    const rawBody = typeof init?.body === "string" ? init.body : undefined;
    let body: unknown;
    if (rawBody !== undefined) {
      try {
        body = JSON.parse(rawBody);
      } catch {
        body = "UNPARSEABLE";
      }
    }
    calls.push({ path, method: (init?.method ?? "GET").toUpperCase(), body, rawBody });
    if (!path.includes(ASSESSMENT_PATH)) {
      return Promise.resolve(jsonResponse({ status: 404, body: { detail: "NOT_FOUND" } }));
    }
    const reply = replies.shift() ?? { status: 200, body: SUCCESS };
    if (reply === "network") return Promise.reject(new TypeError("provider-private-canary"));
    if (reply === "pending") return new Promise<Response>((resolve) => pending.push(resolve));
    return Promise.resolve(jsonResponse(reply));
  });
  return {
    fetcher: fetcher as unknown as typeof fetch,
    mock: fetcher,
    calls,
    pending,
    assessmentCalls: () => calls.filter((call) => call.path.includes(ASSESSMENT_PATH)),
    resolvePending: (reply: HttpReply) => pending.shift()?.(jsonResponse(reply)),
  };
}

type FakeApi = ReturnType<typeof createFetch>;

async function mount(api: FakeApi, onSubmit = vi.fn()) {
  vi.stubGlobal("fetch", api.fetcher);
  const view = render(
    <PaperRiskReviewView
      open
      request={REQUEST}
      onClose={vi.fn()}
      onSubmit={onSubmit}
    />,
  );
  await waitFor(() => expect(api.assessmentCalls().length).toBeGreaterThan(0));
  for (let attempt = 0; attempt < 6; attempt += 1) {
    await act(async () => {
      await Promise.resolve();
    });
  }
  expectNoSoftWarningUi();
  return { ...view, onSubmit };
}

function submitButton() {
  return screen.getByRole("button", { name: /submit/i });
}

function isDisabled(element: Element): boolean {
  return element.matches(":disabled") || element.getAttribute("aria-disabled") === "true";
}

function bodyText(): string {
  return document.body.textContent ?? "";
}

function expectNoSoftWarningUi() {
  expect(bodyText()).not.toMatch(/soft[- ]breach|soft limit exceeded|warning/i);
  expect(
    document.querySelectorAll(
      '[data-severity="warning"],[data-tone="warning"],[aria-label*="warning" i]',
    ),
  ).toHaveLength(0);
}

function expectNeutralPreviewDisclosure() {
  const disclosure = screen.getByText(
    /Hard-limit preview only; soft limits are not evaluated here/i,
  );
  expect(disclosure).toBeTruthy();
  expect(disclosure.getAttribute("role")).not.toBe("alert");
  expect(disclosure.className).not.toMatch(/warning|alert/i);
  expectNoSoftWarningUi();
}

function expectOnlyAssessmentCalls(api: FakeApi) {
  expect(api.calls.length).toBe(api.assessmentCalls().length);
  for (const call of api.calls) {
    expect(call.path).toContain(ASSESSMENT_PATH);
    expect(call.method).toBe("POST");
  }
}

function deny(reason: string, extra: Record<string, unknown> = {}) {
  return { ...SUCCESS, decision: "DENY", reason_codes: [reason], ...extra };
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("PAPER-RISK-REVIEW-UI-001 independent acceptance", () => {
  it("sends the exact PAPER request and shows neutral hard-limit-only scope information", async () => {
    const api = createFetch();
    const { onSubmit } = await mount(api);

    expect(api.assessmentCalls()).toHaveLength(1);
    expect(api.assessmentCalls()[0].method).toBe("POST");
    expect(api.assessmentCalls()[0].body).toEqual(REQUEST);
    expect(Object.keys(api.assessmentCalls()[0].body as object).sort()).toEqual(
      Object.keys(REQUEST).sort(),
    );
    expect(bodyText()).toContain(REQUEST.account_id);
    expect(bodyText()).toContain(REQUEST.venue_id);
    expect(bodyText()).toContain(REQUEST.instrument_id);
    expect(bodyText()).toContain(REQUEST.strategy_id);
    expectNeutralPreviewDisclosure();
    expect(isDisabled(submitButton())).toBe(false);
    expect(onSubmit).not.toHaveBeenCalled();
    expectOnlyAssessmentCalls(api);
  });

  it("hard breach denies submit and shows its bounded reason", async () => {
    const api = createFetch([{ status: 200, body: deny("max_order_notional_exceeded") }]);
    await mount(api);
    expect(isDisabled(submitButton())).toBe(true);
    expect(bodyText()).toMatch(/notional|hard limit|denied/i);
    expect(bodyText()).not.toContain("provider-private-canary");
    expectOnlyAssessmentCalls(api);
  });

  it("stale assessment denies submit with a visible stale reason", async () => {
    const api = createFetch([{ status: 200, body: deny("state_stale") }]);
    await mount(api);
    expect(isDisabled(submitButton())).toBe(true);
    expect(bodyText()).toMatch(/stale/i);
  });

  it("API failure disables submit and never renders arbitrary failure text", async () => {
    const api = createFetch([{ status: 503, body: { detail: "ASSESSMENT_UNAVAILABLE" } }]);
    await mount(api);
    expect(isDisabled(submitButton())).toBe(true);
    expect(bodyText()).toMatch(/unavailable|unable|assessment/i);
    expect(bodyText()).not.toContain("provider-private-canary");
  });

  it("network failure disables submit without echoing the rejected error", async () => {
    const api = createFetch(["network"]);
    await mount(api);
    expect(isDisabled(submitButton())).toBe(true);
    expect(bodyText()).toMatch(/unavailable|unable|assessment/i);
    expect(bodyText()).not.toContain("provider-private-canary");
  });

  it("wrong response scope fails closed even when the decision says ALLOW", async () => {
    const api = createFetch([
      { status: 403, body: { detail: "PAPER_SCOPE_REQUIRED" } },
    ]);
    await mount(api);
    expect(isDisabled(submitButton())).toBe(true);
    expect(bodyText()).toMatch(/scope could not be verified/i);
    expectOnlyAssessmentCalls(api);
  });

  it("unknown decision status fails closed with a reason", async () => {
    const api = createFetch([{ status: 200, body: { ...SUCCESS, decision: "PENDING" } }]);
    await mount(api);
    expect(isDisabled(submitButton())).toBe(true);
    expect(bodyText()).toMatch(/unknown|invalid|unavailable|assessment/i);
  });

  it.each(HARD_BREACH_CODES)(
    "rejects ALLOW paired with hard-breach reason %s without exposing the reason",
    async (reason) => {
      const api = createFetch([{ status: 200, body: { ...SUCCESS, reason_codes: [reason] } }]);
      const onSubmit = vi.fn();
      await mount(api, onSubmit);

      expect(isDisabled(submitButton())).toBe(true);
      expect(onSubmit).not.toHaveBeenCalled();
      expect(screen.getByRole("alert").textContent).toBe(INVALID_ALLOW_REASON_MESSAGE);
      expect(bodyText()).not.toContain(reason);
      expectNoSoftWarningUi();
      expectOnlyAssessmentCalls(api);
    },
  );

  it.each([
    ["empty", []],
    ["duplicate", ["within_hard_limits", "within_hard_limits"]],
    ["mixed", ["within_hard_limits", "max_daily_loss_exceeded"]],
  ] as const)("rejects an ALLOW with %s reason codes", async (_case, reasonCodes) => {
    const api = createFetch([{ status: 200, body: { ...SUCCESS, reason_codes: reasonCodes } }]);
    const onSubmit = vi.fn();
    await mount(api, onSubmit);

    expect(isDisabled(submitButton())).toBe(true);
    expect(onSubmit).not.toHaveBeenCalled();
    expect(screen.getByRole("alert").textContent).toBe(INVALID_ALLOW_REASON_MESSAGE);
    expect(bodyText()).not.toMatch(/max_daily_loss_exceeded|daily loss/i);
    expectNoSoftWarningUi();
    expectOnlyAssessmentCalls(api);
  });

  it.each([
    ["approval issuance", { ...SUCCESS, approval_issued: true }],
    ["order submission", { ...SUCCESS, order_submitted: true }],
  ])("fails closed if the preview claims %s", async (_claim, body) => {
    const api = createFetch([{ status: 200, body }]);
    const { onSubmit } = await mount(api);
    expect(isDisabled(submitButton())).toBe(true);
    expect(bodyText()).toMatch(/could not be verified|blocked/i);
    expect(onSubmit).not.toHaveBeenCalled();
    expectOnlyAssessmentCalls(api);
  });

  it("re-assesses immediately before invoking the scoped submit callback", async () => {
    const api = createFetch([
      { status: 200, body: SUCCESS },
      { status: 200, body: SUCCESS },
    ]);
    const onSubmit = vi.fn();
    await mount(api, onSubmit);

    fireEvent.click(submitButton());
    await waitFor(() => expect(onSubmit).toHaveBeenCalledTimes(1));
    expect(api.assessmentCalls()).toHaveLength(2);
    expect(api.assessmentCalls()[1].body).toEqual(REQUEST);
    expect(api.mock.mock.invocationCallOrder[1]).toBeLessThan(
      onSubmit.mock.invocationCallOrder[0],
    );
    expect(onSubmit).toHaveBeenCalledWith(REQUEST);
    expectNeutralPreviewDisclosure();
    expectOnlyAssessmentCalls(api);
  });

  it("does not invent a client TTL for an ALLOW; submission still requires a fresh ALLOW", async () => {
    const oldAllow = { ...SUCCESS, assessment_time_ns: 1 };
    const api = createFetch([
      { status: 200, body: oldAllow },
      { status: 200, body: SUCCESS },
    ]);
    const onSubmit = vi.fn();
    await mount(api, onSubmit);
    expect(isDisabled(submitButton())).toBe(false);
    expectNeutralPreviewDisclosure();

    fireEvent.click(submitButton());
    await waitFor(() => expect(onSubmit).toHaveBeenCalledTimes(1));
    expect(api.assessmentCalls()).toHaveLength(2);
    expect(api.mock.mock.invocationCallOrder[1]).toBeLessThan(
      onSubmit.mock.invocationCallOrder[0],
    );
  });

  it("blocks the order when the immediate pre-submit assessment changes to DENY", async () => {
    const api = createFetch([
      { status: 200, body: SUCCESS },
      { status: 200, body: deny("max_order_notional_exceeded") },
    ]);
    const onSubmit = vi.fn();
    await mount(api, onSubmit);

    fireEvent.click(submitButton());
    await waitFor(() => expect(api.assessmentCalls()).toHaveLength(2));
    await waitFor(() => expect(isDisabled(submitButton())).toBe(true));
    expect(onSubmit).not.toHaveBeenCalled();
    expect(bodyText()).toMatch(/notional|hard limit|denied/i);
    expectNoSoftWarningUi();
    expectOnlyAssessmentCalls(api);
  });

  it("blocks the order when the immediate pre-submit assessment is unavailable", async () => {
    const api = createFetch([
      { status: 200, body: SUCCESS },
      { status: 503, body: { detail: "ASSESSMENT_UNAVAILABLE" } },
    ]);
    const onSubmit = vi.fn();
    await mount(api, onSubmit);

    fireEvent.click(submitButton());
    await waitFor(() => expect(api.assessmentCalls()).toHaveLength(2));
    await waitFor(() => expect(isDisabled(submitButton())).toBe(true));
    expect(onSubmit).not.toHaveBeenCalled();
    expect(bodyText()).toMatch(/unavailable|unable|assessment/i);
    expectNoSoftWarningUi();
    expectOnlyAssessmentCalls(api);
  });

  it("single-flights a double click while pre-submit re-assessment is pending", async () => {
    const api = createFetch([
      { status: 200, body: SUCCESS },
      "pending",
    ]);
    const onSubmit = vi.fn();
    await mount(api, onSubmit);

    fireEvent.click(submitButton());
    await waitFor(() => expect(api.assessmentCalls()).toHaveLength(2));
    fireEvent.click(submitButton());
    fireEvent.click(submitButton());
    expect(api.assessmentCalls()).toHaveLength(2);
    expect(onSubmit).not.toHaveBeenCalled();

    api.resolvePending({ status: 200, body: SUCCESS });
    await waitFor(() => expect(onSubmit).toHaveBeenCalledTimes(1));
    expect(api.assessmentCalls()).toHaveLength(2);
    expect(onSubmit).toHaveBeenCalledWith(REQUEST);
    expectNeutralPreviewDisclosure();
    expectOnlyAssessmentCalls(api);
  });

  it("exposes no approval, override, or LIVE action", async () => {
    await mount(createFetch());
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).queryByRole("button", { name: /approve|override|live/i })).toBeNull();
    expect(within(dialog).queryByRole("radio", { name: /live/i })).toBeNull();
    expect(within(dialog).queryByRole("switch", { name: /live/i })).toBeNull();
  });

  it("keeps keyboard focus reachable, names state without color, and announces changes", async () => {
    const api = createFetch();
    await mount(api);
    const dialog = screen.getByRole("dialog");
    const heading = screen.getByRole("heading", { name: /paper risk review/i });
    expect(document.activeElement).toBe(heading);
    const controls = [...dialog.querySelectorAll<HTMLElement>("button,input,select,textarea,a[href]")];
    expect(controls.length).toBeGreaterThanOrEqual(2);
    for (const control of controls) {
      const tabindex = control.getAttribute("tabindex");
      expect(tabindex).not.toBe("-1");
      if (tabindex !== null) expect(Number(tabindex)).toBeLessThanOrEqual(0);
    }
    const buttons = controls.filter((control) => control.tagName === "BUTTON");
    const first = buttons[0];
    const last = buttons[buttons.length - 1];
    last.focus();
    fireEvent.keyDown(dialog, { key: "Tab" });
    expect(document.activeElement).toBe(first);
    first.focus();
    fireEvent.keyDown(dialog, { key: "Tab", shiftKey: true });
    expect(document.activeElement).toBe(last);

    const status = dialog.querySelector("[role='status'],[role='alert']");
    expect(status).not.toBeNull();
    expect((status?.textContent ?? "").trim().length).toBeGreaterThan(0);
    expect(status?.textContent).toMatch(/allows this order/i);
    const live = dialog.querySelector("[aria-live]");
    expect(live).not.toBeNull();
    expect(live?.getAttribute("aria-live")).toBe("assertive");
    expect((live?.textContent ?? "").trim()).toMatch(/fresh check/i);
  });

  it.skip("soft-breach warning — BLOCKED: API emits no soft-breach code (open item)", () => {
    // Keep the §4 criterion visible without inventing a response field or reason mapping.
  });
});
