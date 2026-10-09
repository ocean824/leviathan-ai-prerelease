import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  createPaperActivityClient,
  MAX_DECIMAL_TEXT_LENGTH,
  parsePaperActivityPage,
} from "../wave28/api/paperActivity";
import type { PaperActivityPageV1 } from "../wave28/api/paperActivity";
import { PaperActivityView } from "../wave28/views/PaperActivityView";
import {
  haltedPaperRiskStatus,
  ORDER_STATUS_PATH,
  PAPER_ACTIVITY_PATH,
  paperActivityResponse,
  paperOrderStatus,
  RISK_STATUS_PATH,
} from "./fixtures/paperActivity";

const NOW = Date.parse("2026-10-06T15:03:00Z");

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function defaultFetcher(overrides: {
  activity?: unknown;
  activityStatus?: number;
  orderStatus?: unknown;
  orderStatusCode?: number;
  riskStatus?: unknown;
  riskStatusCode?: number;
} = {}): ReturnType<typeof vi.fn<typeof fetch>> {
  return vi.fn<typeof fetch>(async (input) => {
    const url = String(input);
    if (url.startsWith(PAPER_ACTIVITY_PATH)) {
      return jsonResponse(overrides.activity ?? paperActivityResponse, overrides.activityStatus ?? 200);
    }
    if (url === ORDER_STATUS_PATH) {
      return jsonResponse(overrides.orderStatus ?? paperOrderStatus, overrides.orderStatusCode ?? 200);
    }
    if (url === RISK_STATUS_PATH) {
      return jsonResponse(overrides.riskStatus ?? haltedPaperRiskStatus, overrides.riskStatusCode ?? 200);
    }
    throw new Error(`Unexpected test URL: ${url}`);
  });
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((resolvePromise) => { resolve = resolvePromise; });
  return { promise, resolve };
}

function pageFor(accountId: string, orderId: string, netQuantity: string, filledQuantity = "1.75") {
  const page = structuredClone(paperActivityResponse);
  page.account_id = accountId;
  const order = page.items.find((item) => item.kind === "ORDER");
  if (order?.kind === "ORDER" && "order" in order && order.order !== undefined) {
    order.order.order_id = orderId;
    order.order.filled_quantity = filledQuantity;
  }
  page.net_filled_units[0]!.quantity = netQuantity;
  return page;
}

function snapshotStorage(storage: Storage): string[] {
  return Array.from({ length: storage.length }, (_, index) => {
    const key = storage.key(index);
    return key === null ? "" : `${key}=${storage.getItem(key) ?? ""}`;
  }).sort();
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
});

describe("PAPER-ACTIVITY-UI-001 independent acceptance", () => {
  it("accepts the recorded OMS wire fixture without normalizing its decimal strings", () => {
    const parsed = parsePaperActivityPage(paperActivityResponse);
    expect(parsed).not.toBeNull();
    expect(parsed?.net_filled_units[0]?.quantity).toBe("-1.23");
  });

  it("matches OMS decimal bounds, nonnegative replacement fields, and signed SELL net units", () => {
    expect(MAX_DECIMAL_TEXT_LENGTH).toBe(128);

    const signedSellPage = structuredClone(paperActivityResponse);
    const sellOrder = signedSellPage.items.find((item) => item.kind === "ORDER");
    const sellFill = signedSellPage.items.find((item) => item.kind === "FILL");
    if (sellOrder?.kind === "ORDER" && "order" in sellOrder && sellOrder.order) {
      sellOrder.order.side = "SELL";
    }
    if (sellFill?.kind === "FILL" && "fill" in sellFill && sellFill.fill) {
      sellFill.fill.side = "SELL";
    }
    signedSellPage.net_filled_units[0]!.quantity = "-1.23";
    expect(parsePaperActivityPage(signedSellPage)?.net_filled_units[0]?.quantity).toBe("-1.23");

    const exponentBoundary = structuredClone(paperActivityResponse);
    const boundaryFill = exponentBoundary.items.find((item) => item.kind === "FILL");
    if (boundaryFill?.kind === "FILL" && "fill" in boundaryFill && boundaryFill.fill) {
      boundaryFill.fill.price = `0.${"0".repeat(37)}1`;
    }
    expect(parsePaperActivityPage(exponentBoundary)).not.toBeNull();

    const exponentOutOfBounds = structuredClone(paperActivityResponse);
    const outOfBoundsFill = exponentOutOfBounds.items.find((item) => item.kind === "FILL");
    if (outOfBoundsFill?.kind === "FILL" && "fill" in outOfBoundsFill && outOfBoundsFill.fill) {
      outOfBoundsFill.fill.price = `0.${"0".repeat(38)}1`;
    }
    expect(parsePaperActivityPage(exponentOutOfBounds)).toBeNull();

    const excessSignificantDigits = structuredClone(paperActivityResponse);
    const impreciseFill = excessSignificantDigits.items.find((item) => item.kind === "FILL");
    if (impreciseFill?.kind === "FILL" && "fill" in impreciseFill && impreciseFill.fill) {
      impreciseFill.fill.price = "12345678901234567890123456789012345";
    }
    expect(parsePaperActivityPage(excessSignificantDigits)).toBeNull();

    const validBust = structuredClone(paperActivityResponse) as unknown as PaperActivityPageV1;
    const bust = validBust.items.find((item) => item.kind === "FILL_CORRECTION");
    if (bust?.kind === "FILL_CORRECTION" && "correction" in bust && bust.correction) {
      bust.correction.revised_quantity = "0";
      bust.correction.revised_price = null;
      bust.correction.revised_commission = "0";
    }
    expect(parsePaperActivityPage(validBust)).not.toBeNull();

    const invalidReplacementPairs = [
      { revised_quantity: "-0.25", revised_price: "100.25" },
      { revised_quantity: "0", revised_price: "100.25" },
      { revised_quantity: "1", revised_price: null },
    ];
    for (const pair of invalidReplacementPairs) {
      const invalidReplacement = structuredClone(paperActivityResponse);
      const correction = invalidReplacement.items.find((item) => item.kind === "FILL_CORRECTION");
      if (correction?.kind === "FILL_CORRECTION" && "correction" in correction && correction.correction) {
        Object.assign(correction.correction, pair);
      }
      expect(parsePaperActivityPage(invalidReplacement)).toBeNull();
    }

    const negativeCommissions = ["fill", "replacement"] as const;
    for (const field of negativeCommissions) {
      const invalidCommission = structuredClone(paperActivityResponse);
      if (field === "fill") {
        const fill = invalidCommission.items.find((item) => item.kind === "FILL");
        if (fill?.kind === "FILL" && "fill" in fill && fill.fill) fill.fill.commission = "-0.01";
      } else {
        const correction = invalidCommission.items.find((item) => item.kind === "FILL_CORRECTION");
        if (correction?.kind === "FILL_CORRECTION" && "correction" in correction && correction.correction) {
          correction.correction.revised_commission = "-0.01";
        }
      }
      expect(parsePaperActivityPage(invalidCommission)).toBeNull();
    }
  });

  it("accepts the maximum safe high-water sequence and rejects the next integer", async () => {
    const emptyPage = { ...paperActivityResponse, items: [], net_filled_units: [] };
    const atMaximum = vi.fn<typeof fetch>(async () => jsonResponse({
      ...emptyPage,
      high_water_sequence: Number.MAX_SAFE_INTEGER,
    }));
    const aboveMaximum = vi.fn<typeof fetch>(async () => jsonResponse({
      ...emptyPage,
      high_water_sequence: Number.MAX_SAFE_INTEGER + 1,
    }));

    await expect(createPaperActivityClient(atMaximum).getActivity()).resolves.toMatchObject({ ok: true });
    await expect(createPaperActivityClient(aboveMaximum).getActivity()).resolves.toEqual({
      ok: false,
      error: "INVALID_RESPONSE",
    });
  });

  it("accepts 100 distinct net groups and rejects group 101 as an invalid response", async () => {
    const emptyPage = { ...paperActivityResponse, items: [], high_water_sequence: 0 };
    const netGroups = (count: number) => Array.from({ length: count }, (_, index) => ({
      venue: `VENUE-${index}`,
      instrument_id: "SYNTH-01",
      quantity: "0",
    }));
    const atCap = vi.fn<typeof fetch>(async () => jsonResponse({
      ...emptyPage,
      net_filled_units: netGroups(100),
    }));
    const aboveCap = vi.fn<typeof fetch>(async () => jsonResponse({
      ...emptyPage,
      net_filled_units: netGroups(101),
    }));

    await expect(createPaperActivityClient(atCap).getActivity()).resolves.toMatchObject({ ok: true });
    await expect(createPaperActivityClient(aboveCap).getActivity()).resolves.toEqual({
      ok: false,
      error: "INVALID_RESPONSE",
    });
  });

  it("maps the fixed oversized-activity 413 code without retaining server detail", async () => {
    const fetcher = vi.fn<typeof fetch>(async () => jsonResponse({
      error: { code: "ACTIVITY_TOO_LARGE", detail: "ACTIVITY_TOO_LARGE_SECRET_CANARY" },
    }, 413));

    const result = await createPaperActivityClient(fetcher).getActivity();
    expect(result).toEqual({ ok: false, error: "ACTIVITY_TOO_LARGE" });
    expect(JSON.stringify(result)).not.toContain("ACTIVITY_TOO_LARGE_SECRET_CANARY");
  });

  it("stays PAPER-only and read-only, shows HALT, preserves exact net units and separates corrections", async () => {
    const fetcher = defaultFetcher();
    render(<PaperActivityView fetcher={fetcher} clock={() => NOW} />);

    expect(await screen.findByText("HALT REPORTED")).toBeTruthy();
    expect(screen.getByText("PAPER ONLY")).toBeTruthy();
    expect(screen.getByText("LIVE DISABLED")).toBeTruthy();
    expect(screen.getByText(/operator_halt/)).toBeTruthy();
    expect(screen.getByText("OMS net filled units")).toBeTruthy();
    expect(screen.getByText("OMS ledger, not broker-confirmed. No cost basis or valuation is calculated.")).toBeTruthy();

    const activityPanel = screen.getByRole("region", { name: "Paper ledger activity" });
    expect(within(activityPanel).getByText("UNVERIFIED")).toBeTruthy();
    expect(within(activityPanel).getByText(/Source timestamp unavailable/)).toBeTruthy();
    expect(within(activityPanel).getByText("Response receipt time is not source freshness.")).toBeTruthy();

    const netTable = screen.getByRole("table", { name: "OMS net filled units by venue and instrument" });
    expect(within(netTable).getByText("-1.23", { exact: true })).toBeTruthy();

    const ledger = screen.getByRole("table", { name: "OMS paper ledger activity" });
    const rows = Array.from(ledger.querySelectorAll("tbody tr"));
    expect(rows).toHaveLength(3);
    expect(rows[1]?.textContent).toContain("FILL");
    expect(rows[1]?.textContent).toContain("paper-exec-001");
    expect(rows[1]?.textContent).toContain("1.25");
    expect(rows[2]?.textContent).toContain("FILL CORRECTION");
    expect(rows[2]?.textContent).toContain("paper-correction-001");
    expect(rows[2]?.textContent).toContain("1");

    expect(document.querySelector("form")).toBeNull();
    expect(screen.queryByRole("button", { name: /submit|cancel|amend|activate|trade|place order|lift halt|change halt/i })).toBeNull();
    expect(screen.queryByText(/Market value|mark-to-market|buying power|P&L|Cost basis:/i)).toBeNull();

    const requests = fetcher.mock.calls.map(([input, init]) => ({ url: String(input), init }));
    expect(requests.map(({ url }) => url.split("?")[0]).sort()).toEqual([
      PAPER_ACTIVITY_PATH,
      ORDER_STATUS_PATH,
      RISK_STATUS_PATH,
    ].sort());
    for (const { url, init } of requests) {
      expect(init?.method).toBe("GET");
      expect(init?.body).toBeUndefined();
      expect(url).not.toMatch(/[?&](?:account|environment|project)=/i);
    }
    const activityUrl = requests.find(({ url }) => url.startsWith(PAPER_ACTIVITY_PATH))?.url;
    expect(new URL(activityUrl ?? "", "http://localhost").searchParams.get("limit")).toBe("50");
    expect(new URL(activityUrl ?? "", "http://localhost").searchParams.has("cursor")).toBe(false);
  });

  it("uses API source timestamps for status freshness and never upgrades untimestamped data", async () => {
    const noTimestamps = defaultFetcher({
      orderStatus: { ...paperOrderStatus, as_of: undefined },
      riskStatus: { ...haltedPaperRiskStatus, as_of: undefined },
    });
    const firstRender = render(<PaperActivityView fetcher={noTimestamps} clock={() => NOW} />);

    expect(await screen.findByText("HALT REPORTED")).toBeTruthy();
    const risk = screen.getByRole("region", { name: "Risk and HALT status" });
    const order = screen.getByRole("region", { name: "Order gateway status" });
    const activity = screen.getByRole("region", { name: "Paper ledger activity" });
    expect(within(risk).getByText("UNVERIFIED")).toBeTruthy();
    expect(within(order).getByText("UNVERIFIED")).toBeTruthy();
    expect(within(activity).getByText("UNVERIFIED")).toBeTruthy();
    firstRender.unmount();

    const freshFetcher = defaultFetcher();
    const { unmount } = render(<PaperActivityView fetcher={freshFetcher} clock={() => NOW} />);
    expect(await screen.findByText("HALT REPORTED")).toBeTruthy();
    expect(within(screen.getByRole("region", { name: "Risk and HALT status" }))
      .getByText("Source timestamp present; freshness is evaluated from API time.")).toBeTruthy();
    expect(within(screen.getByRole("region", { name: "Order gateway status" }))
      .getByText("Source timestamp present; freshness is evaluated from API time.")).toBeTruthy();
    unmount();
  });

  it("shows old source timestamps as stale while activity remains freshness-unverified", async () => {
    const oldTimestamp = NOW - 10_000;
    const fetcher = defaultFetcher({
      orderStatus: { ...paperOrderStatus, as_of: oldTimestamp },
      riskStatus: { ...haltedPaperRiskStatus, as_of: oldTimestamp },
    });
    render(<PaperActivityView fetcher={fetcher} clock={() => NOW} />);

    expect(await screen.findByText("HALT REPORTED")).toBeTruthy();
    expect(within(screen.getByRole("region", { name: "Order gateway status" })).getByText("STALE")).toBeTruthy();
    expect(within(screen.getByRole("region", { name: "Risk and HALT status" })).getByText("STALE")).toBeTruthy();
    expect(within(screen.getByRole("region", { name: "Paper ledger activity" })).getByText("UNVERIFIED")).toBeTruthy();
  });

  it("maps an activity 401 to the fixed operator-session message without showing response detail", async () => {
    const secretDetail = "401_SECRET_RESPONSE_CANARY";
    const fetcher = defaultFetcher({
      activity: { error: { code: "PRINCIPAL_UNTRUSTED", detail: secretDetail } },
      activityStatus: 401,
    });
    render(<PaperActivityView fetcher={fetcher} clock={() => NOW} />);

    const activity = screen.getByRole("region", { name: "Paper ledger activity" });
    expect((await within(activity).findByRole("alert")).textContent).toContain("operator session unavailable");
    expect(document.body.textContent).not.toContain(secretDetail);
  });

  it("does not render, log, store, or hash free-text/raw response fields", async () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => undefined);
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    const error = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const localBefore = snapshotStorage(window.localStorage);
    const sessionBefore = snapshotStorage(window.sessionStorage);
    const fetcher = defaultFetcher();
    render(<PaperActivityView fetcher={fetcher} clock={() => NOW} />);

    expect(await screen.findByText("HALT REPORTED")).toBeTruthy();
    const visible = `${document.body.textContent ?? ""}\n${document.body.innerHTML}`;
    for (const canary of ["LESSON19_FREE_TEXT_CANARY", "LESSON19_SECRET_CANARY", "ORDER_STATUS_RAW_CANARY", "RISK_STATUS_RAW_CANARY"]) {
      expect(visible).not.toContain(canary);
      expect(JSON.stringify([...log.mock.calls, ...warn.mock.calls, ...error.mock.calls])).not.toContain(canary);
    }
    expect(visible).not.toMatch(/\b[a-f0-9]{64}\b/i);
    expect(snapshotStorage(window.localStorage)).toEqual(localBefore);
    expect(snapshotStorage(window.sessionStorage)).toEqual(sessionBefore);
    expect(fetcher.mock.calls.every(([, init]) => init?.body === undefined)).toBe(true);
  });

  it("drops stale success completions independently for activity, order status and risk status", async () => {
    const firstActivity = deferred<Response>();
    const secondActivity = deferred<Response>();
    const firstOrder = deferred<Response>();
    const secondOrder = deferred<Response>();
    const firstRisk = deferred<Response>();
    const secondRisk = deferred<Response>();
    const callsByRoute: Record<string, number> = {};
    const fetcher = vi.fn<typeof fetch>((input) => {
      const route = String(input).split("?")[0] ?? "";
      callsByRoute[route] = (callsByRoute[route] ?? 0) + 1;
      const callNumber = callsByRoute[route];
      if (route === PAPER_ACTIVITY_PATH) return callNumber === 1 ? firstActivity.promise : secondActivity.promise;
      if (route === ORDER_STATUS_PATH) return callNumber === 1 ? firstOrder.promise : secondOrder.promise;
      if (route === RISK_STATUS_PATH) return callNumber === 1 ? firstRisk.promise : secondRisk.promise;
      throw new Error(`Unexpected route ${route}`);
    });
    render(<PaperActivityView fetcher={fetcher} clock={() => NOW} />);
    await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(3));
    fireEvent.change(screen.getByRole("combobox", { name: "Records per page" }), { target: { value: "25" } });
    await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(6));

    secondActivity.resolve(jsonResponse(pageFor("current-account", "current-order", "-2.75")));
    secondOrder.resolve(jsonResponse({ ...paperOrderStatus, recovery_status: "READY" }));
    secondRisk.resolve(jsonResponse({ ...haltedPaperRiskStatus, active_halts: ["omega_kill_signal"] }));
    const activityPanel = screen.getByRole("region", { name: "Paper ledger activity" });
    await waitFor(() => expect(activityPanel.textContent).toContain("current-account"));
    expect(screen.getByText("current-order")).toBeTruthy();
    expect(screen.getByText(/omega_kill_signal/)).toBeTruthy();

    firstActivity.resolve(jsonResponse(pageFor("stale-account", "stale-order", "-99")));
    firstOrder.resolve(jsonResponse({ ...paperOrderStatus, recovery_status: "FAILED" }));
    firstRisk.resolve(jsonResponse({ ...haltedPaperRiskStatus, halted: false, active_halts: [] }));
    await waitFor(() => {
      expect(activityPanel.textContent).toContain("current-account");
      expect(screen.getByText("current-order")).toBeTruthy();
      expect(screen.getByText(/omega_kill_signal/)).toBeTruthy();
      expect(activityPanel.textContent).not.toContain("stale-account");
      expect(screen.queryByText("stale-order")).toBeNull();
      expect(screen.queryByText("FAILED")).toBeNull();
    });
  });

  it("drops stale error completions without replacing newer pane data", async () => {
    const firstActivity = deferred<Response>();
    const secondActivity = deferred<Response>();
    const firstOrder = deferred<Response>();
    const secondOrder = deferred<Response>();
    const firstRisk = deferred<Response>();
    const secondRisk = deferred<Response>();
    const callsByRoute: Record<string, number> = {};
    const fetcher = vi.fn<typeof fetch>((input) => {
      const route = String(input).split("?")[0] ?? "";
      callsByRoute[route] = (callsByRoute[route] ?? 0) + 1;
      const callNumber = callsByRoute[route];
      if (route === PAPER_ACTIVITY_PATH) return callNumber === 1 ? firstActivity.promise : secondActivity.promise;
      if (route === ORDER_STATUS_PATH) return callNumber === 1 ? firstOrder.promise : secondOrder.promise;
      if (route === RISK_STATUS_PATH) return callNumber === 1 ? firstRisk.promise : secondRisk.promise;
      throw new Error(`Unexpected route ${route}`);
    });
    render(<PaperActivityView fetcher={fetcher} clock={() => NOW} />);
    await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(3));
    fireEvent.change(screen.getByRole("combobox", { name: "Records per page" }), { target: { value: "25" } });
    await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(6));

    secondActivity.resolve(jsonResponse(pageFor("current-account", "current-order", "-2.75")));
    secondOrder.resolve(jsonResponse({ ...paperOrderStatus, recovery_status: "READY" }));
    secondRisk.resolve(jsonResponse({ ...haltedPaperRiskStatus, active_halts: ["omega_kill_signal"] }));
    const activityPanel = screen.getByRole("region", { name: "Paper ledger activity" });
    await waitFor(() => expect(activityPanel.textContent).toContain("current-account"));
    expect(screen.getByText("current-order")).toBeTruthy();
    expect(screen.getByText(/omega_kill_signal/)).toBeTruthy();

    firstActivity.resolve(jsonResponse({ error: { code: "PRINCIPAL_UNTRUSTED", detail: "STALE_ERROR_SECRET" } }, 401));
    firstOrder.resolve(jsonResponse({ detail: "STALE_ORDER_ERROR_SECRET" }, 503));
    firstRisk.resolve(jsonResponse({ detail: "STALE_RISK_ERROR_SECRET" }, 503));
    await waitFor(() => {
      expect(activityPanel.textContent).toContain("current-account");
      expect(screen.getByText("current-order")).toBeTruthy();
      expect(screen.getByText(/omega_kill_signal/)).toBeTruthy();
      expect(screen.queryByText("operator session unavailable")).toBeNull();
      expect(document.body.textContent).not.toContain("UNAVAILABLE");
      expect(document.body.textContent).not.toMatch(/STALE_.*ERROR_SECRET/);
    });
  });
});
