import { act, render, waitFor } from "@testing-library/react";
import { Profiler } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { PaperAccountView } from "../PaperAccountView";

const ACCOUNT_ID = "paper-account-001";
const SNAPSHOT_PATH = `/api/paper/accounts/${encodeURIComponent(ACCOUNT_ID)}/snapshot`;
const NOW = Date.parse("2026-10-06T12:00:00.000Z");
const SOURCE_TIME = "2026-10-06T11:59:30.000000Z";
const QUANTITY = "0.100000000000000001";
const EQUITY_AMOUNT = "100000.000000000001";
const BALANCE_AMOUNT = "87654.321";
const DERIVED_PNL_CANARY = "12345.679000000001";

type Snapshot = {
  account_id: string;
  environment: "paper";
  broker_revision: number;
  broker_observed_at: string;
  balances: null | { currency: string; amount: string }[];
  positions: { instrument_id: string; quantity: string }[];
  equity: null | {
    currency: string;
    amount: string;
    kind: "TOTAL_EQUITY" | "NET_LIQUIDATION";
    broker_observed_at_ns: number;
  };
};

const snapshot: Snapshot = {
  account_id: ACCOUNT_ID,
  environment: "paper",
  broker_revision: 7,
  broker_observed_at: SOURCE_TIME,
  balances: [{ currency: "USD", amount: BALANCE_AMOUNT }],
  positions: [{ instrument_id: "NQ.TEST", quantity: QUANTITY }],
  equity: {
    currency: "USD",
    amount: EQUITY_AMOUNT,
    kind: "NET_LIQUIDATION",
    broker_observed_at_ns: 1_791_287_970_000_000_000,
  },
};

type CapturedCall = {
  input: string;
  method: string;
  credentials: RequestCredentials | undefined;
  cache: RequestCache | undefined;
  body: BodyInit | null | undefined;
};

function jsonResponse(body: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: status === 503 ? "Service Unavailable" : "OK",
    json: async () => body,
    text: async () => JSON.stringify(body),
  } as Response;
}

function fakeFetch(body: unknown, status = 200) {
  const calls: CapturedCall[] = [];
  const fetcher = vi.fn<typeof fetch>(async (input, init) => {
    calls.push({
      input: String(input),
      method: (init?.method ?? "GET").toUpperCase(),
      credentials: init?.credentials,
      cache: init?.cache,
      body: init?.body,
    });
    return jsonResponse(body, status);
  });
  return { fetcher, calls };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((resolvePromise) => { resolve = resolvePromise; });
  return { promise, resolve };
}

function expectOnlySnapshotGet(calls: CapturedCall[]) {
  expect(calls).toHaveLength(1);
  const requestUrl = new URL(calls[0]?.input ?? "", "http://localhost");
  expect(requestUrl.origin).toBe("http://localhost");
  expect(requestUrl.pathname).toBe(SNAPSHOT_PATH);
  expect(calls[0]).toMatchObject({
    method: "GET",
    credentials: "same-origin",
    cache: "no-store",
    body: undefined,
  });
}

function visibleText(): string {
  return document.body.textContent ?? "";
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("PAPER-ACCOUNT-POSITIONS-UI-001 independent acceptance", () => {
  it("renders exact broker positions, equity semantics and source time without inventing PnL", async () => {
    const api = fakeFetch(snapshot);
    render(<PaperAccountView accountId={ACCOUNT_ID} fetcher={api.fetcher} clock={() => NOW} />);

    await waitFor(() => {
      expect(visibleText()).toContain(QUANTITY);
      expect(visibleText()).toContain(EQUITY_AMOUNT);
      expect(visibleText()).toContain(SOURCE_TIME);
    });

    const text = visibleText();
    expect(text).toContain("Broker positions");
    const dataLabels = Array.from(document.querySelectorAll("h1,h2,h3,th,caption,dt"))
      .map((element) => element.textContent ?? "");
    expect(dataLabels.some((label) => /broker positions/i.test(label))).toBe(true);
    expect(dataLabels.some((label) => /OMS\s+net\s+filled\s+units/i.test(label))).toBe(false);
    expect(text).toContain("NET_LIQUIDATION");
    expect(text).toContain("USD");
    expect(text).toContain(BALANCE_AMOUNT);
    expect(text).not.toContain(DERIVED_PNL_CANARY);
    expect(text).not.toMatch(/(?:PnL|P&L)\s*[:=]\s*[-$]?\d/i);

    expectOnlySnapshotGet(api.calls);
  });

  it("shows stale broker time distinctly from an unavailable API snapshot", async () => {
    const staleApi = fakeFetch({
      ...snapshot,
      broker_observed_at: "2020-01-01T00:00:00.000000Z",
    });
    const staleView = render(
      <PaperAccountView accountId={ACCOUNT_ID} fetcher={staleApi.fetcher} clock={() => NOW} />,
    );
    await waitFor(() => expect(visibleText()).toMatch(/stale/i));
    expectOnlySnapshotGet(staleApi.calls);
    staleView.unmount();

  });

  it("never renders raw server error text in the unavailable UI", async () => {
    const rawErrorCanary = "PAPER_SNAPSHOT_RAW_ERROR_CANARY";
    const unavailableApi = fakeFetch({
      error: {
        code: "PAPER_ACCOUNT_SNAPSHOT_UNAVAILABLE",
        detail: rawErrorCanary,
      },
    }, 503);
    render(
      <PaperAccountView accountId={ACCOUNT_ID} fetcher={unavailableApi.fetcher} clock={() => NOW} />,
    );
    await waitFor(() => expect(visibleText()).toMatch(/unavailable/i));
    expect(visibleText()).not.toMatch(/stale/i);
    expect(visibleText()).not.toContain(rawErrorCanary);
    expectOnlySnapshotGet(unavailableApi.calls);
  });

  it("does not show the previous account's rows after switching accounts", async () => {
    const accountA = "paper-account-A";
    const accountB = "paper-account-B";
    const fetcher = vi.fn<typeof fetch>(async (input) => {
      const requested = decodeURIComponent(new URL(String(input), "http://localhost").pathname.split("/").at(-2) ?? "");
      const accountSnapshot = {
        ...snapshot,
        account_id: requested,
        positions: [{ instrument_id: requested === accountA ? "ONLY-A-ROW" : "ONLY-B-ROW", quantity: QUANTITY }],
      };
      return jsonResponse(accountSnapshot);
    });
    const committedText: string[] = [];
    const view = render(
      <Profiler id="paper-account" onRender={() => committedText.push(visibleText())}>
        <PaperAccountView accountId={accountA} fetcher={fetcher} clock={() => NOW} />
      </Profiler>,
    );
    await waitFor(() => expect(visibleText()).toContain("ONLY-A-ROW"));

    committedText.length = 0;
    view.rerender(
      <Profiler id="paper-account" onRender={() => committedText.push(visibleText())}>
        <PaperAccountView accountId={accountB} fetcher={fetcher} clock={() => NOW} />
      </Profiler>,
    );
    expect(committedText.some((text) => text.includes("account paper-account-B") && text.includes("ONLY-A-ROW"))).toBe(false);
    expect(visibleText()).not.toContain("ONLY-A-ROW");
    await waitFor(() => expect(visibleText()).toContain("ONLY-B-ROW"));
    expect(visibleText()).not.toContain("ONLY-A-ROW");
  });

  it("ignores an older in-flight account response after a newer response wins", async () => {
    const accountA = "paper-account-A";
    const accountB = "paper-account-B";
    const responseA = deferred<Response>();
    const responseB = deferred<Response>();
    const fetcher = vi.fn<typeof fetch>((input) => {
      const requested = decodeURIComponent(new URL(String(input), "http://localhost").pathname.split("/").at(-2) ?? "");
      return requested === accountA ? responseA.promise : responseB.promise;
    });
    const view = render(<PaperAccountView accountId={accountA} fetcher={fetcher} clock={() => NOW} />);
    await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(1));
    view.rerender(<PaperAccountView accountId={accountB} fetcher={fetcher} clock={() => NOW} />);
    await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(2));

    const payloadB = { ...snapshot, account_id: accountB, positions: [{ instrument_id: "NEWER-B-ROW", quantity: "2" }] };
    await act(async () => { responseB.resolve(jsonResponse(payloadB)); });
    await waitFor(() => expect(visibleText()).toContain("NEWER-B-ROW"));

    const payloadA = { ...snapshot, account_id: accountA, positions: [{ instrument_id: "OLDER-A-ROW", quantity: "1" }] };
    await act(async () => { responseA.resolve(jsonResponse(payloadA)); });
    expect(visibleText()).toContain("NEWER-B-ROW");
    expect(visibleText()).not.toContain("OLDER-A-ROW");
  });

  it("marks a future-dated broker source time stale", async () => {
    const api = fakeFetch({ ...snapshot, broker_observed_at: "2026-10-06T12:00:00.001000Z" });
    render(<PaperAccountView accountId={ACCOUNT_ID} fetcher={api.fetcher} clock={() => NOW} />);
    await waitFor(() => expect(visibleText()).toMatch(/stale/i));
    expect(visibleText()).toContain("2026-10-06T12:00:00.001000Z");
    expectOnlySnapshotGet(api.calls);
  });

  it("keeps LIVE disabled and performs no mutation or non-snapshot request", async () => {
    const api = fakeFetch(snapshot);
    render(<PaperAccountView accountId={ACCOUNT_ID} fetcher={api.fetcher} clock={() => NOW} />);

    await waitFor(() => expect(visibleText()).toContain(EQUITY_AMOUNT));
    expect(visibleText()).toMatch(/LIVE\s+DISABLED/i);

    const liveControls = Array.from(document.querySelectorAll("button,[role='button']"))
      .filter((control) => /live/i.test(control.textContent ?? control.getAttribute("aria-label") ?? ""));
    expect(liveControls.length).toBeGreaterThan(0);
    for (const control of liveControls) {
      expect(
        control.matches(":disabled") || control.getAttribute("aria-disabled") === "true",
      ).toBe(true);
    }

    expectOnlySnapshotGet(api.calls);
  });
});
