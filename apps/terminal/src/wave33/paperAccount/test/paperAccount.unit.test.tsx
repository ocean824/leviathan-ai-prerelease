import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { describe, expect, it, vi } from "vitest";
import {
  createPaperAccountSnapshotClient,
  PAPER_ACCOUNT_SNAPSHOT_PATH,
} from "../api";
import type { PaperAccountSnapshotV1 } from "../api";
import { PaperAccountView } from "../PaperAccountView";

const OBSERVED_AT = "2026-10-07T12:00:00.123456Z";
const NOW_MS = Date.parse("2026-10-07T12:01:00.000Z");

function snapshot(overrides: Partial<PaperAccountSnapshotV1> = {}): PaperAccountSnapshotV1 {
  return {
    account_id: "paper-account-1",
    environment: "paper",
    broker_revision: 17,
    broker_observed_at: OBSERVED_AT,
    balances: [{ currency: "USD", amount: "10000.125" }],
    positions: [{ instrument_id: "ESZ6", quantity: "1.25" }],
    equity: {
      currency: "USD",
      amount: "10125.5",
      kind: "NET_LIQUIDATION",
      broker_observed_at_ns: 1791374400123456000,
    },
    ...overrides,
  };
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("paper account snapshot client", () => {
  it("uses only the documented read-only PAPER snapshot request and preserves exact strings", async () => {
    const fetcher = vi.fn<typeof fetch>(async () => jsonResponse(snapshot()));
    const result = await createPaperAccountSnapshotClient(fetcher).getSnapshot("paper-account-1");
    expect(result).toEqual({ ok: true, data: snapshot() });
    expect(fetcher).toHaveBeenCalledOnce();
    const [url, init] = fetcher.mock.calls[0]!;
    expect(String(url)).toBe(`${PAPER_ACCOUNT_SNAPSHOT_PATH}/paper-account-1/snapshot`);
    expect(init).toMatchObject({
      method: "GET",
      credentials: "same-origin",
      cache: "no-store",
      headers: { Accept: "application/json" },
    });
    expect(init?.body).toBeUndefined();
  });

  it("rejects malformed decimal, wrong-account, and non-PAPER responses without exposing server details", async () => {
    const malformed = await createPaperAccountSnapshotClient(async () => jsonResponse({
      ...snapshot(),
      positions: [{ instrument_id: "ESZ6", quantity: "1e3" }],
    })).getSnapshot("paper-account-1");
    expect(malformed).toEqual({ ok: false, error: "INVALID_RESPONSE" });

    const mismatch = await createPaperAccountSnapshotClient(async () => jsonResponse(
      snapshot({ account_id: "another-account" }),
    )).getSnapshot("paper-account-1");
    expect(mismatch).toEqual({ ok: false, error: "INVALID_RESPONSE" });

    const denied = await createPaperAccountSnapshotClient(async () => jsonResponse(
      { detail: "internal credential-bearing error" }, 503,
    )).getSnapshot("paper-account-1");
    expect(denied).toEqual({ ok: false, error: "PAPER_ACCOUNT_SNAPSHOT_UNAVAILABLE" });
    expect(JSON.stringify(denied)).not.toContain("credential-bearing");
  });

  it("does not call fetch for an invalid account identifier", async () => {
    const fetcher = vi.fn<typeof fetch>();
    const result = await createPaperAccountSnapshotClient(fetcher).getSnapshot("../live-account");
    expect(result).toEqual({ ok: false, error: "INVALID_ACCOUNT_ID" });
    expect(fetcher).not.toHaveBeenCalled();
  });
});

describe("paper account positions view", () => {
  it("renders exact broker positions, declared equity semantics, balances, time, and disabled LIVE", async () => {
    const fetcher = vi.fn<typeof fetch>(async () => jsonResponse(snapshot()));
    render(<PaperAccountView accountId="paper-account-1" fetcher={fetcher} clock={() => NOW_MS} />);

    expect(await screen.findByRole("heading", { name: "Paper account positions" })).toBeInTheDocument();
    expect(await screen.findByText("Equity (NET_LIQUIDATION): USD 10125.5")).toBeInTheDocument();
    expect(screen.getByText("USD: 10000.125")).toBeInTheDocument();
    expect(screen.getByText("ESZ6: 1.25")).toBeInTheDocument();
    expect(screen.getByText(OBSERVED_AT)).toBeInTheDocument();
    expect(screen.getByText(/LIVE trading is disabled/)).toBeInTheDocument();
    expect(screen.queryByText(/P&L|profit|loss/i)).not.toBeInTheDocument();
    expect(fetcher.mock.calls.every(([, init]) => init?.method === "GET")).toBe(true);
    expect(screen.getByRole("button", { name: "Refresh snapshot" })).toBeEnabled();
  });

  it("shows stale data separately from initial unavailable state and keeps the source time visible", async () => {
    const fetcher = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(snapshot()))
      .mockRejectedValueOnce(new Error("offline"));
    const view = render(<PaperAccountView accountId="paper-account-1" fetcher={fetcher} clock={() => NOW_MS} />);

    expect(await screen.findByText("Current broker snapshot")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Refresh snapshot" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("STALE");
    expect(screen.getByText(OBSERVED_AT)).toBeInTheDocument();
    view.unmount();

    const unavailableFetcher = vi.fn<typeof fetch>(async () => jsonResponse({}, 503));
    render(<PaperAccountView accountId="paper-account-1" fetcher={unavailableFetcher} clock={() => NOW_MS} />);
    expect(await screen.findByRole("alert")).toHaveTextContent("UNAVAILABLE");
    expect(screen.queryByText(OBSERVED_AT)).not.toBeInTheDocument();
  });

  it("marks snapshots older than the five-minute freshness window as stale", async () => {
    const staleSnapshot = snapshot({ broker_observed_at: "2026-10-07T11:55:00.000000Z" });
    render(<PaperAccountView
      accountId="paper-account-1"
      fetcher={async () => jsonResponse(staleSnapshot)}
      clock={() => NOW_MS}
    />);
    expect(await screen.findByRole("alert")).toHaveTextContent("STALE");
  });

  it("allows the exact five-minute freshness boundary", async () => {
    const boundarySnapshot = snapshot({ broker_observed_at: "2026-10-07T11:56:00.000000Z" });
    render(<PaperAccountView
      accountId="paper-account-1"
      fetcher={async () => jsonResponse(boundarySnapshot)}
      clock={() => NOW_MS}
    />);
    expect(await screen.findByText("Current broker snapshot")).toBeInTheDocument();
  });

  it("marks a future-dated broker snapshot stale", async () => {
    const futureSnapshot = snapshot({ broker_observed_at: "2026-10-07T12:02:00.000000Z" });
    render(<PaperAccountView
      accountId="paper-account-1"
      fetcher={async () => jsonResponse(futureSnapshot)}
      clock={() => NOW_MS}
    />);
    expect(await screen.findByRole("alert")).toHaveTextContent("STALE");
    expect(screen.getByText("ESZ6: 1.25")).toBeInTheDocument();
  });

  it("never renders the previous account snapshot after an account switch", async () => {
    let finishSecondRead: ((response: Response) => void) | undefined;
    const fetcher = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(snapshot()))
      .mockImplementationOnce(() => new Promise((resolve) => { finishSecondRead = resolve; }));
    const view = render(<PaperAccountView accountId="paper-account-1" fetcher={fetcher} clock={() => NOW_MS} />);
    expect(await screen.findByText("ESZ6: 1.25")).toBeInTheDocument();

    view.rerender(<PaperAccountView accountId="paper-account-2" fetcher={fetcher} clock={() => NOW_MS} />);
    expect(screen.getByText(/account paper-account-2/)).toBeInTheDocument();
    expect(screen.queryByText("ESZ6: 1.25")).not.toBeInTheDocument();
    expect(screen.queryByText(OBSERVED_AT)).not.toBeInTheDocument();

    finishSecondRead?.(jsonResponse(snapshot({
      account_id: "paper-account-2",
      positions: [{ instrument_id: "NQZ6", quantity: "2" }],
    })));
    expect(await screen.findByText("NQZ6: 2")).toBeInTheDocument();
  });

  it("ignores out-of-order responses and keeps the latest account read", async () => {
    const pending: Array<(response: Response) => void> = [];
    const fetcher = vi.fn<typeof fetch>(() => new Promise((resolve) => pending.push(resolve)));
    const view = render(<PaperAccountView accountId="paper-account-1" fetcher={fetcher} clock={() => NOW_MS} />);
    await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(1));

    view.rerender(<PaperAccountView accountId="paper-account-2" fetcher={fetcher} clock={() => NOW_MS} />);
    await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(2));
    view.rerender(<PaperAccountView accountId="paper-account-3" fetcher={fetcher} clock={() => NOW_MS} />);
    await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(3));

    pending[2]?.(jsonResponse(snapshot({
      account_id: "paper-account-3",
      positions: [{ instrument_id: "YMZ6", quantity: "3" }],
    })));
    expect(await screen.findByText("YMZ6: 3")).toBeInTheDocument();

    pending[1]?.(jsonResponse(snapshot({
      account_id: "paper-account-2",
      positions: [{ instrument_id: "NQZ6", quantity: "2" }],
    })));
    pending[0]?.(jsonResponse(snapshot({
      positions: [{ instrument_id: "ESZ6", quantity: "1" }],
    })));
    await waitFor(() => expect(screen.getByText("YMZ6: 3")).toBeInTheDocument());
    expect(screen.queryByText("NQZ6: 2")).not.toBeInTheDocument();
    expect(screen.queryByText("ESZ6: 1")).not.toBeInTheDocument();
  });

  it("never renders raw API error text", async () => {
    const rawError = "credential token=top-secret-value internal stack trace";
    render(<PaperAccountView
      accountId="paper-account-1"
      fetcher={async () => { throw new Error(rawError); }}
      clock={() => NOW_MS}
    />);
    expect(await screen.findByRole("alert")).toHaveTextContent("UNAVAILABLE");
    expect(screen.queryByText(/top-secret-value|internal stack trace|token=/i)).not.toBeInTheDocument();
    expect(document.body.textContent).not.toContain(rawError);
  });
});
