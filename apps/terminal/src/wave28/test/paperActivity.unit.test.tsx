import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import {
  createPaperActivityClient,
  MAX_DECIMAL_TEXT_LENGTH,
  parsePaperActivityPage,
} from "../api/paperActivity";
import type { PaperActivityPageV1 } from "../api/paperActivity";
import { PaperActivityView } from "../views/PaperActivityView";

const CURSOR = `YWJjXy0.${"A".repeat(43)}`;

function activityPage(
  overrides: Partial<PaperActivityPageV1> = {},
): PaperActivityPageV1 {
  return {
    schema_version: 1,
    evidence_label: "OMS ledger evidence",
    environment: "paper",
    account_id: "paper-account-1",
    high_water_sequence: 4,
    items: [
      {
        kind: "ORDER",
        ledger_sequence: 1,
        order: {
          order_id: "order-1",
          venue: "DEMO",
          instrument_id: "EUR_USD",
          side: "BUY",
          state: "PARTIALLY_FILLED",
          quantity: "2.5",
          filled_quantity: "1.25",
          discrepancies: ["FILL_CORRECTION"],
          created_at_utc: "2026-10-06T12:00:00Z",
        },
      },
      {
        kind: "FILL",
        ledger_sequence: 2,
        fill: {
          order_id: "order-1",
          execution_id: "exec-1",
          venue: "DEMO",
          instrument_id: "EUR_USD",
          side: "BUY",
          quantity: "1.25",
          price: "1.10025",
          commission: "0.01",
          occurred_at_utc: "2026-10-06T12:00:01Z",
        },
      },
      {
        kind: "FILL_CORRECTION",
        ledger_sequence: 3,
        correction: {
          order_id: "order-1",
          execution_id: "exec-1",
          correction_id: "corr-1",
          revision: 1,
          revised_quantity: "0",
          revised_price: null,
          revised_commission: "0",
          occurred_at_utc: "2026-10-06T12:00:02Z",
        },
      },
    ],
    next_cursor: CURSOR,
    net_filled_units: [
      { venue: "DEMO", instrument_id: "EUR_USD", quantity: "0" },
    ],
    ...overrides,
  };
}

function response(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("paper activity API client", () => {
  it("validates and preserves exact decimal text and separate correction records", () => {
    const parsed = parsePaperActivityPage(activityPage());
    expect(parsed?.items.map(({ kind }) => kind)).toEqual([
      "ORDER",
      "FILL",
      "FILL_CORRECTION",
    ]);
    if (parsed?.items[1]?.kind === "FILL")
      expect(parsed.items[1].fill.price).toBe("1.10025");
    expect(parsed?.net_filled_units[0]?.quantity).toBe("0");
  });

  it("accepts the maximum safe integer high-water and rejects the next value", () => {
    expect(
      parsePaperActivityPage(
        activityPage({ high_water_sequence: Number.MAX_SAFE_INTEGER }),
      )?.high_water_sequence,
    ).toBe(Number.MAX_SAFE_INTEGER);
    expect(
      parsePaperActivityPage(
        activityPage({ high_water_sequence: Number.MAX_SAFE_INTEGER + 1 }),
      ),
    ).toBeNull();
  });

  it("accepts 100 net groups and rejects 101 without truncating", () => {
    const groups = Array.from({ length: 100 }, (_, index) => ({
      venue: "DEMO",
      instrument_id: `SYMBOL_${index}`,
      quantity: "0",
    }));
    expect(
      parsePaperActivityPage(activityPage({ net_filled_units: groups }))
        ?.net_filled_units,
    ).toHaveLength(100);
    expect(
      parsePaperActivityPage(
        activityPage({
          net_filled_units: [
            ...groups,
            {
              venue: "DEMO",
              instrument_id: "SYMBOL_100",
              quantity: "0",
            },
          ],
        }),
      ),
    ).toBeNull();
  });

  it("matches the OMS decimal text ceiling and preserves signed net units only", () => {
    expect(MAX_DECIMAL_TEXT_LENGTH).toBe(128);
    const page = activityPage();
    page.net_filled_units[0]!.quantity = "-1.25";
    expect(parsePaperActivityPage(page)?.net_filled_units[0]?.quantity).toBe(
      "-1.25",
    );

    const negativeFillCommission = activityPage();
    const fill = negativeFillCommission.items[1];
    if (fill?.kind === "FILL") fill.fill.commission = "-0.01";
    expect(parsePaperActivityPage(negativeFillCommission)).toBeNull();

    const negativeReplacementQuantity = activityPage();
    const correction = negativeReplacementQuantity.items[2];
    if (correction?.kind === "FILL_CORRECTION") {
      correction.correction.revised_quantity = "-0.25";
      correction.correction.revised_price = "1.1";
    }
    expect(parsePaperActivityPage(negativeReplacementQuantity)).toBeNull();

    const negativeReplacementCommission = activityPage();
    const commissionCorrection = negativeReplacementCommission.items[2];
    if (commissionCorrection?.kind === "FILL_CORRECTION") {
      commissionCorrection.correction.revised_commission = "-0.01";
    }
    expect(parsePaperActivityPage(negativeReplacementCommission)).toBeNull();
  });

  it.each([
    [
      "unlisted state",
      (page: PaperActivityPageV1) => {
        const order = page.items[0];
        if (order?.kind === "ORDER") order.order.state = "SECRET" as never;
      },
    ],
    [
      "unlisted discrepancy",
      (page: PaperActivityPageV1) => {
        const order = page.items[0];
        if (order?.kind === "ORDER")
          order.order.discrepancies = ["ACCOUNT_PASSWORD"] as never;
      },
    ],
    [
      "exponent decimal",
      (page: PaperActivityPageV1) => {
        const fill = page.items[1];
        if (fill?.kind === "FILL") fill.fill.price = "1e4";
      },
    ],
    [
      "noncanonical decimal",
      (page: PaperActivityPageV1) => {
        const fill = page.items[1];
        if (fill?.kind === "FILL") fill.fill.price = "1.1000";
      },
    ],
    [
      "unsafe timestamp",
      (page: PaperActivityPageV1) => {
        const order = page.items[0];
        if (order?.kind === "ORDER")
          order.order.created_at_utc = "2026-02-31T12:00:00Z";
      },
    ],
  ])("rejects %s without producing partial data", (_label, mutate) => {
    const page = activityPage();
    mutate(page);
    expect(parsePaperActivityPage(page)).toBeNull();
  });

  it("uses GET, no-store and encodes the opaque cursor", async () => {
    const fetcher = vi.fn<typeof fetch>(async () =>
      response(activityPage({ next_cursor: null })),
    );
    const client = createPaperActivityClient(fetcher);
    const result = await client.getActivity({ cursor: CURSOR, limit: 50 });
    expect(result.ok).toBe(true);
    const [url, init] = fetcher.mock.calls[0] ?? [];
    expect(String(url)).toBe(
      `/api/orders/activity?limit=50&cursor=${encodeURIComponent(CURSOR)}`,
    );
    expect(init?.method).toBe("GET");
    expect(init?.cache).toBe("no-store");
    expect(String(url)).not.toMatch(/account|environment|project/i);
  });

  it("reduces API errors to fixed codes without retaining response text", async () => {
    const fetcher = vi.fn<typeof fetch>(async () =>
      response(
        {
          error: {
            code: "PAPER_SCOPE_REQUIRED",
            detail: "password=not-for-display",
          },
        },
        403,
      ),
    );
    const client = createPaperActivityClient(fetcher);
    await expect(client.getActivity()).resolves.toEqual({
      ok: false,
      error: "PAPER_SCOPE_REQUIRED",
    });
  });

  it("recognizes the fixed too-large response without exposing response details", async () => {
    const fetcher = vi.fn<typeof fetch>(async () =>
      response(
        {
          error: {
            code: "ACTIVITY_TOO_LARGE",
            detail: "account-specific value",
          },
        },
        413,
      ),
    );
    const client = createPaperActivityClient(fetcher);
    await expect(client.getActivity()).resolves.toEqual({
      ok: false,
      error: "ACTIVITY_TOO_LARGE",
    });
  });
});

describe("PaperActivityView", () => {
  it("shows HALT and paper-only data without mutation controls or freshness claims", async () => {
    const page = activityPage({ next_cursor: null });
    const fetcher = vi.fn<typeof fetch>(async (input) => {
      const url = String(input);
      if (url.startsWith("/api/orders/activity")) return response(page);
      if (url === "/api/orders/status")
        return response({
          live_enabled: false,
          recovery_status: "READY",
          activation_count: 0,
          as_of: 10_000,
        });
      return response({
        halted: true,
        active_halts: ["operator_halt"],
        fault_code: null,
        operating_mode: "research",
        policy: {},
        as_of: 10_000,
      });
    });
    render(<PaperActivityView fetcher={fetcher} clock={() => 10_000} />);

    expect(await screen.findByText("HALT REPORTED")).toBeTruthy();
    expect(screen.getByText("PAPER ONLY")).toBeTruthy();
    expect(screen.getByText("LIVE DISABLED")).toBeTruthy();
    expect(
      await screen.findByText(
        "OMS ledger, not broker-confirmed. No cost basis or valuation is calculated.",
      ),
    ).toBeTruthy();
    expect(await screen.findByText("1.10025")).toBeTruthy();
    expect(screen.getByText(/Source timestamp unavailable/)).toBeTruthy();
    expect(
      screen.queryByRole("button", {
        name: /submit|cancel|activate|lift halt|place order/i,
      }),
    ).toBeNull();
    expect(fetcher.mock.calls.every(([, init]) => init?.method === "GET")).toBe(
      true,
    );
  });

  it("loads the next bounded page with the returned cursor", async () => {
    const fetcher = vi.fn<typeof fetch>(async (input) => {
      if (String(input).startsWith("/api/orders/activity")) {
        const next = String(input).includes("cursor=");
        return response(
          activityPage({ items: [], next_cursor: next ? null : CURSOR }),
        );
      }
      if (String(input) === "/api/orders/status")
        return response({
          live_enabled: false,
          recovery_status: "UNKNOWN",
          activation_count: 0,
        });
      return response({
        halted: false,
        active_halts: [],
        operating_mode: "research",
        policy: null,
      });
    });
    render(<PaperActivityView fetcher={fetcher} clock={() => 10_000} />);
    fireEvent.click(await screen.findByRole("button", { name: "Next page" }));
    await waitFor(() =>
      expect(
        fetcher.mock.calls.some(([url]) =>
          String(url).includes(`cursor=${encodeURIComponent(CURSOR)}`),
        ),
      ).toBe(true),
    );
  });
});
