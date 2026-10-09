import { render, screen, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { JournalResponse } from "../api/client";

const snapshot = vi.hoisted(() => ({
  response: null as JournalResponse | null,
}));

vi.mock("../state/useGatewaySnapshot", () => ({
  useGatewaySnapshot: () => ({
    connection: "connected",
    data: snapshot.response,
    panel: {
      status: "fresh",
      data: snapshot.response,
      source: "Gateway API",
      asOf: Date.now(),
    },
    lastSuccess: Date.now(),
    expiresAt: Date.now() + 5_000,
    error: null,
    retry: vi.fn(),
  }),
}));

vi.mock("../api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api/client")>();
  return { ...actual, api: { ...actual.api, journalRecords: vi.fn() } };
});

import { Journal } from "../tabs/Journal";

const row = {
  trade_id: "trade-1",
  setup_id: "setup-1",
  decision_id: "decision-1",
  outcome: "win" as const,
  entry: "10",
  exit: "12",
  mae: null,
  mfe: null,
  post_trade_notes: "",
};

describe("journal provenance", () => {
  it("labels verified and historical rows and excludes historical rows from verified totals", () => {
    const consoleError = vi.spyOn(console, "error").mockImplementation(() => undefined);
    snapshot.response = {
      records: [
        { ...row, provenance: "route_attempt_terminal_verified" },
        {
          ...row,
          decision_id: "decision-2",
          provenance: "route_attempt_terminal_unverified",
        },
      ],
      stats: { win: 1 },
      unverified_count: 1,
      provenance: "mixed",
    };

    render(<Journal />);

    expect(screen.getByText("Verified")).toBeTruthy();
    expect(screen.getByText("Unverified / historical")).toBeTruthy();
    const totals = screen.getByRole("region", { name: "Journal totals" });
    expect(within(totals).getByText("Outcome totals (verified only)")).toBeTruthy();
    expect(within(totals).getByText("win: 1")).toBeTruthy();
    expect(within(totals).getByText("1 unverified rows not counted")).toBeTruthy();
    expect(consoleError.mock.calls.flat().join(" ")).not.toContain("same key");
    consoleError.mockRestore();
  });

  it("labels empty totals as verified only and reports no unverified rows", () => {
    snapshot.response = {
      records: [],
      stats: {},
      unverified_count: 0,
      provenance: "none",
    };

    render(<Journal />);

    const totals = screen.getByRole("region", { name: "Journal totals" });
    expect(within(totals).getByText("Outcome totals (verified only)")).toBeTruthy();
    expect(within(totals).getByText("0 unverified rows not counted")).toBeTruthy();
  });
});
