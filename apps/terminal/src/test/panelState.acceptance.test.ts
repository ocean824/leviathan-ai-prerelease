import { describe, expect, it, vi } from "vitest";
import { timestampedFixture } from "./fixtures/api";
import {
  OPERATOR_STALE_MS,
  STREAM_STALE_MS,
  errorPanel,
  evaluatePanelState,
  freshPanel,
  unavailablePanel,
} from "../state/panelState";

describe("PanelState timestamp and age requirements", () => {
  it("accepts timestamped data as fresh and changes terminal streams at the 3 second boundary", () => {
    const state = freshPanel(
      { quote: timestampedFixture.value },
      timestampedFixture.source,
      timestampedFixture.asOf,
      () => timestampedFixture.asOf,
    );
    expect(state.status).toBe("fresh");
    expect(STREAM_STALE_MS).toBe(3_000);
    expect(evaluatePanelState(state, () => timestampedFixture.asOf + 2_999, STREAM_STALE_MS).status).toBe("fresh");
    const stale = evaluatePanelState(state, () => timestampedFixture.asOf + 3_000, STREAM_STALE_MS);
    expect(stale.status).toBe("stale");
    if (stale.status === "stale") {
      expect(stale.lastSuccess).toBe(timestampedFixture.asOf);
      expect(stale.data).toEqual({ quote: timestampedFixture.value });
    }
  });

  it("keeps operator panels fresh before 5 seconds and reports stale at the boundary", () => {
    const state = freshPanel({ symbol: "AAPL" }, "Fixture", 20_000, () => 20_000);
    expect(OPERATOR_STALE_MS).toBe(5_000);
    expect(evaluatePanelState(state, () => 24_999, OPERATOR_STALE_MS).status).toBe("fresh");
    expect(evaluatePanelState(state, () => 25_000, OPERATOR_STALE_MS).status).toBe("stale");
  });

  it.each([null, undefined, "invalid"])("does not mark missing or invalid source time fresh (%s)", (asOf) => {
    expect(freshPanel("datum", "API", asOf, () => 20_000).status).toBe("unavailable");
  });

  it("keeps errors distinct from fresh data and exposes last success and retry", () => {
    const retry = vi.fn();
    const state = errorPanel("API", "HTTP 500", 30_000, retry);
    expect(state.status).toBe("error");
    if (state.status === "error") {
      expect(state.code).toBe("HTTP 500");
      expect(state.lastSuccess).toBe(30_000);
      state.retry?.();
    }
    expect(retry).toHaveBeenCalledTimes(1);
    expect(unavailablePanel("API", "offline").status).toBe("unavailable");
  });
});


