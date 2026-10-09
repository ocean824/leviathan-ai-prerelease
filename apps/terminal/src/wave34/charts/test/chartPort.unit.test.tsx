import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { ChartHandle, ChartPort, SeriesHandle } from "../ChartPort";
import { PriceDepthFootprintView } from "../PriceDepthFootprintView";
import {
  MAX_CANDLE_BARS,
  MAX_FOOTPRINT_LEVELS_PER_BAR,
  MAX_MBP_LEVELS,
  addDecimals,
  alignByEventTime,
  buildFootprint,
  normalizeChartSnapshot,
  toChartTime,
  toEventTimeNs,
  type ChartSnapshotV1,
  type MarketBarV1,
  type MboTradeV1,
} from "../model";

afterEach(cleanup);

const bar = (eventTimeNs: string): MarketBarV1 => ({
  eventTimeNs, open: "100.00", high: "101.00", low: "99.00", close: "100.50", volume: "10",
});

const snapshot = (overrides: Partial<ChartSnapshotV1> = {}): ChartSnapshotV1 => ({
  instrument: "ES", venue: "CME", source: "l2", eventTimeNs: "1791300000000000000",
  candles: [bar("1791300000000000000")],
  depth: { feed: "mbp10", eventTimeNs: "1791300000000000000", bids: [{ price: "100.00", quantity: "12" }], asks: [{ price: "100.25", quantity: "8" }] },
  footprint: null,
  gex: { asOfNs: "1791300000000000000", source: "dealer-gamma-v1", callWall: "105", putWall: "95", zeroGammaFlip: "100.5", topStrikes: [{ price: "103", label: "Top call", value: "7" }] },
  indicators: { bookImbalance: "0.2", cumulativeDelta: "-14" },
  ...overrides,
});

function fakePort() {
  const chart = {} as ChartHandle;
  const candles = {} as SeriesHandle;
  return {
    chart, candles,
    port: {
      createChart: vi.fn(() => chart),
      addCandlestickSeries: vi.fn(() => candles),
      addLineSeries: vi.fn(() => ({} as SeriesHandle)),
      addPriceLine: vi.fn(),
      addCustomSeries: vi.fn(() => ({} as SeriesHandle)),
      setData: vi.fn(),
      resize: vi.fn(),
      dispose: vi.fn(),
    } satisfies ChartPort,
  };
}

describe("CHART-001 chart model", () => {
  it("normalizes offset timestamps to the same UTC nanosecond key", () => {
    expect(toEventTimeNs("2026-10-06T10:00:00.123456789-05:00"))
      .toBe(toEventTimeNs("2026-10-06T15:00:00.123456789Z"));
    expect(toChartTime("2026-10-06T15:00:00.123456789Z")).toBeCloseTo(Date.parse("2026-10-06T15:00:00.123Z") / 1000 + 0.000456789, 6);
  });

  it("aligns events to candles by normalized UTC event time", () => {
    const candles = [bar("2026-10-06T10:00:00.000-05:00")];
    const events = [{ eventTimeNs: "2026-10-06T15:00:00.000Z", quantity: "2" }];
    expect(alignByEventTime(candles, events)[0].events).toEqual(events);
  });

  it("adds decimal quantities exactly without binary floating point", () => {
    expect(addDecimals("0.10", "0.20")).toBe("0.3");
    expect(addDecimals("100000000000000000.00000001", "0.00000009")).toBe("100000000000000000.0000001");
  });

  it("aggregates MBO buy and sell volume exactly into candle price levels", () => {
    const trades: MboTradeV1[] = [
      { eventTimeNs: "1000000000", price: "100.25", quantity: "0.1", aggressor: "buy" },
      { eventTimeNs: "2000000000", price: "100.25", quantity: "0.2", aggressor: "buy" },
      { eventTimeNs: "3000000000", price: "100.25", quantity: "0.3", aggressor: "sell" },
    ];
    expect(buildFootprint(trades, [bar("1000000000")])[0].levels).toEqual([
      { price: "100.25", bidVolume: "0.3", askVolume: "0.3" },
    ]);
  });

  it("suppresses NBBO depth and caps each bounded data collection", () => {
    const candles = Array.from({ length: MAX_CANDLE_BARS + 20 }, (_, index) => bar(String(1_000_000_000 + index)));
    const levels = Array.from({ length: MAX_MBP_LEVELS + 4 }, (_, index) => ({ price: String(index), quantity: "1" }));
    const footprint = [{ eventTimeNs: "1", levels: Array.from({ length: MAX_FOOTPRINT_LEVELS_PER_BAR + 2 }, (_, index) => ({ price: String(index), bidVolume: "1", askVolume: "0" })) }];
    const normalized = normalizeChartSnapshot(snapshot({ source: "nbbo", candles, depth: snapshot().depth, footprint }), "9999999999");
    expect(normalized.depth).toBeNull();
    expect(normalized.footprint).toBeNull();
    expect(normalized.candles).toHaveLength(MAX_CANDLE_BARS);
    expect(normalizeChartSnapshot(snapshot({ depth: { feed: "mbp10", eventTimeNs: "1", bids: levels, asks: levels } }), "9999999999").depth?.bids).toHaveLength(MAX_MBP_LEVELS);
  });

  it("does not infer missing candles, depth, or footprint values", () => {
    const normalized = normalizeChartSnapshot(snapshot({ candles: [], depth: null, footprint: null }), "9999999999");
    expect(normalized.candles).toEqual([]);
    expect(normalized.depth).toBeNull();
    expect(normalized.footprint).toBeNull();
  });
});

describe("CHART-001 chart port view", () => {
  it("renders real supplied snapshot values and GEX provenance through an injected port", () => {
    const { port } = fakePort();
    render(<PriceDepthFootprintView panel={{ status: "fresh", data: snapshot(), source: "market-gateway", asOf: Date.now() }} port={port} />);
    expect(screen.getByText("ES")).toBeTruthy();
    expect(screen.getByText(/L2 · MBP-10/)).toBeTruthy();
    expect(screen.getAllByText(/dealer-gamma-v1/).length).toBeGreaterThan(0);
    expect(port.createChart).toHaveBeenCalledTimes(1);
    expect(port.addPriceLine).toHaveBeenCalledTimes(4);
    expect(port.setData).toHaveBeenCalledTimes(1);
  });

  it("exposes a keyboard-focusable chart summary and arrow-key candle selection", () => {
    const { port } = fakePort();
    const data = snapshot({ candles: [bar("1791300000000000000"), bar("1791300001000000000")] });
    render(<PriceDepthFootprintView panel={{ status: "fresh", data, source: "gateway", asOf: Date.now() }} port={port} />);
    const chart = screen.getByRole("img", { name: /Keyboard accessible market price chart/ });
    expect(chart.getAttribute("tabindex")).toBe("0");
    fireEvent.keyDown(chart, { key: "ArrowLeft" });
    expect(screen.getByText(/selected bar at/)).toBeTruthy();
  });

  it("labels stale values as stale and disposes chart resources on unmount", () => {
    const { port } = fakePort();
    const view = render(<PriceDepthFootprintView panel={{ status: "stale", data: snapshot(), source: "gateway", asOf: Date.now() - 10_000, lastSuccess: Date.now() - 10_000 }} port={port} />);
    expect(screen.getByText("Stale snapshot")).toBeTruthy();
    view.unmount();
    expect(port.dispose).toHaveBeenCalledTimes(1);
  });

  it("renders unavailable state without creating a chart", () => {
    const { port } = fakePort();
    render(<PriceDepthFootprintView panel={{ status: "unavailable", source: "gateway", reason: "No depth entitlement" }} port={port} />);
    expect(screen.getAllByText("No depth entitlement").length).toBeGreaterThan(0);
    expect(port.createChart).not.toHaveBeenCalled();
  });
});


