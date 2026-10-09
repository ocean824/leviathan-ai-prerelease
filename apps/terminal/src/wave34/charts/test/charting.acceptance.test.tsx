import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { PanelState } from "../../../state/panelState";
import { PriceDepthFootprintView } from "../PriceDepthFootprintView";
import type { ChartPort } from "../ChartPort";
import {
  MAX_CANDLE_BARS,
  MAX_FOOTPRINT_LEVELS_PER_BAR,
  MAX_GEX_LEVELS,
  MAX_MBP_LEVELS,
  alignByEventTime,
  buildFootprint,
  normalizeChartSnapshot,
  toChartTime,
  toEventTimeNs,
  type ChartSnapshotV1,
  type MarketBarV1,
  type MboTradeV1,
} from "../model";

const asOf = Date.parse("2026-01-02T03:04:05.000Z");
const nowNs = "1767323045000000000";

function bar(eventTimeNs: string, close = "101.25"): MarketBarV1 {
  return { eventTimeNs, open: "100", high: close, low: "99", close, volume: "12" };
}

function snapshot(overrides: Partial<ChartSnapshotV1> = {}): ChartSnapshotV1 {
  return {
    instrument: "ESM6",
    venue: "CME",
    source: "l3",
    eventTimeNs: nowNs,
    candles: [bar("1767323045000000000"), bar("1767323046000000000", "102.5")],
    depth: {
      feed: "mbo",
      eventTimeNs: nowNs,
      bids: [{ price: "101", quantity: "2" }],
      asks: [{ price: "101.25", quantity: "3" }],
    },
    footprint: [{ eventTimeNs: nowNs, levels: [{ price: "101", bidVolume: "1.25", askVolume: "2.5" }] }],
    gex: null,
    indicators: { bookImbalance: "0.125", cumulativeDelta: "1.25" },
    ...overrides,
  };
}

function fakePort(): { port: ChartPort; chart: object; series: object } {
  const chart = {};
  const series = {};
  const port: ChartPort = {
    createChart: vi.fn(() => chart),
    addCandlestickSeries: vi.fn(() => series),
    addLineSeries: vi.fn(() => series),
    addPriceLine: vi.fn(),
    addCustomSeries: vi.fn(() => series),
    setData: vi.fn(),
    resize: vi.fn(),
    dispose: vi.fn(),
  };
  return { port, chart, series };
}

function fresh(data: ChartSnapshotV1): PanelState<ChartSnapshotV1> {
  return { status: "fresh", data, source: "acceptance-fixture", asOf };
}

afterEach(() => cleanup());

describe("CHART-001 independent acceptance", () => {
  it("aligns price, depth, and footprint by exact UTC event time across equivalent offsets", () => {
    const first = "2026-01-02T03:04:05.250Z";
    const offset = "2026-01-02T04:04:05.250+01:00";
    const bars = [bar(first)];
    const aligned = alignByEventTime(bars, [{ eventTimeNs: offset, layer: "depth" }, { eventTimeNs: first, layer: "footprint" }]);

    expect(toEventTimeNs(first)).toBe(toEventTimeNs(offset));
    expect(aligned).toHaveLength(1);
    expect(aligned[0].events.map((event) => event.layer)).toEqual(["depth", "footprint"]);
    expect(toChartTime(first)).toBe(1767323045.25);
  });

  it("labels MBP-10 as L2 and MBO as L3", () => {
    const { port: l2Port } = fakePort();
    const l2 = snapshot({ source: "l2", depth: { feed: "mbp10", eventTimeNs: nowNs, bids: [{ price: "101", quantity: "4" }], asks: [] } });
    const { unmount: unmountL2 } = render(<PriceDepthFootprintView panel={fresh(l2)} port={l2Port} nowNs={nowNs} />);
    expect(screen.getByText("L2 · MBP-10")).toBeTruthy();
    unmountL2();

    const { port: l3Port } = fakePort();
    render(<PriceDepthFootprintView panel={fresh(snapshot())} port={l3Port} nowNs={nowNs} />);
    expect(screen.getByText("L3 · MBO")).toBeTruthy();
    const footprint = screen.getByLabelText("MBO order-flow footprint");
    expect(footprint.textContent).toContain("1.25");
    expect(footprint.textContent).toContain("2.5");
  });

  it("never renders depth or depth-derived indicators from NBBO-only input", () => {
    const { port } = fakePort();
    const nbbo = snapshot({ source: "nbbo", depth: { feed: "mbp10", eventTimeNs: nowNs, bids: [{ price: "101", quantity: "9" }], asks: [] } });
    render(<PriceDepthFootprintView panel={fresh(nbbo)} port={port} nowNs={nowNs} />);

    expect(screen.getByText(/NBBO only — no order-book depth is available/)).toBeTruthy();
    expect(screen.queryByLabelText(/depth ladder heatmap/i)).toBeNull();
    expect(screen.queryByText(/Book imbalance/)).toBeNull();
    expect(normalizeChartSnapshot(nbbo, nowNs).depth).toBeNull();
    expect(normalizeChartSnapshot(nbbo, nowNs).indicators).toBeNull();
  });

  it("builds footprint buckets with exact bid and ask sums and does not bucket without bars", () => {
    const bars = [bar("1000000000"), bar("2000000000")];
    const trades: MboTradeV1[] = [
      { eventTimeNs: "1000000001", price: "1.25", quantity: "0.1", aggressor: "sell" },
      { eventTimeNs: "1500000000", price: "1.25", quantity: "0.2", aggressor: "sell" },
      { eventTimeNs: "1999999999", price: "1.25", quantity: "0.3", aggressor: "buy" },
      { eventTimeNs: "2000000000", price: "1.25", quantity: "0.4", aggressor: "buy" },
    ];
    const result = buildFootprint(trades, bars);
    expect(result).toEqual([
      { eventTimeNs: "1000000000", levels: [{ price: "1.25", bidVolume: "0.3", askVolume: "0.3" }] },
      { eventTimeNs: "2000000000", levels: [{ price: "1.25", bidVolume: "0", askVolume: "0.4" }] },
    ]);
    expect(buildFootprint(trades, [])).toEqual([]);
  });

  it("draws exact GEX price levels and exposes their source and as-of label", () => {
    const { port } = fakePort();
    const data = snapshot({ gex: { asOfNs: "2026-01-02T03:04:04.500Z", source: "synthetic-gex", callWall: "105.125", putWall: "95.875", zeroGammaFlip: "100.5" } });
    render(<PriceDepthFootprintView panel={fresh(data)} port={port} nowNs={nowNs} />);

    const added = vi.mocked(port.addPriceLine).mock.calls.map((call) => call[1]);
    expect(added.map((line) => line.price)).toEqual([105.125, 95.875, 100.5]);
    expect(added.map((line) => line.title)).toEqual([
      "Call wall · synthetic-gex · as of 2026-01-02T03:04:04.500Z",
      "Put wall · synthetic-gex · as of 2026-01-02T03:04:04.500Z",
      "Zero gamma · synthetic-gex · as of 2026-01-02T03:04:04.500Z",
    ]);
    const summary = screen.getByLabelText("Gamma exposure levels");
    expect(summary.textContent).toContain("Call wall: 105.125");
    expect(summary.textContent).toContain("Put wall: 95.875");
    expect(summary.textContent).toContain("Zero gamma: 100.5");
    expect(summary.textContent).toContain("as of 2026-01-02T03:04:04.500Z");
  });

  it("keeps sparse, stale, and unavailable panel states distinct", () => {
    const { port: sparsePort } = fakePort();
    render(<PriceDepthFootprintView panel={fresh(snapshot({ candles: [] }))} port={sparsePort} nowNs={nowNs} />);
    expect(screen.getByText(/The chart is sparse; no prices were inferred/)).toBeTruthy();
    expect(sparsePort.createChart).not.toHaveBeenCalled();
    cleanup();

    const { port: stalePort } = fakePort();
    const stalePanel: PanelState<ChartSnapshotV1> = { status: "stale", data: snapshot(), source: "feed-A", asOf: asOf - 301_000, lastSuccess: asOf - 301_000 };
    render(<PriceDepthFootprintView panel={stalePanel} port={stalePort} nowNs={nowNs} />);
    expect(screen.getByText("Stale snapshot")).toBeTruthy();
    cleanup();

    const { port: unavailablePort } = fakePort();
    render(<PriceDepthFootprintView panel={{ status: "unavailable", source: "feed-A", reason: "No snapshot available." }} port={unavailablePort} nowNs={nowNs} />);
    expect(screen.getByText("Unavailable")).toBeTruthy();
    expect(screen.getAllByText("No snapshot available.")).toHaveLength(2);
    expect(unavailablePort.createChart).not.toHaveBeenCalled();
  });

  it("enforces candle, depth, footprint, and GEX level caps", () => {
    const candles = Array.from({ length: MAX_CANDLE_BARS + 3 }, (_, index) => bar(String(index + 1_000_000_000), String(index + 1)));
    const depthRows = Array.from({ length: MAX_MBP_LEVELS + 2 }, (_, index) => ({ price: String(index + 1), quantity: "1" }));
    const footprintLevels = Array.from({ length: MAX_FOOTPRINT_LEVELS_PER_BAR + 2 }, (_, index) => ({ price: String(index + 1), bidVolume: "1", askVolume: "1" }));
    const strikes = Array.from({ length: MAX_GEX_LEVELS + 2 }, (_, index) => ({ price: String(index + 1), label: `strike-${index}` }));
    const bounded = normalizeChartSnapshot(snapshot({
      candles,
      depth: { feed: "mbo", eventTimeNs: nowNs, bids: depthRows, asks: depthRows },
      footprint: [{ eventTimeNs: nowNs, levels: footprintLevels }],
      gex: { asOfNs: nowNs, source: "synthetic-gex", topStrikes: strikes },
    }), nowNs);

    expect(bounded.candles).toHaveLength(MAX_CANDLE_BARS);
    expect(bounded.depth?.bids).toHaveLength(MAX_MBP_LEVELS);
    expect(bounded.depth?.asks).toHaveLength(MAX_MBP_LEVELS);
    expect(bounded.footprint?.[0].levels).toHaveLength(MAX_FOOTPRINT_LEVELS_PER_BAR);
    expect(bounded.gex?.topStrikes).toHaveLength(MAX_GEX_LEVELS);
  });

  it("supports keyboard focus and a readable text summary", () => {
    const { port } = fakePort();
    render(<PriceDepthFootprintView panel={fresh(snapshot())} port={port} nowNs={nowNs} />);
    const chart = screen.getByRole("img", { name: "Keyboard accessible market price chart" });
    expect(chart.getAttribute("tabindex")).toBe("0");
    expect(chart.getAttribute("aria-describedby")).toBe("chart-summary");
    const summary = document.getElementById("chart-summary");
    expect(summary?.textContent).toContain("ESM6 CME");
    expect(summary?.textContent).toContain("101.25");
    fireEvent.keyDown(chart, { key: "ArrowRight" });
    expect(summary?.textContent).toContain("2026-01-02T03:04:06.000Z");
  });

  it("disposes the injected chart when the view unmounts", () => {
    const { port, chart } = fakePort();
    const { unmount } = render(<PriceDepthFootprintView panel={fresh(snapshot())} port={port} nowNs={nowNs} />);
    expect(port.createChart).toHaveBeenCalledTimes(1);
    unmount();
    expect(port.dispose).toHaveBeenCalledTimes(1);
    expect(port.dispose).toHaveBeenCalledWith(chart);
  });

  it("renders and handles keyboard interaction without making network calls", () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(() => Promise.reject(new Error("network disabled in acceptance")));
    const { port } = fakePort();
    const { unmount } = render(<PriceDepthFootprintView panel={fresh(snapshot())} port={port} nowNs={nowNs} />);
    fireEvent.keyDown(screen.getByRole("img", { name: "Keyboard accessible market price chart" }), { key: "ArrowLeft" });
    unmount();
    expect(fetchSpy).not.toHaveBeenCalled();
    fetchSpy.mockRestore();
  });
});
