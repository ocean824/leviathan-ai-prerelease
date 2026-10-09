import { useEffect, useMemo, useRef, useState } from "react";
import type { PanelState } from "../../state/panelState";
import {
  MAX_CANDLE_BARS,
  MAX_FOOTPRINT_LEVELS_PER_BAR,
  MAX_MBP_LEVELS,
  normalizeChartSnapshot,
  toChartTime,
  toEventTimeNs,
  type ChartSnapshotV1,
  type MarketBarV1,
  type PriceLevelV1,
} from "./model";
import {
  createLightweightChartsPort,
  type ChartHandle,
  type ChartPort,
} from "./ChartPort";

export type PriceDepthFootprintViewProps = {
  panel: PanelState<ChartSnapshotV1>;
  port?: ChartPort;
  nowNs?: string;
  className?: string;
};

const colors = {
  panel: "#10161f",
  panelRaised: "#151e29",
  border: "#263444",
  text: "#e6edf5",
  muted: "#91a0b2",
  accent: "#65b8ff",
  green: "#27c997",
  red: "#ff667e",
  amber: "#f3bd5b",
};

const decimalNumber = (value: string): number => {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : Number.NaN;
};

const timeLabel = (eventTimeNs: string): string => {
  try {
    return new Date(Number(toEventTimeNs(eventTimeNs) / 1_000_000n)).toISOString();
  } catch {
    return "Invalid timestamp";
  }
};

function stateMessage(panel: PanelState<ChartSnapshotV1>): { label: string; detail: string; color: string } {
  switch (panel.status) {
    case "loading":
      return { label: "Loading", detail: "Waiting for a market-data snapshot.", color: colors.accent };
    case "fresh":
      return { label: "Live snapshot", detail: `Source ${panel.source} · updated ${new Date(panel.asOf).toISOString()}`, color: colors.green };
    case "stale":
      return { label: "Stale snapshot", detail: `Last successful update ${new Date(panel.lastSuccess).toISOString()} · source ${panel.source}`, color: colors.amber };
    case "unavailable":
      return { label: "Unavailable", detail: panel.reason, color: colors.muted };
    case "error":
      return { label: "Data error", detail: `Source ${panel.source} · ${panel.code}`, color: colors.red };
  }
}

function latestBar(bars: MarketBarV1[]): MarketBarV1 | undefined {
  return bars[bars.length - 1];
}

function PriceList({ rows, side }: { rows: PriceLevelV1[]; side: "bid" | "ask" }) {
  const maxQuantity = Math.max(1, ...rows.map(({ quantity }) => Math.abs(decimalNumber(quantity)) || 0));
  return (
    <div aria-label={`${side} depth heatmap`} style={{ display: "grid", gap: 3 }}>
      {rows.map((row, index) => {
        const quantity = decimalNumber(row.quantity);
        const opacity = Number.isFinite(quantity) ? 0.12 + 0.42 * Math.abs(quantity) / maxQuantity : 0.12;
        const color = side === "bid" ? colors.green : colors.red;
        return (
          <div key={`${row.price}-${index}`} style={{
            display: "grid", gridTemplateColumns: "1fr auto", gap: 10, padding: "3px 7px",
            borderRadius: 3, background: `color-mix(in srgb, ${color} ${Math.round(opacity * 100)}%, transparent)`,
            font: "11px/1.25 ui-monospace, SFMono-Regular, Consolas, monospace", color: colors.text,
          }}>
            <span>{row.price}</span><span>{row.quantity}</span>
          </div>
        );
      })}
    </div>
  );
}

function FootprintGrid({ snapshot }: { snapshot: ChartSnapshotV1 }) {
  const bars = snapshot.footprint ?? [];
  if (bars.length === 0) return <p style={mutedStyle}>No MBO footprint samples are available.</p>;
  return (
    <div aria-label="MBO order-flow footprint" style={{ overflowX: "auto", display: "flex", gap: 8, paddingBottom: 3 }}>
      {bars.slice(-12).map((bar) => (
        <div key={bar.eventTimeNs} style={{ minWidth: 114, background: colors.panelRaised, border: `1px solid ${colors.border}`, borderRadius: 5 }}>
          <div style={{ padding: "6px 8px", borderBottom: `1px solid ${colors.border}`, color: colors.muted, font: "10px ui-monospace, monospace" }}>
            {timeLabel(bar.eventTimeNs).slice(11, 19)} UTC
          </div>
          <div style={{ padding: 5, display: "grid", gap: 2 }}>
            {bar.levels.slice(0, MAX_FOOTPRINT_LEVELS_PER_BAR).map((level) => (
              <div key={level.price} style={{ display: "grid", gridTemplateColumns: "1fr auto auto", gap: 5, font: "10px/1.5 ui-monospace, monospace" }}>
                <span style={{ color: colors.muted }}>{level.price}</span>
                <span style={{ color: colors.red }}>{level.bidVolume}</span>
                <span style={{ color: colors.green }}>{level.askVolume}</span>
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

const mutedStyle = { color: colors.muted, fontSize: 12, margin: "8px 0" } as const;

export function PriceDepthFootprintView({
  panel,
  port,
  nowNs,
  className,
}: PriceDepthFootprintViewProps) {
  const chartContainerRef = useRef<HTMLDivElement>(null);
  const activeChartRef = useRef<ChartHandle | null>(null);
  const [renderError, setRenderError] = useState<string | null>(null);
  const [keyboardBar, setKeyboardBar] = useState(0);
  const defaultPort = useMemo(() => createLightweightChartsPort(), []);
  const viewPort = port ?? defaultPort;
  const message = stateMessage(panel);
  const snapshot = useMemo(
    () => panel.status === "fresh" || panel.status === "stale"
      ? normalizeChartSnapshot(panel.data, nowNs ?? String(BigInt(Date.now()) * 1_000_000n))
      : null,
    [panel, nowNs],
  );

  useEffect(() => {
    const container = chartContainerRef.current;
    if (!container || !snapshot || snapshot.candles.length === 0) return undefined;
    let chart: ChartHandle | null = null;
    try {
      chart = viewPort.createChart(container, {
        autoSize: false,
        width: Math.max(1, container.clientWidth),
        height: Math.max(230, container.clientHeight),
        layout: {
          background: { color: colors.panel },
          textColor: colors.muted,
          attributionLogo: false,
          panes: { separatorColor: colors.border },
        },
        grid: { vertLines: { color: "#1c2733" }, horzLines: { color: "#1c2733" } },
        rightPriceScale: { borderColor: colors.border },
        timeScale: { borderColor: colors.border, timeVisible: true, secondsVisible: true },
        crosshair: { vertLine: { color: "#5b7794" }, horzLine: { color: "#5b7794" } },
      });
      activeChartRef.current = chart;
      const candles = viewPort.addCandlestickSeries(chart, {
        upColor: colors.green,
        downColor: colors.red,
        borderVisible: false,
        wickUpColor: colors.green,
        wickDownColor: colors.red,
        priceLineVisible: false,
      });
      const candleData = snapshot.candles.map((bar) => ({
        time: toChartTime(bar.eventTimeNs),
        open: decimalNumber(bar.open),
        high: decimalNumber(bar.high),
        low: decimalNumber(bar.low),
        close: decimalNumber(bar.close),
      })).filter((bar) => [bar.open, bar.high, bar.low, bar.close].every(Number.isFinite));
      viewPort.setData(candles, candleData);
      if (snapshot.gex) {
        const levels = [
          ["Call wall", snapshot.gex.callWall, "#ff8e60"],
          ["Put wall", snapshot.gex.putWall, "#7da8ff"],
          ["Zero gamma", snapshot.gex.zeroGammaFlip, "#f3bd5b"],
          ...(snapshot.gex.topStrikes ?? []).map((level) => [level.label, level.price, "#b394ff"] as const),
        ] as const;
        for (const [label, price, color] of levels.slice(0, 3 + 32)) {
          if (!price || !Number.isFinite(decimalNumber(price))) continue;
          viewPort.addPriceLine(candles, {
            price: decimalNumber(price),
            color,
            lineWidth: 1,
            lineStyle: 2,
            axisLabelVisible: true,
            title: `${label} · ${snapshot.gex.source} · as of ${timeLabel(snapshot.gex.asOfNs)}`,
          });
        }
      }
      setRenderError(null);
    } catch (error) {
      if (chart) viewPort.dispose(chart);
      activeChartRef.current = null;
      setRenderError(error instanceof Error ? error.message : "Chart renderer failed.");
    }
    const observer = typeof ResizeObserver === "undefined"
      ? null
      : new ResizeObserver((entries) => {
          const rect = entries[0]?.contentRect;
          if (chart && rect) viewPort.resize(chart, Math.max(1, rect.width), Math.max(230, rect.height));
        });
    if (observer) observer.observe(container);
    else {
      const onResize = () => {
        if (chart) viewPort.resize(chart, Math.max(1, container.clientWidth), Math.max(230, container.clientHeight));
      };
      window.addEventListener("resize", onResize);
      return () => {
        window.removeEventListener("resize", onResize);
        if (chart) viewPort.dispose(chart);
        activeChartRef.current = null;
      };
    }
    return () => {
      observer?.disconnect();
      if (chart) viewPort.dispose(chart);
      activeChartRef.current = null;
    };
  }, [snapshot, viewPort]);

  useEffect(() => () => {
    if (activeChartRef.current) viewPort.dispose(activeChartRef.current);
    activeChartRef.current = null;
  }, [viewPort]);

  const bars = snapshot?.candles ?? [];
  const selectedIndex = Math.min(Math.max(keyboardBar, 0), Math.max(0, bars.length - 1));
  const selectedBar = bars[selectedIndex] ?? latestBar(bars);
  const depth = snapshot?.source === "nbbo" || snapshot?.source === "none" ? null : snapshot?.depth ?? null;
  const summary = snapshot
    ? [
        `${snapshot.instrument} ${snapshot.venue}`,
        `${bars.length} candle bars shown (cap ${MAX_CANDLE_BARS})`,
        selectedBar ? `selected bar at ${timeLabel(selectedBar.eventTimeNs)}: O ${selectedBar.open}, H ${selectedBar.high}, L ${selectedBar.low}, C ${selectedBar.close}` : "No candle bars available",
        depth ? `${depth.feed === "mbp10" ? "L2 MBP-10" : "L3 MBO"} depth with ${depth.bids.length} bid and ${depth.asks.length} ask levels` : "No depth layer",
        snapshot.gex ? `GEX from ${snapshot.gex.source}, as of ${timeLabel(snapshot.gex.asOfNs)}` : "No GEX levels",
      ].join(". ")
    : message.detail;

  return (
    <section className={className} aria-label="Price, depth, footprint, and gamma chart" style={{
      background: colors.panel, border: `1px solid ${colors.border}`, borderRadius: 8,
      color: colors.text, padding: 12, fontFamily: "Inter, Segoe UI, sans-serif", minWidth: 0,
    }}>
      <header style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12, marginBottom: 10 }}>
        <div>
          <div style={{ fontSize: 14, fontWeight: 650, letterSpacing: "0.02em" }}>{snapshot ? snapshot.instrument : "Market chart"}</div>
          <div style={{ color: colors.muted, fontSize: 11, marginTop: 3 }}>{snapshot ? `${snapshot.venue} · ${snapshot.source.toUpperCase()}` : "No instrument snapshot"}</div>
        </div>
        <div role="status" aria-live="polite" style={{ color: message.color, fontSize: 11, fontWeight: 600, textAlign: "right" }}>
          <div>{message.label}</div><div style={{ color: colors.muted, fontWeight: 400, marginTop: 2 }}>{message.detail}</div>
        </div>
      </header>
      {(panel.status === "loading" || panel.status === "unavailable" || panel.status === "error") && (
        <div role={panel.status === "error" ? "alert" : "status"} style={{ padding: "20px 12px", border: `1px dashed ${colors.border}`, borderRadius: 6, color: colors.muted, textAlign: "center", fontSize: 12 }}>
          {message.detail}
        </div>
      )}
      {panel.status === "fresh" || panel.status === "stale" ? (
        <>
          {bars.length === 0 ? (
            <>
              <div role="status" style={{ padding: 20, color: colors.muted, fontSize: 12 }}>No candle bars in this snapshot. The chart is sparse; no prices were inferred.</div>
              {depth && <section aria-label="Unaligned depth snapshot" style={{ margin: "0 10px 10px", padding: 8, border: "1px solid #263444", borderRadius: 5 }}><div style={{ fontSize: 10, color: colors.muted, marginBottom: 5 }}>{depth.feed === "mbp10" ? "L2 MBP-10" : "L3 MBO"} depth · no candle time axis to align against</div><PriceList rows={[...depth.asks].reverse().slice(0, MAX_MBP_LEVELS)} side="ask" /><PriceList rows={depth.bids.slice(0, MAX_MBP_LEVELS)} side="bid" /></section>}
            </>
          ) : (
            <div style={{ position: "relative", height: 310, border: `1px solid ${colors.border}`, borderRadius: 5, overflow: "hidden" }}>
              <div
                ref={chartContainerRef}
                role="img"
                tabIndex={0}
                aria-label="Keyboard accessible market price chart"
                aria-describedby="chart-summary"
                onKeyDown={(event) => {
                  if (event.key === "ArrowLeft") { event.preventDefault(); setKeyboardBar((index) => Math.max(0, index - 1)); }
                  if (event.key === "ArrowRight") { event.preventDefault(); setKeyboardBar((index) => Math.min(bars.length - 1, index + 1)); }
                }}
                style={{ width: "100%", height: "100%", outlineColor: colors.accent }}
              />
              {depth && (
                <aside aria-label={depth.feed === "mbp10" ? "L2 MBP-10 depth ladder heatmap" : "L3 MBO depth ladder heatmap"} style={{
                  position: "absolute", top: 9, right: 48, width: 146, maxHeight: 250, overflow: "auto",
                  background: "rgba(12,18,25,.93)", border: `1px solid ${colors.border}`, borderRadius: 5, padding: 6,
                }}>
                  <div style={{ color: colors.text, fontSize: 10, fontWeight: 700, marginBottom: 5 }}>
                    {depth.feed === "mbp10" ? "L2 · MBP-10" : "L3 · MBO"}
                  </div>
                  <PriceList rows={[...depth.asks].reverse().slice(0, MAX_MBP_LEVELS)} side="ask" />
                  <div aria-hidden="true" style={{ borderTop: `1px solid ${colors.accent}`, margin: "4px 0" }} />
                  <PriceList rows={depth.bids.slice(0, MAX_MBP_LEVELS)} side="bid" />
                </aside>
              )}
            </div>
          )}
          {snapshot?.source === "nbbo" && <div role="note" style={mutedStyle}>NBBO only — no order-book depth is available, and none is inferred.</div>}
          {snapshot?.quote && <section aria-label="Latest bid and ask" style={{ display: "flex", gap: 16, padding: "8px 2px", font: "12px ui-monospace, monospace" }}>
            <span>Bid: {snapshot.quote.bid ? `${snapshot.quote.bid.price} × ${snapshot.quote.bid.size}` : "Unavailable"}</span>
            <span>Ask: {snapshot.quote.ask ? `${snapshot.quote.ask.price} × ${snapshot.quote.ask.size}` : "Unavailable"}</span>
            <span style={{ color: colors.muted }}>Source time: {timeLabel(snapshot.quote.eventTimeNs)}</span>
          </section>}
          {(snapshot?.source === "l2" || snapshot?.source === "l3") && !depth && <div role="status" style={mutedStyle}>Depth unavailable in this snapshot. No depth levels were inferred.</div>}
          {renderError && <div role="alert" style={{ color: colors.red, fontSize: 11, marginTop: 6 }}>Chart renderer error: {renderError}</div>}
          <div id="chart-summary" style={{ color: colors.muted, fontSize: 11, lineHeight: 1.5, padding: "8px 2px" }}>
            <span className="sr-only">Chart summary: </span>{summary}. Use left and right arrow keys while focused to inspect candle timestamps and values.
          </div>
          {snapshot?.gex && (
            <div aria-label="Gamma exposure levels" style={{ display: "flex", flexWrap: "wrap", gap: "5px 12px", color: colors.muted, fontSize: 10, paddingBottom: 8 }}>
              {[
                ["Call wall", snapshot.gex.callWall],
                ["Put wall", snapshot.gex.putWall],
                ["Zero gamma", snapshot.gex.zeroGammaFlip],
                ...(snapshot.gex.topStrikes ?? []).map((level) => [level.label, level.price] as const),
              ].filter((row) => row[1]).slice(0, 3 + 32).map(([label, price]) => (
                <span key={label}>{label}: <strong style={{ color: colors.text }}>{price}</strong></span>
              ))}
              <span>Source: {snapshot.gex.source} · as of {timeLabel(snapshot.gex.asOfNs)}</span>
            </div>
          )}
          {snapshot && depth?.feed === "mbo" && (
            <section aria-label="Order flow footprint" style={{ marginTop: 5 }}>
              <h3 style={{ fontSize: 10, letterSpacing: "0.08em", color: colors.muted, margin: "2px 0 6px", textTransform: "uppercase" }}>
                MBO footprint · bid volume / ask volume
              </h3>
              <FootprintGrid snapshot={snapshot} />
            </section>
          )}
          {snapshot?.indicators && (
            <div aria-label="Depth-driven indicators" style={{ display: "flex", gap: 16, borderTop: `1px solid ${colors.border}`, marginTop: 8, paddingTop: 7, fontSize: 10 }}>
              {snapshot.indicators.bookImbalance !== null && <span>Book imbalance <strong>{snapshot.indicators.bookImbalance}</strong></span>}
              {snapshot.indicators.cumulativeDelta !== null && <span>Cumulative delta <strong>{snapshot.indicators.cumulativeDelta}</strong></span>}
            </div>
          )}
        </>
      ) : null}
    </section>
  );
}









