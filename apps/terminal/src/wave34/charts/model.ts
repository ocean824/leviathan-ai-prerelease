import type { UTCTimestamp } from "lightweight-charts";

export const MAX_CANDLE_BARS = 1_500;
export const MAX_MBP_LEVELS = 10;
export const MAX_FOOTPRINT_LEVELS_PER_BAR = 50;
export const MAX_GEX_LEVELS = 32;

export type PriceLevelV1 = { price: string; quantity: string };
export type FootprintLevelV1 = { price: string; bidVolume: string; askVolume: string };
export type MarketBarV1 = {
  eventTimeNs: string;
  open: string;
  high: string;
  low: string;
  close: string;
  volume: string;
};
export type MboTradeV1 = {
  eventTimeNs: string;
  price: string;
  quantity: string;
  aggressor: "buy" | "sell";
};
export type DepthSnapshotV1 = {
  feed: "mbp10" | "mbo";
  eventTimeNs: string;
  bids: PriceLevelV1[];
  asks: PriceLevelV1[];
};
export type QuoteSnapshotV1 = {
  bid: { price: string; size: string } | null;
  ask: { price: string; size: string } | null;
  eventTimeNs: string;
};
export type FootprintBarV1 = { eventTimeNs: string; levels: FootprintLevelV1[] };
export type GexOverlayV1 = {
  asOfNs: string;
  source: string;
  callWall?: string;
  putWall?: string;
  zeroGammaFlip?: string;
  topStrikes?: Array<{ price: string; label: string; value?: string }>;
};
export type ChartSnapshotV1 = {
  instrument: string;
  venue: string;
  source: "l2" | "l3" | "nbbo" | "none";
  eventTimeNs: string | null;
  candles: MarketBarV1[];
  depth: DepthSnapshotV1 | null;
  quote?: QuoteSnapshotV1 | null;
  footprint: FootprintBarV1[] | null;
  gex: GexOverlayV1 | null;
  indicators: { bookImbalance: string | null; cumulativeDelta: string | null } | null;
};

const NS_PER_SECOND = 1_000_000_000n;
const DECIMAL_RE = /^([+-]?)(\d+)(?:\.(\d+))?$/;

function decimalParts(value: string): { coefficient: bigint; scale: number } {
  const match = DECIMAL_RE.exec(value);
  if (!match) throw new TypeError(`Invalid decimal value: ${value}`);
  const fraction = match[3] ?? "";
  const sign = match[1] === "-" ? -1n : 1n;
  return { coefficient: sign * BigInt(match[2] + fraction), scale: fraction.length };
}

function decimalString(coefficient: bigint, scale: number): string {
  const negative = coefficient < 0n;
  const digits = (negative ? -coefficient : coefficient).toString().padStart(scale + 1, "0");
  const value = scale === 0 ? digits : `${digits.slice(0, -scale)}.${digits.slice(-scale)}`;
  const trimmed = value.includes(".") ? value.replace(/0+$/, "").replace(/\.$/, "") : value;
  return `${negative && coefficient !== 0n ? "-" : ""}${trimmed}`;
}

export function addDecimals(left: string, right: string): string {
  const a = decimalParts(left);
  const b = decimalParts(right);
  const scale = Math.max(a.scale, b.scale);
  return decimalString(
    a.coefficient * 10n ** BigInt(scale - a.scale) + b.coefficient * 10n ** BigInt(scale - b.scale),
    scale,
  );
}

export function toEventTimeNs(eventTimeNs: string): bigint {
  if (/^\d+$/.test(eventTimeNs)) return BigInt(eventTimeNs);
  const match = /^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?(Z|[+-]\d\d:\d\d)$/.exec(eventTimeNs);
  if (!match) throw new TypeError(`Expected epoch nanoseconds or zoned ISO-8601 timestamp: ${eventTimeNs}`);
  const fraction = (match[2] ?? "").padEnd(9, "0");
  const milliseconds = Date.parse(`${match[1]}.${fraction.slice(0, 3)}${match[3]}`);
  if (!Number.isFinite(milliseconds)) throw new TypeError(`Invalid event timestamp: ${eventTimeNs}`);
  return BigInt(milliseconds) * 1_000_000n + BigInt(fraction.slice(3) || "0");
}

export function toChartTime(eventTimeNs: string): UTCTimestamp {
  const ns = toEventTimeNs(eventTimeNs);
  const wholeSeconds = ns / NS_PER_SECOND;
  const remainder = ns % NS_PER_SECOND;
  return (Number(wholeSeconds) + Number(remainder) / 1e9) as UTCTimestamp;
}

function bounded<T>(items: T[], max: number): T[] {
  return items.slice(0, max);
}

export function normalizeChartSnapshot(input: ChartSnapshotV1, _nowNs: string): ChartSnapshotV1 {
  const candles = bounded(
    [...input.candles].filter((bar) => {
      try {
        toEventTimeNs(bar.eventTimeNs);
        for (const n of [bar.open, bar.high, bar.low, bar.close, bar.volume]) decimalParts(n);
        return true;
      } catch {
        return false;
      }
    }).sort((a, b) => {
      const left = toEventTimeNs(a.eventTimeNs);
      const right = toEventTimeNs(b.eventTimeNs);
      return left < right ? -1 : left > right ? 1 : 0;
    }).filter((bar, index, all) => index === 0 || toEventTimeNs(bar.eventTimeNs) !== toEventTimeNs(all[index - 1].eventTimeNs)),
    MAX_CANDLE_BARS,
  );
  const depth =
    input.source === "l2" && input.depth?.feed === "mbp10"
      ? { ...input.depth, bids: bounded(input.depth.bids, MAX_MBP_LEVELS), asks: bounded(input.depth.asks, MAX_MBP_LEVELS) }
      : input.source === "l3" && input.depth?.feed === "mbo"
        ? { ...input.depth, bids: bounded(input.depth.bids, MAX_MBP_LEVELS), asks: bounded(input.depth.asks, MAX_MBP_LEVELS) }
        : null;
  const footprint =
    input.source === "l3" && input.footprint
      ? bounded(input.footprint, MAX_CANDLE_BARS).map((bar) => ({
          ...bar,
          levels: bounded(bar.levels, MAX_FOOTPRINT_LEVELS_PER_BAR),
        }))
      : null;
  const gex = input.gex
    ? { ...input.gex, topStrikes: bounded(input.gex.topStrikes ?? [], MAX_GEX_LEVELS) }
    : null;
  return {
    ...input,
    candles,
    depth,
    footprint,
    gex,
    indicators: input.source === "nbbo" || input.source === "none" ? null : input.indicators,
  };
}

export function alignByEventTime<T extends { eventTimeNs: string }>(
  bars: MarketBarV1[],
  events: T[],
): Array<{ bar: MarketBarV1; events: T[] }> {
  const grouped = new Map<string, T[]>();
  for (const event of events) {
    let key: string;
    try {
      key = toEventTimeNs(event.eventTimeNs).toString();
    } catch {
      continue;
    }
    grouped.set(key, [...(grouped.get(key) ?? []), event]);
  }
  return bars.map((bar) => ({
    bar,
    events: grouped.get(toEventTimeNs(bar.eventTimeNs).toString()) ?? [],
  }));
}

export function buildFootprint(events: MboTradeV1[], bars: MarketBarV1[]): FootprintBarV1[] {
  const sortedBars = [...bars].sort((a, b) => {
    const left = toEventTimeNs(a.eventTimeNs);
    const right = toEventTimeNs(b.eventTimeNs);
    return left < right ? -1 : left > right ? 1 : 0;
  });
  const mutable = sortedBars.map((bar) => ({ eventTimeNs: bar.eventTimeNs, levels: new Map<string, { bidVolume: string; askVolume: string }>() }));
  for (const trade of events) {
    const timestamp = toEventTimeNs(trade.eventTimeNs);
    let barIndex = -1;
    for (let index = sortedBars.length - 1; index >= 0; index -= 1) {
      if (toEventTimeNs(sortedBars[index].eventTimeNs) <= timestamp) {
        barIndex = index;
        break;
      }
    }
    if (barIndex < 0) continue;
    const levels = mutable[barIndex].levels;
    const current = levels.get(trade.price) ?? { bidVolume: "0", askVolume: "0" };
    if (trade.aggressor === "sell") current.bidVolume = addDecimals(current.bidVolume, trade.quantity);
    else current.askVolume = addDecimals(current.askVolume, trade.quantity);
    levels.set(trade.price, current);
  }
  return mutable.map((bar) => ({
    eventTimeNs: bar.eventTimeNs,
    levels: [...bar.levels.entries()]
      .sort(([a], [b]) => {
        const left = decimalParts(a);
        const right = decimalParts(b);
        const scale = Math.max(left.scale, right.scale);
        const x = left.coefficient * 10n ** BigInt(scale - left.scale);
        const y = right.coefficient * 10n ** BigInt(scale - right.scale);
        return x < y ? -1 : x > y ? 1 : 0;
      })
      .slice(-MAX_FOOTPRINT_LEVELS_PER_BAR)
      .map(([price, volumes]) => ({ price, ...volumes })),
  }));
}
