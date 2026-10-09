import {
  CandlestickSeries,
  LineSeries,
  createChart,
  type CreatePriceLineOptions,
  type DeepPartial,
  type IChartApi,
  type ISeriesApi,
  type SeriesOptionsMap,
  type Time,
} from "lightweight-charts";

export type ChartHandle = object;
export type SeriesHandle = object;
export type ChartCreationOptions = DeepPartial<import("lightweight-charts").ChartOptions>;
export type SeriesOptions = Readonly<Record<string, unknown>>;
export type PriceLineOptions = Pick<
  CreatePriceLineOptions,
  "price" | "color" | "lineWidth" | "lineStyle" | "axisLabelVisible" | "title"
>;
export type CustomSeriesDefinition = object;

export interface ChartPort {
  createChart(container: HTMLElement, options: ChartCreationOptions): ChartHandle;
  addCandlestickSeries(chart: ChartHandle, options?: SeriesOptions): SeriesHandle;
  addLineSeries(chart: ChartHandle, options?: SeriesOptions): SeriesHandle;
  addPriceLine(series: SeriesHandle, options: PriceLineOptions): void;
  addCustomSeries(chart: ChartHandle, definition: CustomSeriesDefinition, options?: SeriesOptions): SeriesHandle;
  setData(series: SeriesHandle, data: readonly unknown[]): void;
  resize(chart: ChartHandle, width: number, height: number): void;
  dispose(chart: ChartHandle): void;
}

type RawSeries = {
  setData(data: readonly unknown[]): void;
  createPriceLine(options: PriceLineOptions): unknown;
};
type RawChart = {
  addSeries(type: unknown, options?: unknown): RawSeries;
  addCustomSeries(definition: unknown, options?: unknown): RawSeries;
  remove(): void;
  resize(width: number, height: number, forceRepaint?: boolean): void;
};

function rawChart(chart: ChartHandle): RawChart {
  return chart as RawChart;
}

function rawSeries(series: SeriesHandle): RawSeries {
  return series as RawSeries;
}

export const createLightweightChartsPort = (): ChartPort => ({
  createChart(container, options) {
    return createChart(container, options) as unknown as ChartHandle;
  },
  addCandlestickSeries(chart, options = {}) {
    return rawChart(chart).addSeries(CandlestickSeries, options);
  },
  addLineSeries(chart, options = {}) {
    return rawChart(chart).addSeries(LineSeries, options);
  },
  addPriceLine(series, options) {
    rawSeries(series).createPriceLine(options);
  },
  addCustomSeries(chart, definition, options = {}) {
    return rawChart(chart).addCustomSeries(definition, options);
  },
  setData(series, data) {
    rawSeries(series).setData(data);
  },
  resize(chart, width, height) {
    rawChart(chart).resize(width, height);
  },
  dispose(chart) {
    rawChart(chart).remove();
  },
});

export type { IChartApi, ISeriesApi, SeriesOptionsMap, Time };
