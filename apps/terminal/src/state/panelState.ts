export type Clock = () => number;
export const STREAM_STALE_MS = 3_000;
export const OPERATOR_STALE_MS = 5_000;

export type PanelState<T> =
  | { status: "loading" }
  | { status: "fresh"; data: T; source: string; asOf: number }
  | { status: "stale"; data: T; source: string; asOf: number; lastSuccess: number }
  | { status: "unavailable"; source: string; reason: string }
  | { status: "error"; source: string; code: string; lastSuccess?: number; retry?: () => void };

export const loadingPanel = <T,>(): PanelState<T> => ({ status: "loading" });

export function freshPanel<T>(
  data: T,
  source: string,
  asOf: number | string | null | undefined,
  clock: Clock = Date.now,
): PanelState<T> {
  const stamp = typeof asOf === "string" ? Date.parse(asOf) : asOf;
  if (stamp == null || !Number.isFinite(stamp) || stamp > clock() + 1_000) {
    return unavailablePanel(source, "No valid source timestamp supplied.");
  }
  return { status: "fresh", data, source, asOf: stamp };
}

export const unavailablePanel = <T,>(source: string, reason: string): PanelState<T> =>
  ({ status: "unavailable", source, reason });

export const errorPanel = <T,>(
  source: string,
  code: string,
  lastSuccess?: number,
  retry?: () => void,
): PanelState<T> => ({ status: "error", source, code, lastSuccess, retry });

export function evaluatePanelState<T>(
  state: PanelState<T>,
  clock: Clock,
  thresholdMs: number,
): PanelState<T> {
  if (state.status !== "fresh") return state;
  if (clock() - state.asOf < thresholdMs) return state;
  return {
    status: "stale",
    data: state.data,
    source: state.source,
    asOf: state.asOf,
    lastSuccess: state.asOf,
  };
}
