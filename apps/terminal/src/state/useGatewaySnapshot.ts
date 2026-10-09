import { useEffect, useRef, useState } from "react";
import type { ApiResult } from "../api/client";
import {
  errorPanel,
  evaluatePanelState,
  freshPanel,
  loadingPanel,
  unavailablePanel,
  OPERATOR_STALE_MS,
} from "./panelState";
import type { PanelState } from "./panelState";

export const GATEWAY_POLL_MS = 3_000;
export const GATEWAY_RECEIPT_TTL_MS = 5_000;

type Snapshot<T> = {
  data: T | null;
  lastSuccess: number | null;
  error: string | null;
};

export type GatewayConnection = "checking" | "connected" | "stale" | "disconnected";

export type GatewaySnapshot<T> = {
  connection: GatewayConnection;
  data: T | null;
  panel: PanelState<T>;
  lastSuccess: number | null;
  expiresAt: number | null;
  error: string | null;
  retry: () => void;
};

function sourceTimestamp<T>(data: T): number | string | null | undefined {
  if (data === null || typeof data !== "object") return undefined;
  const record = data as Record<string, unknown>;
  const value = record.as_of ?? record.asOf;
  return typeof value === "number" || typeof value === "string" ? value : undefined;
}

// These legacy endpoints supply no source timestamp. A receipt bounds only how
// long their reported state may be displayed; it does not certify source age.
export function useGatewaySnapshot<T>(
  request: () => Promise<ApiResult<T>>,
  clock: () => number = Date.now,
): GatewaySnapshot<T> {
  const [snapshot, setSnapshot] = useState<Snapshot<T>>({
    data: null,
    lastSuccess: null,
    error: null,
  });
  const [now, setNow] = useState(clock);
  const retryRef = useRef<() => void>(() => undefined);

  useEffect(() => {
    let active = true;
    let inFlight = false;
    let requestId = 0;

    async function refresh(force = false) {
      if (inFlight && !force) return;
      inFlight = true;
      const currentId = ++requestId;
      try {
        const result = await request();
        if (!active || currentId !== requestId) return;
        const receivedAt = clock();
        setNow(receivedAt);
        if (result.ok) {
          setSnapshot({ data: result.data, lastSuccess: receivedAt, error: null });
        } else {
          setSnapshot((previous) => ({ ...previous, data: null, error: result.error }));
        }
      } catch (error) {
        if (!active || currentId !== requestId) return;
        setSnapshot((previous) => ({
          ...previous,
          data: null,
          error: error instanceof Error ? error.message : String(error),
        }));
      } finally {
        if (currentId === requestId) inFlight = false;
      }
    }

    retryRef.current = () => { void refresh(true); };
    void refresh();
    const pollId = window.setInterval(() => { void refresh(); }, GATEWAY_POLL_MS);
    const ageId = window.setInterval(() => setNow(clock()), 1_000);
    return () => {
      active = false;
      requestId += 1;
      window.clearInterval(pollId);
      window.clearInterval(ageId);
      retryRef.current = () => undefined;
    };
  }, [request, clock]);

  const expiresAt = snapshot.lastSuccess == null
    ? null
    : snapshot.lastSuccess + GATEWAY_RECEIPT_TTL_MS;
  const connection: GatewayConnection = snapshot.error
    ? "disconnected"
    : snapshot.data == null
      ? "checking"
      : expiresAt != null && now >= expiresAt
      ? "stale"
      : "connected";

  let panel: PanelState<T>;
  if (connection === "checking" || snapshot.data == null) {
    panel = snapshot.error
      ? errorPanel("Gateway API", snapshot.error, snapshot.lastSuccess ?? undefined, () => retryRef.current())
      : loadingPanel<T>();
  } else if (connection === "disconnected") {
    panel = errorPanel("Gateway API", snapshot.error ?? "Gateway request failed.", snapshot.lastSuccess ?? undefined, () => retryRef.current());
  } else {
    const candidate = freshPanel(snapshot.data, "Gateway API", sourceTimestamp(snapshot.data), clock);
    panel = candidate.status === "fresh"
      ? evaluatePanelState(candidate, clock, OPERATOR_STALE_MS)
      : candidate;
    if (connection === "stale" && panel.status === "fresh") {
      panel = {
        status: "stale",
        data: panel.data,
        source: panel.source,
        asOf: panel.asOf,
        lastSuccess: panel.asOf,
      };
    } else if (connection === "stale" && panel.status === "unavailable") {
      panel = unavailablePanel("Gateway API", "Response receipt expired; current source state is unavailable.");
    }
  }

  return {
    connection,
    data: connection === "connected" ? snapshot.data : null,
    panel,
    lastSuccess: snapshot.lastSuccess,
    expiresAt,
    error: snapshot.error,
    retry: () => retryRef.current(),
  };
}

