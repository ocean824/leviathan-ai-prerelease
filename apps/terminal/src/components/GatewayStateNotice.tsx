import type { GatewayConnection } from "../state/useGatewaySnapshot";
import type { PanelState } from "../state/panelState";

export function GatewayStateNotice({
  state,
  lastSuccess,
  retry,
}: {
  state: PanelState<unknown>;
  connection?: GatewayConnection;
  lastSuccess: number | null;
  retry: () => void;
}) {
  if (state.status === "fresh") return null;
  if (state.status === "loading") return <span className="muted">Contacting gateway…</span>;
  const label = state.status === "error"
    ? "DISCONNECTED"
    : state.status === "stale"
      ? "DELAYED"
      : "UNAVAILABLE";
  const reason = state.status === "error" ? state.code : state.status === "stale"
    ? "Source packet is older than the allowed freshness window."
    : state.reason;
  return (
    <div className="gateway-state" role="status">
      <span className={`chip chip--${state.status === "error" ? "error" : "warn"}`}>{label}</span>
      <span className="gateway-state__reason">{reason}</span>
      <button className="text-action" type="button" onClick={retry}>Retry</button>
      <p className="panel-last-success">
        {lastSuccess == null
          ? "No successful response in this session."
          : `Last successful response received: ${new Date(lastSuccess).toLocaleString()}`}
      </p>
    </div>
  );
}
