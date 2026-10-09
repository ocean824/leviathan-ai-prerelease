import type { GatewayConnection } from "../state/useGatewaySnapshot";
import type { PanelState } from "../state/panelState";

function time(value: number | null) {
  return value == null ? "Unavailable" : new Date(value).toLocaleString();
}

export function GatewayProvenance({
  connection,
  lastSuccess,
  expiresAt,
  state,
}: {
  connection: GatewayConnection;
  lastSuccess: number | null;
  expiresAt: number | null;
  state: PanelState<unknown>;
}) {
  const sourceAsOf = state.status === "fresh" || state.status === "stale"
    ? time(state.asOf)
    : "Unavailable — no valid source timestamp";
  return (
    <p className="panel-provenance">
      Source <strong>Gateway API</strong>
      <span className="provenance-separator">·</span>
      Connection <strong>{connection.toUpperCase()}</strong>
      <span className="provenance-separator">·</span>
      {connection === "connected" ? "Response received" : "Last response"}{" "}
      <strong>{time(lastSuccess)}</strong>
      <span className="provenance-separator">·</span>
      Receipt expires <strong>{time(expiresAt)}</strong>
      <span className="provenance-separator">·</span>
      Source as of <strong>{sourceAsOf}</strong>
    </p>
  );
}
