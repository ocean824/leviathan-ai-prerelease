import type { PanelState } from "../state/panelState";

export function PanelCard<T>({
  title,
  eyebrow,
  state,
  renderData,
  staleLabel = "Delayed",
}: {
  title: string;
  eyebrow: string;
  state: PanelState<T>;
  renderData: (data: T) => React.ReactNode;
  staleLabel?: string;
}) {
  const source = state.status === "loading" ? "Awaiting source" : state.source;
  const asOf = state.status === "fresh" || state.status === "stale"
    ? new Date(state.asOf).toLocaleString()
    : "Unavailable";
  return (
    <section className={`operator-panel operator-panel--${state.status}`} aria-label={title}>
      <div className="operator-panel__topline"><span>{eyebrow}</span><span>○</span></div>
      <div className="operator-panel__heading"><h3>{title}</h3><span className="operator-panel__status">{state.status === "stale" ? staleLabel : state.status}</span></div>
      <div className="operator-panel__body">
        {state.status === "loading" && <p>Waiting for a timestamped packet.</p>}
        {(state.status === "fresh" || state.status === "stale") && renderData(state.data)}
        {state.status === "unavailable" && <p>{state.reason}</p>}
        {state.status === "error" && <><p>{state.code}</p><p className="panel-last-success">{state.lastSuccess == null ? "No successful response in this session." : `Last successful response: ${new Date(state.lastSuccess).toLocaleString()}`}</p>{state.retry && <button className="text-action" onClick={state.retry}>Retry</button>}</>}
      </div>
      <div className="operator-panel__provenance">
        <span>Source <strong>{source}</strong></span><span>As of <strong>{asOf}</strong></span>
      </div>
    </section>
  );
}
