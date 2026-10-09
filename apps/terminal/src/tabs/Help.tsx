import { REGISTRY } from "../navigation/registry";

export function Help({ reason }: { reason?: string }) {
  return <div className="directory-view">
    <div className="view-intro"><div className="eyebrow">SYSTEM / DIRECTORY</div><h2>Function directory</h2>
      <p>Type a code or use the command syntax below. Commands navigate and set local context only.</p></div>
    {reason && <div className="notice notice--warning" role="alert">{reason}</div>}
    <section className="directory-panel"><div className="section-heading"><span>01</span><h3>Workspaces & views</h3><small>{REGISTRY.length} entries</small></div>
      <div className="directory-grid">{REGISTRY.map((entry) => <div className="directory-row" key={entry.code}>
        <strong>{entry.code}</strong><span>{entry.label}</span><small>{entry.description}</small><em>{entry.kind}</em>
      </div>)}</div></section>
    <section className="directory-panel"><div className="section-heading"><span>02</span><h3>Command syntax</h3></div>
      <div className="syntax-grid"><div><code>/tab &lt;code&gt;</code><span>Open a function or view</span></div>
        <div><code>/sym &lt;ticker&gt;</code><span>Set symbol and open Symbol</span></div>
        <div><code>/filter &lt;key=val&gt;</code><span>Local fixture filter: symbol, venue, strategy, timeframe</span></div>
        <div><code>/help</code><span>Open this directory</span></div>
        <div><code>/omega &lt;cmd&gt;</code><span>Disabled — OMEGA bridge unavailable (ØMEGA)</span></div></div>
    </section>
  </div>;
}
