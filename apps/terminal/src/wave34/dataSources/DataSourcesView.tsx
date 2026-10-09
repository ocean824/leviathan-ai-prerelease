import { useEffect, useState } from "react";
import { dataSourcesApi } from "./api";
import type { DataSourceRow, DataSourcesApiResult, DataSourcesLoader } from "./model";

export interface DataSourcesViewProps {
  loadSources?: DataSourcesLoader;
}

function routeLabel(source: DataSourceRow): string {
  if (!source.requires_credentials) return "No credential required";
  if (source.credential_route === "vault_ref") return "Local vault";
  if (source.credential_route === "gateway") return "Remote data gateway";
  return "Credential not configured";
}

export function DataSourcesView({ loadSources = dataSourcesApi.listSources }: DataSourcesViewProps) {
  const [reloadKey, setReloadKey] = useState(0);
  const [result, setResult] = useState<DataSourcesApiResult | null>(null);

  useEffect(() => {
    let active = true;
    setResult(null);
    void loadSources().then((next) => {
      if (active) setResult(next);
    }).catch(() => {
      if (active) setResult({ ok: false, error: "Data source status unavailable" });
    });
    return () => { active = false; };
  }, [loadSources, reloadKey]);

  if (result === null) {
    return <section className="directory-view" aria-busy="true">
      <h2>Data sources</h2><p role="status">Loading data source status…</p>
    </section>;
  }

  if (!result.ok) {
    return <section className="directory-view">
      <h2>Data sources</h2>
      <p role="alert">Data source status unavailable</p>
      <button type="button" onClick={() => setReloadKey((value) => value + 1)}>Retry</button>
    </section>;
  }

  return <section className="directory-view" aria-label="Data sources">
    <div className="view-intro">
      <div className="eyebrow">MARKET DATA / STATUS</div>
      <h2>Data sources</h2>
      <p>Source health and configuration status. Provider credentials are never displayed here.</p>
    </div>
    {result.data.sources.length === 0
      ? <p role="status">No data sources registered.</p>
      : <div className="directory-grid">
        {result.data.sources.map((source) => <article className="directory-row" key={source.provider_id}>
          <strong>{source.display_name}</strong>
          <code>{source.provider_id}</code>
          <span>{source.status.replaceAll("_", " ")}</span>
          <small>{source.capabilities.join(", ")}</small>
          <small>{routeLabel(source)}</small>
          {source.source_time_ns !== null && <small>Source time: {source.source_time_ns} ns</small>}
          {source.received_time_ns !== null && <small>Received: {source.received_time_ns} ns</small>}
          {source.error_code !== null && <small role="status">Health detail: {source.error_code.replaceAll("_", " ")}</small>}
        </article>)}
      </div>}
  </section>;
}
