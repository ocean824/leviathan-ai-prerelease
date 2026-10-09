import { api } from "../api/client";
import { GatewayProvenance } from "../components/GatewayProvenance";
import { GatewayStateNotice } from "../components/GatewayStateNotice";
import { useGatewaySnapshot } from "../state/useGatewaySnapshot";

const fetchJournal = () => api.journalRecords(50);

export function CommandCenter() {
  const health = useGatewaySnapshot(api.health);
  const risk = useGatewaySnapshot(api.riskStatus);
  const journal = useGatewaySnapshot(fetchJournal);
  const verifiedHealth = health.panel.status === "fresh" ? health.panel.data : null;
  const verifiedRisk = risk.panel.status === "fresh" ? risk.panel.data : null;
  const verifiedJournal = journal.panel.status === "fresh" ? journal.panel.data : null;

  return (
    <div className="tab-content">
      <section className="panel" aria-label="Gateway Status">
        <h2 className="panel__heading">Gateway Status</h2>
        {verifiedHealth && (
          <dl className="kv-grid">
            <dt>Status</dt>
            <dd>
              REPORTED: {verifiedHealth.status.toUpperCase()}
            </dd>
            <dt>Operating mode</dt>
            <dd>{verifiedHealth.operating_mode}</dd>
            <dt>API</dt>
            <dd>
              {verifiedHealth.service} v{verifiedHealth.version} (core v{verifiedHealth.core_version},{" "}
              {verifiedHealth.env})
            </dd>
          </dl>
        )}
        <GatewayStateNotice {...health} state={health.panel} />
        <GatewayProvenance {...health} state={health.panel} />
      </section>

      <section className="panel" aria-label="Sovereign Risk">
        <h2 className="panel__heading">Sovereign Risk</h2>
        {verifiedRisk && (
          <div className="risk-summary">
            {verifiedRisk.halted ? (
              <span className="chip chip--error">HALTED · TIMESTAMPED SOURCE</span>
            ) : (
              <span className="chip chip--sovereign">SOVEREIGN NOMINAL · TIMESTAMPED SOURCE</span>
            )}
            <span className="risk-mode">{verifiedRisk.operating_mode}</span>
          </div>
        )}
        <GatewayStateNotice {...risk} state={risk.panel} />
        <GatewayProvenance {...risk} state={risk.panel} />
      </section>

      <section className="panel" aria-label="Journal Stats">
        <h2 className="panel__heading">Journal Stats</h2>
        {verifiedJournal && Object.keys(verifiedJournal.stats).length > 0 ? (
          <div className="chip-row">
            {Object.entries(verifiedJournal.stats).map(([key, value]) => (
              <span key={key} className="chip chip--stat">{key.toUpperCase()}: {value}</span>
            ))}
          </div>
        ) : verifiedJournal ? (
          <span className="muted">No stats available.</span>
        ) : (
          <GatewayStateNotice {...journal} state={journal.panel} />
        )}
        <GatewayProvenance {...journal} state={journal.panel} />
      </section>
    </div>
  );
}
