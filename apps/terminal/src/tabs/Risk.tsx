import { api } from "../api/client";
import { GatewayProvenance } from "../components/GatewayProvenance";
import { GatewayStateNotice } from "../components/GatewayStateNotice";
import { useGatewaySnapshot } from "../state/useGatewaySnapshot";

export function Risk() {
  const risk = useGatewaySnapshot(api.riskStatus);
  const verifiedRisk = risk.panel.status === "fresh" ? risk.panel.data : null;

  return (
    <div className="tab-content">
      <section className="panel" aria-label="Sovereign Risk Domain">
        <h2 className="panel__heading">Sovereign Risk Domain</h2>
        <p className="doctrine-line">Risk is sovereign. Nothing overrides this domain.</p>
        {verifiedRisk && (
          <>
            <div className="risk-halt-row">
              {verifiedRisk.halted ? (
                <span className="chip chip--error chip--lg">HALTED · TIMESTAMPED SOURCE</span>
              ) : (
                <span className="chip chip--sovereign chip--lg">
                  SOVEREIGN NOMINAL · TIMESTAMPED SOURCE
                </span>
              )}
              <span className="risk-mode">{verifiedRisk.operating_mode}</span>
            </div>
            {verifiedRisk.halted && verifiedRisk.active_halts.length > 0 && (
              <div className="halt-reasons">
                <h3 className="panel__subheading">Active Halt Triggers</h3>
                <ul className="halt-list">
                  {verifiedRisk.active_halts.map((reason, index) => (
                    <li key={index} className="halt-item">
                      <span className="halt-bullet">▶</span> {reason}
                    </li>
                  ))}
                </ul>
              </div>
            )}
            <div className="policy-table-wrap">
              <h3 className="panel__subheading">Policy Limits</h3>
              <table className="data-table data-table--compact">
                <thead><tr><th>PARAMETER</th><th>LIMIT</th></tr></thead>
                <tbody>
                  <tr><td>Max Daily Drawdown</td><td>{verifiedRisk.policy.max_daily_dd_pct}</td></tr>
                  <tr><td>Max Open Heat</td><td>{verifiedRisk.policy.max_open_heat_pct}</td></tr>
                  {verifiedRisk.policy.consensus_threshold !== undefined && (
                    <tr><td>Consensus Threshold</td><td>{verifiedRisk.policy.consensus_threshold}</td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </>
        )}
        <GatewayStateNotice {...risk} state={risk.panel} />
        <GatewayProvenance {...risk} state={risk.panel} />
      </section>
    </div>
  );
}
