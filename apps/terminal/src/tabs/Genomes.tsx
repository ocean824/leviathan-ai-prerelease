import { api } from "../api/client";
import { GatewayProvenance } from "../components/GatewayProvenance";
import { GatewayStateNotice } from "../components/GatewayStateNotice";
import { useGatewaySnapshot } from "../state/useGatewaySnapshot";

export function Genomes() {
  const genomes = useGatewaySnapshot(api.genomes);
  const verifiedGenomes = genomes.panel.status === "fresh" ? genomes.panel.data : null;

  return (
    <div className="tab-content">
      <section className="panel panel--full" aria-label="Strategy Genome Registry">
        <h2 className="panel__heading">Strategy Genome Registry</h2>
        {verifiedGenomes && verifiedGenomes.genomes.length === 0 && (
          <p className="muted">No genomes registered in the last gateway response.</p>
        )}
        {verifiedGenomes && verifiedGenomes.genomes.length > 0 && (
          <div className="table-scroll">
            <table className="data-table">
              <thead>
                <tr><th>STRATEGY ID</th><th>FAMILY</th><th>MARKET</th><th>TIMEFRAME</th><th>REPORTED STATE</th></tr>
              </thead>
              <tbody>
                {verifiedGenomes.genomes.map((genome) => (
                  <tr key={genome.strategy_id}>
                    <td className="monospace">{genome.strategy_id}</td>
                    <td>{genome.family}</td>
                    <td>{genome.market}</td>
                    <td>{genome.timeframe}</td>
                    <td>
                      <span className={`chip chip--${genome.stale ? "warn" : "ok"}`}>
                        {genome.stale ? "REPORTED STALE" : "REPORTED NOT STALE"}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <GatewayStateNotice {...genomes} state={genomes.panel} />
        <GatewayProvenance {...genomes} state={genomes.panel} />
      </section>
    </div>
  );
}
