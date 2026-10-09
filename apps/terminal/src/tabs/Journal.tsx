import { api } from "../api/client";
import type { JournalRecord, TradeOutcome } from "../api/client";
import { GatewayProvenance } from "../components/GatewayProvenance";
import { GatewayStateNotice } from "../components/GatewayStateNotice";
import { useGatewaySnapshot } from "../state/useGatewaySnapshot";

function outcomeClass(outcome: TradeOutcome): string {
  switch (outcome) {
    case "win": return "outcome--win";
    case "loss": return "outcome--loss";
    case "scratch": return "outcome--scratch";
    case "blocked": return "outcome--blocked";
  }
}

function nullish(value: string | null): string {
  return value ?? "—";
}

const fetchJournal = () => api.journalRecords(50);

export function Journal() {
  const journal = useGatewaySnapshot(fetchJournal);
  const response = journal.panel.status === "fresh" ? journal.panel.data : null;
  const records = response?.records ?? null;

  return (
    <div className="tab-content">
      <section className="panel panel--full" aria-label="Trade Journal">
        <h2 className="panel__heading">Trade Journal</h2>
        {records && records.length === 0 && (
          <p className="muted">No journaled trades yet.</p>
        )}
        {response && (
          <section aria-label="Journal totals">
            <h3>Outcome totals (verified only)</h3>
            <ul>
              {Object.entries(response.stats).map(([outcome, count]) => (
                <li key={outcome}>{outcome}: {count}</li>
              ))}
            </ul>
            <p>{response.unverified_count} unverified rows not counted</p>
          </section>
        )}
        {records && records.length > 0 && (
          <>
            <div className="table-scroll">
              <table className="data-table">
                <thead>
                  <tr><th>VERIFICATION</th><th>OUTCOME</th><th>TRADE ID</th><th>SETUP</th><th>ENTRY</th><th>EXIT</th><th>MAE</th><th>MFE</th><th>NOTES</th></tr>
                </thead>
                <tbody>
                  {records.map((record: JournalRecord) => (
                    <tr key={`${record.decision_id}:${record.trade_id}`}>
                      <td>
                        <span className={record.provenance === "route_attempt_terminal_verified" ? "chip chip--ok" : "chip chip--warn"}>
                          {record.provenance === "route_attempt_terminal_verified" ? "Verified" : "Unverified / historical"}
                        </span>
                      </td>
                      <td><span className={"outcome-badge " + outcomeClass(record.outcome)}>{record.outcome.toUpperCase()}</span></td>
                      <td className="monospace">{record.trade_id}</td>
                      <td className="monospace">{record.setup_id}</td>
                      <td>{nullish(record.entry)}</td>
                      <td>{nullish(record.exit)}</td>
                      <td>{nullish(record.mae)}</td>
                      <td>{nullish(record.mfe)}</td>
                      <td className="notes-cell">{record.post_trade_notes || "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
        <GatewayStateNotice {...journal} state={journal.panel} />
        <GatewayProvenance {...journal} state={journal.panel} />
      </section>
    </div>
  );
}
