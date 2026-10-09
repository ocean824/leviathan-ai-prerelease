import { useState } from "react";
import { api } from "../api/client";
import type { PipelineResult } from "../api/client";

function ConfidenceBar({ value }: { value: string }) {
  const parsed = Number(value);
  const pct = Number.isFinite(parsed)
    ? Math.round(Math.max(0, Math.min(1, parsed)) * 100)
    : null;
  const cls =
    pct !== null && pct >= 70
      ? "conf-bar__fill--high"
      : pct !== null && pct >= 40
        ? "conf-bar__fill--mid"
        : "conf-bar__fill--low";
  return (
    <div className="conf-bar">
      <div className={`conf-bar__fill ${cls}`} style={{ width: `${pct ?? 0}%` }} />
      <span className="conf-bar__label">{pct === null ? "—" : `${pct}%`}</span>
    </div>
  );
}

function permissionClass(permission: string): string {
  const p = permission.toUpperCase();
  if (p === "GRANTED" || p === "ALLOW" || p === "YES") return "chip chip--ok";
  if (p === "DENIED" || p === "BLOCK" || p === "NO") return "chip chip--error";
  return "chip chip--warn";
}

export function Pipeline() {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<PipelineResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function runReplay() {
    setLoading(true);
    setResult(null);
    setError(null);
    const res = await api.pipelineReplay();
    setLoading(false);
    if (res.ok) setResult(res.data);
    else {
      if (res.data) setResult(res.data);
      setError(res.error);
    }
  }

  return (
    <div className="tab-content">
      <section className="panel">
        <h2 className="panel__heading">Pipeline Replay</h2>

        <button
          className="btn-primary"
          onClick={runReplay}
          disabled={loading}
        >
          {loading ? "RUNNING REPLAY…" : "RUN NQ BREAKOUT REPLAY"}
        </button>

        {error && (
          <div style={{ marginTop: "1rem" }}>
            <span className="chip chip--error">REPLAY INCOMPLETE — {error}</span>
          </div>
        )}
      </section>

      {result && (
        <>
          <section className="panel">
            <h2 className="panel__heading">Route attempt</h2>
            <dl className="kv-grid">
              <dt>Decision ID</dt><dd>{result.decision.decision_id}</dd>
              <dt>Status</dt><dd>{result.status.toUpperCase()}</dd>
              <dt>Final outcome</dt><dd>{result.final ? "COMMITTED" : "INCOMPLETE"}</dd>
              {result.failure_reason && <><dt>Reason</dt><dd>{result.failure_reason}</dd></>}
            </dl>
          </section>
          {/* Session */}
          <section className="panel">
            <h2 className="panel__heading">Session</h2>
            <dl className="kv-grid">
              <dt>Label</dt>
              <dd>{result.session.label}</dd>
              <dt>Quality</dt>
              <dd>{result.session.quality}</dd>
            </dl>
          </section>

          {/* Decision */}
          <section className="panel">
            <h2 className="panel__heading">Decision</h2>
            <div className="pipeline-decision">
              <div className="decision-row">
                <span className={permissionClass(result.decision.permission)}>
                  {result.decision.permission.toUpperCase()}
                </span>
                <span className="decision-direction">
                  {result.decision.direction.toUpperCase()}
                </span>
              </div>
              <div className="conf-label">Confidence</div>
              <ConfidenceBar value={result.decision.confidence} />
              <div className="justification">
                <span className="field-label">Justification</span>
                <p className="justification-text">{result.decision.justification}</p>
              </div>
            </div>
          </section>

          {/* Candidate assessment is never displayed as final authority. */}
          <section className="panel">
            <h2 className="panel__heading">Risk assessment (candidate)</h2>
            <dl className="kv-grid">
              <dt>Action</dt>
              <dd>{result.verdict.action.toUpperCase()}</dd>
              <dt>Reason</dt>
              <dd>{result.verdict.reason}</dd>
              <dt>Committed verdict</dt>
              <dd>{result.final_verdict
                ? `${result.final_verdict.action.toUpperCase()}: ${result.final_verdict.reason}`
                : "NONE — attempt unresolved"}</dd>
            </dl>
          </section>

          {/* Journal is present only after the terminal transaction commits. */}
          {result.journal_record && <section className="panel">
            <h2 className="panel__heading">Journal Record</h2>
            <dl className="kv-grid">
              <dt>Outcome</dt>
              <dd>{result.journal_record.outcome.toUpperCase()}</dd>
              <dt>Entry</dt>
              <dd>{result.journal_record.entry ?? "—"}</dd>
              <dt>Exit</dt>
              <dd>{result.journal_record.exit ?? "—"}</dd>
              <dt>MAE</dt>
              <dd>{result.journal_record.mae ?? "—"}</dd>
              <dt>MFE</dt>
              <dd>{result.journal_record.mfe ?? "—"}</dd>
              <dt>Notes</dt>
              <dd>{result.journal_record.post_trade_notes || "—"}</dd>
            </dl>
          </section>}
        </>
      )}
    </div>
  );
}
