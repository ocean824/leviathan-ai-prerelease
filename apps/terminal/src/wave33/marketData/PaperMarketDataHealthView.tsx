import { useEffect, useMemo, useRef, useState, type CSSProperties, type FormEvent } from "react";
import { isSafeIdentifier } from "../../shared/safeLabel";
import {
  PAPER_MD_DATA_TYPES,
  createPaperMarketDataApi,
  type BackfillJobStatusV1,
  type BackfillSubmissionV1,
  type LatestMarketDataV1,
  type PaperMarketDataApi,
  type PaperMarketDataType,
  type PaperMarketDataErrorCode,
  type PaperMarketDataResult,
  type VenueListV1,
} from "./api";

export interface PaperMarketDataHealthViewProps {
  api?: PaperMarketDataApi;
}

const ERROR_MESSAGES: Record<PaperMarketDataErrorCode, string> = {
  NETWORK_UNAVAILABLE: "The market-data service could not be reached.",
  SERVICE_UNAVAILABLE: "Paper market data is unavailable.",
  MARKET_DATA_UNAVAILABLE: "The latest market-data snapshot is unavailable.",
  BACKFILL_UNAVAILABLE: "The backfill service is unavailable.",
  BACKFILL_NOT_FOUND: "That backfill job was not found.",
  INVALID_REQUEST: "The request was rejected. Check the values and try again.",
  INVALID_RESPONSE: "The service returned an invalid response.",
  HTTP_ERROR: "The request could not be completed.",
};

const inputStyle: CSSProperties = {
  background: "#101820",
  border: "1px solid #8798a8",
  borderRadius: 4,
  color: "#f4f7fa",
  font: "inherit",
  minHeight: 40,
  padding: "0.45rem 0.6rem",
};

const buttonStyle: CSSProperties = {
  background: "#173f5f",
  border: "1px solid #86b7d8",
  borderRadius: 4,
  color: "#ffffff",
  cursor: "pointer",
  font: "inherit",
  fontWeight: 650,
  minHeight: 40,
  padding: "0.45rem 0.8rem",
};

function errorText<T>(result: PaperMarketDataResult<T>): string | null {
  return result.ok ? null : ERROR_MESSAGES[result.error];
}

function nsLabel(value: string | null | undefined): string {
  return value ?? "Not supplied";
}

function positiveNs(value: string): boolean {
  if (!/^(?:0|[1-9][0-9]{0,18})$/.test(value)) return false;
  try {
    const n = BigInt(value);
    return n > 0n && n <= 9_223_372_036_854_775_807n;
  } catch {
    return false;
  }
}

function validTimeWindow(start: string, end: string): boolean {
  if (!positiveNs(start) || !positiveNs(end)) return false;
  const t0 = BigInt(start);
  const t1 = BigInt(end);
  return t0 < t1 && t1 - t0 <= 31n * 24n * 60n * 60n * 1_000_000_000n;
}

function asProgress(status: BackfillJobStatusV1): number | null {
  if (!Number.isSafeInteger(status.completed_count) || !Number.isSafeInteger(status.remaining_count)) return null;
  const total = status.completed_count + status.remaining_count;
  if (total <= 0) return status.status === "COMPLETED" ? 100 : null;
  return Math.min(100, Math.max(0, Math.round((status.completed_count / total) * 100)));
}

function freshnessLabel(venues: VenueListV1 | null, venue: string): string {
  const rows = venues?.venues.filter((row) => row.venue === venue) ?? [];
  if (venues?.source_state !== "AVAILABLE" || rows.length === 0) return "Unknown";
  return rows.some((row) => row.unhealthy || row.freshness === "DEGRADED") ? "Degraded" : "Unknown";
}

function StatusIcon({ kind }: { kind: "good" | "warn" | "unknown" }) {
  const glyph = kind === "good" ? "✓" : kind === "warn" ? "!" : "?";
  const color = kind === "good" ? "#8fe0a4" : kind === "warn" ? "#ffd166" : "#d6e2ed";
  return (
    <span aria-hidden="true" style={{ color, fontWeight: 800, marginRight: 6 }}>
      {glyph}
    </span>
  );
}

export function PaperMarketDataHealthView({ api }: PaperMarketDataHealthViewProps) {
  const client = useMemo(() => api ?? createPaperMarketDataApi(), [api]);
  const [venuesResult, setVenuesResult] = useState<VenueListV1 | null>(null);
  const [venuesError, setVenuesError] = useState<string | null>(null);
  const venueReadGeneration = useRef(0);
  const venueViewMounted = useRef(false);
  const [venue, setVenue] = useState("");
  const [instrument, setInstrument] = useState("");
  const [dataType, setDataType] = useState<PaperMarketDataType>(PAPER_MD_DATA_TYPES[0]);
  const [latest, setLatest] = useState<LatestMarketDataV1 | null>(null);
  const [latestSelection, setLatestSelection] = useState("");
  const [latestError, setLatestError] = useState<string | null>(null);
  const [latestLoading, setLatestLoading] = useState(false);

  const [backfillVenue, setBackfillVenue] = useState("");
  const [instrumentsText, setInstrumentsText] = useState("");
  const [backfillTypes, setBackfillTypes] = useState<PaperMarketDataType[]>([PAPER_MD_DATA_TYPES[0]]);
  const [t0, setT0] = useState("");
  const [t1, setT1] = useState("");
  const [maxRecords, setMaxRecords] = useState("1000");
  const [dryRun, setDryRun] = useState(true);
  const [backfillBusy, setBackfillBusy] = useState(false);
  const backfillLock = useRef(false);
  const [backfillError, setBackfillError] = useState<string | null>(null);
  const [submission, setSubmission] = useState<BackfillSubmissionV1 | null>(null);
  const [jobId, setJobId] = useState("");
  const [jobStatus, setJobStatus] = useState<BackfillJobStatusV1 | null>(null);
  const [jobError, setJobError] = useState<string | null>(null);
  const [jobBusy, setJobBusy] = useState(false);

  async function refreshVenues() {
    const generation = ++venueReadGeneration.current;
    try {
      const result = await client.getVenues({ limit: 50 });
      if (!venueViewMounted.current || generation !== venueReadGeneration.current) return;
      if (result.ok) {
        setVenuesResult(result.data);
        setVenuesError(null);
        if (result.data.venues.length > 0) {
          setVenue((current) => current || result.data.venues[0]?.venue || "");
          setBackfillVenue((current) => current || result.data.venues[0]?.venue || "");
        }
      } else {
        setVenuesError(errorText(result));
      }
    } catch {
      if (!venueViewMounted.current || generation !== venueReadGeneration.current) return;
      setVenuesError("Paper market data is unavailable.");
    }
  }

  useEffect(() => {
    venueViewMounted.current = true;
    void refreshVenues();
    // The initial read is intentionally one-shot; there is no auto-reconnect.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    return () => {
      venueViewMounted.current = false;
      venueReadGeneration.current += 1;
    };
  }, [client]);

  async function readLatest(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLatestLoading(true);
    setLatestError(null);
    try {
      const result = await client.getLatest({ venue, instrument: instrument.trim(), type: dataType });
      if (result.ok) {
        setLatest(result.data);
        setLatestSelection(`${venue} / ${instrument.trim()} / ${dataType}`);
      }
      else setLatestError(errorText(result));
    } catch {
      setLatestError("The latest market-data snapshot is unavailable.");
    } finally {
      setLatestLoading(false);
    }
  }

  const parsedInstruments = instrumentsText.split(",").map((value) => value.trim()).filter(Boolean);
  const recordCount = Number(maxRecords);
  const formValid =
    /^[A-Z0-9]{4}$/.test(backfillVenue) &&
    parsedInstruments.length >= 1 && parsedInstruments.length <= 10 &&
    parsedInstruments.every((value) => isSafeIdentifier(value)) &&
    new Set(parsedInstruments).size === parsedInstruments.length &&
    backfillTypes.length >= 1 && backfillTypes.length <= 4 &&
    backfillTypes.every((value) => (PAPER_MD_DATA_TYPES as readonly string[]).includes(value)) &&
    new Set(backfillTypes).size === backfillTypes.length &&
    validTimeWindow(t0, t1) &&
    Number.isSafeInteger(recordCount) && recordCount >= 1 && recordCount <= 50_000;

  async function submitBackfill(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (backfillLock.current || !formValid) return;
    backfillLock.current = true;
    setBackfillBusy(true);
    setBackfillError(null);
    setSubmission(null);
    setJobStatus(null);
    setJobError(null);
    try {
      const result = await client.submitBackfill({
        venue: backfillVenue,
        instruments: parsedInstruments,
        types: [...backfillTypes],
        t0_ns: t0,
        t1_ns: t1,
        max_records: recordCount,
        dry_run: dryRun,
      });
      if (result.ok) {
        setSubmission(result.data);
        if (result.data.status === "QUEUED") setJobId(result.data.job_id);
      } else {
        setBackfillError(errorText(result));
      }
    } catch {
      setBackfillError("The backfill service is unavailable.");
    } finally {
      backfillLock.current = false;
      setBackfillBusy(false);
    }
  }

  async function readJobStatus() {
    if (!jobId || jobBusy) return;
    setJobBusy(true);
    setJobError(null);
    try {
      const result = await client.getBackfillStatus(jobId);
      if (result.ok) setJobStatus(result.data);
      else setJobError(errorText(result));
    } catch {
      setJobError("The backfill service is unavailable.");
    } finally {
      setJobBusy(false);
    }
  }

  const freshness = freshnessLabel(venuesResult, venue);
  const freshnessKind = freshness === "Degraded" ? "warn" : "unknown";
  const gap = latest?.gap_state ?? "UNKNOWN";
  const progress = jobStatus ? asProgress(jobStatus) : null;
  const progressAvailable = jobStatus !== null && progress !== null;

  return (
    <section aria-labelledby="paper-market-data-title" className="tab-content" style={{ color: "#f4f7fa" }}>
      <style>{`
        .paper-md-health input:focus-visible, .paper-md-health select:focus-visible, .paper-md-health button:focus-visible, .paper-md-health textarea:focus-visible { outline: 3px solid #ffd166; outline-offset: 2px; }
        .paper-md-health button:disabled { cursor: not-allowed; opacity: .65; }
        .paper-md-health .pm-field { display: grid; gap: .35rem; min-width: 14rem; }
        .paper-md-health .pm-grid { display: flex; flex-wrap: wrap; gap: 1rem; align-items: end; }
        .paper-md-health .pm-panel { background: #17212b; border: 1px solid #607080; border-radius: 6px; margin: 1rem 0; padding: 1rem; }
        .paper-md-health .pm-muted { color: #c3ced8; }
        .paper-md-health .pm-error { background: #4b1f27; border: 1px solid #ff9aa8; color: #fff; padding: .7rem; }
        .paper-md-health .pm-state { font-weight: 700; }
      `}</style>
      <div className="paper-md-health">
        <header>
          <h1 id="paper-market-data-title">Paper market data health</h1>
          <p className="pm-muted">Read-only feed health and bounded historical-data requests. Times are UTC nanoseconds.</p>
        </header>

        <section className="pm-panel" aria-labelledby="feed-health-heading">
          <h2 id="feed-health-heading">Feed freshness and gaps</h2>
          <div role="status" aria-live="polite" aria-atomic="true" className="pm-state">
            <StatusIcon kind={freshnessKind} />
            <span>Feed freshness: {freshness}</span>
            <span aria-hidden="true"> · </span>
            <StatusIcon kind={gap === "DETECTED" ? "warn" : gap === "NONE" ? "good" : "unknown"} />
            <span>Gap state: {gap}</span>
          </div>
          {venuesResult?.source_state === "ABSENT" && <p>No venue health source is currently available.</p>}
          {venuesError && <p className="pm-error" role="alert">{venuesError} Previous health values, if any, remain unchanged.</p>}
          <button type="button" style={buttonStyle} onClick={() => void refreshVenues()}>
            Refresh feed health
          </button>
          <p className="pm-muted" id="manual-reconnect-reason">Manual reconnect is disabled because no scoped reconnect API is available. This view does not reconnect automatically.</p>
          <button type="button" style={buttonStyle} disabled aria-describedby="manual-reconnect-reason">Reconnect unavailable</button>

          <form onSubmit={(event) => void readLatest(event)} className="pm-grid" aria-label="Read latest market data">
            <label className="pm-field">Venue
              <select aria-label="Latest data venue" style={inputStyle} value={venue} onChange={(event) => setVenue(event.target.value)} required>
                <option value="">Select a venue</option>
                {(venuesResult?.venues ?? []).map((row) => <option key={row.venue} value={row.venue}>{row.venue}</option>)}
              </select>
            </label>
            <label className="pm-field">Instrument
              <input aria-label="Latest data instrument" style={inputStyle} value={instrument} onChange={(event) => setInstrument(event.target.value)} maxLength={128} required />
            </label>
            <label className="pm-field">Data type
              <select aria-label="Latest data type" style={inputStyle} value={dataType} onChange={(event) => setDataType(event.target.value as PaperMarketDataType)}>
                {PAPER_MD_DATA_TYPES.map((type) => <option key={type} value={type}>{type}</option>)}
              </select>
            </label>
            <button type="submit" style={buttonStyle} disabled={latestLoading || !venue || !instrument.trim()}>
              {latestLoading ? "Reading…" : "Read latest"}
            </button>
          </form>
          {latestError && <p className="pm-error" role="alert">{latestError} The previous snapshot is retained and may be stale.</p>}
          {latest && (
            <div aria-live="polite" aria-atomic="true">
              <p className="pm-muted">Last successful query: {latestSelection}{latestError ? " (stale relative to the latest attempt)" : ""}</p>
              <p><strong>Source:</strong> {latest.source_state}; <strong>gap:</strong> {latest.gap_state}</p>
              {latest.event ? (
                <dl>
                  <dt>Event type</dt><dd>{latest.event.event_type}</dd>
                  <dt>Event time (UTC ns)</dt><dd>{latest.event.event_time_ns}</dd>
                  <dt>Source time (UTC ns)</dt><dd>{nsLabel(latest.event.source_time_ns)}</dd>
                  <dt>Ingest time (UTC ns)</dt><dd>{latest.event.ingest_time_ns}</dd>
                </dl>
              ) : <p>No latest event is available; source and gap state are shown as returned.</p>}
            </div>
          )}
        </section>

        <section className="pm-panel" aria-labelledby="backfill-heading">
          <h2 id="backfill-heading">Historical backfill</h2>
          <p className="pm-muted">Dry-run previews do not write data. Uncheck dry run only to queue a bounded job.</p>
          <form onSubmit={(event) => void submitBackfill(event)} aria-label="Backfill request">
            <div className="pm-grid">
              <label className="pm-field">Venue
                <input aria-label="Backfill venue" style={inputStyle} value={backfillVenue} onChange={(event) => setBackfillVenue(event.target.value.toUpperCase())} maxLength={4} required />
              </label>
              <label className="pm-field">Instrument IDs (comma-separated, up to 10)
                <input aria-label="Backfill instruments" style={inputStyle} value={instrumentsText} onChange={(event) => setInstrumentsText(event.target.value)} maxLength={1290} required />
              </label>
              <label className="pm-field">Data types (choose 1–4)
                <select aria-label="Backfill data types" style={{ ...inputStyle, minHeight: 96 }} multiple size={4} value={backfillTypes} onChange={(event) => setBackfillTypes(Array.from(event.target.selectedOptions, (option) => option.value as PaperMarketDataType))}>
                  {PAPER_MD_DATA_TYPES.map((type) => <option key={type} value={type}>{type}</option>)}
                </select>
              </label>
              <label className="pm-field">Start time (UTC nanoseconds)
                <input aria-label="Backfill start time UTC nanoseconds" style={inputStyle} inputMode="numeric" value={t0} onChange={(event) => setT0(event.target.value)} maxLength={19} required />
              </label>
              <label className="pm-field">End time (UTC nanoseconds)
                <input aria-label="Backfill end time UTC nanoseconds" style={inputStyle} inputMode="numeric" value={t1} onChange={(event) => setT1(event.target.value)} maxLength={19} required />
              </label>
              <label className="pm-field">Maximum records (1–50,000)
                <input aria-label="Backfill maximum records" style={inputStyle} inputMode="numeric" type="number" min={1} max={50_000} value={maxRecords} onChange={(event) => setMaxRecords(event.target.value)} required />
              </label>
            </div>
            {!formValid && <p className="pm-muted" id="backfill-validation">Enter a valid venue, 1–10 unique safe instrument IDs, an allowed time window up to 31 days, and a record limit from 1 to 50,000.</p>}
            <label style={{ display: "inline-flex", alignItems: "center", gap: 8, margin: "1rem 0" }}>
              <input aria-label="Dry run backfill" type="checkbox" checked={dryRun} onChange={(event) => setDryRun(event.target.checked)} />
              Dry run (preview only)
            </label>
            <div>
              <button type="submit" style={buttonStyle} disabled={!formValid || backfillBusy} aria-describedby={formValid ? undefined : "backfill-validation"}>
                {backfillBusy ? "Submitting…" : dryRun ? "Preview backfill" : "Queue backfill"}
              </button>
            </div>
          </form>
          {backfillError && <p className="pm-error" role="alert">{backfillError}</p>}
          {submission?.status === "PREVIEW" && (
            <div role="status" aria-live="polite" aria-atomic="true">
              <p><StatusIcon kind="good" />Preview only; writes performed: no.</p>
              <p>{submission.instrument_count} instrument(s), {submission.type_count} type(s), limit {submission.max_records} records.</p>
              <p>Estimated events: {submission.estimated_event_count === null ? "Not supplied" : submission.estimated_event_count}</p>
            </div>
          )}
          {submission?.status === "QUEUED" && <p role="status" aria-live="polite">Backfill queued. Opaque job ID: {submission.job_id}</p>}
          {jobId && (
            <div>
              <button type="button" style={buttonStyle} onClick={() => void readJobStatus()} disabled={jobBusy}>
                {jobBusy ? "Reading status…" : "Read job status"}
              </button>
              {jobError && <p className="pm-error" role="alert">{jobError} The last known job status is retained.</p>}
            </div>
          )}
          {jobStatus && (
            <div aria-live="polite" aria-atomic="true">
              <p><strong>Job status:</strong> {jobStatus.status}; <strong>source:</strong> {jobStatus.source_state}; <strong>gap:</strong> {jobStatus.gap_state}</p>
              {progressAvailable && progress !== null && (
                <>
                  <label htmlFor="backfill-progress">Progress: {jobStatus.completed_count} completed, {jobStatus.remaining_count} remaining</label>
                  <progress id="backfill-progress" aria-label="Backfill progress" max={100} value={progress}>{progress}%</progress>
                </>
              )}
              <p>Last event time (UTC ns): <span>{nsLabel(jobStatus.last_event_time_ns)}</span></p>
              <p>Last ingest time (UTC ns): <span>{nsLabel(jobStatus.last_ingest_time_ns)}</span></p>
              {"next_attempt_utc_ns" in jobStatus && <p>Next attempt (UTC ns): {String(jobStatus.next_attempt_utc_ns)}</p>}
            </div>
          )}
        </section>
      </div>
    </section>
  );
}

export default PaperMarketDataHealthView;
