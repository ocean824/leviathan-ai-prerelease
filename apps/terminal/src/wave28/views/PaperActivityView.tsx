import { useCallback, useEffect, useRef, useState } from "react";
import { errorPanel, evaluatePanelState, freshPanel, loadingPanel, OPERATOR_STALE_MS, unavailablePanel } from "../../state/panelState";
import type { Clock, PanelState } from "../../state/panelState";
import {
  createPaperActivityClient,
  DEFAULT_ACTIVITY_LIMIT,
  MAX_ACTIVITY_LIMIT,
} from "../api/paperActivity";
import type {
  PaperActivityErrorCode,
  PaperActivityItemV1,
  PaperActivityPageV1,
  PaperFillCorrectionV1,
  PaperFillV1,
  PaperNetFilledUnitsV1,
  PaperOrderV1,
  PaperRiskV1,
  PaperStatusV1,
} from "../api/paperActivity";

const SOURCE_ACTIVITY = "OMS paper activity";
const SOURCE_STATUS = "OMS order status";
const SOURCE_RISK = "Risk status";
const NO_SOURCE_TIME = "Source timestamp unavailable; API-reported data is not freshness-verified.";
const ACTIVITY_ERROR_MESSAGES: Record<PaperActivityErrorCode, string> = {
  PRINCIPAL_UNTRUSTED: "operator session unavailable",
  PAPER_ACTIVITY_FORBIDDEN: "Paper activity access is unavailable.",
  PAPER_SCOPE_REQUIRED: "Paper account scope is unavailable.",
  INVALID_ACTIVITY_QUERY: "The activity request was rejected.",
  INVALID_ACTIVITY_CURSOR: "The activity page cursor is invalid or expired.",
  PAPER_ACTIVITY_UNAVAILABLE: "The paper ledger is unavailable.",
  ACTIVITY_TOO_LARGE: "The paper activity summary exceeds the supported size.",
  OPERATOR_SESSION_UNAVAILABLE: "operator session unavailable",
  NETWORK_UNAVAILABLE: "The service could not be reached.",
  HTTP_ERROR: "The service returned an unavailable response.",
  INVALID_RESPONSE: "The service response was invalid.",
};

type Fetcher = typeof fetch;
type Pane<T> = { panel: PanelState<T>; data: T | null };

function initialPane<T>(): Pane<T> {
  return { panel: loadingPanel<T>(), data: null };
}

function panelForSuccess<T>(data: T, source: string, asOf: number | string | undefined, clock: Clock): PanelState<T> {
  if (asOf === undefined) return unavailablePanel(source, NO_SOURCE_TIME);
  const state = freshPanel(data, source, asOf, clock);
  return state.status === "fresh" ? evaluatePanelState(state, clock, OPERATOR_STALE_MS) : state;
}

function panelForActivity(): PanelState<PaperActivityPageV1> {
  return unavailablePanel(SOURCE_ACTIVITY, NO_SOURCE_TIME);
}

function PaneNotice<T>({ panel, retry }: { panel: PanelState<T>; retry: () => void }) {
  if (panel.status === "loading") return <p role="status">Loading API-reported data…</p>;
  if (panel.status === "fresh") return <p role="status">Source timestamp present; freshness is evaluated from API time.</p>;
  if (panel.status === "stale") {
    return <p role="status"><strong>STALE</strong> — API source timestamp is outside the freshness window. Last source timestamp: {new Date(panel.asOf).toISOString()}. <button type="button" onClick={retry}>Retry</button></p>;
  }
  if (panel.status === "unavailable") {
    return <p role="status"><strong>UNVERIFIED</strong> — {panel.reason} <button type="button" onClick={retry}>Retry</button></p>;
  }
  const message = ACTIVITY_ERROR_MESSAGES[panel.code as PaperActivityErrorCode] ?? ACTIVITY_ERROR_MESSAGES.HTTP_ERROR;
  return <div role="alert"><strong>UNAVAILABLE</strong> — {message} ({panel.code}). <button type="button" onClick={retry}>Retry</button></div>;
}

function Field({ label, value }: { label: string; value: string | number }) {
  return <><dt>{label}</dt><dd>{value}</dd></>;
}

function OrderDetails({ order }: { order: PaperOrderV1 }) {
  return <dl>
    <Field label="Order ID" value={order.order_id} /><Field label="Venue" value={order.venue} />
    <Field label="Instrument" value={order.instrument_id} /><Field label="Side" value={order.side} />
    <Field label="State" value={order.state} /><Field label="Quantity" value={order.quantity} />
    <Field label="Corrected filled quantity" value={order.filled_quantity} />
    <Field label="Discrepancies" value={order.discrepancies.length ? order.discrepancies.join(", ") : "None"} />
    <Field label="Created (UTC)" value={order.created_at_utc} />
  </dl>;
}

function FillDetails({ fill }: { fill: PaperFillV1 }) {
  return <dl>
    <Field label="Order ID" value={fill.order_id} /><Field label="Execution ID" value={fill.execution_id} />
    <Field label="Venue" value={fill.venue} /><Field label="Instrument" value={fill.instrument_id} />
    <Field label="Side" value={fill.side} /><Field label="Quantity" value={fill.quantity} />
    <Field label="OMS fill price" value={fill.price} /><Field label="OMS commission" value={fill.commission} />
    <Field label="Occurred (UTC)" value={fill.occurred_at_utc} />
  </dl>;
}

function CorrectionDetails({ correction }: { correction: PaperFillCorrectionV1 }) {
  return <dl>
    <Field label="Order ID" value={correction.order_id} /><Field label="Correction ID" value={correction.correction_id} />
    <Field label="Execution ID" value={correction.execution_id} /><Field label="Revision" value={correction.revision} />
    <Field label="Revised quantity" value={correction.revised_quantity} />
    <Field label="Revised price" value={correction.revised_price ?? "Full bust; no price"} />
    <Field label="Revised commission" value={correction.revised_commission} />
    <Field label="Occurred (UTC)" value={correction.occurred_at_utc} />
  </dl>;
}

function ActivityRow({ item }: { item: PaperActivityItemV1 }) {
  if (item.kind === "ORDER") {
    return <tr><th scope="row">ORDER</th><td>{item.ledger_sequence}</td><td><OrderDetails order={item.order} /></td></tr>;
  }
  if (item.kind === "FILL") {
    return <tr><th scope="row">FILL</th><td>{item.ledger_sequence}</td><td><FillDetails fill={item.fill} /></td></tr>;
  }
  return <tr><th scope="row">FILL CORRECTION</th><td>{item.ledger_sequence}</td><td><CorrectionDetails correction={item.correction} /></td></tr>;
}

function ActivityTable({ page }: { page: PaperActivityPageV1 }) {
  return page.items.length === 0
    ? <p>No paper activity on this page.</p>
    : <div className="table-scroll">
        <table aria-label="OMS paper ledger activity">
          <caption>Immutable OMS ledger records; fill corrections are separate records.</caption>
          <thead><tr><th scope="col">Record</th><th scope="col">Ledger sequence</th><th scope="col">Record details</th></tr></thead>
          <tbody>{page.items.map((item) => <ActivityRow key={`${item.ledger_sequence}:${item.kind}`} item={item} />)}</tbody>
        </table>
      </div>;
}

function NetUnits({ rows }: { rows: PaperNetFilledUnitsV1[] }) {
  return <section aria-labelledby="paper-net-units-title">
    <h3 id="paper-net-units-title">OMS net filled units</h3>
    <p>OMS ledger, not broker-confirmed. No cost basis or valuation is calculated.</p>
    {rows.length === 0
      ? <p>No net filled units reported.</p>
      : <table aria-label="OMS net filled units by venue and instrument">
          <thead><tr><th scope="col">Venue</th><th scope="col">Instrument</th><th scope="col">Net units</th></tr></thead>
          <tbody>{rows.map((row) => <tr key={JSON.stringify([row.venue, row.instrument_id])}>
            <th scope="row">{row.venue}</th><td>{row.instrument_id}</td><td>{row.quantity}</td>
          </tr>)}</tbody>
        </table>}
  </section>;
}

function RiskSummary({ risk }: { risk: PaperRiskV1 }) {
  const halt = risk.haltedReported || risk.haltCodes.length > 0 || risk.faultCode !== null;
  return <section aria-label="API-reported HALT status" className="operator-panel">
    <h3>HALT status</h3>
    {halt
      ? <div role="alert"><strong>HALT REPORTED</strong><p>Reasons: {risk.haltCodes.length ? risk.haltCodes.join(", ") : "None reported"}.</p>
          {risk.faultCode && <p>Fault: {risk.faultCode}.</p>}</div>
      : <p>No HALT reported by the risk API.</p>}
    <p>Operating mode (API-reported): {risk.operatingMode}.</p>
    <p>This view cannot change HALT state.</p>
  </section>;
}

function OrderStatusSummary({ status }: { status: PaperStatusV1 }) {
  return <section aria-label="API-reported order status">
    <h3>Order gateway status</h3>
    <p>Recovery status (API-reported): {status.recoveryStatus}.</p>
    <p>Activation count (API-reported): {status.activationCount}.</p>
    {status.liveEnabledReported && <p role="alert">API reported live enabled. LIVE remains disabled in this view.</p>}
  </section>;
}

export function PaperActivityView({ fetcher = fetch, clock = Date.now }: { fetcher?: Fetcher; clock?: Clock }) {
  const [limit, setLimit] = useState(DEFAULT_ACTIVITY_LIMIT);
  const [activity, setActivity] = useState<Pane<PaperActivityPageV1>>(initialPane);
  const [status, setStatus] = useState<Pane<PaperStatusV1>>(initialPane);
  const [risk, setRisk] = useState<Pane<PaperRiskV1>>(initialPane);
  const [now, setNow] = useState(clock);
  const activityGeneration = useRef(0);
  const statusGeneration = useRef(0);
  const riskGeneration = useRef(0);
  const client = useRef(createPaperActivityClient(fetcher));

  useEffect(() => { client.current = createPaperActivityClient(fetcher); }, [fetcher]);

  const loadActivity = useCallback(async (cursor: string | null = null, pageLimit = limit) => {
    const generation = ++activityGeneration.current;
    setActivity((prior) => ({
      data: cursor === null ? null : prior.data,
      panel: loadingPanel<PaperActivityPageV1>(),
    }));
    const result = await client.current.getActivity({ limit: pageLimit, cursor });
    if (generation !== activityGeneration.current) return;
    if (!result.ok) {
      setActivity((prior) => ({
        data: prior.data,
        panel: errorPanel(SOURCE_ACTIVITY, result.error),
      }));
      return;
    }
    setActivity({ data: result.data, panel: panelForActivity() });
  }, [limit]);

  const loadStatus = useCallback(async () => {
    const generation = ++statusGeneration.current;
    setStatus((prior) => ({ ...prior, panel: loadingPanel<PaperStatusV1>() }));
    const result = await client.current.getStatus();
    if (generation !== statusGeneration.current) return;
    const receivedAt = clock();
    setNow(receivedAt);
    if (!result.ok) {
      setStatus((prior) => ({ data: prior.data, panel: errorPanel(SOURCE_STATUS, result.error) }));
      return;
    }
    setStatus({ data: result.data, panel: panelForSuccess(result.data, SOURCE_STATUS, result.data.as_of, () => receivedAt) });
  }, [clock]);

  const loadRisk = useCallback(async () => {
    const generation = ++riskGeneration.current;
    setRisk((prior) => ({ ...prior, panel: loadingPanel<PaperRiskV1>() }));
    const result = await client.current.getRisk();
    if (generation !== riskGeneration.current) return;
    const receivedAt = clock();
    setNow(receivedAt);
    if (!result.ok) {
      setRisk((prior) => ({ data: prior.data, panel: errorPanel(SOURCE_RISK, result.error) }));
      return;
    }
    setRisk({ data: result.data, panel: panelForSuccess(result.data, SOURCE_RISK, result.data.as_of, () => receivedAt) });
  }, [clock]);

  useEffect(() => {
    void loadActivity(null, limit);
    void loadStatus();
    void loadRisk();
    return () => {
      activityGeneration.current += 1;
      statusGeneration.current += 1;
      riskGeneration.current += 1;
    };
  }, [limit, loadActivity, loadRisk, loadStatus]);

  useEffect(() => {
    const timer = window.setInterval(() => setNow(clock()), 1_000);
    return () => window.clearInterval(timer);
  }, [clock]);

  const currentStatusPanel = status.panel.status === "fresh"
    ? evaluatePanelState(status.panel, () => now, OPERATOR_STALE_MS)
    : status.panel;
  const currentRiskPanel = risk.panel.status === "fresh"
    ? evaluatePanelState(risk.panel, () => now, OPERATOR_STALE_MS)
    : risk.panel;
  const changeLimit = (event: React.ChangeEvent<HTMLSelectElement>) => {
    const next = Number(event.target.value);
    if (Number.isInteger(next) && next >= 1 && next <= MAX_ACTIVITY_LIMIT) setLimit(next);
  };

  return <main className="tab-content" aria-labelledby="paper-activity-title">
    <section className="panel panel--full" aria-label="Paper activity">
      <h2 id="paper-activity-title" className="panel__heading">Paper Activity</h2>
      <p><strong>PAPER ONLY</strong> — read-only ledger view.</p>
      <p><strong>LIVE DISABLED</strong> — this view has no order, activation, or HALT controls.</p>

      <section aria-label="Risk and HALT status">
        <PaneNotice panel={currentRiskPanel} retry={() => { void loadRisk(); }} />
        {risk.data && <RiskSummary risk={risk.data} />}
      </section>
      <section aria-label="Order gateway status">
        <PaneNotice panel={currentStatusPanel} retry={() => { void loadStatus(); }} />
        {status.data && <OrderStatusSummary status={status.data} />}
      </section>

      <section aria-label="Paper ledger activity">
        <h3>OMS activity</h3>
        <label htmlFor="paper-activity-limit">Records per page</label>
        <select id="paper-activity-limit" value={limit} onChange={changeLimit}>
          <option value={25}>25</option><option value={50}>50</option><option value={100}>100</option>
        </select>
        <PaneNotice panel={activity.panel} retry={() => { void loadActivity(null, limit); }} />
        {activity.data && <>
          <p>Bound account: {activity.data.account_id}. Evidence label: {activity.data.evidence_label}. Environment: PAPER. High-water sequence: {activity.data.high_water_sequence}.</p>
          <p>Response receipt time is not source freshness.</p>
          <ActivityTable page={activity.data} />
          <NetUnits rows={activity.data.net_filled_units} />
          {activity.data.next_cursor && <button type="button" onClick={() => { void loadActivity(activity.data?.next_cursor ?? null, limit); }}>Next page</button>}
        </>}
      </section>
    </section>
  </main>;
}
