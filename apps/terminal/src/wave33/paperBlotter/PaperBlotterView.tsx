import { useCallback, useEffect, useMemo, useState } from "react";
import type {
  PaperActivityItemV1,
  PaperActivityPageV1,
  PaperRiskV1,
  PaperStatusV1,
} from "../../wave28/api/paperActivity";
import {
  createPaperBlotterClient,
  isCancellablePaperOrder,
} from "./api";
import type {
  PaperBlotterClient,
  PaperBlotterErrorCode,
  PaperSelectedOrderV1,
} from "./api";

const ERROR_TEXT: Record<PaperBlotterErrorCode, string> = {
  PRINCIPAL_UNTRUSTED: "Operator session unavailable.",
  PAPER_ACTIVITY_FORBIDDEN: "Paper account access is unavailable.",
  PAPER_SCOPE_REQUIRED: "Paper account scope is unavailable.",
  INVALID_ACTIVITY_QUERY: "The activity request was rejected.",
  INVALID_ACTIVITY_CURSOR: "The activity page cursor is invalid or expired.",
  PAPER_ACTIVITY_UNAVAILABLE: "The paper activity service is unavailable.",
  ACTIVITY_TOO_LARGE: "The activity response exceeds the supported size.",
  OPERATOR_SESSION_UNAVAILABLE: "Operator session unavailable.",
  NETWORK_UNAVAILABLE: "The service could not be reached.",
  HTTP_ERROR: "The service returned an unavailable response.",
  INVALID_RESPONSE: "The service response was invalid.",
  INVALID_ORDER_ID: "The selected order identifier is invalid.",
  ORDER_NOT_CANCELLABLE: "This order is not eligible for cancellation.",
  ORDER_UNAVAILABLE: "The selected order is unavailable.",
};
const BROKER_UNCONFIRMED_STATES = new Set([
  "SUBMITTING",
  "DISPATCH_IN_FLIGHT",
  "CANCEL_PENDING",
  "CANCEL_REQUESTED_UNCONFIRMED",
  "UNKNOWN_SUBMIT",
  "UNKNOWN_CANCEL",
  "RECONCILE_REQUIRED",
]);
const MAX_ACTIVITY_PAGES = 50;
const MAX_ACTIVITY_RECORDS = 10_000;

type Load<T> = { state: "loading" } | { state: "error"; code: PaperBlotterErrorCode } | { state: "ready"; data: T };
const loading = <T,>(): Load<T> => ({ state: "loading" });

function SourceTime({ label, value }: { label: string; value?: number | string }) {
  return <p>{label}: {value === undefined ? "Source timestamp unavailable" : String(value)}</p>;
}

function LoadMessage<T>({ load, retry }: { load: Load<T>; retry: () => void }) {
  if (load.state === "loading") return <p role="status">Loading API-reported data…</p>;
  if (load.state === "error") return <div role="alert">UNAVAILABLE — {ERROR_TEXT[load.code]} <button type="button" onClick={retry}>Retry</button></div>;
  return null;
}

function itemsForOrder(items: PaperActivityItemV1[], orderId: string) {
  return items.filter((item) => {
    if (item.kind === "ORDER") return item.order.order_id === orderId;
    if (item.kind === "FILL") return item.fill.order_id === orderId;
    return item.correction.order_id === orderId;
  }).sort((left, right) => left.ledger_sequence - right.ledger_sequence);
}

function recordLabel(item: PaperActivityItemV1) {
  if (item.kind === "ORDER") return `Order record · ${item.order.created_at_utc}`;
  if (item.kind === "FILL") return `Fill ${item.fill.execution_id} · ${item.fill.occurred_at_utc}`;
  return `Correction ${item.correction.correction_id} for execution ${item.correction.execution_id} · ${item.correction.occurred_at_utc}`;
}

function OrderGroup({
  orderId, items, onSelect,
}: { orderId: string; items: PaperActivityItemV1[]; onSelect: (orderId: string) => void }) {
  const order = items.find((item) => item.kind === "ORDER");
  if (!order || order.kind !== "ORDER") return null;
  const executions = new Set(items.filter((item) => item.kind === "FILL").map((item) => item.fill.execution_id));
  return <article aria-label={`Order ${orderId}`}>
    <h3>{order.order.instrument_id} · {order.order.side}</h3>
    <p>Order ID: {orderId}</p>
    <p>Current OMS snapshot state: {order.order.state}. This is a current snapshot, not historical transition evidence.</p>
    <p>OMS quantity: {order.order.quantity}; corrected filled quantity: {order.order.filled_quantity}.</p>
    <p>Broker confirmation: not established by the OMS ledger snapshot.</p>
    <p>Source timestamp (order record): {order.order.created_at_utc}</p>
    <h4>Ordered ledger records</h4>
    <ol aria-label={`Ledger sequence for order ${orderId}`}>
      {items.map((item) => <li key={`${item.ledger_sequence}-${item.kind}`}>
        Sequence {item.ledger_sequence}: <span>{recordLabel(item)}</span>
        {item.kind === "FILL" && <span> · OMS fill {item.fill.quantity} at {item.fill.price}</span>}
        {item.kind === "FILL_CORRECTION" && <span> · revision {item.correction.revision}, revised quantity {item.correction.revised_quantity}, price {item.correction.revised_price ?? "busted"}</span>}
        {item.kind === "FILL_CORRECTION" && !executions.has(item.correction.execution_id) && <span> · original fill not present in loaded activity</span>}
      </li>)}
    </ol>
    <button type="button" onClick={() => onSelect(orderId)}>Load selected order details</button>
  </article>;
}

function RiskPanel({ risk }: { risk: PaperRiskV1 }) {
  const halted = risk.haltedReported || risk.haltCodes.length > 0 || risk.faultCode !== null;
  return <section aria-label="Risk status">
    <h2>Risk status</h2>
    <p>{halted ? "HALT reported" : "No HALT reported by risk status"}</p>
    {risk.haltCodes.length > 0 && <p>HALT codes: {risk.haltCodes.join(", ")}</p>}
    {risk.faultCode && <p>Fault: {risk.faultCode}</p>}
    <p>Operating mode: {risk.operatingMode}</p>
    <p>Risk-event history: unavailable; this endpoint exposes current status only.</p>
    <SourceTime label="Risk status source timestamp" value={risk.as_of} />
  </section>;
}

export function PaperBlotterView({ client }: { client?: PaperBlotterClient } = {}) {
  const api = useMemo(() => client ?? createPaperBlotterClient(), [client]);
  const [activity, setActivity] = useState<Load<PaperActivityPageV1>>(loading);
  const [status, setStatus] = useState<Load<PaperStatusV1>>(loading);
  const [risk, setRisk] = useState<Load<PaperRiskV1>>(loading);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [selected, setSelected] = useState<Load<PaperSelectedOrderV1> | null>(null);
  const [cancelBusy, setCancelBusy] = useState(false);

  const loadActivity = useCallback(async () => {
    setActivity(loading());
    const first = await api.getActivity({ limit: 100 });
    if (!first.ok) { setActivity({ state: "error", code: first.error }); return; }
    const records: PaperActivityItemV1[] = [...first.data.items];
    let cursor = first.data.next_cursor;
    const seenCursors = new Set<string>();
    let pagesLoaded = 1;
    while (cursor !== null) {
      if (pagesLoaded >= MAX_ACTIVITY_PAGES || seenCursors.has(cursor)) {
        setActivity({ state: "error", code: "PAPER_ACTIVITY_UNAVAILABLE" });
        return;
      }
      seenCursors.add(cursor);
      const result = await api.getActivity({ limit: 100, cursor });
      if (!result.ok) { setActivity({ state: "error", code: result.error }); return; }
      pagesLoaded += 1;
      records.push(...result.data.items);
      cursor = result.data.next_cursor;
      if (records.length > MAX_ACTIVITY_RECORDS) {
        setActivity({ state: "error", code: "PAPER_ACTIVITY_UNAVAILABLE" });
        return;
      }
    }
    setActivity({ state: "ready", data: { ...first.data, items: records, next_cursor: null } });
  }, [api]);
  const loadStatus = useCallback(async () => {
    setStatus(loading());
    const result = await api.getStatus();
    setStatus(result.ok ? { state: "ready", data: result.data } : { state: "error", code: result.error });
  }, [api]);
  const loadRisk = useCallback(async () => {
    setRisk(loading());
    const result = await api.getRisk();
    setRisk(result.ok ? { state: "ready", data: result.data } : { state: "error", code: result.error });
  }, [api]);
  useEffect(() => { void loadActivity(); void loadStatus(); void loadRisk(); }, [loadActivity, loadRisk, loadStatus]);

  const selectOrder = async (orderId: string) => {
    setSelectedId(orderId);
    setSelected(loading());
    const result = await api.getSelectedOrder(orderId);
    setSelected(result.ok ? { state: "ready", data: result.data } : { state: "error", code: result.error });
  };
  const cancelSelected = async () => {
    if (selected?.state !== "ready" || !isCancellablePaperOrder(selected.data)) return;
    setCancelBusy(true);
    const result = await api.cancelOrder(selected.data);
    setCancelBusy(false);
    if (result.ok) setSelected({ state: "ready", data: result.data });
    else setSelected({ state: "error", code: result.error });
  };
  const retrySelected = () => { if (selectedId) void selectOrder(selectedId); };

  const groups = activity.state === "ready"
    ? [...new Set(activity.data.items.filter((item) => item.kind === "ORDER").map((item) => item.kind === "ORDER" ? item.order.order_id : ""))]
    : [];

  return <main aria-labelledby="paper-blotter-title">
    <h1 id="paper-blotter-title">Paper blotter</h1>
    <p>Read-only OMS and risk evidence, except a server-authorized cancel for an eligible paper order. No order placement is available.</p>
    <section aria-label="Paper order activity">
      <h2>Order activity and fill lineage</h2>
      <LoadMessage load={activity} retry={() => void loadActivity()} />
      {activity.state === "ready" && <>
        <p>Activity source: OMS ledger. Record order follows ledger sequence within each order.</p>
        <p>Historical order state-transition events: unavailable from the current activity API.</p>
        <p>Broker-confirmed positions: unavailable from this endpoint.</p>
        {groups.length === 0 ? <p>No orders in the available activity.</p> : groups.map((id) => <OrderGroup key={id} orderId={id} items={itemsForOrder(activity.data.items, id)} onSelect={(orderId) => void selectOrder(orderId)} />)}
        <h3>OMS net filled units</h3>
        <p>OMS accounting units; these are not broker-confirmed positions.</p>
        <ul>{activity.data.net_filled_units.map((row) => <li key={`${row.venue}:${row.instrument_id}`}>{row.venue} · {row.instrument_id}: {row.quantity}</li>)}</ul>
      </>}
    </section>
    <section aria-label="Order gateway status">
      <h2>Order gateway status</h2>
      <LoadMessage load={status} retry={() => void loadStatus()} />
      {status.state === "ready" && <><p>Recovery status: {status.data.recoveryStatus}</p><p>Activation count: {status.data.activationCount}</p><p>Live enabled (API-reported): {status.data.liveEnabledReported ? "Yes" : "No"}</p><SourceTime label="Order status source timestamp" value={status.data.as_of} /></>}
    </section>
    <LoadMessage load={risk} retry={() => void loadRisk()} />
    {risk.state === "ready" && <RiskPanel risk={risk.data} />}
    {selected && <section aria-label="Selected order details">
      <h2>Selected order details</h2>
      <LoadMessage load={selected} retry={retrySelected} />
      {selected.state === "ready" && <>
        <p>Order ID: {selected.data.order_id}</p>
        <p>Current OMS state: {selected.data.state} (version {selected.data.version}).</p>
        <p>Filled quantity (OMS): {selected.data.filled_quantity}</p>
        <p>Broker confirmation: {BROKER_UNCONFIRMED_STATES.has(selected.data.state) ? "UNCONFIRMED; the OMS state does not establish broker confirmation." : selected.data.state === "CANCELED" ? "OMS reports canceled; broker confirmation is not independently established here." : "This view does not claim broker-confirmed position."}</p>
        <p>Selected order source timestamp: unavailable; the endpoint does not provide one.</p>
        {isCancellablePaperOrder(selected.data) && <button type="button" disabled={cancelBusy} onClick={() => void cancelSelected()}>{cancelBusy ? "Sending cancel request…" : "Request cancel"}</button>}
        {!isCancellablePaperOrder(selected.data) && <p>Cancel unavailable for this order state or discrepancy status.</p>}
      </>}
    </section>}
  </main>;
}
