import { useEffect, useRef, useState } from "react";
import {
  errorPanel,
  loadingPanel,
  unavailablePanel,
} from "../../state/panelState";
import type { Clock, PanelState } from "../../state/panelState";
import { orderMonitorClient } from "../api/orderMonitor";
import { classifyOrderDisposition, isValidOrderId } from "../api/orderMonitor";
import type {
  OrderMonitorClient,
  OrderMonitorDisposition,
  OrderMonitorOrder,
  OrderMonitorStatus,
} from "../api/orderMonitor";

const STATUS_POLL_MS = 5_000;
const SAFE_DISCREPANCY_CODE = /^[A-Z0-9_:-]{1,80}$/;

function receiptAge(now: number, receivedAt: number): string {
  const seconds = Math.floor(Math.max(0, now - receivedAt) / 1_000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes}m ${seconds % 60}s`;
}

function panelLabel<T>(state: PanelState<T>): string {
  if (state.status === "loading") return "LOADING";
  if (state.status === "error") return "UNAVAILABLE";
  if (state.status === "fresh") return "FRESH";
  if (state.status === "stale") return "STALE";
  return "UNVERIFIED";
}

function panelMessage<T>(state: PanelState<T>): string {
  if (state.status === "loading") return "Waiting for the Orders API.";
  if (state.status === "error") {
    switch (state.code) {
      case "UNAUTHORIZED": return "You are not authorized to view order status.";
      case "NOT_FOUND": return "Order not found for this ID.";
      case "INVALID_ORDER_ID": return "Enter a valid order ID.";
      case "INVALID_RESPONSE": return "The Orders API response could not be verified.";
      case "GATEWAY_UNAVAILABLE": return "The Orders API is unavailable.";
      default: return "The Orders API returned an error.";
    }
  }
  if (state.status === "unavailable") return state.reason;
  if (state.status === "stale") return "The source timestamp is outside the allowed freshness window.";
  return "Source timestamp is available.";
}

function StatusDetails({ data }: { data: OrderMonitorStatus }) {
  return (
    <dl className="order-monitor__facts">
      <div><dt>Live trading</dt><dd>DISABLED</dd></div>
      <div><dt>OMS recovery (API-reported)</dt><dd>{data.recovery_status}</dd></div>
      <div><dt>Active OMS scopes (API-reported)</dt><dd>{data.activation_count}</dd></div>
    </dl>
  );
}

function OrderDetails({ order }: { order: OrderMonitorOrder }) {
  const disposition: OrderMonitorDisposition = classifyOrderDisposition(order);
  const brokerUnconfirmed = disposition === "UNKNOWN";
  const stateText = disposition === "ACCEPTED"
    ? order.state === "PARTIALLY_FILLED" ? "ACCEPTED · PARTIALLY FILLED" : "ACCEPTED"
    : disposition === "FILLED"
      ? "FILLED"
      : disposition === "UNKNOWN"
        ? "UNKNOWN · BROKER UNCONFIRMED"
        : order.state;
  return (
    <>
      <p className={`order-monitor__disposition order-monitor__disposition--${disposition.toLowerCase()}`}>
        {stateText} <span>· API-reported</span>
      </p>
      {brokerUnconfirmed && (
        <p role="status" className="notice notice--warning">
          Broker confirmation is unconfirmed. Treat this order outcome as UNKNOWN.
        </p>
      )}
      <dl className="order-monitor__facts">
        <div><dt>Order ID</dt><dd>{order.order_id}</dd></div>
        <div><dt>OMS state</dt><dd>{order.state}</dd></div>
        <div><dt>Venue</dt><dd>{order.venue}</dd></div>
        <div><dt>Environment</dt><dd>{order.environment}</dd></div>
        <div><dt>Instrument</dt><dd>{order.instrument_id}</dd></div>
        <div><dt>Filled quantity (OMS)</dt><dd>{order.filled_quantity}</dd></div>
        <div><dt>Venue order ID</dt><dd>{order.venue_order_id ?? "Not available"}</dd></div>
      </dl>
      {order.discrepancies.some((code) => SAFE_DISCREPANCY_CODE.test(code)) && (
        <div className="order-monitor__discrepancies">
          <strong>Discrepancy codes</strong>
          <ul>{order.discrepancies.filter((code) => SAFE_DISCREPANCY_CODE.test(code))
            .map((code, index) => <li key={`${code}-${index}`}>{code}</li>)}</ul>
        </div>
      )}
      <p className="order-monitor__source-note">
        Values are reported by the OMS API. No broker source timestamp is supplied.
      </p>
    </>
  );
}

function ReceiptLine({ receivedAt, now, hasCurrentData }: {
  receivedAt: number | null;
  now: number;
  hasCurrentData: boolean;
}) {
  return (
    <div className="operator-panel__provenance">
      <span>Source <strong>Orders API · API-reported</strong></span>
      <span>
        {hasCurrentData ? "Local receipt" : "Last successful receipt"}
        <strong>{receivedAt == null ? "Unavailable" : new Date(receivedAt).toLocaleString()}</strong>
        {receivedAt != null && <> · Receipt age <strong>{receiptAge(now, receivedAt)}</strong></>}
      </span>
    </div>
  );
}

function MonitorPanel<T>({
  title,
  state,
  data,
  receivedAt,
  now,
  retry,
  hasCurrentData,
  renderData,
}: {
  title: string;
  state: PanelState<T>;
  data: T | null;
  receivedAt: number | null;
  now: number;
  retry?: () => void;
  hasCurrentData: boolean;
  renderData: (value: T) => React.ReactNode;
}) {
  return (
    <section className={`operator-panel operator-panel--${state.status}`} aria-label={title}>
      <div className="operator-panel__topline"><span>READ-ONLY / OMON</span><span>◌</span></div>
      <div className="operator-panel__heading">
        <h3>{title}</h3><span className="operator-panel__status">{panelLabel(state)}</span>
      </div>
      <div className="operator-panel__body">
        {data != null ? renderData(data) : <p role="status">{panelMessage(state)}</p>}
        {state.status === "error" && retry && <button className="text-action" type="button" onClick={retry}>Retry read</button>}
        {data != null && state.status === "unavailable" && <p className="order-monitor__panel-note">{state.reason}</p>}
      </div>
      <ReceiptLine receivedAt={receivedAt} now={now} hasCurrentData={hasCurrentData} />
    </section>
  );
}

export function OrderMonitorView({
  client = orderMonitorClient,
  clock = Date.now,
}: {
  client?: OrderMonitorClient;
  clock?: Clock;
}) {
  const [now, setNow] = useState(clock());
  const [statusPanel, setStatusPanel] = useState<PanelState<OrderMonitorStatus>>(loadingPanel());
  const [statusData, setStatusData] = useState<OrderMonitorStatus | null>(null);
  const [statusReceivedAt, setStatusReceivedAt] = useState<number | null>(null);
  const [statusRetryCount, setStatusRetryCount] = useState(0);
  const [orderId, setOrderId] = useState("");
  const [orderPanel, setOrderPanel] = useState<PanelState<OrderMonitorOrder> | null>(null);
  const [orderData, setOrderData] = useState<OrderMonitorOrder | null>(null);
  const [orderReceivedAt, setOrderReceivedAt] = useState<number | null>(null);
  const orderRequestSequence = useRef(0);

  useEffect(() => {
    const ticker = window.setInterval(() => setNow(clock()), 1_000);
    return () => window.clearInterval(ticker);
  }, [clock]);

  useEffect(() => {
    let active = true;
    let inFlight = false;
    const refresh = async () => {
      if (inFlight) return;
      inFlight = true;
      try {
        const result = await client.getStatus();
        if (!active) return;
        if (result.ok) {
          const receivedAt = clock();
          setStatusData(result.data);
          setStatusReceivedAt(receivedAt);
          setStatusPanel(unavailablePanel(
            "Orders API",
            "API response has no source timestamp; source freshness is unverified.",
          ));
        } else {
          setStatusData(null);
          setStatusPanel(errorPanel("Orders API", result.error));
        }
      } catch {
        if (!active) return;
        setStatusData(null);
        setStatusPanel(errorPanel("Orders API", "GATEWAY_UNAVAILABLE"));
      } finally {
        inFlight = false;
      }
    };
    void refresh();
    const poll = window.setInterval(() => { void refresh(); }, STATUS_POLL_MS);
    return () => {
      active = false;
      window.clearInterval(poll);
    };
  }, [client, clock, statusRetryCount]);

  async function lookupOrder(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const requestSequence = ++orderRequestSequence.current;
    const requestedId = orderId;
    if (!isValidOrderId(requestedId)) {
      setOrderData(null);
      setOrderReceivedAt(null);
      setOrderPanel(errorPanel("Orders API", "INVALID_ORDER_ID"));
      return;
    }
    setOrderData(null);
    setOrderReceivedAt(null);
    setOrderPanel(loadingPanel());
    try {
      const result = await client.getOrder(requestedId);
      if (requestSequence !== orderRequestSequence.current) return;
      if (result.ok) {
        const receivedAt = clock();
        setOrderData(result.data);
        setOrderReceivedAt(receivedAt);
        setOrderPanel(unavailablePanel(
          "Orders API",
          "API response has no source timestamp; source freshness is unverified.",
        ));
      } else {
        setOrderData(null);
        setOrderPanel(errorPanel("Orders API", result.error));
      }
    } catch {
      if (requestSequence !== orderRequestSequence.current) return;
      setOrderData(null);
      setOrderPanel(errorPanel("Orders API", "GATEWAY_UNAVAILABLE"));
    }
  }

  return (
    <div className="operator-view operator-view--order-monitor">
      <div className="view-intro operator-view__intro">
        <div className="eyebrow">OPERATOR WORKSPACE <span>/ ORDER VISIBILITY</span></div>
        <div className="view-intro__title"><h2>Order Monitor</h2><span className="view-code">OMON</span></div>
        <p>Read-only OMS visibility. Accepted, filled, and unknown outcomes remain distinct.</p>
      </div>

      <div className="context-ribbon">
        <div><span className="context-ribbon__label">LIVE TRADING</span><strong>DISABLED</strong></div>
        <div><span className="context-ribbon__label">DATA PROVENANCE</span><strong>API-reported · source time unverified</strong></div>
        <div><span className="context-ribbon__label">RECEIPT AGE</span><strong>Local receipt only · not broker time</strong></div>
      </div>

      <div className="operator-grid">
        <MonitorPanel
          title="Gateway status"
          state={statusPanel}
          data={statusData}
          receivedAt={statusReceivedAt}
          now={now}
          retry={() => setStatusRetryCount((value) => value + 1)}
          hasCurrentData={statusData !== null}
          renderData={(data) => <StatusDetails data={data} />}
        />
        <section className="operator-panel" aria-label="Order lookup">
          <div className="operator-panel__topline"><span>READ-ONLY / GET</span><span>◌</span></div>
          <div className="operator-panel__heading"><h3>Order lookup</h3><span className="operator-panel__status">OPTIONAL</span></div>
          <div className="operator-panel__body">
            <form className="order-monitor__lookup" onSubmit={lookupOrder}>
              <label htmlFor="order-monitor-id">Order ID</label>
              <input
                id="order-monitor-id"
                name="order_id"
                value={orderId}
                onChange={(event) => setOrderId(event.target.value)}
                maxLength={32}
                autoComplete="off"
              />
              <button className="text-action" type="submit">Read order</button>
            </form>
            {orderPanel != null && orderData == null && <p role="status">{panelMessage(orderPanel)}</p>}
          </div>
        </section>
        {orderPanel != null && orderData != null && (
          <MonitorPanel
            title="Order snapshot"
            state={orderPanel}
            data={orderData}
            receivedAt={orderReceivedAt}
            now={now}
            hasCurrentData={orderData !== null}
            renderData={(data) => <OrderDetails order={data} />}
          />
        )}
      </div>

      <div className="view-footnote">
        <span>READ-ONLY MONITOR</span>
        <span>No order submission, cancellation, amendment, or flatten action is available.</span>
      </div>
    </div>
  );
}
