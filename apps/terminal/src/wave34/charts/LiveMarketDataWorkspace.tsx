import { useEffect, useMemo, useState } from "react";
import { createPaperMarketDataApi } from "../../wave33/marketData/api";
import type { PaperMarketDataType } from "../../wave33/marketData/api";
import { errorPanel, loadingPanel, unavailablePanel } from "../../state/panelState";
import type { PanelState } from "../../state/panelState";
import { PriceDepthFootprintView } from "./PriceDepthFootprintView";
import type { ChartSnapshotV1 } from "./model";

type Envelope = {
  schema_version: 1;
  state: "HEALTHY" | "STALE" | "DEGRADED" | "UNKNOWN" | "DISCONNECTED" | "NOT_CONFIGURED" | "CONNECTING";
  snapshot: ChartSnapshotV1 | null;
  received_time_ns: string;
  code: string | null;
};

const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const DATA_TYPES = ["trades", "quotes", "mbp-10", "mbo", "ohlcv-1m"] as const;

function stalePanel(data: ChartSnapshotV1, source: string, asOf: number, lastSuccess: number) {
  return { status: "stale" as const, data, source, asOf, lastSuccess };
}

function decodeEnvelope(value: unknown): Envelope | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  const candidate = value as Partial<Envelope>;
  if (
    candidate.schema_version !== 1
    || typeof candidate.state !== "string"
    || !["HEALTHY", "STALE", "DEGRADED", "UNKNOWN", "DISCONNECTED", "NOT_CONFIGURED", "CONNECTING"].includes(candidate.state)
    || typeof candidate.received_time_ns !== "string"
    || !/^[1-9][0-9]{0,18}$/.test(candidate.received_time_ns)
    || !(candidate.snapshot === null || (typeof candidate.snapshot === "object" && !Array.isArray(candidate.snapshot)))
    || !(candidate.code === null || (typeof candidate.code === "string" && /^[A-Z0-9_]{1,64}$/.test(candidate.code)))
  ) return null;
  return candidate as Envelope;
}

function validSnapshot(value: ChartSnapshotV1 | null): value is ChartSnapshotV1 {
  return value !== null
    && typeof value.instrument === "string"
    && typeof value.venue === "string"
    && ["l2", "l3", "nbbo", "none"].includes(value.source)
    && (value.eventTimeNs === null || (typeof value.eventTimeNs === "string" && /^[1-9][0-9]{0,18}$/.test(value.eventTimeNs)))
    && Array.isArray(value.candles)
    && value.candles.length <= 1500
    && (value.footprint === null || (Array.isArray(value.footprint) && value.footprint.length <= 1500));
}

export function LiveMarketDataWorkspace() {
  const marketDataApi = useMemo(() => createPaperMarketDataApi(), []);
  const [venue, setVenue] = useState("");
  const [instrument, setInstrument] = useState("");
  const [dataType, setDataType] = useState<(typeof DATA_TYPES)[number]>("ohlcv-1m");
  const [selection, setSelection] = useState<{ venue: string; instrument: string; dataType: string } | null>(null);
  const [panel, setPanel] = useState<PanelState<ChartSnapshotV1>>(
    unavailablePanel(
      "Paper market data",
      "Chart snapshot is unavailable until a configured venue and instrument are selected.",
    ),
  );
  const [connectionState, setConnectionState] = useState("NOT_CONFIGURED");

  useEffect(() => {
    if (!selection) return undefined;
    let stopped = false;
    let retryTimer: number | undefined;
    let socket: WebSocket | undefined;
    let lastSnapshot: ChartSnapshotV1 | null = null;
    const scheduleReconnect = () => {
      if (stopped || retryTimer !== undefined) return;
      retryTimer = window.setTimeout(() => {
        retryTimer = undefined;
        void connect();
      }, 1_000);
    };
    const connect = async () => {
      if (stopped) return;
      setConnectionState("CONNECTING");
      setPanel((prior) => prior.status === "fresh"
        ? stalePanel(prior.data, prior.source, prior.asOf, Date.now())
        : prior);
      const scheme = window.location.protocol === "https:" ? "wss:" : "ws:";
      const query = new URLSearchParams({ venue: selection.venue, instrument: selection.instrument, type: selection.dataType });
      const ticketResult = await marketDataApi.mintChartStreamTicket({
        venue: selection.venue,
        instrument: selection.instrument,
        type: selection.dataType as PaperMarketDataType,
      });
      if (stopped) return;
      if (!ticketResult.ok) {
        setConnectionState("DISCONNECTED");
        if (lastSnapshot) setPanel(stalePanel(lastSnapshot, "PAPER feed", Date.now(), Date.now()));
        else setPanel(errorPanel("Paper market data", ticketResult.error));
        scheduleReconnect();
        return;
      }
      socket = new WebSocket(
        `${scheme}//${window.location.host}/api/md/chart?${query.toString()}`,
        ["leviathan.chart.v1", `ticket.${ticketResult.data.ticket}`],
      );
      socket.onmessage = (event) => {
        let decoded: unknown;
        try { decoded = JSON.parse(String(event.data)); } catch { decoded = null; }
        const envelope = decodeEnvelope(decoded);
        if (!envelope) {
          setConnectionState("DEGRADED");
          setPanel(errorPanel("Paper market data", "INVALID_SNAPSHOT"));
          return;
        }
        setConnectionState(envelope.state);
        if (validSnapshot(envelope.snapshot)) lastSnapshot = envelope.snapshot;
        if ((envelope.state === "HEALTHY" || envelope.state === "STALE") && lastSnapshot) {
          const stamp = Number(BigInt(envelope.received_time_ns) / 1_000_000n);
          if (envelope.state === "HEALTHY") {
            setPanel({ status: "fresh", data: lastSnapshot, source: "PAPER feed", asOf: stamp });
          } else {
            setPanel(stalePanel(lastSnapshot, "PAPER feed", stamp, stamp));
          }
        } else if (lastSnapshot && ["DEGRADED", "UNKNOWN", "DISCONNECTED", "CONNECTING"].includes(envelope.state)) {
          setPanel(stalePanel(lastSnapshot, "PAPER feed", Date.now(), Date.now()));
        } else {
          setPanel(errorPanel("Paper market data", envelope.code ?? envelope.state));
        }
      };
      socket.onclose = () => {
        if (stopped) return;
        setConnectionState("DISCONNECTED");
        if (lastSnapshot) setPanel(stalePanel(lastSnapshot, "PAPER feed", Date.now(), Date.now()));
        else setPanel(errorPanel("Paper market data", "DISCONNECTED"));
        scheduleReconnect();
      };
      socket.onerror = () => socket?.close();
    };
    void connect();
    return () => {
      stopped = true;
      if (retryTimer !== undefined) window.clearTimeout(retryTimer);
      socket?.close();
    };
  }, [selection, marketDataApi]);

  function submit(event: import("react").FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const safeVenue = venue.trim();
    const safeInstrument = instrument.trim();
    if (!IDENTIFIER.test(safeVenue) || !IDENTIFIER.test(safeInstrument)) {
      setConnectionState("UNKNOWN");
      setPanel(errorPanel("Paper market data", "INVALID_SELECTION"));
      return;
    }
    setPanel(loadingPanel());
    setSelection({ venue: safeVenue, instrument: safeInstrument, dataType });
  }

  return <section aria-label="Live paper chart workspace">
    <div className="view-intro">
      <div className="eyebrow">PAPER / LIVE MARKET DATA</div>
      <h2>Charts</h2>
      <p>Subscribe to a configured venue, instrument and data type. Stale or disconnected feeds remain visibly marked.</p>
    </div>
    <form onSubmit={submit} aria-label="Chart subscription" style={{ display: "flex", gap: 8, flexWrap: "wrap", margin: "12px 0" }}>
      <label>Venue<input aria-label="Venue" value={venue} onChange={(event) => setVenue(event.target.value)} maxLength={128} /></label>
      <label>Instrument<input aria-label="Instrument" value={instrument} onChange={(event) => setInstrument(event.target.value)} maxLength={128} /></label>
      <label>Data type<select aria-label="Data type" value={dataType} onChange={(event) => setDataType(event.target.value as (typeof DATA_TYPES)[number])}>
        {DATA_TYPES.map((item) => <option key={item} value={item}>{item}</option>)}
      </select></label>
      <button type="submit">Connect chart</button>
    </form>
    <p role="status" aria-live="polite">Feed state: {connectionState}</p>
    <PriceDepthFootprintView panel={panel} />
  </section>;
}
