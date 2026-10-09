import { useMemo, useState } from "react";

const MAX_EA_BYTES = 64 * 1024 * 1024;
const MAX_SET_BYTES = 1024 * 1024;
const INSTALL_PATH = "/api/mt5/ea-host/v1/install";
const SESSION_PATH = "/api/mt5/ea-host/v1/sessions/";

type TerminalFamily = "MT4" | "MT5";
type OperationState = "READY" | "PENDING" | "UNKNOWN" | "ERROR";

interface InstallResponse {
  session_id: string;
  account_id: string;
  environment: "DEMO";
  terminal_family: TerminalFamily;
  expert_relative_path: string;
  preset_relative_path: string;
  ea_sha256: string;
  set_sha256: string;
  provenance: {
    ea_filename: string;
    set_filename: string;
    ea_sha256: string;
    set_sha256: string;
    ea_size_bytes: number;
    set_size_bytes: number;
    installed_at_ns: string;
    operator_id: string;
  };
  startup_config: {
    terminal_family: TerminalFamily;
    expert_name: string;
    set_file: string;
    symbol: string;
    timeframe: string;
    environment: "DEMO";
    execution_allowed: false;
  };
  execution_allowed: false;
}

interface MonitorResponse {
  session_id: string;
  account_id: string;
  environment: "DEMO";
  observed_at_ns: string;
  open_order_count: number;
  open_orders: Array<{
    client_order_id: string;
    venue_order_id: string | null;
    venue: string;
    status: string;
    observed_at_ns: string;
  }>;
  positions: Array<[string, string]>;
  cap_status: "WITHIN_CAPS" | "BREACH" | "UNKNOWN";
  state: "MONITORING" | "HALT_REQUIRED";
  execution_allowed: false;
}

interface KillResponse {
  session_id: string;
  environment: "DEMO";
  state: "STOPPED";
  disabled: boolean;
  close_attempted: true;
  execution_allowed: false;
}

export interface EaHostingViewProps {
  environment: "DEMO" | "LIVE";
  fetcher?: typeof fetch;
}

function fileName(value: string): string {
  return value.split(/[\\/]/).pop() ?? "";
}

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  const chunkSize = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
  }
  return btoa(binary);
}

async function digest(bytes: ArrayBuffer): Promise<string> {
  const hash = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(hash), (value) => value.toString(16).padStart(2, "0")).join("");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isInstallResponse(value: unknown): value is InstallResponse {
  if (!isRecord(value) || !isRecord(value.startup_config) || !isRecord(value.provenance)) return false;
  const validNs = (item: unknown): item is string =>
    typeof item === "string" && /^(0|[1-9][0-9]*)$/.test(item);
  return (
    typeof value.session_id === "string" &&
    typeof value.account_id === "string" &&
    value.environment === "DEMO" &&
    (value.terminal_family === "MT4" || value.terminal_family === "MT5") &&
    typeof value.expert_relative_path === "string" &&
    typeof value.preset_relative_path === "string" &&
    typeof value.ea_sha256 === "string" && /^[0-9a-f]{64}$/.test(value.ea_sha256) &&
    typeof value.set_sha256 === "string" && /^[0-9a-f]{64}$/.test(value.set_sha256) &&
    typeof value.provenance.ea_filename === "string" &&
    typeof value.provenance.set_filename === "string" &&
    value.provenance.ea_sha256 === value.ea_sha256 &&
    value.provenance.set_sha256 === value.set_sha256 &&
    typeof value.provenance.ea_size_bytes === "number" && Number.isSafeInteger(value.provenance.ea_size_bytes) &&
    typeof value.provenance.set_size_bytes === "number" && Number.isSafeInteger(value.provenance.set_size_bytes) &&
    validNs(value.provenance.installed_at_ns) &&
    typeof value.provenance.operator_id === "string" &&
    value.execution_allowed === false &&
    value.startup_config.execution_allowed === false &&
    value.startup_config.environment === "DEMO"
  );
}

function isMonitorResponse(value: unknown): value is MonitorResponse {
  const validNs = (item: unknown): item is string =>
    typeof item === "string" && /^(0|[1-9][0-9]*)$/.test(item);
  return (
    isRecord(value) &&
    typeof value.session_id === "string" &&
    typeof value.account_id === "string" &&
    value.environment === "DEMO" &&
    validNs(value.observed_at_ns) &&
    Array.isArray(value.open_orders) &&
    value.open_orders.every((item) =>
      isRecord(item) &&
      typeof item.client_order_id === "string" &&
      (item.venue_order_id === null || typeof item.venue_order_id === "string") &&
      typeof item.venue === "string" &&
      (item.status === "WORKING" || item.status === "PARTIALLY_FILLED") &&
      validNs(item.observed_at_ns),
    ) &&
    Array.isArray(value.positions) &&
    value.positions.every((item) =>
      Array.isArray(item) && item.length === 2 && typeof item[0] === "string" && typeof item[1] === "string",
    ) &&
    typeof value.open_order_count === "number" && Number.isSafeInteger(value.open_order_count) && value.open_order_count >= 0 &&
    value.open_order_count === value.open_orders.length &&
    (value.cap_status === "WITHIN_CAPS" || value.cap_status === "BREACH" || value.cap_status === "UNKNOWN") &&
    (value.state === "MONITORING" || value.state === "HALT_REQUIRED") &&
    value.execution_allowed === false
  );
}

function isKillResponse(value: unknown): value is KillResponse {
  return (
    isRecord(value) &&
    typeof value.session_id === "string" &&
    value.environment === "DEMO" &&
    value.state === "STOPPED" &&
    value.disabled === true &&
    value.close_attempted === true &&
    value.execution_allowed === false
  );
}

async function responseJson(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return null;
  }
}

export function EaHostingView({ environment, fetcher = fetch }: EaHostingViewProps) {
  const [family, setFamily] = useState<TerminalFamily>("MT5");
  const [eaFile, setEaFile] = useState<File | null>(null);
  const [setFile, setSetFile] = useState<File | null>(null);
  const [symbol, setSymbol] = useState("EURUSD");
  const [timeframe, setTimeframe] = useState("M5");
  const [operation, setOperation] = useState<OperationState>("READY");
  const [message, setMessage] = useState("");
  const [install, setInstall] = useState<InstallResponse | null>(null);
  const [monitor, setMonitor] = useState<MonitorResponse | null>(null);
  const busy = operation === "PENDING";
  const expectedExtension = family === "MT5" ? ".ex5" : ".ex4";

  function clearSession(): void {
    setInstall(null);
    setMonitor(null);
    setMessage("");
    setOperation("READY");
  }

  const selectionError = useMemo(() => {
    if (eaFile && fileName(eaFile.name).toLowerCase().endsWith(expectedExtension) !== true) {
      return "Choose a compiled EA file for the selected terminal.";
    }
    if (setFile && !fileName(setFile.name).toLowerCase().endsWith(".set")) {
      return "Choose a SET preset file.";
    }
    if (eaFile && eaFile.size > MAX_EA_BYTES) return "The EA file exceeds the allowed size.";
    if (setFile && setFile.size > MAX_SET_BYTES) return "The SET file exceeds the allowed size.";
    return "";
  }, [eaFile, expectedExtension, setFile]);

  async function installEa(): Promise<void> {
    if (environment !== "DEMO" || busy || !eaFile || !setFile || selectionError) return;
    setOperation("PENDING");
    setMessage("");
    setInstall(null);
    setMonitor(null);
    try {
      const [eaBytes, setBytes] = await Promise.all([eaFile.arrayBuffer(), setFile.arrayBuffer()]);
      const [eaHash, setHash] = await Promise.all([digest(eaBytes), digest(setBytes)]);
      const response = await fetcher(INSTALL_PATH, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ea_filename: fileName(eaFile.name),
          ea_base64: toBase64(new Uint8Array(eaBytes)),
          set_filename: fileName(setFile.name),
          set_base64: toBase64(new Uint8Array(setBytes)),
          terminal_family: family,
          symbol,
          timeframe,
        }),
      });
      const body = await responseJson(response);
      if (!response.ok || !isInstallResponse(body) || body.ea_sha256 !== eaHash || body.set_sha256 !== setHash) {
        setOperation("UNKNOWN");
        setMessage("Install outcome could not be verified. Check the operator-selected MT5 data folder before retrying.");
        return;
      }
      setInstall(body);
      setOperation("READY");
      setMessage("Files were placed for operator loading. Leviathan did not execute or inspect the EA binary.");
    } catch {
      setOperation("UNKNOWN");
      setMessage("Install outcome is UNKNOWN. Verify the operator-selected MT5 data folder before retrying.");
    }
  }

  async function monitorSession(): Promise<void> {
    if (environment !== "DEMO" || busy || !install) return;
    setOperation("PENDING");
    setMonitor(null);
    try {
      const response = await fetcher(SESSION_PATH + encodeURIComponent(install.session_id), { method: "GET" });
      const body = await responseJson(response);
      if (!response.ok || !isMonitorResponse(body) || body.session_id !== install.session_id || body.account_id !== install.account_id) {
        setMonitor(null);
        setOperation("UNKNOWN");
        setMessage("Monitoring status is UNKNOWN; no status was inferred.");
        return;
      }
      setMonitor(body);
      setOperation("READY");
      setMessage(body.state === "MONITORING" && body.cap_status === "WITHIN_CAPS" ? "Monitoring verified." : "HALT required or cap status is not within limits.");
    } catch {
      setMonitor(null);
      setOperation("UNKNOWN");
      setMessage("Monitoring status is UNKNOWN; no status was inferred.");
    }
  }

  async function killSession(): Promise<void> {
    if (environment !== "DEMO" || busy || !install) return;
    setOperation("PENDING");
    setMonitor(null);
    try {
      const response = await fetcher(SESSION_PATH + encodeURIComponent(install.session_id) + "/kill", { method: "POST" });
      const body = await responseJson(response);
      if (!response.ok || !isKillResponse(body) || body.session_id !== install.session_id) {
        setOperation("UNKNOWN");
        setMessage("Kill outcome is UNKNOWN; do not assume the expert stopped or positions closed.");
        return;
      }
      setOperation("READY");
      setMessage("Expert disable and close outcome confirmed by the API.");
    } catch {
      setOperation("UNKNOWN");
      setMessage("Kill outcome is UNKNOWN; do not assume the expert stopped or positions closed.");
    }
  }

  if (environment !== "DEMO") {
    return (
      <section aria-labelledby="ea-hosting-title">
        <h2 id="ea-hosting-title">EA Hosting</h2>
        <p role="status">Unavailable unless the account is verified DEMO. This feature is DEMO-only.</p>
        <button type="button" disabled>Install EA</button>
        <button type="button" disabled>Monitor</button>
        <button type="button" disabled>Kill EA</button>
      </section>
    );
  }

  return (
    <section aria-labelledby="ea-hosting-title">
      <h2 id="ea-hosting-title">EA Hosting (DEMO only)</h2>
      <p>Choose a compiled EA and SET file. They are copied as opaque files; you load them in your own MetaTrader terminal.</p>
      <label>
        Terminal family
        <select value={family} onChange={(event) => { clearSession(); setFamily(event.target.value as TerminalFamily); }} disabled={busy}>
          <option value="MT5">MT5</option>
          <option value="MT4">MT4</option>
        </select>
      </label>
      <label>
        Compiled EA file
        <input type="file" accept={family === "MT5" ? ".ex5" : ".ex4"} onChange={(event) => { clearSession(); setEaFile(event.target.files?.[0] ?? null); }} disabled={busy} />
      </label>
      <label>
        SET preset
        <input type="file" accept=".set" onChange={(event) => { clearSession(); setSetFile(event.target.files?.[0] ?? null); }} disabled={busy} />
      </label>
      <label>
        Symbol
        <input value={symbol} onChange={(event) => { clearSession(); setSymbol(event.target.value); }} disabled={busy} />
      </label>
      <label>
        Timeframe
        <input value={timeframe} onChange={(event) => { clearSession(); setTimeframe(event.target.value); }} disabled={busy} />
      </label>
      {selectionError && <p role="alert">{selectionError}</p>}
      <button type="button" onClick={() => void installEa()} disabled={busy || !eaFile || !setFile || Boolean(selectionError)}>
        Install files for operator loading
      </button>
      {install && (
        <section aria-label="EA hosting session">
          <h3>Install provenance</h3>
          <p>Account: {install.account_id}</p>
          <p>Expert path: {install.expert_relative_path}</p>
          <p>Preset path: {install.preset_relative_path}</p>
          <p>EA SHA-256: {install.ea_sha256}</p>
          <p>SET SHA-256: {install.set_sha256}</p>
          <p>Installed by: {install.provenance.operator_id}</p>
          <p>Installed at (ns): {install.provenance.installed_at_ns}</p>
          <p>Startup configuration: {install.startup_config.expert_name}, {install.startup_config.set_file}, {install.startup_config.symbol}, {install.startup_config.timeframe}</p>
          <button type="button" onClick={() => void monitorSession()} disabled={busy}>Monitor</button>
          <button type="button" onClick={() => void killSession()} disabled={busy}>Disable expert and close positions</button>
        </section>
      )}
      {monitor && (
        <section aria-label="EA monitoring status">
          <p>Monitoring state: {monitor.state}</p>
          <p>Cap status: {monitor.cap_status}</p>
          <p>Observed at (ns): {monitor.observed_at_ns}</p>
          <p>Open orders: {monitor.open_order_count}</p>
          <ul aria-label="Open orders">
            {monitor.open_orders.map((order, index) => (
              <li key={order.client_order_id + ":" + index}>
                Client order {order.client_order_id}; venue order {order.venue_order_id ?? "unavailable"}; {order.status}
              </li>
            ))}
          </ul>
          <ul aria-label="Open positions">
            {monitor.positions.map(([instrument, quantity]) => <li key={instrument}>{instrument}: {quantity}</li>)}
          </ul>
        </section>
      )}
      {message && <p role="status">{message}</p>}
      {busy && <p role="status">Request pending; waiting for a verified response.</p>}
      {operation === "UNKNOWN" && <p role="alert">UNKNOWN</p>}
    </section>
  );
}
