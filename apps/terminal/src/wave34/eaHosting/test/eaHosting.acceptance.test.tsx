/** Independent UI acceptance for the DEMO-only, operator-loaded EA boundary. */
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { EaHostingView } from "../EaHostingView";

const INSTALL_PATH = "/api/mt5/ea-host/v1/install";
const SESSION_PATH = "/api/mt5/ea-host/v1/sessions/ea-session-synthetic-1";
const EA_BYTES = "synthetic dummy compiled bytes; not executable in this test";
const SET_BYTES = "synthetic preset contents";

type CapturedCall = {
  path: string;
  method: string;
  body?: string;
};

function jsonResponse(body: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: status >= 200 && status < 300 ? "OK" : "Error",
    json: async () => body,
  } as Response;
}

function makeFile(name: string, contents: string): File {
  const file = new File([contents], name);
  const bytes = new TextEncoder().encode(contents);
  Object.defineProperty(file, "arrayBuffer", {
    value: async () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength),
  });
  return file;
}

function installPayload() {
  return {
    session_id: "ea-session-synthetic-1",
    account_id: "synthetic-demo-account",
    environment: "DEMO",
    terminal_family: "MT5",
    expert_relative_path: "MQL5/Experts/SyntheticRisk.ex5",
    preset_relative_path: "MQL5/Presets/SyntheticRisk.set",
    ea_sha256: "",
    set_sha256: "",
    provenance: {
      ea_filename: "SyntheticRisk.ex5",
      set_filename: "SyntheticRisk.set",
      ea_sha256: "",
      set_sha256: "",
      ea_size_bytes: new TextEncoder().encode(EA_BYTES).length,
      set_size_bytes: new TextEncoder().encode(SET_BYTES).length,
      installed_at_ns: "1798761600000000000",
      operator_id: "synthetic-operator",
    },
    startup_config: {
      terminal_family: "MT5",
      expert_name: "SyntheticRisk.ex5",
      set_file: "SyntheticRisk.set",
      symbol: "EURUSD",
      timeframe: "M5",
      environment: "DEMO",
      execution_allowed: false,
    },
    execution_allowed: false,
  };
}

async function digestBase64(value: string): Promise<string> {
  const bytes = Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
  const hashed = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(hashed), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function createFetch(calls: CapturedCall[]) {
  const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input);
    const method = (init?.method ?? "GET").toUpperCase();
    const rawBody = typeof init?.body === "string" ? init.body : undefined;
    calls.push({ path, method, ...(rawBody === undefined ? {} : { body: rawBody }) });
    if (path === INSTALL_PATH && method === "POST") {
      const body = JSON.parse(rawBody ?? "{}") as Record<string, string>;
      return jsonResponse(
        {
          ...installPayload(),
          ea_sha256: await digestBase64(body.ea_base64 ?? ""),
          set_sha256: await digestBase64(body.set_base64 ?? ""),
          provenance: {
            ...installPayload().provenance,
            ea_sha256: await digestBase64(body.ea_base64 ?? ""),
            set_sha256: await digestBase64(body.set_base64 ?? ""),
          },
        },
        201,
      );
    }
    if (path === SESSION_PATH && method === "GET") {
      return jsonResponse({
        session_id: "ea-session-synthetic-1",
        account_id: "synthetic-demo-account",
        environment: "DEMO",
        observed_at_ns: "1798761600000000000",
        open_order_count: 1,
        open_orders: [{
          client_order_id: "synthetic-client-order-1",
          venue_order_id: "synthetic-venue-order-1",
          venue: "MT5",
          status: "WORKING",
          observed_at_ns: "1798761599000000000",
        }],
        positions: [["EURUSD", "0.25"]],
        cap_status: "WITHIN_CAPS",
        state: "MONITORING",
        execution_allowed: false,
      });
    }
    if (path === `${SESSION_PATH}/kill` && method === "POST") {
      return jsonResponse({
        session_id: "ea-session-synthetic-1",
        environment: "DEMO",
        state: "STOPPED",
        disabled: true,
        close_attempted: true,
        execution_allowed: false,
      });
    }
    return jsonResponse({ error: { code: "UNEXPECTED_SYNTHETIC_ENDPOINT" } }, 404);
  });
  return fetcher;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("EA hosting browser acceptance", () => {
  it("uses only explicit DEMO install, monitor and kill requests with honest status", async () => {
    const calls: CapturedCall[] = [];
    const fetcher = createFetch(calls);
    render(<EaHostingView environment="DEMO" fetcher={fetcher} />);

    expect(calls).toEqual([]);
    expect(screen.getByRole("heading", { name: "EA Hosting (DEMO only)" })).toBeTruthy();
    expect(screen.getByText(/you load them in your own MetaTrader terminal/i)).toBeTruthy();
    expect(screen.queryByRole("button", { name: /execute|compile|decompile/i })).toBeNull();

    fireEvent.change(screen.getByLabelText("Compiled EA file"), {
      target: { files: [makeFile("SyntheticRisk.ex5", EA_BYTES)] },
    });
    fireEvent.change(screen.getByLabelText("SET preset"), {
      target: { files: [makeFile("SyntheticRisk.set", SET_BYTES)] },
    });
    fireEvent.click(screen.getByRole("button", { name: "Install files for operator loading" }));

    await waitFor(() => expect(calls).toHaveLength(1));
    expect(calls[0]).toMatchObject({ path: INSTALL_PATH, method: "POST" });
    const submitted = JSON.parse(calls[0]?.body ?? "{}") as Record<string, unknown>;
    expect(Object.keys(submitted).sort()).toEqual([
      "ea_base64",
      "ea_filename",
      "set_base64",
      "set_filename",
      "symbol",
      "terminal_family",
      "timeframe",
    ]);
    expect(submitted).toMatchObject({
      ea_filename: "SyntheticRisk.ex5",
      set_filename: "SyntheticRisk.set",
      terminal_family: "MT5",
      symbol: "EURUSD",
      timeframe: "M5",
    });
    expect(atob(String(submitted.ea_base64))).toBe(EA_BYTES);
    expect(atob(String(submitted.set_base64))).toBe(SET_BYTES);
    expect(await screen.findByText(/files were placed for operator loading/i)).toBeTruthy();
    expect(screen.getByText("Installed at (ns): 1798761600000000000")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Monitor" }));
    await waitFor(() => expect(calls).toHaveLength(2));
    expect(calls[1]).toEqual({ path: SESSION_PATH, method: "GET" });
    expect(await screen.findByText("Monitoring state: MONITORING")).toBeTruthy();
    expect(screen.getByText("Cap status: WITHIN_CAPS")).toBeTruthy();
    expect(screen.getByText("Observed at (ns): 1798761600000000000")).toBeTruthy();
    expect(screen.getByText(/synthetic-client-order-1/)).toBeTruthy();
    expect(screen.getByText("EURUSD: 0.25")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Disable expert and close positions" }));
    await waitFor(() => expect(calls).toHaveLength(3));
    expect(calls[2]).toEqual({ path: `${SESSION_PATH}/kill`, method: "POST" });
    expect(await screen.findByText(/disable and close outcome confirmed/i)).toBeTruthy();
    expect(calls.map(({ path, method }) => `${method} ${path}`)).toEqual([
      `POST ${INSTALL_PATH}`,
      `GET ${SESSION_PATH}`,
      `POST ${SESSION_PATH}/kill`,
    ]);
  });

  it("keeps LIVE controls disabled and makes no request", () => {
    const calls: CapturedCall[] = [];
    const fetcher = createFetch(calls);
    render(<EaHostingView environment="LIVE" fetcher={fetcher} />);

    expect(screen.getByRole("status").textContent).toMatch(/DEMO-only/i);
    for (const name of ["Install EA", "Monitor", "Kill EA"]) {
      expect((screen.getByRole("button", { name }) as HTMLButtonElement).disabled).toBe(true);
    }
    expect(calls).toEqual([]);
  });

  it("rejects wrong extensions and oversize selections before any request", () => {
    const calls: CapturedCall[] = [];
    const fetcher = createFetch(calls);
    render(<EaHostingView environment="DEMO" fetcher={fetcher} />);

    const eaInput = screen.getByLabelText("Compiled EA file");
    fireEvent.change(eaInput, { target: { files: [makeFile("SyntheticRisk.ex4", EA_BYTES)] } });
    fireEvent.change(screen.getByLabelText("SET preset"), {
      target: { files: [makeFile("SyntheticRisk.set", SET_BYTES)] },
    });
    expect(screen.getByRole("alert").textContent).toMatch(/compiled EA file/i);
    expect(
      (screen.getByRole("button", { name: "Install files for operator loading" }) as HTMLButtonElement)
        .disabled,
    ).toBe(true);

    const oversized = makeFile("LargeSynthetic.ex5", "x");
    Object.defineProperty(oversized, "size", { value: 64 * 1024 * 1024 + 1 });
    fireEvent.change(eaInput, { target: { files: [oversized] } });
    expect(screen.getByRole("alert").textContent).toMatch(/exceeds the allowed size/i);
    expect(calls).toEqual([]);

    fireEvent.change(eaInput, {
      target: { files: [makeFile("SyntheticRisk.ex5", EA_BYTES)] },
    });
    const setInput = screen.getByLabelText("SET preset");
    const oversizedSet = makeFile("LargeSynthetic.set", "x");
    Object.defineProperty(oversizedSet, "size", { value: 1024 * 1024 + 1 });
    fireEvent.change(setInput, { target: { files: [oversizedSet] } });
    expect(screen.getByRole("alert").textContent).toMatch(/SET file exceeds/i);
    expect(calls).toEqual([]);
  });

  it("renders only fixed UNKNOWN text after an ambiguous network outcome", async () => {
    const calls: CapturedCall[] = [];
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ path: String(input), method: (init?.method ?? "GET").toUpperCase() });
      throw new Error("synthetic provider secret text");
    });
    render(<EaHostingView environment="DEMO" fetcher={fetcher} />);
    fireEvent.change(screen.getByLabelText("Compiled EA file"), {
      target: { files: [makeFile("SyntheticRisk.ex5", EA_BYTES)] },
    });
    fireEvent.change(screen.getByLabelText("SET preset"), {
      target: { files: [makeFile("SyntheticRisk.set", SET_BYTES)] },
    });
    fireEvent.click(screen.getByRole("button", { name: "Install files for operator loading" }));

    expect(await screen.findByText(/install outcome is UNKNOWN/i)).toBeTruthy();
    expect(screen.queryByText(/synthetic provider secret text/i)).toBeNull();
    expect(calls).toEqual([{ path: INSTALL_PATH, method: "POST" }]);
  });
});
