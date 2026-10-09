import { render, screen, waitFor, within } from "@testing-library/react";
import { beforeAll, describe, expect, it, vi } from "vitest";
import { apiResponse } from "../../test/fixtures/api";
import {
  KNOWN_HALT_CODES,
  MAX_HALT_CODES,
  OMEGA_HALT,
  OMEGA_HALT_PREFIXES,
  displayHaltCode,
  OPERATING_MODES,
  fetchOrderGuard,
  fetchRiskGuard,
  parseOrderGuard,
  parseRiskGuard,
} from "../api/liveGuard";
import { LIVE_DISABLED_REASON, LiveGuardView } from "../views/LiveGuardView";

const CANARY = "SYNTHETIC_CANARY_VALUE_7731";
const UNVERIFIED_ONLY = /(?<!un)verified/i;

const riskBody = (extra: Record<string, unknown> = {}) => ({
  halted: false,
  active_halts: [],
  fault_code: null,
  operating_mode: "research",
  policy: { max_daily_dd_pct: "7.77", max_open_heat_pct: "8.88", max_leverage_x: "9.99" },
  lock_file: `${CANARY}.yaml`,
  ...extra,
});
const orderBody = (extra: Record<string, unknown> = {}) => ({
  live_enabled: false,
  recovery_status: "READY",
  activation_count: 3,
  ...extra,
});

type Handler = () => Response | Promise<Response>;

function mockGateway(routes: { risk?: Handler; orders?: Handler }) {
  return vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
    const url = String(input);
    if (url.endsWith("/api/risk/status") && routes.risk) return routes.risk();
    if (url.endsWith("/api/orders/status") && routes.orders) return routes.orders();
    throw new TypeError("Failed to fetch");
  });
}

const never = (): Promise<Response> => new Promise(() => undefined);

describe("liveGuard API readers", () => {
  it("keeps only allowlisted codes, flags and counts", () => {
    const report = parseRiskGuard(riskBody({
      active_halts: ["daily_drawdown_breach", "bad value!"],
    }));
    expect(report).toEqual({
      haltedReported: false,
      haltCodes: ["daily_drawdown_breach", "UNRECOGNIZED"],
      faultCode: null,
      operatingMode: "research",
      policyReported: true,
    });
    expect(JSON.stringify(report)).not.toMatch(/7\.77|8\.88|9\.99|SYNTHETIC_CANARY/);
    expect(parseRiskGuard(riskBody({ operating_mode: "live" }))?.operatingMode)
      .toBe("UNRECOGNIZED");
    for (const mode of OPERATING_MODES) {
      expect(parseRiskGuard(riskBody({ operating_mode: mode }))?.operatingMode).toBe(mode);
    }
    expect(parseOrderGuard(orderBody({ recovery_status: "ready now" }))?.recoveryStatus)
      .toBe("UNRECOGNIZED");
    for (const status of ["UNKNOWN", "FAILED", "READY"]) {
      expect(parseOrderGuard(orderBody({ recovery_status: status }))?.recoveryStatus).toBe(status);
    }
  });

  it("shows only closed-set codes: code-shaped or hyphenated free text is UNRECOGNIZED", () => {
    const hostile = ["RAW-CANARY-DO-NOT-RENDER", "RAW_CANARY_LOOKS_LIKE_A_CODE", "operator note",
      "DAILY_DRAWDOWN_BREACH", CANARY];
    const report = parseRiskGuard(riskBody({ active_halts: hostile, fault_code: hostile[0] }));
    expect(report?.haltCodes).toEqual(hostile.map(() => "UNRECOGNIZED"));
    expect(report?.faultCode).toBe("UNRECOGNIZED");
    expect(JSON.stringify(report)).not.toMatch(/CANARY|operator note/);
    expect(parseRiskGuard(riskBody({ fault_code: "HALT_STORE_UNAVAILABLE" }))?.faultCode)
      .toBe("HALT_STORE_UNAVAILABLE");
    expect(parseOrderGuard(orderBody({ recovery_status: "RAW_CANARY_STATUS" }))?.recoveryStatus)
      .toBe("UNRECOGNIZED");
  });

  it("rejects an oversized halt list instead of truncating it", () => {
    const fifty = Array.from({ length: MAX_HALT_CODES }, () => "daily_drawdown_breach");
    expect(parseRiskGuard(riskBody({ active_halts: fifty }))?.haltCodes.length)
      .toBe(MAX_HALT_CODES);
    expect(parseRiskGuard(riskBody({ active_halts: [...fifty, "daily_drawdown_breach"] })))
      .toBeNull();
    const huge = Array.from({ length: 100_000 }, () => "x");
    expect(parseRiskGuard(riskBody({ active_halts: huge }))).toBeNull();
  });

  it("only passes a valid source timestamp through", () => {
    expect(parseRiskGuard(riskBody({ as_of: 1_700_000_000_000 }))?.as_of).toBe(1_700_000_000_000);
    expect(parseOrderGuard(orderBody({ asOf: "2026-10-06T12:00:00Z" }))?.as_of)
      .toBe("2026-10-06T12:00:00Z");
    for (const bad of [Number.NaN, Infinity, "", {}, null, true]) {
      expect(parseRiskGuard(riskBody({ as_of: bad }))).not.toHaveProperty("as_of");
    }
  });

  it("rejects malformed payloads", () => {
    for (const bad of [null, [], "x", 3, {}, riskBody({ halted: "false" }),
      riskBody({ active_halts: "none" }), riskBody({ active_halts: [1] }),
      riskBody({ operating_mode: 4 }), riskBody({ fault_code: 4 }), riskBody({ policy: [] })]) {
      expect(parseRiskGuard(bad)).toBeNull();
    }
    for (const bad of [null, {}, orderBody({ live_enabled: "false" }),
      orderBody({ recovery_status: 1 }), orderBody({ activation_count: -1 }),
      orderBody({ activation_count: 1.5 }), orderBody({ activation_count: "3" })]) {
      expect(parseOrderGuard(bad)).toBeNull();
    }
  });

  it("issues only GET requests to the two status paths and reports codes, not bodies", async () => {
    const spy = mockGateway({
      risk: () => apiResponse(riskBody()),
      orders: () => apiResponse({ detail: "NOT_CONFIGURED", note: CANARY }, 503),
    });
    expect((await fetchRiskGuard()).ok).toBe(true);
    expect(await fetchOrderGuard()).toEqual({ ok: false, error: "HTTP_503:NOT_CONFIGURED" });
    expect(spy.mock.calls.map(([url, init]) => [String(url), init?.method])).toEqual([
      ["/api/risk/status", "GET"],
      ["/api/orders/status", "GET"],
    ]);
    for (const [, init] of spy.mock.calls) expect(init?.body).toBeUndefined();
  });

  it("maps failures to fixed codes", async () => {
    mockGateway({ risk: () => apiResponse({ detail: `lower ${CANARY}` }, 403) });
    expect(await fetchRiskGuard()).toEqual({ ok: false, error: "HTTP_403" });
    mockGateway({ risk: () => apiResponse({ detail: "SECRET_TOKEN_VALUE" }, 403) });
    expect(await fetchRiskGuard()).toEqual({ ok: false, error: "HTTP_403" });
    mockGateway({ risk: () => apiResponse(riskBody({ halted: "yes" })) });
    expect(await fetchRiskGuard()).toEqual({ ok: false, error: "MALFORMED_RESPONSE" });
    mockGateway({ risk: () => new Response("not json", { status: 200 }) });
    expect(await fetchRiskGuard()).toEqual({ ok: false, error: "MALFORMED_RESPONSE" });
    mockGateway({ risk: () => new Response("<html>", { status: 502 }) });
    expect(await fetchRiskGuard()).toEqual({ ok: false, error: "HTTP_502" });
    mockGateway({});
    expect(await fetchRiskGuard()).toEqual({ ok: false, error: "NETWORK_ERROR" });
  });
});

describe("LiveGuardView", () => {
  const liveState = () => screen.getByTestId("live-state");

  it("shows LIVE DISABLED while loading", () => {
    mockGateway({ risk: never, orders: never });
    render(<LiveGuardView />);
    expect(liveState().textContent).toBe("DISABLED");
    expect(screen.getByText(new RegExp(LIVE_DISABLED_REASON))).toBeTruthy();
  });

  it("shows LIVE DISABLED when the gateway is unreachable, with no green or ready state", async () => {
    mockGateway({});
    const { container } = render(<LiveGuardView />);
    await waitFor(() => expect(screen.getAllByText("NETWORK_ERROR").length).toBe(4));
    expect(liveState().textContent).toBe("DISABLED");
    expect(container.textContent).not.toMatch(/ready|nominal|verified/i);
    expect(container.querySelector(".chip--ok, .chip--sovereign")).toBeNull();
  });

  it.each([403, 401, 503])("shows only the gate code for HTTP %i", async (status) => {
    mockGateway({
      risk: () => apiResponse({ detail: "OPERATOR_REQUIRED", secret: CANARY }, status),
      orders: () => apiResponse({ detail: `free text ${CANARY}`, secret: CANARY }, status),
    });
    const { container } = render(<LiveGuardView />);
    expect((await screen.findAllByText(`HTTP_${status}:OPERATOR_REQUIRED`)).length).toBe(2);
    expect(screen.getAllByText(`HTTP_${status}`).length).toBe(2);
    expect(container.textContent).not.toContain(CANARY);
    expect(liveState().textContent).toBe("DISABLED");
    expect(container.textContent).not.toMatch(/ready|nominal|(?<!un)verified/i);
  });

  it("treats malformed payloads as errors and never renders them", async () => {
    mockGateway({
      risk: () => apiResponse({ halted: "no", note: CANARY }),
      orders: () => apiResponse({ live_enabled: false, recovery_status: "READY" }),
    });
    const { container } = render(<LiveGuardView />);
    await waitFor(() => expect(screen.getAllByText("MALFORMED_RESPONSE").length).toBe(4));
    expect(container.textContent).not.toContain(CANARY);
    expect(container.textContent).not.toContain("READY");
    expect(liveState().textContent).toBe("DISABLED");
  });

  it("labels reports without a source timestamp as unverified and separates receipt time", async () => {
    mockGateway({
      risk: () => apiResponse(riskBody({ active_halts: ["daily_drawdown_breach"], halted: true })),
      orders: () => apiResponse(orderBody()),
    });
    const { container } = render(<LiveGuardView />);
    const unverifiedRisk = await screen.findByRole("region", {
      name: "Risk status: unverified API report",
    });
    expect(within(unverifiedRisk).getByText("UNVERIFIED")).toBeTruthy();
    expect(within(unverifiedRisk).getByText("HALT INDICATED")).toBeTruthy();
    expect(within(unverifiedRisk).getByText("daily_drawdown_breach")).toBeTruthy();
    const unverifiedOrders = await screen.findByRole("region", {
      name: "Order gateway status: unverified API report",
    });
    expect(within(unverifiedOrders).getByText("READY")).toBeTruthy();
    expect(within(unverifiedOrders).getByText("3")).toBeTruthy();
    expect(screen.getAllByText("No valid source timestamp supplied.").length).toBe(4);
    expect(container.textContent).toContain("Source as of");
    expect(screen.getAllByText("Unavailable — no valid source timestamp").length).toBe(2);
    expect(container.textContent).toContain("Response received");
    expect(container.textContent).toContain("Receipt expires");
    expect(container.textContent).not.toMatch(UNVERIFIED_ONLY);
    expect(container.textContent).not.toMatch(/7\.77|8\.88|9\.99|limits?:/i);
    expect(liveState().textContent).toBe("DISABLED");
  });

  it("keeps API-reported fields labelled as reported even with a source timestamp", async () => {
    mockGateway({
      risk: () => apiResponse(riskBody({ as_of: Date.now() })),
      orders: () => apiResponse(orderBody({ as_of: Date.now() })),
    });
    render(<LiveGuardView />);
    await screen.findByText("Halt state (API-reported)");
    expect(screen.getByText("Recovery status (API-reported)")).toBeTruthy();
    expect(screen.getByText("Activation count (API-reported)")).toBeTruthy();
    expect(screen.queryByText("UNVERIFIED")).toBeNull();
    expect(liveState().textContent).toBe("DISABLED");
  });

  it("never renders free-text halt or fault values", async () => {
    mockGateway({
      risk: () => apiResponse(riskBody({
        halted: true, active_halts: ["RAW-CANARY-DO-NOT-RENDER", "daily_drawdown_breach"],
        fault_code: "RAW_CANARY_FAULT",
      })),
      orders: () => apiResponse(orderBody()),
    });
    const { container } = render(<LiveGuardView />);
    const region = await screen.findByRole("region", { name: "Risk status: unverified API report" });
    expect(within(region).getByText("UNRECOGNIZED, daily_drawdown_breach")).toBeTruthy();
    expect(container.textContent).not.toMatch(/CANARY/);
  });

  it("hides report values when the source timestamp is outside the freshness window", async () => {
    mockGateway({
      risk: () => apiResponse(riskBody({
        halted: true, active_halts: ["daily_drawdown_breach"], as_of: Date.now() - 60_000,
      })),
      orders: () => apiResponse(orderBody({ as_of: Date.now() - 60_000 })),
    });
    const { container } = render(<LiveGuardView />);
    await waitFor(() => expect(screen.getAllByText(/values are hidden/).length).toBe(2));
    expect(container.textContent).not.toMatch(/daily_drawdown_breach|HALT INDICATED|READY/);
    expect(screen.queryByRole("region", { name: /unverified API report/ })).toBeNull();
    expect(container.textContent).toContain("DELAYED");
    expect(liveState().textContent).toBe("DISABLED");
  });

  it("ignores an API claim that live is enabled", async () => {
    mockGateway({
      risk: () => apiResponse(riskBody({ operating_mode: "live" })),
      orders: () => apiResponse(orderBody({ live_enabled: true })),
    });
    render(<LiveGuardView />);
    await screen.findByText(/API REPORTED live_enabled TRUE/);
    expect(screen.getByText(/LIVE stays DISABLED in this view/)).toBeTruthy();
    expect(liveState().textContent).toBe("DISABLED");
    expect(screen.getAllByText("UNRECOGNIZED").length).toBeGreaterThan(0);
  });

  it("has no control that can enable, arm or toggle anything, and sends only GET", async () => {
    const spy = mockGateway({
      risk: () => apiResponse(riskBody()),
      orders: () => apiResponse(orderBody()),
    });
    const { container } = render(<LiveGuardView />);
    await screen.findByRole("region", { name: "Risk status: unverified API report" });
    expect(container.querySelectorAll("input, select, textarea, form, [role='switch']").length)
      .toBe(0);
    for (const button of screen.getAllByRole("button")) {
      expect(button.textContent).toBe("Retry");
    }
    expect(spy.mock.calls.length).toBeGreaterThan(0);
    for (const [, init] of spy.mock.calls) expect(init?.method).toBe("GET");
  });
});

describe("closed halt vocabulary (mirrors risk/halt_reasons.py)", () => {
  // The backend vocabulary is read as text so the UI sets cannot drift from it. Node
  // modules are loaded dynamically because this project's app tsconfig has no Node types.
  const RELATIVE = "packages/leviathan-core/src/leviathan_core/risk/halt_reasons.py";
  let source = "";
  beforeAll(async () => {
    const specifier = "node:fs";
    const fs = (await import(/* @vite-ignore */ specifier)) as {
      readFileSync: (path: string, encoding: string) => string;
      existsSync: (path: string) => boolean;
    };
    const cwd = (globalThis as unknown as { process: { cwd: () => string } }).process.cwd();
    const found = [`${cwd}/../../${RELATIVE}`, `${cwd}/${RELATIVE}`].find((path) => fs.existsSync(path));
    expect(found).toBeDefined();
    source = fs.readFileSync(found!, "utf-8");
  });
  const section = (start: string, end: string): string[] => {
    const body = source.slice(source.indexOf(start), source.indexOf(end));
    return [...body.matchAll(/^\s+[A-Z_]+ = "([a-z_]+)"$/gm)].map((match) => match[1]!);
  };
  const HEX = "ab".repeat(32);

  it("has exactly the static codes and OMEGA prefixes the backend enum declares", () => {
    const staticCodes = section("class HaltReasonV1", "class HaltReasonPatternV1");
    const prefixes = section("class HaltReasonPatternV1", "_DYNAMIC_SUFFIX");
    expect(staticCodes.length).toBeGreaterThan(0);
    expect(prefixes.length).toBeGreaterThan(0);
    expect([...KNOWN_HALT_CODES].sort()).toEqual([...staticCodes].sort());
    expect([...OMEGA_HALT_PREFIXES].sort()).toEqual([...prefixes].sort());
  });

  it("shows every static code as itself", () => {
    for (const code of KNOWN_HALT_CODES) expect(displayHaltCode(code)).toBe(code);
    const codes = [...KNOWN_HALT_CODES];
    expect(parseRiskGuard(riskBody({ active_halts: codes }))?.haltCodes).toEqual(codes);
  });

  it("shows an exact OMEGA key as OMEGA_HALT and never renders its hex", () => {
    for (const prefix of OMEGA_HALT_PREFIXES) {
      expect(displayHaltCode(`${prefix}:${HEX}`)).toBe(OMEGA_HALT);
    }
    const report = parseRiskGuard(riskBody({ active_halts: [`omega_kill:${HEX}`] }));
    expect(report?.haltCodes).toEqual([OMEGA_HALT]);
    expect(JSON.stringify(report)).not.toContain(HEX);
  });

  it("treats near-miss OMEGA keys and every other string as UNRECOGNIZED", () => {
    const near = [
      `omega_kill:${HEX.toUpperCase()}`, `omega_kill:${HEX.slice(1)}`, `omega_kill:${HEX}0`,
      `omega_kill:${HEX}:${HEX}`, `omega_kill:`, `omega_kill`, `omega_kill :${HEX}`,
      ` omega_kill:${HEX}`, `omega_unknown:${HEX}`, `OMEGA_KILL:${HEX}`, `:${HEX}`,
      `omega_kill_signal:${HEX}`, `risk_limit_breach:${HEX}`, "RISK_LIMIT_BREACH", "stale data",
      "", CANARY,
    ];
    for (const value of near) expect(displayHaltCode(value)).toBe("UNRECOGNIZED");
  });

  it("renders OMEGA_HALT and the new static codes in the view without any hex", async () => {
    mockGateway({
      risk: () => apiResponse(riskBody({
        halted: true,
        active_halts: [`omega_bridge_degraded:${HEX}`, "reconciliation_divergence", "stale_data"],
      })),
      orders: () => apiResponse(orderBody()),
    });
    const { container } = render(<LiveGuardView />);
    const region = await screen.findByRole("region", { name: "Risk status: unverified API report" });
    expect(within(region).getByText("OMEGA_HALT, reconciliation_divergence, stale_data")).toBeTruthy();
    expect(within(region).getByText("HALT INDICATED")).toBeTruthy();
    expect(container.textContent).not.toContain(HEX);
  });
});
