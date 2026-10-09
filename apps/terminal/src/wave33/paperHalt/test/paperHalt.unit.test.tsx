import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import "@testing-library/jest-dom/vitest";
import {
  HALT_ENGAGE_PATH,
  HALT_LIFT_PATH,
  HALT_REASON_OPTIONS,
  HALT_STATUS_PATH,
  createPaperHaltApi,
  type KnownHaltReason,
} from "../api";
import { PaperHaltControlView } from "../PaperHaltControlView";

function response(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

const statusBody = (extra: Record<string, unknown> = {}) => ({
  halted: false,
  active_halts: [],
  fault_code: null,
  operating_mode: "research",
  ...extra,
});

function makeFetcher(overrides: {
  status?: () => Promise<Response> | Response;
  engage?: () => Promise<Response> | Response;
  lift?: () => Promise<Response> | Response;
} = {}) {
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input);
    if (path === HALT_STATUS_PATH) return (overrides.status ?? (() => response(statusBody())))();
    if (path === HALT_ENGAGE_PATH) return (overrides.engage ?? (() => response({ halted: true, active_halts: ["operator_halt"] })))();
    if (path === HALT_LIFT_PATH) return (overrides.lift ?? (() => response({ halted: false, active_halts: [] })))();
    throw new Error(`Unexpected request path: ${path} ${init?.method ?? "GET"}`);
  }) as unknown as typeof fetch & ReturnType<typeof vi.fn>;
}

describe("paper halt API", () => {
  it("uses only the three risk routes and sends only a closed reason", async () => {
    const fetcher = makeFetcher({
      status: () => response(statusBody({ active_halts: ["operator_hold"] })),
    });
    const api = createPaperHaltApi(fetcher);
    const status = await api.getStatus();
    expect(status.ok).toBe(true);
    const result = await api.engage("operator_halt");
    expect(result.ok).toBe(true);
    expect(fetcher.mock.calls.map(([path]) => String(path))).toEqual([
      HALT_STATUS_PATH,
      HALT_ENGAGE_PATH,
    ]);
    const call = fetcher.mock.calls[1];
    if (call === undefined) throw new Error("expected HALT mutation call");
    const request = call[1] as RequestInit;
    expect(request.method).toBe("POST");
    expect(request.body).toBe(JSON.stringify({ reason: "operator_halt" }));
    expect(request.cache).toBe("no-store");
    expect(request.credentials).toBe("same-origin");
  });

  it("rejects free text and pattern reasons for engage without a request", async () => {
    const fetcher = makeFetcher();
    const api = createPaperHaltApi(fetcher);
    const result = await api.engage("operator requested this" as never);
    expect(result).toEqual({ ok: false, error: "INVALID_HALT_REASON" });
    expect(fetcher).not.toHaveBeenCalled();
    expect(HALT_REASON_OPTIONS).toHaveLength(12);
  });

  it("preserves only a valid active dynamic reason for exact lift", async () => {
    const dynamic = `omega_kill:${"a".repeat(64)}` as KnownHaltReason;
    const fetcher = makeFetcher({
      status: () => response(statusBody({ halted: true, active_halts: [dynamic] })),
    });
    const api = createPaperHaltApi(fetcher);
    const current = await api.getStatus();
    expect(current.ok && current.data.active_halts).toEqual([dynamic]);
    const lifted = await api.lift(dynamic);
    expect(lifted.ok).toBe(true);
    const liftCall = fetcher.mock.calls[1];
    if (liftCall === undefined) throw new Error("expected HALT lift call");
    expect(String(liftCall[0])).toBe(HALT_LIFT_PATH);
    expect((liftCall[1] as RequestInit).body).toBe(JSON.stringify({ reason: dynamic }));
  });

  it("does not expose response bodies or thrown error text", async () => {
    const fetcher = makeFetcher({
      engage: () => response({ detail: "PRIVATE_MARKER" }, 503),
    });
    const api = createPaperHaltApi(fetcher);
    await expect(api.engage("operator_hold")).resolves.toEqual({
      ok: false,
      error: "HALT_STORE_UNAVAILABLE",
    });
    const networkApi = createPaperHaltApi(vi.fn(async () => { throw new Error("PRIVATE_MARKER"); }) as unknown as typeof fetch);
    await expect(networkApi.getStatus()).resolves.toEqual({ ok: false, error: "NETWORK_ERROR" });
  });

  it("bounds response-body parsing with the same request deadline", async () => {
    vi.useFakeTimers();
    const fetcher = vi.fn(async () => ({
      ok: true,
      status: 200,
      json: () => new Promise<unknown>(() => undefined),
    }) as unknown as Response) as unknown as typeof fetch;
    const pending = createPaperHaltApi(fetcher).getStatus();
    await vi.advanceTimersByTimeAsync(5_000);
    await expect(pending).resolves.toEqual({ ok: false, error: "TIMEOUT" });
    vi.useRealTimers();
  });

  it("rejects unrecognized status reasons instead of rendering arbitrary text", async () => {
    const api = createPaperHaltApi(makeFetcher({
      status: () => response(statusBody({ active_halts: ["PRIVATE_MARKER"] })),
    }));
    await expect(api.getStatus()).resolves.toEqual({ ok: false, error: "INVALID_RESPONSE" });
  });

  it("maps the store fault sentinel to the fixed fault status without offering a lift reason", async () => {
    const api = createPaperHaltApi(makeFetcher({
      status: () => response(statusBody({
        halted: true,
        active_halts: ["__halt_store_unavailable__"],
        fault_code: "HALT_STORE_UNAVAILABLE",
      })),
    }));
    await expect(api.getStatus()).resolves.toEqual({ ok: true, data: {
      halted: true,
      active_halts: [],
      fault_code: "HALT_STORE_UNAVAILABLE",
      operating_mode: "research",
    } });
  });
});

describe("PaperHaltControlView", () => {
  it("renders status and leaves LIVE disabled", async () => {
    render(<PaperHaltControlView fetcher={makeFetcher()} />);
    expect(await screen.findByText("NO ACTIVE HALT")).toBeTruthy();
    expect(screen.getByRole("button", { name: "LIVE trading disabled" })).toHaveProperty("disabled", true);
    expect(screen.getByRole("combobox", { name: "Reason to engage" })).toBeTruthy();
  });

  it("shows pending without optimistic status and allows a keyboard-selectable static reason", async () => {
    let resolveMutation: ((value: Response) => void) | undefined;
    const pending = new Promise<Response>((resolve) => { resolveMutation = resolve; });
    let engaged = false;
    const fetcher = makeFetcher({
      status: () => response(statusBody({ halted: engaged, active_halts: engaged ? ["risk_limit_breach"] : [] })),
      engage: async () => { const result = await pending; engaged = true; return result; },
    });
    render(<PaperHaltControlView fetcher={fetcher} />);
    expect(await screen.findByText("NO ACTIVE HALT")).toBeTruthy();
    const select = screen.getByRole("combobox", { name: "Reason to engage" });
    fireEvent.change(select, { target: { value: "risk_limit_breach" } });
    fireEvent.click(screen.getByRole("button", { name: "Engage HALT" }));
    expect(await screen.findByText("HALT change pending…")).toBeTruthy();
    expect(screen.getByText("HALT status pending / unverified.")).toBeTruthy();
    expect(screen.queryByText("HALT ENGAGED")).toBeNull();
    resolveMutation?.(response({ halted: true, active_halts: ["risk_limit_breach"] }));
    await waitFor(() => expect(screen.getByText("HALT ENGAGED")).toBeTruthy());
  });

  it("lifts the exact active reason only", async () => {
    let active = true;
    const fetcher = makeFetcher({
      status: () => response(statusBody({ halted: active, active_halts: active ? ["operator_hold"] : [] })),
      lift: () => { active = false; return response({ halted: false, active_halts: [] }); },
    });
    render(<PaperHaltControlView fetcher={fetcher} />);
    expect(await screen.findByText("HALT ENGAGED")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Lift HALT reason operator_hold" }));
    expect(screen.getByRole("group", { name: "Confirm HALT lift" })).toBeTruthy();
    expect(fetcher.mock.calls.filter(([path]) => String(path) === HALT_LIFT_PATH)).toHaveLength(0);
    fireEvent.click(screen.getByRole("button", { name: "Confirm lift" }));
    await waitFor(() => expect(screen.getByText("NO ACTIVE HALT")).toBeTruthy());
    const liftCall = fetcher.mock.calls.find(([path]) => String(path) === HALT_LIFT_PATH);
    if (liftCall === undefined) throw new Error("expected HALT lift call");
    expect(String(liftCall[0])).toBe(HALT_LIFT_PATH);
    expect((liftCall[1] as RequestInit).body).toBe(JSON.stringify({ reason: "operator_hold" }));
  });

  it("does not let an older refresh overwrite a newer post-mutation status", async () => {
    let statusCalls = 0;
    let resolveOlderRead: ((value: Response) => void) | undefined;
    const olderRead = new Promise<Response>((resolve) => { resolveOlderRead = resolve; });
    const fetcher = makeFetcher({
      status: () => {
        statusCalls += 1;
        if (statusCalls === 2) return olderRead;
        return response(statusBody({
          halted: statusCalls >= 3,
          active_halts: statusCalls >= 3 ? ["operator_halt"] : [],
        }));
      },
      engage: () => response({ halted: true, active_halts: ["operator_halt"] }),
    });
    render(<PaperHaltControlView fetcher={fetcher} />);
    expect(await screen.findByText("NO ACTIVE HALT")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Refresh HALT status" }));
    fireEvent.click(screen.getByRole("button", { name: "Engage HALT" }));
    await waitFor(() => expect(screen.getByText("HALT ENGAGED")).toBeTruthy());
    await act(async () => {
      resolveOlderRead?.(response(statusBody()));
      await olderRead;
    });
    expect(screen.getByText("HALT ENGAGED")).toBeTruthy();
    expect(screen.queryByText("NO ACTIVE HALT")).toBeNull();
  });

  it("ignores an older status read that finishes after the post-mutation refresh", async () => {
    let statusCalls = 0;
    let resolveOlderRead: ((value: Response) => void) | undefined;
    const olderRead = new Promise<Response>((resolve) => { resolveOlderRead = resolve; });
    const fetcher = makeFetcher({
      status: () => {
        statusCalls += 1;
        if (statusCalls === 2) return olderRead;
        return response(statusBody({
          halted: statusCalls >= 3,
          active_halts: statusCalls >= 3 ? ["operator_halt"] : [],
        }));
      },
      engage: () => response({ halted: true, active_halts: ["operator_halt"] }),
    });
    render(<PaperHaltControlView fetcher={fetcher} />);
    expect(await screen.findByText("NO ACTIVE HALT")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Refresh HALT status" }));
    fireEvent.click(screen.getByRole("button", { name: "Engage HALT" }));
    await waitFor(() => expect(screen.getByText("HALT ENGAGED")).toBeTruthy());

    await act(async () => {
      resolveOlderRead?.(response(statusBody()));
      await olderRead;
    });
    expect(screen.getByText("HALT ENGAGED")).toBeTruthy();
    expect(screen.queryByText("NO ACTIVE HALT")).toBeNull();
  });

  it("re-fetches after persistence errors and does not claim a committed change", async () => {
    const fetcher = makeFetcher({ engage: () => response({ detail: "HALT_STORE_UNAVAILABLE" }, 503) });
    render(<PaperHaltControlView fetcher={fetcher} />);
    expect(await screen.findByText("NO ACTIVE HALT")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Engage HALT" }));
    expect((await screen.findByRole("alert")).textContent).toContain("HALT state could not be persisted");
    await waitFor(() => expect(fetcher.mock.calls.filter(([path]) => String(path) === HALT_STATUS_PATH)).toHaveLength(2));
    expect(screen.getByText("NO ACTIVE HALT")).toBeTruthy();
  });

  it("has a synchronous re-entrancy guard for double submit", async () => {
    let resolveMutation: ((value: Response) => void) | undefined;
    const pending = new Promise<Response>((resolve) => { resolveMutation = resolve; });
    const fetcher = makeFetcher({ engage: () => pending });
    render(<PaperHaltControlView fetcher={fetcher} />);
    expect(await screen.findByText("NO ACTIVE HALT")).toBeTruthy();
    const button = screen.getByRole("button", { name: "Engage HALT" });
    fireEvent.click(button);
    fireEvent.click(button);
    expect(fetcher.mock.calls.filter(([path]) => String(path) === HALT_ENGAGE_PATH)).toHaveLength(1);
    resolveMutation?.(response({ halted: true, active_halts: ["operator_halt"] }));
  });

  it("shows failure and refreshes status after timeout", async () => {
    let calls = 0;
    const fetcher = makeFetcher({
      engage: () => new Promise<Response>(() => undefined),
      status: () => { calls += 1; return response(statusBody()); },
    });
    render(<PaperHaltControlView fetcher={fetcher} />);
    expect(await screen.findByText("NO ACTIVE HALT")).toBeTruthy();
    vi.useFakeTimers();
    fireEvent.click(screen.getByRole("button", { name: "Engage HALT" }));
    await act(async () => { await vi.advanceTimersByTimeAsync(5_000); });
    expect(screen.getByRole("alert").textContent).toContain("request timed out");
    expect(calls).toBe(2);
    expect(screen.getByText("HALT status is unverified.")).toBeTruthy();
    vi.useRealTimers();
  });
});
