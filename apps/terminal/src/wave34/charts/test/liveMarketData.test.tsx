import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { PaperMarketDataFetcher } from "../../../wave33/marketData/api";
import { LiveMarketDataWorkspace } from "../LiveMarketDataWorkspace";

vi.mock("../PriceDepthFootprintView", () => ({
  PriceDepthFootprintView: ({ panel }: { panel: { status: string } }) => (
    <div data-testid="chart-panel-state">{panel.status}</div>
  ),
}));

class FakeWebSocket {
  static instances: FakeWebSocket[] = [];
  onmessage: ((event: MessageEvent<string>) => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;
  readonly url: string;
  readonly protocols: string[];

  constructor(url: string, protocols: string[] = []) {
    this.url = url;
    this.protocols = protocols;
    FakeWebSocket.instances.push(this);
  }

  close() {
    this.onclose?.();
  }

  send(_message: string) {}

  emit(value: unknown) {
    this.onmessage?.({ data: JSON.stringify(value) } as MessageEvent<string>);
  }
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.useRealTimers();
  FakeWebSocket.instances = [];
});

describe("live market-data workspace", () => {
  it("mints a single-use ticket before connecting and displays server stale state", async () => {
    vi.stubGlobal("WebSocket", FakeWebSocket as unknown as typeof WebSocket);
    const fetcher = vi.fn<PaperMarketDataFetcher>(async (_input, _init) => new Response(
      JSON.stringify({ schema_version: 1, ticket: "a".repeat(43) }),
      { status: 201, headers: { "Content-Type": "application/json" } },
    ));
    vi.stubGlobal("fetch", fetcher);
    render(<LiveMarketDataWorkspace />);
    fireEvent.change(screen.getByLabelText("Venue"), { target: { value: "XNAS" } });
    fireEvent.change(screen.getByLabelText("Instrument"), { target: { value: "SYNTH" } });
    fireEvent.submit(screen.getByLabelText("Chart subscription"));

    await waitFor(() => expect(FakeWebSocket.instances).toHaveLength(1));
    const socket = FakeWebSocket.instances[0];
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(String(fetcher.mock.calls[0]?.[0])).toBe("/api/md/chart/ticket");
    const ticketRequest = fetcher.mock.calls[0]?.[1] as RequestInit | undefined;
    expect(ticketRequest?.method).toBe("POST");
    expect(socket.url).toBe("ws://localhost:3000/api/md/chart?venue=XNAS&instrument=SYNTH&type=ohlcv-1m");
    expect(socket.url).not.toContain("ticket");
    expect(socket.protocols).toEqual(["leviathan.chart.v1", `ticket.${"a".repeat(43)}`]);
    act(() => {
      socket.emit({
        schema_version: 1,
        state: "STALE",
        snapshot: {
          instrument: "SYNTH",
          venue: "XNAS",
          source: "nbbo",
          eventTimeNs: "1800000000000000000",
          candles: [],
          depth: null,
          quote: null,
          footprint: [],
          gex: null,
          indicators: null,
        },
        received_time_ns: "1800000000000000000",
        code: "STALE",
      });
    });

    expect(screen.getByText("Feed state: STALE")).toBeTruthy();
    expect(screen.getByTestId("chart-panel-state").textContent).toBe("stale");
  });

  it("fails closed on malformed stream envelopes", async () => {
    vi.stubGlobal("WebSocket", FakeWebSocket as unknown as typeof WebSocket);
    vi.stubGlobal("fetch", vi.fn<PaperMarketDataFetcher>(async (_input, _init) => new Response(
      JSON.stringify({ schema_version: 1, ticket: "b".repeat(43) }),
      { status: 201, headers: { "Content-Type": "application/json" } },
    )));
    render(<LiveMarketDataWorkspace />);
    fireEvent.change(screen.getByLabelText("Venue"), { target: { value: "XNAS" } });
    fireEvent.change(screen.getByLabelText("Instrument"), { target: { value: "SYNTH" } });
    fireEvent.submit(screen.getByLabelText("Chart subscription"));

    await waitFor(() => expect(FakeWebSocket.instances).toHaveLength(1));
    act(() => FakeWebSocket.instances[0]?.emit({ schema_version: 1, state: "HEALTHY" }));

    expect(screen.getByText("Feed state: DEGRADED")).toBeTruthy();
    expect(screen.getByTestId("chart-panel-state").textContent).toBe("error");
  });

  it("mints a fresh ticket for every reconnect", async () => {
    vi.stubGlobal("WebSocket", FakeWebSocket as unknown as typeof WebSocket);
    let ticketNumber = 0;
    const fetcher = vi.fn<PaperMarketDataFetcher>(async (_input, _init) => {
      ticketNumber += 1;
      return new Response(
        JSON.stringify({ schema_version: 1, ticket: String(ticketNumber).padStart(43, "x") }),
        { status: 201, headers: { "Content-Type": "application/json" } },
      );
    });
    vi.stubGlobal("fetch", fetcher);
    render(<LiveMarketDataWorkspace />);
    fireEvent.change(screen.getByLabelText("Venue"), { target: { value: "XNAS" } });
    fireEvent.change(screen.getByLabelText("Instrument"), { target: { value: "SYNTH" } });
    fireEvent.submit(screen.getByLabelText("Chart subscription"));
    await waitFor(() => expect(FakeWebSocket.instances).toHaveLength(1));

    vi.useFakeTimers();
    act(() => FakeWebSocket.instances[0]?.close());
    await act(async () => { await vi.advanceTimersByTimeAsync(1_000); });
    await act(async () => { await Promise.resolve(); await Promise.resolve(); });

    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(FakeWebSocket.instances).toHaveLength(2);
    expect(FakeWebSocket.instances[0]?.protocols[1]).not.toBe(FakeWebSocket.instances[1]?.protocols[1]);
  });
});
