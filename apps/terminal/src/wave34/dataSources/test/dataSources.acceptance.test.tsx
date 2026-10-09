import { act, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { DataSourcesView } from "../DataSourcesView";
import type { DataSourcesApiResult, DataSourcesResponse } from "../model";

const allHealthStates: DataSourcesResponse = {
  schema_version: "leviathan.data-sources/1",
  sources: [
    {
      provider_id: "source.not-configured",
      display_name: "Unconfigured feed",
      capabilities: ["TRADES"],
      requires_credentials: true,
      credential_route: null,
      status: "NOT_CONFIGURED",
      source_time_ns: null,
      received_time_ns: null,
      error_code: null,
    },
    {
      provider_id: "source.ready",
      display_name: "Ready feed",
      capabilities: ["QUOTES"],
      requires_credentials: true,
      credential_route: "vault_ref",
      status: "READY",
      source_time_ns: 101,
      received_time_ns: 117,
      error_code: null,
    },
    {
      provider_id: "source.degraded",
      display_name: "Delayed feed",
      capabilities: ["TRADES"],
      requires_credentials: true,
      credential_route: "gateway",
      status: "DEGRADED",
      source_time_ns: 201,
      received_time_ns: 233,
      error_code: "SOURCE_STALE",
    },
    {
      provider_id: "source.external-gate",
      display_name: "Entitlement-gated feed",
      capabilities: ["DEPTH"],
      requires_credentials: false,
      credential_route: null,
      status: "EXTERNAL_GATE",
      source_time_ns: null,
      received_time_ns: null,
      error_code: null,
    },
    {
      provider_id: "source.disabled",
      display_name: "Disabled feed",
      capabilities: ["ALTERNATIVE_DATA"],
      requires_credentials: false,
      credential_route: null,
      status: "DISABLED",
      source_time_ns: 301,
      received_time_ns: 337,
      error_code: "AUTH_REJECTED",
    },
  ],
};

describe("DataSourcesView acceptance", () => {
  it("shows loading and every reported health state with separate times and typed route labels", async () => {
    let resolveLoad!: (result: DataSourcesApiResult) => void;
    const loadSources = vi.fn(
      () => new Promise<DataSourcesApiResult>((resolve) => { resolveLoad = resolve; }),
    );
    render(<DataSourcesView loadSources={loadSources} />);

    expect(screen.getByRole("status").textContent).toContain("Loading data source status");
    expect(document.querySelector("section[aria-busy='true']")).not.toBeNull();

    await act(async () => {
      resolveLoad({ ok: true, data: allHealthStates });
    });

    expect(await screen.findByText("NOT CONFIGURED")).toBeTruthy();
    expect(screen.getByText("READY")).toBeTruthy();
    expect(screen.getByText("DEGRADED")).toBeTruthy();
    expect(screen.getByText("EXTERNAL GATE")).toBeTruthy();
    expect(screen.getByText("DISABLED")).toBeTruthy();
    expect(screen.getByText("source.ready")).toBeTruthy();
    expect(screen.getByText("Ready feed")).toBeTruthy();
    expect(screen.getByText("Local vault")).toBeTruthy();
    expect(screen.getByText("Remote data gateway")).toBeTruthy();
    expect(screen.getByText("Credential not configured")).toBeTruthy();
    expect(screen.getByText("Source time: 101 ns")).toBeTruthy();
    expect(screen.getByText("Received: 117 ns")).toBeTruthy();
    expect(screen.getByText("Source time: 201 ns")).toBeTruthy();
    expect(screen.getByText("Received: 233 ns")).toBeTruthy();
    expect(screen.getByText("Health detail: SOURCE STALE")).toBeTruthy();
    expect(document.body.textContent).not.toContain("vault://");
    expect(document.body.textContent).not.toContain("credential_ref");
  });

  it("renders empty and unavailable states without showing loader error details", async () => {
    const emptyResult: DataSourcesApiResult = {
      ok: true,
      data: { schema_version: "leviathan.data-sources/1", sources: [] },
    };
    const { rerender } = render(
      <DataSourcesView loadSources={async () => emptyResult} />,
    );
    expect((await screen.findByRole("status")).textContent).toContain(
      "No data sources registered",
    );

    const loadSources = vi.fn(async (): Promise<DataSourcesApiResult> => ({
      ok: false,
      error: "provider key=fixture-secret-never-display-this",
    }));
    rerender(<DataSourcesView loadSources={loadSources} />);

    expect((await screen.findByRole("alert")).textContent).toBe(
      "Data source status unavailable",
    );
    expect(screen.getByRole("button", { name: "Retry" })).toBeTruthy();
    expect(document.body.textContent).not.toContain("fixture-secret-never-display-this");
  });

  it("keeps a rejected loader in the unavailable state", async () => {
    render(
      <DataSourcesView
        loadSources={async () => { throw new Error("secret=fixture-private"); }}
      />,
    );
    await waitFor(() => {
      expect(screen.getByRole("alert").textContent).toBe(
        "Data source status unavailable",
      );
    });
    expect(document.body.textContent).not.toContain("fixture-private");
  });
});
