import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { DataSourcesView } from "../DataSourcesView";
import type { DataSourcesApiResult } from "../model";

const configured = {
  schema_version: "leviathan.data-sources/1" as const,
  sources: [{
    provider_id: "sample_feed",
    display_name: "Sample Feed",
    capabilities: ["TRADES", "QUOTES"],
    requires_credentials: true,
    credential_route: "gateway" as const,
    status: "DEGRADED" as const,
    source_time_ns: 101,
    received_time_ns: 117,
    error_code: "SOURCE_STALE" as const,
  }],
};

describe("DataSourcesView", () => {
  it("renders truthful health, distinct timestamps and remote credential route", async () => {
    const loadSources = vi.fn(async (): Promise<DataSourcesApiResult> => ({ ok: true, data: configured }));
    render(<DataSourcesView loadSources={loadSources} />);

    expect(await screen.findByText("DEGRADED")).toBeTruthy();
    expect(screen.getByText("Sample Feed")).toBeTruthy();
    expect(screen.getByText("sample_feed")).toBeTruthy();
    expect(screen.getByText("Remote data gateway")).toBeTruthy();
    expect(screen.getByText("Source time: 101 ns")).toBeTruthy();
    expect(screen.getByText("Received: 117 ns")).toBeTruthy();
    expect(screen.getByText("Health detail: SOURCE STALE")).toBeTruthy();
    expect(loadSources).toHaveBeenCalledTimes(1);
  });

  it("renders an empty registry without suggesting a source is ready", async () => {
    render(<DataSourcesView loadSources={async () => ({
      ok: true,
      data: { schema_version: "leviathan.data-sources/1", sources: [] },
    })} />);
    expect((await screen.findByRole("status")).textContent).toContain("No data sources registered");
  });

  it("shows a content-free unavailable state after API errors", async () => {
    render(<DataSourcesView loadSources={async () => ({ ok: false, error: "provider key=synthetic-secret" })} />);
    expect((await screen.findByRole("alert")).textContent).toContain("Data source status unavailable");
    expect(screen.getByRole("button", { name: "Retry" })).toBeTruthy();
    expect(document.body.textContent).not.toContain("synthetic-secret");
  });
});
