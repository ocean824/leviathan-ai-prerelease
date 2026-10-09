import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { apiResponse } from "../../test/fixtures/api";
import {
  KNOWN_BLOCK_IDS,
  MAX_TEMPLATES,
  OPERATOR_SESSION_UNAVAILABLE,
  fetchEaTemplates,
  parseEaCatalog,
} from "../api/eaTemplates";
import { EaTemplateCatalogView, SESSION_UNAVAILABLE_TEXT } from "../views/EaTemplateCatalogView";

const CANARY = "SYNTHETIC_SOURCE_BODY_CANARY_5521";
const DIGEST = "ab".repeat(32);
const BLOCKS = [...KNOWN_BLOCK_IDS].sort();
const FORBIDDEN_WORDS = /validated|deployable|deploy|export|download|generate|metaeditor|broker/i;

const entry = (platform: string, blockId: string) => ({
  template_id: `${platform}:${blockId}`, block_id: blockId, platform,
});
const catalogBody = (extra: Record<string, unknown> = {}) => ({
  catalog_id: "leviathan_mql_source",
  version: 1,
  catalog_digest: DIGEST,
  templates: ["MT4", "MT5"].flatMap((platform) => BLOCKS.map((block) => entry(platform, block))),
  ...extra,
});

type Handler = () => Response | Promise<Response>;
const mockApi = (handler: Handler) =>
  vi.spyOn(globalThis, "fetch").mockImplementation(async () => handler());
const never = (): Promise<Response> => new Promise(() => undefined);

describe("eaTemplates API reader", () => {
  it("keeps closed-set identifiers and drops every other field", () => {
    const body = catalogBody({
      source: CANARY,
      templates: [{ ...entry("MT5", "compare.v1"), source_body: CANARY, mql: CANARY }],
    });
    expect(parseEaCatalog(body)).toEqual({
      catalogId: "leviathan_mql_source", version: 1, catalogDigest: DIGEST,
      templates: [{ templateId: "MT5:compare.v1", blockId: "compare.v1", platform: "MT5" }],
      unrecognizedCount: 0,
    });
    expect(JSON.stringify(parseEaCatalog(body))).not.toContain(CANARY);
  });

  it("shows an unknown catalog id as UNRECOGNIZED and counts unknown blocks without showing them", () => {
    const report = parseEaCatalog(catalogBody({
      catalog_id: "RAW-CANARY-CATALOG",
      templates: [entry("MT4", "bar_event"), entry("MT4", "RAW_CANARY_BLOCK")],
    }));
    expect(report?.catalogId).toBe("UNRECOGNIZED");
    expect(report?.templates.map((row) => row.templateId)).toEqual(["MT4:bar_event"]);
    expect(report?.unrecognizedCount).toBe(1);
    expect(JSON.stringify(report)).not.toContain("CANARY");
  });

  it("drops any timestamp field because the route defines no source timestamp", () => {
    for (const stamp of [1_700_000_000_000, Date.now(), "2026-10-06T12:00:00Z", Number.NaN]) {
      const report = parseEaCatalog(catalogBody({ as_of: stamp, asOf: stamp }));
      expect(report).not.toBeNull();
      expect(report).not.toHaveProperty("as_of");
      expect(report).not.toHaveProperty("asOf");
    }
  });

  it("rejects malformed shapes, id mismatches, duplicates and oversize lists", () => {
    const good = entry("MT4", "bar_event");
    const bad: unknown[] = [
      null, [], "x", {}, catalogBody({ catalog_id: 4 }), catalogBody({ version: 0 }),
      catalogBody({ version: 1.5 }), catalogBody({ version: 1e12 }), catalogBody({ version: "1" }),
      catalogBody({ catalog_digest: "ABC" }), catalogBody({ catalog_digest: "ab".repeat(31) }),
      catalogBody({ templates: "none" }), catalogBody({ templates: [null] }),
      catalogBody({ templates: [{ ...good, template_id: "MT5:bar_event" }] }),
      catalogBody({ templates: [{ ...good, platform: "MT6", template_id: "MT6:bar_event" }] }),
      catalogBody({ templates: [{ ...good, block_id: 5 }] }),
      catalogBody({ templates: [good, good] }),
      catalogBody({ templates: Array.from({ length: MAX_TEMPLATES + 1 }, () => good) }),
      catalogBody({ templates: Array.from({ length: 100_000 }, () => 0) }),
    ];
    for (const item of bad) expect(parseEaCatalog(item)).toBeNull();
    expect(parseEaCatalog(catalogBody({ templates: [] }))?.templates).toEqual([]);
  });

  it("sends only GET to the catalog path with no query or body, and maps failures to fixed codes", async () => {
    const spy = mockApi(() => apiResponse(catalogBody()));
    expect((await fetchEaTemplates()).ok).toBe(true);
    expect(spy.mock.calls.map(([url, init]) => [String(url), init?.method])).toEqual([
      ["/api/v1/ea/templates", "GET"],
    ]);
    expect(spy.mock.calls[0]?.[1]?.body).toBeUndefined();
    mockApi(() => apiResponse({ detail: "AUTH_REQUIRED" }, 401));
    expect(await fetchEaTemplates()).toEqual({ ok: false, error: OPERATOR_SESSION_UNAVAILABLE });
    mockApi(() => apiResponse({ detail: "CATALOG_UNAVAILABLE", note: CANARY }, 503));
    expect(await fetchEaTemplates()).toEqual({ ok: false, error: "HTTP_503:CATALOG_UNAVAILABLE" });
    mockApi(() => apiResponse({ detail: "SECRET_TOKEN_VALUE" }, 400));
    expect(await fetchEaTemplates()).toEqual({ ok: false, error: "HTTP_400" });
    mockApi(() => new Response("<html>", { status: 502 }));
    expect(await fetchEaTemplates()).toEqual({ ok: false, error: "HTTP_502" });
    mockApi(() => new Response("not json", { status: 200 }));
    expect(await fetchEaTemplates()).toEqual({ ok: false, error: "MALFORMED_RESPONSE" });
    mockApi(() => { throw new TypeError("Failed to fetch"); });
    expect(await fetchEaTemplates()).toEqual({ ok: false, error: "NETWORK_ERROR" });
  });
});

describe("EaTemplateCatalogView", () => {
  it("reports loading honestly", () => {
    mockApi(never);
    render(<EaTemplateCatalogView />);
    expect(screen.getByRole("region", { name: "Template catalog" })).toBeTruthy();
    expect(screen.getByText("Waiting for a timestamped packet.")).toBeTruthy();
  });

  it("shows plain text for an unauthenticated session and no data", async () => {
    mockApi(() => apiResponse({ detail: "AUTH_REQUIRED" }, 401));
    const { container } = render(<EaTemplateCatalogView />);
    expect((await screen.findAllByText(SESSION_UNAVAILABLE_TEXT)).length).toBe(2);
    expect(SESSION_UNAVAILABLE_TEXT).toBe("operator session unavailable");
    expect(container.textContent).not.toContain("AUTH_REQUIRED");
    expect(container.querySelector("table")).toBeNull();
  });

  it("shows only a fixed code for server failures, malformed payloads and an unreachable gateway", async () => {
    mockApi(() => apiResponse({ detail: "CATALOG_UNAVAILABLE", secret: CANARY }, 503));
    const failed = render(<EaTemplateCatalogView />);
    expect((await screen.findAllByText("HTTP_503:CATALOG_UNAVAILABLE")).length).toBe(2);
    expect(failed.container.textContent).not.toContain(CANARY);
    failed.unmount();
    mockApi(() => apiResponse(catalogBody({ catalog_digest: CANARY })));
    const malformed = render(<EaTemplateCatalogView />);
    expect((await screen.findAllByText("MALFORMED_RESPONSE")).length).toBe(2);
    expect(malformed.container.textContent).not.toContain(CANARY);
    expect(malformed.container.querySelector("table")).toBeNull();
    malformed.unmount();
    mockApi(() => { throw new TypeError("Failed to fetch"); });
    render(<EaTemplateCatalogView />);
    expect((await screen.findAllByText("NETWORK_ERROR")).length).toBe(2);
  });

  it("shows an empty catalog explicitly and as unverified", async () => {
    mockApi(() => apiResponse(catalogBody({ templates: [] })));
    render(<EaTemplateCatalogView />);
    const region = await screen.findByRole("region", { name: "Template catalog: API-reported catalog" });
    expect(within(region).getByText("No templates reported.")).toBeTruthy();
    expect(within(region).getByText("UNVERIFIED")).toBeTruthy();
  });

  it("labels the listing unverified without a source timestamp and keeps receipt time separate", async () => {
    mockApi(() => apiResponse(catalogBody({ source: CANARY })));
    const { container } = render(<EaTemplateCatalogView />);
    const region = await screen.findByRole("region", { name: "Template catalog: API-reported catalog" });
    expect(within(region).getByText("UNVERIFIED")).toBeTruthy();
    const table = within(region).getByRole("table", { name: "Template catalog entries" });
    expect(within(table).getAllByRole("row").length).toBe(1 + 2 * BLOCKS.length);
    expect(within(table).getByText("MT4:bar_event")).toBeTruthy();
    expect(within(table).getByText("MT5:exit_signal.v1")).toBeTruthy();
    expect(within(region).getByText(DIGEST)).toBeTruthy();
    expect(screen.getAllByText("No valid source timestamp supplied.").length).toBe(2);
    expect(screen.getByText("Unavailable — no valid source timestamp")).toBeTruthy();
    expect(container.textContent).toContain("Response received");
    expect(container.textContent).toContain("Receipt expires");
    expect(container.textContent).not.toContain(CANARY);
  });

  it("does not show a closed-set violation and counts it instead", async () => {
    mockApi(() => apiResponse(catalogBody({
      templates: [entry("MT5", "sma_indicator"), entry("MT5", "RAW_CANARY_BLOCK")],
    })));
    const { container } = render(<EaTemplateCatalogView />);
    const region = await screen.findByRole("region", { name: "Template catalog: API-reported catalog" });
    expect(within(region).getByText("1 unrecognized")).toBeTruthy();
    expect(container.textContent).not.toContain("CANARY");
  });

  it("cannot be made fresh by an extra current timestamp the route does not define", async () => {
    mockApi(() => apiResponse(catalogBody({ as_of: Date.now(), asOf: Date.now() })));
    const { container } = render(<EaTemplateCatalogView />);
    const region = await screen.findByRole("region", { name: "Template catalog: API-reported catalog" });
    expect(within(region).getByText("UNVERIFIED")).toBeTruthy();
    expect(screen.getAllByText("No valid source timestamp supplied.").length).toBe(2);
    expect(screen.getByText("Unavailable — no valid source timestamp")).toBeTruthy();
    expect(container.querySelector(".operator-panel--fresh")).toBeNull();
  });

  it("treats an old extra timestamp the same way: still unverified, never delayed or hidden", async () => {
    mockApi(() => apiResponse(catalogBody({ as_of: Date.now() - 60_000 })));
    const { container } = render(<EaTemplateCatalogView />);
    await screen.findByRole("region", { name: "Template catalog: API-reported catalog" });
    expect(container.textContent).not.toContain("DELAYED");
    expect(container.textContent).not.toMatch(/values are hidden/);
  });

  it("has no control beyond Retry, no links, and makes no claim about EA status", async () => {
    const spy = mockApi(() => apiResponse(catalogBody()));
    const { container } = render(<EaTemplateCatalogView />);
    await screen.findByRole("table", { name: "Template catalog entries" });
    expect(container.querySelectorAll("input, select, textarea, form, a, [role='switch']").length)
      .toBe(0);
    for (const button of screen.getAllByRole("button")) expect(button.textContent).toBe("Retry");
    expect(container.textContent).not.toMatch(FORBIDDEN_WORDS);
    for (const [, init] of spy.mock.calls) expect(init?.method).toBe("GET");
  });

  it("ignores a late response from an older request once a newer one has landed", async () => {
    const resolvers: Array<(response: Response) => void> = [];
    let calls = 0;
    mockApi(() => {
      calls += 1;
      if (calls === 1) return apiResponse({ detail: "CATALOG_UNAVAILABLE" }, 503);
      if (calls === 2) return new Promise<Response>((resolve) => resolvers.push(resolve));
      return apiResponse(catalogBody({ templates: [entry("MT4", "bar_event")] }));
    });
    render(<EaTemplateCatalogView />);
    await screen.findAllByText("HTTP_503:CATALOG_UNAVAILABLE");
    fireEvent.click(screen.getAllByRole("button", { name: "Retry" })[0]!); // request 2: stays pending
    await waitFor(() => expect(calls).toBe(2));
    fireEvent.click(screen.getAllByRole("button", { name: "Retry" })[0]!); // request 3: lands first
    await screen.findByText("MT4:bar_event");
    await act(async () => {
      resolvers[0]?.(apiResponse(catalogBody({ templates: [entry("MT5", "compare.v1")] })));
    });
    expect(screen.getByText("MT4:bar_event")).toBeTruthy();
    expect(screen.queryByText("MT5:compare.v1")).toBeNull();
  });
});
