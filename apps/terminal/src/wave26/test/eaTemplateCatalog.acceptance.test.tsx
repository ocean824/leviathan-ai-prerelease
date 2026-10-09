import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { parseEaCatalog } from "../api/eaTemplates";
import { EaTemplateCatalogView } from "../views/EaTemplateCatalogView";
import {
  EA_TEMPLATE_GRAPH_CANARY,
  EA_TEMPLATE_SECRET_CANARY,
  EA_TEMPLATE_SOURCE_CANARY,
  catalogResponseWithTemplates,
  eaTemplateCatalogResponse,
  eaTemplateCatalogWithUntrustedTimestamp,
  eaTemplateCatalogWithUnknownBlock,
  invalidTemplateIds,
} from "./fixtures/eaTemplateCatalog";

type CapturedRequest = { url: string; method: string };
type DeferredRequest = CapturedRequest & { resolve: (response: Response) => void };

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function installFetcher(respond: (url: string, method: string) => Response | Promise<Response>) {
  const requests: CapturedRequest[] = [];
  const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = { url: String(input), method: init?.method ?? "GET" };
    requests.push(request);
    return respond(request.url, request.method);
  });
  vi.stubGlobal("fetch", fetcher);
  return { fetcher, requests };
}

function installDeferredFetcher() {
  const requests: DeferredRequest[] = [];
  const fetcher = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    return new Promise<Response>((resolve) => {
      requests.push({
        url: String(input),
        method: init?.method ?? "GET",
        resolve,
      });
    });
  });
  vi.stubGlobal("fetch", fetcher);
  return { fetcher, requests };
}

async function resolveRequest(request: DeferredRequest, response: Response) {
  await act(async () => {
    request.resolve(response);
    await Promise.resolve();
    await Promise.resolve();
  });
}

function assertReadOnly(requests: readonly CapturedRequest[]) {
  expect(requests.length).toBeGreaterThan(0);
  expect(requests.every(({ url }) => url === "/api/v1/ea/templates")).toBe(true);
  expect(requests.every(({ method }) => method === "GET")).toBe(true);
}

function assertNoExportOrDeployControls() {
  expect(screen.queryByRole("button", { name: /export|deploy|download|metaeditor|broker|submit/i })).toBeNull();
  expect(screen.queryByRole("link", { name: /export|deploy|download|metaeditor|broker|submit/i })).toBeNull();
  expect(screen.queryByRole("textbox")).toBeNull();
}

function assertNoTemplateBodiesOrRawPayloads() {
  const rendered = `${document.body.textContent ?? ""}\n${document.body.innerHTML}`;
  for (const canary of [EA_TEMPLATE_SOURCE_CANARY, EA_TEMPLATE_GRAPH_CANARY, EA_TEMPLATE_SECRET_CANARY]) {
    expect(rendered).not.toContain(canary);
  }
  expect(rendered).not.toMatch(/\bsource_text\b|\bmql_source\b|\bgraph_json\b|\braw_payload\b/i);
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("EA-TEMPLATE-CATALOG-UI-001 independent acceptance", () => {
  it("uses only GET for the catalog, renders no source body, and exposes no export/deploy controls", async () => {
    const { requests } = installFetcher(() => jsonResponse(eaTemplateCatalogResponse));
    render(<EaTemplateCatalogView />);

    expect(await screen.findByText("MT4:bar_event")).toBeTruthy();
    expect(screen.getByText("MT5:sma_indicator")).toBeTruthy();
    assertReadOnly(requests);
    assertNoExportOrDeployControls();
    assertNoTemplateBodiesOrRawPayloads();
  });

  it("accepts only closed-grammar template IDs and never renders an unrecognized block ID", async () => {
    const { requests } = installFetcher(() => jsonResponse(eaTemplateCatalogWithUnknownBlock));
    render(<EaTemplateCatalogView />);

    expect(await screen.findByText("MT4:bar_event")).toBeTruthy();
    expect(screen.queryByText("MT4:unsupported_block_v1")).toBeNull();
    expect(screen.queryByText("unsupported_block_v1")).toBeNull();
    expect(screen.getByText("1 unrecognized")).toBeTruthy();
    assertReadOnly(requests);
    assertNoTemplateBodiesOrRawPayloads();
  });

  it.each(invalidTemplateIds)("drops malformed template ID %s without echoing it", async (templateId) => {
    const platform = templateId.startsWith("MT5:") ? "MT5" : "MT4";
    const { requests } = installFetcher(() => jsonResponse(catalogResponseWithTemplates([
      { template_id: templateId, block_id: "bar_event", platform },
    ])));
    render(<EaTemplateCatalogView />);

    await waitFor(() => expect(document.body.textContent).toMatch(/MALFORMED_RESPONSE|malformed/i));
    expect(document.body.textContent).not.toContain(templateId);
    expect(document.body.innerHTML).not.toContain(templateId);
    assertReadOnly(requests);
  });

  it("maps 401 to the fixed operator-session message without showing the response body", async () => {
    const responseCanary = "SYNTHETIC_401_BODY_SECRET_MUST_NOT_RENDER";
    const { requests } = installFetcher(() => jsonResponse({
      detail: "AUTH_REQUIRED",
      message: responseCanary,
      raw_payload: responseCanary,
    }, 401));
    render(<EaTemplateCatalogView />);

    expect((await screen.findAllByText("operator session unavailable")).length).toBe(2);
    expect(document.body.textContent).not.toContain(responseCanary);
    expect(document.body.innerHTML).not.toContain(responseCanary);
    assertReadOnly(requests);
    assertNoExportOrDeployControls();
  });

  it("keeps a successful catalog API-reported and unavailable when the source timestamp is absent", async () => {
    const { requests } = installFetcher(() => jsonResponse(eaTemplateCatalogResponse));
    render(<EaTemplateCatalogView />);

    const catalogRegion = await screen.findByRole("region", {
      name: "Template catalog: API-reported catalog",
    });
    expect(catalogRegion.textContent).toContain("UNVERIFIED");
    expect(screen.getByText("UNAVAILABLE")).toBeTruthy();
    expect(screen.getAllByText(/no valid source timestamp/i).length).toBeGreaterThanOrEqual(2);
    expect(screen.getAllByText(/response received/i).length).toBeGreaterThanOrEqual(1);
    expect(catalogRegion.textContent).not.toMatch(/\bFRESH\b|\bVERIFIED\b/);
    assertReadOnly(requests);
  });

  it("drops an older catalog refresh that resolves after a newer one", async () => {
    const { requests } = installDeferredFetcher();
    render(<EaTemplateCatalogView />);
    await waitFor(() => expect(requests).toHaveLength(1));

    await resolveRequest(requests[0]!, jsonResponse({ detail: "AUTH_REQUIRED" }, 401));
    expect((await screen.findAllByText("operator session unavailable")).length).toBe(2);

    fireEvent.click(screen.getAllByRole("button", { name: "Retry" })[0]!);
    await waitFor(() => expect(requests).toHaveLength(2));
    fireEvent.click(screen.getAllByRole("button", { name: "Retry" })[0]!);
    await waitFor(() => expect(requests).toHaveLength(3));
    assertReadOnly(requests);

    const newer = catalogResponseWithTemplates([
      { template_id: "MT5:exit_signal.v1", block_id: "exit_signal.v1", platform: "MT5" },
    ]);
    const older = catalogResponseWithTemplates([
      { template_id: "MT4:sma_indicator", block_id: "sma_indicator", platform: "MT4" },
    ]);
    await resolveRequest(requests[2]!, jsonResponse(newer));
    expect(await screen.findByText("MT5:exit_signal.v1")).toBeTruthy();
    await resolveRequest(requests[1]!, jsonResponse(older));

    expect(screen.getByText("MT5:exit_signal.v1")).toBeTruthy();
    expect(screen.queryByText("MT4:sma_indicator")).toBeNull();
    assertNoTemplateBodiesOrRawPayloads();
  });
});

describe("EA-TEMPLATE-CATALOG-UI-001 timestamp boundary", () => {
  it.each(["as_of", "asOf"] as const)(
    "does not trust current extra %s as source time",
    async (timestampField) => {
      const response = eaTemplateCatalogWithUntrustedTimestamp(timestampField);
      const report = parseEaCatalog(response);
      expect(report).not.toBeNull();
      expect(report).not.toHaveProperty("as_of");
      expect(report).not.toHaveProperty("asOf");

      const { requests } = installFetcher(() => jsonResponse(response));
      render(<EaTemplateCatalogView />);

      const catalogRegion = await screen.findByRole("region", {
        name: "Template catalog: API-reported catalog",
      });
      expect(catalogRegion.textContent).toContain("UNVERIFIED");
      expect(screen.getByText("UNAVAILABLE")).toBeTruthy();
      expect(screen.getAllByText("No valid source timestamp supplied.").length).toBeGreaterThanOrEqual(2);
      expect(document.body.textContent).toMatch(
        /Source as of\s+Unavailable.*no valid source timestamp/i,
      );
      expect(document.body.textContent).toMatch(/Response received/i);
      expect(document.body.textContent).toMatch(/Receipt expires/i);
      expect(document.querySelector(".operator-panel--unavailable")).not.toBeNull();
      expect(document.querySelector(".operator-panel--fresh")).toBeNull();
      assertReadOnly(requests);
    },
  );
});


