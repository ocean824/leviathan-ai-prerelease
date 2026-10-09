import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import App from "../App";
import { REGISTRY, resolveHash } from "../navigation/registry";
import { ChatTerminal } from "../chat/ChatTerminal";
import { createFakeChatPorts } from "../chat/chatClient";
import type {
  ChatStreamEventV1,
  ChatToolRegistryV1,
  ChatToolResultV1,
} from "../chat/chatTypes";

const wave35Codes = [
  "CC", "INTEL", "QR", "GP", "HP", "OMON", "CURV", "FXC", "WEI", "JRNL", "RISK", "GENOME",
  "LIVE", "KNOW", "LGD", "PACT", "PAPR", "EAC", "FLR", "DATA", "CHRT", "PORD", "PIPE", "HELP",
  "TODAY", "SYMBOL", "STRATEGY",
] as const;
const wave36Entries = [
  { code: "CONN", label: "Connections" },
  { code: "APPR", label: "Appearance" },
  { code: "CHAT", label: "Chat" },
] as const;
const expectedCodes = [...wave35Codes, ...wave36Entries.map(({ code }) => code)];

type RecordedCall = { url: string; method: string };

function setHash(hash: string) {
  window.history.replaceState({}, "", `/${hash}`);
}

function workspaceName(code: string) {
  const entry = REGISTRY.find((candidate) => candidate.code === code);
  return entry?.kind === "tab" ? `${entry.code} ${entry.label}` : `${code} workspace`;
}

function recordingFetch(calls: RecordedCall[]) {
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    calls.push({ url: String(input), method: init?.method ?? "GET" });
    return new Response(JSON.stringify({ code: "DEPENDENCY_UNAVAILABLE" }), {
      status: 503,
      headers: { "Content-Type": "application/json" },
    });
  });
}

afterEach(() => {
  cleanup();
  document.documentElement.removeAttribute("style");
  document.documentElement.removeAttribute("data-theme");
  document.documentElement.removeAttribute("data-accent");
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("NAV-WAVE36-001 independent acceptance", () => {
  it("adds exactly CONN, APPR, and CHAT as unique tab entries without changing prior codes", () => {
    const codes = REGISTRY.map(({ code }) => code);
    expect(new Set(codes).size).toBe(codes.length);
    expect([...codes].sort()).toEqual([...expectedCodes].sort());

    const added = REGISTRY.filter((entry) => !wave35Codes.includes(entry.code as (typeof wave35Codes)[number]));
    expect(added.map(({ code, label, kind }) => ({ code, label, kind }))).toEqual([
      { code: "CONN", label: "Connections", kind: "tab" },
      { code: "APPR", label: "Appearance", kind: "tab" },
      { code: "CHAT", label: "Chat", kind: "tab" },
    ]);
    for (const { code } of wave36Entries) {
      expect(REGISTRY.filter((entry) => entry.code === code)).toHaveLength(1);
      expect(resolveHash(`#${code}`).code).toBe(code);
    }
  });

  it.each([
    ["CONN", "Connections"],
    ["APPR", "Appearance"],
    ["CHAT", "Assistant terminal"],
  ])("deep-links #%s to the matching view", async (code, heading) => {
    setHash(`#${code}`);
    const fetcher = recordingFetch([]);
    vi.stubGlobal("fetch", fetcher);
    render(<App />);

    const workspace = await screen.findByRole("tabpanel", { name: workspaceName(code) });
    expect(within(workspace).getByRole("heading", { name: heading })).toBeTruthy();
    expect(resolveHash(window.location.hash).code).toBe(code);
  });

  it.each(["CONN", "APPR", "CHAT"] as const)(
    "performs only the selected view's read requests at initial render for #%s",
    async (code) => {
      const calls: RecordedCall[] = [];
      const fetcher = recordingFetch(calls);
      vi.stubGlobal("fetch", fetcher);
      setHash(`#${code}`);
      render(<App />);
      const heading = code === "CONN" ? "Connections" : code === "APPR" ? "Appearance" : "Assistant terminal";
      await screen.findByRole("heading", { name: heading });
      if (code === "CHAT") {
        expect(await screen.findByText("Authentication is unavailable. Chat history and models are not loaded.")).toBeTruthy();
        expect(calls).toEqual([]);
        expect(fetcher).not.toHaveBeenCalled();
        return;
      }
      await waitFor(() => expect(calls.length).toBeGreaterThan(0));

      expect(calls.every(({ method }) => method.toUpperCase() === "GET")).toBe(true);
      const urls = calls.map(({ url }) => url);
      if (code === "CONN") {
        expect(urls.sort()).toEqual(["/api/connections/catalog", "/api/connections/status"].sort());
      } else {
        expect(urls.length).toBeGreaterThan(0);
        expect(urls.every((url) => /appearance|preferences/i.test(url))).toBe(true);
      }
      expect(fetcher).toHaveBeenCalledTimes(calls.length);
    },
  );

  it("applies Appearance immediately while the preferences API is unavailable and makes no sync claim", async () => {
    localStorage.clear();
    const calls: RecordedCall[] = [];
    const fetcher = recordingFetch(calls);
    vi.stubGlobal("fetch", fetcher);
    setHash("#APPR");
    const originalDocument = document;
    const originalRoot = document.documentElement;
    render(<App />);

    await screen.findByRole("heading", { name: "Appearance" });
    expect(await screen.findByText(/account preferences are unavailable|not authoritative or synced across devices/i)).toBeTruthy();
    const callsBeforePreview = calls.length;
    fireEvent.click(screen.getByRole("radio", { name: /Light/ }));

    await waitFor(() => expect(document.documentElement.dataset.theme).toBe("light"));
    expect(document).toBe(originalDocument);
    expect(document.documentElement).toBe(originalRoot);
    expect(window.location.hash).toBe("#APPR");
    expect(calls).toHaveLength(callsBeforePreview);
    expect(document.body.textContent).not.toMatch(/synced across devices|saved to the account/i);
  });

  it("renders Chat fail-closed without approval and never writes chat state to localStorage", async () => {
    const storageWrite = vi.spyOn(Storage.prototype, "setItem");
    const proposal = {
      name: "paper.order.preview",
      arguments_json: JSON.stringify({ symbol: "ES", quantity: 1 }),
    };
    const streamEvents: ChatStreamEventV1[] = [
      { event: "tool_proposal", request_id: "request-chat", tool_proposal: proposal },
      { event: "finish", request_id: "request-chat", finish_reason: "tool_calls" },
    ];
    const registry: ChatToolRegistryV1 = {
      version: "1",
      revision: "synthetic-registry",
      entries: [{
        tool_id: proposal.name,
        capability: "Preview paper order",
        route: "paper/orders/preview",
        input_fields: ["symbol", "quantity"],
        output_schema: "PaperOrderPreviewV1",
        mutating: true,
        confirmation_parity: "typed_confirmation",
      }],
    };
    const ports = createFakeChatPorts({ streamEvents, registry });
    const plannedResult: ChatToolResultV1 = {
      version: "1",
      request_id: "plan-request",
      tool_id: proposal.name,
      status: "APPROVAL_REQUIRED",
      reason_codes: [],
      effect_performed: false,
      output_json: null,
      plan: {
        version: "1",
        plan_id: "synthetic-plan",
        tool_id: proposal.name,
        normalized_arguments: { symbol: "ES", quantity: 1 },
        account_id: "synthetic-account",
        environment: "paper",
        policy_revision: "policy-1",
        route: "paper/orders/preview",
        policy_summary: "Synthetic paper plan",
        risk_summary: "No effect until approved",
        expires_at_ns: Date.now() * 1_000_000 + 60_000_000_000,
        digest: "a".repeat(64),
        typed_confirmation: "CONFIRM PAPER ORDER ES",
        status: "APPROVAL_REQUIRED",
        reason_codes: [],
      },
    };
    const plan = vi.spyOn(ports.toolsPort, "plan").mockResolvedValue(plannedResult);
    const confirm = vi.spyOn(ports.toolsPort, "confirm");

    render(
      <ChatTerminal
        accountScopeKey="synthetic-scope"
        authState="fresh"
        chatPort={ports.chatPort}
        historyPort={ports.historyPort}
        toolsPort={ports.toolsPort}
      />,
    );
    await screen.findByText(/History: available/);
    fireEvent.change(screen.getByRole("textbox", { name: "Message" }), {
      target: { value: "Review a synthetic paper route" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Send" }));
    await screen.findByText("Awaiting operator review");
    fireEvent.click(screen.getByRole("button", { name: "Prepare plan" }));
    await screen.findByText("Plan · no effect is claimed");
    expect(plan).toHaveBeenCalledTimes(1);

    fireEvent.change(screen.getByRole("textbox", { name: "Typed confirmation" }), {
      target: { value: plannedResult.plan!.typed_confirmation },
    });
    fireEvent.click(screen.getByRole("button", { name: "Confirm this plan" }));
    expect(confirm).not.toHaveBeenCalled();
    expect(storageWrite).not.toHaveBeenCalled();
    expect(document.body.textContent).not.toContain("approval_proof");
  });
});
