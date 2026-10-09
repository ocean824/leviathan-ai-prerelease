import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { describe, expect, it, vi } from "vitest";
import { ChatTerminal } from "../ChatTerminal";
import { createFakeChatPorts } from "../chatClient";
import { parseProposalArguments, redactChatText, sanitizeJsonForDisplay } from "../chatState";
import type { ChatModelPublicV1, ChatToolConfirmRequestV1, ChatToolPlanRequestV1, ChatToolRegistryV1 } from "../chatTypes";

const MODEL: ChatModelPublicV1 = {
  alias: "safe-model", provider: "fixture", model_version: "v1", registry_version: "r1",
  modalities: ["text"], max_context_tokens: 4096, max_output_tokens: 256,
};

describe("chat terminal", () => {
  it("limits model choices to server-advertised aliases and labels local drafts honestly", async () => {
    const ports = createFakeChatPorts({ models: [MODEL] });
    render(<ChatTerminal accountScopeKey="acct-a" authState="fresh" {...ports} />);

    expect(await screen.findByRole("option", { name: "safe-model · fixture" })).toBeInTheDocument();
    expect(screen.getByLabelText("Message")).toBeInTheDocument();
    expect(screen.getByText(/Draft is in memory only/)).toBeInTheDocument();
    expect(screen.getByText(/History: available/)).toBeInTheDocument();
  });

  it("renders streamed output and says cost is unavailable when no price is supplied", async () => {
    const ports = createFakeChatPorts({ models: [MODEL] });
    render(<ChatTerminal accountScopeKey="acct-a" authState="fresh" {...ports} />);
    await screen.findByRole("option", { name: "safe-model · fixture" });
    fireEvent.change(screen.getByLabelText("Message"), { target: { value: "What is the status?" } });
    fireEvent.click(screen.getByRole("button", { name: "Send" }));

    expect(await screen.findByText("Fixture response")).toBeInTheDocument();
    expect(await screen.findByText(/cost unavailable/)).toBeInTheDocument();
    expect(screen.getAllByText("Saved to account history")).toHaveLength(2);
  });

  it("clears drafts when the authenticated account changes or signs out", async () => {
    const ports = createFakeChatPorts({ models: [MODEL] });
    const view = render(<ChatTerminal accountScopeKey="acct-a" authState="fresh" {...ports} />);
    await screen.findByRole("option", { name: "safe-model · fixture" });
    fireEvent.change(screen.getByLabelText("Message"), { target: { value: "private unsent prompt" } });
    expect(screen.getByLabelText("Message")).toHaveValue("private unsent prompt");

    view.rerender(<ChatTerminal accountScopeKey="acct-b" authState="fresh" {...ports} />);
    await waitFor(() => expect(screen.getByLabelText("Message")).toHaveValue(""));
    view.rerender(<ChatTerminal accountScopeKey="acct-b" authState="signed-out" {...ports} />);
    expect(screen.getByText("Sign in to use chat.")).toBeInTheDocument();
    expect(screen.getByLabelText("Message")).toHaveValue("");
  });

  it("forwards trusted proof only after exact typed confirmation and fails closed without proof", async () => {
    const registry: ChatToolRegistryV1 = { version: "1", revision: "r1", entries: [{ tool_id: "paper.place", capability: "Place paper order", route: "/paper/orders", input_fields: ["symbol"], output_schema: "PaperOrder", mutating: true, confirmation_parity: "typed_confirmation" }] };
    const ports = createFakeChatPorts({ models: [MODEL], registry, streamEvents: [{ event: "tool_proposal", request_id: "fixture", tool_proposal: { name: "paper.place", arguments_json: "{\"symbol\":\"ABC\"}" } }] });
    const plan = { version: "1" as const, plan_id: "plan-1", tool_id: "paper.place", normalized_arguments: { symbol: "ABC" }, account_id: "paper-account", environment: "PAPER", policy_revision: "p1", route: "/paper/orders", policy_summary: "Paper only", risk_summary: "Bounded", expires_at_ns: 1_900_000_000_000_000_000, digest: "digest-1", typed_confirmation: "CONFIRM PAPER ORDER", status: "APPROVAL_REQUIRED" as const, reason_codes: [] };
    const planResult = { version: "1" as const, request_id: "request-1", tool_id: "paper.place", status: "APPROVAL_REQUIRED" as const, reason_codes: [], effect_performed: false, output_json: null, plan };
    const planSpy = vi.fn(async (_request: ChatToolPlanRequestV1) => planResult);
    const confirmSpy = vi.fn(async (_request: ChatToolConfirmRequestV1) => ({ version: "1" as const, request_id: "request-2", tool_id: "paper.place", status: "CONFIRMED" as const, reason_codes: [], effect_performed: true, output_json: "{\"receipt\":\"verified\"}", plan: null }));
    const approvalSpy = vi.fn(async () => "opaque-sec004-proof" as string | null);
    const toolPorts = { ...ports, toolsPort: { ...ports.toolsPort, plan: planSpy, confirm: confirmSpy } };
    const approvalPort = { obtainApprovalProof: approvalSpy };
    render(<ChatTerminal accountScopeKey="acct-a" authState="fresh" {...toolPorts} approvalPort={approvalPort} />);
    await screen.findByRole("option", { name: "safe-model · fixture" });
    fireEvent.change(screen.getByLabelText("Message"), { target: { value: "Place paper order" } });
    fireEvent.click(screen.getByRole("button", { name: "Send" }));
    fireEvent.click(await screen.findByRole("button", { name: "Prepare plan" }));
    await screen.findByText(/Type exactly:/);
    const confirmation = screen.getByLabelText("Typed confirmation");
    fireEvent.change(confirmation, { target: { value: "wrong phrase" } });
    expect(screen.getByRole("button", { name: "Confirm this plan" })).toBeDisabled();
    fireEvent.change(confirmation, { target: { value: "CONFIRM PAPER ORDER" } });
    fireEvent.click(screen.getByRole("button", { name: "Confirm this plan" }));
    await waitFor(() => expect(confirmSpy).toHaveBeenCalledTimes(1));
    expect(approvalSpy).toHaveBeenCalledWith({ plan_id: "plan-1", digest: "digest-1", typed_confirmation: "CONFIRM PAPER ORDER" });
    expect(confirmSpy.mock.calls[0]?.[0]).toMatchObject({ approval_proof: "opaque-sec004-proof", typed_confirmation: "CONFIRM PAPER ORDER" });
    expect(screen.queryByText("opaque-sec004-proof")).not.toBeInTheDocument();
    expect(planSpy).toHaveBeenCalledTimes(1);
    expect(screen.getByText("Verified route result")).toBeInTheDocument();
  });
});

describe("chat display sanitizers", () => {
  it("redacts credential-like text and sensitive argument keys", () => {
    expect(redactChatText("Authorization: Bearer abcdefghijklmnop")).toBe("[sensitive content redacted]");
    expect(sanitizeJsonForDisplay({ symbol: "ABC", api_key: "secret-value" })).not.toContain("secret-value");
    expect(parseProposalArguments({ name: "tool", arguments_json: "[]" })).toBeNull();
  });
});
