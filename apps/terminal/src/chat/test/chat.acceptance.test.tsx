import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ChatTerminal } from "../ChatTerminal";
import { ChatToolCard } from "../ChatToolCard";
import { ChatTranscript } from "../ChatTranscript";
import type { ChatToolCardProps } from "../ChatToolCard";
import type {
  ChatClientPort,
  ChatHistoryMessageV1,
  ChatHistoryPort,
  ChatModelPublicV1,
  ChatToolApprovalPort,
  ChatToolPlanCardV1,
  ChatToolRegistryEntryV1,
  ChatToolResultV1,
  ChatToolProposalV1,
  ChatToolsPort,
  ChatMessageViewV1,
  ConversationV1,
} from "../chatTypes";

const proposal: ChatToolProposalV1 = {
  name: "paper.order.preview",
  arguments_json: JSON.stringify({ symbol: "ES", quantity: 1 }),
};

afterEach(() => cleanup());

const registryEntry: ChatToolRegistryEntryV1 = {
  tool_id: "paper.order.preview",
  capability: "Preview paper order",
  route: "paper/orders/preview",
  input_fields: ["symbol", "quantity"],
  output_schema: "PaperOrderPreviewV1",
  mutating: true,
  confirmation_parity: "typed_confirmation",
};

const plan: ChatToolPlanCardV1 = {
  version: "1",
  plan_id: "plan-001",
  tool_id: registryEntry.tool_id,
  normalized_arguments: { symbol: "ES", quantity: 1 },
  account_id: "synthetic-account",
  environment: "paper",
  policy_revision: "policy-1",
  route: registryEntry.route,
  policy_summary: "Paper-only route",
  risk_summary: "Within synthetic limits",
  expires_at_ns: 1_800_000_000_000_000_000,
  digest: "a".repeat(64),
  typed_confirmation: "CONFIRM PAPER ORDER ES",
  status: "APPROVAL_REQUIRED",
  reason_codes: [],
};

function planResult(): ChatToolResultV1 {
  return {
    version: "1",
    request_id: "request-001",
    tool_id: registryEntry.tool_id,
    status: "APPROVAL_REQUIRED",
    reason_codes: [],
    effect_performed: false,
    output_json: null,
    plan,
  };
}

function renderCard(overrides: Partial<ChatToolCardProps> = {}) {
  const onPrepare = vi.fn();
  const onConfirm = vi.fn();
  render(
    <ChatToolCard
      proposal={proposal}
      registryEntry={registryEntry}
      mode="plan_then_confirm"
      result={planResult()}
      authEnabled
      onPrepare={onPrepare}
      onConfirm={onConfirm}
      {...overrides}
    />,
  );
  return { onPrepare, onConfirm };
}

const model = {
  alias: "safe-paper-model",
  provider: "synthetic",
  model_version: "1",
  registry_version: "models-1",
  modalities: ["text"],
  max_context_tokens: 2048,
  max_output_tokens: 256,
};
const additionalModel = { ...model, alias: "second-advertised-model" };

const conversation = {
  conversation_id: "conversation-1",
  user_scope: "authenticated-user",
  title: "Synthetic conversation",
  model_alias: model.alias,
  created_at_ns: 1,
  updated_at_ns: 1,
  revision: 1,
  retention_until_ns: 9_999_999_999,
};
const accountAMessage: ChatHistoryMessageV1 = {
  message_id: "account-a-message",
  conversation_id: conversation.conversation_id,
  role: "user",
  content: { text: "PRIVATE ACCOUNT A TRANSCRIPT" },
  created_at_ns: 2,
  provider_usage: null,
};

const toolRegistry = {
  version: "1" as const,
  revision: "tools-1",
  entries: [registryEntry],
};

function makePorts(options: {
  stream?: ChatClientPort["stream"];
  models?: readonly ChatModelPublicV1[];
  conversations?: readonly ConversationV1[];
  messages?: readonly ChatHistoryMessageV1[];
} = {}) {
  const stream = options.stream ?? vi.fn(() => (async function* () {
  yield { event: "tool_proposal" as const, request_id: "chat-request", tool_proposal: proposal };
  yield { event: "finish" as const, request_id: "chat-request", finish_reason: "tool_calls" as const };
})());
  const chatPort: ChatClientPort = {
    listModels: vi.fn(async () => options.models ?? [model]),
    complete: vi.fn(),
    stream,
  };
  const historyPort: ChatHistoryPort = {
    listConversations: vi.fn(async () => ({ conversations: options.conversations ?? [conversation], next_cursor: null })),
    createConversation: vi.fn(async (request) => ({ ...conversation, model_alias: request.model_alias })),
    listMessages: vi.fn(async () => ({ messages: options.messages ?? [], next_cursor: null })),
    appendMessage: vi.fn(async (request) => ({
      ...request,
      created_at_ns: 2,
      provider_usage: request.provider_usage ?? null,
    })),
    deleteConversation: vi.fn(async () => undefined),
  };
  const toolsPort: ChatToolsPort = {
    listRegistry: vi.fn(async () => toolRegistry),
    plan: vi.fn(async () => planResult()),
    confirm: vi.fn(async (): Promise<ChatToolResultV1> => ({ ...planResult(), status: "CONFIRMED", effect_performed: true })),
    read: vi.fn(async () => ({
      version: "1" as const,
      request_id: "read-1",
      tool_id: registryEntry.tool_id,
      status: "READ_ALLOWED" as const,
      reason_codes: [],
      effect_performed: false,
      output_json: JSON.stringify({ status: "available" }),
      plan: null,
    })),
  };
  return { chatPort, historyPort, toolsPort };
}

async function renderTerminal(options: {
  accountScopeKey?: string;
  authState?: "fresh" | "stale" | "unavailable" | "signed-out";
  approvalPort?: ChatToolApprovalPort;
  ports?: ReturnType<typeof makePorts>;
} = {}) {
  const ports = options.ports ?? makePorts();
  const view = render(
    <ChatTerminal
      accountScopeKey={options.accountScopeKey ?? "account-A"}
      authState={options.authState ?? "fresh"}
      chatPort={ports.chatPort}
      historyPort={ports.historyPort}
      toolsPort={ports.toolsPort}
      approvalPort={options.approvalPort}
    />,
  );
  await screen.findByText(/History: available/);
  return { ...ports, ...view };
}

async function submitToolProposal() {
  fireEvent.change(screen.getByRole("combobox", { name: "Conversation" }), {
    target: { value: conversation.conversation_id },
  });
  await waitFor(() => expect((screen.getByRole("combobox", { name: "Conversation" }) as HTMLSelectElement).value).toBe(conversation.conversation_id));
  fireEvent.change(screen.getByRole("textbox", { name: "Message" }), {
    target: { value: "Review a synthetic paper route" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Send" }));
  await screen.findByText("Awaiting operator review");
}

async function submitAndPrepareTool() {
  await submitToolProposal();
  fireEvent.click(screen.getByRole("button", { name: "Prepare plan" }));
  await screen.findByText("Type exactly:");
}

describe("CHAT-003 independent tool-card acceptance", () => {
  it("requires the exact displayed typed confirmation before enabling a mutation", () => {
    const { onConfirm } = renderCard();
    const confirm = screen.getByRole("button", { name: "Confirm this plan" });
    expect((confirm as HTMLButtonElement).disabled).toBe(true);

    const input = screen.getByRole("textbox", { name: "Typed confirmation" });
    fireEvent.change(input, { target: { value: "confirm paper order es" } });
    expect((confirm as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(input, { target: { value: plan.typed_confirmation } });
    expect((confirm as HTMLButtonElement).disabled).toBe(false);
    fireEvent.click(confirm);
    expect(onConfirm).toHaveBeenCalledTimes(1);
    expect(onConfirm).toHaveBeenCalledWith(plan, plan.typed_confirmation);
  });

  it("allows walkthrough planning without exposing a mutation confirmation control", () => {
    const { onPrepare, onConfirm } = renderCard({ mode: "walkthrough", result: null });
    expect(screen.getByText(/cannot execute mutations/i)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Confirm this plan" })).toBeNull();
    expect((screen.getByRole("button", { name: "Prepare plan" }) as HTMLButtonElement).disabled).toBe(false);
    fireEvent.click(screen.getByRole("button", { name: "Prepare plan" }));
    expect(onPrepare).toHaveBeenCalledWith(proposal, "walkthrough");
    expect(onConfirm).not.toHaveBeenCalled();
  });

  it("shows a plan as unperformed and keeps untrusted proposal values out of display", () => {
    const unsafeProposal: ChatToolProposalV1 = {
      name: proposal.name,
      arguments_json: JSON.stringify({ api_key: "sk-live-DO_NOT_RENDER_1234", note: "Bearer secret-token-123456789", symbol: "ES" }),
    };
    const { container } = render(
      <ChatToolCard
        proposal={unsafeProposal}
        registryEntry={registryEntry}
        mode="plan_then_confirm"
        result={planResult()}
        authEnabled
        onPrepare={vi.fn()}
        onConfirm={vi.fn()}
      />,
    );
    expect(screen.getByText(/no effect is claimed/i)).toBeTruthy();
    expect(container.textContent).not.toContain("DO_NOT_RENDER");
    expect(container.textContent).not.toContain("sk-live-");
    expect(container.textContent).toContain("[sensitive content redacted]");
  });

  it("renders output as sanitized content and labels a denial", () => {
    const denied: ChatToolResultV1 = {
      ...planResult(),
      status: "DENIED",
      plan: null,
      reason_codes: ["POLICY_DENIED"],
      output_json: JSON.stringify({ password: "Bearer secret-token-123456789", status: "denied" }),
    };
    const { container } = render(
      <ChatToolCard
        proposal={proposal}
        registryEntry={registryEntry}
        mode="plan_then_confirm"
        result={denied}
        authEnabled
        onPrepare={vi.fn()}
        onConfirm={vi.fn()}
      />,
    );
    expect(screen.getByText("Tool request denied")).toBeTruthy();
    expect(container.textContent).not.toContain("secret-token");
    expect(container.textContent).not.toContain("Bearer");
  });

  it("does not expose action controls when the proposal is absent from the approved registry", () => {
    const { onPrepare, onConfirm } = renderCard({ registryEntry: null, result: null });
    expect(screen.getByText(/not listed in the server-approved registry/i)).toBeTruthy();
    expect(screen.queryByRole("button", { name: /prepare|run approved read/i })).toBeNull();
    expect(onPrepare).not.toHaveBeenCalled();
    expect(onConfirm).not.toHaveBeenCalled();
  });

  it("obtains proof from the injected trusted adapter and forwards it only to confirm", async () => {
    const proof = "opaque-test-proof-never-render-this";
    const approvalPort: ChatToolApprovalPort = {
      obtainApprovalProof: vi.fn(async () => proof),
    };
    const { toolsPort, historyPort } = await renderTerminal({ approvalPort });
    await submitAndPrepareTool();
    fireEvent.change(screen.getByRole("textbox", { name: "Typed confirmation" }), {
      target: { value: plan.typed_confirmation },
    });
    fireEvent.click(screen.getByRole("button", { name: "Confirm this plan" }));

    await waitFor(() => expect(toolsPort.confirm).toHaveBeenCalledTimes(1));
    expect(approvalPort.obtainApprovalProof).toHaveBeenCalledWith({
      plan_id: plan.plan_id,
      digest: plan.digest,
      typed_confirmation: plan.typed_confirmation,
    });
    expect(toolsPort.confirm).toHaveBeenCalledWith(expect.objectContaining({
      plan_id: plan.plan_id,
      digest: plan.digest,
      typed_confirmation: plan.typed_confirmation,
      approval_proof: proof,
    }));
    expect(document.body.textContent).not.toContain(proof);
    expect(JSON.stringify(vi.mocked(historyPort.appendMessage).mock.calls)).not.toContain(proof);
  });

  it("does not call confirm when the approval adapter cannot issue proof", async () => {
    const approvalPort: ChatToolApprovalPort = {
      obtainApprovalProof: vi.fn(async () => null),
    };
    const { toolsPort } = await renderTerminal({ approvalPort });
    await submitAndPrepareTool();
    fireEvent.change(screen.getByRole("textbox", { name: "Typed confirmation" }), {
      target: { value: plan.typed_confirmation },
    });
    fireEvent.click(screen.getByRole("button", { name: "Confirm this plan" }));

    expect(await screen.findByText(/Trusted approval is unavailable/i)).toBeTruthy();
    expect(toolsPort.confirm).not.toHaveBeenCalled();
  });

  it("keeps approval pending until the trusted adapter resolves", async () => {
    let releaseProof: ((value: string | null) => void) | undefined;
    const approvalPort: ChatToolApprovalPort = {
      obtainApprovalProof: vi.fn(() => new Promise<string | null>((resolve) => { releaseProof = resolve; })),
    };
    const { toolsPort } = await renderTerminal({ approvalPort });
    await submitAndPrepareTool();
    fireEvent.change(screen.getByRole("textbox", { name: "Typed confirmation" }), {
      target: { value: plan.typed_confirmation },
    });
    fireEvent.click(screen.getByRole("button", { name: "Confirm this plan" }));
    await waitFor(() => expect(approvalPort.obtainApprovalProof).toHaveBeenCalledTimes(1));
    expect(toolsPort.confirm).not.toHaveBeenCalled();
    releaseProof?.("opaque-pending-proof");
    await waitFor(() => expect(toolsPort.confirm).toHaveBeenCalledTimes(1));
  });

  it("renders a server denial as a visible non-effect result after typed approval", async () => {
    const approvalPort: ChatToolApprovalPort = { obtainApprovalProof: vi.fn(async () => "opaque-proof") };
    const ports = makePorts();
    vi.mocked(ports.toolsPort.confirm).mockResolvedValue({
      ...planResult(),
      status: "DENIED",
      effect_performed: false,
      plan: null,
      reason_codes: ["POLICY_CHANGED"],
    });
    await renderTerminal({ approvalPort, ports });
    await submitAndPrepareTool();
    fireEvent.change(screen.getByRole("textbox", { name: "Typed confirmation" }), {
      target: { value: plan.typed_confirmation },
    });
    fireEvent.click(screen.getByRole("button", { name: "Confirm this plan" }));
    expect(await screen.findByText("Tool request denied")).toBeTruthy();
    expect(document.body.textContent).not.toContain("effect performed");
  });

  it("plan-then-confirm mode performs planning only until explicit typed approval", async () => {
    const approvalPort: ChatToolApprovalPort = { obtainApprovalProof: vi.fn(async () => null) };
    const { toolsPort } = await renderTerminal({ approvalPort });
    await submitAndPrepareTool();
    expect(toolsPort.plan).toHaveBeenCalledTimes(1);
    expect(toolsPort.confirm).not.toHaveBeenCalled();
    expect((screen.getByRole("button", { name: "Confirm this plan" }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("walk-through mode may plan but exposes no mutation confirmation path", async () => {
    const ports = makePorts();
    await renderTerminal({ ports });
    fireEvent.change(screen.getByRole("combobox", { name: "Interaction" }), {
      target: { value: "walkthrough" },
    });
    await submitToolProposal();
    expect((screen.getByRole("button", { name: "Prepare plan" }) as HTMLButtonElement).disabled).toBe(false);
    fireEvent.click(screen.getByRole("button", { name: "Prepare plan" }));
    await screen.findByText("No mutation confirmation is available in this mode.");
    expect(ports.toolsPort.plan).toHaveBeenCalledTimes(1);
    expect(ports.toolsPort.confirm).not.toHaveBeenCalled();
    expect(screen.queryByRole("button", { name: "Confirm this plan" })).toBeNull();
  });
});

describe("CHAT-003 independent terminal acceptance", () => {
  it("clears account A history from memory before loading account B and never sends the UI scope key", async () => {
    const portsA = makePorts({ messages: [accountAMessage] });
    const first = await renderTerminal({ accountScopeKey: "synthetic-account-A", ports: portsA });
    fireEvent.change(screen.getByRole("combobox", { name: "Conversation" }), {
      target: { value: conversation.conversation_id },
    });
    expect(await screen.findByText("PRIVATE ACCOUNT A TRANSCRIPT")).toBeTruthy();

    const portsB = makePorts({ conversations: [], messages: [] });
    first.rerender(
      <ChatTerminal
        accountScopeKey="synthetic-account-B"
        authState="fresh"
        chatPort={portsB.chatPort}
        historyPort={portsB.historyPort}
        toolsPort={portsB.toolsPort}
      />,
    );
    await waitFor(() => expect(screen.queryByText("PRIVATE ACCOUNT A TRANSCRIPT")).toBeNull());
    const calls = JSON.stringify([
      vi.mocked(portsA.historyPort.listConversations).mock.calls,
      vi.mocked(portsA.historyPort.listMessages).mock.calls,
      vi.mocked(portsB.historyPort.listConversations).mock.calls,
      vi.mocked(portsB.historyPort.listMessages).mock.calls,
    ]);
    expect(calls).not.toContain("synthetic-account-A");
    expect(calls).not.toContain("synthetic-account-B");
  });

  it("announces loading and then fails closed to a content-free offline message", async () => {
    const ports = makePorts();
    let resolveModels: ((value: readonly typeof model[]) => void) | undefined;
    vi.mocked(ports.chatPort.listModels).mockImplementation(() => new Promise((resolve) => { resolveModels = resolve; }));
    render(
      <ChatTerminal
        accountScopeKey="account-loading"
        authState="fresh"
        chatPort={ports.chatPort}
        historyPort={ports.historyPort}
        toolsPort={ports.toolsPort}
      />,
    );
    expect(screen.getByRole("region", { name: "Chat terminal" }).querySelector(".chat-terminal__status")?.textContent).toContain("loading");
    resolveModels?.([model]);
    expect(await screen.findByText(/History: available/)).toBeTruthy();

    cleanup();
    const failing = makePorts();
    vi.mocked(failing.chatPort.listModels).mockRejectedValue(new Error("provider secret payload must not echo"));
    render(
      <ChatTerminal
        accountScopeKey="account-offline"
        authState="fresh"
        chatPort={failing.chatPort}
        historyPort={failing.historyPort}
        toolsPort={failing.toolsPort}
      />,
    );
    expect(await screen.findByText("Chat services are unavailable. Retry to load account history and models.")).toBeTruthy();
    expect(document.body.textContent).not.toContain("provider secret payload");
    expect((screen.getByRole("button", { name: "Send" }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("offers only advertised model aliases and labels unknown usage and cost unavailable", async () => {
    const record = {
      request_id: "chat-1",
      model_alias: model.alias,
      api_shape: "chat.completions",
      registry_version: "models-1",
      policy_version: "policy-1",
      elapsed_ns: 1,
      usage: { input_tokens: 4, output_tokens: 3 },
      cost_status: "unavailable" as const,
      cost_usd: null,
      hosted_egress_disclosed: false,
    };
    const stream: ChatClientPort["stream"] = vi.fn(() => (async function* () {
      yield { event: "text_delta" as const, request_id: "chat-1", text_delta: "Synthetic answer" };
      yield { event: "record" as const, request_id: "chat-1", record };
    })());
    const ports = makePorts({ models: [model, additionalModel], stream });
    await renderTerminal({ ports });
    const modelPicker = screen.getByRole("combobox", { name: "Model" }) as HTMLSelectElement;
    expect(Array.from(modelPicker.options).map((option) => option.value).filter(Boolean)).toEqual([
      model.alias,
      additionalModel.alias,
    ]);
    fireEvent.change(screen.getByRole("combobox", { name: "Conversation" }), {
      target: { value: conversation.conversation_id },
    });
    fireEvent.change(screen.getByRole("textbox", { name: "Message" }), {
      target: { value: "synthetic prompt" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Send" }));
    const answerCopies = await screen.findAllByText("Synthetic answer");
    expect(answerCopies).toHaveLength(1);
    expect(screen.getByText(/7 tokens · cost unavailable/)).toBeTruthy();
  });

  it("aborts the in-flight stream when Cancel response is activated", async () => {
    let activeSignal: AbortSignal | undefined;
    const stream: ChatClientPort["stream"] = vi.fn((request, signal) => {
      activeSignal = signal;
      return (async function* () {
        yield { event: "start" as const, request_id: request.request_id };
        yield { event: "text_delta" as const, request_id: request.request_id, text_delta: "Partial answer" };
        await new Promise<void>((resolve) => signal.addEventListener("abort", () => resolve(), { once: true }));
      })();
    });
    const ports = makePorts({ stream });
    await renderTerminal({ ports });
    fireEvent.change(screen.getByRole("combobox", { name: "Conversation" }), {
      target: { value: conversation.conversation_id },
    });
    fireEvent.change(screen.getByRole("textbox", { name: "Message" }), {
      target: { value: "cancel this stream" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Send" }));
    await screen.findByText("Cancel response");
    fireEvent.click(screen.getByRole("button", { name: "Cancel response" }));
    expect(activeSignal?.aborted).toBe(true);
  });

  it("does not enable sending under stale authentication", async () => {
    await renderTerminal({ authState: "stale" });
    fireEvent.change(screen.getByRole("textbox", { name: "Message" }), {
      target: { value: "must not send while auth is stale" },
    });
    expect((screen.getByRole("button", { name: "Send" }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("retries the same logical request with the same idempotency request_id", async () => {
    let attempts = 0;
    const requestIds: string[] = [];
    const stream: ChatClientPort["stream"] = vi.fn((request) => {
      requestIds.push(request.request_id);
      attempts += 1;
      return (async function* () {
        if (attempts === 1) throw new Error("PROVIDER_TIMEOUT");
        yield { event: "text_delta" as const, request_id: request.request_id, text_delta: "Retry result" };
      })();
    });
    const ports = makePorts({ stream });
    await renderTerminal({ ports });
    fireEvent.change(screen.getByRole("combobox", { name: "Conversation" }), {
      target: { value: conversation.conversation_id },
    });
    await waitFor(() => expect((screen.getByRole("combobox", { name: "Conversation" }) as HTMLSelectElement).value).toBe(conversation.conversation_id));
    fireEvent.change(screen.getByRole("textbox", { name: "Message" }), {
      target: { value: "retry this once" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Send" }));
    const timeoutMessages = await screen.findAllByText("The chat provider timed out.");
    expect(timeoutMessages.length).toBeGreaterThan(0);
    fireEvent.click(screen.getByRole("button", { name: "Retry last message" }));
    expect(await screen.findByText("Retry result")).toBeTruthy();
    expect(requestIds).toHaveLength(2);
    expect(requestIds[1]).toBe(requestIds[0]);
  });

  it("uses labelled keyboard-reachable controls and a polite transcript live region", async () => {
    await renderTerminal();
    expect(screen.getByRole("textbox", { name: "Message" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Send" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Compact panel" })).toBeTruthy();
    expect(screen.getByRole("log", { name: "Chat messages" }).getAttribute("aria-live")).toBe("polite");
    const input = screen.getByRole("textbox", { name: "Message" });
    input.focus();
    expect(document.activeElement).toBe(input);
  });

  it("presents supplied citations as safe links and does not make unsafe schemes clickable", () => {
    const messages: ChatMessageViewV1[] = [{
      id: "assistant-citations",
      kind: "assistant",
      text: "Evidence summary",
      citations: [
        { label: "Verified source", href: "https://example.invalid/source" },
        { label: "Unsafe source", href: "javascript:alert(1)" },
      ],
      persisted: false,
    }];
    render(
      <ChatTranscript
        messages={messages}
        toolMode="plan_then_confirm"
        registryEntries={[]}
        authEnabled
        onPrepareTool={vi.fn()}
        onConfirmTool={vi.fn()}
      />,
    );
    expect(screen.getByRole("link", { name: "Verified source" }).getAttribute("href")).toBe("https://example.invalid/source");
    expect(screen.getByText("Unsafe source").closest("a")).toBeNull();
  });

  it("does not persist prompts or approval proof to browser storage", async () => {
    const storageWrite = vi.spyOn(Storage.prototype, "setItem");
    const storageRemove = vi.spyOn(Storage.prototype, "removeItem");
    try {
      await renderTerminal({ approvalPort: { obtainApprovalProof: vi.fn(async () => "opaque-proof") } });
      expect(storageWrite).not.toHaveBeenCalled();
      expect(storageRemove).not.toHaveBeenCalled();
      expect(localStorage.length).toBe(0);
      expect(sessionStorage.length).toBe(0);
    } finally {
      storageWrite.mockRestore();
      storageRemove.mockRestore();
    }
  });
});
