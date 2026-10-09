import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ChatTranscript } from "./ChatTranscript";
import { chatErrorLabel, createRequestId, redactChatText } from "./chatState";
import type { ChatAuthStateV1, ChatHistoryMessageV1, ChatInteractionModeV1, ChatMessageViewV1, ChatModelPublicV1, ChatToolPlanCardV1, ChatToolProposalV1, ChatToolRegistryEntryV1, ChatToolResultV1, ChatViewModeV1, ConversationV1 } from "./chatTypes";
import type { ChatApprovalRequestV1, ChatClientPort, ChatHistoryPort, ChatToolApprovalPort, ChatToolModeV1, ChatToolsPort } from "./chatTypes";
import "./ChatTerminal.css";

export interface ChatTerminalProps {
  readonly accountScopeKey: string;
  readonly authState: ChatAuthStateV1;
  readonly chatPort: ChatClientPort;
  readonly historyPort: ChatHistoryPort;
  readonly toolsPort: ChatToolsPort;
  readonly approvalPort?: ChatToolApprovalPort;
  readonly initialViewMode?: ChatViewModeV1;
  readonly onViewModeChange?: (mode: ChatViewModeV1) => void;
}

type DataState = "loading" | "fresh" | "stale" | "offline" | "error";

function toViewMessage(message: ChatHistoryMessageV1): ChatMessageViewV1 {
  const kind: ChatMessageViewV1["kind"] = message.role === "user" ? "user" : message.role === "tool" ? "tool" : "assistant";
  return { id: message.message_id, kind, text: message.content.text, timestampNs: message.created_at_ns, persisted: true };
}

function safeTitle(value: string): string {
  const title = redactChatText(value.trim().replace(/\s+/g, " "), 80);
  return title || "New conversation";
}

function makeContent(text: string): string {
  return text.slice(0, 32_768);
}

export function ChatTerminal({ accountScopeKey, authState, chatPort, historyPort, toolsPort, approvalPort, initialViewMode = "expanded", onViewModeChange }: ChatTerminalProps): React.JSX.Element {
  const [models, setModels] = useState<readonly ChatModelPublicV1[]>([]);
  const [selectedModel, setSelectedModel] = useState("");
  const [conversations, setConversations] = useState<readonly ConversationV1[]>([]);
  const [conversationId, setConversationId] = useState<string | null>(null);
  const [messages, setMessages] = useState<readonly ChatMessageViewV1[]>([]);
  const [draft, setDraft] = useState("");
  const [hostedEgressDisclosed, setHostedEgressDisclosed] = useState(false);
  const [dataState, setDataState] = useState<DataState>("loading");
  const [error, setError] = useState("");
  const [viewMode, setViewMode] = useState<ChatViewModeV1>(initialViewMode);
  const [toolMode, setToolMode] = useState<ChatInteractionModeV1>("plan_then_confirm");
  const [registry, setRegistry] = useState<readonly ChatToolRegistryEntryV1[]>([]);
  const [streaming, setStreaming] = useState(false);
  const [streamingText, setStreamingText] = useState("");
  const [usageLabel, setUsageLabel] = useState("Usage unavailable");
  const [lastRequest, setLastRequest] = useState<string | null>(null);
  const [lastRequestId, setLastRequestId] = useState<string | null>(null);
  const [lastUserMessageId, setLastUserMessageId] = useState<string | null>(null);
  const [lastUserMessagePersisted, setLastUserMessagePersisted] = useState(false);
  const [busyToolId, setBusyToolId] = useState<string | null>(null);
  const [accountEpoch, setAccountEpoch] = useState(0);
  const streamAbort = useRef<AbortController | null>(null);
  const accountRef = useRef(accountScopeKey);
  const skipHistoryLoadFor = useRef<string | null>(null);
  const isSignedIn = authState === "fresh" || authState === "stale";
  const authEnabled = authState === "fresh" && dataState !== "offline" && dataState !== "error";
  const authLabel = authState === "fresh" ? "Signed in · session current" : authState === "stale" ? "Signed in · session may be stale" : authState === "signed-out" ? "Signed out" : "Authentication unavailable";

  const cancelStream = useCallback(() => {
    streamAbort.current?.abort();
    streamAbort.current = null;
    setStreaming(false);
  }, []);

  useEffect(() => {
    if (accountRef.current === accountScopeKey) return;
    accountRef.current = accountScopeKey;
    cancelStream();
    setAccountEpoch((value) => value + 1);
    setDraft(""); setHostedEgressDisclosed(false); setMessages([]); setConversations([]); setConversationId(null); setModels([]); setSelectedModel("");
    setStreamingText(""); setLastRequest(null); setLastRequestId(null); setLastUserMessageId(null); setLastUserMessagePersisted(false); setError(""); setRegistry([]); setUsageLabel("Usage unavailable");
  }, [accountScopeKey, cancelStream]);

  useEffect(() => {
    if (!isSignedIn) {
      cancelStream(); setModels([]); setSelectedModel(""); setConversations([]); setMessages([]); setConversationId(null); setDraft(""); setHostedEgressDisclosed(false); setLastRequest(null); setLastRequestId(null); setLastUserMessageId(null); setLastUserMessagePersisted(false); setRegistry([]);
      setDataState(authState === "signed-out" ? "offline" : "error");
      setError(authState === "signed-out" ? "Sign in to use chat." : "Authentication is unavailable. Chat history and models are not loaded.");
      return;
    }
    const controller = new AbortController();
    setDataState("loading"); setError("");
    void Promise.all([chatPort.listModels(controller.signal), historyPort.listConversations({ limit: 50 }, controller.signal), toolsPort.listRegistry(controller.signal)])
      .then(([availableModels, page, toolRegistry]) => {
        if (controller.signal.aborted) return;
        setModels(availableModels); setSelectedModel((current) => availableModels.some((model) => model.alias === current) ? current : (availableModels[0]?.alias ?? ""));
        setConversations(page.conversations); setRegistry(toolRegistry.entries); setDataState(authState === "stale" ? "stale" : "fresh");
      })
      .catch(() => { if (!controller.signal.aborted) { setDataState("offline"); setError("Chat services are unavailable. Retry to load account history and models."); } });
    return () => controller.abort();
  }, [accountEpoch, authState, cancelStream, chatPort, historyPort, isSignedIn, toolsPort]);

  useEffect(() => {
    if (!conversationId || !isSignedIn) { setMessages([]); return; }
    if (skipHistoryLoadFor.current === conversationId) { skipHistoryLoadFor.current = null; return; }
    const controller = new AbortController();
    setMessages([]);
    void historyPort.listMessages({ conversation_id: conversationId, limit: 100 }, controller.signal)
      .then((page) => { if (!controller.signal.aborted) setMessages(page.messages.map(toViewMessage)); })
      .catch(() => { if (!controller.signal.aborted) setError("Conversation history is unavailable. Your unsent draft remains in memory."); });
    return () => controller.abort();
  }, [conversationId, historyPort, isSignedIn]);

  useEffect(() => () => { streamAbort.current?.abort(); }, []);

  const conversationOptions = useMemo(() => conversations.map((conversation) => (
    <option key={conversation.conversation_id} value={conversation.conversation_id}>{redactChatText(conversation.title, 80)}</option>
  )), [conversations]);

  const appendPersisted = useCallback(async (id: string, role: "user" | "assistant", text: string, usage?: { tokens: number; cost: string | null } | null) => {
    const persisted = await historyPort.appendMessage({ conversation_id: id, message_id: createRequestId("message"), role, content: { text: makeContent(text) }, provider_usage: usage ?? null });
    const viewMessage = toViewMessage(persisted);
    setMessages((current) => {
      const optimisticIndex = current.findIndex((item) => !item.persisted && item.kind === role && item.text === text);
      if (optimisticIndex < 0) return [...current.filter((item) => item.id !== viewMessage.id), viewMessage];
      return current.map((item, index) => index === optimisticIndex ? viewMessage : item);
    });
  }, [historyPort]);

  const submit = useCallback(async (text = draft, retryRequestId?: string) => {
    const prompt = text.trim();
    if (!prompt || !selectedModel || !authEnabled || streaming) return;
    cancelStream(); setError(""); setStreamingText(""); setStreaming(true); setUsageLabel("Usage unavailable");
    const controller = new AbortController(); streamAbort.current = controller;
    let activeConversation = conversationId;
    const requestId = retryRequestId ?? createRequestId("chat");
    setLastRequestId(requestId);
    const userMessageId = retryRequestId && lastUserMessageId ? lastUserMessageId : createRequestId("message");
    if (!retryRequestId) {
      const userMessage: ChatMessageViewV1 = { id: userMessageId, kind: "user", text: makeContent(prompt), timestampNs: Date.now() * 1_000_000, persisted: false };
      setMessages((current) => [...current, userMessage]);
      setLastUserMessageId(userMessageId);
      setLastUserMessagePersisted(false);
    }
    setDraft(""); setLastRequest(prompt);
    try {
      if (!activeConversation) {
        const created = await historyPort.createConversation({ title: safeTitle(prompt), model_alias: selectedModel }, controller.signal);
        activeConversation = created.conversation_id; skipHistoryLoadFor.current = activeConversation; setConversationId(activeConversation); setConversations((current) => [created, ...current]);
      }
      if (!retryRequestId || !lastUserMessagePersisted) {
        await historyPort.appendMessage({ conversation_id: activeConversation, message_id: userMessageId, role: "user", content: { text: makeContent(prompt) }, provider_usage: null }, controller.signal);
        setLastUserMessagePersisted(true);
        setMessages((current) => current.map((message) => message.id === userMessageId ? { ...message, persisted: true } : message));
      }
      const priorMessages = messages.filter((message) => message.kind === "user" || message.kind === "assistant").slice(-40).map((message) => ({ role: message.kind as "user" | "assistant", content: makeContent(message.text) }));
      const request = { request_id: requestId, model_alias: selectedModel, messages: [...priorMessages, { role: "user" as const, content: prompt }], max_output_tokens: models.find((model) => model.alias === selectedModel)?.max_output_tokens ?? 1024, stream: true, hosted_egress_disclosed: hostedEgressDisclosed };
      let answer = "";
      let record: import("./chatTypes").ChatRequestRecordV1 | null = null;
      for await (const event of chatPort.stream(request, controller.signal)) {
        if (event.event === "text_delta") { answer += event.text_delta; setStreamingText(answer); }
        else if (event.event === "tool_proposal") {
          const proposal = event.tool_proposal;
          setMessages((current) => [...current, { id: createRequestId("proposal"), kind: "tool", text: "Tool proposal requires review.", proposal, persisted: false }]);
        } else if (event.event === "error") throw new Error(event.error_code);
        else if (event.event === "record") record = event.record;
      }
      if (controller.signal.aborted) return;
      if (answer) {
        setMessages((current) => [...current, { id: createRequestId("assistant"), kind: "assistant", text: answer, timestampNs: Date.now() * 1_000_000, persisted: false }]);
        if (record) await appendPersisted(activeConversation, "assistant", answer, { tokens: record.usage.input_tokens + record.usage.output_tokens, cost: record.cost_status === "available" ? record.cost_usd : null });
      }
      if (record) setUsageLabel(record.cost_status === "available" && record.cost_usd !== null ? `${record.usage.input_tokens + record.usage.output_tokens} tokens · $${record.cost_usd}` : `${record.usage.input_tokens + record.usage.output_tokens} tokens · cost unavailable`);
    } catch (caught) {
      if (!controller.signal.aborted) {
        const code = caught instanceof Error ? caught.message : "SERVICE_UNAVAILABLE";
        const label = chatErrorLabel(code);
        setError(label); setMessages((current) => [...current, { id: createRequestId("error"), kind: "error", text: label, persisted: false }]);
      }
    } finally {
      if (streamAbort.current === controller) streamAbort.current = null;
      setStreaming(false); setStreamingText("");
    }
  }, [appendPersisted, authEnabled, cancelStream, chatPort, conversationId, draft, hostedEgressDisclosed, historyPort, lastUserMessageId, lastUserMessagePersisted, messages, models, selectedModel, streaming]);

  const retry = () => { if (lastRequest) void submit(lastRequest, lastRequestId ?? undefined); };

  const prepareTool = useCallback(async (proposal: ChatToolProposalV1, mode: ChatToolModeV1, messageId: string) => {
    const entry = registry.find((candidate) => candidate.tool_id === proposal.name);
    if (!entry || !authEnabled || (entry.mutating && entry.confirmation_parity !== "typed_confirmation")) return;
    setBusyToolId(messageId); setError("");
    try {
      let result: ChatToolResultV1;
      if (entry.mutating) {
        result = await toolsPort.plan({ version: "1", request_id: createRequestId("tool-plan"), proposal, mode });
      } else {
        result = await toolsPort.read({ version: "1", request_id: createRequestId("tool-read"), proposal });
      }
      setMessages((current) => current.map((message) => message.id === messageId ? { ...message, toolResult: result, toolPlan: result.plan ?? undefined } : message));
    } catch { setError("The tool service is unavailable. No effect is claimed."); }
    finally { setBusyToolId(null); }
  }, [authEnabled, registry, toolsPort]);

  const confirmTool = useCallback(async (plan: ChatToolPlanCardV1, typedConfirmation: string, messageId: string) => {
    if (!approvalPort || !authEnabled || !typedConfirmation || typedConfirmation !== plan.typed_confirmation) return;
    const entry = registry.find((candidate) => candidate.tool_id === plan.tool_id);
    if (!entry?.mutating || entry.confirmation_parity !== "typed_confirmation" || toolMode === "walkthrough") return;
    setBusyToolId(messageId); setError("");
    try {
      const approvalRequest: ChatApprovalRequestV1 = { plan_id: plan.plan_id, digest: plan.digest, typed_confirmation: typedConfirmation };
      const approvalProof = await approvalPort.obtainApprovalProof(approvalRequest);
      if (!approvalProof || typeof approvalProof !== "string") { setError("Trusted approval is unavailable. No action was confirmed."); return; }
      const result = await toolsPort.confirm({ version: "1", plan_id: plan.plan_id, digest: plan.digest, typed_confirmation: typedConfirmation, approval_proof: approvalProof, idempotency_key: createRequestId("confirm") });
      setMessages((current) => current.map((message) => message.id === messageId ? { ...message, toolResult: result, toolPlan: result.plan ?? plan } : message));
    } catch { setError("The confirmation service is unavailable. No effect is claimed."); }
    finally { setBusyToolId(null); }
  }, [approvalPort, authEnabled, registry, toolMode, toolsPort]);

  const changeView = (mode: ChatViewModeV1) => { setViewMode(mode); onViewModeChange?.(mode); };

  return (
    <section className={`chat-terminal chat-terminal--${viewMode}`} aria-label="Chat terminal">
      <header className="chat-terminal__header">
        <div><p className="chat-eyebrow">CHAT</p><h1>Assistant terminal</h1><span className={`chat-terminal__auth chat-terminal__auth--${authState}`}>{authLabel}</span></div>
        <div className="chat-terminal__header-actions">
          <button type="button" aria-pressed={viewMode === "compact"} onClick={() => changeView(viewMode === "compact" ? "expanded" : "compact")}>{viewMode === "compact" ? "Expand panel" : "Compact panel"}</button>
          <button type="button" onClick={() => { setConversationId(null); setMessages([]); setDraft(""); setLastRequest(null); setLastRequestId(null); setLastUserMessageId(null); setLastUserMessagePersisted(false); }}>New chat</button>
        </div>
      </header>
      <div className="chat-terminal__toolbar">
        <label>Conversation<select value={conversationId ?? ""} onChange={(event) => setConversationId(event.currentTarget.value || null)} disabled={!authEnabled}><option value="">New conversation</option>{conversationOptions}</select></label>
        <label>Model<select value={selectedModel} onChange={(event) => setSelectedModel(event.currentTarget.value)} disabled={!models.length || !authEnabled}><option value="">No server models available</option>{models.map((model) => <option key={model.alias} value={model.alias}>{model.alias} · {model.provider}</option>)}</select></label>
        <label>Interaction<select value={toolMode} onChange={(event) => setToolMode(event.currentTarget.value as ChatInteractionModeV1)}><option value="plan_then_confirm">Plan then confirm</option><option value="walkthrough">Walk me through it · no mutations</option><option value="do_it_for_me">Do it for me</option></select></label>
      </div>
      <label className="chat-terminal__disclosure"><input type="checkbox" checked={hostedEgressDisclosed} onChange={(event) => setHostedEgressDisclosed(event.currentTarget.checked)} disabled={!authEnabled || streaming} />I understand prompts may be sent to a hosted provider</label>
      <div className="chat-terminal__status" role="status"><span>History: {dataState === "fresh" ? "available" : dataState === "stale" ? "available · session may be stale" : dataState === "loading" ? "loading" : "unavailable"}</span><span>{usageLabel}</span></div>
      {error && <div className="chat-terminal__error" role="alert"><p>{error}</p><button type="button" onClick={() => { setError(""); setAccountEpoch((value) => value + 1); }}>Retry</button>{lastRequest && <button type="button" onClick={retry} disabled={!authEnabled}>Retry last message</button>}</div>}
      <ChatTranscript messages={messages} streaming={streaming} streamingText={streamingText} toolMode={toolMode} registryEntries={registry} authEnabled={authEnabled} busyToolId={busyToolId} onPrepareTool={prepareTool} onConfirmTool={confirmTool} />
      {streaming && <div className="chat-terminal__stream-actions"><span>Generating response…</span><button type="button" onClick={cancelStream}>Cancel response</button></div>}
      <form className="chat-terminal__composer" onSubmit={(event) => { event.preventDefault(); void submit(); }}>
        <label htmlFor="chat-terminal-draft">Message</label>
        <textarea id="chat-terminal-draft" value={draft} onChange={(event) => setDraft(event.currentTarget.value)} rows={4} maxLength={32_768} placeholder="Ask a question…" disabled={!authEnabled || streaming} />
        <div className="chat-terminal__composer-footer"><span>Draft is in memory only · {draft.length}/32768</span><button type="submit" disabled={!authEnabled || !selectedModel || !draft.trim() || streaming}>Send</button></div>
      </form>
      {authState === "signed-out" && <p className="chat-terminal__signed-out" role="status">Sign out clears this chat draft and conversation view. No prompt is stored in this browser.</p>}
    </section>
  );
}
