import type {
  AppendMessageRequestV1,
  ChatClientPort,
  ChatHistoryMessageV1,
  ChatHistoryPort,
  ChatModelPublicV1,
  ChatRequestRecordV1,
  ChatStreamEventV1,
  ChatToolConfirmRequestV1,
  ChatToolPlanRequestV1,
  ChatToolReadRequestV1,
  ChatToolRegistryV1,
  ChatToolResultV1,
  ChatToolsPort,
  ConversationPageV1,
  ConversationV1,
  CreateConversationRequestV1,
  ListMessagesRequestV1,
  MessagePageV1,
} from "./chatTypes";

export type FetchPortV1 = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;
export type ChatServiceAreaV1 = "chat" | "history" | "tools";

const SAFE_CODES = new Set([
  "AUTH_REQUIRED", "REQUEST_INVALID", "MODEL_NOT_ALLOWED", "POLICY_DENIED", "BUDGET_EXCEEDED",
  "RATE_LIMITED", "DISCLOSURE_REQUIRED", "CREDENTIAL_UNAVAILABLE", "ENDPOINT_UNSAFE",
  "PROVIDER_UNAVAILABLE", "PROVIDER_RATE_LIMITED", "PROVIDER_TIMEOUT", "PROVIDER_INVALID_RESPONSE",
  "CANCELLED", "NOT_FOUND", "CONFLICT", "INVALID_REQUEST", "INVALID_CURSOR", "SECRET_DETECTED",
  "PAYLOAD_TOO_LARGE", "PLAN_CREATED", "READ_ALLOWED", "APPROVAL_REQUIRED", "CONFIRMED", "DENIED",
  "EXPIRED", "REPLAYED", "POLICY_CHANGED", "HALTED", "DEPENDENCY_UNAVAILABLE", "INVALID_PROPOSAL",
  "PLAN_NOT_FOUND", "EFFECT_UNAVAILABLE",
]);

export class ChatTransportError extends Error {
  readonly code: string;
  readonly area: ChatServiceAreaV1;

  constructor(area: ChatServiceAreaV1, code: string) {
    const safeCode = SAFE_CODES.has(code) ? code : "SERVICE_UNAVAILABLE";
    super(safeCode);
    this.name = "ChatTransportError";
    this.code = safeCode;
    this.area = area;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasOnlyKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  return Object.keys(value).every((key) => keys.includes(key));
}

function parseJson(text: string, area: ChatServiceAreaV1): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new ChatTransportError(area, "INVALID_RESPONSE");
  }
}

function requireRecord(value: unknown, area: ChatServiceAreaV1): Record<string, unknown> {
  if (!isRecord(value)) throw new ChatTransportError(area, "INVALID_RESPONSE");
  return value;
}

function requireString(value: unknown, area: ChatServiceAreaV1, max = 4096): string {
  if (typeof value !== "string" || value.length > max) throw new ChatTransportError(area, "INVALID_RESPONSE");
  return value;
}

function requireFiniteInt(value: unknown, area: ChatServiceAreaV1): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new ChatTransportError(area, "INVALID_RESPONSE");
  }
  return value;
}

function parseModel(value: unknown): ChatModelPublicV1 {
  const r = requireRecord(value, "chat");
  if (!hasOnlyKeys(r, ["alias", "provider", "model_version", "registry_version", "modalities", "max_context_tokens", "max_output_tokens"])) throw new ChatTransportError("chat", "INVALID_RESPONSE");
  if (!Array.isArray(r.modalities) || !r.modalities.every((item) => typeof item === "string" && item.length <= 64)) throw new ChatTransportError("chat", "INVALID_RESPONSE");
  return {
    alias: requireString(r.alias, "chat", 128),
    provider: requireString(r.provider, "chat", 128),
    model_version: requireString(r.model_version, "chat", 128),
    registry_version: requireString(r.registry_version, "chat", 128),
    modalities: r.modalities,
    max_context_tokens: requireFiniteInt(r.max_context_tokens, "chat"),
    max_output_tokens: requireFiniteInt(r.max_output_tokens, "chat"),
  };
}

function parseRequestRecord(value: unknown): ChatRequestRecordV1 {
  const record = requireRecord(value, "chat");
  const usage = requireRecord(record.usage, "chat");
  const costStatus = record.cost_status;
  if (costStatus !== "available" && costStatus !== "unavailable") throw new ChatTransportError("chat", "INVALID_RESPONSE");
  const costUsd = record.cost_usd === null ? null : requireString(record.cost_usd, "chat", 128);
  if (typeof record.hosted_egress_disclosed !== "boolean") throw new ChatTransportError("chat", "INVALID_RESPONSE");
  return {
    request_id: requireString(record.request_id, "chat", 128),
    model_alias: requireString(record.model_alias, "chat", 128),
    api_shape: requireString(record.api_shape, "chat", 64),
    registry_version: requireString(record.registry_version, "chat", 64),
    policy_version: requireString(record.policy_version, "chat", 64),
    elapsed_ns: requireFiniteInt(record.elapsed_ns, "chat"),
    usage: { input_tokens: requireFiniteInt(usage.input_tokens, "chat"), output_tokens: requireFiniteInt(usage.output_tokens, "chat") },
    cost_status: costStatus,
    cost_usd: costUsd,
    hosted_egress_disclosed: record.hosted_egress_disclosed,
  };
}

function parseChatEvent(value: unknown): ChatStreamEventV1 {
  const r = requireRecord(value, "chat");
  const requestId = requireString(r.request_id, "chat", 128);
  switch (r.event) {
    case "start": return { event: "start", request_id: requestId };
    case "text_delta": return { event: "text_delta", request_id: requestId, text_delta: requireString(r.text_delta, "chat", 16_384) };
    case "usage": {
      const usage = requireRecord(r.usage, "chat");
      return { event: "usage", request_id: requestId, usage: { input_tokens: requireFiniteInt(usage.input_tokens, "chat"), output_tokens: requireFiniteInt(usage.output_tokens, "chat") } };
    }
    case "tool_proposal": {
      const p = requireRecord(r.tool_proposal, "chat");
      return { event: "tool_proposal", request_id: requestId, tool_proposal: { name: requireString(p.name, "chat", 128), arguments_json: requireString(p.arguments_json, "chat", 8192) } };
    }
    case "finish":
      if (!["stop", "length", "tool_calls"].includes(String(r.finish_reason))) throw new ChatTransportError("chat", "INVALID_RESPONSE");
      return { event: "finish", request_id: requestId, finish_reason: r.finish_reason as "stop" | "length" | "tool_calls" };
    case "error":
      return { event: "error", request_id: requestId, error_code: requireString(r.error_code, "chat", 64) as ChatStreamEventV1 & never };
    case "record": {
      return { event: "record", request_id: requestId, record: parseRequestRecord(r.record) };
    }
    default: throw new ChatTransportError("chat", "INVALID_RESPONSE");
  }
}

function parseConversation(value: unknown): ConversationV1 {
  const r = requireRecord(value, "history");
  if (!hasOnlyKeys(r, ["conversation_id", "user_scope", "title", "model_alias", "created_at_ns", "updated_at_ns", "revision", "retention_until_ns"])) throw new ChatTransportError("history", "INVALID_RESPONSE");
  return {
    conversation_id: requireString(r.conversation_id, "history", 128),
    user_scope: requireString(r.user_scope, "history", 256),
    title: requireString(r.title, "history", 512),
    model_alias: requireString(r.model_alias, "history", 128),
    created_at_ns: requireFiniteInt(r.created_at_ns, "history"),
    updated_at_ns: requireFiniteInt(r.updated_at_ns, "history"),
    revision: requireFiniteInt(r.revision, "history"),
    retention_until_ns: requireFiniteInt(r.retention_until_ns, "history"),
  };
}

function parsePageCursor(value: unknown, area: ChatServiceAreaV1): string | null {
  if (value === null) return null;
  return requireString(value, area, 2048);
}

function parseConversationPage(value: unknown): ConversationPageV1 {
  const r = requireRecord(value, "history");
  if (!Array.isArray(r.conversations)) throw new ChatTransportError("history", "INVALID_RESPONSE");
  return { conversations: r.conversations.map(parseConversation), next_cursor: parsePageCursor(r.next_cursor, "history") };
}

function parseHistoryMessage(value: unknown): ChatHistoryMessageV1 {
  const r = requireRecord(value, "history");
  if (!hasOnlyKeys(r, ["message_id", "conversation_id", "role", "content", "created_at_ns", "provider_usage"])) throw new ChatTransportError("history", "INVALID_RESPONSE");
  if (!["user", "assistant", "tool", "system"].includes(String(r.role))) throw new ChatTransportError("history", "INVALID_RESPONSE");
  const content = requireRecord(r.content, "history");
  if (!hasOnlyKeys(content, ["text", "tool_card"]) || typeof content.text !== "string") throw new ChatTransportError("history", "INVALID_RESPONSE");
  let usage: ChatHistoryMessageV1["provider_usage"] = null;
  if (r.provider_usage !== null) {
    const u = requireRecord(r.provider_usage, "history");
    if (!hasOnlyKeys(u, ["tokens", "cost"])) throw new ChatTransportError("history", "INVALID_RESPONSE");
    usage = { tokens: requireFiniteInt(u.tokens, "history"), cost: u.cost === null ? null : requireString(u.cost, "history", 128) };
  }
  return {
    message_id: requireString(r.message_id, "history", 128), conversation_id: requireString(r.conversation_id, "history", 128),
    role: r.role as ChatHistoryMessageV1["role"], content: { text: content.text, ...(isRecord(content.tool_card) ? { tool_card: content.tool_card } : {}) },
    created_at_ns: requireFiniteInt(r.created_at_ns, "history"), provider_usage: usage,
  };
}

function parseMessagePage(value: unknown): MessagePageV1 {
  const r = requireRecord(value, "history");
  if (!Array.isArray(r.messages)) throw new ChatTransportError("history", "INVALID_RESPONSE");
  return { messages: r.messages.map(parseHistoryMessage), next_cursor: parsePageCursor(r.next_cursor, "history") };
}

function parseToolRegistry(value: unknown): ChatToolRegistryV1 {
  const r = requireRecord(value, "tools");
  if (r.version !== "1" || typeof r.revision !== "string" || !Array.isArray(r.entries)) throw new ChatTransportError("tools", "INVALID_RESPONSE");
  const entries = r.entries.map((entry) => {
    const e = requireRecord(entry, "tools");
    if (!Array.isArray(e.input_fields) || !e.input_fields.every((f) => typeof f === "string") || typeof e.mutating !== "boolean" || !["none", "typed_confirmation", "typed_confirmation_mfa"].includes(String(e.confirmation_parity))) throw new ChatTransportError("tools", "INVALID_RESPONSE");
    return { tool_id: requireString(e.tool_id, "tools", 128), capability: requireString(e.capability, "tools", 128), route: requireString(e.route, "tools", 256), input_fields: e.input_fields as string[], output_schema: requireString(e.output_schema, "tools", 128), mutating: e.mutating, confirmation_parity: e.confirmation_parity as ChatToolRegistryV1["entries"][number]["confirmation_parity"] };
  });
  const ids = entries.map((entry) => entry.tool_id);
  if (new Set(ids).size !== ids.length) throw new ChatTransportError("tools", "INVALID_RESPONSE");
  return { version: "1", revision: r.revision, entries };
}

function parseToolResult(value: unknown): ChatToolResultV1 {
  const r = requireRecord(value, "tools");
  const planValue = r.plan;
  let plan: ChatToolResultV1["plan"] = null;
  if (planValue !== null) {
    const p = requireRecord(planValue, "tools");
    if (!isRecord(p.normalized_arguments) || !Array.isArray(p.reason_codes)) throw new ChatTransportError("tools", "INVALID_RESPONSE");
    plan = {
      version: "1", plan_id: requireString(p.plan_id, "tools", 128), tool_id: requireString(p.tool_id, "tools", 128),
      normalized_arguments: p.normalized_arguments, account_id: requireString(p.account_id, "tools", 256), environment: requireString(p.environment, "tools", 64),
      policy_revision: requireString(p.policy_revision, "tools", 64), route: requireString(p.route, "tools", 256),
      policy_summary: requireString(p.policy_summary, "tools", 2048), risk_summary: requireString(p.risk_summary, "tools", 2048),
      expires_at_ns: requireFiniteInt(p.expires_at_ns, "tools"), digest: requireString(p.digest, "tools", 64),
      typed_confirmation: requireString(p.typed_confirmation, "tools", 192), status: requireString(p.status, "tools", 64) as ChatToolResultV1["status"],
      reason_codes: p.reason_codes.map((code) => requireString(code, "tools", 64)),
    };
  }
  if (!Array.isArray(r.reason_codes) || typeof r.effect_performed !== "boolean" || (r.output_json !== null && typeof r.output_json !== "string")) throw new ChatTransportError("tools", "INVALID_RESPONSE");
  return { version: "1", request_id: requireString(r.request_id, "tools", 128), tool_id: r.tool_id === null ? null : requireString(r.tool_id, "tools", 128),
    status: requireString(r.status, "tools", 64) as ChatToolResultV1["status"], reason_codes: r.reason_codes.map((code) => requireString(code, "tools", 64)),
    effect_performed: r.effect_performed, output_json: r.output_json as string | null, plan };
}

async function safeErrorCode(response: Response, area: ChatServiceAreaV1): Promise<never> {
  let code = "SERVICE_UNAVAILABLE";
  try {
    const body: unknown = await response.json();
    if (isRecord(body) && typeof body.code === "string" && SAFE_CODES.has(body.code)) code = body.code;
  } catch {
    code = response.status >= 500 ? "SERVICE_UNAVAILABLE" : "REQUEST_REJECTED";
  }
  throw new ChatTransportError(area, code);
}

function createTransport(fetcher: FetchPortV1) {
  return async (path: string, init: RequestInit, area: ChatServiceAreaV1): Promise<Response> => {
    try {
      const response = await fetcher(`/api${path}`, {
        ...init,
        credentials: "same-origin",
        cache: "no-store",
        redirect: "error",
        headers: { Accept: "application/json", "Content-Type": "application/json", ...init.headers },
      });
      if (!response.ok) return await safeErrorCode(response, area);
      return response;
    } catch (error) {
      if (error instanceof ChatTransportError) throw error;
      if (init.signal?.aborted) throw new ChatTransportError(area, "CANCELLED");
      throw new ChatTransportError(area, "SERVICE_UNAVAILABLE");
    }
  };
}

function jsonRequest(method: string, body?: unknown, signal?: AbortSignal): RequestInit {
  return { method, ...(body === undefined ? {} : { body: JSON.stringify(body) }), ...(signal ? { signal } : {}) };
}

async function responseJson(response: Response, area: ChatServiceAreaV1): Promise<unknown> {
  try { return await response.json() as unknown; } catch { throw new ChatTransportError(area, "INVALID_RESPONSE"); }
}

async function* parseSse(response: Response, requestId: string, signal: AbortSignal): AsyncIterable<ChatStreamEventV1> {
  const body = response.body;
  if (!body) throw new ChatTransportError("chat", "INVALID_RESPONSE");
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let pending = "";
  const parseFrame = (frame: string): ChatStreamEventV1 | null => {
    const data = frame.split(/\r?\n/).filter((line) => line.startsWith("data:")).map((line) => line.slice(5).trimStart()).join("\n");
    if (!data) return null;
    const event = parseChatEvent(parseJson(data, "chat"));
    if (event.request_id !== requestId) throw new ChatTransportError("chat", "INVALID_RESPONSE");
    return event;
  };
  try {
    while (true) {
      if (signal.aborted) throw new ChatTransportError("chat", "CANCELLED");
      const { done, value } = await reader.read();
      pending += decoder.decode(value, { stream: !done });
      let boundary: number;
      while ((boundary = pending.search(/\r?\n\r?\n/)) >= 0) {
        const frame = pending.slice(0, boundary);
        const delimiter = pending.slice(boundary).match(/^\r?\n\r?\n/)?.[0] ?? "\n\n";
        pending = pending.slice(boundary + delimiter.length);
        const parsed = parseFrame(frame);
        if (parsed) yield parsed;
      }
      if (done) break;
    }
    const finalEvent = parseFrame(pending);
    if (finalEvent) yield finalEvent;
  } catch (error) {
    if (error instanceof ChatTransportError) throw error;
    if (signal.aborted) throw new ChatTransportError("chat", "CANCELLED");
    throw new ChatTransportError("chat", "INVALID_RESPONSE");
  } finally {
    try { await reader.cancel(); } catch { /* response is already closed */ }
    reader.releaseLock();
  }
}

export function createChatClientsV1(fetcher: FetchPortV1 = globalThis.fetch.bind(globalThis)) {
  const transport = createTransport(fetcher);
  const chatPort: ChatClientPort = {
    async listModels(signal) {
      const response = await transport("/chat/models", jsonRequest("GET", undefined, signal), "chat");
      const data = requireRecord(await responseJson(response, "chat"), "chat");
      if (!Array.isArray(data.models)) throw new ChatTransportError("chat", "INVALID_RESPONSE");
      return data.models.map(parseModel);
    },
    async complete(request, signal) {
      const response = await transport("/chat/complete", jsonRequest("POST", { ...request, stream: false }, signal), "chat");
      const data = requireRecord(await responseJson(response, "chat"), "chat");
      if (!Array.isArray(data.events)) throw new ChatTransportError("chat", "INVALID_RESPONSE");
      const events = data.events.map(parseChatEvent);
      const recordEvent = parseRequestRecord(data.record);
      return { events, record: recordEvent };
    },
    async *stream(request, signal) {
      const response = await transport("/chat/stream", jsonRequest("POST", { ...request, stream: true }, signal), "chat");
      yield* parseSse(response, request.request_id, signal);
    },
  };

  const historyPort: ChatHistoryPort = {
    async listConversations(request, signal) {
      const query = new URLSearchParams({ limit: String(request.limit) });
      if (request.cursor) query.set("cursor", request.cursor);
      const response = await transport(`/chat/history/conversations?${query.toString()}`, jsonRequest("GET", undefined, signal), "history");
      return parseConversationPage(await responseJson(response, "history"));
    },
    async createConversation(request: CreateConversationRequestV1, signal) {
      const response = await transport("/chat/history/conversations", jsonRequest("POST", request, signal), "history");
      return parseConversation(await responseJson(response, "history"));
    },
    async listMessages(request: ListMessagesRequestV1, signal) {
      const query = new URLSearchParams({ limit: String(request.limit) });
      if (request.cursor) query.set("cursor", request.cursor);
      const response = await transport(`/chat/history/conversations/${encodeURIComponent(request.conversation_id)}/messages?${query.toString()}`, jsonRequest("GET", undefined, signal), "history");
      return parseMessagePage(await responseJson(response, "history"));
    },
    async appendMessage(request: AppendMessageRequestV1, signal) {
      const body = { message_id: request.message_id, role: request.role, content: request.content, provider_usage: request.provider_usage ?? null };
      const response = await transport(`/chat/history/conversations/${encodeURIComponent(request.conversation_id)}/messages`, jsonRequest("POST", body, signal), "history");
      return parseHistoryMessage(await responseJson(response, "history"));
    },
    async deleteConversation(conversationId, signal) {
      await transport(`/chat/history/conversations/${encodeURIComponent(conversationId)}`, jsonRequest("DELETE", undefined, signal), "history");
    },
  };

  const toolsPort: ChatToolsPort = {
    async listRegistry(signal) {
      const response = await transport("/chat/tools/registry", jsonRequest("GET", undefined, signal), "tools");
      return parseToolRegistry(await responseJson(response, "tools"));
    },
    async plan(request: ChatToolPlanRequestV1, signal) {
      const response = await transport("/chat/tools/plan", jsonRequest("POST", request, signal), "tools");
      return parseToolResult(await responseJson(response, "tools"));
    },
    async confirm(request: ChatToolConfirmRequestV1, signal) {
      const response = await transport("/chat/tools/confirm", jsonRequest("POST", request, signal), "tools");
      return parseToolResult(await responseJson(response, "tools"));
    },
    async read(request: ChatToolReadRequestV1, signal) {
      const response = await transport("/chat/tools/read", jsonRequest("POST", request, signal), "tools");
      return parseToolResult(await responseJson(response, "tools"));
    },
  };
  return { chatPort, historyPort, toolsPort };
}

export interface FakeChatPortsOptionsV1 {
  readonly models?: readonly ChatModelPublicV1[];
  readonly streamEvents?: readonly ChatStreamEventV1[];
  readonly registry?: ChatToolRegistryV1;
}

export function createFakeChatPorts(options: FakeChatPortsOptionsV1 = {}) {
  const model: ChatModelPublicV1 = options.models?.[0] ?? {
    alias: "test-model", provider: "fixture", model_version: "test-v1", registry_version: "test-registry",
    modalities: ["text"], max_context_tokens: 4096, max_output_tokens: 1024,
  };
  const conversations = new Map<string, ConversationV1>();
  const messages = new Map<string, ChatHistoryMessageV1[]>();
  let sequence = 0;
  const now = () => Date.now() * 1_000_000;
  const id = (prefix: string) => `${prefix}-${++sequence}`;
  const chatPort: ChatClientPort = {
    async listModels() { return options.models ?? [model]; },
    async complete(request) {
      const record = { request_id: request.request_id, model_alias: request.model_alias, api_shape: "fixture", registry_version: "fixture", policy_version: "fixture", elapsed_ns: 0, usage: { input_tokens: 1, output_tokens: 1 }, cost_status: "unavailable" as const, cost_usd: null, hosted_egress_disclosed: false };
      const events: ChatStreamEventV1[] = options.streamEvents ? [...options.streamEvents] : [
        { event: "start", request_id: request.request_id },
        { event: "text_delta", request_id: request.request_id, text_delta: "Fixture response" },
        { event: "finish", request_id: request.request_id, finish_reason: "stop" },
        { event: "record", request_id: request.request_id, record },
      ];
      return { events, record };
    },
    async *stream(request, signal) {
      const result = await chatPort.complete(request);
      for (const event of result.events) {
        if (signal.aborted) return;
        yield { ...event, request_id: request.request_id } as ChatStreamEventV1;
      }
    },
  };
  const historyPort: ChatHistoryPort = {
    async listConversations() { return { conversations: [...conversations.values()], next_cursor: null }; },
    async createConversation(request) {
      const timestamp = now();
      const conversation: ConversationV1 = { conversation_id: id("conversation"), user_scope: "fixture-scope", title: request.title, model_alias: request.model_alias, created_at_ns: timestamp, updated_at_ns: timestamp, revision: 1, retention_until_ns: timestamp + 90 * 86_400_000_000_000 };
      conversations.set(conversation.conversation_id, conversation);
      messages.set(conversation.conversation_id, []);
      return conversation;
    },
    async listMessages(request) { return { messages: messages.get(request.conversation_id) ?? [], next_cursor: null }; },
    async appendMessage(request: AppendMessageRequestV1) {
      const item: ChatHistoryMessageV1 = { ...request, content: request.content, provider_usage: request.provider_usage ?? null, created_at_ns: now() };
      const rows = messages.get(request.conversation_id) ?? [];
      rows.push(item);
      messages.set(request.conversation_id, rows);
      return item;
    },
    async deleteConversation(conversationId) { conversations.delete(conversationId); messages.delete(conversationId); },
  };
  const toolsPort: ChatToolsPort = {
    async listRegistry() { return options.registry ?? { version: "1", revision: "fixture", entries: [] }; },
    async plan(request) { return { version: "1", request_id: request.request_id, tool_id: request.proposal.name, status: "DENIED", reason_codes: ["FIXTURE_ONLY"], effect_performed: false, output_json: null, plan: null }; },
    async confirm(request) { return { version: "1", request_id: request.plan_id, tool_id: null, status: "DENIED", reason_codes: ["FIXTURE_ONLY"], effect_performed: false, output_json: null, plan: null }; },
    async read(request) { return { version: "1", request_id: request.request_id, tool_id: request.proposal.name, status: "DENIED", reason_codes: ["FIXTURE_ONLY"], effect_performed: false, output_json: null, plan: null }; },
  };
  return { chatPort, historyPort, toolsPort };
}

export type { AppendMessageRequestV1, ChatHistoryPort, ChatToolsPort };
