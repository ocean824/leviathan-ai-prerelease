import type { ChatErrorCodeV1, ChatToolProposalV1 } from "./chatTypes";

let localSequence = 0;
export function createRequestId(prefix: string): string {
  const random = globalThis.crypto?.randomUUID?.();
  if (random) return `${prefix}-${random}`;
  localSequence += 1;
  return `${prefix}-${Date.now().toString(36)}-${localSequence.toString(36)}`;
}

const SECRET_KEY = /(?:secret|password|passwd|credential|authorization|cookie|api[_-]?key|access[_-]?token|refresh[_-]?token|private[_-]?key|idempotency[_-]?key|plan[_-]?id)/i;
const SECRET_VALUE = /(?:\bsk_(?:live|test)_[A-Za-z0-9_-]{4,}|\bsk-[A-Za-z0-9_-]{8,}|\bBearer\s+[A-Za-z0-9._~+/-]{8,}|\bgh[pso]_[A-Za-z0-9_-]{8,}|\bAKIA[0-9A-Z]{16}\b|\bpassword\s*[:=]\s*\S+)/i;
export function redactChatText(value: string, maxLength = 4096): string {
  const bounded = Array.from(value.slice(0, maxLength)).filter((character) => {
    const point = character.codePointAt(0) ?? 0;
    return (point >= 32 && !(point >= 127 && point <= 159)) || point === 9 || point === 10 || point === 13;
  }).join("");
  if (SECRET_VALUE.test(bounded)) return "[sensitive content redacted]";
  return bounded;
}

function sanitizeValue(value: unknown, depth: number): unknown {
  if (depth > 5) return "[nested content omitted]";
  if (typeof value === "string") return redactChatText(value, 1024);
  if (typeof value === "number" || typeof value === "boolean" || value === null) return value;
  if (Array.isArray(value)) return value.slice(0, 32).map((item) => sanitizeValue(item, depth + 1));
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>).slice(0, 32);
    return Object.fromEntries(entries.filter(([key]) => !SECRET_KEY.test(key)).map(([key, item]) => [redactChatText(key, 64), sanitizeValue(item, depth + 1)]));
  }
  return "[unsupported value omitted]";
}

export function sanitizeJsonForDisplay(value: unknown): string {
  try {
    return JSON.stringify(sanitizeValue(value, 0), null, 2).slice(0, 16_384);
  } catch {
    return "[content unavailable]";
  }
}

export function parseProposalArguments(proposal: ChatToolProposalV1): Readonly<Record<string, unknown>> | null {
  try {
    const parsed: unknown = JSON.parse(proposal.arguments_json);
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return null;
    return parsed as Readonly<Record<string, unknown>>;
  } catch {
    return null;
  }
}

export function chatErrorLabel(code: ChatErrorCodeV1 | string): string {
  const labels: Record<string, string> = {
    AUTH_REQUIRED: "Sign in to use chat.",
    REQUEST_INVALID: "This chat request could not be sent.",
    MODEL_NOT_ALLOWED: "That model is not available for this account.",
    POLICY_DENIED: "Chat is unavailable under the current policy.",
    BUDGET_EXCEEDED: "The chat budget is exhausted.",
    RATE_LIMITED: "Chat is temporarily rate limited.",
    DISCLOSURE_REQUIRED: "Review the hosted-provider data notice before continuing.",
    CREDENTIAL_UNAVAILABLE: "The selected provider is unavailable.",
    ENDPOINT_UNSAFE: "The selected provider endpoint is unavailable.",
    PROVIDER_UNAVAILABLE: "The chat provider is unavailable.",
    PROVIDER_RATE_LIMITED: "The chat provider is temporarily rate limited.",
    PROVIDER_TIMEOUT: "The chat provider timed out.",
    PROVIDER_INVALID_RESPONSE: "The chat provider returned an invalid response.",
    CANCELLED: "Response cancelled.",
  };
  return labels[code] ?? "Chat service unavailable. Try again.";
}

export function toolDecisionLabel(code: string): string {
  const labels: Record<string, string> = {
    PLAN_CREATED: "Plan ready for review",
    READ_ALLOWED: "Read completed under policy",
    APPROVAL_REQUIRED: "Typed confirmation is required",
    CONFIRMED: "Confirmed result received",
    DENIED: "Tool request denied",
    EXPIRED: "Plan expired",
    REPLAYED: "This confirmation was already used",
    POLICY_CHANGED: "Policy changed; create a new plan",
    HALTED: "Action blocked while the system is halted",
    DEPENDENCY_UNAVAILABLE: "Required tool service is unavailable",
    INVALID_PROPOSAL: "The proposed tool input is invalid",
    PLAN_NOT_FOUND: "The plan is no longer available",
    EFFECT_UNAVAILABLE: "The requested effect was not performed",
  };
  return labels[code] ?? "Tool result unavailable";
}

export function formatNsTimestamp(value: number | undefined): string | null {
  if (value === undefined || !Number.isSafeInteger(value) || value < 0) return null;
  const milliseconds = Math.floor(value / 1_000_000);
  const date = new Date(milliseconds);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}
