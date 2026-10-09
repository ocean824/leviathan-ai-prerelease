export type ChatRoleV1 = "system" | "user" | "assistant";
export type ChatHistoryRoleV1 = ChatRoleV1 | "tool";

export interface ChatModelMessageV1 {
  readonly role: ChatRoleV1;
  readonly content: string;
}

export interface ChatRequestV1 {
  readonly request_id: string;
  readonly model_alias: string;
  readonly messages: readonly ChatModelMessageV1[];
  readonly max_output_tokens: number;
  readonly stream: boolean;
  readonly hosted_egress_disclosed: boolean;
}

export interface ChatUsageV1 {
  readonly input_tokens: number;
  readonly output_tokens: number;
}

export type ChatErrorCodeV1 =
  | "AUTH_REQUIRED"
  | "REQUEST_INVALID"
  | "MODEL_NOT_ALLOWED"
  | "POLICY_DENIED"
  | "BUDGET_EXCEEDED"
  | "RATE_LIMITED"
  | "DISCLOSURE_REQUIRED"
  | "CREDENTIAL_UNAVAILABLE"
  | "ENDPOINT_UNSAFE"
  | "PROVIDER_UNAVAILABLE"
  | "PROVIDER_RATE_LIMITED"
  | "PROVIDER_TIMEOUT"
  | "PROVIDER_INVALID_RESPONSE"
  | "CANCELLED";

export interface ChatToolProposalV1 {
  readonly name: string;
  readonly arguments_json: string;
}

export interface ChatRequestRecordV1 {
  readonly request_id: string;
  readonly model_alias: string;
  readonly api_shape: string;
  readonly registry_version: string;
  readonly policy_version: string;
  readonly elapsed_ns: number;
  readonly usage: ChatUsageV1;
  readonly cost_status: "available" | "unavailable";
  readonly cost_usd: string | null;
  readonly hosted_egress_disclosed: boolean;
}

export type ChatStreamEventV1 =
  | { readonly event: "start"; readonly request_id: string }
  | { readonly event: "text_delta"; readonly request_id: string; readonly text_delta: string }
  | { readonly event: "usage"; readonly request_id: string; readonly usage: ChatUsageV1 }
  | {
      readonly event: "tool_proposal";
      readonly request_id: string;
      readonly tool_proposal: ChatToolProposalV1;
    }
  | {
      readonly event: "finish";
      readonly request_id: string;
      readonly finish_reason: "stop" | "length" | "tool_calls";
    }
  | { readonly event: "error"; readonly request_id: string; readonly error_code: ChatErrorCodeV1 }
  | { readonly event: "record"; readonly request_id: string; readonly record: ChatRequestRecordV1 };

export interface ChatResultV1 {
  readonly events: readonly ChatStreamEventV1[];
  readonly record: ChatRequestRecordV1;
}

export interface ChatModelPublicV1 {
  readonly alias: string;
  readonly provider: string;
  readonly model_version: string;
  readonly registry_version: string;
  readonly modalities: readonly string[];
  readonly max_context_tokens: number;
  readonly max_output_tokens: number;
}

export interface ConversationV1 {
  readonly conversation_id: string;
  readonly user_scope: string;
  readonly title: string;
  readonly model_alias: string;
  readonly created_at_ns: number;
  readonly updated_at_ns: number;
  readonly revision: number;
  readonly retention_until_ns: number;
}

export interface ChatHistoryContentV1 {
  readonly text: string;
  readonly tool_card?: Readonly<Record<string, unknown>>;
}

export interface ChatHistoryMessageV1 {
  readonly message_id: string;
  readonly conversation_id: string;
  readonly role: ChatHistoryRoleV1;
  readonly content: ChatHistoryContentV1;
  readonly created_at_ns: number;
  readonly provider_usage: Readonly<{ tokens: number; cost: string | null }> | null;
}

export interface ConversationPageV1 {
  readonly conversations: readonly ConversationV1[];
  readonly next_cursor: string | null;
}

export interface MessagePageV1 {
  readonly messages: readonly ChatHistoryMessageV1[];
  readonly next_cursor: string | null;
}

export interface ListPageRequestV1 {
  readonly limit: number;
  readonly cursor?: string;
}

export interface CreateConversationRequestV1 {
  readonly title: string;
  readonly model_alias: string;
}

export interface ListMessagesRequestV1 extends ListPageRequestV1 {
  readonly conversation_id: string;
}

export interface AppendMessageRequestV1 {
  readonly conversation_id: string;
  readonly message_id: string;
  readonly role: Exclude<ChatHistoryRoleV1, "system">;
  readonly content: ChatHistoryContentV1;
  readonly provider_usage?: Readonly<{ tokens: number; cost: string | null }> | null;
}

export type ChatToolModeV1 = "plan_then_confirm" | "walkthrough" | "do_it_for_me";
export type ChatToolDecisionCodeV1 =
  | "PLAN_CREATED"
  | "READ_ALLOWED"
  | "APPROVAL_REQUIRED"
  | "CONFIRMED"
  | "DENIED"
  | "EXPIRED"
  | "REPLAYED"
  | "POLICY_CHANGED"
  | "HALTED"
  | "DEPENDENCY_UNAVAILABLE"
  | "INVALID_PROPOSAL"
  | "PLAN_NOT_FOUND"
  | "EFFECT_UNAVAILABLE";

export interface ChatToolRegistryEntryV1 {
  readonly tool_id: string;
  readonly capability: string;
  readonly route: string;
  readonly input_fields: readonly string[];
  readonly output_schema: string;
  readonly mutating: boolean;
  readonly confirmation_parity: "none" | "typed_confirmation" | "typed_confirmation_mfa";
}

export interface ChatToolRegistryV1 {
  readonly version: "1";
  readonly revision: string;
  readonly entries: readonly ChatToolRegistryEntryV1[];
}

export interface ChatToolPlanRequestV1 {
  readonly version: "1";
  readonly request_id: string;
  readonly proposal: ChatToolProposalV1;
  readonly mode: ChatToolModeV1;
}

export interface ChatToolConfirmRequestV1 {
  readonly version: "1";
  readonly plan_id: string;
  readonly digest: string;
  readonly typed_confirmation: string;
  readonly approval_proof: string;
  readonly idempotency_key: string;
}

export interface ChatToolReadRequestV1 {
  readonly version: "1";
  readonly request_id: string;
  readonly proposal: ChatToolProposalV1;
}

export interface ChatToolPlanCardV1 {
  readonly version: "1";
  readonly plan_id: string;
  readonly tool_id: string;
  readonly normalized_arguments: Readonly<Record<string, unknown>>;
  readonly account_id: string;
  readonly environment: string;
  readonly policy_revision: string;
  readonly route: string;
  readonly policy_summary: string;
  readonly risk_summary: string;
  readonly expires_at_ns: number;
  readonly digest: string;
  readonly typed_confirmation: string;
  readonly status: ChatToolDecisionCodeV1;
  readonly reason_codes: readonly string[];
}

export interface ChatToolResultV1 {
  readonly version: "1";
  readonly request_id: string;
  readonly tool_id: string | null;
  readonly status: ChatToolDecisionCodeV1;
  readonly reason_codes: readonly string[];
  readonly effect_performed: boolean;
  readonly output_json: string | null;
  readonly plan: ChatToolPlanCardV1 | null;
}

export interface ChatClientPort {
  listModels(signal?: AbortSignal): Promise<readonly ChatModelPublicV1[]>;
  complete(request: ChatRequestV1, signal?: AbortSignal): Promise<ChatResultV1>;
  stream(request: ChatRequestV1, signal: AbortSignal): AsyncIterable<ChatStreamEventV1>;
}

export interface ChatHistoryPort {
  listConversations(request: ListPageRequestV1, signal?: AbortSignal): Promise<ConversationPageV1>;
  createConversation(
    request: CreateConversationRequestV1,
    signal?: AbortSignal,
  ): Promise<ConversationV1>;
  listMessages(request: ListMessagesRequestV1, signal?: AbortSignal): Promise<MessagePageV1>;
  appendMessage(request: AppendMessageRequestV1, signal?: AbortSignal): Promise<ChatHistoryMessageV1>;
  deleteConversation(conversationId: string, signal?: AbortSignal): Promise<void>;
}

export interface ChatToolsPort {
  listRegistry(signal?: AbortSignal): Promise<ChatToolRegistryV1>;
  plan(request: ChatToolPlanRequestV1, signal?: AbortSignal): Promise<ChatToolResultV1>;
  confirm(request: ChatToolConfirmRequestV1, signal?: AbortSignal): Promise<ChatToolResultV1>;
  read(request: ChatToolReadRequestV1, signal?: AbortSignal): Promise<ChatToolResultV1>;
}

export interface ChatApprovalRequestV1 {
  readonly plan_id: string;
  readonly digest: string;
  readonly typed_confirmation: string;
}

/** Trusted SEC-004 adapter. The UI never creates or retains approval evidence. */
export interface ChatToolApprovalPort {
  obtainApprovalProof(request: ChatApprovalRequestV1): Promise<string | null>;
}

export type ChatAuthStateV1 = "fresh" | "stale" | "unavailable" | "signed-out";
export type ChatViewModeV1 = "compact" | "expanded";
export type ChatInteractionModeV1 = ChatToolModeV1;

export interface ChatCitationV1 {
  readonly label: string;
  readonly href?: string;
}

export type ChatMessageViewKindV1 = "user" | "assistant" | "tool" | "approval" | "error";

export interface ChatMessageViewV1 {
  readonly id: string;
  readonly kind: ChatMessageViewKindV1;
  readonly text: string;
  readonly timestampNs?: number;
  readonly citations?: readonly ChatCitationV1[];
  readonly proposal?: ChatToolProposalV1;
  readonly toolResult?: ChatToolResultV1;
  readonly toolPlan?: ChatToolPlanCardV1;
  readonly persisted: boolean;
}
