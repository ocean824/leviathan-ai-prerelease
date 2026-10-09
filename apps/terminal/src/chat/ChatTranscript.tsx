import { formatNsTimestamp, redactChatText } from "./chatState";
import { ChatToolCard } from "./ChatToolCard";
import type {
  ChatMessageViewV1,
  ChatToolModeV1,
  ChatToolPlanCardV1,
  ChatToolRegistryEntryV1,
} from "./chatTypes";

export interface ChatTranscriptProps {
  readonly messages: readonly ChatMessageViewV1[];
  readonly streamingText?: string;
  readonly streaming?: boolean;
  readonly toolMode: ChatToolModeV1;
  readonly registryEntries: readonly ChatToolRegistryEntryV1[];
  readonly authEnabled: boolean;
  readonly busyToolId?: string | null;
  readonly onPrepareTool: (proposal: NonNullable<ChatMessageViewV1["proposal"]>, mode: ChatToolModeV1, messageId: string) => void;
  readonly onConfirmTool: (plan: ChatToolPlanCardV1, typedConfirmation: string, messageId: string) => void;
}

function citationHref(value: string | undefined): string | null {
  if (!value) return null;
  try {
    const url = new URL(value);
    return url.protocol === "https:" || url.protocol === "http:" ? url.toString() : null;
  } catch {
    return null;
  }
}

export function ChatTranscript({
  messages,
  streamingText = "",
  streaming = false,
  toolMode,
  registryEntries,
  authEnabled,
  busyToolId = null,
  onPrepareTool,
  onConfirmTool,
}: ChatTranscriptProps): React.JSX.Element {
  return (
    <section className="chat-transcript" aria-label="Conversation transcript">
      {messages.length === 0 && !streamingText && (
        <div className="chat-transcript__empty" role="status">
          <p className="chat-eyebrow">READY WHEN YOU ARE</p>
          <h2>Start a conversation</h2>
          <p>Your unsent draft stays in memory on this screen. It is not part of account history until sent.</p>
        </div>
      )}
      <ol className="chat-transcript__events" role="log" aria-live="polite" aria-relevant="additions text" aria-label="Chat messages">
        {messages.map((message) => {
          if (message.kind === "tool" && message.proposal) {
            const toolId = registryEntries.find((entry) => entry.tool_id === message.proposal?.name)?.tool_id ?? message.proposal.name;
            const registryEntry = registryEntries.find((entry) => entry.tool_id === toolId) ?? null;
            return (
              <li key={message.id} className="chat-transcript__event chat-transcript__event--tool">
                <ChatToolCard
                  proposal={message.proposal}
                  registryEntry={registryEntry}
                  mode={toolMode}
                  result={message.toolResult ?? null}
                  plan={message.toolPlan ?? null}
                  authEnabled={authEnabled}
                  busy={busyToolId === message.id}
                  onPrepare={(proposal, mode) => onPrepareTool(proposal, mode, message.id)}
                  onConfirm={(plan, typed) => onConfirmTool(plan, typed, message.id)}
                />
              </li>
            );
          }
          const label = message.kind === "user" ? "You" : message.kind === "assistant" ? "Assistant" : message.kind === "approval" ? "Approval" : message.kind === "error" ? "Service status" : "Tool";
          const stamp = formatNsTimestamp(message.timestampNs);
          return (
            <li key={message.id} className={`chat-transcript__event chat-transcript__event--${message.kind}`}>
              <article aria-label={`${label} message`}>
                <header className="chat-transcript__message-head">
                  <strong>{label}</strong>
                  {stamp && <time dateTime={stamp}>{stamp}</time>}
                  <span className="chat-transcript__persisted">{message.persisted ? "Saved to account history" : "Not saved to account history"}</span>
                </header>
                <p className="chat-transcript__message-text">{redactChatText(message.text, 32_768)}</p>
                {message.citations && message.citations.length > 0 && (
                  <ul className="chat-transcript__citations" aria-label="Sources">
                    {message.citations.map((citation, index) => {
                      const href = citationHref(citation.href);
                      const labelText = redactChatText(citation.label, 128);
                      return <li key={`${message.id}-source-${index}`}>{href ? <a href={href} target="_blank" rel="noreferrer">{labelText}</a> : <span>{labelText}</span>}</li>;
                    })}
                  </ul>
                )}
              </article>
            </li>
          );
        })}
        {streaming && streamingText && (
          <li className="chat-transcript__event chat-transcript__event--assistant chat-transcript__event--streaming">
            <article aria-label="Assistant response in progress">
              <header className="chat-transcript__message-head"><strong>Assistant</strong><span>Response in progress · not saved yet</span></header>
              <p className="chat-transcript__message-text">{redactChatText(streamingText, 32_768)}</p>
            </article>
          </li>
        )}
      </ol>
      <p className="chat-transcript__live" role="status" aria-live="polite" aria-atomic="true">
        {streaming ? "Assistant is responding. New text will appear in the transcript." : ""}
      </p>
    </section>
  );
}
