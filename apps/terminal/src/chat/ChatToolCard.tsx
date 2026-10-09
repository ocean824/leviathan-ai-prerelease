import { useState } from "react";
import { formatNsTimestamp, parseProposalArguments, redactChatText, sanitizeJsonForDisplay, toolDecisionLabel } from "./chatState";
import type { ChatToolModeV1, ChatToolPlanCardV1, ChatToolProposalV1, ChatToolRegistryEntryV1, ChatToolResultV1 } from "./chatTypes";

export interface ChatToolCardProps {
  readonly proposal: ChatToolProposalV1;
  readonly registryEntry: ChatToolRegistryEntryV1 | null;
  readonly mode: ChatToolModeV1;
  readonly result: ChatToolResultV1 | null;
  readonly plan?: ChatToolPlanCardV1 | null;
  readonly authEnabled: boolean;
  readonly busy?: boolean;
  readonly onPrepare: (proposal: ChatToolProposalV1, mode: ChatToolModeV1) => void;
  readonly onConfirm: (plan: ChatToolPlanCardV1, typedConfirmation: string) => void;
}

function parseJsonValue(value: string): unknown {
  try { return JSON.parse(value) as unknown; } catch { return "[invalid result omitted]"; }
}

export function ChatToolCard({ proposal, registryEntry, mode, result, plan, authEnabled, busy = false, onPrepare, onConfirm }: ChatToolCardProps): React.JSX.Element {
  const [confirmation, setConfirmation] = useState("");
  const parsed = plan ?? result?.plan ?? null;
  const canPrepare = Boolean(registryEntry && authEnabled && !busy && !result && (!registryEntry.mutating || registryEntry.confirmation_parity === "typed_confirmation"));
  const canConfirm = Boolean(parsed && registryEntry?.mutating && registryEntry.confirmation_parity === "typed_confirmation" && mode !== "walkthrough" && authEnabled && !busy && (result?.status === "PLAN_CREATED" || result?.status === "APPROVAL_REQUIRED") && confirmation === parsed.typed_confirmation);
  const toolId = registryEntry?.tool_id ?? proposal.name;
  const resultShowsEffect = result?.status === "CONFIRMED" && result.effect_performed;
  const resultJson = result?.output_json ? sanitizeJsonForDisplay(parseJsonValue(result.output_json)) : null;
  const safeArguments = parseProposalArguments(proposal);

  return (
    <section className="chat-tool-card" aria-label={`Tool request ${redactChatText(toolId, 128)}`}>
      <header className="chat-tool-card__header">
        <div><p className="chat-eyebrow">Tool request · untrusted proposal</p><h3>{redactChatText(registryEntry?.capability ?? "Unrecognized tool", 128)}</h3></div>
        <span className={`chat-state-pill chat-state-pill--${result?.status === "DENIED" ? "danger" : "pending"}`}>{result ? toolDecisionLabel(result.status) : "Awaiting operator review"}</span>
      </header>
      <dl className="chat-tool-card__summary">
        <div><dt>Tool</dt><dd>{redactChatText(toolId, 128)}</dd></div>
        <div><dt>Route</dt><dd>{redactChatText(registryEntry?.route ?? "Not in approved catalog", 256)}</dd></div>
        <div><dt>Capability</dt><dd>{registryEntry ? (registryEntry.mutating ? "Mutation · confirmation required" : "Read only") : "Unavailable"}</dd></div>
      </dl>
      <details className="chat-tool-card__details"><summary>Review sanitized input</summary><pre>{safeArguments ? sanitizeJsonForDisplay(safeArguments) : "[invalid or unavailable input]"}</pre></details>
      {!registryEntry && <p role="status" className="chat-tool-card__notice">This tool is not listed in the server-approved registry. No request was sent.</p>}
      {registryEntry && !result && (
        <div className="chat-tool-card__actions">
          <p>{mode === "walkthrough" ? "Walk me through it: this mode cannot execute mutations. No mutation confirmation is available in this mode." : mode === "do_it_for_me" ? "Do it for me: reads may run after review. Mutations still require your typed confirmation and trusted approval." : "Review the plan. Mutations remain paused until you confirm."}</p>
          {registryEntry.confirmation_parity === "typed_confirmation_mfa" && <p role="status">This action requires an MFA adapter that is unavailable in this chat.</p>}
          <button type="button" disabled={!canPrepare} onClick={() => onPrepare(proposal, mode)}>{registryEntry.mutating ? "Prepare plan" : "Run approved read"}</button>
        </div>
      )}
      {parsed && (
        <div className="chat-tool-card__plan" aria-label="Planned action">
          <h4>Plan · no effect is claimed</h4>
          <dl>
            <div><dt>Account / environment</dt><dd>{redactChatText(parsed.account_id, 128)} / {redactChatText(parsed.environment, 64)}</dd></div>
            <div><dt>Route</dt><dd>{redactChatText(parsed.route, 256)}</dd></div>
            <div><dt>Policy</dt><dd>{redactChatText(parsed.policy_summary, 1024)} · {redactChatText(parsed.policy_revision, 64)}</dd></div>
            <div><dt>Risk</dt><dd>{redactChatText(parsed.risk_summary, 1024)}</dd></div>
            <div><dt>Expires</dt><dd>{formatNsTimestamp(parsed.expires_at_ns) ?? "Unavailable"}</dd></div>
          </dl>
          <details><summary>Normalized arguments</summary><pre>{sanitizeJsonForDisplay(parsed.normalized_arguments)}</pre></details>
          {registryEntry?.mutating && mode !== "walkthrough" && (result?.status === "PLAN_CREATED" || result?.status === "APPROVAL_REQUIRED") && (
            <div className="chat-tool-card__confirm">
              <p>Type exactly: <code>{redactChatText(parsed.typed_confirmation, 192)}</code></p>
              <label>Typed confirmation<input value={confirmation} onChange={(event) => setConfirmation(event.currentTarget.value)} autoComplete="off" /></label>
              <button type="button" disabled={!canConfirm} onClick={() => onConfirm(parsed, confirmation)}>Confirm this plan</button>
            </div>
          )}
          {(mode === "walkthrough" || !registryEntry?.mutating) && <p className="chat-tool-card__notice">No mutation confirmation is available in this mode.</p>}
        </div>
      )}
      {result && !parsed && <p role="status" className="chat-tool-card__notice">{toolDecisionLabel(result.status)}{result.reason_codes.length ? ` · ${result.reason_codes.map((code) => redactChatText(code, 64)).join(", ")}` : ""}</p>}
      {resultJson && <details className="chat-tool-card__result" open><summary>{resultShowsEffect ? "Verified route result" : "Sanitized tool response"}</summary><pre>{resultJson}</pre></details>}
      {result?.status === "CONFIRMED" && !result.effect_performed && <p role="status" className="chat-tool-card__notice">The route returned CONFIRMED without an effect receipt. No effect is claimed.</p>}
    </section>
  );
}
