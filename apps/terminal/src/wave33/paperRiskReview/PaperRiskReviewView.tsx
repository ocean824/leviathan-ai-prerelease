import { useEffect, useId, useRef, useState, type KeyboardEvent } from "react";
import {
  assessPaperRisk,
  PaperRiskAssessmentError,
  type PaperRiskAssessment,
  type PaperRiskAssessmentErrorCode,
  type PaperRiskAssessmentRequest,
  type PaperRiskReasonCode,
} from "./api";

export interface PaperRiskReviewViewProps {
  readonly open: boolean;
  readonly request: PaperRiskAssessmentRequest;
  readonly onClose: () => void;
  readonly onSubmit: (request: PaperRiskAssessmentRequest) => void | Promise<void>;
}

type ReviewState =
  | { readonly status: "loading" }
  | { readonly status: "allowed"; readonly assessment: PaperRiskAssessment }
  | { readonly status: "denied"; readonly assessment: PaperRiskAssessment }
  | { readonly status: "error"; readonly code: PaperRiskAssessmentErrorCode };

const REASON_LABELS: Partial<Record<PaperRiskReasonCode, string>> = {
  as_of_invalid: "The assessment timestamp is invalid.",
  policy_unverified: "The risk policy could not be verified.",
  policy_tampered: "The risk policy failed integrity checks.",
  order_invalid: "The order details are invalid.",
  state_missing: "Required paper account state is unavailable.",
  PRECISION_EXCEEDED: "The order exceeds supported numeric precision.",
  account_mismatch: "The selected account does not match the assessment.",
  environment_mismatch: "Only paper environment assessments are allowed.",
  account_inactive: "The selected account is not active.",
  state_invalid: "The paper account state is invalid.",
  policy_missing: "The risk policy is unavailable.",
  policy_invalid: "The risk policy is invalid.",
  policy_ambiguous: "The risk policy is ambiguous.",
  policy_stale: "The risk policy is stale.",
  scope_not_allowed: "This strategy is not allowed in the selected scope.",
  instrument_not_allowed: "This instrument is not allowed by the selected policy.",
  state_stale: "The paper account state is stale.",
  price_stale: "The price evidence is stale.",
  state_incomplete: "The paper account state is incomplete.",
  state_oversized: "The paper account state exceeds supported bounds.",
  fx_ambiguous: "Currency conversion evidence is ambiguous.",
  rate_state_invalid: "The rate state is invalid.",
  rate_counter_stale: "The rate counter is stale.",
  rate_ambiguous: "The rate evidence is ambiguous.",
  fx_missing: "Currency conversion evidence is unavailable.",
  fx_invalid: "Currency conversion evidence is invalid.",
  fx_stale: "Currency conversion evidence is stale.",
  currency_mismatch: "The order currency does not match the assessment.",
  price_invalid: "The price evidence is invalid.",
  state_ambiguous: "The paper account state is ambiguous.",
  state_inconsistent: "The paper account state is inconsistent.",
  order_duplicate: "This order attempt is already known.",
  buying_power_exceeded: "The order exceeds available buying power.",
  max_order_quantity_exceeded: "The order exceeds the maximum quantity.",
  max_order_notional_exceeded: "The order exceeds the maximum order notional.",
  max_projected_position_exceeded: "The order exceeds the projected position limit.",
  max_gross_exposure_exceeded: "The order exceeds the gross exposure limit.",
  max_net_exposure_exceeded: "The order exceeds the net exposure limit.",
  max_leverage_exceeded: "The order exceeds the leverage limit.",
  max_daily_loss_exceeded: "The order exceeds the daily loss limit.",
  rate_state_missing: "Required order-rate state is unavailable.",
  order_rate_exceeded: "The order rate limit is exceeded.",
  input_invalid: "The assessment input is invalid.",
  within_hard_limits: "The preview is within the assessed hard limits.",
};

const ERROR_LABELS: Record<PaperRiskAssessmentErrorCode, string> = {
  NETWORK_UNAVAILABLE: "The risk assessment service could not be reached. Submission is blocked.",
  PRINCIPAL_REQUIRED: "A trusted operator session is required. Submission is blocked.",
  PAPER_SCOPE_REQUIRED: "The selected paper scope could not be verified. Submission is blocked.",
  INVALID_REQUEST: "The risk assessment request is invalid. Submission is blocked.",
  ASSESSMENT_UNAVAILABLE: "The risk assessment is unavailable. Submission is blocked.",
  HTTP_ERROR: "The risk assessment request failed. Submission is blocked.",
  INVALID_RESPONSE: "The assessment response could not be verified. Submission is blocked.",
};

function reasonLabel(code: PaperRiskReasonCode): string {
  return REASON_LABELS[code] ?? "The risk assessment denied this order.";
}

function isStaleReason(code: PaperRiskReasonCode): boolean {
  return code === "state_stale" || code === "price_stale" || code === "policy_stale";
}


function assessmentAllowsSubmission(assessment: PaperRiskAssessment): boolean {
  return assessment.decision === "ALLOW" && assessment.reason_codes.length === 1 && assessment.reason_codes.every((code) => code === "within_hard_limits");
}
function requestIdentity(request: PaperRiskAssessmentRequest): string {
  return JSON.stringify([
    request.scope,
    request.account_id,
    request.request_id,
    request.attempt_id,
    request.strategy_id,
    request.venue_id,
    request.instrument_id,
    request.side,
    request.quantity,
    request.price,
    request.contract_multiplier,
    request.currency,
    request.price_source_ns,
    request.price_ingest_ns,
    request.price_source_id,
  ]);
}

export function PaperRiskReviewView({
  open,
  request,
  onClose,
  onSubmit,
}: PaperRiskReviewViewProps) {
  const [state, setState] = useState<ReviewState>({ status: "loading" });
  const [checking, setChecking] = useState(false);
  const [announcement, setAnnouncement] = useState("Checking the current paper risk assessment.");
  const inFlightRef = useRef(false);
  const openRef = useRef(open);
  const requestRef = useRef(request);
  const titleId = useId();
  const descriptionId = useId();
  const statusId = useId();
  const headingRef = useRef<HTMLHeadingElement>(null);
  const priorFocusRef = useRef<HTMLElement | null>(null);
  const identity = requestIdentity(request);

  openRef.current = open;
  requestRef.current = request;

  useEffect(() => {
    if (!open) return;
    priorFocusRef.current = document.activeElement instanceof HTMLElement
      ? document.activeElement
      : null;
    headingRef.current?.focus();
    return () => {
      priorFocusRef.current?.focus();
      openRef.current = false;
    };
  }, [open]);

  useEffect(() => {
    if (!open) {
      setState({ status: "loading" });
      setChecking(false);
      inFlightRef.current = false;
      return;
    }

    let current = true;
    setState({ status: "loading" });
    setChecking(false);
    setAnnouncement("Checking the current paper risk assessment.");

    void assessPaperRisk(request).then(
      (assessment) => {
        if (!current) return;
        const allowed = assessmentAllowsSubmission(assessment);
        setState(allowed ? { status: "allowed", assessment } : { status: "denied", assessment });
        const stale = assessment.reason_codes.some(isStaleReason);
        setAnnouncement(
          allowed
            ? "Paper hard-limit preview allows this order for review; submission requires a fresh check."
            : stale
              ? "Paper risk assessment is stale. Submission is blocked."
              : "Paper risk assessment denied this order. Submission is blocked.",
        );
      },
      (error: unknown) => {
        if (!current) return;
        const code =
          error instanceof PaperRiskAssessmentError ? error.code : "ASSESSMENT_UNAVAILABLE";
        setState({ status: "error", code });
        setAnnouncement(ERROR_LABELS[code]);
      },
    );

    return () => {
      current = false;
    };
  }, [identity, open, request]);

  async function handleSubmit(): Promise<void> {
    if (
      inFlightRef.current ||
      !openRef.current ||
      state.status !== "allowed" ||
      checking
    ) {
      return;
    }

    inFlightRef.current = true;
    setChecking(true);
    setAnnouncement("Rechecking paper risk immediately before submission.");

    try {
      const currentRequest = requestRef.current;
      const freshAssessment = await assessPaperRisk(currentRequest);
      if (!openRef.current || requestIdentity(requestRef.current) !== requestIdentity(currentRequest)) return;
      if (!openRef.current) return;
      setState(
        assessmentAllowsSubmission(freshAssessment)
          ? { status: "allowed", assessment: freshAssessment }
          : { status: "denied", assessment: freshAssessment },
      );

      if (!assessmentAllowsSubmission(freshAssessment)) {
        const stale = freshAssessment.reason_codes.some(isStaleReason);
        setAnnouncement(
          stale
            ? "The latest paper risk assessment is stale. Submission is blocked."
            : "The latest paper risk assessment denied this order. Submission is blocked.",
        );
        return;
      }

      setAnnouncement("Fresh paper hard-limit preview allows this scoped paper order.");
      await onSubmit(currentRequest);
    } catch (error: unknown) {
      if (!openRef.current) return;
      const code =
        error instanceof PaperRiskAssessmentError ? error.code : "ASSESSMENT_UNAVAILABLE";
      setState({ status: "error", code });
      setAnnouncement(ERROR_LABELS[code]);
    } finally {
      inFlightRef.current = false;
      setChecking(false);
    }
  }

  function handleKeyDown(event: KeyboardEvent<HTMLDivElement>): void {
    if (event.key === "Escape") {
      event.preventDefault();
      if (!checking) onClose();
      return;
    }
    if (event.key !== "Tab") return;
    const controls = event.currentTarget.querySelectorAll<HTMLElement>(
      'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
    );
    const focusable = [...controls].filter((element) => element.tabIndex >= 0);
    if (focusable.length === 0) {
      event.preventDefault();
      headingRef.current?.focus();
      return;
    }
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  }

  if (!open) return null;

  const blocked =
    state.status === "loading" ||
    state.status === "denied" ||
    state.status === "error" ||
    checking;
  const reasonCodes = state.status === "allowed" || state.status === "denied"
    ? state.assessment.reason_codes
    : [];

  return (
    <div className="paper-risk-review-backdrop" style={{ position: "fixed", inset: 0, zIndex: 10000, display: "grid", placeItems: "center", padding: "1rem", background: "rgba(0, 0, 0, 0.55)" }}>
      <section
        aria-labelledby={titleId}
        aria-describedby={descriptionId}
        aria-modal="true"
        className="paper-risk-review-dialog"
        onKeyDown={handleKeyDown}
        role="dialog" style={{ width: "min(100%, 42rem)", maxHeight: "calc(100vh - 2rem)", overflowY: "auto", padding: "1.5rem", borderRadius: "0.5rem", background: "var(--panel-background, #fff)", color: "var(--text-primary, #111)", boxShadow: "0 1rem 3rem rgba(0, 0, 0, 0.35)" }}
      >
        <h2 id={titleId} ref={headingRef} tabIndex={-1}>Paper risk review</h2>
        <p id={descriptionId}>
          Hard-limit preview only; soft limits are not evaluated here. This preview cannot approve,
          override risk, grant LIVE access, or submit an order.
        </p>

        <p aria-atomic="true" aria-live="assertive" className="sr-only">{announcement}</p>

        <dl>
          <dt>Scope</dt>
          <dd>Paper · {request.account_id} · {request.strategy_id}</dd>
          <dt>Venue and instrument</dt>
          <dd>{request.venue_id} · {request.instrument_id}</dd>
          <dt>Order</dt>
          <dd>{request.side} {request.quantity} {request.instrument_id} at {request.price} {request.currency}</dd>
        </dl>

        <div
          aria-live="assertive"
          className="paper-risk-review-status"
          id={statusId}
          role={state.status === "error" || state.status === "denied" ? "alert" : "status"}
        >
          {state.status === "loading" && "Checking the current paper risk assessment."}
          {state.status === "allowed" && (
            <>
              <span>Paper risk assessment allows this order for review.</span>
              <ul>
                {reasonCodes.map((code) => <li key={code}>{reasonLabel(code)}</li>)}
              </ul>
            </>
          )}
          {state.status === "denied" && (
            <>
              {reasonCodes.some(isStaleReason) ? "Stale assessment: " : "Submission denied: "}
              {reasonCodes.map(reasonLabel).join(" ")}
            </>
          )}
          {state.status === "error" && ERROR_LABELS[state.code]}
        </div>

        {state.status === "allowed" && (
          <p>Assessment time: {state.assessment.assessment_time_ns}</p>
        )}

        <div className="paper-risk-review-actions" style={{ display: "flex", justifyContent: "flex-end", gap: "0.75rem", marginTop: "1.5rem" }}>
          <button type="button" onClick={onClose} disabled={checking}>Close</button>
          <button
            type="button"
            onClick={() => void handleSubmit()}
            disabled={blocked}
            aria-disabled={blocked}
          >
            Submit
          </button>
        </div>
      </section>
    </div>
  );
}







