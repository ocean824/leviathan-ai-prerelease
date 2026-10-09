import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { isSafeIdentifier } from "../../shared/safeLabel";
import { createPaperSessionApi } from "./api";
import type { PaperSessionScope } from "./api";
import type {
  PaperActivationErrorCode,
  PaperOrderStatusV1,
} from "../../wave27/api/paperActivation";
import type { RiskGuardReport } from "../../wave26/api/liveGuard";

type ReadState<T> =
  | { state: "loading" }
  | { state: "ready"; data: T }
  | { state: "error"; code: PaperActivationErrorCode };

type ScopeField = keyof PaperSessionScope;
type FormValues = Record<ScopeField, string> & {
  confirm_account_id: string;
  confirm_venue: string;
  confirm_instrument_id: string;
  confirm_strategy_id: string;
};
type ConfirmationKey = Exclude<keyof FormValues, ScopeField>;

const FIELDS: ReadonlyArray<{
  key: ScopeField;
  label: string;
  confirmationKey: ConfirmationKey;
  confirmationLabel: string;
}> = [
  { key: "account_id", label: "Account ID", confirmationKey: "confirm_account_id", confirmationLabel: "Confirm account ID" },
  { key: "venue", label: "Venue ID", confirmationKey: "confirm_venue", confirmationLabel: "Confirm venue ID" },
  { key: "instrument_id", label: "Instrument ID", confirmationKey: "confirm_instrument_id", confirmationLabel: "Confirm instrument ID" },
  { key: "strategy_id", label: "Strategy ID", confirmationKey: "confirm_strategy_id", confirmationLabel: "Confirm strategy ID" },
];

const ERROR_MESSAGES: Record<PaperActivationErrorCode, string> = {
  NETWORK_UNAVAILABLE: "The service could not be reached. Current API status is unverified.",
  OPERATOR_SESSION_UNAVAILABLE: "The operator session is unavailable.",
  ACTION_FORBIDDEN: "The requested paper session action is not authorized.",
  ACTION_CONFLICT: "The requested action conflicts with the current API state.",
  INVALID_SCOPE: "Enter and confirm a valid identifier for every field.",
  SERVICE_UNAVAILABLE: "The paper runtime is unavailable.",
  HTTP_ERROR: "The API request failed.",
  INVALID_RESPONSE: "The API response could not be verified.",
};

const EMPTY_FORM: FormValues = {
  account_id: "",
  venue: "",
  instrument_id: "",
  strategy_id: "",
  confirm_account_id: "",
  confirm_venue: "",
  confirm_instrument_id: "",
  confirm_strategy_id: "",
};

function validField(value: string, confirmation: string): boolean {
  return isSafeIdentifier(value) && value === confirmation;
}

function validForm(values: FormValues): boolean {
  return FIELDS.every((field) => validField(values[field.key], values[field.confirmationKey]));
}

function scopeFrom(values: FormValues): PaperSessionScope {
  return {
    account_id: values.account_id,
    venue: values.venue,
    instrument_id: values.instrument_id,
    strategy_id: values.strategy_id,
  };
}

function haltIsActive(risk: RiskGuardReport): boolean {
  return risk.haltedReported || risk.haltCodes.length > 0 || risk.faultCode !== null;
}

function resumeBlockReason(
  order: ReadState<PaperOrderStatusV1>,
  risk: ReadState<RiskGuardReport>,
): string | null {
  if (order.state !== "ready") return "Order status is not verified; resume is blocked.";
  if (order.data.liveEnabledReported) return "LIVE is reported enabled; resume is disabled.";
  if (order.data.configured !== true) return "The paper runtime is not configured; resume is blocked.";
  if (order.data.recoveryStatus !== "READY") return "Recovery must be READY before resume.";
  if (risk.state !== "ready") return "Risk status is not verified; resume is blocked.";
  if (haltIsActive(risk.data)) return "API-reported HALT or fault blocks resume.";
  return null;
}

export interface PaperSessionControlsViewProps {
  fetcher?: typeof fetch;
}

export function PaperSessionControlsView({
  fetcher = fetch,
}: PaperSessionControlsViewProps) {
  const api = useMemo(() => createPaperSessionApi(fetcher), [fetcher]);
  const [form, setForm] = useState<FormValues>(EMPTY_FORM);
  const [order, setOrder] = useState<ReadState<PaperOrderStatusV1>>({ state: "loading" });
  const [risk, setRisk] = useState<ReadState<RiskGuardReport>>({ state: "loading" });
  const [refreshing, setRefreshing] = useState(false);
  const [pendingAction, setPendingAction] = useState<"pause" | "resume" | null>(null);
  const actionLock = useRef(false);
  const [validationVisible, setValidationVisible] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [acknowledgement, setAcknowledgement] = useState<{
    action: "pause" | "resume";
    acknowledgedAt: string;
  } | null>(null);

  const refreshStatus = useCallback(async () => {
    setRefreshing(true);
    setOrder({ state: "loading" });
    setRisk({ state: "loading" });
    const [orderResult, riskResult] = await Promise.all([
      api.getOrderStatus(),
      api.getRiskStatus(),
    ]);
    const nextOrder: ReadState<PaperOrderStatusV1> = orderResult.ok
      ? { state: "ready", data: orderResult.data }
      : { state: "error", code: orderResult.error };
    const nextRisk: ReadState<RiskGuardReport> = riskResult.ok
      ? { state: "ready", data: riskResult.data }
      : { state: "error", code: riskResult.error };
    if (
      (nextRisk.state === "ready" && haltIsActive(nextRisk.data)) ||
      (nextOrder.state === "ready" && nextOrder.data.recoveryStatus !== "READY")
    ) {
      setAcknowledgement(null);
    }
    setOrder(nextOrder);
    setRisk(nextRisk);
    setRefreshing(false);
    return { order: nextOrder, risk: nextRisk };
  }, [api]);

  useEffect(() => {
    void refreshStatus();
  }, [refreshStatus]);

  const handleChange = (key: keyof FormValues) => (event: React.ChangeEvent<HTMLInputElement>) => {
    setForm((prior) => ({ ...prior, [key]: event.target.value }));
    setActionError(null);
    setAcknowledgement(null);
  };

  const handlePaste = (key: keyof FormValues) => (event: React.ClipboardEvent<HTMLInputElement>) => {
    const pasted = event.clipboardData.getData("text");
    if (/[\r\n]/.test(pasted)) {
      event.preventDefault();
      setForm((prior) => ({ ...prior, [key]: pasted }));
      setValidationVisible(true);
      setActionError(null);
      setAcknowledgement(null);
    }
  };

  const formIsValid = validForm(form);
  const scope = scopeFrom(form);
  const knownLiveEnabled = order.state === "ready" && order.data.liveEnabledReported;
  const resumeBlocked = resumeBlockReason(order, risk);
  const canPause =
    formIsValid &&
    pendingAction === null;
  const canResume =
    formIsValid &&
    pendingAction === null &&
    !refreshing &&
    resumeBlocked === null;

  const runAction = async (action: "pause" | "resume") => {
    if (actionLock.current) return;
    setValidationVisible(true);
    setActionError(null);
    setAcknowledgement(null);
    if (!formIsValid) {
      setActionError("Enter and confirm a valid identifier for every field.");
      return;
    }
    if (action === "resume" && knownLiveEnabled) {
      setActionError("LIVE is reported enabled; resume is disabled.");
      return;
    }

    actionLock.current = true;
    setPendingAction(action);
    try {
      if (action === "resume") {
        const current = await refreshStatus();
        const block = resumeBlockReason(current.order, current.risk);
        if (block !== null) {
          setActionError(block);
          return;
        }
      }
      const result = action === "pause"
        ? await api.pause(scope)
        : await api.resume(scope);
      if (!result.ok) {
        setActionError(ERROR_MESSAGES[result.error]);
      } else {
        setAcknowledgement({ action, acknowledgedAt: new Date().toISOString() });
      }
      await refreshStatus();
    } catch {
      setActionError("The paper session action could not be verified.");
      await refreshStatus();
    } finally {
      actionLock.current = false;
      setPendingAction(null);
    }
  };

  const activeText = order.state === "ready"
    ? String(order.data.activationCount)
    : "Unknown";
  const recoveryText = order.state === "ready"
    ? order.data.recoveryStatus
    : "Unknown";
  const orderMessage = order.state === "loading"
    ? "Loading order status."
    : order.state === "error"
      ? ERROR_MESSAGES[order.code]
      : "Order status is API-reported and aggregate.";
  const riskMessage = risk.state === "loading"
    ? "Loading risk status."
    : risk.state === "error"
      ? ERROR_MESSAGES[risk.code]
      : haltIsActive(risk.data)
        ? "HALT or fault is API-reported."
        : "No HALT or fault is API-reported.";

  return (
    <main className="tab-content" aria-labelledby="paper-session-title">
      <section className="panel panel--full" aria-label="Paper session controls">
        <h1 id="paper-session-title" className="panel__heading">Paper Session Controls</h1>
        <p>
          <strong
            aria-label="SIM / PAPER environment watermark"
            style={{ display: "inline-block", border: "2px solid currentColor", padding: "0.35rem 0.65rem", fontWeight: 800, letterSpacing: "0.12em" }}
          >
            SIM / PAPER
          </strong>
        </p>
        <p>Pause stops new submissions for this scope. It does not cancel working orders or pause the simulator.</p>
        <p>Resume re-enables new submissions for this paper scope only.</p>
        <p>LIVE is disabled.</p>
        <button type="button" disabled aria-label="LIVE environment disabled">LIVE (disabled)</button>

        <section aria-label="API-reported session status">
          <h2>API-reported session status</h2>
          <p role={order.state === "error" ? "alert" : "status"}>Active paper activations (aggregate, API-reported): {activeText}.</p>
          <p role={order.state === "error" ? "alert" : "status"}>Recovery state (aggregate, API-reported): {recoveryText}.</p>
          <p role={order.state === "error" ? "alert" : "status"}>Order status: {orderMessage}</p>
          <p role={risk.state === "error" || (risk.state === "ready" && haltIsActive(risk.data)) ? "alert" : "status"}>
            Risk status: {riskMessage}
          </p>
          <p>Scope-specific state unavailable; the API reports aggregate status only.</p>
          {order.state === "ready" && order.data.liveEnabledReported
            ? <p role="alert">LIVE is reported enabled. Resume is disabled.</p>
            : null}
          <button type="button" onClick={() => void refreshStatus()} disabled={refreshing || pendingAction !== null}>
            {refreshing ? "Refreshing status…" : "Refresh status"}
          </button>
        </section>

        <form onSubmit={(event) => { event.preventDefault(); }} noValidate>
          <fieldset disabled={pendingAction !== null}>
            <legend>Confirm paper session scope</legend>
            {FIELDS.map((field) => {
              const hasEntry = form[field.key] !== "" || form[field.confirmationKey] !== "";
              const invalid = (validationVisible || hasEntry) && !validField(form[field.key], form[field.confirmationKey]);
              const errorId = field.key + "-error";
              return (
                <div key={field.key}>
                  <label htmlFor={field.key}>{field.label}</label>
                  <input
                    id={field.key}
                    name={field.key}
                    value={form[field.key]}
                    maxLength={128}
                    autoComplete="off"
                    spellCheck={false}
                    onChange={handleChange(field.key)}
                    onPaste={handlePaste(field.key)}
                    aria-invalid={invalid}
                    aria-describedby={invalid ? errorId : undefined}
                  />
                  <label htmlFor={field.confirmationKey}>{field.confirmationLabel}</label>
                  <input
                    id={field.confirmationKey}
                    name={field.confirmationKey}
                    value={form[field.confirmationKey]}
                    maxLength={128}
                    autoComplete="off"
                    spellCheck={false}
                    onChange={handleChange(field.confirmationKey)}
                    onPaste={handlePaste(field.confirmationKey)}
                    aria-invalid={invalid}
                    aria-describedby={invalid ? errorId : undefined}
                  />
                  {invalid ? <p id={errorId} role="alert">Enter a valid matching identifier.</p> : null}
                </div>
              );
            })}
          </fieldset>

          <div>
            <button
              type="button"
              onClick={() => void runAction("pause")}
              disabled={!canPause}
            >
              {pendingAction === "pause" ? "Pausing…" : "Pause submissions"}
            </button>
            <button
              type="button"
              onClick={() => void runAction("resume")}
              disabled={!canResume}
              aria-describedby="resume-block-reason"
            >
              {pendingAction === "resume" ? "Resuming…" : "Resume submissions"}
            </button>
          </div>
        </form>
        {resumeBlocked !== null && formIsValid
          ? <p id="resume-block-reason" role="status">{resumeBlocked}</p>
          : null}
        {pendingAction !== null
          ? <p role="status" aria-live="polite">Paper session action in progress.</p>
          : null}
        {actionError ? <p role="alert">{actionError}</p> : null}
        {acknowledgement
          ? <p role="status">
              {acknowledgement.action === "pause" ? "Pause" : "Resume"} accepted by the API for this session at {acknowledgement.acknowledgedAt}; scope-specific state remains unavailable.
            </p>
          : null}
      </section>
    </main>
  );
}
