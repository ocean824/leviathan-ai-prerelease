import { useCallback, useEffect, useMemo, useState } from "react";
import { isSafeIdentifier } from "../../shared/safeLabel";
import { createPaperActivationApi } from "../api/paperActivation";
import type {
  PaperActivationErrorCode,
  PaperActivationScope,
  PaperOrderStatusV1,
} from "../api/paperActivation";
import type { RiskGuardReport } from "../../wave26/api/liveGuard";

type ReadState<T> =
  | { state: "loading" }
  | { state: "ready"; data: T }
  | { state: "error"; code: PaperActivationErrorCode };

type IdentifierField = keyof PaperActivationScope;
type FormValues = Record<IdentifierField, string> & {
  confirm_account_id: string;
  confirm_venue: string;
  confirm_instrument_id: string;
  confirm_strategy_id: string;
};

const FIELDS: ReadonlyArray<{
  key: IdentifierField;
  label: string;
  confirmationKey: keyof FormValues;
  confirmationLabel: string;
}> = [
  { key: "account_id", label: "Account ID", confirmationKey: "confirm_account_id", confirmationLabel: "Confirm account ID" },
  { key: "venue", label: "Venue ID", confirmationKey: "confirm_venue", confirmationLabel: "Confirm venue ID" },
  { key: "instrument_id", label: "Instrument ID", confirmationKey: "confirm_instrument_id", confirmationLabel: "Confirm instrument ID" },
  { key: "strategy_id", label: "Strategy ID", confirmationKey: "confirm_strategy_id", confirmationLabel: "Confirm strategy ID" },
];

const ERROR_MESSAGES: Record<PaperActivationErrorCode, string> = {
  NETWORK_UNAVAILABLE: "The service could not be reached. Status is unverified.",
  OPERATOR_SESSION_UNAVAILABLE: "The operator session is unavailable.",
  ACTION_FORBIDDEN: "The requested action is not authorized.",
  ACTION_CONFLICT: "The requested action conflicts with the current API state.",
  INVALID_SCOPE: "Enter and confirm a valid identifier for every field.",
  SERVICE_UNAVAILABLE: "The paper runtime is not configured or is unavailable.",
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

function scopeFrom(values: FormValues): PaperActivationScope {
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

function activationBlockReason(
  order: ReadState<PaperOrderStatusV1>,
  risk: ReadState<RiskGuardReport>,
): string | null {
  if (order.state !== "ready") return "Order runtime status is not verified.";
  if (order.data.configured !== true) return "Order runtime is not configured.";
  if (order.data.recoveryStatus !== "READY") return "Recovery status must be READY.";
  if (risk.state !== "ready") return "Risk status is not verified.";
  if (haltIsActive(risk.data)) return "Activation is blocked by API-reported HALT or fault status.";
  return null;
}

export interface PaperActivationViewProps {
  fetcher?: typeof fetch;
  clock?: () => number;
}

export function PaperActivationView({
  fetcher = fetch,
  clock = Date.now,
}: PaperActivationViewProps) {
  const api = useMemo(() => createPaperActivationApi(fetcher), [fetcher]);
  const [form, setForm] = useState<FormValues>(EMPTY_FORM);
  const [order, setOrder] = useState<ReadState<PaperOrderStatusV1>>({ state: "loading" });
  const [risk, setRisk] = useState<ReadState<RiskGuardReport>>({ state: "loading" });
  const [refreshing, setRefreshing] = useState(false);
  const [pendingAction, setPendingAction] = useState<"activate" | "revoke" | null>(null);
  const [validationVisible, setValidationVisible] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [acknowledgement, setAcknowledgement] = useState<{ action: "Activation" | "Revocation"; at: number } | null>(null);

  const refreshStatus = useCallback(async () => {
    setRefreshing(true);
    setOrder({ state: "loading" });
    setRisk({ state: "loading" });
    const [orderResult, riskResult] = await Promise.all([
      api.getOrderStatus(),
      api.getRiskStatus(),
    ]);
    setOrder(orderResult.ok
      ? { state: "ready", data: orderResult.data }
      : { state: "error", code: orderResult.error });
    setRisk(riskResult.ok
      ? { state: "ready", data: riskResult.data }
      : { state: "error", code: riskResult.error });
    setRefreshing(false);
    return {
      order: orderResult.ok ? { state: "ready" as const, data: orderResult.data } : { state: "error" as const, code: orderResult.error },
      risk: riskResult.ok ? { state: "ready" as const, data: riskResult.data } : { state: "error" as const, code: riskResult.error },
    };
  }, [api]);

  useEffect(() => {
    void refreshStatus();
  }, [refreshStatus]);

  const handleChange = (key: keyof FormValues) => (event: React.ChangeEvent<HTMLInputElement>) => {
    setForm((prior) => ({ ...prior, [key]: event.target.value }));
    setActionError(null);
  };

  const handlePaste = (key: keyof FormValues) => (event: React.ClipboardEvent<HTMLInputElement>) => {
    const pasted = event.clipboardData.getData("text");
    if (/[\r\n]/.test(pasted)) {
      event.preventDefault();
      setForm((prior) => ({ ...prior, [key]: pasted }));
      setValidationVisible(true);
      setActionError(null);
    }
  };

  const formIsValid = validForm(form);
  const blocked = activationBlockReason(order, risk);
  const activateEnabled = formIsValid && blocked === null && pendingAction === null && !refreshing;

  const runAction = async (action: "activate" | "revoke") => {
    setValidationVisible(true);
    setActionError(null);
    setAcknowledgement(null);
    if (!formIsValid) {
      setActionError("Enter and confirm a valid identifier for every field.");
      return;
    }
    setPendingAction(action);
    try {
      if (action === "activate") {
        const current = await refreshStatus();
        const currentBlock = activationBlockReason(current.order, current.risk);
        if (currentBlock !== null) {
          setActionError(currentBlock);
          return;
        }
      }
      const result = action === "activate"
        ? await api.activate(scopeFrom(form))
        : await api.revoke(scopeFrom(form));
      if (!result.ok) {
        setActionError(ERROR_MESSAGES[result.error]);
        return;
      }
      setAcknowledgement({
        action: action === "activate" ? "Activation" : "Revocation",
        at: clock(),
      });
    } finally {
      setPendingAction(null);
    }
  };

  const orderStatusText = order.state === "loading"
    ? "Loading order runtime status."
    : order.state === "error"
      ? ERROR_MESSAGES[order.code]
      : `Configured runtime reported. Recovery status: ${order.data.recoveryStatus}.`;
  const riskStatusText = risk.state === "loading"
    ? "Loading risk status."
    : risk.state === "error"
      ? ERROR_MESSAGES[risk.code]
      : haltIsActive(risk.data)
        ? "HALT or fault reported by risk API."
        : "No HALT or fault reported by risk API.";

  return (
    <main className="tab-content" aria-labelledby="paper-activation-title">
      <section className="panel panel--full" aria-label="Paper activation">
        <h2 id="paper-activation-title" className="panel__heading">Paper Activation</h2>
        <p><strong>Environment: PAPER</strong> (fixed for this panel).</p>
        <p>LIVE is disabled.</p>
        <button type="button" disabled aria-label="LIVE environment disabled">LIVE (disabled)</button>
        <p role="status">Scope status: unknown — API-reported/unverified. Aggregate status does not identify this scope.</p>
        <p>No scope-specific state is available from the API after reload.</p>

        <section aria-label="Runtime and risk status">
          <h3>Runtime and risk status</h3>
          <p role={order.state === "error" ? "alert" : "status"}>Order runtime: {orderStatusText}</p>
          <p role={risk.state === "error" || (risk.state === "ready" && haltIsActive(risk.data)) ? "alert" : "status"}>
            Risk status: {riskStatusText}
          </p>
          <p>All API status is reported and freshness-unverified.</p>
          <button type="button" onClick={() => void refreshStatus()} disabled={refreshing}>
            {refreshing ? "Refreshing status…" : "Refresh status"}
          </button>
        </section>

        <form onSubmit={(event) => { event.preventDefault(); void runAction("activate"); }} noValidate>
          <fieldset>
            <legend>Confirm paper dispatch scope</legend>
            {FIELDS.map((field) => {
              const hasEntry = form[field.key] !== "" || form[field.confirmationKey] !== "";
              const invalid = (validationVisible || hasEntry) && !validField(form[field.key], form[field.confirmationKey]);
              const errorId = `${field.key}-error`;
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
                  {invalid && <p id={errorId} role="alert">Enter a valid matching identifier.</p>}
                </div>
              );
            })}
          </fieldset>
          <p>Identifiers must match exactly and pass the safe identifier rules.</p>
          <button type="submit" disabled={!activateEnabled}>
            Activate{pendingAction === "activate" && <span aria-live="polite"> — Activating…</span>}
          </button>
          {blocked !== null && <p role="status">Activation unavailable: {blocked}</p>}
        </form>

        <button
          type="button"
          onClick={() => void runAction("revoke")}
          disabled={!formIsValid || pendingAction !== null}
        >
          Revoke{pendingAction === "revoke" && <span aria-live="polite"> — Revoking…</span>}
        </button>

        {actionError !== null && <p role="alert">Action not completed: {actionError}</p>}
        {acknowledgement !== null && (
          <p role="status">
            {acknowledgement.action} accepted by the API for this session at {new Date(acknowledgement.at).toISOString()}.
            This is a local-session acknowledgement only.
            Scope status remains API-reported/unverified.
          </p>
        )}
        <p>LIVE stays disabled. This panel does not create, submit, cancel, or recover orders.</p>
      </section>
    </main>
  );
}

export default PaperActivationView;
