import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  HALT_REASON_OPTIONS,
  createPaperHaltApi,
  type HaltApiError,
  type HaltStatusV1,
  type KnownHaltReason,
  type StaticHaltReason,
} from "./api";

type StatusState =
  | { state: "loading" }
  | { state: "ready"; data: HaltStatusV1 }
  | { state: "error" };

const ERROR_MESSAGES: Record<HaltApiError, string> = {
  NETWORK_ERROR: "The risk service could not be reached. HALT status is unverified.",
  TIMEOUT: "The request timed out. HALT status is being refreshed.",
  INVALID_RESPONSE: "The risk service returned an invalid response. HALT status is unverified.",
  INVALID_HALT_REASON: "The selected HALT reason was rejected.",
  HALT_REASON_NOT_ACTIVE: "That HALT reason is no longer active.",
  HALT_STORE_UNAVAILABLE: "The HALT state could not be persisted.",
  HTTP_ERROR: "The risk request failed.",
};

export interface PaperHaltControlViewProps {
  fetcher?: typeof fetch;
}

export function PaperHaltControlView({ fetcher = fetch }: PaperHaltControlViewProps) {
  const api = useMemo(() => createPaperHaltApi(fetcher), [fetcher]);
  const [status, setStatus] = useState<StatusState>({ state: "loading" });
  const [selectedReason, setSelectedReason] = useState<StaticHaltReason>("operator_halt");
  const [pendingAction, setPendingAction] = useState<string | null>(null);
  const [failure, setFailure] = useState<string | null>(null);
  const [liftConfirmation, setLiftConfirmation] = useState<KnownHaltReason | null>(null);
  const [statusUnverified, setStatusUnverified] = useState(false);
  const inFlight = useRef(false);
  const latestRead = useRef(0);
  const mounted = useRef(false);

  const refreshStatus = useCallback(async (clearUnverified = false) => {
    const sequence = ++latestRead.current;
    const result = await api.getStatus();
    if (!mounted.current || sequence !== latestRead.current) return result.ok;
    setStatus(result.ok ? { state: "ready", data: result.data } : { state: "error" });
    if (result.ok && clearUnverified) setStatusUnverified(false);
    return result.ok;
  }, [api]);

  useEffect(() => {
    mounted.current = true;
    void refreshStatus();
    return () => {
      mounted.current = false;
      latestRead.current += 1;
    };
  }, [refreshStatus]);

  const submit = useCallback(
    async (action: "engage" | "lift", reason: string) => {
      if (inFlight.current) return;
      inFlight.current = true;
      setFailure(null);
      setLiftConfirmation(null);
      setPendingAction(`${action}:${reason}`);
      try {
        const result = action === "engage"
          ? await api.engage(reason as StaticHaltReason)
          : await api.lift(reason as KnownHaltReason);
        if (!mounted.current) return;
        if (!result.ok) {
          setFailure(ERROR_MESSAGES[result.error]);
          if (result.error === "TIMEOUT") setStatusUnverified(true);
        } else {
          setStatusUnverified(false);
        }
        await refreshStatus();
      } catch {
        if (mounted.current) {
          setFailure("The risk request failed. HALT status is being refreshed.");
          setStatusUnverified(true);
        }
        await refreshStatus();
      } finally {
        if (mounted.current) setPendingAction(null);
        inFlight.current = false;
      }
    },
    [api, refreshStatus],
  );

  const activeReasons = status.state === "ready" ? status.data.active_halts : [];
  const halted = status.state === "ready" && (
    status.data.halted || activeReasons.length > 0 || status.data.fault_code !== null
  );
  const controlsDisabled = pendingAction !== null || liftConfirmation !== null;
  const confirmLift = () => {
    if (liftConfirmation !== null) void submit("lift", liftConfirmation);
  };

  return (
    <section aria-labelledby="paper-halt-heading" className="operator-panel">
      <h2 id="paper-halt-heading">Paper risk HALT control</h2>
      <p>Engaging HALT blocks new submits. LIVE controls are not available here.</p>

      <p aria-live="polite" role="status">
        {pendingAction !== null && "HALT status pending / unverified."}
        {pendingAction === null && (statusUnverified || status.state === "error") && "HALT status is unverified."}
        {pendingAction === null && !statusUnverified && status.state === "loading" && "Loading HALT status..."}
        {pendingAction === null && !statusUnverified && status.state === "ready" && (halted ? "HALT ENGAGED" : "NO ACTIVE HALT")}
      </p>
      {status.state === "ready" && status.data.fault_code !== null && (
        <p role="alert">HALT persistence is unavailable.</p>
      )}
      {status.state === "ready" && activeReasons.length > 0 && (
        <section aria-label="Active HALT reasons">
          <h3>Active reasons</h3>
          <ul>
            {activeReasons.map((reason) => (
              <li key={reason}>
                <span>{reason}</span>{" "}
                <button
                  type="button"
                  disabled={controlsDisabled}
                  onClick={() => setLiftConfirmation(reason)}
                >
                  Lift HALT reason {reason}
                </button>
              </li>
            ))}
          </ul>
        </section>
      )}

      <div>
        <label htmlFor="paper-halt-reason">Reason to engage</label>
        <select
          id="paper-halt-reason"
          value={selectedReason}
          onChange={(event) => setSelectedReason(event.target.value as StaticHaltReason)}
          disabled={controlsDisabled}
        >
          {HALT_REASON_OPTIONS.map((reason) => <option key={reason} value={reason}>{reason}</option>)}
        </select>
        <button
          type="button"
          disabled={controlsDisabled}
          onClick={() => void submit("engage", selectedReason)}
        >
          Engage HALT
        </button>
      </div>

      {liftConfirmation !== null && (
        <div role="group" aria-label="Confirm HALT lift">
          <p>Confirm lifting HALT reason {liftConfirmation}? This may allow new paper submits.</p>
          <button type="button" onClick={confirmLift}>Confirm lift</button>
          <button type="button" onClick={() => setLiftConfirmation(null)}>Cancel lift</button>
        </div>
      )}
      {pendingAction !== null && <p aria-live="assertive" role="status">HALT change pending…</p>}
      {failure !== null && <p role="alert">{failure}</p>}
      <button type="button" disabled>LIVE trading disabled</button>
      <button type="button" onClick={() => void refreshStatus(true)} disabled={controlsDisabled}>
        Refresh HALT status
      </button>
    </section>
  );
}
