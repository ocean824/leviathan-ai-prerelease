import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { isSafeIdentifier } from "../../shared/safeLabel";
import {
  createLiveActivationApi,
  type LiveActivationBlockerCode,
  type LiveActivationErrorCode,
  type LiveActivationStatusV1,
} from "./api";

type StatusState =
  | { state: "loading" }
  | { state: "ready"; data: LiveActivationStatusV1 }
  | { state: "error"; code: LiveActivationErrorCode };

const ERROR_TEXT: Record<LiveActivationErrorCode, string> = {
  NETWORK_UNAVAILABLE: "The service could not be reached. LIVE status is unverified.",
  AUTH_REQUIRED: "Sign in is required to manage LIVE activation.",
  ACTION_FORBIDDEN: "This action is not authorized for the current account.",
  ACCOUNT_NOT_FOUND: "The account could not be verified.",
  FEATURE_UNAVAILABLE: "LIVE activation is unavailable or disabled.",
  INVALID_ACCOUNT_ID: "Enter a valid account identifier.",
  INVALID_QUERY: "The status request was invalid.",
  INVALID_REQUEST: "The request could not be verified.",
  CONFIRMATION_REQUIRED: "Type the exact LIVE confirmation phrase.",
  OWNER_REQUIRED: "Only the account owner can enable LIVE.",
  HALT_ACTIVE: "HALT is active. LIVE cannot be enabled.",
  HALT_STATUS_UNAVAILABLE: "HALT status is unavailable. LIVE is blocked.",
  ENTITLEMENT_UNVERIFIED: "Account entitlement could not be verified.",
  ENTITLEMENT_CHANGED: "Account entitlement changed. Refresh and verify LIVE again.",
  SUBSCRIPTION_INACTIVE: "The account subscription is not active.",
  LIVE_FEATURE_NOT_ENTITLED: "This account is not entitled to LIVE trading.",
  LIVE_ACCOUNT_LIMIT_REACHED: "The LIVE account limit has been reached.",
  MFA_UNVERIFIED: "Recent multi-factor authentication is required.",
  MFA_STALE: "Multi-factor authentication is no longer recent enough.",
  BROKER_BINDING_UNVERIFIED: "Broker account binding could not be verified.",
  BROKER_EVIDENCE_STALE: "Broker verification is stale.",
  RISK_ACK_MISMATCH: "Risk policy acknowledgement does not match current policy.",
  RISK_POLICY_CHANGED: "Risk policy changed. LIVE activation was invalidated.",
  RISK_ACK_STALE: "Risk policy acknowledgement is stale.",
  RECOVERY_NOT_READY: "Recovery must be ready before LIVE can be enabled.",
  FAULT_ACTIVE: "A runtime fault is active. LIVE cannot be enabled.",
  FEED_EVIDENCE_STALE: "Market feed verification is stale.",
  ACCOUNT_EVIDENCE_STALE: "Account verification is stale.",
  ACCOUNT_BINDING_CHANGED: "Account binding changed. Refresh and verify again.",
  ACCOUNT_EVIDENCE_UNAVAILABLE: "Account evidence is unavailable.",
  EVIDENCE_UNAVAILABLE: "Required LIVE evidence is unavailable.",
  STORE_UNAVAILABLE: "The activation record could not be saved.",
  HTTP_ERROR: "The API request failed.",
  INVALID_RESPONSE: "The API response could not be verified.",
};

export interface LiveActivationViewProps {
  fetcher?: typeof fetch;
  clock?: () => number;
}

function isVerifiedLive(status: LiveActivationStatusV1): boolean {
  return status.effective_state === "LIVE" && status.verified && status.preconditions_verified;
}

function blockerMessage(code: LiveActivationBlockerCode): string {
  if (code === "ACCOUNT_NOT_SELECTED") return "Select an account to check LIVE eligibility.";
  return ERROR_TEXT[code];
}

function formatTimestampNs(value: number | null): string {
  if (value === null) return "Not verified";
  const date = new Date(value / 1_000_000);
  return Number.isNaN(date.getTime()) ? "Timestamp unavailable" : date.toISOString();
}

export function LiveActivationView({ fetcher = fetch, clock = Date.now }: LiveActivationViewProps) {
  const api = useMemo(() => createLiveActivationApi(fetcher), [fetcher]);
  const [accountId, setAccountId] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [status, setStatus] = useState<StatusState>({ state: "loading" });
  const [refreshing, setRefreshing] = useState(false);
  const [pending, setPending] = useState<"enable" | "disable" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [acknowledgement, setAcknowledgement] = useState<{ action: "Enable" | "Disable"; at: number } | null>(null);
  const actionLock = useRef(false);

  const refreshStatus = useCallback(async (id = "") => {
    setRefreshing(true);
    setStatus({ state: "loading" });
    const result = await api.getStatus(isSafeIdentifier(id) ? id : undefined);
    if (result.ok) setStatus({ state: "ready", data: result.data });
    else setStatus({ state: "error", code: result.error });
    setRefreshing(false);
    return result;
  }, [api]);

  useEffect(() => {
    void refreshStatus("");
  }, [refreshStatus]);

  const validAccount = isSafeIdentifier(accountId);
  const confirmationMatches = confirmation === `ENABLE LIVE ${accountId}`;
  const statusMatchesAccount = status.state === "ready" && status.data.account_id === accountId;
  const live = status.state === "ready" && statusMatchesAccount && isVerifiedLive(status.data);
  const offAndEligible = status.state === "ready" && statusMatchesAccount &&
    status.data.effective_state === "OFF" && status.data.verified &&
    status.data.preconditions_verified && status.data.blockers.length === 0;
  const enableReady = validAccount && confirmationMatches && offAndEligible && pending === null && !refreshing;
  const disableReady = validAccount && pending === null;

  const onAccountChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    setAccountId(event.target.value);
    setConfirmation("");
    setAcknowledgement(null);
    setError(null);
    setStatus({ state: "loading" });
  };

  const onAccountPaste = (event: React.ClipboardEvent<HTMLInputElement>) => {
    const pasted = event.clipboardData.getData("text");
    if (/[\r\n]/.test(pasted)) {
      event.preventDefault();
      setAccountId(pasted);
      setConfirmation("");
      setAcknowledgement(null);
      setStatus({ state: "loading" });
    }
  };

  const runAction = async (action: "enable" | "disable") => {
    if (actionLock.current || pending !== null) return;
    actionLock.current = true;
    setPending(action);
    setError(null);
    setAcknowledgement(null);
    try {
      if (!validAccount) {
        setError(ERROR_TEXT.INVALID_ACCOUNT_ID);
        return;
      }
      if (action === "enable") {
        if (!confirmationMatches) {
          setError(ERROR_TEXT.CONFIRMATION_REQUIRED);
          return;
        }
        const current = await refreshStatus(accountId);
        if (!current.ok) {
          setError(ERROR_TEXT[current.error]);
          return;
        }
        if (current.data.account_id !== accountId || current.data.effective_state !== "OFF" ||
            !current.data.verified || !current.data.preconditions_verified || current.data.blockers.length > 0) {
          setError(current.data.blockers.length > 0
            ? blockerMessage(current.data.blockers[0]!)
            : "LIVE eligibility is not verified. Refresh status before trying again.");
          return;
        }
      }
      const receipt = action === "enable"
        ? await api.enable(accountId, confirmation)
        : await api.disable(accountId);
      if (!receipt.ok) {
        setError(ERROR_TEXT[receipt.error]);
        return;
      }
      const reread = await refreshStatus(accountId);
      if (!reread.ok) {
        setError(ERROR_TEXT[reread.error]);
        return;
      }
      setAcknowledgement({ action: action === "enable" ? "Enable" : "Disable", at: clock() });
    } finally {
      actionLock.current = false;
      setPending(null);
    }
  };

  const stateText = status.state === "loading"
    ? "LIVE state is unknown while status loads."
    : status.state === "error"
      ? ERROR_TEXT[status.code]
      : status.data.account_id !== accountId || accountId === ""
        ? "LIVE state is OFF at startup; this account is not selected or verified."
        : isVerifiedLive(status.data)
          ? "API-reported LIVE; verified for this session."
          : status.data.effective_state === "LIVE"
            ? "LIVE was reported without complete verification. Treat state as unknown; controls are blocked."
            : "API-reported OFF.";
  const blockers = status.state === "ready" && status.data.account_id === accountId
    ? status.data.blockers.map(blockerMessage)
    : [];

  return (
    <main className="tab-content" aria-labelledby="live-activation-title">
      <section className="panel panel--full" aria-label="Live account activation">
        <h2 id="live-activation-title" className="panel__heading">LIVE Account Activation</h2>
        <p className="live-activation-watermark" role="status"><strong>LIVE / SIMULATION CONTROL</strong></p>
        <p>LIVE activation starts OFF after every application restart. HALT always takes precedence.</p>
        <p>Disabling LIVE prevents new LIVE submissions. It does not cancel or flatten existing orders.</p>
        <p>Activation is account-scoped and advisory to the order path. It does not create or submit orders.</p>

        <section aria-label="Account scope and state">
          <h3>Account scope</h3>
          <label htmlFor="live-account-id">Account ID</label>
          <input
            id="live-account-id"
            name="account_id"
            value={accountId}
            maxLength={128}
            autoComplete="off"
            spellCheck={false}
            disabled={pending !== null}
            onChange={onAccountChange}
            onPaste={onAccountPaste}
            aria-invalid={accountId.length > 0 && !validAccount}
          />
          {accountId.length > 0 && !validAccount && <p role="alert">Enter a valid account identifier.</p>}
          <p>LIVE status: <strong>{live ? "LIVE (verified)" : status.state === "ready" && status.data.effective_state === "OFF" ? "OFF" : "UNKNOWN"}</strong></p>
          <p role={status.state === "error" ? "alert" : "status"}>{stateText}</p>
          <p>MFA verification is server-side; missing or stale MFA evidence blocks LIVE. This screen never accepts MFA codes.</p>
          {status.state === "ready" && statusMatchesAccount && (
            <dl aria-label="Verified activation details">
              <dt>Activation revision</dt><dd>{status.data.activation_revision}</dd>
              <dt>Last verified source time</dt><dd>{formatTimestampNs(status.data.last_verified_at_ns)}</dd>
              <dt>Risk policy digest</dt><dd>{status.data.risk_policy_sha256 ?? "Not acknowledged"}</dd>
            </dl>
          )}
          <section aria-label="Open LIVE orders">
            <h3>Open LIVE orders (API-reported)</h3>
            {status.state !== "ready" || !statusMatchesAccount ||
            status.data.open_orders_state === "UNAVAILABLE" ? (
              <p role="status">Open orders are unknown or unavailable.</p>
            ) : status.data.open_orders!.length === 0 ? (
              <p role="status">No non-terminal LIVE orders were reported.</p>
            ) : (
              <table>
                <caption>Verified non-terminal LIVE orders</caption>
                <thead><tr><th>Order ID</th><th>Instrument</th><th>Side</th><th>Quantity</th><th>Status</th><th>Verified at (UTC ns)</th></tr></thead>
                <tbody>{status.data.open_orders!.map((order) => (
                  <tr key={order.order_id}>
                    <td>{order.order_id}</td><td>{order.instrument_id}</td><td>{order.side}</td>
                    <td>{order.quantity}</td><td>{order.status}</td><td>{order.verified_at_ns}</td>
                  </tr>
                ))}</tbody>
              </table>
            )}
            <p>Disabling LIVE does not cancel or flatten these orders.</p>
          </section>
          {blockers.length > 0 && <ul aria-label="LIVE blockers">{blockers.map((item) => <li key={item}>{item}</li>)}</ul>}
          <button type="button" onClick={() => void refreshStatus()} disabled={refreshing || pending !== null}>
            {refreshing ? "Refreshing status…" : "Refresh status"}
          </button>
        </section>

        <section aria-label="Enable LIVE">
          <h3>Enable LIVE</h3>
          <p>Only the account owner may enable LIVE. Type the exact confirmation phrase to proceed.</p>
          <label htmlFor="live-confirmation">Confirmation phrase</label>
          <input
            id="live-confirmation"
            value={confirmation}
            maxLength={160}
            autoComplete="off"
            disabled={pending !== null}
            onChange={(event) => setConfirmation(event.target.value)}
            aria-describedby="live-confirmation-help"
          />
          <p id="live-confirmation-help">Type: ENABLE LIVE followed by the account ID.</p>
          <button type="button" onClick={() => void runAction("enable")} disabled={!enableReady} aria-busy={pending === "enable"}>
            {pending === "enable" ? "Enabling LIVE…" : "Enable LIVE"}
          </button>
        </section>

        <section aria-label="Disable LIVE">
          <h3>Disable LIVE</h3>
          <p>Turning LIVE off does not cancel, close or flatten existing positions or working orders.</p>
          <button type="button" onClick={() => void runAction("disable")} disabled={!disableReady} aria-busy={pending === "disable"}>
            {pending === "disable" ? "Disabling LIVE…" : "Disable LIVE"}
          </button>
        </section>

        <p>When LIVE is OFF, the LIVE activation control does not authorize live dispatch.</p>
        {error !== null && <p role="alert">Action not completed: {error}</p>}
        {acknowledgement !== null && (
          <p role="status">{acknowledgement.action} request accepted by the API at {new Date(acknowledgement.at).toISOString()}. The displayed account state comes from the API status read.</p>
        )}
        {pending !== null && <p role="status" aria-live="polite">LIVE activation request is pending. Do not retry.</p>}
      </section>
    </main>
  );
}

export default LiveActivationView;
