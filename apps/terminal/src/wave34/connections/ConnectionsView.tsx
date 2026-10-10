import { useCallback, useEffect, useMemo, useState } from "react";
import { errorPanel, evaluatePanelState, freshPanel, OPERATOR_STALE_MS, unavailablePanel, type PanelState } from "../../state/panelState";
import { connectionsApi } from "./api";
import { CredentialConnectionsPanel } from "./CredentialConnectionsPanel";
import {
  createFailClosedExternalUrlOpener,
  formatExpiry,
  isValidOAuthExpiry,
  isValidOAuthState,
  providerLabel,
  validateLoopbackRedirect,
  validateOAuthUrl,
  type ApiResult,
  type Clock,
  type ConnectionEnvironment,
  type ConnectionProviderId,
  type ConnectionsApi,
  type ConnectionsCatalogV1,
  type ConnectionsErrorCode,
  type ConnectionsStatusV1,
  type ExternalUrlOpenerPort,
} from "./model";

interface ConnectionsPageData {
  catalog: ConnectionsCatalogV1;
  status: ConnectionsStatusV1;
}

interface OAuthLink {
  provider: ConnectionProviderId;
  href: string;
  expiresAtNs: string;
}

export interface ConnectionsViewProps {
  api?: ConnectionsApi;
  externalUrlOpener?: ExternalUrlOpenerPort;
  clock?: Clock;
}

const SAFE_ERROR_TEXT: Record<ConnectionsErrorCode, string> = {
  PRINCIPAL_UNTRUSTED: "Your local session is not trusted. Re-authenticate and retry.",
  CONNECTION_FORBIDDEN: "This session is not allowed to change connections.",
  INVALID_PROVIDER: "This provider is not supported.",
  UNSUPPORTED_BODY: "The request was rejected.",
  PROVIDER_NOT_FOUND: "This provider is not available.",
  CONNECTIONS_UNAVAILABLE: "Connection service is unavailable.",
  NETWORK_UNAVAILABLE: "Connection service could not be reached.",
  INVALID_RESPONSE: "Connection service returned an invalid response.",
};

function currentEnvironment(data: ConnectionsPageData): ConnectionEnvironment | null {
  const environments = new Set(data.status.connections.map((connection) => connection.environment));
  return environments.size === 1 ? [...environments][0] ?? null : null;
}

function panelForFailure<T>(result: ApiResult<unknown>, now: number): PanelState<T> {
  if (result.ok) return errorPanel<T>("connections-api", "INVALID_RESPONSE", now);
  if (result.error === "CONNECTIONS_UNAVAILABLE" || result.error === "NETWORK_UNAVAILABLE") {
    return unavailablePanel<T>("connections-api", "Connection service is unavailable.");
  }
  return errorPanel<T>("connections-api", result.error, now);
}

function stateText(state: string): string {
  return state.toLowerCase().replaceAll("_", " ");
}

export function ConnectionsView({
  api = connectionsApi,
  externalUrlOpener = createFailClosedExternalUrlOpener(),
  clock = Date.now,
}: ConnectionsViewProps) {
  const [panel, setPanel] = useState<PanelState<ConnectionsPageData>>({ status: "loading" });
  const [reloadCount, setReloadCount] = useState(0);
  const [busyProvider, setBusyProvider] = useState<ConnectionProviderId | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [actionNotice, setActionNotice] = useState<string | null>(null);
  const [clockTick, setClockTick] = useState(clock());
  const [oauthLink, setOauthLink] = useState<OAuthLink | null>(null);
  const [credentialProvider, setCredentialProvider] = useState<ConnectionProviderId | null>(null);
  const [copyResult, setCopyResult] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setPanel({ status: "loading" });
    const [catalogResult, statusResult] = await Promise.all([api.getCatalog(), api.getStatus()]);
    const now = clock();
    if (!catalogResult.ok) {
      setPanel(panelForFailure<ConnectionsPageData>(catalogResult, now));
      return;
    }
    if (!statusResult.ok) {
      setPanel(panelForFailure<ConnectionsPageData>(statusResult, now));
      return;
    }
    setPanel(freshPanel({ catalog: catalogResult.data, status: statusResult.data }, "connections-api", now, clock));
  }, [api, clock]);

  useEffect(() => {
    void refresh();
  }, [refresh, reloadCount]);

  useEffect(() => {
    const timer = window.setInterval(() => {
      setClockTick(clock());
      setPanel((current) => evaluatePanelState(current, clock, OPERATOR_STALE_MS));
    }, 1_000);
    return () => window.clearInterval(timer);
  }, [clock]);

  const data = panel.status === "fresh" || panel.status === "stale" ? panel.data : null;
  const activeEnv = useMemo(() => data ? currentEnvironment(data) : null, [data]);

  async function runAction(provider: ConnectionProviderId, action: "cancel" | "disconnect") {
    setBusyProvider(provider);
    setActionError(null);
    setActionNotice(null);
    setOauthLink(null);
    setCredentialProvider(null);
    const result = await api[action](provider);
    if (!result.ok) setActionError(SAFE_ERROR_TEXT[result.error]);
    else setReloadCount((count) => count + 1);
    setBusyProvider(null);
  }

  async function connect(provider: ConnectionProviderId, expectedAuth: string) {
    setBusyProvider(provider);
    setActionError(null);
    setActionNotice(null);
    setOauthLink(null);
    setCredentialProvider(null);
    const result = await api.connect(provider);
    setBusyProvider(null);
    if (!result.ok) {
      setActionError(SAFE_ERROR_TEXT[result.error]);
      return;
    }
    const response = result.data;
    if (response.provider_id !== provider || response.auth_method !== expectedAuth || response.environment === "LIVE") {
      void api.cancel(provider);
      setActionError("Connection details did not match the selected provider and allowed environment.");
      return;
    }
    if (response.auth_method === "oauth") {
      const safeUrl = validateOAuthUrl(response.authorization_url, response.authorization_host);
      const urlParams = safeUrl ? [...safeUrl.searchParams.keys()] : [];
      const uniqueParams = new Set(urlParams).size === urlParams.length;
      const protocolParamsMatch = safeUrl?.searchParams.getAll("state").length === 1 &&
        safeUrl.searchParams.get("state") === response.state &&
        safeUrl.searchParams.getAll("redirect_uri").length === 1 &&
        safeUrl.searchParams.get("redirect_uri") === response.redirect_uri;
      if (!safeUrl || !uniqueParams || !protocolParamsMatch || !validateLoopbackRedirect(response.redirect_uri) || !isValidOAuthState(response.state) ||
          response.single_use !== true || !isValidOAuthExpiry(response.expires_at_ns, clock())) {
        void api.cancel(provider);
        setActionError("Authorization details failed local safety checks. No link was opened.");
        return;
      }
      let opened: "opened" | "unavailable" = "unavailable";
      try {
        opened = await externalUrlOpener.open(safeUrl);
      } catch {
        opened = "unavailable";
      }
      if (opened === "unavailable") {
        setOauthLink({ provider, href: safeUrl.href, expiresAtNs: response.expires_at_ns });
      } else {
        setActionNotice("Authorization link opened. Complete the single-use sign-in before it expires.");
      }
      return;
    }
    if ((response.auth_method === "api_key" || response.auth_method === "mt5_login") && response.credential_entry_handle) {
      setCredentialProvider(provider);
      return;
    }
    void api.cancel(provider);
    setActionError("Credential entry could not be opened.");
  }

  async function copyAuthorizationLink() {
    if (!oauthLink) return;
    try {
      await navigator.clipboard.writeText(oauthLink.href);
      setCopyResult("Authorization link copied.");
    } catch {
      setCopyResult("Copy is unavailable. Use the link to open it in your browser.");
    }
  }

  if (panel.status === "loading") {
    return <section className="directory-view" aria-busy="true" aria-label="Connections">
      <h2>Connections</h2><p role="status">Loading connection status…</p>
    </section>;
  }
  if (panel.status === "unavailable") {
    return <section className="directory-view" aria-label="Connections">
      <h2>Connections</h2><p role="alert">Connection service unavailable.</p>
      <button type="button" onClick={() => setReloadCount((count) => count + 1)}>Retry</button>
    </section>;
  }
  if (panel.status === "error") {
    const text = SAFE_ERROR_TEXT[panel.code as ConnectionsErrorCode] ?? "Connection status could not be verified.";
    return <section className="directory-view" aria-label="Connections">
      <h2>Connections</h2><p role="alert">{text}</p>
      <button type="button" onClick={() => setReloadCount((count) => count + 1)}>Retry</button>
    </section>;
  }

  if (!data) return null;

  return <section className="directory-view" aria-label="Connections">
    <div className="view-intro">
      <div className="eyebrow">PROVIDERS / CONNECTION STATUS</div>
      <h2>Connections</h2>
      <p>Connect or disconnect providers for the environment assigned to this authenticated project session. Credentials are never displayed here.</p>
    </div>
    {panel.status === "stale" && <p role="status">Connection status is stale. Refresh before changing a connection.</p>}
    {panel.status === "fresh" && <p role="status">Connection status is current.</p>}
    <p className="live-disabled" role="note">Starting Live connections is disabled in this terminal. Pending requests can still be canceled and existing connections can be disconnected.</p>
    {!activeEnv && <p role="status">The active environment could not be verified. Connection changes are disabled.</p>}
    {actionError && <p role="alert">{actionError}</p>}
    {actionNotice && <p role="status">{actionNotice}</p>}
    {oauthLink && <div className="authorization-link" role="group" aria-label="Single-use authorization link">
      {clockTick >= Number(BigInt(oauthLink.expiresAtNs) / 1_000_000n)
        ? <p role="status">{providerLabel(oauthLink.provider)} sign-in link expired.</p>
        : <>
          <p>{providerLabel(oauthLink.provider)} sign-in link. Single use; expires at {formatExpiry(oauthLink.expiresAtNs)}.</p>
          <button type="button" onClick={() => void copyAuthorizationLink()}>Copy link / open it in your browser</button>
          <a href={oauthLink.href} target="_blank" rel="noopener noreferrer">Open authorization link</a>
          {copyResult && <p role="status">{copyResult}</p>}
        </>}
    </div>}
    {credentialProvider && <p role="status">
      <a href="#LIVE">Continue to {providerLabel(credentialProvider)} credential entry</a>
    </p>}
    {data.catalog.providers.length === 0
      ? <p role="status">No providers are available in the connection catalog.</p>
      : <div className="directory-grid">
        {data.catalog.providers.map((provider) => {
          const rows = data.status.connections.filter((connection) => connection.provider_id === provider.provider_id);
          const row = activeEnv ? rows.find((connection) => connection.environment === activeEnv) : undefined;
          const busy = busyProvider === provider.provider_id;
          const canMutate = panel.status === "fresh" && activeEnv !== null && row !== undefined && !busyProvider;
          const canInitiate = canMutate && activeEnv !== "LIVE";
          return <article className="directory-row" key={provider.provider_id}>
            <strong>{providerLabel(provider.provider_id)}</strong>
            <code>{provider.provider_id}</code>
            <span>{row ? stateText(row.state) : "status unavailable"}</span>
            <small>Environment: {row?.environment ?? "unverified"}</small>
            <small>Capabilities: {provider.capabilities.join(", ") || "none reported"}</small>
            <small>Available environments: {provider.environments.join(", ") || "none"}</small>
            <small>Authentication: {provider.auth_method.replaceAll("_", " ")}</small>
            <small>Default provider: {provider.default_route ? "Yes" : "No"}</small>
            {row?.configured && <small>Configured</small>}
            {provider.auth_method === "oauth" && <button type="button" disabled={!canInitiate || (row?.state === "CONNECTED") || busy}
              onClick={() => void connect(provider.provider_id, provider.auth_method)}>
              {busy ? "Working…" : "Connect"}
            </button>}
            {(provider.auth_method === "api_key" || provider.auth_method === "mt5_login") && <button type="button"
              disabled={!canInitiate || row?.state === "CONNECTED" || busy}
              onClick={() => void connect(provider.provider_id, provider.auth_method)}>
              {busy ? "Working…" : "Open credential entry"}
            </button>}
            {row?.state === "PENDING" && <button type="button" disabled={!canMutate || busy}
              onClick={() => void runAction(provider.provider_id, "cancel")}>Cancel</button>}
            {row?.state === "CONNECTED" && <button type="button" disabled={!canMutate || busy}
              onClick={() => void runAction(provider.provider_id, "disconnect")}>Disconnect</button>}
          </article>;
        })}
      </div>}
    <button type="button" onClick={() => setReloadCount((count) => count + 1)}>Refresh connections</button>
    <CredentialConnectionsPanel />
  </section>;
}
