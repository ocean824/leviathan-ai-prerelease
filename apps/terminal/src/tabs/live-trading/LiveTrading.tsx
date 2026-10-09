import { useEffect, useRef, useState } from "react";
import type { FormEvent } from "react";
import { credentialApi } from "../../api/client";
import type {
  CredentialEnvironment,
  CredentialProvider,
  CredentialPutBody,
  CredentialStatusResponse,
  CredentialStatusRow,
} from "../../api/client";
import { errorPanel, freshPanel, loadingPanel } from "../../state/panelState";
import type { PanelState } from "../../state/panelState";
import "./LiveTrading.css";

type FieldName = "key_id" | "secret_key" | "host" | "port" | "client_id" | "account_id" | "server" | "login" | "password" | "server_id" | "token";
type FieldDefinition = { name: FieldName; label: string; secret?: boolean; inputMode?: "numeric" | "text"; placeholder?: string };
type ProviderDefinition = {
  provider: CredentialProvider;
  label: string;
  environments: readonly CredentialEnvironment[];
  fields: readonly FieldDefinition[];
};

const PROVIDERS: readonly ProviderDefinition[] = [
  {
    provider: "ALPACA",
    label: "Alpaca",
    environments: ["PAPER", "LIVE"],
    fields: [
      { name: "key_id", label: "Key ID", secret: true },
      { name: "secret_key", label: "Secret key", secret: true },
    ],
  },
  {
    provider: "IBKR",
    label: "Interactive Brokers",
    environments: ["PAPER", "LIVE"],
    fields: [
      { name: "host", label: "Loopback host", placeholder: "127.0.0.1 or ::1" },
      { name: "port", label: "Port", inputMode: "numeric" },
      { name: "client_id", label: "Client ID", inputMode: "numeric" },
      { name: "account_id", label: "Account ID" },
    ],
  },
  {
    provider: "MT5",
    label: "MetaTrader 5",
    environments: ["DEMO", "LIVE"],
    fields: [
      { name: "server", label: "Server" },
      { name: "login", label: "Login" },
      { name: "password", label: "Password", secret: true },
    ],
  },
  {
    provider: "MCP",
    label: "MCP server",
    environments: ["PAPER"],
    fields: [
      { name: "server_id", label: "Server name / ID", placeholder: "lowercase-name" },
      { name: "token", label: "Access token", secret: true },
    ],
  },
];

const SECRET_FIELDS: Record<CredentialProvider, readonly string[]> = {
  ALPACA: ["key_id", "secret_key"],
  IBKR: [],
  MT5: ["password"],
  MCP: ["token"],
};

const ID_PATTERN = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const RESERVED_IDS = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])$/i;
const STATUS_POLL_MS = 3_000;

function validIdentifier(value: string): boolean {
  return ID_PATTERN.test(value) && !RESERVED_IDS.test(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function allowedEnvironment(provider: CredentialProvider, environment: unknown): environment is CredentialEnvironment {
  return PROVIDERS.find((item) => item.provider === provider)?.environments.includes(environment as CredentialEnvironment) ?? false;
}

function sanitizeStatus(value: unknown): CredentialStatusResponse | null {
  if (!isRecord(value) || !Array.isArray(value.profiles)) return null;
  const profiles: CredentialStatusRow[] = [];

  for (const item of value.profiles) {
    if (!isRecord(item)) return null;
    const provider = item.provider;
    if (provider !== "ALPACA" && provider !== "IBKR" && provider !== "MT5" && provider !== "MCP") return null;
    if (!allowedEnvironment(provider, item.environment)) return null;
    if (typeof item.profile !== "string" || !validIdentifier(item.profile)) return null;
    const rawConfigured = item.configured;
    if (!isRecord(rawConfigured)) return null;
    const fields = SECRET_FIELDS[provider];
    const configured = Object.fromEntries(fields.map((field) => [field, rawConfigured[field] === true]));
    const updatedAt = typeof item.updated_at === "string" && Number.isFinite(Date.parse(item.updated_at))
      ? item.updated_at
      : null;
    profiles.push({
      provider,
      environment: item.environment,
      profile: item.profile,
      configured,
      updated_at: updatedAt,
      verification: "NOT_TESTED",
      ...(item.status === "CORRUPT" ? { status: "CORRUPT" as const } : {}),
    });
  }

  return { profiles };
}

function useCredentialStatus() {
  const [panel, setPanel] = useState<PanelState<CredentialStatusResponse>>(() => loadingPanel());
  const lastSuccessRef = useRef<number | undefined>(undefined);
  const retryRef = useRef<() => void>(() => undefined);

  useEffect(() => {
    let active = true;
    let inFlight = false;
    let requestId = 0;

    async function refresh(force = false) {
      if (inFlight && !force) return;
      inFlight = true;
      const currentId = ++requestId;
      try {
        const result = await credentialApi.status();
        if (!active || currentId !== requestId) return;
        const receivedAt = Date.now();
        const safeStatus = result.ok ? sanitizeStatus(result.data) : null;
        if (safeStatus) {
          lastSuccessRef.current = receivedAt;
          setPanel(freshPanel(safeStatus, "Runtime credential API", receivedAt));
        } else {
          setPanel(errorPanel(
            "Runtime credential API",
            "Credential status unavailable.",
            lastSuccessRef.current,
            () => retryRef.current(),
          ));
        }
      } catch {
        if (!active || currentId !== requestId) return;
        setPanel(errorPanel(
          "Runtime credential API",
          "Credential status unavailable.",
          lastSuccessRef.current,
          () => retryRef.current(),
        ));
      } finally {
        if (currentId === requestId) inFlight = false;
      }
    }

    retryRef.current = () => { void refresh(true); };
    void refresh();
    const interval = window.setInterval(() => { void refresh(); }, STATUS_POLL_MS);
    return () => {
      active = false;
      requestId += 1;
      window.clearInterval(interval);
      retryRef.current = () => undefined;
    };
  }, []);

  return { panel, retry: () => retryRef.current() };
}

function updatedLabel(value: string | null): string {
  return value ? new Date(value).toLocaleString() : "time unavailable";
}

function ProfileStatus({ row }: { row: CredentialStatusRow }) {
  if (row.status === "CORRUPT") {
    return <span className="credential-status credential-status--unavailable" role="status">Unavailable · stored record is corrupt</span>;
  }
  const fields = SECRET_FIELDS[row.provider];
  const configured = fields.every((field) => row.configured[field] === true);
  const anyConfigured = fields.some((field) => row.configured[field] === true);
  const label = configured ? "Configured" : anyConfigured ? "Partially configured" : "Incomplete";
  return <span className="credential-status" role="status">
    {label}, updated {updatedLabel(row.updated_at)}, verification NOT_TESTED
  </span>;
}

function CredentialEnvironmentForm({
  provider,
  providerLabel,
  environment,
  fields,
  rows,
  onSaved,
}: {
  provider: CredentialProvider;
  providerLabel: string;
  environment: CredentialEnvironment;
  fields: readonly FieldDefinition[];
  rows: readonly CredentialStatusRow[];
  onSaved: () => void;
}) {
  const [submitting, setSubmitting] = useState(false);
  const inFlightRef = useRef(false);
  const [feedback, setFeedback] = useState<{ kind: "success" | "error"; message: string } | null>(null);
  const isLive = environment === "LIVE";
  const regionName = `${providerLabel} ${environment} configuration`;

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (inFlightRef.current) return;
    inFlightRef.current = true;

    const form = event.currentTarget;
    let clearIbkrInputs = false;
    try {
      const values = new FormData(form);
      for (const secretInput of form.querySelectorAll<HTMLInputElement>('input[type="password"]')) {
        secretInput.value = "";
      }

      const confirmationInput = form.elements.namedItem("confirm_environment");
      if (confirmationInput instanceof HTMLInputElement) confirmationInput.value = "";
      setFeedback(null);
      setSubmitting(true);

      const rawProfileId = provider === "MCP" ? values.get("server_id") : values.get("profile_id");
      const profileId = typeof rawProfileId === "string" ? rawProfileId : "";
      if (!validIdentifier(profileId)) {
        setFeedback({ kind: "error", message: "Use a lowercase ID with 1–64 letters, digits, underscores or hyphens; reserved device names are not allowed." });
        return;
      }
      if (isLive && values.get("confirm_environment") !== "LIVE") {
        setFeedback({ kind: "error", message: "Type LIVE to confirm this change." });
        return;
      }

      const body: CredentialPutBody = {};
      for (const field of fields) {
        const rawValue = values.get(field.name);
        const value = typeof rawValue === "string" ? rawValue : "";
        if (field.secret) {
          if (value.length > 0) Object.assign(body, { [field.name]: value });
        } else if (provider === "IBKR" && field.name === "port") {
          if (!/^\d+$/.test(value) || Number(value) < 1 || Number(value) > 65535) {
            setFeedback({ kind: "error", message: "Enter a valid loopback host, port, client ID and account ID." });
            return;
          }
          body.port = Number(value);
        } else if (provider === "IBKR" && field.name === "client_id") {
          if (!/^\d+$/.test(value) || !Number.isSafeInteger(Number(value))) {
            setFeedback({ kind: "error", message: "Enter a valid loopback host, port, client ID and account ID." });
            return;
          }
          body.client_id = Number(value);
        } else if (field.name === "host") {
          if (value !== "127.0.0.1" && value !== "::1") {
            setFeedback({ kind: "error", message: "IBKR host must be 127.0.0.1 or ::1." });
            return;
          }
          body.host = value;
        } else if (field.name === "account_id" || field.name === "server" || field.name === "login") {
          if (!value.trim() || value.length > 256) {
            setFeedback({ kind: "error", message: `Enter a valid ${field.label.toLowerCase()}.` });
            return;
          }
          if (field.name === "account_id") body.account_id = value;
          if (field.name === "server") body.server = value;
          if (field.name === "login") body.login = value;
        }
      }

      if (provider === "MCP") body.server_id = profileId;
      if (isLive) body.confirm_environment = "LIVE";

      const result = await credentialApi.putProfile(provider, environment, profileId, body);
      if (!result.ok) {
        setFeedback({ kind: "error", message: "Configuration was not saved. Review the fields or retry." });
        return;
      }
      if (provider === "IBKR") clearIbkrInputs = true;
      setFeedback({ kind: "success", message: "Configuration saved. Verification NOT_TESTED." });
      onSaved();
    } catch {
      setFeedback({ kind: "error", message: "Configuration was not saved. Review the fields or retry." });
    } finally {
      for (const secretInput of form.querySelectorAll<HTMLInputElement>('input[type="password"]')) {
        secretInput.value = "";
      }
      if (clearIbkrInputs) {
        for (const input of form.querySelectorAll<HTMLInputElement>(".credential-fields input")) {
          input.value = "";
        }
      }
      const confirmationInput = form.elements.namedItem("confirm_environment");
      if (confirmationInput instanceof HTMLInputElement) confirmationInput.value = "";
      setSubmitting(false);
      inFlightRef.current = false;
    }
  }
  const statusRows = rows.filter((row) => row.provider === provider && row.environment === environment);

  return <section className={`credential-environment${isLive ? " credential-environment--live" : ""}`} aria-label={regionName}>
    <div className="credential-environment__header">
      <div>
        <span className="credential-environment__eyebrow">{provider}</span>
        <h4>{environment} configuration</h4>
      </div>
      {isLive && <span className="credential-live-badge">LIVE</span>}
    </div>

    <div className="credential-status-list" aria-label={`${providerLabel} ${environment} status`}>
      {statusRows.length > 0 ? statusRows.map((row) => <div className="credential-status-row" key={row.profile}>
        <span className="credential-status-row__profile">{row.profile}</span>
        <ProfileStatus row={row} />
      </div>) : <span className="credential-status credential-status--muted" role="status">Not configured</span>}
    </div>

    {isLive && <p className="credential-live-warning" role="note">
      Live credentials do not enable order submission. Type LIVE below to confirm a credential write.
    </p>}

    <form className="credential-form" aria-label={`${providerLabel} ${environment} credential form`} onSubmit={handleSubmit} noValidate>
      {provider !== "MCP" && <label className="credential-field">
        <span>Profile ID</span>
        <input name="profile_id" type="text" defaultValue="default" autoComplete="off" maxLength={64} />
      </label>}

      <div className="credential-fields">
        {fields.map((field) => {
          const inputId = `${provider.toLowerCase()}-${environment.toLowerCase()}-${field.name}`;
          return <label className="credential-field" htmlFor={inputId} key={field.name}>
            <span>{field.label}</span>
            <input
              id={inputId}
              name={field.name}
              type={field.secret ? "password" : "text"}
              autoComplete={field.secret ? "new-password" : "off"}
              inputMode={field.inputMode}
              placeholder={field.placeholder}
              maxLength={field.secret ? 4096 : 256}
              spellCheck={false}
            />
          </label>;
        })}
      </div>

      {isLive && <label className="credential-field credential-confirmation">
        <span>Type LIVE to confirm</span>
        <input name="confirm_environment" type="text" autoComplete="off" maxLength={4} spellCheck={false} />
      </label>}

      <div className="credential-form__actions">
        <button type="submit" disabled={submitting}>{submitting ? "Saving…" : "Save configuration"}</button>
        {feedback && <span className={`credential-feedback credential-feedback--${feedback.kind}`} role={feedback.kind === "error" ? "alert" : "status"}>{feedback.message}</span>}
      </div>
    </form>
  </section>;
}

export function LiveTrading() {
  const { panel, retry } = useCredentialStatus();
  const profiles = panel.status === "fresh" ? panel.data.profiles : [];

  return <div className="live-trading">
    <header className="view-intro live-trading__intro">
      <div className="eyebrow">LIVE TRADING / CONFIGURATIONS</div>
      <div className="view-intro__title"><h2>Live Trading</h2><span className="view-code">LIVE</span></div>
      <p>Enter runtime operator credentials for paper, demo, live and MCP profiles.</p>
    </header>

    <section className="credential-status-panel" aria-label="Credential status">
      <div className="credential-section-heading"><span>CONFIGURATION STATUS</span><span>VALUES ARE WRITE-ONLY</span></div>
      {panel.status === "loading" && <p role="status">Loading credential status…</p>}
      {panel.status === "error" && <div className="credential-unavailable" role="alert">
        <span>Credential status unavailable. Secret values are not shown.</span>
        <button type="button" onClick={retry}>Retry</button>
      </div>}
      {panel.status === "fresh" && profiles.length === 0 && <p className="credential-muted">No credential profiles configured.</p>}
      {panel.status === "fresh" && profiles.length > 0 && <div className="credential-overview">
        {profiles.map((row) => <div className="credential-overview__row" key={`${row.provider}-${row.environment}-${row.profile}`}>
          <strong>{row.provider} / {row.environment} / {row.profile}</strong>
          <ProfileStatus row={row} />
        </div>)}
      </div>}
    </section>

    {PROVIDERS.map((provider) => <section className="credential-provider" aria-label={`${provider.label} configurations`} key={provider.provider}>
      <div className="credential-section-heading"><span>{provider.provider}</span><span>{provider.label}</span></div>
      <div className="credential-environments">
        {provider.environments.map((environment) => <CredentialEnvironmentForm
          key={`${provider.provider}-${environment}`}
          provider={provider.provider}
          providerLabel={provider.label}
          environment={environment}
          fields={provider.fields}
          rows={profiles}
          onSaved={retry}
        />)}
      </div>
    </section>)}

    <aside className="credential-live-note" aria-label="Live trading safety">
      <strong>Live trading stays disabled.</strong>
      <span>It stays disabled until risk limits are set and the operator switch is flipped by the user.</span>
      <span>Saving a LIVE credential does not enable live trading.</span>
    </aside>
  </div>;
}
