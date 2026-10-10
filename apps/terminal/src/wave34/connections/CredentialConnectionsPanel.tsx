import { useEffect, useState } from "react";
import { credentialConnectionsApi, type CredentialStateV1, type CredentialWriteV1 } from "./credentialApi";

type Field = { name: string; label: string; secret?: boolean; numeric?: boolean };
type Provider = { id: string; label: string; environments: readonly string[]; fields: readonly Field[]; file?: boolean };

const PROVIDERS: readonly Provider[] = [
  ...[
    ["databento", "Databento", "DATABENTO_API_KEY"], ["massive", "Massive", "MASSIVE_API_KEY"],
    ["unusual_whales", "Unusual Whales", "UNUSUAL_WHALES_API_KEY"], ["fred", "FRED", "FRED_API_KEY"],
    ["bea", "BEA", "BEA_API_KEY"], ["eia", "EIA", "EIA_API_KEY"],
    ["trading_economics", "Trading Economics", "TRADING_ECONOMICS_API_KEY"],
    ["census", "Census", "CENSUS_API_KEY"], ["usda", "USDA", "USDA_API_KEY"],
    ["quiver", "Quiver", "QUIVER_API_KEY"], ["copernicus", "Copernicus", "COPERNICUS_API_KEY"],
  ].map(([id, label]) => ({ id, label, environments: ["DEVELOPMENT"], fields: [{ name: "api_key", label: "API key", secret: true }] })),
  { id: "bls", label: "BLS", environments: ["DEVELOPMENT"], fields: [] },
  { id: "alpaca", label: "Alpaca", environments: ["PAPER", "LIVE"], fields: [
    { name: "key_id", label: "Key ID", secret: true }, { name: "secret_key", label: "Secret key", secret: true },
    { name: "account_id", label: "Account ID" },
  ] },
  { id: "ibkr", label: "IBKR", environments: ["PAPER", "LIVE"], fields: [
    { name: "host", label: "Loopback host" }, { name: "port", label: "Port", numeric: true },
    { name: "client_id", label: "Client ID", numeric: true }, { name: "account_id", label: "Account ID" },
  ] },
  { id: "mt5_forexcom", label: "FOREX.com MT5", environments: ["DEMO", "LIVE"], fields: [
    { name: "server", label: "Server" }, { name: "login", label: "Login" }, { name: "password", label: "Password", secret: true },
  ] },
  { id: "coinbase_spot", label: "Coinbase CDP", environments: ["PAPER", "LIVE"], fields: [
    { name: "key_name", label: "Key name" }, { name: "private_key", label: "Private key", secret: true },
  ] },
  { id: "kalshi", label: "Kalshi", environments: ["PAPER", "DEMO", "LIVE"], fields: [
    { name: "key_name", label: "Key ID" },
  ], file: true },
  { id: "polymarket", label: "Polymarket", environments: ["PAPER", "LIVE"], fields: [
    { name: "account_id", label: "Wallet / account ID" }, { name: "wallet_private_key", label: "Wallet private key", secret: true },
    { name: "api_key", label: "API key", secret: true }, { name: "api_secret", label: "API secret", secret: true },
    { name: "api_passphrase", label: "API passphrase", secret: true },
  ] },
];

const SAFE_ERRORS: Record<string, string> = {
  PRINCIPAL_UNTRUSTED: "Re-authenticate before changing credentials.",
  CONNECTION_FORBIDDEN: "This session cannot change credentials.",
  INVALID_CREDENTIAL: "Credential input was rejected.",
  LIVE_BINDING_UNAVAILABLE: "LIVE bindings could not be checked. No credential change was made.",
  LIVE_ACTIVATION_UNAVAILABLE: "LIVE could not be disabled safely. No credential change was made.",
  AUDIT_UNAVAILABLE: "The credential action could not be audited.",
  CREDENTIALS_UNAVAILABLE: "Credential service is unavailable.",
  TEST_UNAVAILABLE: "Connection test is unavailable.",
};

function errorMessage(error: unknown): string {
  const code = error instanceof Error ? error.message : "CREDENTIALS_UNAVAILABLE";
  return SAFE_ERRORS[code] ?? "Credential action failed.";
}

function fmtTime(value: number | null): string {
  if (value === null || !Number.isSafeInteger(value) || value < 0) return "Not recorded";
  return new Date(value / 1_000_000).toLocaleString();
}

export function CredentialConnectionsPanel() {
  const [rows, setRows] = useState<CredentialStateV1[]>([]);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [statusError, setStatusError] = useState<string | null>(null);
  const [editing, setEditing] = useState<string | null>(null);
  const [removeTarget, setRemoveTarget] = useState<{ id: string; env: string } | null>(null);
  const [pending, setPending] = useState(false);

  async function refresh() {
    try {
      setRows((await credentialConnectionsApi.status()).credentials);
      setStatusError(null);
    } catch {
      setStatusError("Credential status is unavailable.");
    }
  }
  useEffect(() => { void refresh(); }, []);

  async function replace(event: React.FormEvent<HTMLFormElement>, provider: Provider, env: string) {
    event.preventDefault();
    const form = event.currentTarget;
    const input = new FormData(form);
    if (env === "LIVE" && input.get("live_confirmation") !== "LIVE") {
      form.reset(); setError("Type LIVE to confirm a LIVE credential change."); return;
    }
    const body: CredentialWriteV1 = { fields: {}, secrets: {}, ...(env === "LIVE" ? { confirm_environment: "LIVE" as const } : {}) };
    for (const field of provider.fields) {
      const raw = input.get(field.name);
      if (typeof raw !== "string" || !raw) continue;
      if (field.secret) body.secrets![field.name] = raw;
      else body.fields![field.name] = field.numeric ? Number(raw) : raw;
    }
    form.reset();
    setPending(true); setError(null); setMessage(null);
    try {
      if (provider.file) {
        const file = input.get("private_key_file");
        const keyName = input.get("key_name");
        if (!(file instanceof File) || !file.size || typeof keyName !== "string" || !keyName) throw new Error("INVALID_CREDENTIAL");
        const bytes = new Uint8Array(await file.arrayBuffer());
        await credentialConnectionsApi.uploadKalshiKey(env, keyName, bytes, env === "LIVE");
      } else {
        await credentialConnectionsApi.replace(provider.id, env, body);
      }
      setEditing(null); setMessage(`${provider.label} credential replaced.`); await refresh();
    } catch (reason) { setError(errorMessage(reason)); }
    finally { setPending(false); }
  }

  async function test(provider: Provider, env: string) {
    setPending(true); setError(null); setMessage(null);
    try {
      const result = await credentialConnectionsApi.test(provider.id, env);
      setMessage(result.verified ? `${provider.label} connection verified.` : "Connection test did not verify.");
      await refresh();
    } catch (reason) { setError(errorMessage(reason)); }
    finally { setPending(false); }
  }

  async function remove() {
    if (!removeTarget) return;
    setPending(true); setError(null); setMessage(null);
    try {
      await credentialConnectionsApi.remove(removeTarget.id, removeTarget.env, removeTarget.env === "LIVE");
      setMessage("Credential removed."); setRemoveTarget(null); await refresh();
    } catch (reason) { setError(errorMessage(reason)); }
    finally { setPending(false); }
  }

  return <section aria-label="Write-only credentials" className="credential-connections">
    <h3>Credentials</h3>
    <p>Stored values are write-only. Replace inputs clear as soon as you submit.</p>
    {error && <p role="alert">{error}</p>}{statusError && <p role="status">{statusError}</p>}{message && <p role="status">{message}</p>}
    <div className="credential-connections__list">
      {PROVIDERS.map((provider) => provider.environments.map((env) => {
        const row = rows.find((item) => item.provider_id === provider.id && item.environment === env);
        const key = `${provider.id}:${env}`;
        return <article key={key} aria-label={`${provider.label} ${env} credentials`}>
          <h4>{provider.label} · {env}</h4>
          <p>{row?.configured ? "Configured" : "Not configured"} · {row?.verified ? "Verified" : "Not verified"}</p>
          <small>Last tested: {fmtTime(row?.last_tested_ns ?? null)}</small>
          <small>Last rotated: {fmtTime(row?.last_rotated_ns ?? null)}</small>
          {row?.error_code && <small role="status">Status code: {row.error_code}</small>}
          {(provider.fields.length > 0 || provider.file) && <button type="button" disabled={pending} onClick={() => { setEditing(editing === key ? null : key); setError(null); }}>
            Replace
          </button>}
          <button type="button" disabled={pending || !row?.configured} onClick={() => void test(provider, env)}>Test connection</button>
          <button type="button" disabled={pending || !row?.configured} onClick={() => setRemoveTarget({ id: provider.id, env })}>Remove</button>
          {editing === key && <form aria-label={`${provider.label} ${env} replace form`} onSubmit={(event) => void replace(event, provider, env)}>
            {provider.fields.map((field) => <label key={field.name}>{field.label}
              <input name={field.name} type={field.secret ? "password" : "text"} inputMode={field.numeric ? "numeric" : undefined} autoComplete="new-password" />
            </label>)}
            {provider.file && <label>Private key file
              <input name="private_key_file" type="file" accept=".pem,.key,application/x-pem-file" />
            </label>}
            {env === "LIVE" && <label>Type LIVE to confirm
              <input name="live_confirmation" type="text" autoComplete="off" />
            </label>}
            <button type="submit" disabled={pending}>Save credential</button>
            <button type="button" disabled={pending} onClick={() => setEditing(null)}>Cancel</button>
          </form>}
        </article>;
      }))}
    </div>
    {removeTarget && <div role="dialog" aria-modal="true" aria-label="Confirm credential removal">
      <p>Remove this credential? LIVE credentials require reconfirmation after replacement.</p>
      <button type="button" disabled={pending} onClick={() => void remove()}>Confirm removal</button>
      <button type="button" disabled={pending} onClick={() => setRemoveTarget(null)}>Cancel</button>
    </div>}
  </section>;
}
