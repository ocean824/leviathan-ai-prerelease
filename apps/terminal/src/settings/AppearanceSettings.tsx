import { useCallback, useEffect, useMemo, useState } from "react";
import "../views/design/themePresets.css";
import {
  applyThemeTokens,
  getThemeTokens,
  THEME_PRESETS,
  THEME_TOKENS,
  type AccentId,
  type ThemeId,
  type ThemeToken,
  type ThemeTokens,
} from "../views/design/themeRegistry";
import { validateThemeContrast } from "../views/design/contrast";
import {
  createAppearanceClient,
  DEFAULT_APPEARANCE_PREFERENCE,
  type AppearanceCachePort,
  type AppearancePreferenceV1,
  type PreferencesPort,
  type VersionedAppearancePreferenceV1,
} from "./appearanceClient";
import "./AppearanceSettings.css";

export interface AppearanceSettingsProps {
  readonly preferencesPort: PreferencesPort;
  readonly cache?: AppearanceCachePort;
}

function tokenLabel(token: ThemeToken): string {
  return token.replace(/([A-Z])/g, " $1").replace(/^./, (letter) => letter.toUpperCase());
}

function preferenceFromRecord(
  record: VersionedAppearancePreferenceV1 | null,
): AppearancePreferenceV1 {
  return record?.preference ?? DEFAULT_APPEARANCE_PREFERENCE;
}

export function AppearanceSettings({
  preferencesPort,
  cache,
}: AppearanceSettingsProps): React.JSX.Element {
  const client = useMemo(
    () => createAppearanceClient(preferencesPort, cache),
    [preferencesPort, cache],
  );
  const [draft, setDraft] = useState<AppearancePreferenceV1>(DEFAULT_APPEARANCE_PREFERENCE);
  const [revision, setRevision] = useState<string | null>(null);
  const [serverConflict, setServerConflict] = useState<{
    readonly record: VersionedAppearancePreferenceV1 | null;
  } | null>(null);
  const [sourceLabel, setSourceLabel] = useState("Loading appearance preferences…");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [appliedTokens, setAppliedTokens] = useState<ThemeTokens>(() =>
    getThemeTokens("dark", "cyan"),
  );

  const tokens = useMemo(
    () => getThemeTokens(draft.theme_id, draft.accent_id, draft.custom_tokens),
    [draft],
  );
  const contrast = useMemo(() => validateThemeContrast(tokens), [tokens]);

  const applyIfValid = useCallback((preference: AppearancePreferenceV1) => {
    const candidate = getThemeTokens(
      preference.theme_id,
      preference.accent_id,
      preference.custom_tokens,
    );
    if (!validateThemeContrast(candidate).valid) return false;
    applyThemeTokens(candidate, preference.theme_id, preference.accent_id);
    setAppliedTokens(candidate);
    return true;
  }, []);

  useEffect(() => {
    let active = true;
    void client.load().then((result) => {
      if (!active) return;
      const record = result.record;
      const loaded = preferenceFromRecord(record);
      setDraft(loaded);
      setRevision(record?.revision ?? null);
      setSourceLabel(
        result.source === "server"
          ? "Preferences loaded from the account."
          : result.source === "local-cache"
            ? "Local cache only — not authoritative or synced across devices."
            : "Using the default appearance; account preferences are unavailable.",
      );
      if (!applyIfValid(loaded)) {
        const fallback = DEFAULT_APPEARANCE_PREFERENCE;
        setDraft(fallback);
        applyIfValid(fallback);
        setMessage("Saved palette did not pass contrast checks. The last valid appearance is retained.");
      }
    });
    return () => {
      active = false;
    };
  }, [applyIfValid, client]);

  const updateDraft = useCallback(
    (next: AppearancePreferenceV1) => {
      setDraft(next);
      setMessage("");
      if (applyIfValid(next)) {
        setSourceLabel("Preview applied immediately. Save to persist this appearance.");
      } else {
        setSourceLabel("Preview held at the last valid palette until contrast passes.");
      }
    },
    [applyIfValid],
  );

  const updateTheme = (themeId: ThemeId) => updateDraft({ ...draft, theme_id: themeId });
  const updateAccent = (accentId: AccentId) => updateDraft({ ...draft, accent_id: accentId });

  const updateToken = (token: ThemeToken, color: string) => {
    const customTokens = { ...draft.custom_tokens, [token]: color };
    updateDraft({ ...draft, custom_tokens: customTokens });
  };

  const save = async () => {
    if (!contrast.valid || busy) return;
    setBusy(true);
    setMessage("");
    try {
      const result = await client.save(draft, revision);
      if (result.kind === "saved") {
        setRevision(result.record.revision);
        setServerConflict(null);
        setSourceLabel("Saved to the account preferences.");
        setMessage("Appearance saved.");
      } else if (result.kind === "offline-cache") {
        setSourceLabel("Local cache only — not authoritative or synced across devices.");
        setMessage("Saved on this device. Account synchronization is unavailable.");
      } else if (result.kind === "conflict") {
        setServerConflict({ record: result.current });
        setRevision(result.current?.revision ?? null);
        setMessage("Account preferences changed. Your unsaved draft is preserved; reload the account version or save again.");
      } else {
        setMessage("This palette failed contrast validation and was not saved.");
      }
    } finally {
      setBusy(false);
    }
  };

  const useServerVersion = () => {
    const serverPreference = preferenceFromRecord(serverConflict?.record ?? null);
    setDraft(serverPreference);
    setRevision(serverConflict?.record?.revision ?? null);
    setServerConflict(null);
    setMessage("Account appearance loaded.");
    setSourceLabel("Preferences loaded from the account.");
    applyIfValid(serverPreference);
  };

  return (
    <section className="appearance-settings" aria-labelledby="appearance-title">
      <header className="appearance-settings__header">
        <div>
          <p className="appearance-settings__eyebrow">Settings</p>
          <h1 id="appearance-title">Appearance</h1>
          <p className="appearance-settings__description">
            Choose a terminal theme and tune semantic colors. Status labels remain explicit so color never carries meaning alone.
          </p>
        </div>
        <span className="appearance-settings__source" role="status">{sourceLabel}</span>
      </header>

      <div className="appearance-settings__layout">
        <div className="appearance-settings__controls">
          <fieldset className="appearance-settings__fieldset">
            <legend>Theme</legend>
            {Object.values(THEME_PRESETS).map((preset) => (
              <label className="appearance-settings__choice" key={preset.id}>
                <input
                  type="radio"
                  name="appearance-theme"
                  value={preset.id}
                  checked={draft.theme_id === preset.id}
                  onChange={() => updateTheme(preset.id)}
                />
                <span>{preset.label}</span>
                <small>{preset.description}</small>
              </label>
            ))}
          </fieldset>

          <label className="appearance-settings__field" htmlFor="appearance-accent">
            <span>Accent palette</span>
            <select
              id="appearance-accent"
              value={draft.accent_id}
              onChange={(event) => updateAccent(event.currentTarget.value as AccentId)}
            >
              <option value="cyan">Terminal cyan</option>
              <option value="gold">Market gold</option>
              <option value="violet">Signal violet</option>
              <option value="emerald">Growth emerald</option>
            </select>
          </label>

          <details className="appearance-settings__editor" open>
            <summary>Custom semantic palette</summary>
            <p>Changes preview immediately. Invalid combinations keep the last valid palette applied.</p>
            <div className="appearance-settings__token-grid">
              {THEME_TOKENS.map((token) => (
                <label className="appearance-settings__color-field" key={token}>
                  <span>{tokenLabel(token)}</span>
                  <input
                    type="color"
                    aria-label={`Custom ${tokenLabel(token)} color`}
                    value={tokens[token]}
                    onChange={(event) => updateToken(token, event.currentTarget.value)}
                  />
                </label>
              ))}
            </div>
            <button
              className="appearance-settings__secondary"
              type="button"
              onClick={() => updateDraft({ ...draft, custom_tokens: {} })}
            >
              Reset custom colors
            </button>
          </details>
        </div>

        <aside className="appearance-settings__preview" aria-label="Live theme preview">
          <div className="appearance-settings__preview-card" style={{ backgroundColor: appliedTokens.surface }}>
            <span className="appearance-settings__preview-label">Live preview</span>
            <h2 style={{ color: appliedTokens.text }}>LEVIATHAN terminal</h2>
            <p style={{ color: appliedTokens.textMuted }}>Compact, clear, and yours.</p>
            <div className="appearance-settings__status-list">
              <span style={{ color: appliedTokens.positive }}>● Positive status</span>
              <span style={{ color: appliedTokens.warning }}>▲ Warning status</span>
              <span style={{ color: appliedTokens.danger }}>■ Danger status</span>
            </div>
            <div className="appearance-settings__chart-preview" aria-label="Chart series preview">
              {([
                appliedTokens.chartSeries1,
                appliedTokens.chartSeries2,
                appliedTokens.chartSeries3,
                appliedTokens.chartSeries4,
                appliedTokens.chartSeries5,
                appliedTokens.chartSeries6,
              ] as const).map((color, index) => (
                <span
                  key={`chart-${index + 1}`}
                  aria-label={`Chart series ${index + 1}`}
                  style={{ backgroundColor: color, height: `${28 + index * 7}px` }}
                />
              ))}
            </div>
            <button type="button" className="appearance-settings__preview-button" style={{
              backgroundColor: appliedTokens.accent,
              color: appliedTokens.textOnAccent,
            }}>
              Focusable control
            </button>
          </div>

          <section className="appearance-settings__validation" aria-labelledby="contrast-title">
            <h2 id="contrast-title">Contrast validation</h2>
            {contrast.valid ? (
              <p className="appearance-settings__valid">All required color pairs pass WCAG AA thresholds.</p>
            ) : (
              <div className="appearance-settings__failures" role="alert">
                <p>Palette not saved. Fix these color pairs:</p>
                <ul>
                  {contrast.failures.map((failure) => (
                    <li key={`${failure.foreground}-${failure.background}-${failure.kind}`}>
                      {tokenLabel(failure.foreground)} on {tokenLabel(failure.background)}: {failure.ratio.toFixed(2)}:1
                      (requires {failure.requiredRatio}:1)
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </section>
        </aside>
      </div>

      {serverConflict !== null && (
        <div className="appearance-settings__conflict" role="alert">
          <span>
            Server revision {serverConflict.record?.revision ?? "none"} differs from your draft. Your draft is preserved.
          </span>
          <button type="button" onClick={useServerVersion}>Load account version</button>
        </div>
      )}
      {message && <p className="appearance-settings__message" role="status">{message}</p>}
      <footer className="appearance-settings__footer">
        <button type="button" disabled={!contrast.valid || busy} onClick={() => void save()}>
          {busy ? "Saving…" : "Save appearance"}
        </button>
      </footer>
    </section>
  );
}
