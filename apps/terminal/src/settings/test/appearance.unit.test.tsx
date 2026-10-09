import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { validateThemeContrast, calculateContrastRatio } from "../../views/design/contrast";
import {
  ACCENT_PRESETS,
  getThemeTokens,
  THEME_PRESETS,
  type AccentId,
  type ThemeId,
} from "../../views/design/themeRegistry";
import { AppearanceSettings } from "../AppearanceSettings";
import {
  createAppearanceClient,
  createFakePreferencesPort,
  createMemoryAppearanceCache,
  DEFAULT_APPEARANCE_PREFERENCE,
  type VersionedAppearancePreferenceV1,
} from "../appearanceClient";

const SERVER_RECORD: VersionedAppearancePreferenceV1 = {
  preference: DEFAULT_APPEARANCE_PREFERENCE,
  revision: "rev-1",
  updated_at_ns: "1770000000000000000",
};

describe("theme contrast", () => {
  it("calculates WCAG contrast ratios for standard boundary colors", () => {
    expect(calculateContrastRatio("#000000", "#ffffff")).toBe(21);
    expect(calculateContrastRatio("#ffffff", "#ffffff")).toBe(1);
    expect(calculateContrastRatio("not-a-color", "#ffffff")).toBe(0);
  });

  it("keeps every built-in theme and named accent palette within the AA rules", () => {
    for (const themeId of Object.keys(THEME_PRESETS) as ThemeId[]) {
      for (const accentId of Object.keys(ACCENT_PRESETS) as AccentId[]) {
        const report = validateThemeContrast(getThemeTokens(themeId, accentId));
        expect(report.valid, `${themeId}/${accentId}: ${JSON.stringify(report.failures)}`).toBe(true);
      }
    }
  });

  it("reports each failing foreground/background token pair and threshold", () => {
    const tokens = getThemeTokens("dark", "cyan", { text: "#000000" });
    const report = validateThemeContrast(tokens);
    expect(report.valid).toBe(false);
    expect(report.failures).toContainEqual(
      expect.objectContaining({
        foreground: "text",
        background: "surface",
        requiredRatio: 4.5,
        passes: false,
      }),
    );
  });
});

describe("appearance preference client", () => {
  it("loads authenticated preference as authoritative and caches it", async () => {
    const port = createFakePreferencesPort(SERVER_RECORD);
    const cache = createMemoryAppearanceCache();
    const client = createAppearanceClient(port, cache);

    const loaded = await client.load();

    expect(loaded).toEqual({
      kind: "ready",
      source: "server",
      authoritative: true,
      record: SERVER_RECORD,
    });
    expect(await cache.read()).toEqual(SERVER_RECORD);
  });

  it("labels cached preferences as non-authoritative when the service is offline", async () => {
    const port = createFakePreferencesPort();
    port.setOffline(true);
    const cache = createMemoryAppearanceCache();
    await cache.write(SERVER_RECORD);
    const client = createAppearanceClient(port, cache);

    const loaded = await client.load();

    expect(loaded.kind).toBe("ready");
    if (loaded.kind === "ready") {
      expect(loaded.source).toBe("local-cache");
      expect(loaded.authoritative).toBe(false);
      expect(loaded.record.preference.theme_id).toBe("dark");
    }
  });

  it("stores a valid offline save only in cache and does not call it synced", async () => {
    const port = createFakePreferencesPort(SERVER_RECORD);
    port.setOffline(true);
    const cache = createMemoryAppearanceCache();
    const client = createAppearanceClient(port, cache);
    const preference = { ...DEFAULT_APPEARANCE_PREFERENCE, theme_id: "light" as const };

    const result = await client.save(preference, SERVER_RECORD.revision);

    expect(result.kind).toBe("offline-cache");
    if (result.kind === "offline-cache") {
      expect(result.authoritative).toBe(false);
      expect(result.source).toBe("local-cache");
      expect(result.record.preference.theme_id).toBe("light");
    }
    expect(port.snapshot()?.preference.theme_id).toBe("dark");
  });

  it("preserves the local draft on a server revision conflict", async () => {
    const port = createFakePreferencesPort(SERVER_RECORD);
    const cache = createMemoryAppearanceCache();
    const client = createAppearanceClient(port, cache);
    const changed = { ...DEFAULT_APPEARANCE_PREFERENCE, theme_id: "light" as const };
    const current: VersionedAppearancePreferenceV1 = {
      preference: { ...DEFAULT_APPEARANCE_PREFERENCE, accent_id: "gold" },
      revision: "rev-2",
      updated_at_ns: "1770000000000000001",
    };
    port.forceConflict(current);

    const result = await client.save(changed, SERVER_RECORD.revision);

    expect(result).toEqual({ kind: "conflict", current });
    expect(changed.theme_id).toBe("light");
    expect(port.snapshot()).toEqual(current);
  });

  it("refuses an invalid low-contrast palette before writing", async () => {
    const port = createFakePreferencesPort(SERVER_RECORD);
    const client = createAppearanceClient(port, createMemoryAppearanceCache());
    const invalid = {
      ...DEFAULT_APPEARANCE_PREFERENCE,
      custom_tokens: { text: "#000000" },
    };

    expect(await client.save(invalid, SERVER_RECORD.revision)).toEqual({ kind: "invalid" });
    expect(port.snapshot()).toEqual(SERVER_RECORD);
  });
});

describe("AppearanceSettings", () => {
  it("previews valid choices immediately and retains the applied palette for invalid edits", async () => {
    const port = createFakePreferencesPort(SERVER_RECORD);
    render(<AppearanceSettings preferencesPort={port} cache={createMemoryAppearanceCache()} />);
    await screen.findByText("Preferences loaded from the account.");

    fireEvent.click(screen.getByRole("radio", { name: /Light/ }));
    await waitFor(() => {
      expect(document.documentElement.dataset.theme).toBe("light");
    });
    const appliedLightSurface = document.documentElement.style.getPropertyValue("--theme-surface");
    expect(appliedLightSurface).toBe("#F3F6F8");

    fireEvent.input(screen.getByLabelText("Custom Text color"), {
      target: { value: "#FFFFFF" },
    });

    await waitFor(() => {
      expect(
        (screen.getByRole("button", { name: "Save appearance" }) as HTMLButtonElement).disabled,
      ).toBe(true);
    });
    expect(screen.getByText(/Fix these color pairs/)).toBeTruthy();
    expect(
      (screen.getByRole("button", { name: "Save appearance" }) as HTMLButtonElement).disabled,
    ).toBe(true);
    expect(document.documentElement.style.getPropertyValue("--theme-surface")).toBe(appliedLightSurface);
    expect(screen.getAllByText(/Text on Surface/).length).toBeGreaterThan(0);
  });

  it("saves only appearance preferences and labels the account-backed result", async () => {
    const port = createFakePreferencesPort(SERVER_RECORD);
    render(<AppearanceSettings preferencesPort={port} cache={createMemoryAppearanceCache()} />);
    await screen.findByText("Preferences loaded from the account.");
    fireEvent.click(screen.getByRole("button", { name: "Save appearance" }));

    expect(await screen.findByText("Appearance saved.")).toBeTruthy();
    expect(port.snapshot()?.preference.user_scope).toBe("user");
  });

  it("surfaces a conflict with no current record while preserving the draft", async () => {
    const port = createFakePreferencesPort(SERVER_RECORD);
    port.forceConflict(null);
    render(<AppearanceSettings preferencesPort={port} cache={createMemoryAppearanceCache()} />);
    await screen.findByText("Preferences loaded from the account.");
    fireEvent.click(screen.getByRole("button", { name: "Save appearance" }));

    expect(await screen.findByText(/Server revision none differs from your draft/)).toBeTruthy();
    expect(document.documentElement.dataset.theme).toBe("dark");
    expect(screen.getByRole("button", { name: "Save appearance" })).toBeTruthy();
  });
});
