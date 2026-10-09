import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AppearanceSettings } from "../AppearanceSettings";
import {
  createFakePreferencesPort,
  createMemoryAppearanceCache,
  DEFAULT_APPEARANCE_PREFERENCE,
  type AppearancePreferenceV1,
  type VersionedAppearancePreferenceV1,
} from "../appearanceClient";
import { calculateContrastRatio, validateThemeContrast } from "../../views/design/contrast";
import {
  ACCENT_PRESETS,
  getThemeTokens,
  THEME_PRESETS,
  type AccentId,
  type ThemeId,
} from "../../views/design/themeRegistry";

afterEach(() => {
  document.documentElement.removeAttribute("style");
  document.documentElement.removeAttribute("data-theme");
  document.documentElement.removeAttribute("data-accent");
});

function record(
  preference: AppearancePreferenceV1 = DEFAULT_APPEARANCE_PREFERENCE,
  revision = "rev-1",
): VersionedAppearancePreferenceV1 {
  return { preference, revision, updated_at_ns: "1770000000000000000" };
}

async function renderAppearance(
  initial: VersionedAppearancePreferenceV1 | null = record(),
) {
  const preferencesPort = createFakePreferencesPort(initial);
  const cache = createMemoryAppearanceCache();
  const view = render(<AppearanceSettings preferencesPort={preferencesPort} cache={cache} />);
  await screen.findByText("Preferences loaded from the account.");
  return { ...view, preferencesPort, cache };
}

describe("THEME-001 independent acceptance", () => {
  it("keeps every built-in theme and accent within all AA text and control thresholds", () => {
    for (const themeId of Object.keys(THEME_PRESETS) as ThemeId[]) {
      for (const accentId of Object.keys(ACCENT_PRESETS) as AccentId[]) {
        const report = validateThemeContrast(getThemeTokens(themeId, accentId));
        expect(report.valid, `${themeId}/${accentId} failures: ${JSON.stringify(report.failures)}`).toBe(true);
        expect(report.pairs.length).toBeGreaterThan(0);
        for (const pair of report.pairs) {
          const minimum = pair.kind === "regular-text" ? 4.5 : 3;
          expect(pair.requiredRatio).toBe(minimum);
          expect(pair.ratio).toBeGreaterThanOrEqual(minimum);
          expect(pair.passes).toBe(true);
        }
      }
    }
  });

  it("matches independently known WCAG contrast ratios and enforces the 4.5 text boundary", () => {
    expect(calculateContrastRatio("#000000", "#ffffff")).toBeCloseTo(21, 10);
    expect(calculateContrastRatio("#777777", "#ffffff")).toBeCloseTo(4.478089, 5);
    expect(calculateContrastRatio("#767676", "#ffffff")).toBeCloseTo(4.542225, 5);
    expect(calculateContrastRatio("#ffffff", "#ffffff")).toBe(1);
  });

  it("rejects a failing custom palette, names the failing pair, and keeps the last valid palette applied", async () => {
    const { preferencesPort } = await renderAppearance();
    const write = vi.spyOn(preferencesPort, "write");
    const root = document.documentElement;
    const lastValidText = root.style.getPropertyValue("--theme-text");
    const lastValidSurface = root.style.getPropertyValue("--theme-surface");

    fireEvent.input(screen.getByLabelText("Custom Text color"), {
      target: { value: lastValidSurface },
    });

    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("Text on Surface:");
    expect((screen.getByRole("button", { name: "Save appearance" }) as HTMLButtonElement).disabled).toBe(true);
    expect(root.style.getPropertyValue("--theme-text")).toBe(lastValidText);
    expect(root.style.getPropertyValue("--theme-surface")).toBe(lastValidSurface);
    fireEvent.click(screen.getByRole("button", { name: "Save appearance" }));
    expect(write).not.toHaveBeenCalled();
  });

  it("applies a selected theme to root custom properties without replacing the document", async () => {
    await renderAppearance();
    const root = document.documentElement;
    const documentBefore = document;

    fireEvent.click(screen.getByRole("radio", { name: /Light/ }));

    await waitFor(() => {
      expect(root.dataset.theme).toBe("light");
      expect(root.style.getPropertyValue("--theme-surface")).toBe("#F3F6F8");
    });
    expect(document).toBe(documentBefore);
    expect(root).toBe(document.documentElement);
    expect(root.style.getPropertyValue("--theme-text")).toBe("#15202B");
  });

  it("keeps status meaning in visible text and exposes keyboard-focusable labelled controls", async () => {
    await renderAppearance();
    const description = screen.getByText(/Status labels remain explicit/);
    expect(description).toBeTruthy();
    expect(screen.getByText(/Positive status/)).toBeTruthy();
    expect(screen.getByText(/Warning status/)).toBeTruthy();
    expect(screen.getByText(/Danger status/)).toBeTruthy();

    const lightRadio = screen.getByRole("radio", { name: /Light/ }) as HTMLInputElement;
    const accent = screen.getByRole("combobox", { name: /Accent palette/ }) as HTMLSelectElement;
    const color = screen.getByLabelText("Custom Text color") as HTMLInputElement;
    const save = screen.getByRole("button", { name: "Save appearance" }) as HTMLButtonElement;
    for (const control of [lightRadio, accent, color, save]) {
      expect(control.tabIndex).toBeGreaterThanOrEqual(0);
      control.focus();
      expect(document.activeElement).toBe(control);
    }
    expect(lightRadio.labels?.length).toBeGreaterThan(0);
  });

  it("honors reduced-motion preferences in the loaded theme stylesheet", async () => {
    await renderAppearance();
    const mediaRules = Array.from(document.styleSheets).flatMap((sheet) => {
      try {
        return Array.from(sheet.cssRules).filter(
          (rule): rule is CSSMediaRule => rule instanceof CSSMediaRule,
        );
      } catch {
        return [];
      }
    });
    const reducedMotion = mediaRules.find((rule) => rule.conditionText.includes("prefers-reduced-motion: reduce"));
    expect(reducedMotion).toBeDefined();
    const cssText = Array.from(reducedMotion?.cssRules ?? []).map((rule) => rule.cssText).join("\n");
    expect(cssText).toContain("animation-duration: 0.01ms");
    expect(cssText).toContain("transition-duration: 0.01ms");
  });

  it("persists through the injected PreferencesPort and labels local cache as non-authoritative", async () => {
    const saved = await renderAppearance();
    const write = vi.spyOn(saved.preferencesPort, "write");
    const storageWrite = vi.spyOn(Storage.prototype, "setItem");

    fireEvent.click(screen.getByRole("button", { name: "Save appearance" }));
    expect(await screen.findByText("Appearance saved.")).toBeTruthy();
    expect(write).toHaveBeenCalledTimes(1);
    expect(write).toHaveBeenCalledWith(
      "appearance",
      expect.objectContaining({ schema_version: 1, user_scope: "user" }),
      "rev-1",
    );
    expect(storageWrite).not.toHaveBeenCalled();
    saved.unmount();

    const offlinePort = createFakePreferencesPort(record());
    offlinePort.setOffline(true);
    const offlineCache = createMemoryAppearanceCache();
    await offlineCache.write(record({ ...DEFAULT_APPEARANCE_PREFERENCE, theme_id: "light" }));
    render(<AppearanceSettings preferencesPort={offlinePort} cache={offlineCache} />);
    expect(await screen.findByText(/Local cache only.*not authoritative or synced across devices/)).toBeTruthy();
    expect(document.documentElement.dataset.theme).toBe("light");
  });

  it("preserves an unsaved draft when the server reports a newer revision", async () => {
    const { preferencesPort } = await renderAppearance();
    const draft = { ...DEFAULT_APPEARANCE_PREFERENCE, theme_id: "light" as const };
    fireEvent.click(screen.getByRole("radio", { name: /Light/ }));
    preferencesPort.forceConflict(
      record({ ...DEFAULT_APPEARANCE_PREFERENCE, theme_id: "high-contrast", accent_id: "gold" }, "rev-2"),
    );

    fireEvent.click(screen.getByRole("button", { name: "Save appearance" }));
    expect((await screen.findByRole("alert")).textContent).toMatch(/Your draft is preserved/);
    expect((screen.getByRole("radio", { name: /Light/ }) as HTMLInputElement).checked).toBe(true);
    expect(document.documentElement.dataset.theme).toBe(draft.theme_id);
    expect(document.documentElement.style.getPropertyValue("--theme-surface")).toBe("#F3F6F8");
  });
});
