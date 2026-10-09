export type ThemeId = "dark" | "light" | "high-contrast";
export type AccentId = "cyan" | "gold" | "violet" | "emerald";

export const THEME_TOKENS = [
  "surface",
  "surfaceRaised",
  "surfaceOverlay",
  "text",
  "textMuted",
  "textOnAccent",
  "border",
  "borderStrong",
  "focus",
  "selection",
  "selectionText",
  "accent",
  "positive",
  "positiveSurface",
  "warning",
  "warningSurface",
  "danger",
  "dangerSurface",
  "chartSeries1",
  "chartSeries2",
  "chartSeries3",
  "chartSeries4",
  "chartSeries5",
  "chartSeries6",
  "overlay",
] as const;

export type ThemeToken = (typeof THEME_TOKENS)[number];
export type ThemeTokens = Readonly<Record<ThemeToken, string>>;
export type ThemeTokenOverrides = Partial<Record<ThemeToken, string>>;

export interface ThemePreset {
  readonly id: ThemeId;
  readonly label: string;
  readonly description: string;
  readonly tokens: ThemeTokens;
}

export interface AccentPreset {
  readonly id: AccentId;
  readonly label: string;
  readonly darkColor: string;
  readonly lightColor: string;
  readonly textOnDarkColor: string;
  readonly textOnLightColor: string;
}

const DARK_TOKENS: ThemeTokens = {
  surface: "#080C10",
  surfaceRaised: "#111923",
  surfaceOverlay: "#1A2530",
  text: "#F4F7FA",
  textMuted: "#B8C2CC",
  textOnAccent: "#071116",
  border: "#728191",
  borderStrong: "#AAB6C1",
  focus: "#55E5D3",
  selection: "#174456",
  selectionText: "#F4FBFF",
  accent: "#55E5D3",
  positive: "#55E2A7",
  positiveSurface: "#15372B",
  warning: "#FFD166",
  warningSurface: "#42351C",
  danger: "#FF7D87",
  dangerSurface: "#48242A",
  chartSeries1: "#55E5D3",
  chartSeries2: "#74B8FF",
  chartSeries3: "#D4A3FF",
  chartSeries4: "#FFD166",
  chartSeries5: "#FF8797",
  chartSeries6: "#8BE5A1",
  overlay: "#91A1B3",
};

const LIGHT_TOKENS: ThemeTokens = {
  surface: "#F3F6F8",
  surfaceRaised: "#FFFFFF",
  surfaceOverlay: "#E6EDF2",
  text: "#15202B",
  textMuted: "#405262",
  textOnAccent: "#FFFFFF",
  border: "#667887",
  borderStrong: "#354A5A",
  focus: "#006F78",
  selection: "#B9E8EA",
  selectionText: "#10252B",
  accent: "#006F78",
  positive: "#17663D",
  positiveSurface: "#DDF2E5",
  warning: "#775400",
  warningSurface: "#F5E8C5",
  danger: "#9E2737",
  dangerSurface: "#F7E0E2",
  chartSeries1: "#006F78",
  chartSeries2: "#0059A8",
  chartSeries3: "#7043A4",
  chartSeries4: "#775400",
  chartSeries5: "#9E2737",
  chartSeries6: "#17663D",
  overlay: "#4B6173",
};

const HIGH_CONTRAST_TOKENS: ThemeTokens = {
  surface: "#000000",
  surfaceRaised: "#000000",
  surfaceOverlay: "#111111",
  text: "#FFFFFF",
  textMuted: "#F0F0F0",
  textOnAccent: "#000000",
  border: "#FFFFFF",
  borderStrong: "#FFFFFF",
  focus: "#FFFF00",
  selection: "#005FCC",
  selectionText: "#FFFFFF",
  accent: "#00FFFF",
  positive: "#00FF66",
  positiveSurface: "#003311",
  warning: "#FFFF00",
  warningSurface: "#333300",
  danger: "#FF6677",
  dangerSurface: "#330011",
  chartSeries1: "#00FFFF",
  chartSeries2: "#FFFF00",
  chartSeries3: "#FF66FF",
  chartSeries4: "#66FF66",
  chartSeries5: "#FF9966",
  chartSeries6: "#6699FF",
  overlay: "#FFFFFF",
};

export const THEME_PRESETS: Readonly<Record<ThemeId, ThemePreset>> = Object.freeze({
  dark: Object.freeze({
    id: "dark",
    label: "Dark",
    description: "Deep-black terminal with cyan highlights.",
    tokens: Object.freeze({ ...DARK_TOKENS }),
  }),
  light: Object.freeze({
    id: "light",
    label: "Light",
    description: "High-legibility light surfaces with the same compact density.",
    tokens: Object.freeze({ ...LIGHT_TOKENS }),
  }),
  "high-contrast": Object.freeze({
    id: "high-contrast",
    label: "High contrast",
    description: "Maximum contrast with clear borders and focus indicators.",
    tokens: Object.freeze({ ...HIGH_CONTRAST_TOKENS }),
  }),
});

export const ACCENT_PRESETS: Readonly<Record<AccentId, AccentPreset>> = Object.freeze({
  cyan: Object.freeze({
    id: "cyan",
    label: "Terminal cyan",
    darkColor: "#55E5D3",
    lightColor: "#006F78",
    textOnDarkColor: "#071116",
    textOnLightColor: "#FFFFFF",
  }),
  gold: Object.freeze({
    id: "gold",
    label: "Market gold",
    darkColor: "#FFD166",
    lightColor: "#775400",
    textOnDarkColor: "#171103",
    textOnLightColor: "#FFFFFF",
  }),
  violet: Object.freeze({
    id: "violet",
    label: "Signal violet",
    darkColor: "#D4A3FF",
    lightColor: "#7043A4",
    textOnDarkColor: "#140A20",
    textOnLightColor: "#FFFFFF",
  }),
  emerald: Object.freeze({
    id: "emerald",
    label: "Growth emerald",
    darkColor: "#8BE5A1",
    lightColor: "#17663D",
    textOnDarkColor: "#07170B",
    textOnLightColor: "#FFFFFF",
  }),
});

const CSS_VARIABLES: Readonly<Record<ThemeToken, string>> = Object.freeze(
  Object.fromEntries(
    THEME_TOKENS.map((token) => [
      token,
      `--theme-${token.replace(/[A-Z0-9]/g, (letter) => `-${letter.toLowerCase()}`)}`,
    ]),
  ) as Record<ThemeToken, string>,
);

function assertThemeId(value: ThemeId): void {
  if (!Object.hasOwn(THEME_PRESETS, value)) throw new TypeError("Unknown theme preset");
}

function assertAccentId(value: AccentId): void {
  if (!Object.hasOwn(ACCENT_PRESETS, value)) throw new TypeError("Unknown accent preset");
}

export function getThemeTokens(
  themeId: ThemeId,
  accentId: AccentId,
  customTokens: ThemeTokenOverrides = {},
): ThemeTokens {
  assertThemeId(themeId);
  assertAccentId(accentId);
  const preset = THEME_PRESETS[themeId].tokens;
  const accent = ACCENT_PRESETS[accentId];
  const accentColor = themeId === "light" ? accent.lightColor : accent.darkColor;
  const textOnAccent = themeId === "light" ? accent.textOnLightColor : accent.textOnDarkColor;
  return Object.freeze({
    ...preset,
    accent: accentColor,
    textOnAccent,
    chartSeries1: accentColor,
    ...customTokens,
  });
}

export function applyThemeTokens(
  tokens: ThemeTokens,
  themeId: ThemeId,
  accentId: AccentId,
  root: HTMLElement = document.documentElement,
): void {
  assertThemeId(themeId);
  assertAccentId(accentId);
  root.dataset.theme = themeId;
  root.dataset.accent = accentId;
  for (const token of THEME_TOKENS) {
    root.style.setProperty(CSS_VARIABLES[token], tokens[token]);
  }
  root.style.colorScheme = themeId === "light" ? "light" : "dark";
}
