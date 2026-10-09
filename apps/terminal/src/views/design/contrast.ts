import type { ThemeToken, ThemeTokens } from "./themeRegistry";

export type ContrastKind = "regular-text" | "large-text" | "control";

export interface ContrastPairResult {
  readonly foreground: ThemeToken;
  readonly background: ThemeToken;
  readonly kind: ContrastKind;
  readonly ratio: number;
  readonly requiredRatio: number;
  readonly passes: boolean;
}

export interface ContrastFailure extends ContrastPairResult {}

export interface ContrastReport {
  readonly valid: boolean;
  readonly pairs: readonly ContrastPairResult[];
  readonly failures: readonly ContrastFailure[];
}

interface ContrastPairSpec {
  readonly foreground: ThemeToken;
  readonly background: ThemeToken;
  readonly kind: ContrastKind;
}

const PAIRS: readonly ContrastPairSpec[] = [
  { foreground: "text", background: "surface", kind: "regular-text" },
  { foreground: "text", background: "surfaceRaised", kind: "regular-text" },
  { foreground: "text", background: "surfaceOverlay", kind: "regular-text" },
  { foreground: "textMuted", background: "surface", kind: "regular-text" },
  { foreground: "textMuted", background: "surfaceRaised", kind: "regular-text" },
  { foreground: "textMuted", background: "surfaceOverlay", kind: "regular-text" },
  { foreground: "textOnAccent", background: "accent", kind: "regular-text" },
  { foreground: "selectionText", background: "selection", kind: "regular-text" },
  { foreground: "text", background: "positiveSurface", kind: "regular-text" },
  { foreground: "text", background: "warningSurface", kind: "regular-text" },
  { foreground: "text", background: "dangerSurface", kind: "regular-text" },
  { foreground: "positive", background: "surface", kind: "regular-text" },
  { foreground: "warning", background: "surface", kind: "regular-text" },
  { foreground: "danger", background: "surface", kind: "regular-text" },
  { foreground: "text", background: "surfaceOverlay", kind: "large-text" },
  { foreground: "border", background: "surface", kind: "control" },
  { foreground: "border", background: "surfaceRaised", kind: "control" },
  { foreground: "borderStrong", background: "surface", kind: "control" },
  { foreground: "borderStrong", background: "surfaceRaised", kind: "control" },
  { foreground: "focus", background: "surface", kind: "control" },
  { foreground: "focus", background: "surfaceRaised", kind: "control" },
  { foreground: "overlay", background: "surface", kind: "control" },
  ...(
    ["chartSeries1", "chartSeries2", "chartSeries3", "chartSeries4", "chartSeries5", "chartSeries6"] as const
  ).flatMap((foreground) => [
    { foreground, background: "surface" as const, kind: "control" as const },
    { foreground, background: "surfaceRaised" as const, kind: "control" as const },
  ]),
];

const MINIMUMS: Readonly<Record<ContrastKind, number>> = {
  "regular-text": 4.5,
  "large-text": 3,
  control: 3,
};

function parseHexColor(color: string): readonly [number, number, number] | null {
  if (typeof color !== "string") return null;
  const match = /^#([0-9a-f]{3}|[0-9a-f]{6})$/i.exec(color);
  if (!match) return null;
  const digits = match[1];
  const expanded = digits.length === 3 ? [...digits].map((part) => part + part).join("") : digits;
  return [
    Number.parseInt(expanded.slice(0, 2), 16) / 255,
    Number.parseInt(expanded.slice(2, 4), 16) / 255,
    Number.parseInt(expanded.slice(4, 6), 16) / 255,
  ];
}

function linearize(channel: number): number {
  return channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4;
}

function relativeLuminance(color: string): number | null {
  const rgb = parseHexColor(color);
  if (!rgb) return null;
  return 0.2126 * linearize(rgb[0]) + 0.7152 * linearize(rgb[1]) + 0.0722 * linearize(rgb[2]);
}

export function calculateContrastRatio(foreground: string, background: string): number {
  const foregroundLuminance = relativeLuminance(foreground);
  const backgroundLuminance = relativeLuminance(background);
  if (foregroundLuminance === null || backgroundLuminance === null) return 0;
  const light = Math.max(foregroundLuminance, backgroundLuminance);
  const dark = Math.min(foregroundLuminance, backgroundLuminance);
  return (light + 0.05) / (dark + 0.05);
}

export function validateThemeContrast(tokens: ThemeTokens): ContrastReport {
  const pairs = PAIRS.map((pair) => {
    const ratio = calculateContrastRatio(tokens[pair.foreground], tokens[pair.background]);
    const requiredRatio = MINIMUMS[pair.kind];
    return {
      ...pair,
      ratio,
      requiredRatio,
      passes: Number.isFinite(ratio) && ratio >= requiredRatio,
    };
  });
  const failures = pairs.filter((pair) => !pair.passes);
  return {
    valid: failures.length === 0,
    pairs,
    failures,
  };
}
