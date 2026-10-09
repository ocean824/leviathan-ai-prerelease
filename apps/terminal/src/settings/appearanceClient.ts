import {
  ACCENT_PRESETS,
  getThemeTokens,
  THEME_PRESETS,
  THEME_TOKENS,
  type AccentId,
  type ThemeId,
  type ThemeToken,
  type ThemeTokenOverrides,
  type ThemeTokens,
} from "../views/design/themeRegistry";
import { validateThemeContrast } from "../views/design/contrast";

export const APPEARANCE_NAMESPACE = "appearance" as const;

export interface AppearancePreferenceV1 {
  readonly schema_version: 1;
  readonly user_scope: "user";
  readonly theme_id: ThemeId;
  readonly accent_id: AccentId;
  readonly custom_tokens: ThemeTokenOverrides;
}

export interface VersionedAppearancePreferenceV1 {
  readonly preference: AppearancePreferenceV1;
  readonly revision: string;
  readonly updated_at_ns: string;
}

export type PreferenceReadResult =
  | { readonly status: "fresh"; readonly record: VersionedAppearancePreferenceV1 | null }
  | { readonly status: "offline" };

export type PreferenceWriteResult =
  | { readonly status: "saved"; readonly record: VersionedAppearancePreferenceV1 }
  | {
      readonly status: "conflict";
      readonly current: VersionedAppearancePreferenceV1 | null;
    }
  | { readonly status: "offline" };

export interface PreferencesPort {
  read(namespace: typeof APPEARANCE_NAMESPACE): Promise<PreferenceReadResult>;
  write(
    namespace: typeof APPEARANCE_NAMESPACE,
    preference: AppearancePreferenceV1,
    expectedRevision: string | null,
  ): Promise<PreferenceWriteResult>;
}

export interface AppearanceCachePort {
  read(): Promise<VersionedAppearancePreferenceV1 | null>;
  write(record: VersionedAppearancePreferenceV1): Promise<void>;
  clear(): Promise<void>;
}

export type AppearanceLoadResult =
  | {
      readonly kind: "ready";
      readonly source: "server";
      readonly authoritative: true;
      readonly record: VersionedAppearancePreferenceV1;
    }
  | {
      readonly kind: "ready";
      readonly source: "local-cache";
      readonly authoritative: false;
      readonly record: VersionedAppearancePreferenceV1;
    }
  | {
      readonly kind: "default";
      readonly source: "default";
      readonly authoritative: false;
      readonly record: null;
    };

export type AppearanceSaveResult =
  | {
      readonly kind: "saved";
      readonly source: "server";
      readonly authoritative: true;
      readonly record: VersionedAppearancePreferenceV1;
    }
  | {
      readonly kind: "offline-cache";
      readonly source: "local-cache";
      readonly authoritative: false;
      readonly record: VersionedAppearancePreferenceV1;
    }
  | {
      readonly kind: "conflict";
      readonly current: VersionedAppearancePreferenceV1 | null;
    }
  | { readonly kind: "invalid" };

const CACHE_KEY = "xyra.appearance.preference.v1";
const HEX_COLOR = /^#[0-9a-f]{6}$/i;

export const DEFAULT_APPEARANCE_PREFERENCE: AppearancePreferenceV1 = Object.freeze({
  schema_version: 1,
  user_scope: "user",
  theme_id: "dark",
  accent_id: "cyan",
  custom_tokens: Object.freeze({}),
});

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function isAppearancePreferenceV1(value: unknown): value is AppearancePreferenceV1 {
  if (!isRecord(value)) return false;
  if (
    Object.keys(value).some(
      (key) => !["schema_version", "user_scope", "theme_id", "accent_id", "custom_tokens"].includes(key),
    )
  ) {
    return false;
  }
  if (value.schema_version !== 1 || value.user_scope !== "user") return false;
  if (typeof value.theme_id !== "string" || !Object.hasOwn(THEME_PRESETS, value.theme_id)) return false;
  if (typeof value.accent_id !== "string" || !Object.hasOwn(ACCENT_PRESETS, value.accent_id)) return false;
  if (!isRecord(value.custom_tokens)) return false;
  if (Object.keys(value.custom_tokens).some((token) => !THEME_TOKENS.includes(token as ThemeToken))) {
    return false;
  }
  return Object.values(value.custom_tokens).every(
    (color) => typeof color === "string" && HEX_COLOR.test(color),
  );
}

function isVersionedPreference(value: unknown): value is VersionedAppearancePreferenceV1 {
  return (
    isRecord(value) &&
    Object.keys(value).every((key) => ["preference", "revision", "updated_at_ns"].includes(key)) &&
    isAppearancePreferenceV1(value.preference) &&
    typeof value.revision === "string" &&
    value.revision.length <= 128 &&
    typeof value.updated_at_ns === "string" &&
    /^[0-9]{1,32}$/.test(value.updated_at_ns)
  );
}

export function createMemoryAppearanceCache(): AppearanceCachePort {
  let cached: VersionedAppearancePreferenceV1 | null = null;
  return {
    async read() {
      return cached;
    },
    async write(record) {
      cached = record;
    },
    async clear() {
      cached = null;
    },
  };
}

export function createBrowserAppearanceCache(storage?: Storage): AppearanceCachePort {
  let browserStorage = storage;
  if (!browserStorage && typeof window !== "undefined") {
    try {
      browserStorage = window.localStorage;
    } catch {
      browserStorage = undefined;
    }
  }
  return {
    async read() {
      try {
        const raw = browserStorage?.getItem(CACHE_KEY);
        if (!raw) return null;
        const value: unknown = JSON.parse(raw);
        return isVersionedPreference(value) ? value : null;
      } catch {
        return null;
      }
    },
    async write(record) {
      try {
        browserStorage?.setItem(CACHE_KEY, JSON.stringify(record));
      } catch {
        // Local cache is optional; the server remains the only authority.
      }
    },
    async clear() {
      try {
        browserStorage?.removeItem(CACHE_KEY);
      } catch {
        // Local cache is optional; the server remains the only authority.
      }
    },
  };
}

function makeLocalRecord(
  preference: AppearancePreferenceV1,
  previous: VersionedAppearancePreferenceV1 | null,
): VersionedAppearancePreferenceV1 {
  return Object.freeze({
    preference,
    revision: previous?.revision ?? "local-cache",
    updated_at_ns: (BigInt(Date.now()) * 1_000_000n).toString(),
  });
}

function isContrastValid(preference: AppearancePreferenceV1): boolean {
  const tokens = getThemeTokens(
    preference.theme_id,
    preference.accent_id,
    preference.custom_tokens,
  ) as ThemeTokens;
  return validateThemeContrast(tokens).valid;
}

export interface AppearanceClient {
  load(): Promise<AppearanceLoadResult>;
  save(
    preference: AppearancePreferenceV1,
    expectedRevision: string | null,
  ): Promise<AppearanceSaveResult>;
  clearCache(): Promise<void>;
}

export function createAppearanceClient(
  preferencesPort: PreferencesPort,
  cache: AppearanceCachePort = createBrowserAppearanceCache(),
): AppearanceClient {
  return {
    async load() {
      try {
        const response = await preferencesPort.read(APPEARANCE_NAMESPACE);
        if (response.status === "fresh" && response.record === null) {
          await cache.clear();
          return { kind: "default", source: "default", authoritative: false, record: null };
        }
        if (response.status === "fresh" && isVersionedPreference(response.record)) {
          await cache.write(response.record);
          return {
            kind: "ready",
            source: "server",
            authoritative: true,
            record: response.record,
          };
        }
      } catch {
        // A transport exception is an offline read; never promote cache to authority.
      }
      const cached = await cache.read();
      if (cached && isVersionedPreference(cached)) {
        return {
          kind: "ready",
          source: "local-cache",
          authoritative: false,
          record: cached,
        };
      }
      return { kind: "default", source: "default", authoritative: false, record: null };
    },
    async save(preference, expectedRevision) {
      if (!isAppearancePreferenceV1(preference) || !isContrastValid(preference)) {
        return { kind: "invalid" };
      }
      try {
        const response = await preferencesPort.write(
          APPEARANCE_NAMESPACE,
          preference,
          expectedRevision,
        );
        if (response.status === "saved" && isVersionedPreference(response.record)) {
          await cache.write(response.record);
          return {
            kind: "saved",
            source: "server",
            authoritative: true,
            record: response.record,
          };
        }
        if (response.status === "conflict") {
          return { kind: "conflict", current: response.current };
        }
      } catch {
        // Fall through to the labelled, non-authoritative local cache.
      }
      const previous = await cache.read();
      const record = makeLocalRecord(preference, previous);
      await cache.write(record);
      return {
        kind: "offline-cache",
        source: "local-cache",
        authoritative: false,
        record,
      };
    },
    async clearCache() {
      await cache.clear();
    },
  };
}

export interface FakePreferencesPort extends PreferencesPort {
  setOffline(offline: boolean): void;
  forceConflict(record: VersionedAppearancePreferenceV1 | null): void;
  snapshot(): VersionedAppearancePreferenceV1 | null;
}

export function createFakePreferencesPort(
  initial: VersionedAppearancePreferenceV1 | null = null,
): FakePreferencesPort {
  let current = initial;
  let offline = false;
  let forcedConflict: VersionedAppearancePreferenceV1 | null | undefined;
  return {
    setOffline(value) {
      offline = value;
    },
    forceConflict(record) {
      forcedConflict = record;
    },
    snapshot() {
      return current;
    },
    async read(namespace) {
      if (namespace !== APPEARANCE_NAMESPACE || offline) return { status: "offline" };
      return { status: "fresh", record: current };
    },
    async write(namespace, preference, expectedRevision) {
      if (namespace !== APPEARANCE_NAMESPACE || offline) return { status: "offline" };
      if (forcedConflict !== undefined) {
        current = forcedConflict;
        forcedConflict = undefined;
        return { status: "conflict", current };
      }
      if (expectedRevision !== (current?.revision ?? null)) {
        return { status: "conflict", current };
      }
      const revision = String((Number(current?.revision ?? 0) || 0) + 1);
      current = {
        preference,
        revision,
        updated_at_ns: (BigInt(Date.now()) * 1_000_000n).toString(),
      };
      return { status: "saved", record: current };
    },
  };
}
