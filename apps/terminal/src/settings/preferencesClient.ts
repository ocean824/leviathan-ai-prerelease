/** Revisioned user-preference client. Local cache is a labelled convenience only. */

export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue };

export interface UserPreferencesV1 {
  schema_version: 1;
  user_scope: string;
  namespace: string;
  document: Record<string, JsonValue>;
  /** Canonical decimal string: epoch nanoseconds exceed Number.MAX_SAFE_INTEGER. */
  updated_at_ns: string;
  revision: number;
}

export interface LocalPreferencesCacheEntry {
  source: "local-cache";
  cached_at_ms: number;
  record: UserPreferencesV1;
}

export interface PreferencesCachePortV1 {
  get(key: string): LocalPreferencesCacheEntry | undefined;
  set(key: string, entry: LocalPreferencesCacheEntry): void;
  delete(key: string): void;
}

export interface PreferencesClientOptions {
  fetchImpl?: typeof fetch;
  cache?: PreferencesCachePortV1;
  basePath?: string;
  nowMs?: () => number;
}

export class PreferencesHttpError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string) {
    super(code);
    this.name = "PreferencesHttpError";
    this.status = status;
    this.code = code;
  }
}

export class PreferencesConflictError extends PreferencesHttpError {
  readonly current: UserPreferencesV1 | null;
  readonly draft: Record<string, JsonValue>;

  constructor(current: UserPreferencesV1 | null, draft: Record<string, JsonValue>) {
    super(409, "REVISION_CONFLICT");
    this.name = "PreferencesConflictError";
    this.current = current;
    this.draft = cloneDocument(draft);
  }
}

function cloneDocument(document: Record<string, JsonValue>): Record<string, JsonValue> {
  return JSON.parse(JSON.stringify(document)) as Record<string, JsonValue>;
}

function isRecord(value: unknown): value is UserPreferencesV1 {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const candidate = value as Record<string, unknown>;
  return (
    candidate.schema_version === 1 &&
    typeof candidate.user_scope === "string" &&
    typeof candidate.namespace === "string" &&
    typeof candidate.document === "object" &&
    candidate.document !== null &&
    !Array.isArray(candidate.document) &&
    isCanonicalNs(candidate.updated_at_ns) &&
    Number.isSafeInteger(candidate.revision)
  );
}

function isCanonicalNs(value: unknown): value is string {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]{0,18})$/.test(value)) return false;
  return value.length < 19 || value <= "9223372036854775807";
}

function safeErrorCode(value: unknown, fallback: string): string {
  if (typeof value !== "object" || value === null) return fallback;
  const error = (value as { error?: unknown }).error;
  if (typeof error !== "object" || error === null) return fallback;
  const code = (error as { code?: unknown }).code;
  return typeof code === "string" && /^[A-Z][A-Z0-9_]{0,63}$/.test(code) ? code : fallback;
}

export class PreferencesClient {
  private readonly fetchImpl: typeof fetch;
  private readonly cache?: PreferencesCachePortV1;
  private readonly basePath: string;
  private readonly nowMs: () => number;

  constructor(options: PreferencesClientOptions = {}) {
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.cache = options.cache;
    this.basePath = (options.basePath ?? "/api/preferences").replace(/\/$/, "");
    this.nowMs = options.nowMs ?? Date.now;
  }

  async get(namespace: string): Promise<UserPreferencesV1> {
    const response = await this.fetchImpl(this.url(namespace), {
      method: "GET",
      credentials: "same-origin",
      cache: "no-store",
      headers: { Accept: "application/json" },
    });
    const payload: unknown = await response.json().catch(() => undefined);
    if (!response.ok) throw new PreferencesHttpError(response.status, safeErrorCode(payload, "PREFERENCES_UNAVAILABLE"));
    if (!isRecord(payload)) throw new PreferencesHttpError(502, "PREFERENCES_INVALID_RESPONSE");
    this.remember(namespace, payload);
    return payload;
  }

  async put(
    namespace: string,
    document: Record<string, JsonValue>,
    expectedRevision: number | "*",
  ): Promise<UserPreferencesV1> {
    const response = await this.fetchImpl(this.url(namespace), {
      method: "PUT",
      credentials: "same-origin",
      cache: "no-store",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        "If-Match": expectedRevision === "*" ? "*" : String(expectedRevision),
      },
      body: JSON.stringify({ document }),
    });
    const payload: unknown = await response.json().catch(() => undefined);
    if (response.status === 409) {
      const currentValue =
        typeof payload === "object" && payload !== null
          ? (payload as { current?: unknown }).current
          : undefined;
      const current = isRecord(currentValue) ? currentValue : null;
      if (current !== null) this.remember(namespace, current);
      throw new PreferencesConflictError(current, document);
    }
    if (!response.ok) throw new PreferencesHttpError(response.status, safeErrorCode(payload, "PREFERENCES_UNAVAILABLE"));
    if (!isRecord(payload)) throw new PreferencesHttpError(502, "PREFERENCES_INVALID_RESPONSE");
    this.remember(namespace, payload);
    return payload;
  }

  async delete(namespace: string): Promise<void> {
    const response = await this.fetchImpl(this.url(namespace), {
      method: "DELETE",
      credentials: "same-origin",
      cache: "no-store",
      headers: { Accept: "application/json" },
    });
    if (!response.ok) {
      const payload: unknown = await response.json().catch(() => undefined);
      throw new PreferencesHttpError(response.status, safeErrorCode(payload, "PREFERENCES_UNAVAILABLE"));
    }
    this.cache?.delete(namespace);
  }

  getCached(namespace: string): LocalPreferencesCacheEntry | undefined {
    const entry = this.cache?.get(namespace);
    if (entry === undefined || entry.source !== "local-cache") return undefined;
    return { source: "local-cache", cached_at_ms: entry.cached_at_ms, record: entry.record };
  }

  private url(namespace: string): string {
    return `${this.basePath}/${encodeURIComponent(namespace)}`;
  }

  private remember(namespace: string, record: UserPreferencesV1): void {
    this.cache?.set(namespace, {
      source: "local-cache",
      cached_at_ms: this.nowMs(),
      record,
    });
  }
}

export function createPreferencesClient(options: PreferencesClientOptions = {}): PreferencesClient {
  return new PreferencesClient(options);
}
