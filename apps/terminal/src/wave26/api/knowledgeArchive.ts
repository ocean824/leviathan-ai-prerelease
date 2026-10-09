import { isSafeIdentifier } from "../../shared/safeLabel";

export const KNOWLEDGE_ARCHIVE_BASE = "/api/v1/knowledge/ingestions" as const;
export const UNLISTED_TAG_MARKER = "[unlisted tag]" as const;

export type KnowledgeArchiveSourceTypeV1 = "web" | "file" | "api" | "custom";

export type KnowledgeArchiveQueryV1 = {
  cursor?: string;
  limit?: number;
  sourceType?: KnowledgeArchiveSourceTypeV1;
  createdAfter?: string;
  createdBefore?: string;
  tag?: string;
};

export type KnowledgeArchiveEntryV1 = {
  id: string;
  sourceType: KnowledgeArchiveSourceTypeV1;
  createdAtNs: string;
  updatedAtNs: string;
  tags: readonly string[];
  status: "archived";
};

export type KnowledgeArchivePageV1 = {
  items: readonly KnowledgeArchiveEntryV1[];
  nextCursor: string | null;
  warnings: readonly "IGNORED_UNKNOWN_FILTER"[];
  sourceAsOf?: number | string;
};

export type KnowledgeArchiveDetailV1 = KnowledgeArchiveEntryV1 & {
  sourceAsOf?: number | string;
};

export type KnowledgeArchiveErrorCodeV1 =
  | "OPERATOR_SESSION_UNAVAILABLE"
  | "FORBIDDEN"
  | "NOT_FOUND"
  | "ARCHIVE_GONE"
  | "SERVICE_UNAVAILABLE"
  | "REQUEST_REJECTED"
  | "NETWORK_UNAVAILABLE"
  | "INVALID_QUERY"
  | "INVALID_RESPONSE";

export class KnowledgeArchiveError extends Error {
  readonly code: KnowledgeArchiveErrorCodeV1;
  readonly status: number | null;

  constructor(code: KnowledgeArchiveErrorCodeV1, status: number | null = null) {
    super(code);
    this.name = "KnowledgeArchiveError";
    this.code = code;
    this.status = status;
  }
}

type FetchLike = typeof fetch;
type JsonObject = Record<string, unknown>;

const MAX_NS = "253402300799999999999";
const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
const CURSOR_PATTERN = /^(?:0|[1-9][0-9]{0,17})$/;
const TAG_PATTERN = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const SOURCE_TYPES = new Set<KnowledgeArchiveSourceTypeV1>(["web", "file", "api", "custom"]);
const QUERY_KEYS = new Set([
  "cursor",
  "limit",
  "sourceType",
  "createdAfter",
  "createdBefore",
  "tag",
]);

function invalidResponse(): never {
  throw new KnowledgeArchiveError("INVALID_RESPONSE");
}

function object(value: unknown): JsonObject {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return invalidResponse();
  }
  return value as JsonObject;
}

function exactKeys(value: JsonObject, expected: readonly string[]): void {
  const keys = Object.keys(value);
  if (keys.length !== expected.length || keys.some((key) => !expected.includes(key))) {
    invalidResponse();
  }
}

function isBoundedDecimalString(value: unknown, maximum: string): value is string {
  if (typeof value !== "string" || !/^(?:0|[1-9][0-9]*)$/.test(value)) return false;
  return value.length < maximum.length || (value.length === maximum.length && value <= maximum);
}

function parseTimestampNs(value: unknown): string {
  if (!isBoundedDecimalString(value, MAX_NS)) return invalidResponse();
  return value;
}

function isSourceType(value: unknown): value is KnowledgeArchiveSourceTypeV1 {
  return typeof value === "string" && SOURCE_TYPES.has(value as KnowledgeArchiveSourceTypeV1);
}

export function isSafeKnowledgeArchiveTag(value: unknown): value is string {
  return typeof value === "string" && TAG_PATTERN.test(value) && isSafeIdentifier(value);
}

function parseEntry(value: unknown): KnowledgeArchiveEntryV1 {
  const raw = object(value);
  exactKeys(raw, ["id", "source_type", "created_at_ns", "updated_at_ns", "tags", "status", "data"]);
  if (
    typeof raw.id !== "string" || !ID_PATTERN.test(raw.id) ||
    !isSourceType(raw.source_type) || raw.status !== "archived" ||
    !Array.isArray(raw.tags) || raw.tags.length > 100 ||
    !raw.tags.every((tag) => typeof tag === "string")
  ) {
    return invalidResponse();
  }
  if (new Set(raw.tags).size !== raw.tags.length) return invalidResponse();
  const safeTags = raw.tags.map((tag) => isSafeKnowledgeArchiveTag(tag) ? tag : UNLISTED_TAG_MARKER);
  // The payload is intentionally checked only as an object, then discarded.
  object(raw.data);
  return {
    id: raw.id,
    sourceType: raw.source_type,
    createdAtNs: parseTimestampNs(raw.created_at_ns),
    updatedAtNs: parseTimestampNs(raw.updated_at_ns),
    tags: safeTags,
    status: "archived",
  };
}

function parseSourceAsOf(root: JsonObject): number | string | undefined {
  const value = root.as_of ?? root.asOf;
  if (value === undefined) return undefined;
  if (typeof value === "string") return value;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  return invalidResponse();
}

function parseWarnings(value: unknown): readonly "IGNORED_UNKNOWN_FILTER"[] {
  if (!Array.isArray(value) || !value.every((warning) => warning === "IGNORED_UNKNOWN_FILTER")) {
    return invalidResponse();
  }
  return value as readonly "IGNORED_UNKNOWN_FILTER"[];
}

function parseReplacement(value: unknown): void {
  const replacement = object(value);
  if (Object.keys(replacement).length !== 2 ||
    !["market_data_doc", "ea_builder_doc"].every((key) => typeof replacement[key] === "string")) {
    invalidResponse();
  }
}

function parsePage(value: unknown): KnowledgeArchivePageV1 {
  const root = object(value);
  const rootKeys = Object.keys(root);
  if (
    !rootKeys.includes("data") || !rootKeys.includes("meta") ||
    rootKeys.some((key) => !["data", "meta", "as_of", "asOf"].includes(key))
  ) {
    return invalidResponse();
  }
  const meta = object(root.meta);
  exactKeys(meta, ["cursor", "warnings", "replacement"]);
  if (meta.cursor !== null && (typeof meta.cursor !== "string" || !CURSOR_PATTERN.test(meta.cursor))) {
    return invalidResponse();
  }
  parseReplacement(meta.replacement);
  if (!Array.isArray(root.data) || root.data.length > 200) return invalidResponse();
  const page: KnowledgeArchivePageV1 = {
    items: root.data.map(parseEntry),
    nextCursor: meta.cursor,
    warnings: parseWarnings(meta.warnings),
  };
  const sourceAsOf = parseSourceAsOf(root);
  return sourceAsOf === undefined ? page : { ...page, sourceAsOf };
}

function parseDetail(value: unknown): KnowledgeArchiveDetailV1 {
  const root = object(value);
  const rootKeys = Object.keys(root);
  if (
    !rootKeys.includes("data") || !rootKeys.includes("meta") ||
    rootKeys.some((key) => !["data", "meta", "as_of", "asOf"].includes(key))
  ) {
    return invalidResponse();
  }
  const meta = object(root.meta);
  exactKeys(meta, ["replacement"]);
  parseReplacement(meta.replacement);
  const entry = parseEntry(root.data);
  const sourceAsOf = parseSourceAsOf(root);
  return sourceAsOf === undefined ? entry : { ...entry, sourceAsOf };
}

function normalizeTimestamp(value: string): string {
  const normalized = value.replace(/^0+(?=[0-9])/, "");
  return normalized || "0";
}

function compareTimestamps(left: string, right: string): number {
  const a = normalizeTimestamp(left);
  const b = normalizeTimestamp(right);
  return a.length === b.length ? a.localeCompare(b) : a.length - b.length;
}

function archiveUrl(query: KnowledgeArchiveQueryV1 = {}): string {
  if (query === null || typeof query !== "object" || Array.isArray(query)) {
    throw new KnowledgeArchiveError("INVALID_QUERY");
  }
  if (Reflect.ownKeys(query).some((key) => typeof key !== "string" || !QUERY_KEYS.has(key))) {
    throw new KnowledgeArchiveError("INVALID_QUERY");
  }
  if (query.cursor !== undefined && (typeof query.cursor !== "string" || !CURSOR_PATTERN.test(query.cursor))) {
    throw new KnowledgeArchiveError("INVALID_QUERY");
  }
  if (query.limit !== undefined && (!Number.isInteger(query.limit) || query.limit < 1 || query.limit > 200)) {
    throw new KnowledgeArchiveError("INVALID_QUERY");
  }
  if (query.sourceType !== undefined && !isSourceType(query.sourceType)) {
    throw new KnowledgeArchiveError("INVALID_QUERY");
  }
  for (const stamp of [query.createdAfter, query.createdBefore]) {
    if (stamp !== undefined && !isBoundedDecimalString(stamp, MAX_NS)) {
      throw new KnowledgeArchiveError("INVALID_QUERY");
    }
  }
  if (query.tag !== undefined && (typeof query.tag !== "string" || !TAG_PATTERN.test(query.tag))) {
    throw new KnowledgeArchiveError("INVALID_QUERY");
  }
  if (
    query.createdAfter !== undefined && query.createdBefore !== undefined &&
    compareTimestamps(query.createdAfter, query.createdBefore) > 0
  ) {
    throw new KnowledgeArchiveError("INVALID_QUERY");
  }

  const params: string[] = [];
  const append = (key: string, value: string) => params.push(`${encodeURIComponent(key)}=${encodeURIComponent(value)}`);
  if (query.cursor !== undefined) append("cursor", query.cursor);
  if (query.limit !== undefined) append("limit", String(query.limit));
  if (query.sourceType !== undefined) append("source_type", query.sourceType);
  if (query.createdAfter !== undefined) append("created_after", query.createdAfter);
  if (query.createdBefore !== undefined) append("created_before", query.createdBefore);
  if (query.tag !== undefined) {
    if (!isSafeKnowledgeArchiveTag(query.tag)) throw new KnowledgeArchiveError("INVALID_QUERY");
    append("tag", query.tag);
  }
  const suffix = params.join("&");
  return suffix ? `${KNOWLEDGE_ARCHIVE_BASE}?${suffix}` : KNOWLEDGE_ARCHIVE_BASE;
}

function parseJsonText(text: string): unknown {
  // Preserve the archive API's 64-bit nanosecond integers before JSON.parse rounds them.
  const exactTimestamps = text.replace(
    /("(?:created_at_ns|updated_at_ns)"\s*:\s*)(0|[1-9][0-9]*)(?=\s*[,}])/g,
    '$1"$2"',
  );
  return JSON.parse(exactTimestamps) as unknown;
}

async function request<T>(
  path: string,
  parse: (value: unknown) => T,
  fetcher: FetchLike,
): Promise<T> {
  let response: Response;
  try {
    response = await fetcher(path, { method: "GET", headers: { Accept: "application/json" } });
  } catch {
    throw new KnowledgeArchiveError("NETWORK_UNAVAILABLE");
  }
  if (!response.ok) {
    const code: KnowledgeArchiveErrorCodeV1 = response.status === 401
      ? "OPERATOR_SESSION_UNAVAILABLE"
      : response.status === 403
        ? "FORBIDDEN"
        : response.status === 404
          ? "NOT_FOUND"
          : response.status === 410
            ? "ARCHIVE_GONE"
            : response.status >= 500
              ? "SERVICE_UNAVAILABLE"
              : "REQUEST_REJECTED";
    throw new KnowledgeArchiveError(code, response.status);
  }
  try {
    return parse(parseJsonText(await response.text()));
  } catch (error) {
    if (error instanceof KnowledgeArchiveError) throw error;
    throw new KnowledgeArchiveError("INVALID_RESPONSE");
  }
}

export function listKnowledgeIngestions(
  query: KnowledgeArchiveQueryV1 = {},
  fetcher: FetchLike = fetch,
): Promise<KnowledgeArchivePageV1> {
  return request(archiveUrl(query), parsePage, fetcher);
}

export function getKnowledgeIngestion(
  ingestionId: string,
  fetcher: FetchLike = fetch,
): Promise<KnowledgeArchiveDetailV1> {
  if (typeof ingestionId !== "string" || !ID_PATTERN.test(ingestionId)) {
    return Promise.reject(new KnowledgeArchiveError("INVALID_QUERY"));
  }
  return request(`${KNOWLEDGE_ARCHIVE_BASE}/${encodeURIComponent(ingestionId)}`, parseDetail, fetcher);
}

export function listKnowledgeIngestionRuns(
  ingestionId: string,
  query: KnowledgeArchiveQueryV1 = {},
  fetcher: FetchLike = fetch,
): Promise<KnowledgeArchivePageV1> {
  if (typeof ingestionId !== "string" || !ID_PATTERN.test(ingestionId)) {
    return Promise.reject(new KnowledgeArchiveError("INVALID_QUERY"));
  }
  return request(
    `${archiveUrl(query).replace(KNOWLEDGE_ARCHIVE_BASE, `${KNOWLEDGE_ARCHIVE_BASE}/${encodeURIComponent(ingestionId)}/runs`)}`,
    parsePage,
    fetcher,
  );
}
