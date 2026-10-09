import { isSafeIdentifier } from "../../shared/safeLabel";

export const PAPER_MD_SCHEMA_VERSION = "leviathan.market-data-paper/1" as const;
export const PAPER_MD_VENUES_PATH = "/api/ingest/venues";
export const PAPER_MD_LATEST_PATH = "/api/md/latest";
export const PAPER_MD_BACKFILL_PATH = "/api/ingest/backfill";
export const PAPER_MD_CHART_TICKET_PATH = "/api/md/chart/ticket";
export const PAPER_MD_BACKFILL_STATUS_PATH = (jobId: string) =>
  `${PAPER_MD_BACKFILL_PATH}/${encodeURIComponent(jobId)}`;

export const PAPER_MD_DATA_TYPES = ["trades", "quotes", "mbp-1", "mbo", "mbp-10", "ohlcv-1m"] as const;
export type PaperMarketDataType = (typeof PAPER_MD_DATA_TYPES)[number];
export type PaperMarketFreshness = "UNKNOWN" | "DEGRADED";
export type PaperMarketSourceState = "AVAILABLE" | "ABSENT";
export type PaperMarketGapState = "DETECTED" | "NONE" | "UNKNOWN";

export const PAPER_MD_ERROR_CODES = [
  "NETWORK_UNAVAILABLE",
  "SERVICE_UNAVAILABLE",
  "MARKET_DATA_UNAVAILABLE",
  "BACKFILL_UNAVAILABLE",
  "BACKFILL_NOT_FOUND",
  "INVALID_REQUEST",
  "INVALID_RESPONSE",
  "HTTP_ERROR",
] as const;
export type PaperMarketDataErrorCode = (typeof PAPER_MD_ERROR_CODES)[number];

export type PaperMarketDataResult<T> =
  | { ok: true; data: T }
  | { ok: false; error: PaperMarketDataErrorCode };

export interface VenueHealthV1 {
  venue: string;
  type: PaperMarketDataType;
  freshness: PaperMarketFreshness;
  unhealthy: boolean;
  gap_count: number;
  last_event_time_ns: string | null;
  last_ingest_time_ns: string | null;
}

export interface VenueListV1 {
  source_state: PaperMarketSourceState;
  venues: VenueHealthV1[];
}

export interface LatestEventV1 {
  event_id: string;
  event_type: "trade" | "quote" | "book_delta" | "book_snapshot" | "bar" | "status" | "reference" | "corporate_action" | "news";
  event_time_ns: string;
  source_time_ns: string | null;
  ingest_time_ns: string;
}

export interface LatestMarketDataV1 {
  source_state: PaperMarketSourceState;
  gap_state: PaperMarketGapState;
  event: LatestEventV1 | null;
}

export interface PaperBackfillRequestV1 {
  venue: string;
  instruments: string[];
  types: PaperMarketDataType[];
  t0_ns: string;
  t1_ns: string;
  max_records: number;
  dry_run: boolean;
}

export interface BackfillPreviewV1 {
  status: "PREVIEW";
  instrument_count: number;
  type_count: number;
  max_records: number;
  estimated_event_count: number | null;
  writes_performed: false;
}

export interface QueuedBackfillV1 {
  job_id: string;
  status: "QUEUED";
}

export type BackfillSubmissionV1 = BackfillPreviewV1 | QueuedBackfillV1;
export type BackfillJobState = "QUEUED" | "RUNNING" | "COMPLETED" | "FAILED" | "CANCELLED";

export interface BackfillJobStatusV1 {
  job_id: string;
  status: BackfillJobState;
  completed_count: number;
  remaining_count: number;
  source_state: "AVAILABLE" | "ABSENT" | "UNKNOWN";
  gap_state: PaperMarketGapState;
  last_event_time_ns: string | null;
  last_ingest_time_ns: string | null;
}

export interface LatestQueryV1 {
  venue: string;
  instrument: string;
  type: PaperMarketDataType;
}

export interface ChartStreamTicketV1 {
  ticket: string;
}

export interface PaperMarketDataApi {
  getVenues(query?: { venue?: string; limit?: number }): Promise<PaperMarketDataResult<VenueListV1>>;
  getLatest(query: LatestQueryV1): Promise<PaperMarketDataResult<LatestMarketDataV1>>;
  mintChartStreamTicket(query: LatestQueryV1): Promise<PaperMarketDataResult<ChartStreamTicketV1>>;
  submitBackfill(request: PaperBackfillRequestV1): Promise<PaperMarketDataResult<BackfillSubmissionV1>>;
  getBackfillStatus(jobId: string): Promise<PaperMarketDataResult<BackfillJobStatusV1>>;
}

export type PaperMarketDataFetcher = typeof fetch;

const MAX_RESPONSE_BYTES = 64_000;
const MAX_INT64 = 9_223_372_036_854_775_807n;
const VENUE_GRAMMAR = /^(?:[A-Z0-9]{4}|DBN-PUB-[0-9]{1,19})$/;
const ID_GRAMMAR = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const JOB_STATES = ["QUEUED", "RUNNING", "COMPLETED", "FAILED", "CANCELLED"] as const;
const EVENT_TYPES = ["trade", "quote", "book_delta", "book_snapshot", "bar", "status", "reference", "corporate_action", "news"] as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const keys = Object.keys(value);
  return keys.length === expected.length && expected.every((key) => Object.hasOwn(value, key));
}

function isVenue(value: unknown): value is string {
  return typeof value === "string" && VENUE_GRAMMAR.test(value);
}

function isSafeId(value: unknown): value is string {
  return typeof value === "string" && ID_GRAMMAR.test(value) && isSafeIdentifier(value);
}

function isDataType(value: unknown): value is PaperMarketDataType {
  return typeof value === "string" && (PAPER_MD_DATA_TYPES as readonly string[]).includes(value);
}

function isNs(value: unknown): value is string {
  if (typeof value !== "string" || !/^(?:0|[1-9][0-9]{0,18})$/.test(value)) return false;
  try {
    const number = BigInt(value);
    return number > 0n && number <= MAX_INT64;
  } catch {
    return false;
  }
}

function parseNs(value: unknown): string | null {
  if (isNs(value)) return value;
  if (typeof value === "number" && Number.isSafeInteger(value) && value > 0) return String(value);
  return null;
}

function isCount(value: unknown, max = 50_000): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= max;
}

function quoteNanosecondIntegerTokens(source: string): string {
  let output = "";
  let index = 0;
  let pendingKey: string | null = null;
  let valueKey: string | null = null;
  while (index < source.length) {
    const char = source[index] ?? "";
    if (char === '"') {
      const start = index;
      index += 1;
      let escaped = false;
      while (index < source.length) {
        const current = source[index] ?? "";
        index += 1;
        if (escaped) {
          escaped = false;
        } else if (current === "\\") {
          escaped = true;
        } else if (current === '"') {
          break;
        }
      }
      const token = source.slice(start, index);
      let lookahead = index;
      while (/\s/.test(source[lookahead] ?? "")) lookahead += 1;
      if (source[lookahead] === ":") {
        try {
          const key: unknown = JSON.parse(token);
          pendingKey = typeof key === "string" ? key : null;
        } catch {
          pendingKey = null;
        }
      } else {
        valueKey = null;
      }
      output += token;
      continue;
    }
    if (char === ":") {
      output += char;
      valueKey = pendingKey;
      pendingKey = null;
      index += 1;
      continue;
    }
    if (char === "{" || char === "[" || char === "," || char === "}") {
      output += char;
      valueKey = null;
      pendingKey = null;
      index += 1;
      continue;
    }
    if (char === "-") {
      const match = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(source.slice(index));
      if (match) {
        const token = match[0];
        output += valueKey?.endsWith("_ns") && /^[0-9]+$/.test(token) ? `"${token}"` : token;
        valueKey = null;
        index += token.length;
        continue;
      }
    }
    if (/[0-9]/.test(char)) {
      const match = /^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(source.slice(index));
      if (match) {
        const token = match[0];
        output += valueKey?.endsWith("_ns") && /^[0-9]+$/.test(token) ? `"${token}"` : token;
        valueKey = null;
        index += token.length;
        continue;
      }
    }
    output += char;
    if (!/\s/.test(char)) valueKey = null;
    index += 1;
  }
  return output;
}

async function parseResponseBody(response: Response): Promise<unknown> {
  try {
    const declaredLength = response.headers.get("content-length");
    if (declaredLength !== null && /^\d+$/.test(declaredLength) && Number(declaredLength) > MAX_RESPONSE_BYTES) {
      await response.body?.cancel();
      return undefined;
    }
    if (response.body === null) return undefined;
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_RESPONSE_BYTES) {
        await reader.cancel();
        return undefined;
      }
      chunks.push(value);
    }
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    return JSON.parse(quoteNanosecondIntegerTokens(text)) as unknown;
  } catch {
    return undefined;
  }
}

function parseVenueRow(value: unknown): VenueHealthV1 | null {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, ["venue", "type", "freshness", "unhealthy", "gap_count", "last_event_time_ns", "last_ingest_time_ns"]) ||
    !isVenue(value.venue) ||
    !isDataType(value.type) ||
    (value.freshness !== "UNKNOWN" && value.freshness !== "DEGRADED") ||
    typeof value.unhealthy !== "boolean" ||
    !isCount(value.gap_count) ||
    !(value.last_event_time_ns === null || isNs(value.last_event_time_ns)) ||
    !(value.last_ingest_time_ns === null || isNs(value.last_ingest_time_ns))
  ) return null;
  return {
    venue: value.venue,
    type: value.type,
    freshness: value.freshness,
    unhealthy: value.unhealthy,
    gap_count: value.gap_count,
    last_event_time_ns: value.last_event_time_ns,
    last_ingest_time_ns: value.last_ingest_time_ns,
  };
}

function parseVenueList(value: unknown): VenueListV1 | null {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, ["schema_version", "source_state", "venues"]) ||
    value.schema_version !== PAPER_MD_SCHEMA_VERSION ||
    (value.source_state !== "AVAILABLE" && value.source_state !== "ABSENT") ||
    !Array.isArray(value.venues) ||
    value.venues.length > 100
  ) return null;
  const venues = value.venues.map(parseVenueRow);
  if (venues.some((row) => row === null)) return null;
  if (value.source_state === "ABSENT" && venues.length !== 0) return null;
  return { source_state: value.source_state, venues: venues as VenueHealthV1[] };
}

function parseLatestEvent(value: unknown): LatestEventV1 | null {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, ["event_id", "event_type", "event_time_ns", "source_time_ns", "ingest_time_ns"]) ||
    typeof value.event_id !== "string" ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value.event_id) ||
    typeof value.event_type !== "string" ||
    !(EVENT_TYPES as readonly string[]).includes(value.event_type)
  ) return null;
  const eventTime = parseNs(value.event_time_ns);
  const sourceTime = value.source_time_ns === null ? null : parseNs(value.source_time_ns);
  const ingestTime = parseNs(value.ingest_time_ns);
  if (eventTime === null || (value.source_time_ns !== null && sourceTime === null) || ingestTime === null) return null;
  return {
    event_id: value.event_id,
    event_type: value.event_type as LatestEventV1["event_type"],
    event_time_ns: eventTime,
    source_time_ns: sourceTime,
    ingest_time_ns: ingestTime,
  };
}

function parseLatest(value: unknown): LatestMarketDataV1 | null {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, ["schema_version", "source_state", "gap_state", "event"]) ||
    value.schema_version !== PAPER_MD_SCHEMA_VERSION ||
    (value.source_state !== "AVAILABLE" && value.source_state !== "ABSENT") ||
    !(["DETECTED", "NONE", "UNKNOWN"] as const).includes(value.gap_state as PaperMarketGapState) ||
    !(value.event === null || isRecord(value.event))
  ) return null;
  const event = value.event === null ? null : parseLatestEvent(value.event);
  if (value.event !== null && event === null) return null;
  if ((value.source_state === "ABSENT") !== (event === null)) return null;
  return {
    source_state: value.source_state,
    gap_state: value.gap_state as PaperMarketGapState,
    event,
  };
}

function parseChartStreamTicket(value: unknown): ChartStreamTicketV1 | null {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, ["schema_version", "ticket"]) ||
    value.schema_version !== 1 ||
    typeof value.ticket !== "string" ||
    !/^[A-Za-z0-9_-]{43}$/.test(value.ticket)
  ) return null;
  return { ticket: value.ticket };
}

function parsePreview(value: unknown): BackfillPreviewV1 | null {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, ["schema_version", "status", "instrument_count", "type_count", "max_records", "estimated_event_count", "writes_performed"]) ||
    value.schema_version !== PAPER_MD_SCHEMA_VERSION ||
    value.status !== "PREVIEW" ||
    !isCount(value.instrument_count, 10) || value.instrument_count < 1 ||
    !isCount(value.type_count, 4) || value.type_count < 1 ||
    !isCount(value.max_records) || value.max_records < 1 ||
    !(value.estimated_event_count === null || isCount(value.estimated_event_count)) ||
    value.writes_performed !== false
  ) return null;
  return {
    status: "PREVIEW",
    instrument_count: value.instrument_count,
    type_count: value.type_count,
    max_records: value.max_records,
    estimated_event_count: value.estimated_event_count,
    writes_performed: false,
  };
}

function parseQueued(value: unknown): QueuedBackfillV1 | null {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, ["schema_version", "job_id", "status"]) ||
    value.schema_version !== PAPER_MD_SCHEMA_VERSION ||
    !isSafeId(value.job_id) ||
    value.status !== "QUEUED"
  ) return null;
  return { job_id: value.job_id, status: "QUEUED" };
}

function parseJob(value: unknown, expectedJobId: string): BackfillJobStatusV1 | null {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, ["schema_version", "job_id", "status", "completed_count", "remaining_count", "source_state", "gap_state", "last_event_time_ns", "last_ingest_time_ns"]) ||
    value.schema_version !== PAPER_MD_SCHEMA_VERSION ||
    value.job_id !== expectedJobId ||
    !isSafeId(value.job_id) ||
    typeof value.status !== "string" || !(JOB_STATES as readonly string[]).includes(value.status) ||
    !isCount(value.completed_count) ||
    !isCount(value.remaining_count) ||
    (value.source_state !== "AVAILABLE" && value.source_state !== "ABSENT" && value.source_state !== "UNKNOWN") ||
    !(["DETECTED", "NONE", "UNKNOWN"] as const).includes(value.gap_state as PaperMarketGapState) ||
    !(value.last_event_time_ns === null || isNs(value.last_event_time_ns)) ||
    !(value.last_ingest_time_ns === null || isNs(value.last_ingest_time_ns))
  ) return null;
  return {
    job_id: expectedJobId,
    status: value.status as BackfillJobState,
    completed_count: value.completed_count,
    remaining_count: value.remaining_count,
    source_state: value.source_state,
    gap_state: value.gap_state as PaperMarketGapState,
    last_event_time_ns: value.last_event_time_ns,
    last_ingest_time_ns: value.last_ingest_time_ns,
  };
}

function httpError(status: number, body: unknown): PaperMarketDataErrorCode {
  const code = isRecord(body) && isRecord(body.error) && typeof body.error.code === "string"
    ? body.error.code
    : "";
  if (status === 503) {
    return code === "BACKFILL_UNAVAILABLE" ? "BACKFILL_UNAVAILABLE" :
      code === "MARKET_DATA_UNAVAILABLE" ? "MARKET_DATA_UNAVAILABLE" : "SERVICE_UNAVAILABLE";
  }
  if (status === 404 && code === "BACKFILL_NOT_FOUND") return "BACKFILL_NOT_FOUND";
  if (status === 400 && code === "INVALID_REQUEST") return "INVALID_REQUEST";
  return "HTTP_ERROR";
}

async function request<T>(
  fetcher: PaperMarketDataFetcher,
  input: string,
  init: RequestInit,
  parse: (value: unknown) => T | null,
  expectedSuccessStatus?: number,
): Promise<PaperMarketDataResult<T>> {
  let response: Response;
  try {
    response = await fetcher(input, { ...init, credentials: "same-origin", cache: "no-store" });
  } catch {
    return { ok: false, error: "NETWORK_UNAVAILABLE" };
  }
  if (!response.ok) {
    const body = await parseResponseBody(response);
    return { ok: false, error: httpError(response.status, body) };
  }
  if (expectedSuccessStatus !== undefined && response.status !== expectedSuccessStatus) {
    try {
      await response.body?.cancel();
    } catch {
      // The status mismatch already determines the fixed failure result.
    }
    return { ok: false, error: "INVALID_RESPONSE" };
  }
  const body = await parseResponseBody(response);
  const data = parse(body);
  return data === null ? { ok: false, error: "INVALID_RESPONSE" } : { ok: true, data };
}

function isSafeVenueQuery(venue: string | undefined): boolean {
  return venue === undefined || isVenue(venue);
}

function isValidBackfill(request: PaperBackfillRequestV1): boolean {
  if (
    typeof request !== "object" || request === null ||
    !isVenue(request.venue) ||
    !Array.isArray(request.instruments) || !Array.isArray(request.types) ||
    request.instruments.length < 1 || request.instruments.length > 10 ||
    request.instruments.some((item) => !isSafeId(item)) || new Set(request.instruments).size !== request.instruments.length ||
    request.types.length < 1 || request.types.length > 4 || request.types.some((item) => !isDataType(item)) ||
    new Set(request.types).size !== request.types.length ||
    typeof request.dry_run !== "boolean" ||
    !Number.isSafeInteger(request.max_records) || request.max_records < 1 || request.max_records > 50_000 ||
    !isNs(request.t0_ns) || !isNs(request.t1_ns)
  ) return false;
  const start = BigInt(request.t0_ns);
  const end = BigInt(request.t1_ns);
  return start < end && end - start <= 31n * 24n * 60n * 60n * 1_000_000_000n;
}

function serializeBackfill(request: PaperBackfillRequestV1): string {
  // The backend schema requires JSON integers. Keep epoch-nanosecond digits
  // exact by emitting only the validated decimal strings as numeric tokens.
  return `{"venue":${JSON.stringify(request.venue)},"instruments":${JSON.stringify(request.instruments)},"types":${JSON.stringify(request.types)},"t0_ns":${request.t0_ns},"t1_ns":${request.t1_ns},"max_records":${request.max_records},"dry_run":${request.dry_run}}`;
}

export function createPaperMarketDataApi(fetcher: PaperMarketDataFetcher = fetch): PaperMarketDataApi {
  return {
    getVenues: (query = {}) => {
      if (!isSafeVenueQuery(query.venue) || (query.limit !== undefined && (!Number.isSafeInteger(query.limit) || query.limit < 1 || query.limit > 100))) {
        return Promise.resolve({ ok: false, error: "INVALID_REQUEST" });
      }
      const params = new URLSearchParams();
      if (query.venue !== undefined) params.set("venue", query.venue);
      if (query.limit !== undefined) params.set("limit", String(query.limit));
      const suffix = params.size ? `?${params.toString()}` : "";
      return request(fetcher, `${PAPER_MD_VENUES_PATH}${suffix}`, {
        method: "GET", headers: { Accept: "application/json" },
      }, parseVenueList);
    },
    getLatest: (query) => {
      if (!isVenue(query.venue) || !isSafeId(query.instrument) || !isDataType(query.type)) {
        return Promise.resolve({ ok: false, error: "INVALID_REQUEST" });
      }
      const params = new URLSearchParams({ venue: query.venue, instrument: query.instrument, type: query.type });
      return request(fetcher, `${PAPER_MD_LATEST_PATH}?${params.toString()}`, {
        method: "GET", headers: { Accept: "application/json" },
      }, parseLatest);
    },
    mintChartStreamTicket: (query) => {
      if (!isVenue(query.venue) || !isSafeId(query.instrument) || !isDataType(query.type)) {
        return Promise.resolve({ ok: false, error: "INVALID_REQUEST" });
      }
      return request(fetcher, PAPER_MD_CHART_TICKET_PATH, {
        method: "POST",
        headers: { Accept: "application/json", "Content-Type": "application/json" },
        body: JSON.stringify({ venue: query.venue, instrument: query.instrument, type: query.type }),
      }, parseChartStreamTicket, 201);
    },
    submitBackfill: (backfill) => {
      if (!isValidBackfill(backfill)) return Promise.resolve({ ok: false, error: "INVALID_REQUEST" });
      const parse = backfill.dry_run
        ? (value: unknown): BackfillSubmissionV1 | null => parsePreview(value)
        : (value: unknown): BackfillSubmissionV1 | null => parseQueued(value);
      return request(fetcher, PAPER_MD_BACKFILL_PATH, {
        method: "POST",
        headers: { Accept: "application/json", "Content-Type": "application/json" },
        body: serializeBackfill(backfill),
      }, parse, backfill.dry_run ? undefined : 202);
    },
    getBackfillStatus: (jobId) => {
      if (!isSafeId(jobId)) return Promise.resolve({ ok: false, error: "INVALID_REQUEST" });
      return request(fetcher, PAPER_MD_BACKFILL_STATUS_PATH(jobId), {
        method: "GET", headers: { Accept: "application/json" },
      }, (value) => parseJob(value, jobId));
    },
  };
}
