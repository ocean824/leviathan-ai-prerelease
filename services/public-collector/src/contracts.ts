import { z } from "zod";

export const MAX_LINE_BYTES = 1_100_000;
export const MAX_RESPONSE_BYTES = 1_048_576;
export const MAX_RECORDS = 500;
export const OPERATION_TIMEOUT_MS = 15_000;
export const HUMAN_ACTION_TIMEOUT_MS = 600_000;

const boundedText = z.string().min(1).max(512);
const isoTimestamp = z.string().datetime({ offset: true });
const qualityStatus = z.enum(["source_timestamped", "first_observed", "availability_unknown"]);
const row = z.object({
  record_id: boundedText,
  as_of: isoTimestamp,
  event_at: isoTimestamp.nullable(),
  published_at: isoTimestamp.nullable(),
  available_at: isoTimestamp.nullable(),
  knowable_at: isoTimestamp.nullable(),
  first_seen_at: isoTimestamp,
  quality: qualityStatus,
  values: z.record(z.string().max(96), z.unknown()).refine((value) => Object.keys(value).length <= 64),
  redistribution: z.literal(false),
}).strict();

const calendarOutput = z.array(
  z.object({
    record_id: boundedText.optional(),
    event_name: boundedText,
    agency: boundedText,
    scheduled_at: isoTimestamp,
    release_type: boundedText,
    published_at: isoTimestamp.nullable().optional(),
    knowable_at: isoTimestamp.nullable().optional(),
  }).strict(),
).max(MAX_RECORDS);

const earningsOutput = z.array(
  z.object({
    record_id: boundedText.optional(),
    ticker: z.string().regex(/^[A-Z0-9.-]{1,16}$/),
    fiscal_period: z.string().max(64).nullable(),
    event_type: z.enum(["earnings", "conference_call", "guidance"]),
    scheduled_at: isoTimestamp,
    status: boundedText,
    published_at: isoTimestamp.nullable().optional(),
    knowable_at: isoTimestamp.nullable().optional(),
  }).strict(),
).max(MAX_RECORDS);

const senateOutput = z.array(
  z.object({
    record_id: boundedText.optional(),
    report_url: z.string().url().max(2048),
    filed_at: isoTimestamp.nullable(),
    transactions: z.array(z.object({
      ticker: z.string().max(16).nullable(),
      trade_date: isoTimestamp.nullable(),
      transaction_type: boundedText,
      amount_range: boundedText,
    }).strict()).max(200),
    knowable_at: isoTimestamp.nullable().optional(),
  }).strict(),
).max(MAX_RECORDS);

const cboeOutput = z.array(
  z.object({
    record_id: boundedText.optional(),
    observed_at: isoTimestamp,
    metric: z.enum(["put_call_ratio", "vix_term_structure"]),
    value: z.number().finite(),
    unit: boundedText,
    maturity: z.string().max(64).nullable(),
    published_at: isoTimestamp.nullable().optional(),
    knowable_at: isoTimestamp.nullable().optional(),
  }).strict(),
).max(MAX_RECORDS);

const fearGreedOutput = z.array(
  z.object({
    record_id: boundedText.optional(),
    value: z.number().int().min(0).max(100),
    label: boundedText,
    observed_at: isoTimestamp,
    knowable_at: isoTimestamp.nullable().optional(),
  }).strict(),
).max(MAX_RECORDS);

export const operationContracts = {
  "calendar.fed": { site: "fed-calendar", operation: "release-calendar", challengeUrl: "https://www.federalreserve.gov/monetarypolicy/fomccalendars.htm", allowedHosts: ["www.federalreserve.gov", "federalreserve.gov"], challengeHosts: [], factor: "event_risk", cadenceSeconds: 86400, minIntervalMs: 5000, freshnessSeconds: 172800, tosReviewId: "fed-public-schedule-2026-10-09", records: calendarOutput, input: z.object({ year: z.number().int().min(2020).max(2100) }).strict(), tos: "ALLOWED", tosUrl: "https://www.federalreserve.gov/monetarypolicy/fomccalendars.htm", mappingRecipe: { format: "json", extract: "events", pick: ["event_name=name", "agency=agency", "scheduled_at=date", "release_type=type", "record_id=id", "published_at=publishedAt"] }, mappingFixtureKind: "hand-built-native-body" },
  "earnings.forward": { site: "earnings-calendar", operation: "forward-calendar", challengeUrl: "https://finance.yahoo.com/calendar/earnings/", allowedHosts: ["finance.yahoo.com", "query1.finance.yahoo.com", "query2.finance.yahoo.com"], challengeHosts: [], factor: "earnings", cadenceSeconds: 21600, minIntervalMs: 5000, freshnessSeconds: 43200, tosReviewId: "yahoo-finance-owner-review-2026-10-09", records: earningsOutput, input: z.object({ symbols: z.array(z.string().regex(/^[A-Z0-9.-]{1,16}$/)).min(1).max(100) }).strict(), tos: "REVIEW", tosUrl: "https://finance.yahoo.com/", mappingRecipe: { format: "json", extract: "calendar", pick: ["ticker=ticker.symbol", "fiscal_period=quarter", "event_type=type", "scheduled_at=date", "status=status", "record_id=id"] }, mappingFixtureKind: "hand-built-native-body" },
  "senate.efd.ptr": { site: "senate-efd", operation: "periodic-transactions", challengeUrl: "https://efdsearch.senate.gov/search/", allowedHosts: ["efdsearch.senate.gov"], challengeHosts: [], factor: "political_trades", cadenceSeconds: 86400, minIntervalMs: 5000, freshnessSeconds: 172800, tosReviewId: "senate-efd-public-filings-2026-10-09", records: senateOutput, input: z.object({ page: z.number().int().min(1).max(10) }).strict(), tos: "REVIEW", tosUrl: "https://efdsearch.senate.gov/search/", mappingRecipe: { format: "json", extract: "reports", pick: ["report_url=url", "filed_at=filedAt", "transactions=transactions", "record_id=id", "knowable_at=availableAt"] }, mappingFixtureKind: "hand-built-native-body" },
  "cboe.daily.stats": { site: "cboe-market-stats", operation: "daily-statistics", challengeUrl: "https://www.cboe.com/us/indices/dashboard/putcall/", allowedHosts: ["www.cboe.com", "cboe.com", "cdn.cboe.com"], challengeHosts: [], factor: "volatility", cadenceSeconds: 86400, minIntervalMs: 5000, freshnessSeconds: 172800, tosReviewId: "cboe-market-data-owner-review-2026-10-09", records: cboeOutput, input: z.object({ date: z.string().date() }).strict(), tos: "REVIEW", tosUrl: "https://www.cboe.com/us/en/about/market-data/", mappingRecipe: { format: "json", extract: "dailyStatistics", pick: ["observed_at=timestamp", "metric=name", "value=value", "unit=unit", "maturity=expiry", "record_id=id"] }, mappingFixtureKind: "hand-built-native-body" },
  "cnn.fear_greed": { site: "cnn-fear-greed", operation: "current-index", challengeUrl: "https://www.cnn.com/markets/fear-and-greed", allowedHosts: ["www.cnn.com", "cnn.com", "cdn.cnn.com"], challengeHosts: [], factor: "sentiment", cadenceSeconds: 3600, minIntervalMs: 5000, freshnessSeconds: 7200, tosReviewId: "cnn-owner-review-2026-10-09", records: fearGreedOutput, input: z.object({}).strict(), tos: "REVIEW", tosUrl: "https://www.cnn.com/markets/fear-and-greed", mappingRecipe: { format: "json", extract: "fear_and_greed_historical.data", pick: ["value=value", "label=rating", "observed_at=timestamp", "record_id=id"] }, mappingFixtureKind: "recorded-native-body" },
} as const;

export type OperationId = keyof typeof operationContracts;
export const pinRequirements: Record<OperationId, "reviewed-fixture-allowed" | "recorded-native-body-required"> = {
  "calendar.fed": "recorded-native-body-required",
  "earnings.forward": "reviewed-fixture-allowed",
  "senate.efd.ptr": "recorded-native-body-required",
  "cboe.daily.stats": "reviewed-fixture-allowed",
  "cnn.fear_greed": "reviewed-fixture-allowed",
};
export type OperationStatus = "OK" | "DEGRADED" | "USER_ACTION_REQUIRED" | "USER_ACTION_DECLINED" | "TIMEOUT" | "RATE_LIMITED";

export const requestSchema = z.discriminatedUnion("method", [
  z.object({ method: z.literal("health"), request_id: z.string().uuid() }).strict(),
  z.object({ method: z.literal("call"), request_id: z.string().uuid(), operation_id: z.enum(Object.keys(operationContracts) as [OperationId, ...OperationId[]]), args: z.record(z.string(), z.unknown()) }).strict(),
  z.object({ method: z.literal("repair"), request_id: z.string().uuid(), operation_id: z.enum(Object.keys(operationContracts) as [OperationId, ...OperationId[]]), args: z.record(z.string(), z.unknown()) }).strict(),
  z.object({ method: z.literal("learn"), request_id: z.string().uuid(), operation_id: z.enum(Object.keys(operationContracts) as [OperationId, ...OperationId[]]), examples: z.tuple([z.record(z.string(), z.unknown()), z.record(z.string(), z.unknown())]) }).strict(),
]);

export const responseSchema = z.object({
  schema_version: z.literal(1),
  request_id: z.string().uuid(),
  operation_id: z.string().nullable(),
  template_version: z.string().nullable(),
  source_id: z.string().nullable(),
  source_tier: z.literal(3).nullable(),
  status: z.enum(["OK", "DEGRADED", "USER_ACTION_REQUIRED", "USER_ACTION_DECLINED", "TIMEOUT"]),
  fetched_at: isoTimestamp,
  as_of: isoTimestamp.nullable(),
  knowable_at: isoTimestamp.nullable(),
  redistribution: z.literal(false),
  records: z.array(row).max(MAX_RECORDS),
  template_sha256: z.string().regex(/^[a-f0-9]{64}$/).nullable().optional(),
  approval_id: z.string().min(1).max(128).nullable().optional(),
  approval_deadline: isoTimestamp.nullable().optional(),
  freshness_deadline: isoTimestamp.nullable().optional(),
  candidate_only: z.boolean().optional(),
  error_code: z.enum(["COLLECTOR_UNAVAILABLE", "OPERATION_DEGRADED", "SCHEMA_INVALID", "PIN_REGISTRY_INVALID", "FIRST_SEEN_LEDGER_INVALID", "TEMPLATE_UNAVAILABLE", "TEMPLATE_UNPINNED", "USER_ACTION_REQUIRED", "USER_ACTION_DECLINED", "TIMEOUT", "RATE_LIMITED", "NOT_DUE", "CHALLENGE_WINDOW_FAILED", "BROWSER_UNAVAILABLE"]).optional(),
}).strict();
