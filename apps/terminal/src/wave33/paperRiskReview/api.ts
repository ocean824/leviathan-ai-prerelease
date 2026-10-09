export const PAPER_RISK_ASSESSMENT_PATH = "/api/paper/risk/assessment/v1/preview";

export type PaperRiskSide = "BUY" | "SELL";

export interface PaperRiskAssessmentRequest {
  readonly scope: "paper";
  readonly account_id: string;
  readonly request_id: string;
  readonly attempt_id: string;
  readonly strategy_id: string;
  readonly venue_id: string;
  readonly instrument_id: string;
  readonly side: PaperRiskSide;
  readonly quantity: string;
  readonly price: string;
  readonly contract_multiplier: string;
  readonly currency: string;
  readonly price_source_ns: number;
  readonly price_ingest_ns: number;
  readonly price_source_id: string;
}

export const PAPER_RISK_REASON_CODES = [
  "within_hard_limits",
  "as_of_invalid",
  "policy_unverified",
  "policy_tampered",
  "order_invalid",
  "state_missing",
  "PRECISION_EXCEEDED",
  "account_mismatch",
  "environment_mismatch",
  "account_inactive",
  "state_invalid",
  "policy_missing",
  "policy_invalid",
  "policy_ambiguous",
  "policy_stale",
  "scope_not_allowed",
  "instrument_not_allowed",
  "state_stale",
  "price_stale",
  "state_incomplete",
  "state_oversized",
  "fx_ambiguous",
  "rate_state_invalid",
  "rate_counter_stale",
  "rate_ambiguous",
  "fx_missing",
  "fx_invalid",
  "fx_stale",
  "currency_mismatch",
  "price_invalid",
  "state_ambiguous",
  "state_inconsistent",
  "order_duplicate",
  "buying_power_exceeded",
  "max_order_quantity_exceeded",
  "max_order_notional_exceeded",
  "max_projected_position_exceeded",
  "max_gross_exposure_exceeded",
  "max_net_exposure_exceeded",
  "max_leverage_exceeded",
  "max_daily_loss_exceeded",
  "rate_state_missing",
  "order_rate_exceeded",
  "input_invalid",
] as const;

export type PaperRiskReasonCode = (typeof PAPER_RISK_REASON_CODES)[number];
export type PaperRiskDecision = "ALLOW" | "DENY";

export interface PaperRiskAssessment {
  readonly scope: "paper";
  readonly assessment_kind: "preview";
  readonly decision: PaperRiskDecision;
  readonly assessment_time_ns: number;
  readonly policy_version: 1;
  readonly policy_revisions: readonly string[];
  readonly policy_digest: string;
  readonly reason_codes: readonly PaperRiskReasonCode[];
  readonly evidence_digest: string;
  readonly approval_issued: false;
  readonly order_submitted: false;
}

export type PaperRiskAssessmentErrorCode =
  | "NETWORK_UNAVAILABLE"
  | "PRINCIPAL_REQUIRED"
  | "PAPER_SCOPE_REQUIRED"
  | "INVALID_REQUEST"
  | "ASSESSMENT_UNAVAILABLE"
  | "HTTP_ERROR"
  | "INVALID_RESPONSE";

const ERROR_MESSAGES: Record<PaperRiskAssessmentErrorCode, string> = {
  NETWORK_UNAVAILABLE: "The risk assessment service could not be reached.",
  PRINCIPAL_REQUIRED: "A trusted operator session is required.",
  PAPER_SCOPE_REQUIRED: "This assessment is not authorized for the selected paper scope.",
  INVALID_REQUEST: "The assessment request is invalid.",
  ASSESSMENT_UNAVAILABLE: "The risk assessment is unavailable. Submission is blocked.",
  HTTP_ERROR: "The risk assessment request failed. Submission is blocked.",
  INVALID_RESPONSE: "The assessment response could not be verified. Submission is blocked.",
};

export class PaperRiskAssessmentError extends Error {
  readonly code: PaperRiskAssessmentErrorCode;

  constructor(code: PaperRiskAssessmentErrorCode) {
    super(ERROR_MESSAGES[code]);
    this.name = "PaperRiskAssessmentError";
    this.code = code;
  }
}

const REQUEST_KEYS = [
  "scope",
  "account_id",
  "request_id",
  "attempt_id",
  "strategy_id",
  "venue_id",
  "instrument_id",
  "side",
  "quantity",
  "price",
  "contract_multiplier",
  "currency",
  "price_source_ns",
  "price_ingest_ns",
  "price_source_id",
] as const;

const RESPONSE_KEYS = [
  "scope",
  "assessment_kind",
  "decision",
  "assessment_time_ns",
  "policy_version",
  "policy_revisions",
  "policy_digest",
  "reason_codes",
  "evidence_digest",
  "approval_issued",
  "order_submitted",
] as const;

const REASON_CODE_SET: ReadonlySet<string> = new Set(PAPER_RISK_REASON_CODES);
const ALLOW_REASON_CODES: ReadonlySet<PaperRiskReasonCode> = new Set(["within_hard_limits"]);
const DECIMAL_PATTERN = /^(?:0|[0-9]+)(?:\.[0-9]+)?$/;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function isNonEmptyText(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function isTimestamp(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 0;
}

function isAssessmentRequest(value: unknown): value is PaperRiskAssessmentRequest {
  if (!isRecord(value) || !hasExactKeys(value, REQUEST_KEYS)) return false;
  return (
    value.scope === "paper" &&
    isNonEmptyText(value.account_id) &&
    isNonEmptyText(value.request_id) &&
    isNonEmptyText(value.attempt_id) &&
    isNonEmptyText(value.strategy_id) &&
    isNonEmptyText(value.venue_id) &&
    isNonEmptyText(value.instrument_id) &&
    (value.side === "BUY" || value.side === "SELL") &&
    typeof value.quantity === "string" &&
    DECIMAL_PATTERN.test(value.quantity) &&
    typeof value.price === "string" &&
    DECIMAL_PATTERN.test(value.price) &&
    typeof value.contract_multiplier === "string" &&
    DECIMAL_PATTERN.test(value.contract_multiplier) &&
    isNonEmptyText(value.currency) &&
    isTimestamp(value.price_source_ns) &&
    isTimestamp(value.price_ingest_ns) &&
    isNonEmptyText(value.price_source_id)
  );
}

function parseAssessment(value: unknown): PaperRiskAssessment | null {
  if (!isRecord(value) || !hasExactKeys(value, RESPONSE_KEYS)) return null;
  const reasons = value.reason_codes;
  const revisions = value.policy_revisions;
  if (
    value.scope !== "paper" ||
    value.assessment_kind !== "preview" ||
    (value.decision !== "ALLOW" && value.decision !== "DENY") ||
    !isTimestamp(value.assessment_time_ns) ||
    value.policy_version !== 1 ||
    !Array.isArray(revisions) ||
    !revisions.every((revision) => typeof revision === "string") ||
    !Array.isArray(reasons) ||
    reasons.length < 1 ||
    reasons.length > 16 ||
    !reasons.every(
      (reason): reason is PaperRiskReasonCode =>
        typeof reason === "string" && reason.length <= 32 && REASON_CODE_SET.has(reason),
    ) ||
    typeof value.policy_digest !== "string" ||
    !SHA256_PATTERN.test(value.policy_digest) ||
    typeof value.evidence_digest !== "string" ||
    !SHA256_PATTERN.test(value.evidence_digest) ||
    value.approval_issued !== false ||
    value.order_submitted !== false
  ) {
    return null;
  }

  if (new Set(reasons).size !== reasons.length) return null;
  if (value.decision === "ALLOW" && (reasons.length !== 1 || !ALLOW_REASON_CODES.has(reasons[0]))) return null;
  if (value.decision === "DENY" && reasons.some((reason) => ALLOW_REASON_CODES.has(reason))) return null;

  return {
    scope: "paper",
    assessment_kind: "preview",
    decision: value.decision,
    assessment_time_ns: value.assessment_time_ns,
    policy_version: 1,
    policy_revisions: revisions,
    policy_digest: value.policy_digest,
    reason_codes: reasons,
    evidence_digest: value.evidence_digest,
    approval_issued: false,
    order_submitted: false,
  };
}

function httpErrorCode(status: number): PaperRiskAssessmentErrorCode {
  if (status === 401) return "PRINCIPAL_REQUIRED";
  if (status === 403) return "PAPER_SCOPE_REQUIRED";
  if (status === 422) return "INVALID_REQUEST";
  if (status === 503) return "ASSESSMENT_UNAVAILABLE";
  return "HTTP_ERROR";
}

export async function assessPaperRisk(
  request: PaperRiskAssessmentRequest,
  fetchImpl?: typeof fetch,
): Promise<PaperRiskAssessment> {
  if (!isAssessmentRequest(request)) throw new PaperRiskAssessmentError("INVALID_REQUEST");
  const fetcher = fetchImpl ?? globalThis.fetch;
  if (typeof fetcher !== "function") {
    throw new PaperRiskAssessmentError("NETWORK_UNAVAILABLE");
  }

  const body = Object.fromEntries(REQUEST_KEYS.map((key) => [key, request[key]]));
  let response: Response;
  try {
    response = await fetcher(PAPER_RISK_ASSESSMENT_PATH, {
      method: "POST",
      credentials: "same-origin",
      cache: "no-store",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
    });
  } catch {
    throw new PaperRiskAssessmentError("NETWORK_UNAVAILABLE");
  }

  if (!response.ok) throw new PaperRiskAssessmentError(httpErrorCode(response.status));

  let responseBody: unknown;
  try {
    responseBody = await response.json();
  } catch {
    throw new PaperRiskAssessmentError("INVALID_RESPONSE");
  }

  const assessment = parseAssessment(responseBody);
  if (!assessment) throw new PaperRiskAssessmentError("INVALID_RESPONSE");
  return assessment;
}

