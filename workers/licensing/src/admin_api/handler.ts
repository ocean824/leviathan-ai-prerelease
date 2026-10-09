import { AdminApiErrorV1, type AdminApiDependenciesV1, type AdminEnvelopeV1 } from "./models.js";

const MESSAGES: Readonly<Record<string, string>> = {
  INVALID_REQUEST: "The request is invalid.",
  UNAUTHENTICATED: "Authentication is required.",
  AUTHENTICATION_FAILED: "Authentication failed.",
  TOTP_ENROLLMENT_REQUIRED: "Multi-factor enrollment is required.",
  LOGIN_LOCKED: "Sign-in is temporarily unavailable.",
  FORBIDDEN: "The requested action is not permitted.",
  NOT_FOUND: "The requested resource was not found.",
  VERSION_CONFLICT: "The resource changed. Refresh and try again.",
  IDEMPOTENCY_CONFLICT: "The request key was already used for a different action.",
  INVALID_STATUS_TRANSITION: "The requested status transition is not allowed.",
  UNSUPPORTED_STATUS: "The requested subscription status is not supported.",
  TERM_NOT_ACTIVE: "The subscription term does not permit this action.",
  SUBSCRIPTION_UNAVAILABLE: "No eligible subscription is available.",
  SESSION_POLICY_NOT_CONFIGURED: "Session policy is not configured.",
  AUTH_UNAVAILABLE: "Authentication is temporarily unavailable.",
  STORE_UNAVAILABLE: "The licensing service is temporarily unavailable.",
  MUTATION_REJECTED: "The change could not be completed.",
  BOOTSTRAP_DENIED: "The initial owner could not be provisioned.",
  NOT_CONFIGURED: "The administrative API is not configured.",
  INTERNAL_ERROR: "The request could not be completed.",
};

export interface AdminResponseContextV1 {
  readonly request_id: string;
  readonly observed_at_ns: string;
}

function safeRequestId(dependencies: AdminApiDependenciesV1): string {
  try {
    const value = dependencies.ids.next("request");
    return /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(value) ? value : "request-unavailable";
  } catch { return "request-unavailable"; }
}

export function adminResponseContextV1(dependencies: AdminApiDependenciesV1): AdminResponseContextV1 {
  const request_id = safeRequestId(dependencies);
  let observed_at_ns = "0";
  try {
    const value = dependencies.clock.nowUtcNs();
    if (/^(0|[1-9][0-9]{0,63})$/.test(value) && value.length <= 64) observed_at_ns = value;
  } catch { /* Fixed fallback keeps the response content-free and bounded. */ }
  return Object.freeze({ request_id, observed_at_ns });
}

export function adminJsonV1(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "pragma": "no-cache",
      "x-content-type-options": "nosniff",
    },
  });
}

export function adminSuccessV1<T>(context: AdminResponseContextV1, data: T): AdminEnvelopeV1<T> {
  return Object.freeze({ schema_version: 1, request_id: context.request_id,
    observed_at_ns: context.observed_at_ns, data });
}

export function adminErrorV1(error: unknown, context: AdminResponseContextV1): Response {
  const known = error instanceof AdminApiErrorV1;
  const status = known ? error.status : 503;
  const rawCode = known ? error.code : "INTERNAL_ERROR";
  const code = /^[A-Za-z0-9_.:-]{1,64}$/.test(rawCode) ? rawCode : "INTERNAL_ERROR";
  const message = MESSAGES[code] ?? "The request could not be completed.";
  return adminJsonV1(Object.freeze({
    schema_version: 1,
    request_id: context.request_id,
    observed_at_ns: context.observed_at_ns,
    error: Object.freeze({ code, message }),
    ...(known && error.data ? { data: error.data } : {}),
  }), status);
}

export function adminNotConfiguredV1(request: Request): Response {
  let request_id = "request-unavailable";
  const supplied = request.headers.get("x-request-id");
  if (supplied && /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(supplied)) request_id = supplied;
  return adminJsonV1({
    schema_version: 1, request_id, observed_at_ns: "0",
    error: { code: "NOT_CONFIGURED", message: MESSAGES.NOT_CONFIGURED },
  }, 503);
}
