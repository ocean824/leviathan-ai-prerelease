export interface AuthResponseContextV1 {
  readonly request_id: string;
  readonly observed_at_ns: string;
}

export function authJsonV1(value: unknown, status = 200, headers: HeadersInit = {}): Response {
  const normalized = new Headers({
    "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store",
    "Pragma": "no-cache", "X-Content-Type-Options": "nosniff",
  });
  new Headers(headers).forEach((v,k) => normalized.set(k,v));
  return new Response(JSON.stringify(value), { status, headers: normalized });
}

export function authErrorV1(code: string, context: AuthResponseContextV1, status: number): Response {
  const messages: Record<string, string> = {
    INVALID_REQUEST: "The request is invalid.", AUTHENTICATION_FAILED: "Authentication failed.",
    TOTP_REQUIRED: "A valid authenticator code is required.", TOTP_ENROLLMENT_REQUIRED: "Authenticator enrollment is required.",
    SESSION_UNAVAILABLE: "The session could not be created.", LICENSE_UNAVAILABLE: "An active licence is required.",
    NOT_FOUND: "The requested route was not found.", NOT_CONFIGURED: "Service unavailable.",
  };
  return authJsonV1({ schema_version: 1, request_id: context.request_id,
    observed_at_ns: context.observed_at_ns, error: { code, message: messages[code] ?? "The request could not be completed." } }, status);
}
