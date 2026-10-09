import { AdminApiError, AdminDataError } from './client'

export type SafeErrorTarget = 'email' | 'password' | 'totp_code' | 'org_name' | 'owner_email' | 'owner_password' | 'plan_id' | 'term_start_utc_ns' | 'term_end_utc_ns' | 'seats' | 'role_id' | 'status' | 'form'

export interface SafeMessage {
  target: SafeErrorTarget
  text: string
}

const CODE_MESSAGES: Record<string, SafeMessage> = {
  INVALID_REQUEST: { target: 'form', text: 'Review the highlighted fields and correct the request.' },
  UNAUTHENTICATED: { target: 'form', text: 'Your session ended. Sign in again.' },
  FORBIDDEN: { target: 'form', text: 'Your role cannot make this change.' },
  RATE_LIMITED: { target: 'form', text: 'Too many attempts. Wait briefly and try again.' },
  AUTH_LOCKED: { target: 'form', text: 'Sign-in is temporarily locked. Contact an administrator.' },
  DEVICE_BINDING_MISMATCH: { target: 'form', text: 'This device is not authorized for the account.' },
  TENANT_SCOPE_DENIED: { target: 'form', text: 'The selected account is outside your authorized scope.' },
  IDEMPOTENCY_KEY_REQUIRED: { target: 'form', text: 'The request could not be safely identified. Refresh and try again.' },
  IDEMPOTENCY_CONFLICT: { target: 'form', text: 'This request conflicts with a previous change. Refresh the server state.' },
  VERSION_CONFLICT: { target: 'form', text: 'Server data changed. Refresh before trying again.' },
  INVALID_TRANSITION: { target: 'status', text: 'That status change is not allowed. Refresh the server state.' },
  NOT_FOUND: { target: 'form', text: 'The requested record is no longer available. Refresh the server state.' },
  SEC_AUTHZ_UNAVAILABLE: { target: 'form', text: 'Authorization could not be confirmed. No change was made.' },
  AUDIT_FAILED: { target: 'form', text: 'The change could not be recorded. No updated state is shown.' },
  TRANSACTION_FAILED: { target: 'form', text: 'The change did not complete. Refresh the server state before retrying.' },
  TERM_INVALID: { target: 'term_end_utc_ns', text: 'Enter a valid start and end time for the term.' },
  SEAT_LIMIT_EXCEEDED: { target: 'seats', text: 'The requested seat count exceeds the allowed limit.' },
}

export function safeErrorMessage(error: unknown): SafeMessage {
  if (error instanceof AdminApiError) {
    if (error.status === 409) return CODE_MESSAGES[error.code] ?? { target: 'form', text: 'Server data changed. Refresh before trying again.' }
    if (error.status === 422) return CODE_MESSAGES[error.code] ?? { target: 'form', text: 'Review the fields and submit a corrected request.' }
    if (error.status === 403) return CODE_MESSAGES[error.code] ?? { target: 'form', text: 'Your role cannot make this change.' }
    if (error.status === 401) return CODE_MESSAGES[error.code] ?? { target: 'form', text: 'Your session ended. Sign in again.' }
    return { target: 'form', text: 'The server could not confirm this request. No updated state is shown.' }
  }
  if (error instanceof AdminDataError) return { target: 'form', text: 'Server evidence is missing, stale, or malformed. Re-read required.' }
  return { target: 'form', text: 'The server could not be reached. No updated state is shown.' }
}

