export const SUBSCRIPTION_STATUSES = ['ACTIVE', 'PAST_DUE', 'PAUSED', 'SUSPENDED', 'CANCELED', 'EXPIRED'] as const
export type SubscriptionStatus = (typeof SUBSCRIPTION_STATUSES)[number]

export interface AdminSessionV1 {
  schema_version: 1
  session_token: string
  expires_at_utc_ns: string
  org_id: string
  audit_id: string
}

export interface AdminPageEnvelopeV1<T> {
  schema_version: 1
  request_id: string
  observed_at_ns: string
  data: { items: T[]; next_cursor: string | null }
}

export interface AdminDetailEnvelopeV1<T> {
  schema_version: 1
  request_id: string
  observed_at_ns: string
  data: T
}

export interface AccountRowV1 {
  org_id: string
  display_name?: string | null
  version: string
}

export interface UserRowV1 {
  user_id: string
  role_id: string
  seat_id: string | null
  status: string
  version: string
}

export interface SubscriptionRowV1 {
  subscription_id: string
  org_id: string
  plan_id: string
  term_start_utc_ns: string
  term_end_utc_ns: string
  seats: string
  status: SubscriptionStatus
  version: string
  created_at_utc_ns: string
  updated_at_utc_ns: string
}

export interface DeviceRowV1 {
  device_id: string
  org_id: string
  user_id: string
  status: string
  created_at_utc_ns: string
  last_seen_at_utc_ns: string | null
  revoked_at_utc_ns: string | null
  version: string
}

export interface AuditRowV1 {
  audit_id: string
  org_id: string
  actor_user_id: string | null
  action: string
  resource_type: string
  resource_id: string | null
  occurred_at_utc_ns: string
  outcome: string
  reason: string | null
  correlation_id: string | null
}

export interface MutationReceiptV1 {
  schema_version: 1
  request_id: string
  observed_at_ns: string
  data: { resource_id: string; resource_version: string }
  audit_id: string
}

export interface PageResult<T> {
  items: T[]
  nextCursor: string | null
  requestId: string
  observedAtNs: bigint
}

export interface ObservedResult<T> {
  data: T
  requestId: string
  observedAtNs: bigint
}

export interface SignInInput {
  owner_email: string
  password: string
  totp_code?: string
  device_id: string
}

export interface CreateAccountInput {
  org: { name: string }
  owner: { email: string }
  initial_subscription: {
    plan_id: string
    term_start_utc_ns: string
    term_end_utc_ns: string
    seats: string
    status: SubscriptionStatus | ''
  }
  reason: string
  expected_version: "0"
}

export type AdminMutationInput = Record<string, string | number | boolean | null | undefined | Record<string, string | number | boolean | null | undefined>>
export type AdminSection = 'accounts' | 'users' | 'subscriptions' | 'devices' | 'audit'

