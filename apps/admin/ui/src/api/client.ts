import type {
  AccountRowV1, AdminMutationInput, AdminSessionV1,
  AuditRowV1, DeviceRowV1, MutationReceiptV1, ObservedResult, PageResult,
  SignInInput, SubscriptionRowV1, UserRowV1,
} from './models'

const WORKER_ORIGIN = __ADMIN_WORKER_ORIGIN__
export const READ_STALE_BOUND_NS = 120_000_000_000n
export const CLOCK_SKEW_BOUND_NS = 5_000_000_000n
const DECIMAL_UINT = /^(0|[1-9][0-9]{0,39})$/
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/
const SUBSCRIPTION_STATES = ['ACTIVE', 'PAST_DUE', 'PAUSED', 'SUSPENDED', 'CANCELED', 'EXPIRED']
const USER_STATES = ['ACTIVE', 'INVITED', 'REVOKED']
const DEVICE_STATES = ['ACTIVE', 'REVOKED']

export type FetchLike = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>

export interface TotpEnrollmentChallengeV1 {
  readonly otpauthUri: string
  readonly base32Secret: string
}

export class AdminApiError extends Error {
  readonly status: number
  readonly code: string
  readonly #totpEnrollmentChallenge: TotpEnrollmentChallengeV1 | null
  constructor(status: number, code: string, challenge: TotpEnrollmentChallengeV1 | null = null) {
    super('Administrative request was not accepted')
    this.name = 'AdminApiError'
    this.status = status
    this.code = code
    this.#totpEnrollmentChallenge = challenge
  }
  /** Available only for the specific first-owner enrollment challenge. */
  get totpEnrollmentChallenge(): TotpEnrollmentChallengeV1 | null {
    return this.#totpEnrollmentChallenge
  }
}

export class AdminDataError extends Error {
  constructor() {
    super('Administrative response could not be verified')
    this.name = 'AdminDataError'
  }
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}
function safeId(value: unknown): value is string {
  return typeof value === 'string' && SAFE_ID.test(value)
}
function decimalUint(value: unknown): value is string {
  return typeof value === 'string' && DECIMAL_UINT.test(value)
}
function nullableId(value: unknown): boolean { return value === null || safeId(value) }
function hasControlChars(value: string): boolean {
  for (const character of value) {
    const point = character.codePointAt(0) ?? 0
    if (point <= 0x1f || point === 0x7f) return true
  }
  return false
}
function withinCharacters(value: string, maximum: number): boolean { return [...value].length <= maximum }

function validAccount(item: unknown): item is AccountRowV1 {
  return record(item) && safeId(item.org_id) && decimalUint(item.version) &&
    (item.display_name === undefined || item.display_name === null || (typeof item.display_name === 'string' && item.display_name.length <= 160))
}
function validUser(item: unknown): item is UserRowV1 {
  return record(item) && safeId(item.user_id) && safeId(item.role_id) && decimalUint(item.version) &&
    typeof item.status === 'string' && USER_STATES.includes(item.status) &&
    Object.hasOwn(item, 'seat_id') && nullableId(item.seat_id)
}
function validSubscription(item: unknown): item is SubscriptionRowV1 {
  return record(item) && safeId(item.subscription_id) && safeId(item.org_id) && safeId(item.plan_id) &&
    decimalUint(item.term_start_utc_ns) && decimalUint(item.term_end_utc_ns) && decimalUint(item.seats) &&
    typeof item.status === 'string' && SUBSCRIPTION_STATES.includes(item.status) && decimalUint(item.version) &&
    decimalUint(item.created_at_utc_ns) && decimalUint(item.updated_at_utc_ns)
}
function validDevice(item: unknown): item is DeviceRowV1 {
  return record(item) && safeId(item.device_id) && safeId(item.org_id) && safeId(item.user_id) &&
    typeof item.status === 'string' && DEVICE_STATES.includes(item.status) && decimalUint(item.created_at_utc_ns) &&
    (item.last_seen_at_utc_ns === null || decimalUint(item.last_seen_at_utc_ns)) &&
    (item.revoked_at_utc_ns === null || decimalUint(item.revoked_at_utc_ns)) && decimalUint(item.version)
}
function validAudit(item: unknown): item is AuditRowV1 {
  const shortText = (field: unknown, maximum: number) => typeof field === 'string' && field.length > 0 && field.length <= maximum
  return record(item) && safeId(item.audit_id) && safeId(item.org_id) && nullableId(item.actor_user_id) &&
    shortText(item.action, 96) && shortText(item.resource_type, 64) && nullableId(item.resource_id) &&
    decimalUint(item.occurred_at_utc_ns) && item.outcome === 'SUCCEEDED' &&
    (item.reason === null || (typeof item.reason === 'string' && withinCharacters(item.reason, 512) && !hasControlChars(item.reason))) && nullableId(item.correlation_id)
}

function validObservedEnvelope(value: unknown): value is Record<string, unknown> & { request_id: string; observed_at_ns: string; data: unknown } {
  return record(value) && value.schema_version === 1 && safeId(value.request_id) &&
    decimalUint(value.observed_at_ns) && Object.hasOwn(value, 'data')
}

function parseError(status: number, value: unknown): AdminApiError {
  const error = record(value) && value.schema_version === 1 && safeId(value.request_id) &&
    decimalUint(value.observed_at_ns) && record(value.error) ? value.error : null
  const validCode = error && typeof error.code === 'string' && /^[A-Za-z0-9._:-]{1,64}$/.test(error.code)
  const validMessage = error && typeof error.message === 'string' && withinCharacters(error.message, 160) &&
    !hasControlChars(error.message)
  const code = validCode && validMessage ? error.code as string : 'UNKNOWN'
  const challenge = status === 403 && code === 'TOTP_ENROLLMENT_REQUIRED' && record(value) && record(value.data)
    ? parseTotpEnrollmentChallenge(value.data.otpauth_uri)
    : null
  return new AdminApiError(status, code, challenge)
}

function parseTotpEnrollmentChallenge(value: unknown): TotpEnrollmentChallengeV1 | null {
  if (typeof value !== 'string' || value.length > 2048 || hasControlChars(value)) return null
  try {
    const uri = new URL(value)
    const secrets = uri.searchParams.getAll('secret')
    const issuers = uri.searchParams.getAll('issuer')
    if (uri.protocol !== 'otpauth:' || uri.hostname !== 'totp' || uri.username || uri.password || uri.port ||
        uri.hash || !uri.pathname.startsWith('/') || secrets.length !== 1 || issuers.length !== 1 ||
        uri.searchParams.get('algorithm') !== 'SHA1' || uri.searchParams.get('digits') !== '6' ||
        uri.searchParams.get('period') !== '30' || [...uri.searchParams.keys()].some((key) =>
          !['secret', 'issuer', 'algorithm', 'digits', 'period'].includes(key))) return null
    const base32Secret = secrets[0]
    if (!base32Secret || !/^[A-Z2-7]{16,128}$/.test(base32Secret)) return null
    return Object.freeze({ otpauthUri: value, base32Secret })
  } catch {
    return null
  }
}

function assertSession(value: unknown, nowNs: bigint): AdminSessionV1 {
  if (!validObservedEnvelope(value) || !isFreshRead(BigInt(value.observed_at_ns), nowNs) || !record(value.data) ||
      typeof value.data.session_token !== 'string' || value.data.session_token.length < 16 ||
      value.data.session_token.length > 4096 || hasControlChars(value.data.session_token) ||
      !decimalUint(value.data.expires_at_utc_ns) || !safeId(value.data.org_id) || !safeId(value.data.audit_id) ||
      BigInt(value.data.expires_at_utc_ns) <= nowNs) {
    throw new AdminDataError()
  }
  return {
    schema_version: 1,
    session_token: value.data.session_token,
    expires_at_utc_ns: value.data.expires_at_utc_ns,
    org_id: value.data.org_id,
    audit_id: value.data.audit_id,
  }
}

function assertLogoutReceipt(value: unknown, nowNs: bigint): string {
  if (!validObservedEnvelope(value) || !isFreshRead(BigInt(value.observed_at_ns), nowNs) ||
      !record(value.data) || value.data.revoked !== true || !safeId(value.audit_id)) throw new AdminDataError()
  return value.audit_id
}

function assertPage<T>(value: unknown, validItem: (item: unknown) => item is T): PageResult<T> {
  if (!validObservedEnvelope(value) || !record(value.data) || !Array.isArray(value.data.items) ||
      !(value.data.next_cursor === null || (typeof value.data.next_cursor === 'string' && value.data.next_cursor.length <= 512)) ||
      !value.data.items.every(validItem)) throw new AdminDataError()
  return {
    items: value.data.items,
    nextCursor: value.data.next_cursor,
    requestId: value.request_id,
    observedAtNs: BigInt(value.observed_at_ns),
  }
}

function assertDetail<T>(value: unknown, validItem: (item: unknown) => item is T): ObservedResult<T> {
  if (!validObservedEnvelope(value) || !validItem(value.data)) throw new AdminDataError()
  return { data: value.data, requestId: value.request_id, observedAtNs: BigInt(value.observed_at_ns) }
}

function assertReceipt(value: unknown): MutationReceiptV1 {
  if (!validObservedEnvelope(value) || !record(value.data) || !safeId(value.data.resource_id) ||
      !decimalUint(value.data.resource_version) || !safeId(value.audit_id)) throw new AdminDataError()
  return value as unknown as MutationReceiptV1
}

export function isFreshRead(observedAtNs: bigint, nowNs = BigInt(Date.now()) * 1_000_000n): boolean {
  return observedAtNs > 0n && observedAtNs >= nowNs - READ_STALE_BOUND_NS && observedAtNs <= nowNs + CLOCK_SKEW_BOUND_NS
}

export class AdminApiClient {
  private session: AdminSessionV1 | null = null
  private readonly fetcher: FetchLike
  private readonly nowNs: () => bigint

  constructor(fetcher: FetchLike = fetch, nowNs: () => bigint = () => BigInt(Date.now()) * 1_000_000n) {
    this.fetcher = fetcher
    this.nowNs = nowNs
  }

  get currentSession(): Omit<AdminSessionV1, 'session_token'> | null {
    const session = this.session
    if (!session || BigInt(session.expires_at_utc_ns) <= this.nowNs()) return null
    return { schema_version: 1, expires_at_utc_ns: session.expires_at_utc_ns, org_id: session.org_id, audit_id: session.audit_id }
  }

  async signIn(input: SignInInput): Promise<Omit<AdminSessionV1, 'session_token'>> {
    this.session = null
    const session = assertSession(await this.send('/session', { method: 'POST', body: input, authenticated: false }), this.nowNs())
    this.session = session
    return { schema_version: 1, expires_at_utc_ns: session.expires_at_utc_ns, org_id: session.org_id, audit_id: session.audit_id }
  }

  async confirmTotpEnrollment(input: { owner_email: string; password: string; totp_code: string }): Promise<void> {
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(input.owner_email) || input.password.length < 12 ||
        input.password.length > 256 || !/^\d{6,8}$/.test(input.totp_code)) throw new AdminDataError()
    const value = await this.send('/session/enrollment/confirm', {
      method: 'POST', body: input, authenticated: false,
    })
    if (!validObservedEnvelope(value) || !isFreshRead(BigInt(value.observed_at_ns), this.nowNs()) ||
        !record(value.data) || value.data.enrolled !== true) throw new AdminDataError()
  }

  async signOut(): Promise<string | null> {
    const session = this.session
    this.session = null
    if (!session) return null
    try {
      const response = await this.fetcher(new URL('/v1/admin/session', WORKER_ORIGIN), {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${session.session_token}`, Accept: 'application/json' },
        cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer', credentials: 'omit',
      })
      if (!response.ok) return null
      return assertLogoutReceipt(await response.json(), this.nowNs())
    } catch {
      return null
    }
  }

  async listAccounts(cursor?: string): Promise<PageResult<AccountRowV1>> {
    const orgId = this.requireOrgScope(this.session?.org_id)
    return this.read('/accounts', cursor, (item): item is AccountRowV1 => validAccount(item) && item.org_id === orgId)
  }
  async listUsers(orgId: string, cursor?: string): Promise<PageResult<UserRowV1>> {
    this.requireOrgScope(orgId)
    return this.read(`/accounts/${encodeURIComponent(orgId)}/users`, cursor, validUser)
  }
  async listSubscriptions(orgId: string, cursor?: string): Promise<PageResult<SubscriptionRowV1>> {
    this.requireOrgScope(orgId)
    return this.read(`/accounts/${encodeURIComponent(orgId)}/subscriptions`, cursor, (item): item is SubscriptionRowV1 => validSubscription(item) && item.org_id === orgId)
  }
  async listDevices(orgId: string, cursor?: string): Promise<PageResult<DeviceRowV1>> {
    this.requireOrgScope(orgId)
    return this.read(`/accounts/${encodeURIComponent(orgId)}/devices`, cursor, (item): item is DeviceRowV1 => validDevice(item) && item.org_id === orgId)
  }
  async listAudit(orgId: string, cursor?: string): Promise<PageResult<AuditRowV1>> {
    this.requireOrgScope(orgId)
    return this.read(`/accounts/${encodeURIComponent(orgId)}/audit`, cursor, (item): item is AuditRowV1 => validAudit(item) && item.org_id === orgId)
  }

  async getAccount(orgId: string): Promise<ObservedResult<AccountRowV1>> {
    this.requireOrgScope(orgId)
    return assertDetail(await this.send(`/accounts/${encodeURIComponent(orgId)}`, { method: 'GET', authenticated: true }),
      (item): item is AccountRowV1 => validAccount(item) && item.org_id === orgId)
  }

  async mutate(path: string, body: AdminMutationInput, idempotencyKey: string): Promise<MutationReceiptV1> {
    return this.write(path, 'POST', body, idempotencyKey)
  }
  async put(path: string, body: AdminMutationInput, idempotencyKey: string): Promise<MutationReceiptV1> {
    return this.write(path, 'PUT', body, idempotencyKey)
  }
  async patch(path: string, body: AdminMutationInput, idempotencyKey: string): Promise<MutationReceiptV1> {
    return this.write(path, 'PATCH', body, idempotencyKey)
  }

  private async write(path: string, method: string, body: AdminMutationInput, idempotencyKey: string): Promise<MutationReceiptV1> {
    if (!SAFE_ID.test(idempotencyKey) || !isValidMutationBody(body)) throw new AdminDataError()
    return assertReceipt(await this.send(path, {
      method, body, authenticated: true, headers: { 'Idempotency-Key': idempotencyKey },
    }))
  }

  private async read<T>(path: string, cursor: string | undefined, validItem: (item: unknown) => item is T): Promise<PageResult<T>> {
    const query = new URLSearchParams({ page_size: '50' })
    if (cursor) query.set('cursor', cursor)
    return assertPage(await this.send(`${path}?${query.toString()}`, { method: 'GET', authenticated: true }), validItem)
  }

  private requireOrgScope(orgId: string | undefined): string {
    if (!orgId || !safeId(orgId) || !this.currentSession || orgId !== this.session?.org_id) throw new AdminDataError()
    return orgId
  }

  private async send(path: string, options: {
    method: string; body?: unknown; authenticated: boolean; headers?: Record<string, string>
  }): Promise<unknown> {
    if (options.authenticated && (!this.session || BigInt(this.session.expires_at_utc_ns) <= this.nowNs())) {
      this.session = null
      throw new AdminApiError(401, 'UNAUTHENTICATED')
    }
    let response: Response
    try {
      response = await this.fetcher(new URL(`/v1/admin${path}`, WORKER_ORIGIN), {
        method: options.method,
        headers: {
          Accept: 'application/json',
          ...(options.body === undefined ? {} : { 'Content-Type': 'application/json' }),
          ...(this.session && options.authenticated ? { Authorization: `Bearer ${this.session.session_token}` } : {}),
          ...options.headers,
        },
        ...(options.body === undefined ? {} : { body: JSON.stringify(options.body) }),
        cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer', credentials: 'omit',
      })
    } catch {
      throw new AdminApiError(0, 'NETWORK')
    }
    let payload: unknown
    try { payload = await response.json() } catch { throw new AdminDataError() }
    if (!response.ok) throw parseError(response.status, payload)
    if (!record(payload) || payload.schema_version !== 1) throw new AdminDataError()
    return payload
  }
}

function isValidMutationBody(body: AdminMutationInput): boolean {
  const reason = body.reason
  const version = body.expected_version
  return typeof reason === 'string' && reason.trim().length > 0 && reason.length <= 512 &&
    withinCharacters(reason, 512) && !hasControlChars(reason) && typeof version === 'string' && DECIMAL_UINT.test(version)
}

