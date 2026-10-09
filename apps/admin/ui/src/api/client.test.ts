import { describe, expect, it, vi } from 'vitest'
import { AdminApiClient, AdminApiError, AdminDataError, CLOCK_SKEW_BOUND_NS, isFreshRead, READ_STALE_BOUND_NS } from './client'

const NOW = 2_000_000_000_000n
const ID = 'request-1'
const session = { schema_version: 1, request_id: ID, observed_at_ns: NOW.toString(), data: { session_token: 'session-secret-value', expires_at_utc_ns: (NOW + 60_000_000_000n).toString(), org_id: 'org-1', audit_id: 'audit-login' } }
const account = { org_id: 'org-1', display_name: 'Example', version: '2' }
const page = (data: unknown, observed = NOW) => ({ schema_version: 1, request_id: ID, observed_at_ns: observed.toString(), data })
const response = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

describe('freshness boundary', () => {
  it('accepts exactly the coordinator-set age and future-skew boundaries', () => {
    expect(READ_STALE_BOUND_NS).toBe(120_000_000_000n)
    expect(CLOCK_SKEW_BOUND_NS).toBe(5_000_000_000n)
    expect(isFreshRead(NOW - READ_STALE_BOUND_NS, NOW)).toBe(true)
    expect(isFreshRead(NOW - READ_STALE_BOUND_NS - 1n, NOW)).toBe(false)
    expect(isFreshRead(NOW + CLOCK_SKEW_BOUND_NS, NOW)).toBe(true)
    expect(isFreshRead(NOW + CLOCK_SKEW_BOUND_NS + 1n, NOW)).toBe(false)
    expect(isFreshRead(0n, NOW)).toBe(false)
  })
})

describe('AdminApiClient', () => {
  it('keeps the bearer token in memory and sends only the scoped session route', async () => {
    const fetcher = vi.fn()
      .mockResolvedValueOnce(response(session))
      .mockResolvedValueOnce(response(page({ items: [account], next_cursor: null })))
    const client = new AdminApiClient(fetcher, () => NOW)
    await client.signIn({ owner_email: 'owner@example.test', password: 'passphrase', totp_code: '123456', device_id: 'a'.repeat(32) })
    expect(client.currentSession).toEqual({ schema_version: 1, expires_at_utc_ns: session.data.expires_at_utc_ns, org_id: 'org-1', audit_id: 'audit-login' })
    await client.listAccounts()
    const [signInUrl, signInInit] = fetcher.mock.calls[0]!
    expect(String(signInUrl)).toMatch(/\/v1\/admin\/session$/)
    expect(signInInit).toMatchObject({ method: 'POST', credentials: 'omit', cache: 'no-store' })
    expect(JSON.stringify(signInInit)).not.toContain(session.data.session_token)
    const [, readInit] = fetcher.mock.calls[1]!
    expect(new Headers(readInit?.headers).get('Authorization')).toBe(`Bearer ${session.data.session_token}`)
    expect(window.localStorage.length).toBe(0)
  })

  it('accepts the audited logout receipt and clears the in-memory bearer token', async () => {
    const logout = { schema_version: 1, request_id: 'request-2', observed_at_ns: NOW.toString(), data: { revoked: true }, audit_id: 'audit-logout' }
    const fetcher = vi.fn().mockResolvedValueOnce(response(session)).mockResolvedValueOnce(response(logout))
    const client = new AdminApiClient(fetcher, () => NOW)
    await client.signIn({ owner_email: 'owner@example.test', password: 'passphrase', totp_code: '123456', device_id: 'a'.repeat(32) })
    await expect(client.signOut()).resolves.toBe('audit-logout')
    expect(client.currentSession).toBeNull()
    expect(fetcher.mock.calls[1]?.[1]).toMatchObject({ method: 'DELETE', credentials: 'omit', cache: 'no-store' })
    expect(new Headers(fetcher.mock.calls[1]?.[1]?.headers).get('Authorization')).toBe('Bearer session-secret-value')
  })

  it('rejects unknown row status and malformed read evidence', async () => {
    const fetcher = vi.fn().mockResolvedValueOnce(response(session)).mockResolvedValueOnce(response(page({
      items: [{ user_id: 'user-1', role_id: 'role-1', seat_id: null, status: 'UNKNOWN', version: '1' }], next_cursor: null,
    })))
    const client = new AdminApiClient(fetcher, () => NOW)
    await client.signIn({ owner_email: 'owner@example.test', password: 'passphrase', totp_code: '123456', device_id: 'a'.repeat(32) })
    await expect(client.listUsers('org-1')).rejects.toBeInstanceOf(AdminDataError)
  })

  it('refuses a crafted cross-organization path before making a request', async () => {
    const fetcher = vi.fn().mockResolvedValueOnce(response(session))
    const client = new AdminApiClient(fetcher, () => NOW)
    await client.signIn({ owner_email: 'owner@example.test', password: 'passphrase', totp_code: '123456', device_id: 'a'.repeat(32) })
    await expect(client.listAudit('org-other')).rejects.toBeInstanceOf(AdminDataError)
    expect(fetcher).toHaveBeenCalledTimes(1)
  })

  it('requires reason and expected version, and sends an idempotency key with a valid acknowledged receipt', async () => {
    const receipt = page({ resource_id: 'org-2', resource_version: '1' })
    const ack = { ...receipt, audit_id: 'audit-1' }
    const fetcher = vi.fn().mockResolvedValueOnce(response(session)).mockResolvedValueOnce(response(ack))
    const client = new AdminApiClient(fetcher, () => NOW)
    await client.signIn({ owner_email: 'owner@example.test', password: 'passphrase', totp_code: '123456', device_id: 'a'.repeat(32) })
    await expect(client.mutate('/accounts', { reason: 'create organization', expected_version: '0' }, 'idem-1')).resolves.toMatchObject({ audit_id: 'audit-1' })
    const [url, init] = fetcher.mock.calls[1]!
    expect(String(url)).toMatch(/\/v1\/admin\/accounts$/)
    expect(init).toMatchObject({ method: 'POST' })
    expect(new Headers(init?.headers).get('Idempotency-Key')).toBe('idem-1')
    await expect(client.mutate('/accounts', { reason: 'bad\nreason', expected_version: '0' }, 'idem-2')).rejects.toBeInstanceOf(AdminDataError)
    await expect(client.mutate('/accounts', { reason: 'missing version' }, 'idem-3')).rejects.toBeInstanceOf(AdminDataError)
    expect(fetcher).toHaveBeenCalledTimes(2)
  })

  it('maps malformed or provider-verbose errors to an opaque code and never exposes the message', async () => {
    const fetcher = vi.fn().mockResolvedValueOnce(response(session)).mockResolvedValueOnce(response({
      schema_version: 1, request_id: 'request-2', observed_at_ns: NOW.toString(),
      error: { code: 'VERSION_CONFLICT', message: 'secret provider detail' },
    }, 409))
    const client = new AdminApiClient(fetcher, () => NOW)
    await client.signIn({ owner_email: 'owner@example.test', password: 'passphrase', totp_code: '123456', device_id: 'a'.repeat(32) })
    const error = await client.mutate('/accounts', { reason: 'change', expected_version: '0' }, 'idem-4').catch((cause: unknown) => cause)
    expect(error).toBeInstanceOf(AdminApiError)
    expect((error as AdminApiError).code).toBe('VERSION_CONFLICT')
    expect((error as Error).message).not.toContain('secret provider detail')
  })

  it('exposes only a validated first-owner enrollment challenge and confirms through the dedicated route', async () => {
    const secret = 'JBSWY3DPEHPK3PXP'
    const otpauthUri = `otpauth://totp/Leviathan:owner%40example.test?secret=${secret}&issuer=Leviathan&algorithm=SHA1&digits=6&period=30`
    const challenge = { ...page(undefined), error: { code: 'TOTP_ENROLLMENT_REQUIRED', message: 'Enrollment required' }, data: { otpauth_uri: otpauthUri } }
    const confirmed = page({ enrolled: true })
    const fetcher = vi.fn().mockResolvedValueOnce(response(challenge, 403)).mockResolvedValueOnce(response(confirmed))
    const client = new AdminApiClient(fetcher, () => NOW)
    const cause = await client.signIn({ owner_email: 'owner@example.test', password: 'long-passphrase', device_id: 'a'.repeat(32) }).catch((error: unknown) => error)
    expect(cause).toBeInstanceOf(AdminApiError)
    expect((cause as AdminApiError).code).toBe('TOTP_ENROLLMENT_REQUIRED')
    expect((cause as AdminApiError).totpEnrollmentChallenge).toEqual({ otpauthUri, base32Secret: secret })
    expect((cause as Error).message).not.toContain(secret)

    await client.confirmTotpEnrollment({ owner_email: 'owner@example.test', password: 'long-passphrase', totp_code: '123456' })
    const [confirmUrl, confirmInit] = fetcher.mock.calls[1]!
    expect(String(confirmUrl)).toMatch(/\/v1\/admin\/session\/enrollment\/confirm$/)
    expect(confirmInit).toMatchObject({ method: 'POST', credentials: 'omit', cache: 'no-store' })
    expect(JSON.parse(String(confirmInit?.body))).toEqual({ owner_email: 'owner@example.test', password: 'long-passphrase', totp_code: '123456' })
  })

  it('does not expose malformed enrollment URI secrets', async () => {
    const invalidUri = 'otpauth://totp/owner?secret=NOT-BASE32-0&issuer=Leviathan&algorithm=SHA1&digits=6&period=30'
    const challenge = { ...page(undefined), error: { code: 'TOTP_ENROLLMENT_REQUIRED', message: 'Enrollment required' }, data: { otpauth_uri: invalidUri } }
    const client = new AdminApiClient(vi.fn().mockResolvedValueOnce(response(challenge, 403)), () => NOW)
    const cause = await client.signIn({ owner_email: 'owner@example.test', password: 'long-passphrase', device_id: 'a'.repeat(32) }).catch((error: unknown) => error)
    expect((cause as AdminApiError).totpEnrollmentChallenge).toBeNull()
    expect((cause as Error).message).not.toContain('NOT-BASE32-0')
  })
})
