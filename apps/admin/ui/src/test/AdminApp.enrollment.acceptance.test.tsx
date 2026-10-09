import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { AdminApp } from '../AdminApp'
import { AdminApiClient, type FetchLike } from '../api/client'

const NOW = BigInt(Date.now()) * 1_000_000n
const URI = 'otpauth://totp/Leviathan:owner%40example.test?secret=JBSWY3DPEHPK3PXP&issuer=Leviathan&algorithm=SHA1&digits=6&period=30'
const KEY = 'JBSWY3DPEHPK3PXP'
const PASSWORD = 'first-login-password-fixture'
const CONFIRM_CODE = '123456'
const NEXT_CODE = '234567'

function envelope(data: unknown, requestId = 'request-1') {
  return { schema_version: 1, request_id: requestId, observed_at_ns: NOW.toString(), data }
}

function response(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

function sessionResponse() {
  return response(envelope({
    session_token: 'admin-session-token-fixture',
    expires_at_utc_ns: (NOW + 60_000_000_000n).toString(),
    org_id: 'org-1',
    audit_id: 'audit-login',
  }))
}

function accountsResponse() {
  return response(envelope({ items: [{ org_id: 'org-1', display_name: 'Owner workspace', version: '1' }], next_cursor: null }))
}

function fillCredentials() {
  fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'owner@example.test' } })
  fireEvent.change(screen.getByLabelText('Password'), { target: { value: PASSWORD } })
}

function storageValues(storage: Storage): string[] {
  return Array.from({ length: storage.length }, (_, index) => storage.getItem(storage.key(index) ?? '') ?? '')
}

afterEach(() => {
  window.localStorage.clear()
  window.sessionStorage.clear()
  vi.restoreAllMocks()
})

describe('ADMIN-APP-ENROLL-001 acceptance', () => {
  it('shows a first-login enrollment URI as text, confirms at the enrollment route, then clears enrollment secrets and signs in', async () => {
    let sessionAttempts = 0
    const requests: Array<{ url: string; init?: RequestInit }> = []
    const fetcher: FetchLike = vi.fn(async (input, init) => {
      const url = String(input)
      requests.push({ url, init })
      if (url.endsWith('/v1/admin/session') && init?.method === 'POST') {
        sessionAttempts += 1
        return sessionAttempts === 1
          ? response({
            schema_version: 1,
            request_id: 'request-enrollment',
            observed_at_ns: NOW.toString(),
            data: { otpauth_uri: URI },
            error: { code: 'TOTP_ENROLLMENT_REQUIRED', message: 'Authenticator enrollment is required' },
          }, 403)
          : sessionResponse()
      }
      if (url.endsWith('/v1/admin/session/enrollment/confirm') && init?.method === 'POST') {
        return response(envelope({ enrolled: true }, 'request-confirm'))
      }
      if (url.includes('/v1/admin/accounts?') && init?.method === 'GET') return accountsResponse()
      return response({ schema_version: 1, request_id: 'request-not-found', observed_at_ns: NOW.toString(), error: { code: 'NOT_FOUND' } }, 404)
    })
    const logSpies = [vi.spyOn(console, 'log'), vi.spyOn(console, 'info'), vi.spyOn(console, 'warn'), vi.spyOn(console, 'error')]
    const storageWriteSpy = vi.spyOn(Storage.prototype, 'setItem')
    const client = new AdminApiClient(fetcher, () => NOW)

    render(<AdminApp client={client} deviceIdProvider={async () => 'a'.repeat(32)} />)
    fillCredentials()
    fireEvent.click(screen.getByRole('button', { name: 'Continue securely' }))

    const uriField = await screen.findByLabelText('Authenticator setup URI')
    expect(uriField).toHaveValue(URI)
    expect(uriField.tagName).toBe('TEXTAREA')
    expect(screen.getByText(KEY, { exact: true })).toBeInTheDocument()
    expect(screen.getAllByLabelText('Authenticator setup URI')).toHaveLength(1)
    expect(screen.getAllByText(KEY, { exact: true })).toHaveLength(1)

    const codeInput = screen.getAllByLabelText(/code/i).at(-1)
    expect(codeInput).toBeTruthy()
    fireEvent.change(codeInput!, { target: { value: CONFIRM_CODE } })
    const clock = vi.spyOn(Date, 'now').mockReturnValue(29_500)
    fireEvent.click(screen.getByRole('button', { name: /confirm/i }))

    expect(await screen.findByText(/authenticator enrolled.*wait for the next code/i)).toBeInTheDocument()
    expect(requests.filter(({ url, init }) => url.endsWith('/v1/admin/session') && init?.method === 'POST')).toHaveLength(1)
    expect(screen.queryByLabelText('Authenticator setup URI')).not.toBeInTheDocument()
    expect(screen.queryByText(KEY, { exact: true })).not.toBeInTheDocument()
    const freshCodeInput = screen.getByLabelText(/authentication code/i)
    expect(freshCodeInput).toHaveValue('')
    expect(freshCodeInput).toBeDisabled()
    clock.mockReturnValue(30_001)
    await waitFor(() => expect(freshCodeInput).toBeEnabled())
    clock.mockRestore()
    fireEvent.change(freshCodeInput, { target: { value: NEXT_CODE } })
    fireEvent.click(screen.getByRole('button', { name: /continue securely|sign in/i }))

    await screen.findByText('Owner workspace')
    expect(screen.getByText(/rotate your password/i)).toBeInTheDocument()
    const confirmIndex = requests.findIndex(({ url, init }) => url.endsWith('/v1/admin/session/enrollment/confirm') && init?.method === 'POST')
    const signInIndexes = requests.flatMap(({ url, init }, index) => url.endsWith('/v1/admin/session') && init?.method === 'POST' ? [index] : [])
    expect(confirmIndex).toBeGreaterThan(signInIndexes[0] ?? -1)
    expect(confirmIndex).toBeLessThan(signInIndexes[1] ?? Number.POSITIVE_INFINITY)
    expect(requests[confirmIndex]?.url).toBe('https://licensing-worker.invalid/v1/admin/session/enrollment/confirm')
    const confirmBody = JSON.parse(String(requests[confirmIndex]?.init?.body)) as Record<string, unknown>
    expect(confirmBody).toMatchObject({ owner_email: 'owner@example.test', password: PASSWORD, totp_code: CONFIRM_CODE })
    expect(signInIndexes).toHaveLength(2)
    const initialSignIn = JSON.parse(String(requests[signInIndexes[0] ?? -1]?.init?.body)) as Record<string, unknown>
    const finalSignIn = JSON.parse(String(requests[signInIndexes[1] ?? -1]?.init?.body)) as Record<string, unknown>
    expect(initialSignIn).not.toHaveProperty('totp_code')
    expect(finalSignIn.totp_code).toBe(NEXT_CODE)

    await waitFor(() => {
      expect(screen.queryByLabelText('Authenticator setup URI')).not.toBeInTheDocument()
      expect(screen.queryByText(KEY, { exact: true })).not.toBeInTheDocument()
    })
    expect(screen.queryByLabelText('Password')).not.toBeInTheDocument()
    expect(screen.queryByLabelText(/code/i)).not.toBeInTheDocument()
    expect(window.localStorage.length).toBe(0)
    expect(window.sessionStorage.length).toBe(0)
    const storedWrites = JSON.stringify(storageWriteSpy.mock.calls)
    expect(storedWrites).not.toContain(URI)
    expect(storedWrites).not.toContain(KEY)
    const logged = JSON.stringify(logSpies.flatMap((spy) => spy.mock.calls))
    for (const secret of [URI, KEY, PASSWORD, CONFIRM_CODE]) expect(logged).not.toContain(secret)
    expect([...storageValues(window.localStorage), ...storageValues(window.sessionStorage)].join('\n')).not.toMatch(/otpauth|JBSWY3DPEHPK3PXP/)
  })

  it('keeps an already-enrolled owner on the normal TOTP sign-in path without offering enrollment', async () => {
    let sessionAttempts = 0
    const requests: Array<{ url: string; init?: RequestInit }> = []
    const fetcher: FetchLike = vi.fn(async (input, init) => {
      const url = String(input)
      requests.push({ url, init })
      if (url.endsWith('/v1/admin/session') && init?.method === 'POST') {
        sessionAttempts += 1
        if (sessionAttempts === 1) {
          return response({
            schema_version: 1,
            request_id: 'request-denied',
            observed_at_ns: NOW.toString(),
            error: { code: 'AUTHENTICATION_FAILED', message: 'Authentication failed' },
          }, 401)
        }
        return sessionResponse()
      }
      if (url.includes('/v1/admin/accounts?') && init?.method === 'GET') return accountsResponse()
      return response({ schema_version: 1, request_id: 'request-not-found', observed_at_ns: NOW.toString(), error: { code: 'NOT_FOUND' } }, 404)
    })
    const client = new AdminApiClient(fetcher, () => NOW)

    render(<AdminApp client={client} deviceIdProvider={async () => 'b'.repeat(32)} />)
    fillCredentials()
    fireEvent.change(screen.getByLabelText(/authentication code/i), { target: { value: CONFIRM_CODE } })
    fireEvent.click(screen.getByRole('button', { name: 'Continue securely' }))

    expect(await screen.findByRole('alert')).toBeInTheDocument()
    expect(screen.queryByLabelText('Authenticator setup URI')).not.toBeInTheDocument()
    expect(screen.queryByText(KEY)).not.toBeInTheDocument()
    expect(requests.some(({ url }) => url.endsWith('/v1/admin/session/enrollment/confirm'))).toBe(false)
    fillCredentials()
    fireEvent.change(screen.getByLabelText(/authentication code/i), { target: { value: NEXT_CODE } })
    fireEvent.click(screen.getByRole('button', { name: 'Continue securely' }))

    await screen.findByText('Owner workspace')
    expect(requests.filter(({ url, init }) => url.endsWith('/v1/admin/session') && init?.method === 'POST')).toHaveLength(2)
    const deniedBody = JSON.parse(String(requests[0]?.init?.body)) as Record<string, unknown>
    expect(deniedBody.totp_code).toBe(CONFIRM_CODE)
    expect(requests.some(({ url }) => url.endsWith('/v1/admin/session/enrollment/confirm'))).toBe(false)
    expect(screen.queryByLabelText('Authenticator setup URI')).not.toBeInTheDocument()
    expect(screen.queryByText(KEY)).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /confirm enrollment/i })).not.toBeInTheDocument()
  })
})
