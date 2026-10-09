import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { AdminApp } from '../ui/src/AdminApp'
import { AdminApiClient, isFreshRead } from '../ui/src/api/client'
import type { AdminApiClient as AdminApiClientType } from '../ui/src/api/client'

const NOW_NS = 1_800_000_000_000_000_000n

function page<T>(items: T[], observedAtNs = BigInt(Date.now()) * 1_000_000n) {
  return { items, nextCursor: null, requestId: 'request-test', observedAtNs }
}

function emptyClient() {
  return {
    currentSession: { schema_version: 1, expires_at_utc_ns: (NOW_NS + 60_000_000_000n).toString(), org_id: 'org-test' },
    signOut: vi.fn(),
    listAccounts: vi.fn(async () => page([])),
    listUsers: vi.fn(async () => page([])),
    listSubscriptions: vi.fn(async () => page([])),
    listDevices: vi.fn(async () => page([])),
    listAudit: vi.fn(async () => page([])),
    getAccount: vi.fn(),
    mutate: vi.fn(),
    put: vi.fn(),
    patch: vi.fn(),
  } as unknown as AdminApiClientType
}

describe('ADMIN-APP-001 acceptance UI behavior', () => {
  it('renders sign-in and all five principal-scoped administration screens', async () => {
    const signedOut = emptyClient()
    let activeSession: NonNullable<AdminApiClientType['currentSession']> | null = null
    Object.defineProperty(signedOut, 'currentSession', { get: () => activeSession, configurable: true })
    signedOut.signIn = vi.fn(async () => {
      const session = {
        schema_version: 1,
        expires_at_utc_ns: (NOW_NS + 60_000_000_000n).toString(),
        org_id: 'org-test',
        audit_id: 'audit-login',
      }
      activeSession = session
      return session
    })
    signedOut.signOut = vi.fn(async () => {
      activeSession = null
      return 'audit-logout'
    })

    render(<AdminApp client={signedOut} deviceIdProvider={async () => 'device-test'} />)
    expect(screen.getByRole('heading', { name: 'Sign in' })).toBeInTheDocument()
    expect(screen.getByLabelText('Email')).toBeInTheDocument()
    expect(screen.getByLabelText('Password')).toBeInTheDocument()
    expect(screen.getByLabelText('Authentication code')).toBeInTheDocument()

    fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'operator@example.invalid' } })
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'synthetic-password' } })
    fireEvent.change(screen.getByLabelText('Authentication code'), { target: { value: '123456' } })
    fireEvent.click(screen.getByRole('button', { name: 'Continue securely' }))

    for (const section of ['Accounts', 'Users & Roles', 'Subscriptions', 'Devices', 'Audit']) {
      const button = await screen.findByRole('button', { name: new RegExp(section.replace('&', '\\&')) })
      fireEvent.click(button)
      await waitFor(() => expect(screen.getAllByRole('heading', { name: section }).length).toBeGreaterThan(0))
    }
    fireEvent.click(screen.getByRole('button', { name: 'Sign out' }))
    expect(await screen.findByRole('status')).toHaveTextContent('Sign-out recorded · audit audit-logout')
  })

  it('uses inclusive 120-second age and 5-second future-skew bounds', () => {
    expect(isFreshRead(NOW_NS - 120_000_000_000n, NOW_NS)).toBe(true)
    expect(isFreshRead(NOW_NS - 120_000_000_001n, NOW_NS)).toBe(false)
    expect(isFreshRead(NOW_NS + 5_000_000_000n, NOW_NS)).toBe(true)
    expect(isFreshRead(NOW_NS + 5_000_000_001n, NOW_NS)).toBe(false)
  })

  it.each<[string, bigint]>([
    ['stale', NOW_NS - 120_000_000_001n],
    ['too far in the future', NOW_NS + 5_000_000_001n],
  ])('blocks mutation UI on a %s server read', async (_label, observedAtNs) => {
    const client = emptyClient() as unknown as AdminApiClientType & {
      listAccounts: ReturnType<typeof vi.fn>
    }
    client.listAccounts = vi.fn(async () => page([], observedAtNs))
    render(<AdminApp client={client} />)

    expect(await screen.findByTestId('unknown-state')).toBeInTheDocument()
    expect(screen.getByText('Refresh the server data before making changes.')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Create account' })).not.toBeInTheDocument()
  })

  it('keeps server state hidden until the mutation receipt is acknowledged', async () => {
    let serverStatus = 'ACTIVE'
    let acknowledge: ((receipt: { audit_id: string }) => void) | undefined
    const client = emptyClient() as unknown as AdminApiClientType & {
      mutate: ReturnType<typeof vi.fn>
      listDevices: ReturnType<typeof vi.fn>
    }
    client.listDevices = vi.fn(async () => page([{
      device_id: 'device-test', org_id: 'org-test', user_id: 'user-test', status: serverStatus,
      created_at_utc_ns: '1', last_seen_at_utc_ns: null, revoked_at_utc_ns: null, version: '4',
    }]))
    client.mutate = vi.fn(() => new Promise((resolve) => { acknowledge = resolve }))

    render(<AdminApp client={client} />)
    fireEvent.click(await screen.findByRole('button', { name: /Devices/ }))
    expect(await screen.findByText('Active')).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('Reason for device device-test'), { target: { value: 'operator requested revocation' } })
    fireEvent.click(screen.getByRole('button', { name: 'Revoke device' }))

    expect(await screen.findByTestId('loading-state')).toBeInTheDocument()
    expect(screen.queryByText('Revoked')).not.toBeInTheDocument()
    expect(client.mutate).toHaveBeenCalledTimes(1)
    const [path, body, idempotencyKey] = client.mutate.mock.calls[0]
    expect(path).toContain('/devices/device-test/revoke')
    expect(body).toMatchObject({ expected_version: '4', reason: 'operator requested revocation' })
    expect(idempotencyKey).toMatch(/^[A-Za-z0-9._:-]{1,128}$/)

    serverStatus = 'REVOKED'
    if (!acknowledge) throw new Error('Mutation receipt callback was not registered')
    acknowledge({ audit_id: 'audit-test' })
    expect(await screen.findByText('Revoked')).toBeInTheDocument()
  })

  it('sends mutation idempotency and concurrency fields through the API client', async () => {
    const calls: Array<{ input: RequestInfo | URL; init?: RequestInit }> = []
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ input, init })
      const envelope = { schema_version: 1, request_id: `request-${calls.length}`, observed_at_ns: NOW_NS.toString() }
      const body = calls.length === 1
        ? { ...envelope, data: { session_token: 'synthetic-session-token-123', expires_at_utc_ns: (NOW_NS + 60_000_000_000n).toString(), org_id: 'org-test', audit_id: 'audit-login' } }
        : calls.length === 2
          ? { ...envelope, data: { resource_id: 'user-test', resource_version: '2' }, audit_id: 'audit-test' }
          : { ...envelope, data: { revoked: true }, audit_id: 'audit-logout' }
      return new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } })
    })
    const api = new AdminApiClient(fetcher, () => NOW_NS)
    await api.signIn({ owner_email: 'operator@example.invalid', password: 'synthetic', totp_code: '123456', device_id: 'device-test' })
    await api.mutate('/accounts/org-test/users', { role_id: 'operator', expected_version: '1', reason: 'synthetic test' }, 'idempotency-test-01')

    expect(calls).toHaveLength(2)
    const mutation = calls[1]
    if (!mutation) throw new Error('Mutation request was not recorded')
    const headers = mutation.init?.headers
    if (!headers) throw new Error('Mutation request headers were not recorded')
    expect((headers as Record<string, string>)['Idempotency-Key']).toBe('idempotency-test-01')
    const requestBody = mutation.init?.body
    if (requestBody === undefined) throw new Error('Mutation request body was not recorded')
    expect(JSON.parse(String(requestBody))).toMatchObject({ expected_version: '1', reason: 'synthetic test' })
    await expect(api.signOut()).resolves.toBe('audit-logout')
    expect(calls).toHaveLength(3)
    const logout = calls[2]
    if (!logout) throw new Error('Logout request was not recorded')
    expect(logout.init?.method).toBe('DELETE')
  })
})
