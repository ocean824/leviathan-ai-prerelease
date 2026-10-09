import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { AdminApp } from './AdminApp'
import { AdminApiClient, type FetchLike } from './api/client'

function envelope(data: unknown) {
  return { schema_version: 1, request_id: 'req-1', observed_at_ns: (BigInt(Date.now()) * 1_000_000n).toString(), data }
}

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

describe('AdminApp', () => {
  it('enrolls an un-enrolled owner, clears setup material, waits for a fresh code, then signs in', async () => {
    let clock = new Date('2026-10-07T12:00:00.000Z').getTime()
    const dateNow = vi.spyOn(Date, 'now').mockImplementation(() => clock)
    const requests: Array<{ url: string; init?: RequestInit }> = []
    const secret = 'JBSWY3DPEHPK3PXP'
    const otpauthUri = `otpauth://totp/Leviathan:owner%40example.test?secret=${secret}&issuer=Leviathan&algorithm=SHA1&digits=6&period=30`
    const fetcher: FetchLike = vi.fn(async (input, init) => {
      const url = String(input)
      requests.push({ url, init })
      if (url.endsWith('/v1/admin/session') && requests.filter((request) => request.url.endsWith('/v1/admin/session')).length === 1) {
        return json({ ...envelope(undefined), error: { code: 'TOTP_ENROLLMENT_REQUIRED', message: 'Enrollment required' }, data: { otpauth_uri: otpauthUri } }, 403)
      }
      if (url.endsWith('/v1/admin/session/enrollment/confirm')) return json(envelope({ enrolled: true }))
      if (url.endsWith('/v1/admin/session')) return json(envelope({ session_token: 'memory-only-admin-token', expires_at_utc_ns: (BigInt(Date.now()) * 1_000_000n + 60_000_000_000n).toString(), org_id: 'org-1', audit_id: 'audit-login' }))
      if (url.includes('/v1/admin/accounts')) return json(envelope({ items: [], next_cursor: null }))
      return json({ schema_version: 1, request_id: 'req-x', observed_at_ns: (BigInt(Date.now()) * 1_000_000n).toString(), error: { code: 'NOT_FOUND', message: 'No details' } }, 404)
    })
    try {
      const client = new AdminApiClient(fetcher)
      render(<AdminApp client={client} deviceIdProvider={async () => 'a'.repeat(32)} />)
      fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'owner@example.test' } })
      fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'credential-value' } })
      fireEvent.click(screen.getByRole('button', { name: 'Continue securely' }))
      expect(await screen.findByLabelText('Authenticator setup URI')).toHaveValue(otpauthUri)
      expect(screen.getByLabelText('Manual-entry key')).toHaveTextContent(secret)
      expect(screen.queryByRole('img')).not.toBeInTheDocument()

      fireEvent.change(screen.getByLabelText('Authentication code'), { target: { value: '123456' } })
      fireEvent.click(screen.getByRole('button', { name: 'Confirm authenticator' }))
      expect(await screen.findByText(/Authenticator enrolled — wait for the next code, then sign in/)).toBeInTheDocument()
      expect(screen.queryByLabelText('Authenticator setup URI')).not.toBeInTheDocument()
      expect(screen.queryByText(secret)).not.toBeInTheDocument()
      expect(screen.getByLabelText('Authentication code')).toHaveValue('')
      expect(screen.getByLabelText('Authentication code')).toBeDisabled()
      expect(requests.filter((request) => request.url.endsWith('/v1/admin/session'))).toHaveLength(1)

      clock += 30_000
      await waitFor(() => expect(screen.getByLabelText('Authentication code')).toBeEnabled())
      expect(screen.getByLabelText('Authentication code')).toBeEnabled()
      fireEvent.change(screen.getByLabelText('Authentication code'), { target: { value: '654321' } })
      fireEvent.click(screen.getByRole('button', { name: 'Continue securely' }))
      await screen.findByText(/Rotate your password at first sign-in/)
      const sessionPosts = requests.filter((request) => request.url.endsWith('/v1/admin/session'))
      expect(sessionPosts).toHaveLength(2)
      expect(JSON.parse(String(sessionPosts[0]?.init?.body))).not.toHaveProperty('totp_code')
      expect(JSON.parse(String(sessionPosts[1]?.init?.body))).toMatchObject({ totp_code: '654321' })
      expect(requests.some((request) => request.url.endsWith('/v1/admin/session/enrollment/confirm'))).toBe(true)
    } finally {
      dateNow.mockRestore()
    }
  })

  it('creates only after fresh account preflight and shows the server receipt after acknowledgement', async () => {
    const requests: Array<{ url: string; init?: RequestInit }> = []
    const fetcher: FetchLike = vi.fn(async (input, init) => {
      const url = String(input)
      requests.push({ url, init })
      if (url.endsWith('/v1/admin/session')) {
        return json(envelope({ session_token: 'memory-only-admin-token', expires_at_utc_ns: (BigInt(Date.now()) * 1_000_000n + 60_000_000_000n).toString(), org_id: 'org-1', audit_id: 'audit-login' }))
      }
      if (url.endsWith('/v1/admin/accounts') && init?.method === 'POST') {
        return json({ ...envelope({ resource_id: 'org-2', resource_version: '1' }), audit_id: 'audit-accepted' })
      }
      if (url.includes('/v1/admin/accounts') && init?.method === 'GET') {
        return json(envelope({ items: [{ org_id: 'org-1', display_name: 'Current org', version: '4' }], next_cursor: null }))
      }
      return json({ schema_version: 1, request_id: 'req-x', observed_at_ns: (BigInt(Date.now()) * 1_000_000n).toString(), error: { code: 'NOT_FOUND', message: 'No details' } }, 404)
    })
    const client = new AdminApiClient(fetcher)
    render(<AdminApp client={client} deviceIdProvider={async () => 'a'.repeat(32)} />)
    fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'owner@example.test' } })
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'credential-value' } })
    fireEvent.change(screen.getByLabelText('Authentication code'), { target: { value: '123456' } })
    fireEvent.click(screen.getByRole('button', { name: 'Continue securely' }))
    await screen.findByText('Current org')

    fireEvent.click(screen.getByText('Create account', { selector: 'strong' }))
    fireEvent.change(screen.getByLabelText('Organization name'), { target: { value: 'New org' } })
    fireEvent.change(screen.getByLabelText('Owner email'), { target: { value: 'new-owner@example.test' } })
    fireEvent.change(screen.getByLabelText('Plan identifier'), { target: { value: 'plan-basic' } })
    fireEvent.change(screen.getByLabelText('Term start · UTC nanoseconds'), { target: { value: '100' } })
    fireEvent.change(screen.getByLabelText('Term end · UTC nanoseconds'), { target: { value: '200' } })
    fireEvent.change(screen.getByLabelText('Seats'), { target: { value: '3' } })
    fireEvent.change(screen.getByLabelText('Status'), { target: { value: 'ACTIVE' } })
    fireEvent.change(screen.getByLabelText('Reason for this change'), { target: { value: 'Approved onboarding' } })
    const accountForm = screen.getByRole('button', { name: 'Create account' }).closest('form')!
    fireEvent.submit(accountForm)

    await screen.findByText(/audit audit-accepted/)
    await waitFor(() => expect(requests.filter((request) => request.url.endsWith('/v1/admin/accounts') && request.init?.method === 'POST')).toHaveLength(1))
    const createIndex = requests.findIndex((request) => request.url.endsWith('/v1/admin/accounts') && request.init?.method === 'POST')
    expect(requests[createIndex - 1]?.init?.method).toBe('GET')
    expect(requests[createIndex + 1]?.init?.method).toBe('GET')
    const body = JSON.parse(String(requests[createIndex]?.init?.body)) as Record<string, unknown>
    expect(body).toMatchObject({ expected_version: '0', reason: 'Approved onboarding', owner: { email: 'new-owner@example.test' } })
    expect(JSON.stringify(body)).not.toContain('password')
    expect(JSON.stringify(body)).not.toContain('credential-value')
    expect(within(screen.getByRole('main')).queryByText('credential-value')).not.toBeInTheDocument()
  })

  it('keeps state unknown and blocks writes when the authoritative read is stale', async () => {
    let now = BigInt(Date.now()) * 1_000_000n
    const requests: Array<{ url: string; init?: RequestInit }> = []
    const fetcher: FetchLike = vi.fn(async (input, init) => {
      const url = String(input)
      requests.push({ url, init })
      if (url.endsWith('/v1/admin/session')) return json(envelope({ session_token: 'memory-only-admin-token', expires_at_utc_ns: (now + 60_000_000_000n).toString(), org_id: 'org-1', audit_id: 'audit-login' }))
      return json({ schema_version: 1, request_id: 'req-2', observed_at_ns: (now - 120_000_000_001n).toString(), data: { items: [], next_cursor: null } })
    })
    const client = new AdminApiClient(fetcher, () => now)
    render(<AdminApp client={client} deviceIdProvider={async () => 'b'.repeat(32)} />)
    fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'owner@example.test' } })
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'credential-value' } })
    fireEvent.change(screen.getByLabelText('Authentication code'), { target: { value: '123456' } })
    fireEvent.click(screen.getByRole('button', { name: 'Continue securely' }))
    await screen.findByText(/Re-read required/)
    expect(screen.getByTestId('unknown-state')).toBeInTheDocument()
    expect(requests).toHaveLength(2)
    now += 1_000_000n
    expect(requests.every((request) => request.url.endsWith('/v1/admin/session') || request.init?.method === 'GET')).toBe(true)
  })
})
