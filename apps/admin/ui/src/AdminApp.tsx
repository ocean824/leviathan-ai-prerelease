import { useCallback, useEffect, useMemo, useState } from 'react'
import type { FormEvent } from 'react'
import { AdminApiError, AdminDataError, AdminApiClient, isFreshRead } from './api/client'
import type { AccountRowV1, AdminSection, AuditRowV1, CreateAccountInput, DeviceRowV1, PageResult, SignInInput, SubscriptionRowV1, SubscriptionStatus, UserRowV1 } from './api/models'
import { SUBSCRIPTION_STATUSES } from './api/models'
import { safeErrorMessage } from './api/safeMessages'
import { acquireDeviceId } from './runtime'

type ViewState = { status: 'unknown' | 'loading' } | { status: 'ready'; section: AdminSection; items: unknown[]; cursor: string | null; nextCursor: string | null }

export interface AdminAppProps {
  client?: AdminApiClient
  deviceIdProvider?: () => Promise<string>
}

const NAV_ITEMS: ReadonlyArray<{ id: AdminSection; label: string; number: string }> = [
  { id: 'accounts', label: 'Accounts', number: '01' },
  { id: 'users', label: 'Users & Roles', number: '02' },
  { id: 'subscriptions', label: 'Subscriptions', number: '03' },
  { id: 'devices', label: 'Devices', number: '04' },
  { id: 'audit', label: 'Audit', number: '05' },
]

const initialAccount: CreateAccountInput = {
  org: { name: '' },
  owner: { email: '' },
  initial_subscription: {
    plan_id: '', term_start_utc_ns: '', term_end_utc_ns: '', seats: '', status: '',
  },
  reason: '',
  expected_version: '0',
}

function idempotencyKey(): string {
  return crypto.randomUUID().replaceAll('-', '')
}

function decimalText(value: string): boolean {
  return /^(0|[1-9][0-9]{0,39})$/.test(value)
}

function safeIdentity(value: string): boolean {
  return /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value)
}

function validReason(value: string): boolean {
  return value.trim().length > 0 && [...value].length <= 512 && ![...value].some((character) => {
    const code = character.codePointAt(0) ?? 0
    return code <= 0x1f || code === 0x7f
  })
}

function pageFor(client: AdminApiClient, section: AdminSection, orgId: string, cursor?: string): Promise<PageResult<unknown>> {
  switch (section) {
    case 'accounts': return client.listAccounts(cursor)
    case 'users': return client.listUsers(orgId, cursor)
    case 'subscriptions': return client.listSubscriptions(orgId, cursor)
    case 'devices': return client.listDevices(orgId, cursor)
    case 'audit': return client.listAudit(orgId, cursor)
  }
}

function SignIn({ client, getDeviceId, onSignedIn }: {
  client: AdminApiClient
  getDeviceId: () => Promise<string>
  onSignedIn: (auditId: string, firstSignIn: boolean) => void
}) {
  const [ownerEmail, setOwnerEmail] = useState('')
  const [password, setPassword] = useState('')
  const [totpCode, setTotpCode] = useState('')
  const [enrollment, setEnrollment] = useState<Readonly<{ otpauthUri: string; base32Secret: string }> | null>(null)
  const [enrolled, setEnrolled] = useState(false)
  const [waitSeconds, setWaitSeconds] = useState(0)
  const [enrollmentNotice, setEnrollmentNotice] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (!enrolled) return
    const timer = window.setInterval(() => {
      const remaining = Math.ceil((30_000 - (Date.now() % 30_000)) / 1_000)
      setWaitSeconds(remaining === 30 ? 0 : remaining)
    }, 250)
    return () => window.clearInterval(timer)
  }, [enrolled])

  function clearEnrollmentMaterial() {
    setEnrollment(null)
    setTotpCode('')
  }

  async function confirmEnrollment(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (busy || !enrollment || !/^\d{6,8}$/.test(totpCode)) return
    setError('')
    setBusy(true)
    try {
      await client.confirmTotpEnrollment({ owner_email: ownerEmail.trim(), password, totp_code: totpCode })
      clearEnrollmentMaterial()
      setEnrolled(true)
      setWaitSeconds(Math.ceil((30_000 - (Date.now() % 30_000)) / 1_000))
      setEnrollmentNotice('Authenticator enrolled — wait for the next code, then sign in.')
    } catch (cause) {
      setTotpCode('')
      setError(safeErrorMessage(cause).text)
    } finally {
      setBusy(false)
    }
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (busy) return
    setError('')
    setBusy(true)
    try {
      const deviceId = await getDeviceId()
      if (!safeIdentity(deviceId) || ownerEmail.trim().length === 0 || password.length === 0 ||
          (totpCode.length > 0 && !/^\d{6,8}$/.test(totpCode)) || (enrolled && (waitSeconds > 0 || !/^\d{6,8}$/.test(totpCode)))) {
        setError(enrolled && waitSeconds > 0 ? 'Wait for the next authentication code before signing in.' : 'Enter a valid email, password, and authentication code.')
        return
      }
      const input: SignInInput = { owner_email: ownerEmail.trim(), password, ...(totpCode ? { totp_code: totpCode } : {}), device_id: deviceId }
      const session = await client.signIn(input)
      setPassword('')
      setTotpCode('')
      clearEnrollmentMaterial()
      onSignedIn(session.audit_id, enrolled)
    } catch (cause) {
      setTotpCode('')
      if (cause instanceof AdminApiError && cause.code === 'TOTP_ENROLLMENT_REQUIRED' && cause.totpEnrollmentChallenge) {
        setEnrollment(cause.totpEnrollmentChallenge)
        setEnrolled(false)
        setEnrollmentNotice('')
      }
      setError(safeErrorMessage(cause).text)
    } finally {
      setBusy(false)
    }
  }

  return <main className="signin-shell">
    <section className="signin-card" aria-labelledby="signin-title">
      <div className="brand-mark" aria-hidden="true">L</div>
      <p className="eyebrow">LEVIATHAN / ADMINISTRATION</p>
      <h1 id="signin-title">Sign in</h1>
      <p className="muted">Use your administrator account and registered device.</p>
      {enrollment ? <form onSubmit={confirmEnrollment} className="form-stack" noValidate>
        <p className="muted">Set up an authenticator app. Enter this address or key manually; the key is shown once.</p>
        <label htmlFor="totp-setup-uri">Authenticator setup URI</label>
        <textarea id="totp-setup-uri" name="otpauth_uri" value={enrollment.otpauthUri} readOnly rows={3} />
        <label htmlFor="totp-setup-key">Manual-entry key</label>
        <output id="totp-setup-key" className="secret-text">{enrollment.base32Secret}</output>
        <p className="muted">Enter the current six-digit code from your authenticator to confirm setup.</p>
        <label htmlFor="totp-code">Authentication code</label>
        <input id="totp-code" name="totp_code" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6,8}" maxLength={8} value={totpCode} onChange={(event) => setTotpCode(event.target.value)} required />
        {error && <p className="message message--error" role="alert">{error}</p>}
        <button className="button button--primary button--wide" type="submit" disabled={busy || !/^\d{6,8}$/.test(totpCode)}>
          {busy ? 'Confirming…' : 'Confirm authenticator'}
        </button>
      </form> : <form onSubmit={submit} className="form-stack" noValidate>
        <label htmlFor="owner-email">Email</label>
        <input id="owner-email" name="owner_email" type="email" autoComplete="username" value={ownerEmail} onChange={(event) => setOwnerEmail(event.target.value)} required />
        <label htmlFor="owner-password">Password</label>
        <input id="owner-password" name="password" type="password" autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} required />
        <label htmlFor="totp-code">Authentication code</label>
        <input id="totp-code" name="totp_code" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6,8}" maxLength={8} value={totpCode} onChange={(event) => setTotpCode(event.target.value)} required={enrolled} disabled={waitSeconds > 0} />
        {enrollmentNotice && <p className="message message--success" role="status">{enrollmentNotice} {waitSeconds > 0 && <span>Next code in {waitSeconds}s.</span>}</p>}
        {error && <p className="message message--error" role="alert">{error}</p>}
        <button className="button button--primary button--wide" type="submit" disabled={busy}>
          {busy ? 'Verifying…' : 'Continue securely'}
        </button>
      </form>}
      <p className="signin-footnote">Administrative access is verified by the licensing service.</p>
    </section>
  </main>
}

export function AdminApp({ client: suppliedClient, deviceIdProvider = acquireDeviceId }: AdminAppProps) {
  const client = useMemo(() => suppliedClient ?? new AdminApiClient(), [suppliedClient])
  const [sessionVersion, setSessionVersion] = useState(0)
  const [section, setSection] = useState<AdminSection>('accounts')
  const [view, setView] = useState<ViewState>({ status: 'unknown' })
  const [notice, setNotice] = useState('')
  const [problem, setProblem] = useState('')
  const [busy, setBusy] = useState(false)

  const session = client.currentSession
  const orgId = session?.org_id ?? ''

  const refresh = useCallback(async (selected = section, cursor?: string): Promise<boolean> => {
    if (!client.currentSession) {
      client.signOut()
      setSessionVersion((value) => value + 1)
      setView({ status: 'unknown' })
      return false
    }
    setView({ status: 'loading' })
    setProblem('')
    try {
      const page = await pageFor(client, selected, orgId, cursor)
      if (!isFreshRead(page.observedAtNs)) throw new AdminDataError()
      setView({ status: 'ready', section: selected, items: page.items, cursor: cursor ?? null, nextCursor: page.nextCursor })
      return true
    } catch (cause) {
      setView({ status: 'unknown' })
      setProblem(safeErrorMessage(cause).text)
      if (cause instanceof AdminApiError && cause.status === 401) {
        client.signOut()
        setSessionVersion((value) => value + 1)
      }
      return false
    }
  }, [client, orgId, section])

  useEffect(() => {
    if (!client.currentSession) return
    void refresh(section)
  }, [client, refresh, section, sessionVersion])

  async function signOut() {
    const auditId = await client.signOut()
    setView({ status: 'unknown' })
    setNotice(auditId ? `Sign-out recorded · audit ${auditId}` : '')
    setProblem(auditId ? '' : 'Sign-out could not be verified. Re-read required.')
    setSessionVersion((value) => value + 1)
  }

  async function runMutation(action: (page: PageResult<unknown>) => Promise<{ auditId: string }>) {
    if (busy || !client.currentSession) return
    setBusy(true)
    setView({ status: 'loading' })
    setProblem('')
    setNotice('')
    try {
      const cursor = view.status === 'ready' && view.section === section ? view.cursor ?? undefined : undefined
      const current = await pageFor(client, section, orgId, cursor)
      if (!isFreshRead(current.observedAtNs)) throw new AdminDataError()
      const receipt = await action(current)
      if (!safeIdentity(receipt.auditId)) throw new AdminDataError()
      setNotice(`Change recorded · audit ${receipt.auditId}`)
      await refresh(section, cursor)
    } catch (cause) {
      setView({ status: 'unknown' })
      setProblem(safeErrorMessage(cause).text)
    } finally {
      setBusy(false)
    }
  }

  if (!session) {
    return <>
      {notice && <p className="message message--success" role="status">{notice}</p>}
      {problem && <p className="message message--error" role="alert">{problem}</p>}
      <SignIn client={client} getDeviceId={deviceIdProvider} onSignedIn={(auditId, firstSignIn) => { setNotice(firstSignIn ? `Rotate your password at first sign-in. Sign-in recorded · audit ${auditId}` : `Sign-in recorded · audit ${auditId}`); setProblem(''); setSessionVersion((value) => value + 1) }} />
    </>
  }

  return <div className="admin-app" data-testid="admin-app">
    <aside className="sidebar">
      <div className="sidebar-brand"><span className="brand-mark brand-mark--small" aria-hidden="true">L</span><div><strong>LEVIATHAN</strong><small>ADMIN CONSOLE</small></div></div>
      <div className="sidebar-label">WORKSPACE</div>
      <nav aria-label="Administration sections">
        {NAV_ITEMS.map((item) => <button key={item.id} type="button" className={`nav-item ${section === item.id ? 'nav-item--active' : ''}`} aria-current={section === item.id ? 'page' : undefined} onClick={() => { setSection(item.id); setNotice(''); }}>
          <span className="nav-number">{item.number}</span><span>{item.label}</span><span className="nav-arrow" aria-hidden="true">›</span>
        </button>)}
      </nav>
      <div className="sidebar-bottom"><span className="connection-dot" aria-hidden="true"/><span>SECURE ADMIN SESSION</span><small>Scoped to {orgId}</small></div>
    </aside>

    <main className="main-panel">
      <header className="topbar">
        <div><span className="eyebrow">ACCOUNT OPERATIONS</span><h1>{NAV_ITEMS.find((item) => item.id === section)?.label}</h1></div>
        <div className="topbar-right"><span className="scope-pill"><span className="scope-dot"/>Authorized organization</span><button type="button" className="button button--quiet" onClick={() => void signOut()}>Sign out</button></div>
      </header>
      <section className="content" aria-live="polite" aria-busy={busy || view.status === 'loading'}>
        {notice && <p className="message message--success" role="status">{notice}</p>}
        {problem && <p className="message message--error" role="alert">{problem}</p>}
        {view.status === 'loading' && <div className="empty-state" data-testid="loading-state"><span className="spinner" aria-hidden="true"/><p>Checking the latest server state…</p></div>}
        {view.status === 'unknown' && <div className="empty-state" data-testid="unknown-state"><span className="state-icon state-icon--unknown" aria-hidden="true">?</span><h2>State not verified</h2><p>Refresh the server data before making changes.</p><button className="button button--secondary" type="button" onClick={() => void refresh()}>Refresh state</button></div>}
        {view.status === 'ready' && view.section === section && <><SectionContent section={section} items={view.items} orgId={orgId} client={client} busy={busy} runMutation={runMutation} /><div className="pagination-controls"><span>Page data verified at {view.cursor ? 'continuation' : 'current head'}</span>{view.nextCursor && <button type="button" className="button button--secondary" disabled={busy} onClick={() => void refresh(section, view.nextCursor ?? undefined)}>Next page</button>}</div></>}
      </section>
      <footer className="footer"><span>Server-authoritative workspace</span><span>V1 / SECURE OPERATIONS</span></footer>
    </main>
  </div>
}

function SectionContent({ section, items, orgId, client, busy, runMutation }: {
  section: AdminSection
  items: unknown[]
  orgId: string
  client: AdminApiClient
  busy: boolean
  runMutation: (action: (page: PageResult<unknown>) => Promise<{ auditId: string }>) => Promise<void>
}) {
  switch (section) {
    case 'accounts': return <AccountsSection items={items as AccountRowV1[]} client={client} busy={busy} runMutation={runMutation} />
    case 'users': return <UsersSection items={items as UserRowV1[]} orgId={orgId} client={client} busy={busy} runMutation={runMutation} />
    case 'subscriptions': return <SubscriptionsSection items={items as SubscriptionRowV1[]} orgId={orgId} client={client} busy={busy} runMutation={runMutation} />
    case 'devices': return <DevicesSection items={items as DeviceRowV1[]} orgId={orgId} client={client} busy={busy} runMutation={runMutation} />
    case 'audit': return <AuditSection items={items as AuditRowV1[]} />
  }
}

function AccountsSection({ items, client, busy, runMutation }: {
  items: AccountRowV1[]; client: AdminApiClient; busy: boolean
  runMutation: (action: (page: PageResult<unknown>) => Promise<{ auditId: string }>) => Promise<void>
}) {
  const [form, setForm] = useState<CreateAccountInput>(initialAccount)
  const set = (key: keyof CreateAccountInput['initial_subscription'], value: string) => setForm((previous) => ({ ...previous, initial_subscription: { ...previous.initial_subscription, [key]: value } }))
  return <>
    <SectionIntro eyebrow="ORGANIZATION SCOPE" title="Accounts" description="Account visibility is restricted to the signed-in administrator’s organization." />
    <div className="summary-strip"><div><span>AUTHORIZED ORGANIZATION</span><strong>{items.length}</strong></div><div><span>DATA SOURCE</span><strong>Licensing service</strong></div><div><span>CHANGE POLICY</span><strong>Server acknowledged</strong></div></div>
    <div className="record-grid">{items.map((item) => <article className="record-card" key={item.org_id}><div className="record-card__top"><span className="record-icon">ORG</span><span className="status-badge">Server row</span></div><h3>{item.display_name || 'Organization'}</h3><p className="record-id">{item.org_id}</p><div className="record-meta"><span>Version</span><strong>{item.version}</strong></div></article>)}</div>
    <details className="form-panel"><summary><span><strong>Create account</strong><small>Creates an organization, owner, and initial subscription together.</small></span><span className="summary-action">Open form</span></summary>
      <form className="data-form" onSubmit={(event) => { event.preventDefault(); if (!form.org.name.trim() || !form.owner.email.trim() || !validReason(form.reason) || !isSubscriptionStatus(form.initial_subscription.status) || !safeIdentity(form.initial_subscription.plan_id) || !decimalText(form.initial_subscription.term_start_utc_ns) || !decimalText(form.initial_subscription.term_end_utc_ns) || !decimalText(form.initial_subscription.seats) || BigInt(form.initial_subscription.seats || '0') < 1n || BigInt(form.initial_subscription.term_end_utc_ns || '0') <= BigInt(form.initial_subscription.term_start_utc_ns || '0')) return; void runMutation(async () => { const receipt = await client.mutate('/accounts', { ...form }, idempotencyKey()); setForm(initialAccount); return { auditId: receipt.audit_id }; }); }}>
      <div className="form-grid"><TextField label="Organization name" value={form.org.name} onChange={(value) => setForm((previous) => ({ ...previous, org: { name: value } }))} required />
          <TextField label="Owner email" type="email" value={form.owner.email} onChange={(value) => setForm((previous) => ({ ...previous, owner: { ...previous.owner, email: value } }))} required />
          <TextField label="Plan identifier" value={form.initial_subscription.plan_id} onChange={(value) => set('plan_id', value)} required />
          <TextField label="Term start · UTC nanoseconds" value={form.initial_subscription.term_start_utc_ns} onChange={(value) => set('term_start_utc_ns', value)} required />
          <TextField label="Term end · UTC nanoseconds" value={form.initial_subscription.term_end_utc_ns} onChange={(value) => set('term_end_utc_ns', value)} required />
          <TextField label="Seats" value={form.initial_subscription.seats} onChange={(value) => set('seats', value)} required />
          <StatusField value={form.initial_subscription.status} onChange={(value) => set('status', value)} />
          <TextField label="Reason for this change" value={form.reason} onChange={(value) => setForm((previous) => ({ ...previous, reason: value }))} required />
        </div><button className="button button--primary" type="submit" disabled={busy}>Create account</button>
      </form>
    </details>
  </>
}

function UsersSection({ items, orgId, client, busy, runMutation }: {
  items: UserRowV1[]; orgId: string; client: AdminApiClient; busy: boolean
  runMutation: (action: (page: PageResult<unknown>) => Promise<{ auditId: string }>) => Promise<void>
}) {
  const [email, setEmail] = useState('')
  const [roleId, setRoleId] = useState('')
  const [reason, setReason] = useState('')
  const create = (event: FormEvent<HTMLFormElement>) => { event.preventDefault(); if (!email.trim() || !safeIdentity(roleId) || !validReason(reason)) return; void runMutation(async () => { const receipt = await client.mutate(`/accounts/${encodeURIComponent(orgId)}/users`, { email: email.trim(), role_id: roleId, expected_version: '0', reason }, idempotencyKey()); setEmail(''); setReason(''); return { auditId: receipt.audit_id }; }) }
  return <>
    <SectionIntro eyebrow="TENANT ACCESS" title="Users & Roles" description="User rows and role assignments are read from the authorized organization." />
    <div className="table-wrap"><table><thead><tr><th>User identifier</th><th>Role</th><th>Seat</th><th>Status</th><th>Version</th><th>Change role</th></tr></thead><tbody>
      {items.map((item) => <UserRow key={item.user_id} item={item} orgId={orgId} client={client} busy={busy} runMutation={runMutation} />)}
      {items.length === 0 && <EmptyRow columns={5} text="No user rows were returned for this organization." />}
    </tbody></table></div>
    <form className="inline-create" onSubmit={create}><div><span className="eyebrow">ADD USER</span><strong>Invite a user to this organization</strong></div><TextField label="User email" type="email" value={email} onChange={setEmail} required /><TextField label="Role identifier" value={roleId} onChange={setRoleId} required /><TextField label="Reason" value={reason} onChange={setReason} required /><button className="button button--primary" type="submit" disabled={busy}>Create user</button></form>
  </>
}

function UserRow({ item, orgId, client, busy, runMutation }: {
  item: UserRowV1; orgId: string; client: AdminApiClient; busy: boolean
  runMutation: (action: (page: PageResult<unknown>) => Promise<{ auditId: string }>) => Promise<void>
}) {
  const [nextRole, setNextRole] = useState(item.role_id)
  const [changeReason, setChangeReason] = useState('')
  return <tr><td className="record-id">{item.user_id}</td><td>{item.role_id}</td><td>{item.seat_id ?? '—'}</td><td><StatusBadge value={item.status} /></td><td>{item.version}</td><td><form className="row-action" onSubmit={(event) => { event.preventDefault(); if (!safeIdentity(nextRole) || !validReason(changeReason)) return; void runMutation(async (page) => { const latest = (page.items as UserRowV1[]).find((row) => row.user_id === item.user_id); if (!latest) throw new AdminDataError(); const receipt = await client.put(`/accounts/${encodeURIComponent(orgId)}/users/${encodeURIComponent(item.user_id)}/role`, { role_id: nextRole, expected_version: latest.version, reason: changeReason }, idempotencyKey()); return { auditId: receipt.audit_id }; }); }}><input aria-label={`New role for ${item.user_id}`} value={nextRole} onChange={(event) => setNextRole(event.target.value)} /><input aria-label={`Reason for ${item.user_id}`} value={changeReason} onChange={(event) => setChangeReason(event.target.value)} /><button className="button button--small" type="submit" disabled={busy || !validReason(changeReason)}>Save</button></form></td></tr>
}

function SubscriptionsSection({ items, orgId, client, busy, runMutation }: {
  items: SubscriptionRowV1[]; orgId: string; client: AdminApiClient; busy: boolean
  runMutation: (action: (page: PageResult<unknown>) => Promise<{ auditId: string }>) => Promise<void>
}) {
  const [planId, setPlanId] = useState('')
  const [start, setStart] = useState('')
  const [end, setEnd] = useState('')
  const [seats, setSeats] = useState('')
  const [status, setStatus] = useState<SubscriptionStatus | ''>('')
  const [reason, setReason] = useState('')
  const create = (event: FormEvent<HTMLFormElement>) => { event.preventDefault(); if (!safeIdentity(planId) || !decimalText(start) || !decimalText(end) || !decimalText(seats) || BigInt(seats || '0') < 1n || BigInt(end || '0') <= BigInt(start || '0') || !validReason(reason) || !isSubscriptionStatus(status)) return; void runMutation(async () => { const account = await client.getAccount(orgId); if (!isFreshRead(account.observedAtNs)) throw new AdminDataError(); const receipt = await client.mutate(`/accounts/${encodeURIComponent(orgId)}/subscriptions`, { plan_id: planId, term_start_utc_ns: start, term_end_utc_ns: end, seats, status, expected_version: account.data.version, reason }, idempotencyKey()); return { auditId: receipt.audit_id }; }) }
  return <>
    <SectionIntro eyebrow="ENTITLEMENTS" title="Subscriptions" description="Only server-confirmed status and term values are shown." />
    <div className="record-grid record-grid--subscriptions">{items.map((item) => <article className="record-card" key={item.subscription_id}><div className="record-card__top"><span className="record-icon">SUB</span><StatusBadge value={item.status} /></div><h3>{item.plan_id}</h3><p className="record-id">{item.subscription_id}</p><div className="record-meta"><span>Seats</span><strong>{item.seats}</strong></div><div className="record-meta"><span>Term starts</span><strong>{item.term_start_utc_ns}</strong></div><div className="record-meta"><span>Term ends</span><strong>{item.term_end_utc_ns}</strong></div><div className="record-meta"><span>Version</span><strong>{item.version}</strong></div><SubscriptionActions item={item} orgId={orgId} client={client} busy={busy} runMutation={runMutation} /></article>)}{items.length === 0 && <EmptyCard text="No subscription records were returned." />}</div>
    <form className="form-panel data-form" onSubmit={create}><div className="panel-heading"><div><span className="eyebrow">NEW RECORD</span><h2>Create subscription</h2></div><p>Every term, plan, seat count, and status must be entered explicitly.</p></div><div className="form-grid"><TextField label="Plan identifier" value={planId} onChange={setPlanId} required /><TextField label="Term start · UTC nanoseconds" value={start} onChange={setStart} required /><TextField label="Term end · UTC nanoseconds" value={end} onChange={setEnd} required /><TextField label="Seats" value={seats} onChange={setSeats} required /><StatusField value={status} onChange={setStatus} /><TextField label="Reason for this change" value={reason} onChange={setReason} required /></div><button className="button button--primary" type="submit" disabled={busy}>Create subscription</button></form>
  </>
}

function SubscriptionActions({ item, orgId, client, busy, runMutation }: {
  item: SubscriptionRowV1; orgId: string; client: AdminApiClient; busy: boolean
  runMutation: (action: (page: PageResult<unknown>) => Promise<{ auditId: string }>) => Promise<void>
}) {
  const [newEnd, setNewEnd] = useState(item.term_end_utc_ns)
  const [reason, setReason] = useState('')
  const [resumeStatus, setResumeStatus] = useState('')
  const post = (suffix: string, body: Record<string, string>) => { if (!validReason(reason)) return; void runMutation(async (page) => { const latest = (page.items as SubscriptionRowV1[]).find((row) => row.subscription_id === item.subscription_id); if (!latest) throw new AdminDataError(); const receipt = await client.mutate(`/accounts/${encodeURIComponent(orgId)}/subscriptions/${encodeURIComponent(item.subscription_id)}${suffix}`, { ...body, expected_version: latest.version, reason }, idempotencyKey()); return { auditId: receipt.audit_id }; }) }
  return <div className="card-actions">
    <label>Reason for change<input value={reason} onChange={(event) => setReason(event.target.value)} required /></label>
    <label>Extend through · UTC ns<input value={newEnd} onChange={(event) => setNewEnd(event.target.value)} /></label>
    <button type="button" className="button button--small" disabled={busy || !validReason(reason) || !decimalText(newEnd) || BigInt(newEnd || '0') <= BigInt(item.term_end_utc_ns)} onClick={() => post('/extend', { term_end_utc_ns: newEnd, expected_version: item.version })}>Extend</button>
    {item.status === 'ACTIVE' || item.status === 'PAST_DUE' ? <button type="button" className="button button--small button--danger" disabled={busy || !validReason(reason)} onClick={() => post('/suspend', {})}>Suspend access</button> : null}
    {item.status === 'PAUSED' || item.status === 'SUSPENDED' ? <><label>Resume status<select aria-label={`Resume status for ${item.subscription_id}`} value={resumeStatus} onChange={(event) => setResumeStatus(event.target.value)}><option value="">Select status</option><option value="ACTIVE">Active</option><option value="PAST_DUE">Past due</option></select></label><button type="button" className="button button--small" disabled={busy || !validReason(reason) || (resumeStatus !== 'ACTIVE' && resumeStatus !== 'PAST_DUE')} onClick={() => post('/resume', { target_status: resumeStatus })}>Resume access</button></> : null}
  </div>
}

function DevicesSection({ items, orgId, client, busy, runMutation }: {
  items: DeviceRowV1[]; orgId: string; client: AdminApiClient; busy: boolean
  runMutation: (action: (page: PageResult<unknown>) => Promise<{ auditId: string }>) => Promise<void>
}) {
  return <>
    <SectionIntro eyebrow="DEVICE BINDING" title="Devices" description="Device state is refreshed from the licensing service before revocation." />
    <div className="table-wrap"><table><thead><tr><th>Device identifier</th><th>Status</th><th>Version</th><th>Action</th></tr></thead><tbody>{items.map((item) => <DeviceRow key={item.device_id} item={item} orgId={orgId} client={client} busy={busy} runMutation={runMutation} />)}{items.length === 0 && <EmptyRow columns={4} text="No device records were returned." />}</tbody></table></div>
  </>
}

function DeviceRow({ item, orgId, client, busy, runMutation }: {
  item: DeviceRowV1; orgId: string; client: AdminApiClient; busy: boolean
  runMutation: (action: (page: PageResult<unknown>) => Promise<{ auditId: string }>) => Promise<void>
}) {
  const [reason, setReason] = useState('')
  return <tr><td className="record-id">{item.device_id}</td><td><StatusBadge value={item.status} /></td><td>{item.version}</td><td><div className="row-action"><input aria-label={`Reason for device ${item.device_id}`} value={reason} onChange={(event) => setReason(event.target.value)} /><button className="button button--small button--danger" type="button" disabled={busy || item.status === 'REVOKED' || !validReason(reason)} onClick={() => { if (!validReason(reason)) return; void runMutation(async (page) => { const latest = (page.items as DeviceRowV1[]).find((row) => row.device_id === item.device_id); if (!latest) throw new AdminDataError(); const receipt = await client.mutate(`/accounts/${encodeURIComponent(orgId)}/devices/${encodeURIComponent(item.device_id)}/revoke`, { expected_version: latest.version, reason }, idempotencyKey()); return { auditId: receipt.audit_id }; }); }}>Revoke device</button></div></td></tr>
}

function AuditSection({ items }: { items: AuditRowV1[] }) {
  return <>
    <SectionIntro eyebrow="IMMUTABLE RECORD" title="Audit" description="Administrative actions are displayed from server audit records." />
    <div className="table-wrap"><table><thead><tr><th>Audit identifier</th><th>Action</th><th>Resource</th><th>Outcome</th><th>Occurred at (UTC ns)</th></tr></thead><tbody>{items.map((item) => <tr key={item.audit_id}><td className="record-id">{item.audit_id}</td><td>{item.action}</td><td>{item.resource_type}{item.resource_id ? ` / ${item.resource_id}` : ''}</td><td><StatusBadge value={item.outcome} /></td><td>{item.occurred_at_utc_ns}</td></tr>)}{items.length === 0 && <EmptyRow columns={5} text="No audit rows were returned." />}</tbody></table></div>
  </>
}

function SectionIntro({ eyebrow, title, description }: { eyebrow: string; title: string; description: string }) {
  return <div className="section-intro"><span className="eyebrow">{eyebrow}</span><h2>{title}</h2><p>{description}</p></div>
}

function TextField({ label, value, onChange, type = 'text', required = false }: { label: string; value: string; onChange: (value: string) => void; type?: string; required?: boolean }) {
  return <label className="field">{label}<input type={type} value={value} onChange={(event) => onChange(event.target.value)} required={required} autoComplete="off" /></label>
}

function StatusField({ value, onChange }: { value: SubscriptionStatus | ''; onChange: (value: SubscriptionStatus | '') => void }) {
  return <label className="field">Status<select value={value} onChange={(event) => onChange(event.target.value as SubscriptionStatus | '')}><option value="">Select status</option>{SUBSCRIPTION_STATUSES.map((status) => <option key={status} value={status}>{statusLabel(status)}</option>)}</select></label>
}

function StatusBadge({ value }: { value: string }) {
  const safe = value.length <= 32 && /^[A-Z_]+$/.test(value) ? statusLabel(value) : 'Unknown'
  const tone = safe === 'Active' || safe === 'Verified' ? 'status-badge--active' : safe === 'Unknown' ? 'status-badge--unknown' : 'status-badge--muted'
  return <span className={`status-badge ${tone}`}><span className="status-mark" aria-hidden="true"/>{safe}</span>
}

function isSubscriptionStatus(value: string): value is SubscriptionStatus { return (SUBSCRIPTION_STATUSES as readonly string[]).includes(value) }

function statusLabel(value: string): string { return value.split('_').map((part) => part.slice(0, 1) + part.slice(1).toLowerCase()).join(' ') }

function EmptyRow({ columns, text }: { columns: number; text: string }) { return <tr><td className="empty-cell" colSpan={columns}>{text}</td></tr> }
function EmptyCard({ text }: { text: string }) { return <div className="empty-card">{text}</div> }

