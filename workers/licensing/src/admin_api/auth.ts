import {
  AdminApiErrorV1,
  type AdminApiDependenciesV1,
  type AdminOwnerAuthRecordV1,
  type AdminPrincipalV1,
} from "./models.js";

const ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
const UINT = /^(0|[1-9][0-9]{0,63})$/;
const TOTP = /^[0-9]{6,8}$/;
const MIN_TTL_SECONDS = 60n;
const MAX_TTL_SECONDS = 900n;
const MAX_LOGIN_FAILURES = 20;
const MAX_LOCKOUT_SECONDS = 3_600;

function validId(value: unknown): value is string {
  return typeof value === "string" && ID.test(value);
}

function nowNs(dependencies: AdminApiDependenciesV1): string {
  let value: string;
  try { value = dependencies.clock.nowUtcNs(); }
  catch { throw new AdminApiErrorV1(503, "AUTH_UNAVAILABLE"); }
  if (!UINT.test(value) || value.length > 64) throw new AdminApiErrorV1(503, "AUTH_UNAVAILABLE");
  return value;
}

function approvedTtlSeconds(dependencies: AdminApiDependenciesV1): bigint {
  const raw = dependencies.session_policy.ttl_seconds;
  if (raw === null || !UINT.test(raw)) throw new AdminApiErrorV1(503, "SESSION_POLICY_NOT_CONFIGURED");
  const ttl = BigInt(raw);
  if (ttl < MIN_TTL_SECONDS || ttl > MAX_TTL_SECONDS) {
    throw new AdminApiErrorV1(503, "SESSION_POLICY_NOT_CONFIGURED");
  }
  const { max_failed_attempts, lockout_seconds } = dependencies.session_policy;
  if (!Number.isSafeInteger(max_failed_attempts) || max_failed_attempts < 1
      || max_failed_attempts > MAX_LOGIN_FAILURES || !Number.isSafeInteger(lockout_seconds)
      || lockout_seconds < 1 || lockout_seconds > MAX_LOCKOUT_SECONDS) {
    throw new AdminApiErrorV1(503, "SESSION_POLICY_NOT_CONFIGURED");
  }
  return ttl;
}

function email(value: unknown): string {
  if (typeof value !== "string" || value.length > 254 || value.trim() !== value
      || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
    throw new AdminApiErrorV1(400, "INVALID_REQUEST");
  }
  return value.toLowerCase();
}

function credentialRecord(value: unknown): AdminOwnerAuthRecordV1 | null {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  const row = value as Partial<AdminOwnerAuthRecordV1>;
  if (!validId(row.org_id) || !validId(row.user_id)
      || typeof row.password_hash_argon2id !== "string"
      || row.password_hash_argon2id.length < 20 || row.password_hash_argon2id.length > 512
      || row.active !== true || row.owner !== true
      || (row.totp_enrolled !== undefined && typeof row.totp_enrolled !== "boolean")) return null;
  return row as AdminOwnerAuthRecordV1;
}

/**
 * Login is fake-port-only here. Argon2id and TOTP are verified by injected
 * cryptographic adapters; database adapters own bounded, atomic lockout state.
 */
export async function createAdminSessionV1(
  dependencies: AdminApiDependenciesV1,
  input: Readonly<Record<string, unknown>>,
  requestId: string,
): Promise<{ readonly session_token: string; readonly expires_at_utc_ns: string; readonly org_id: string; readonly audit_id: string }> {
  const emailAddress = email(input.owner_email);
  const password = input.password;
  const totpCode = input.totp_code;
  const deviceId = input.device_id;
  if (typeof password !== "string" || password.length < 12 || password.length > 256
      || (totpCode !== undefined && (typeof totpCode !== "string" || !TOTP.test(totpCode))) || !validId(deviceId)) {
    throw new AdminApiErrorV1(400, "INVALID_REQUEST");
  }

  const ttlSeconds = approvedTtlSeconds(dependencies);
  const occurredAt = nowNs(dependencies);
  let locked: boolean;
  let record: AdminOwnerAuthRecordV1 | null;
  try {
    locked = await dependencies.auth.isLoginLocked(emailAddress, deviceId);
    record = credentialRecord(await dependencies.auth.findOwnerByEmail(emailAddress));
  } catch {
    throw new AdminApiErrorV1(503, "AUTH_UNAVAILABLE");
  }
  if (locked) throw new AdminApiErrorV1(429, "LOGIN_LOCKED");

  let passwordValid = false;
  let totpValid = false;
  try {
    passwordValid = await dependencies.auth.verifyArgon2id(password, record?.password_hash_argon2id ?? null);
    if (record && passwordValid && record.active && record.owner && record.totp_enrolled === false) {
      if (!dependencies.auth.beginTotpEnrollment) throw new Error("TOTP_ENROLLMENT_UNAVAILABLE");
      const otpauthUri = await dependencies.auth.beginTotpEnrollment(record.user_id, emailAddress);
      throw new AdminApiErrorV1(403, "TOTP_ENROLLMENT_REQUIRED", { otpauth_uri: otpauthUri });
    }
    if (record && passwordValid && record.active && record.owner && typeof totpCode === "string") {
      totpValid = await dependencies.auth.verifyTotp(record.user_id, totpCode, occurredAt);
    }
  } catch (error) {
    if (error instanceof AdminApiErrorV1) throw error;
    throw new AdminApiErrorV1(503, "AUTH_UNAVAILABLE");
  }
  if (!record || !passwordValid || !totpValid || !record.active || !record.owner) {
    let now = occurredAt;
    try {
      if (await dependencies.auth.recordFailedLogin({
        email: emailAddress,
        device_id: deviceId,
        occurred_at_utc_ns: now,
        max_failed_attempts: dependencies.session_policy.max_failed_attempts,
        lockout_seconds: dependencies.session_policy.lockout_seconds,
      })) throw new AdminApiErrorV1(429, "LOGIN_LOCKED");
    } catch (error) {
      if (error instanceof AdminApiErrorV1) throw error;
      throw new AdminApiErrorV1(503, "AUTH_UNAVAILABLE");
    }
    throw new AdminApiErrorV1(401, "AUTHENTICATION_FAILED");
  }

  try { await dependencies.auth.clearFailedLogins(emailAddress, deviceId); }
  catch { throw new AdminApiErrorV1(503, "AUTH_UNAVAILABLE"); }
  const expiresAt = (BigInt(occurredAt) + ttlSeconds * 1_000_000_000n).toString();
  const auditId = dependencies.ids.next("audit");
  let token: string;
  try {
    token = await dependencies.auth.issueSession({
      org_id: record.org_id,
      user_id: record.user_id,
      device_id: deviceId,
      issued_at_utc_ns: occurredAt,
      expires_at_utc_ns: expiresAt,
      token_id: dependencies.ids.next("session"),
      audit_id: auditId,
      correlation_id: requestId,
      reason: "OWNER_MFA_LOGIN",
    });
  } catch {
    throw new AdminApiErrorV1(503, "AUTH_UNAVAILABLE");
  }
  if (typeof token !== "string" || token.length < 32 || token.length > 512
      || /[\r\n\u0000-\u001f\u007f]/.test(token)) {
    throw new AdminApiErrorV1(503, "AUTH_UNAVAILABLE");
  }
  return Object.freeze({ session_token: token, expires_at_utc_ns: expiresAt, org_id: record.org_id, audit_id: auditId });
}

/** Confirm first-factor ownership and a fresh TOTP step before enabling MFA. */
export async function confirmTotpEnrollmentV1(
  dependencies: AdminApiDependenciesV1, input: Readonly<Record<string, unknown>>,
): Promise<{ readonly enrolled: true }> {
  const emailAddress = email(input.owner_email);
  const password = input.password; const code = input.totp_code;
  if (typeof password !== "string" || password.length < 12 || password.length > 256
      || typeof code !== "string" || !TOTP.test(code)) throw new AdminApiErrorV1(400, "INVALID_REQUEST");
  if (!dependencies.auth.confirmTotpEnrollment) throw new AdminApiErrorV1(503, "AUTH_UNAVAILABLE");
  const record = credentialRecord(await dependencies.auth.findOwnerByEmail(emailAddress));
  const passwordValid = await dependencies.auth.verifyArgon2id(password, record?.password_hash_argon2id ?? null);
  if (!record || !passwordValid || !record.active || !record.owner || record.totp_enrolled !== false) {
    throw new AdminApiErrorV1(401, "AUTHENTICATION_FAILED");
  }
  const confirmed = await dependencies.auth.confirmTotpEnrollment(record.user_id, code, nowNs(dependencies));
  if (!confirmed) throw new AdminApiErrorV1(401, "AUTHENTICATION_FAILED");
  return Object.freeze({ enrolled: true });
}

export async function resolveAdminPrincipalV1(
  dependencies: AdminApiDependenciesV1,
  request: Request,
): Promise<AdminPrincipalV1> {
  const authorization = request.headers.get("authorization");
  const deviceId = request.headers.get("x-device-id");
  if (!authorization?.startsWith("Bearer ") || authorization.length > 520 || !validId(deviceId)) {
    throw new AdminApiErrorV1(401, "UNAUTHENTICATED");
  }
  const token = authorization.slice(7);
  if (token.length < 32 || /[\r\n\u0000-\u001f\u007f]/.test(token)) {
    throw new AdminApiErrorV1(401, "UNAUTHENTICATED");
  }
  const now = nowNs(dependencies);
  let principal: AdminPrincipalV1 | null;
  try { principal = await dependencies.auth.resolveSession(token, deviceId, now); }
  catch { throw new AdminApiErrorV1(503, "AUTH_UNAVAILABLE"); }
  if (!principal || principal.schema_version !== 1 || !validId(principal.org_id)
      || !validId(principal.user_id) || !validId(principal.device_id)
      || !validId(principal.session_id) || principal.device_id !== deviceId) {
    throw new AdminApiErrorV1(401, "UNAUTHENTICATED");
  }
  return Object.freeze({ ...principal });
}

export async function revokeAdminSessionV1(
  dependencies: AdminApiDependenciesV1,
  request: Request,
  principal: AdminPrincipalV1,
  nowUtcNs: string,
  requestId: string,
): Promise<string> {
  const token = request.headers.get("authorization")!.slice(7);
  const auditId = dependencies.ids.next("audit");
  try {
    await dependencies.auth.revokeSession({ token, device_id: principal.device_id,
      now_utc_ns: nowUtcNs, audit_id: auditId, correlation_id: requestId,
      reason: "OWNER_SESSION_REVOKED" });
  }
  catch { throw new AdminApiErrorV1(503, "AUTH_UNAVAILABLE"); }
  return auditId;
}
