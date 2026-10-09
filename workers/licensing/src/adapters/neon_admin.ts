import type {
  AdminApiDependenciesV1, AdminAuthenticationPortV1, AdminAuthorizationPortV1,
  AdminOwnerAuthRecordV1, AdminPrincipalV1, AdminApiStorePortV1, AdminTransactionV1,
  AdminAuditRowV1, AdminDeviceRowV1, AdminSubscriptionRowV1, AdminUserRowV1,
  AdminUserSeatRecordV1, AdminAccountRowV1, AdminPageV1, AdminListQueryV1, AdminMutationContextV1,
  AdminMutationReceiptV1, AdminSubscriptionStatusV1,
} from "../admin_api/models.js";
import type { PgQueryV1 } from "../db/repository.js";

const PBKDF2_ITERATIONS = 600_000;
const PBKDF2_SALT_BYTES = 16;
const PBKDF2_HASH_BYTES = 32;
const B64 = /^[A-Za-z0-9+/]+={0,2}$/;
const ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;

function ab(bytes: Uint8Array): ArrayBuffer {
  const copy = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(copy).set(bytes);
  return copy;
}
function b64(bytes: Uint8Array): string {
  let raw = "";
  for (const byte of bytes) raw += String.fromCharCode(byte);
  return btoa(raw);
}
function unb64(value: string): Uint8Array | null {
  if (!B64.test(value) || value.length > 4096) return null;
  try {
    const raw = atob(value);
    return Uint8Array.from(raw, (char) => char.charCodeAt(0));
  } catch { return null; }
}
function equal(a: Uint8Array, b: Uint8Array): boolean {
  let diff = a.length ^ b.length;
  const length = Math.max(a.length, b.length);
  for (let i = 0; i < length; i += 1) diff |= (a[i % (a.length || 1)] ?? 0) ^ (b[i % (b.length || 1)] ?? 0);
  return diff === 0;
}

async function derive(password: string, salt: Uint8Array, iterations: number, cryptoApi: Crypto): Promise<Uint8Array> {
  const key = await cryptoApi.subtle.importKey("raw", ab(new TextEncoder().encode(password)), "PBKDF2", false, ["deriveBits"]);
  return new Uint8Array(await cryptoApi.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: ab(salt), iterations }, key, PBKDF2_HASH_BYTES * 8,
  ));
}

/** Worker-runtime PBKDF2 substitute; encoding is `pbkdf2-sha256$iterations$salt$hash`. */
export async function hashPasswordPbkdf2V1(password: string, cryptoApi: Crypto = globalThis.crypto): Promise<string> {
  if (typeof password !== "string" || password.length < 12 || password.length > 256) throw new TypeError("INVALID_PASSWORD");
  const salt = cryptoApi.getRandomValues(new Uint8Array(PBKDF2_SALT_BYTES));
  const hash = await derive(password, salt, PBKDF2_ITERATIONS, cryptoApi);
  return `pbkdf2-sha256$${PBKDF2_ITERATIONS}$${b64(salt)}$${b64(hash)}`;
}

/** Constant-time verifier; null credentials execute a fixed dummy derivation. */
export async function verifyPasswordPbkdf2V1(
  password: string, encodedHash: string | null, cryptoApi: Crypto = globalThis.crypto,
): Promise<boolean> {
  if (typeof password !== "string" || password.length > 256) password = "invalid-credential";
  let iterations = PBKDF2_ITERATIONS;
  let salt = new Uint8Array(PBKDF2_SALT_BYTES);
  let expected = new Uint8Array(PBKDF2_HASH_BYTES);
  let validEncoding = false;
  const parts = typeof encodedHash === "string" ? encodedHash.split("$") : [];
  if (parts.length === 4 && parts[0] === "pbkdf2-sha256" && /^(?:[1-9][0-9]{0,8})$/.test(parts[1]!)) {
    const n = Number(parts[1]);
    const decodedSalt = unb64(parts[2]!);
    const decodedHash = unb64(parts[3]!);
    if (n >= PBKDF2_ITERATIONS && n <= 5_000_000 && decodedSalt?.length === PBKDF2_SALT_BYTES
        && decodedHash?.length === PBKDF2_HASH_BYTES) {
      iterations = n;
      salt = new Uint8Array(decodedSalt);
      expected = new Uint8Array(decodedHash);
      validEncoding = true;
    }
  }
  const actual = await derive(password, salt, iterations, cryptoApi);
  return validEncoding && equal(actual, expected);
}

function base32Decode(value: string): Uint8Array | null {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const normalized = value.replace(/=+$/, "").toUpperCase();
  if (!/^[A-Z2-7]{16,128}$/.test(normalized)) return null;
  const output: number[] = [];
  let buffer = 0; let bits = 0;
  for (const char of normalized) {
    buffer = (buffer << 5) | alphabet.indexOf(char); bits += 5;
    if (bits >= 8) { bits -= 8; output.push((buffer >> bits) & 255); }
  }
  return Uint8Array.from(output);
}
function base32Encode(bytes: Uint8Array): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let buffer = 0; let bits = 0; let out = "";
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte; bits += 8;
    while (bits >= 5) { bits -= 5; out += alphabet[(buffer >> bits) & 31]; }
  }
  if (bits) out += alphabet[(buffer << (5 - bits)) & 31];
  return out;
}
function decodeKey(value: string): Uint8Array | null {
  const key = unb64(value);
  return key?.length === 32 ? key : null;
}

/** Encrypt a base32 TOTP seed with AES-256-GCM and row-bound AAD. */
export async function encryptTotpSecretV1(
  secretBase32: string, keyBase64: string, orgId: string, userId: string,
  cryptoApi: Crypto = globalThis.crypto,
): Promise<string> {
  const keyBytes = decodeKey(keyBase64); const seed = base32Decode(secretBase32);
  if (!keyBytes || !seed || !ID.test(orgId) || !ID.test(userId)) throw new TypeError("NOT_CONFIGURED");
  const key = await cryptoApi.subtle.importKey("raw", ab(keyBytes), "AES-GCM", false, ["encrypt"]);
  const iv = cryptoApi.getRandomValues(new Uint8Array(12));
  const cipher = new Uint8Array(await cryptoApi.subtle.encrypt(
    { name: "AES-GCM", iv: ab(iv), additionalData: ab(new TextEncoder().encode(`${orgId}|${userId}`)), tagLength: 128 },
    key, ab(seed),
  ));
  return `aes256gcm$${b64(iv)}$${b64(cipher)}`;
}

/** Decrypt only when the stored ciphertext's org/user AAD binding matches. */
export async function decryptTotpSecretV1(
  serialized: string, keyBase64: string, orgId: string, userId: string,
  cryptoApi: Crypto = globalThis.crypto,
): Promise<string> {
  const keyBytes = decodeKey(keyBase64); const parts = serialized.split("$");
  const iv = parts.length === 3 && parts[0] === "aes256gcm" ? unb64(parts[1]!) : null;
  const cipher = parts.length === 3 ? unb64(parts[2]!) : null;
  if (!keyBytes || !iv || iv.length !== 12 || !cipher || cipher.length < 17 || !ID.test(orgId) || !ID.test(userId)) {
    throw new TypeError("TOTP_SECRET_UNAVAILABLE");
  }
  const key = await cryptoApi.subtle.importKey("raw", ab(keyBytes), "AES-GCM", false, ["decrypt"]);
  const seed = new Uint8Array(await cryptoApi.subtle.decrypt(
    { name: "AES-GCM", iv: ab(iv), additionalData: ab(new TextEncoder().encode(`${orgId}|${userId}`)), tagLength: 128 },
    key, ab(cipher),
  ));
  return base32Encode(seed);
}

/** Return the matching 30s counter only if it is fresh and within +/- one step. */
export async function verifyTotpStepV1(
  secretBase32: string, code: string, nowUnixSeconds: number, lastAcceptedStep: bigint | null,
  cryptoApi: Crypto = globalThis.crypto,
): Promise<bigint | null> {
  const seed = base32Decode(secretBase32);
  if (!seed || !/^\d{6}$/.test(code) || !Number.isSafeInteger(nowUnixSeconds) || nowUnixSeconds < 0) return null;
  const center = BigInt(Math.floor(nowUnixSeconds / 30));
  const key = await cryptoApi.subtle.importKey("raw", ab(seed), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  for (const step of [center - 1n, center, center + 1n]) {
    if (step < 0n || (lastAcceptedStep !== null && step <= lastAcceptedStep)) continue;
    const message = new Uint8Array(8); let counter = step;
    for (let i = 7; i >= 0; i -= 1) { message[i] = Number(counter & 255n); counter >>= 8n; }
    const digest = new Uint8Array(await cryptoApi.subtle.sign("HMAC", key, ab(message)));
    const offset = digest[digest.length - 1]! & 15;
    const binary = ((digest[offset]! & 127) << 24) | (digest[offset + 1]! << 16)
      | (digest[offset + 2]! << 8) | digest[offset + 3]!;
    if (String(binary % 1_000_000).padStart(6, "0") === code) return step;
  }
  return null;
}

/** A minimal SQL interface shared by the direct Neon and Hyperdrive adapters. */
export interface PgDriverV1 extends PgQueryV1 {
  transaction<T>(work: (tx: PgQueryV1) => Promise<T>): Promise<T>;
  close?(): Promise<void>;
}

/** Adapter seam consumed by fakes; direct Neon uses its Pool transaction discipline. */
export function createNeonPgDriverV1(pool: {
  connect(): Promise<{ query<Row>(sql: string, params?: readonly unknown[]): Promise<{ rows: Row[] }>; release(): void }>;
  query<Row>(sql: string, params?: readonly unknown[]): Promise<{ rows: Row[] }>;
  end(): Promise<void>;
}): PgDriverV1 {
  return Object.freeze({
    query: <Row>(sql: string, params: readonly unknown[]) => pool.query<Row>(sql, params),
    transaction: async <T>(work: (tx: PgQueryV1) => Promise<T>): Promise<T> => {
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        const result = await work({ query: (sql, params) => client.query(sql, params) });
        await client.query("COMMIT"); return result;
      } catch (error) { await client.query("ROLLBACK").catch(() => undefined); throw error; }
      finally { client.release(); }
    },
    close: () => pool.end(),
  });
}

export interface HyperdriveTransactionSqlV1 {
  unsafe<Row = Record<string, unknown>>(sql: string, params?: readonly unknown[]): Promise<Row[]>;
}
export interface HyperdriveSqlV1 extends HyperdriveTransactionSqlV1 {
  begin<T>(work: (transaction: HyperdriveTransactionSqlV1) => Promise<T>): Promise<T>;
  end(options?: { timeout?: number }): Promise<void>;
}

/** Postgres.js/Hyperdrive driver adapter; transaction pooling keeps prepared statements enabled. */
export function createHyperdrivePgDriverV1(sql: HyperdriveSqlV1): PgDriverV1 {
  return Object.freeze({
    query: async <Row>(text: string, params: readonly unknown[]) => ({ rows: await sql.unsafe<Row>(text, [...params]) }),
    transaction: <T>(work: (tx: PgQueryV1) => Promise<T>) => sql.begin((transaction) => work({
      query: async <Row>(text: string, params: readonly unknown[]) => ({ rows: await transaction.unsafe<Row>(text, [...params]) }),
    })),
    close: () => sql.end({ timeout: 5 }),
  });
}

/** A construction bundle that keeps one SQL driver shared across both adapter ports. */
export interface NeonAdminAdapterBundleV1 {
  readonly driver: PgDriverV1;
  readonly auth: AdminAuthenticationPortV1;
  readonly authorization: AdminAuthorizationPortV1;
  readonly store: AdminApiStorePortV1;
}

export function createNeonAdminAdapterV1(driver: PgDriverV1, totpEncryptionKey: string, capsApproved = false): NeonAdminAdapterBundleV1 {
  if (!decodeKey(totpEncryptionKey)) throw new TypeError("NOT_CONFIGURED");
  const nowNs = (): string => (BigInt(Date.now()) * 1_000_000n).toString();
  const sha256 = async (text: string): Promise<string> => Array.from(
    new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", new TextEncoder().encode(text))),
    (byte) => byte.toString(16).padStart(2, "0"),
  ).join("");
  const auth: AdminAuthenticationPortV1 = {
    async findOwnerByEmail(email): Promise<AdminOwnerAuthRecordV1 | null> {
      const result = await driver.query<Record<string, unknown>>(
        "SELECT org_id,user_id,password_hash_pbkdf2,active,owner,totp_enrolled FROM licensing_users WHERE lower(email)=lower($1) AND owner=TRUE LIMIT 1", [email]);
      const row = result.rows[0];
      if (!row || typeof row.org_id !== "string" || typeof row.user_id !== "string"
          || typeof row.password_hash_pbkdf2 !== "string") return null;
      return Object.freeze({ org_id: row.org_id, user_id: row.user_id,
        password_hash_argon2id: row.password_hash_pbkdf2, active: row.active === true,
        owner: row.owner === true, totp_enrolled: row.totp_enrolled === true });
    },
    async isLoginLocked(email, deviceId) {
      const row = (await driver.query<{ locked_until_utc_ns: string | null }>(
        "SELECT locked_until_utc_ns::text AS locked_until_utc_ns FROM licensing_users WHERE lower(email)=lower($1) AND owner=TRUE LIMIT 1", [email])).rows[0];
      const until = row?.locked_until_utc_ns;
      return typeof until === "string" && BigInt(until) > BigInt(nowNs());
    },
    async recordFailedLogin(input) {
      const now = BigInt(input.occurred_at_utc_ns);
      const lockUntil = (now + BigInt(input.lockout_seconds) * 1_000_000_000n).toString();
      const result = await driver.query<{ failed_login_count: number }>(
        "UPDATE licensing_users SET failed_login_count=failed_login_count+1,locked_until_utc_ns=CASE WHEN failed_login_count+1 >= $3 THEN $4 ELSE locked_until_utc_ns END WHERE lower(email)=lower($1) AND owner=TRUE RETURNING failed_login_count",
        [input.email,input.device_id,input.max_failed_attempts,lockUntil]);
      return (result.rows[0]?.failed_login_count ?? 0) >= input.max_failed_attempts;
    },
    async clearFailedLogins(email) {
      await driver.query("UPDATE licensing_users SET failed_login_count=0,locked_until_utc_ns=NULL WHERE lower(email)=lower($1) AND owner=TRUE", [email]);
    },
    verifyArgon2id(password, encodedHash) { return verifyPasswordPbkdf2V1(password, encodedHash); },
    async verifyTotp(userId, code, occurredAt) {
      return driver.transaction(async (tx) => {
        const selected = await tx.query<{ org_id: string; totp_secret_ciphertext: string | null; totp_enrolled: boolean; totp_last_step: string | null }>(
          "SELECT org_id,totp_secret_ciphertext,totp_enrolled,totp_last_step::text AS totp_last_step FROM licensing_users WHERE user_id=$1 AND owner=TRUE FOR UPDATE", [userId]);
        const row = selected.rows[0];
        if (!row || row.totp_enrolled !== true || typeof row.totp_secret_ciphertext !== "string") return false;
        let secret: string;
        try { secret = await decryptTotpSecretV1(row.totp_secret_ciphertext, totpEncryptionKey, row.org_id, userId); }
        catch { return false; }
        const step = await verifyTotpStepV1(secret, code, Number(BigInt(occurredAt) / 1_000_000_000n),
          row.totp_last_step === null ? null : BigInt(row.totp_last_step));
        if (step === null) return false;
        const changed = await tx.query("UPDATE licensing_users SET totp_last_step=$3 WHERE org_id=$1 AND user_id=$2 AND (totp_last_step IS NULL OR totp_last_step<$3)",
          [row.org_id,userId,step.toString()]);
        return changed.rows.length === 1;
      });
    },
    async beginTotpEnrollment(userId, email) {
      if (!ID.test(userId) || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new Error("AUTH_UNAVAILABLE");
      return driver.transaction(async (tx) => {
        const selected = await tx.query<{ org_id: string; totp_enrolled: boolean; totp_secret_ciphertext: string | null }>(
          "SELECT org_id,totp_enrolled,totp_secret_ciphertext FROM licensing_users WHERE user_id=$1 AND lower(email)=lower($2) AND owner=TRUE FOR UPDATE",
          [userId,email]);
        const row = selected.rows[0];
        if (!row || row.totp_enrolled) throw new Error("AUTH_UNAVAILABLE");
        let seed: string;
        if (row.totp_secret_ciphertext) seed = await decryptTotpSecretV1(row.totp_secret_ciphertext, totpEncryptionKey, row.org_id, userId);
        else {
          seed = base32Encode(globalThis.crypto.getRandomValues(new Uint8Array(20)));
          const encrypted = await encryptTotpSecretV1(seed, totpEncryptionKey, row.org_id, userId);
          const changed = await tx.query("UPDATE licensing_users SET totp_secret_ciphertext=$3 WHERE org_id=$1 AND user_id=$2 AND totp_enrolled=FALSE AND totp_secret_ciphertext IS NULL RETURNING user_id",
            [row.org_id,userId,encrypted]);
          if (changed.rows.length !== 1) throw new Error("AUTH_UNAVAILABLE");
          const occurred = nowNs(); const audit = `audit-${crypto.randomUUID()}`;
          await tx.query("INSERT INTO licensing_audit_events(id,org_id,actor,action,resource,digest,created_at_utc_ns) VALUES ($1,$2,$3,'admin.totp.enrollment.start',$4,$5,$6)",
            [audit,row.org_id,userId,`user:${userId}`,await sha256(encrypted),occurred]);
        }
        const issuer = encodeURIComponent("Leviathan AI");
        return `otpauth://totp/${issuer}:${encodeURIComponent(email)}?secret=${seed}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30`;
      });
    },
    async confirmTotpEnrollment(userId, code, occurredAt) {
      return driver.transaction(async (tx) => {
        const selected = await tx.query<{ org_id: string; totp_enrolled: boolean; totp_secret_ciphertext: string | null; totp_last_step: string | null }>(
          "SELECT org_id,totp_enrolled,totp_secret_ciphertext,totp_last_step::text AS totp_last_step FROM licensing_users WHERE user_id=$1 AND owner=TRUE FOR UPDATE", [userId]);
        const row = selected.rows[0];
        if (!row || row.totp_enrolled || typeof row.totp_secret_ciphertext !== "string") return false;
        const seed = await decryptTotpSecretV1(row.totp_secret_ciphertext, totpEncryptionKey, row.org_id, userId);
        const step = await verifyTotpStepV1(seed, code, Number(BigInt(occurredAt) / 1_000_000_000n),
          row.totp_last_step === null ? null : BigInt(row.totp_last_step));
        if (step === null) return false;
        const changed = await tx.query("UPDATE licensing_users SET totp_enrolled=TRUE,totp_last_step=$3 WHERE org_id=$1 AND user_id=$2 AND totp_enrolled=FALSE",
          [row.org_id,userId,step.toString()]);
        if (changed.rows.length !== 1) return false;
        const audit = `audit-${crypto.randomUUID()}`;
        await tx.query("INSERT INTO licensing_audit_events(id,org_id,actor,action,resource,digest,created_at_utc_ns) VALUES ($1,$2,$3,'admin.totp.enrollment.confirm',$4,$5,$6)",
          [audit,row.org_id,userId,`user:${userId}`,await sha256(row.totp_secret_ciphertext),occurredAt]);
        return true;
      });
    },
    async issueSession(input) {
      const tokenBytes = globalThis.crypto.getRandomValues(new Uint8Array(32));
      const token = b64(tokenBytes).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"");
      const tokenDigest = await sha256(token);
      const sessionId = input.token_id;
      await driver.transaction(async (tx) => {
        const device = await tx.query("SELECT 1 FROM licensing_devices WHERE device_id=$1 AND org_id=$2 AND user_id=$3 AND status='ACTIVE'", [input.device_id,input.org_id,input.user_id]);
        if (device.rows.length !== 1) throw new Error("DEVICE_NOT_ACTIVE");
        await tx.query("INSERT INTO licensing_admin_sessions(session_id,token_digest,org_id,user_id,device_id,issued_at_utc_ns,expires_at_utc_ns) VALUES ($1,$2,$3,$4,$5,$6,$7)",
          [sessionId,tokenDigest,input.org_id,input.user_id,input.device_id,input.issued_at_utc_ns,input.expires_at_utc_ns]);
        await tx.query("INSERT INTO licensing_audit_events(id,org_id,actor,action,resource,digest,created_at_utc_ns) VALUES ($1,$2,$3,'admin.session.issue',$4,$5,$6)",
          [input.audit_id,input.org_id,input.user_id,`session:${sessionId}`,await sha256(tokenDigest),input.issued_at_utc_ns]);
      });
      return token;
    },
    async resolveSession(token, deviceId, now) {
      const tokenDigest = await sha256(token);
      const result = await driver.query<{ session_id: string; org_id: string; user_id: string; device_id: string }>(
        "SELECT s.session_id,s.org_id,s.user_id,s.device_id FROM licensing_admin_sessions s JOIN licensing_users u ON u.org_id=s.org_id AND u.user_id=s.user_id JOIN licensing_devices d ON d.device_id=s.device_id WHERE s.token_digest=$1 AND s.device_id=$2 AND s.session_kind='ADMIN' AND s.revoked_at_utc_ns IS NULL AND s.expires_at_utc_ns>$3 AND u.active=TRUE AND d.status='ACTIVE' LIMIT 1",
        [tokenDigest,deviceId,now]);
      const row = result.rows[0];
      return row ? Object.freeze({ schema_version: 1, org_id: row.org_id, user_id: row.user_id,
        device_id: row.device_id, session_id: row.session_id }) : null;
    },
    async revokeSession(input) {
      const tokenDigest = await sha256(input.token);
      await driver.transaction(async (tx) => {
        const revoked = await tx.query<{ org_id: string; user_id: string; session_id: string }>(
          "UPDATE licensing_admin_sessions SET revoked_at_utc_ns=$3 WHERE token_digest=$1 AND device_id=$2 AND revoked_at_utc_ns IS NULL RETURNING org_id,user_id,session_id",
          [tokenDigest,input.device_id,input.now_utc_ns]);
        const row = revoked.rows[0];
        if (!row) return;
        await tx.query("INSERT INTO licensing_audit_events(id,org_id,actor,action,resource,digest,created_at_utc_ns) VALUES ($1,$2,$3,'admin.session.revoke',$4,$5,$6)",
          [input.audit_id,row.org_id,row.user_id,`session:${row.session_id}`,await sha256(tokenDigest),input.now_utc_ns]);
      });
    },
  };
  const authorization: AdminAuthorizationPortV1 = {
    async authorize(principal: AdminPrincipalV1, _action: string, now) {
      const result = await driver.query("SELECT 1 FROM licensing_users WHERE org_id=$1 AND user_id=$2 AND active=TRUE AND owner=TRUE", [principal.org_id,principal.user_id]);
      return result.rows.length === 1 && BigInt(now) >= 0n;
    },
  };
  const encodeCursor = (last: string, org: string, resource: string): string => b64(new TextEncoder().encode(JSON.stringify([1,org,resource,last])));
  const decodeCursor = (cursor: string, org: string, resource: string): string | null => {
    try {
      const decoded = JSON.parse(atob(cursor)) as unknown;
      return Array.isArray(decoded) && decoded.length === 4 && decoded[0] === 1
        && decoded[1] === org && decoded[2] === resource && typeof decoded[3] === "string" ? decoded[3] : null;
    } catch { return null; }
  };
  const pageRows = async <T>(query: { org_id: string; page_size: number; cursor: string | null },
    resource: string, sql: string, validate: (row: Record<string, unknown>) => T): Promise<AdminPageV1<T>> => {
    const cursor = query.cursor === null ? null : decodeCursor(query.cursor, query.org_id, resource);
    if (query.cursor !== null && cursor === null) throw new Error("INVALID_CURSOR");
    const result = await driver.query<Record<string, unknown>>(sql,
      [query.org_id, cursor, query.page_size + 1]);
    const more = result.rows.length > query.page_size;
    const rows = result.rows.slice(0, query.page_size).map(validate);
    const last = more && rows.length ? (rows[rows.length - 1] as unknown as Record<string, unknown>)[resource === "accounts" ? "org_id" : resource === "users" ? "user_id" : resource === "subscriptions" ? "subscription_id" : resource === "devices" ? "device_id" : "audit_id"] : null;
    return Object.freeze({ items: Object.freeze(rows), next_cursor: typeof last === "string" ? encodeCursor(last,query.org_id,resource) : null });
  };
  const subscriptionRecord = (row: Record<string, unknown>): AdminSubscriptionRowV1 => {
    if (typeof row.subscription_id !== "string" || typeof row.org_id !== "string"
        || typeof row.plan_id !== "string" || typeof row.term_start_utc_ns !== "string"
        || typeof row.term_end_utc_ns !== "string" || typeof row.seats !== "string"
        || typeof row.status !== "string" || !["ACTIVE","PAST_DUE","PAUSED","SUSPENDED","CANCELED","EXPIRED"].includes(row.status)
        || typeof row.version !== "string" || typeof row.created_at_utc_ns !== "string"
        || typeof row.updated_at_utc_ns !== "string") throw new Error("STORE_UNAVAILABLE");
    return Object.freeze({ subscription_id: row.subscription_id, org_id: row.org_id, plan_id: row.plan_id,
      term_start_utc_ns: row.term_start_utc_ns, term_end_utc_ns: row.term_end_utc_ns, seats: row.seats,
      status: row.status as AdminSubscriptionStatusV1, version: row.version,
      created_at_utc_ns: row.created_at_utc_ns, updated_at_utc_ns: row.updated_at_utc_ns });
  };
  const deviceRecord = (row: Record<string, unknown>): AdminDeviceRowV1 => {
    if (typeof row.device_id !== "string" || typeof row.org_id !== "string" || typeof row.user_id !== "string"
        || (row.status !== "ACTIVE" && row.status !== "REVOKED") || typeof row.created_at_utc_ns !== "string"
        || (row.last_seen_at_utc_ns !== null && typeof row.last_seen_at_utc_ns !== "string")
        || (row.revoked_at_utc_ns !== null && typeof row.revoked_at_utc_ns !== "string")
        || typeof row.version !== "string") throw new Error("STORE_UNAVAILABLE");
    return Object.freeze({ device_id: row.device_id, org_id: row.org_id, user_id: row.user_id, status: row.status,
      created_at_utc_ns: row.created_at_utc_ns, last_seen_at_utc_ns: row.last_seen_at_utc_ns,
      revoked_at_utc_ns: row.revoked_at_utc_ns, version: row.version });
  };
  const auditRecord = (row: Record<string, unknown>): AdminAuditRowV1 => {
    if (typeof row.audit_id !== "string" || typeof row.org_id !== "string" || typeof row.actor_user_id !== "string"
        || typeof row.action !== "string" || typeof row.resource !== "string"
        || typeof row.occurred_at_utc_ns !== "string") throw new Error("STORE_UNAVAILABLE");
    const separator = row.resource.indexOf(":");
    return Object.freeze({ audit_id: row.audit_id, org_id: row.org_id, actor_user_id: row.actor_user_id,
      action: row.action, resource_type: separator < 0 ? row.resource : row.resource.slice(0, separator),
      resource_id: separator < 0 ? "" : row.resource.slice(separator + 1), occurred_at_utc_ns: row.occurred_at_utc_ns,
      outcome: "SUCCEEDED", reason: "", correlation_id: row.audit_id });
  };
  const makeTransaction = (pg: PgQueryV1): AdminTransactionV1 => {
    const seatTransactions = { transaction<T>(work: (tx: PgQueryV1) => Promise<T>) { return work(pg); } };
    return {
      seat_transactions: seatTransactions,
      async createOrganization(input) {
        if (input.expected_version !== "0") throw new Error("VERSION_CONFLICT");
        const result = await pg.query<{ org_id: string; active: boolean; display_name: string | null }>(
          "INSERT INTO licensing_organizations(org_id,active,display_name) VALUES ($1,$2,$3) RETURNING org_id,active,display_name",
          [input.org_id,input.active,input.display_name]);
        const row = result.rows[0]; if (!row) throw new Error("STORE_UNAVAILABLE");
        return Object.freeze({ org_id: row.org_id, display_name: row.display_name, version: "1" });
      },
      async createOwnerIdentity(input) {
        await pg.query("INSERT INTO licensing_users(org_id,user_id,email,role_id,password_hash_pbkdf2,active,owner,totp_enrolled,created_at_utc_ns) VALUES ($1,$2,lower($3),'owner',NULL,TRUE,TRUE,FALSE,$4)",
          [input.org_id,input.user_id,input.email,input.occurred_at_utc_ns]);
      },
      async createSubscription(input) {
        if (input.expected_version !== "1" || input.plan_id !== "all_access_v1"
            || !["ACTIVE","PAST_DUE","PAUSED","CANCELED"].includes(input.status)) throw new Error("UNSUPPORTED_STATUS");
        const featureKeys = ["chat_terminal","data_sources","strategy_lab","charts","paper_trading","live_trading","ea_hosting","connections","admin_console","user_settings"];
        const features = JSON.stringify(Object.fromEntries(featureKeys.map((key) => [key, capsApproved])));
        const limits = JSON.stringify({ seat_limit: input.seats, broker_connection_limit: "10", data_source_limit: "50", live_account_limit: "3" });
        const result = await pg.query<{ revision: string }>(
          "INSERT INTO licensing_subscriptions(org_id,subscription_id,revision,status,term_start_utc_ns,term_end_utc_ns,seat_limit,features,limits,billing_reference,billing_amount_decimal,billing_currency,audit_event_id,plan_id,created_at_utc_ns,updated_at_utc_ns) VALUES ($1,$2,1,$3,$4,$5,$6,$7::jsonb,$8::jsonb,NULL,NULL,NULL,$9,$10,$11,$11) RETURNING revision::text AS revision",
          [input.org_id,input.subscription_id,input.status,input.term_start_utc_ns,input.term_end_utc_ns,input.seats,features,limits,input.audit_id,input.plan_id,input.occurred_at_utc_ns]);
        if (result.rows.length !== 1) throw new Error("STORE_UNAVAILABLE");
        const source = `admin-${input.audit_id}`;
        await pg.query("INSERT INTO licensing_subscription_revisions(org_id,subscription_id,revision,status,term_start_utc_ns,term_end_utc_ns,seat_limit,features,limits,billing_reference,billing_amount_decimal,billing_currency,audit_event_id,source_event_id,created_at_utc_ns) VALUES ($1,$2,1,$3,$4,$5,$6,$7::jsonb,$8::jsonb,NULL,NULL,NULL,$9,$10,$11)",
          [input.org_id,input.subscription_id,input.status,input.term_start_utc_ns,input.term_end_utc_ns,input.seats,features,limits,input.audit_id,source,input.occurred_at_utc_ns]);
        await pg.query("INSERT INTO licensing_subscription_outbox(org_id,subscription_id,revision,audit_event_id,source_event_id,created_at_utc_ns,status) VALUES ($1,$2,1,$3,$4,$5,$6)",
          [input.org_id,input.subscription_id,input.audit_id,source,input.occurred_at_utc_ns,input.status]);
        return Object.freeze({ subscription_id: input.subscription_id, org_id: input.org_id, plan_id: input.plan_id,
          term_start_utc_ns: input.term_start_utc_ns, term_end_utc_ns: input.term_end_utc_ns, seats: input.seats,
          status: input.status, version: "1", created_at_utc_ns: input.occurred_at_utc_ns,
          updated_at_utc_ns: input.occurred_at_utc_ns });
      },
      async createUserIdentity(input) {
        await pg.query("INSERT INTO licensing_users(org_id,user_id,email,role_id,password_hash_pbkdf2,active,owner,totp_enrolled,created_at_utc_ns) VALUES ($1,$2,lower($3),'readonly',NULL,TRUE,FALSE,FALSE,$4)",
          [input.org_id,input.user_id,input.email,input.occurred_at_utc_ns]);
      },
      async findCurrentSubscription(orgId, occurred) {
        const result = await pg.query<Record<string, unknown>>(
          "SELECT org_id,subscription_id,plan_id,term_start_utc_ns::text AS term_start_utc_ns,term_end_utc_ns::text AS term_end_utc_ns,seat_limit::text AS seats,status,revision::text AS version,created_at_utc_ns::text AS created_at_utc_ns,updated_at_utc_ns::text AS updated_at_utc_ns FROM licensing_subscriptions WHERE org_id=$1 AND status='ACTIVE' AND term_start_utc_ns<=$2 AND term_end_utc_ns>$2 ORDER BY revision DESC LIMIT 1 FOR UPDATE",
          [orgId,occurred]);
        return result.rows[0] ? subscriptionRecord(result.rows[0]) : null;
      },
      async changeSubscription(input) {
        const current = await pg.query<{ revision: string; plan_id: string; status: AdminSubscriptionStatusV1; term_start_utc_ns: string; term_end_utc_ns: string; seat_limit: string; features: Record<string,boolean>; limits: Record<string,string> }>(
          "SELECT revision::text AS revision,plan_id,status,term_start_utc_ns::text AS term_start_utc_ns,term_end_utc_ns::text AS term_end_utc_ns,seat_limit::text AS seat_limit,features,limits FROM licensing_subscriptions WHERE org_id=$1 AND subscription_id=$2 FOR UPDATE", [input.org_id,input.subscription_id]);
        const row = current.rows[0]; if (!row || row.revision !== input.expected_version) throw new Error("VERSION_CONFLICT");
        const patch = input.patch; const status = (patch.status ?? row.status) as AdminSubscriptionStatusV1;
        if (!["ACTIVE","PAST_DUE","PAUSED","CANCELED"].includes(status)) throw new Error("UNSUPPORTED_STATUS");
        const start = patch.term_start_utc_ns ?? row.term_start_utc_ns; const end = patch.term_end_utc_ns ?? row.term_end_utc_ns;
        const seats = patch.seats ?? row.seat_limit; const planId = patch.plan_id ?? row.plan_id;
        const version = (BigInt(row.revision) + 1n).toString(); const source = `admin-${input.audit_id}`;
        await pg.query("UPDATE licensing_subscriptions SET revision=$3,status=$4,term_start_utc_ns=$5,term_end_utc_ns=$6,seat_limit=$7,plan_id=$8,audit_event_id=$9,updated_at_utc_ns=$10 WHERE org_id=$1 AND subscription_id=$2 AND revision=$11",
          [input.org_id,input.subscription_id,version,status,start,end,seats,planId,input.audit_id,input.occurred_at_utc_ns,input.expected_version]);
        await pg.query("INSERT INTO licensing_subscription_revisions(org_id,subscription_id,revision,status,term_start_utc_ns,term_end_utc_ns,seat_limit,features,limits,billing_reference,billing_amount_decimal,billing_currency,audit_event_id,source_event_id,created_at_utc_ns) VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9::jsonb,NULL,NULL,NULL,$10,$11,$12)",
          [input.org_id,input.subscription_id,version,status,start,end,seats,JSON.stringify(row.features),JSON.stringify(row.limits),input.audit_id,source,input.occurred_at_utc_ns]);
        await pg.query("INSERT INTO licensing_subscription_outbox(org_id,subscription_id,revision,audit_event_id,source_event_id,created_at_utc_ns,status) VALUES ($1,$2,$3,$4,$5,$6,$7)",
          [input.org_id,input.subscription_id,version,input.audit_id,source,input.occurred_at_utc_ns,status]);
        return Object.freeze({ subscription_id: input.subscription_id, org_id: input.org_id, plan_id: planId,
          term_start_utc_ns: start, term_end_utc_ns: end, seats, status, version,
          created_at_utc_ns: input.occurred_at_utc_ns, updated_at_utc_ns: input.occurred_at_utc_ns });
      },
      async revokeDevice(input) {
        const result = await pg.query<Record<string, unknown>>(
          "UPDATE licensing_devices SET status='REVOKED',revoked_at_utc_ns=$4,version=version+1 WHERE org_id=$1 AND device_id=$2 AND version=$3 RETURNING device_id,org_id,user_id,status,created_at_utc_ns::text AS created_at_utc_ns,last_seen_at_utc_ns::text AS last_seen_at_utc_ns,revoked_at_utc_ns::text AS revoked_at_utc_ns,version::text AS version",
          [input.org_id,input.device_id,input.expected_version,input.occurred_at_utc_ns]);
        if (!result.rows[0]) throw new Error("VERSION_CONFLICT");
        return deviceRecord(result.rows[0]);
      },
      async appendAudit(row) {
        await pg.query("INSERT INTO licensing_audit_events(id,org_id,actor,action,resource,digest,created_at_utc_ns) VALUES ($1,$2,$3,$4,$5,$6,$7)",
          [row.audit_id,row.org_id,row.actor_user_id,row.action,`${row.resource_type}:${row.resource_id}`,await sha256(JSON.stringify(row)),row.occurred_at_utc_ns]);
      },
      async saveIdempotency(input) {
        const result = await pg.query("INSERT INTO licensing_admin_idempotency(org_id,actor_user_id,idempotency_key,request_fingerprint,receipt) VALUES ($1,$2,$3,$4,$5::jsonb) ON CONFLICT(org_id,actor_user_id,idempotency_key) DO NOTHING RETURNING receipt",
          [input.org_id,input.actor_user_id,input.idempotency_key,input.request_fingerprint,JSON.stringify(input.receipt)]);
        if (result.rows.length !== 1) throw new Error("IDEMPOTENCY_CONFLICT");
        return input.receipt;
      },
      async readIdempotency(input) {
        const result = await pg.query<{ request_fingerprint: string; receipt: AdminMutationReceiptV1 }>(
          "SELECT request_fingerprint,receipt FROM licensing_admin_idempotency WHERE org_id=$1 AND actor_user_id=$2 AND idempotency_key=$3 AND expires_at_utc_ns>$4",
          [input.org_id,input.actor_user_id,input.idempotency_key,nowNs()]);
        const row = result.rows[0];
        if (!row) return null;
        if (row.request_fingerprint !== input.request_fingerprint) throw new Error("IDEMPOTENCY_CONFLICT");
        return row.receipt;
      },
    };
  };
  const store: AdminApiStorePortV1 = {
    transaction<T>(work: (tx: AdminTransactionV1) => Promise<T>) {
      return driver.transaction((pg) => work(makeTransaction(pg)));
    },
    async readAccount(org_id: string) {
      const result = await driver.query<{ org_id: string; display_name: string | null; active: boolean }>(
        "SELECT org_id,display_name,active FROM licensing_organizations WHERE org_id=$1", [org_id]);
      const row = result.rows[0]; return row ? Object.freeze({ org_id: row.org_id, display_name: row.display_name, version: row.active ? "1" : "0" }) : null;
    },
    async readUser(org_id: string, user_id: string): Promise<AdminUserSeatRecordV1 | null> {
      const result = await driver.query<{ user_id: string; role_id: string; status: AdminUserRowV1["status"]; version: string; subscription_id: string | null; seat_id: string | null }>(
        "SELECT u.user_id,COALESCE(s.role_id,u.role_id) AS role_id,CASE WHEN s.status='INVITED' THEN 'INVITED' WHEN u.active THEN 'ACTIVE' ELSE 'REVOKED' END AS status,u.version::text AS version,s.subscription_id,s.seat_id FROM licensing_users u LEFT JOIN licensing_seats s ON s.org_id=u.org_id AND s.user_id=u.user_id AND s.status IN ('ACTIVE','INVITED') WHERE u.org_id=$1 AND u.user_id=$2 LIMIT 1", [org_id,user_id]);
      const row = result.rows[0]; return row ? Object.freeze({ user_id: row.user_id, role_id: row.role_id, status: row.status,
        version: row.version, subscription_id: row.subscription_id ?? "", seat_id: row.seat_id }) : null;
    },
    async listAccounts(query: AdminListQueryV1) {
      return pageRows(query,"accounts","SELECT org_id,display_name,active FROM licensing_organizations WHERE org_id=$1 AND ($2::text IS NULL OR org_id>$2) ORDER BY org_id LIMIT $3",
        (row) => Object.freeze({ org_id: String(row.org_id), display_name: row.display_name as string|null, version: row.active === true ? "1" : "0" }));
    },
    async listUsers(query: AdminListQueryV1) {
      return pageRows(query,"users","SELECT u.user_id,COALESCE(s.role_id,u.role_id) AS role_id,s.seat_id,CASE WHEN s.status='INVITED' THEN 'INVITED' WHEN u.active THEN 'ACTIVE' ELSE 'REVOKED' END AS status,u.version::text AS version FROM licensing_users u LEFT JOIN licensing_seats s ON s.org_id=u.org_id AND s.user_id=u.user_id AND s.status IN ('ACTIVE','INVITED') WHERE u.org_id=$1 AND ($2::text IS NULL OR u.user_id>$2) ORDER BY u.user_id LIMIT $3",
        (row) => Object.freeze({ user_id: String(row.user_id), role_id: String(row.role_id), seat_id: typeof row.seat_id === "string" ? row.seat_id : null, status: row.status as AdminUserRowV1["status"], version: String(row.version) }));
    },
    async listSubscriptions(query: AdminListQueryV1) {
      return pageRows(query,"subscriptions","SELECT org_id,subscription_id,plan_id,term_start_utc_ns::text AS term_start_utc_ns,term_end_utc_ns::text AS term_end_utc_ns,seat_limit::text AS seats,status,revision::text AS version,created_at_utc_ns::text AS created_at_utc_ns,updated_at_utc_ns::text AS updated_at_utc_ns FROM licensing_subscriptions WHERE org_id=$1 AND ($2::text IS NULL OR subscription_id>$2) ORDER BY subscription_id LIMIT $3",
        (row) => subscriptionRecord(row));
    },
    async readSubscription(org_id: string, subscription_id: string) {
      const result = await driver.query<Record<string, unknown>>("SELECT org_id,subscription_id,plan_id,term_start_utc_ns::text AS term_start_utc_ns,term_end_utc_ns::text AS term_end_utc_ns,seat_limit::text AS seats,status,revision::text AS version,created_at_utc_ns::text AS created_at_utc_ns,updated_at_utc_ns::text AS updated_at_utc_ns FROM licensing_subscriptions WHERE org_id=$1 AND subscription_id=$2",
        [org_id,subscription_id]);
      return result.rows[0] ? subscriptionRecord(result.rows[0]) : null;
    },
    async listDevices(query: AdminListQueryV1) {
      return pageRows(query,"devices","SELECT device_id,org_id,user_id,status,created_at_utc_ns::text AS created_at_utc_ns,last_seen_at_utc_ns::text AS last_seen_at_utc_ns,revoked_at_utc_ns::text AS revoked_at_utc_ns,version::text AS version FROM licensing_devices WHERE org_id=$1 AND ($2::text IS NULL OR device_id>$2) ORDER BY device_id LIMIT $3",
        (row) => deviceRecord(row));
    },
    async listAudit(query: AdminListQueryV1) {
      return pageRows(query,"audit","SELECT id AS audit_id,org_id,actor AS actor_user_id,action,resource,digest,created_at_utc_ns::text AS occurred_at_utc_ns FROM licensing_audit_events WHERE org_id=$1 AND ($2::text IS NULL OR id>$2) ORDER BY id LIMIT $3",
        (row) => auditRecord(row));
    },
    async decodeCursor(cursor, org_id, resource) { return decodeCursor(cursor,org_id,resource); },
    async encodeCursor(last_key, org_id, resource) { return encodeCursor(last_key,org_id,resource); },
  };
  return Object.freeze({ driver, auth, authorization, store });
}

export type { AdminApiDependenciesV1, AdminOwnerAuthRecordV1, AdminPrincipalV1 };
