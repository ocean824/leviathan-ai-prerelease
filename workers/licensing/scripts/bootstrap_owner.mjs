import { randomBytes, randomUUID, webcrypto } from "node:crypto";
import { Pool } from "@neondatabase/serverless";

const ITERATIONS = 600_000;
const encoder = new TextEncoder();
const b64 = (bytes) => Buffer.from(bytes).toString("base64");

async function passwordHash(password) {
  const salt = randomBytes(16);
  const material = await webcrypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = new Uint8Array(await webcrypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: ITERATIONS }, material, 256,
  ));
  return `pbkdf2-sha256$${ITERATIONS}$${b64(salt)}$${b64(bits)}`;
}

export async function bootstrapOwnerV1({ databaseUrl, ownerEmail, ownerPassword, capsApproved, pool } = {}) {
  if (!databaseUrl || !ownerEmail || !ownerPassword || ownerPassword.length < 12 || capsApproved !== true) {
    throw new Error("OWNER_BOOTSTRAP_NOT_CONFIGURED");
  }
  const db = pool ?? new Pool({ connectionString: databaseUrl });
  const client = await db.connect();
  const orgId = `org-${randomUUID()}`; const userId = `user-${randomUUID()}`;
  const deviceId = `device-${randomUUID()}`; const subscriptionId = `sub-${randomUUID()}`; const auditId = `audit-${randomUUID()}`;
  const now = BigInt(Date.now()) * 1_000_000n;
  const end = now + 315_360_000_000_000_000n;
  const termStart = now.toString(); const termEnd = end.toString();
  const hash = await passwordHash(ownerPassword);
  const features = JSON.stringify({ desktop_app: true, market_data: true, analytics: true,
    admin_api: true, connections: true, options: true, order_flow: true });
  const limits = JSON.stringify({ api_rate_limit_rps: "1000", seats: "1000" });
  const digest = Buffer.from(await webcrypto.subtle.digest("SHA-256", encoder.encode(`${orgId}|owner-bootstrap`))).toString("hex");
  try {
    await client.query("BEGIN");
    await client.query("INSERT INTO licensing_organizations(org_id,active,display_name) VALUES ($1,TRUE,'Owner')", [orgId]);
    await client.query(
      "INSERT INTO licensing_users(org_id,user_id,email,role_id,password_hash_pbkdf2,active,owner,totp_enrolled,created_at_utc_ns) VALUES ($1,$2,$3,'Owner',$4,TRUE,TRUE,FALSE,$5)",
      [orgId,userId,ownerEmail.toLowerCase(),hash,termStart],
    );
    await client.query("INSERT INTO licensing_devices(device_id,org_id,user_id,status,created_at_utc_ns) VALUES ($1,$2,$3,'ACTIVE',$4)",
      [deviceId,orgId,userId,termStart]);
    await client.query(
      "INSERT INTO licensing_audit_events(id,org_id,actor,action,resource,digest,created_at_utc_ns) VALUES ($1,$2,'system:bootstrap','owner.bootstrap',$3,$4,$5)",
      [auditId,orgId,`user:${userId}`,digest,termStart],
    );
    await client.query(
      "INSERT INTO licensing_subscriptions(org_id,subscription_id,revision,status,term_start_utc_ns,term_end_utc_ns,seat_limit,features,limits,billing_reference,billing_amount_decimal,billing_currency,audit_event_id) VALUES ($1,$2,1,'ACTIVE',$3,$4,1000,$5::jsonb,$6::jsonb,'invoice-internal-owner',NULL,NULL,$7)",
      [orgId,subscriptionId,termStart,termEnd,features,limits,auditId],
    );
    await client.query(
      "INSERT INTO licensing_subscription_revisions(org_id,subscription_id,revision,status,term_start_utc_ns,term_end_utc_ns,seat_limit,features,limits,billing_reference,billing_amount_decimal,billing_currency,audit_event_id,source_event_id,created_at_utc_ns) VALUES ($1,$2,1,'ACTIVE',$3,$4,1000,$5::jsonb,$6::jsonb,'invoice-internal-owner',NULL,NULL,$7,$8,$3)",
      [orgId,subscriptionId,termStart,termEnd,features,limits,auditId,`bootstrap-${randomUUID()}`],
    );
    await client.query(
      "INSERT INTO licensing_subscription_outbox(org_id,subscription_id,revision,audit_event_id,source_event_id,created_at_utc_ns,status) VALUES ($1,$2,1,$3,$4,$5,'ACTIVE')",
      [orgId,subscriptionId,auditId,`bootstrap-outbox-${randomUUID()}`,termStart],
    );
    await client.query("COMMIT");
    return Object.freeze({ org_id: orgId, user_id: userId, device_id: deviceId, subscription_id: subscriptionId });
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
    if (!pool) await db.end();
  }
}

if (process.argv[1]?.endsWith("bootstrap_owner.mjs")) {
  try {
    await bootstrapOwnerV1({ databaseUrl: process.env.DATABASE_URL,
      ownerEmail: process.env.OWNER_EMAIL, ownerPassword: process.env.OWNER_PASSWORD,
      capsApproved: process.env.CAPS_APPROVED === "true" });
    process.stdout.write("Owner bootstrap completed.\n");
  } catch (error) {
    process.stderr.write("Owner bootstrap failed.\n");
    process.exitCode = 1;
  }
}
