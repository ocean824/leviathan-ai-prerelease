import { confirmTotpEnrollmentV1, createAdminSessionV1, resolveAdminPrincipalV1, revokeAdminSessionV1 } from "./auth.js";
import { adminErrorV1, adminJsonV1, adminResponseContextV1, adminSuccessV1, adminNotConfiguredV1 } from "./handler.js";
import {
  AdminApiErrorV1,
  type AdminApiDependenciesV1,
  type AdminAuditRowV1,
  type AdminPageV1,
  type AdminPrincipalV1,
  type AdminSubscriptionRowV1,
} from "./models.js";
import {
  assertAdminRows,
  authorizeAdminActionV1,
  changeSubscriptionV1,
  createAccountV1,
  createSubscriptionV1,
  createUserV1,
  isAllowedDeviceRow,
  isAllowedUserRow,
  requireReason,
  revokeDeviceV1,
  setUserRoleV1,
  validId,
  validStatus,
  validUint,
} from "./service.js";

const MAX_BODY_BYTES = 64 * 1024;
const PAGE_SIZE_DEFAULT = 50;
const PAGE_SIZE_MAX = 100;
const STATUSES = ["ACTIVE", "PAST_DUE", "PAUSED", "SUSPENDED", "CANCELED", "EXPIRED"] as const;

function record(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exact(value: Record<string, unknown>, keys: readonly string[]): void {
  const actual = Reflect.ownKeys(value);
  if (actual.length !== keys.length || actual.some((key) => typeof key !== "string" || !keys.includes(key))) {
    throw new AdminApiErrorV1(400, "INVALID_REQUEST");
  }
}

function requiredText(value: unknown, max = 256): string {
  if (typeof value !== "string" || value.length === 0 || value.length > max
      || value.trim() !== value || /[\u0000-\u001f\u007f]/.test(value)) {
    throw new AdminApiErrorV1(400, "INVALID_REQUEST");
  }
  return value;
}

function email(value: unknown): string {
  const text = requiredText(value, 254);
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(text)) throw new AdminApiErrorV1(400, "INVALID_REQUEST");
  return text.toLowerCase();
}

async function body(request: Request, keys: readonly string[], optionalKeys: readonly string[] = []): Promise<Record<string, unknown>> {
  if (!request.headers.get("content-type")?.toLowerCase().startsWith("application/json")) {
    throw new AdminApiErrorV1(400, "INVALID_REQUEST");
  }
  const declaredLength = request.headers.get("content-length");
  if (declaredLength && (!/^\d{1,8}$/.test(declaredLength) || Number(declaredLength) > MAX_BODY_BYTES)) {
    throw new AdminApiErrorV1(413, "INVALID_REQUEST");
  }
  let text: string;
  try {
    const reader = request.body?.getReader();
    if (!reader) throw new Error("missing body");
    const chunks: Uint8Array[] = [];
    let total = 0;
    while (true) {
      const part = await reader.read();
      if (part.done) break;
      total += part.value.byteLength;
      if (total > MAX_BODY_BYTES) {
        await reader.cancel();
        throw new AdminApiErrorV1(413, "INVALID_REQUEST");
      }
      chunks.push(part.value);
    }
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch (error) {
    if (error instanceof AdminApiErrorV1) throw error;
    throw new AdminApiErrorV1(400, "INVALID_REQUEST");
  }
  let parsed: unknown;
  try { parsed = JSON.parse(text) as unknown; }
  catch { throw new AdminApiErrorV1(400, "INVALID_REQUEST"); }
  if (!record(parsed) || Object.getOwnPropertySymbols(parsed).length !== 0) {
    throw new AdminApiErrorV1(400, "INVALID_REQUEST");
  }
  const actual = Reflect.ownKeys(parsed);
  if (actual.some((key) => typeof key !== "string" || (!keys.includes(key) && !optionalKeys.includes(key)))
      || keys.some((key) => !Object.prototype.hasOwnProperty.call(parsed, key))) {
    throw new AdminApiErrorV1(400, "INVALID_REQUEST");
  }
  return parsed;
}

function pageQuery(url: URL): { page_size: number; cursor: string | null } {
  const keys: string[] = [];
  url.searchParams.forEach((_value, key) => keys.push(key));
  if (keys.some((key) => key !== "page_size" && key !== "cursor")
      || keys.some((key) => url.searchParams.getAll(key).length !== 1)) {
    throw new AdminApiErrorV1(400, "INVALID_REQUEST");
  }
  const rawSize = url.searchParams.get("page_size");
  const size = rawSize === null ? PAGE_SIZE_DEFAULT : Number(rawSize);
  const cursor = url.searchParams.get("cursor");
  if (!Number.isSafeInteger(size) || size < 1 || size > PAGE_SIZE_MAX
      || (cursor !== null && (cursor.length === 0 || cursor.length > 1024))) {
    throw new AdminApiErrorV1(400, "INVALID_REQUEST");
  }
  return { page_size: size, cursor };
}

async function page<T>(
  dependencies: AdminApiDependenciesV1,
  orgId: string,
  resource: string,
  query: { page_size: number; cursor: string | null },
  read: (cursor: string | null) => Promise<AdminPageV1<T>>,
  validate: (row: unknown) => boolean,
): Promise<AdminPageV1<T>> {
  let decoded: string | null = null;
  if (query.cursor !== null) {
    try { decoded = await dependencies.store.decodeCursor(query.cursor, orgId, resource); }
    catch { throw new AdminApiErrorV1(400, "INVALID_CURSOR"); }
    if (typeof decoded !== "string" || decoded.length === 0 || decoded.length > 512) {
      throw new AdminApiErrorV1(400, "INVALID_CURSOR");
    }
  }
  let value: AdminPageV1<T>;
  try { value = await read(decoded); }
  catch { throw new AdminApiErrorV1(503, "STORE_UNAVAILABLE"); }
  const items = assertAdminRows(value.items, (row) => validate(row)
    && (!record(row) || row.org_id === orgId));
  let next = value.next_cursor;
  if (next !== null) {
    if (typeof next !== "string" || next.length === 0 || next.length > 512) {
      throw new AdminApiErrorV1(503, "STORE_UNAVAILABLE");
    }
    try { next = await dependencies.store.encodeCursor(next, orgId, resource); }
    catch { throw new AdminApiErrorV1(503, "STORE_UNAVAILABLE"); }
    if (typeof next !== "string" || next.length === 0 || next.length > 1024) {
      throw new AdminApiErrorV1(503, "STORE_UNAVAILABLE");
    }
  }
  return Object.freeze({ items, next_cursor: next });
}

function accountRow(value: unknown): boolean {
  if (!record(value)) return false;
  const displayName = value.display_name;
  return validId(value.org_id) && (displayName === null || (typeof displayName === "string" && displayName.length <= 256))
    && validUint(value.version);
}

function subscriptionRow(value: unknown): value is AdminSubscriptionRowV1 {
  if (!record(value)) return false;
  return validId(value.subscription_id) && validId(value.org_id) && validId(value.plan_id)
    && validUint(value.term_start_utc_ns) && validUint(value.term_end_utc_ns)
    && BigInt(value.term_end_utc_ns) > BigInt(value.term_start_utc_ns)
    && validUint(value.seats) && validStatus(value.status) && validUint(value.version)
    && validUint(value.created_at_utc_ns) && validUint(value.updated_at_utc_ns);
}

function auditRow(value: unknown): value is AdminAuditRowV1 {
  if (!record(value)) return false;
  return validId(value.audit_id) && validId(value.org_id) && validId(value.actor_user_id)
    && typeof value.action === "string" && value.action.length > 0 && value.action.length <= 64
    && typeof value.resource_type === "string" && value.resource_type.length > 0 && value.resource_type.length <= 64
    && validId(value.resource_id) && validUint(value.occurred_at_utc_ns)
    && value.outcome === "SUCCEEDED" && typeof value.reason === "string"
    && [...value.reason].length > 0 && [...value.reason].length <= 512
    && validId(value.correlation_id);
}

function expectedVersion(value: unknown, create = false): string {
  if (!validUint(value) || (create && value !== "0")) throw new AdminApiErrorV1(400, "INVALID_REQUEST");
  return value;
}

function idempotency(request: Request): string {
  const value = request.headers.get("idempotency-key");
  if (!validId(value)) throw new AdminApiErrorV1(400, "INVALID_REQUEST");
  return value;
}

async function principalAndAuth(
  request: Request,
  dependencies: AdminApiDependenciesV1,
  action: string,
): Promise<{ principal: AdminPrincipalV1; now: string }> {
  const principal = await resolveAdminPrincipalV1(dependencies, request);
  const now = await authorizeAdminActionV1(dependencies, principal, action);
  return { principal, now };
}

function requireOrg(principal: AdminPrincipalV1, requested: string): void {
  if (principal.org_id !== requested) throw new AdminApiErrorV1(404, "NOT_FOUND");
}

function pathId(value: string): string {
  if (!validId(value)) throw new AdminApiErrorV1(404, "NOT_FOUND");
  return value;
}

function requestId(ctx: ReturnType<typeof adminResponseContextV1>): string { return ctx.request_id; }

/** Public fake-port Worker route surface; no production Neon/auth adapter is constructed here. */
export async function adminApiRoutes(request: Request, dependencies?: AdminApiDependenciesV1): Promise<Response> {
  if (!dependencies) return adminNotConfiguredV1(request);
  const responseContext = adminResponseContextV1(dependencies);
  try {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/$/, "") || "/";
    if (path === "/v1/admin/session" && request.method === "POST") {
      const value = await body(request, ["owner_email", "password", "device_id"], ["totp_code"]);
      const session = await createAdminSessionV1(dependencies, value, responseContext.request_id);
      return adminJsonV1({ schema_version: 1, request_id: responseContext.request_id,
        observed_at_ns: responseContext.observed_at_ns, data: session });
    }
    if (path === "/v1/admin/session/enrollment/confirm" && request.method === "POST") {
      const value = await body(request, ["owner_email", "password", "totp_code"]);
      const result = await confirmTotpEnrollmentV1(dependencies, value);
      return adminJsonV1(adminSuccessV1(responseContext, result));
    }
    if (path === "/v1/admin/session" && request.method === "DELETE") {
      const { principal, now } = await principalAndAuth(request, dependencies, "session:revoke");
      const auditId = await revokeAdminSessionV1(dependencies, request, principal, now, responseContext.request_id);
      return adminJsonV1({ ...adminSuccessV1(responseContext, { revoked: true }), audit_id: auditId });
    }

    let parts: string[];
    try { parts = path.split("/").slice(3).map((part) => decodeURIComponent(part)); }
    catch { throw new AdminApiErrorV1(400, "INVALID_REQUEST"); }
    if (parts[0] === "accounts" && parts.length === 1 && request.method === "GET") {
      const { principal } = await principalAndAuth(request, dependencies, "accounts:read");
      const query = pageQuery(url);
      const data = await page(dependencies, principal.org_id, "accounts", query,
        (cursor) => dependencies.store.listAccounts({ org_id: principal.org_id, page_size: query.page_size, cursor }), accountRow);
      return adminJsonV1(adminSuccessV1(responseContext, data));
    }
    if (parts[0] === "accounts" && parts.length === 1 && request.method === "POST") {
      const { principal, now } = await principalAndAuth(request, dependencies, "accounts:create");
      const value = await body(request, ["org", "owner", "initial_subscription", "expected_version", "reason"]);
      if (!record(value.org) || !record(value.owner) || !record(value.initial_subscription)) throw new AdminApiErrorV1(400, "INVALID_REQUEST");
      exact(value.org, ["name"]); exact(value.owner, ["email"]);
      exact(value.initial_subscription, ["plan_id", "term_start_utc_ns", "term_end_utc_ns", "seats", "status"]);
      const sub = value.initial_subscription;
      if (sub.status !== "ACTIVE" && sub.status !== "PAUSED") throw new AdminApiErrorV1(422, "UNSUPPORTED_STATUS");
      const start = requiredText(sub.term_start_utc_ns, 64); const end = requiredText(sub.term_end_utc_ns, 64);
      if (!validUint(start) || !validUint(end) || BigInt(end) <= BigInt(start)) throw new AdminApiErrorV1(400, "INVALID_REQUEST");
      const result = await createAccountV1(dependencies, principal, {
        org_name: requiredText(value.org.name), owner_email: email(value.owner.email),
        plan_id: requiredText(sub.plan_id, 128), term_start_utc_ns: start, term_end_utc_ns: end,
        seats: expectedVersion(sub.seats), status: sub.status,
        expected_version: expectedVersion(value.expected_version, true) as "0",
        reason: requireReason(value.reason), idempotency_key: idempotency(request), request_id: requestId(responseContext),
      }, now);
      return adminJsonV1({ ...adminSuccessV1(responseContext, {
        resource_id: result.resource_id, resource_version: result.resource_version,
      }), audit_id: result.audit_id });
    }

    const orgId = parts[0] === "accounts" && parts.length > 1 ? pathId(parts[1]!) : null;
    if (orgId !== null && parts.length === 2 && request.method === "GET") {
      const { principal } = await principalAndAuth(request, dependencies, "accounts:read");
      requireOrg(principal, orgId);
      const row = await dependencies.store.readAccount(orgId);
      if (!row || !accountRow(row)) throw new AdminApiErrorV1(404, "NOT_FOUND");
      return adminJsonV1(adminSuccessV1(responseContext, row));
    }
    if (orgId !== null && parts[2] === "users" && parts.length === 3 && request.method === "GET") {
      const { principal } = await principalAndAuth(request, dependencies, "users:read"); requireOrg(principal, orgId);
      const query = pageQuery(url);
      const data = await page(dependencies, orgId, "users", query,
        (cursor) => dependencies.store.listUsers({ org_id: orgId, page_size: query.page_size, cursor }), isAllowedUserRow);
      return adminJsonV1(adminSuccessV1(responseContext, data));
    }
    if (orgId !== null && parts[2] === "users" && parts.length === 3 && request.method === "POST") {
      const { principal, now } = await principalAndAuth(request, dependencies, "users:create"); requireOrg(principal, orgId);
      const value = await body(request, ["email", "role_id", "expected_version", "reason"]);
      const result = await createUserV1(dependencies, principal, {
        email: email(value.email), role_id: requiredText(value.role_id, 128),
        expected_version: expectedVersion(value.expected_version, true) as "0",
        reason: requireReason(value.reason), idempotency_key: idempotency(request), request_id: requestId(responseContext),
      }, now);
      return adminJsonV1({ ...adminSuccessV1(responseContext, { resource_id: result.resource_id, resource_version: result.resource_version }), audit_id: result.audit_id });
    }
    if (orgId !== null && parts[2] === "users" && parts.length === 5 && parts[4] === "role" && request.method === "PUT") {
      const { principal, now } = await principalAndAuth(request, dependencies, "users:set-role"); requireOrg(principal, orgId);
      const value = await body(request, ["role_id", "expected_version", "reason"]);
      const result = await setUserRoleV1(dependencies, principal, pathId(parts[3]!), {
        role_id: requiredText(value.role_id, 128), expected_version: expectedVersion(value.expected_version),
        reason: requireReason(value.reason), idempotency_key: idempotency(request), request_id: requestId(responseContext),
      }, now);
      return adminJsonV1({ ...adminSuccessV1(responseContext, { resource_id: result.resource_id, resource_version: result.resource_version }), audit_id: result.audit_id });
    }
    if (orgId !== null && parts[2] === "subscriptions" && parts.length === 3 && request.method === "GET") {
      const { principal } = await principalAndAuth(request, dependencies, "subscriptions:read"); requireOrg(principal, orgId);
      const query = pageQuery(url);
      const data = await page(dependencies, orgId, "subscriptions", query,
        (cursor) => dependencies.store.listSubscriptions({ org_id: orgId, page_size: query.page_size, cursor }), subscriptionRow);
      return adminJsonV1(adminSuccessV1(responseContext, data));
    }
    if (orgId !== null && parts[2] === "subscriptions" && parts.length === 3 && request.method === "POST") {
      const { principal, now } = await principalAndAuth(request, dependencies, "subscriptions:create"); requireOrg(principal, orgId);
      const value = await body(request, ["plan_id", "term_start_utc_ns", "term_end_utc_ns", "seats", "status", "expected_version", "reason"]);
      if (!validStatus(value.status)) throw new AdminApiErrorV1(422, "UNSUPPORTED_STATUS");
      const start = requiredText(value.term_start_utc_ns, 64); const end = requiredText(value.term_end_utc_ns, 64);
      if (!validUint(start) || !validUint(end) || BigInt(end) <= BigInt(start)) throw new AdminApiErrorV1(400, "INVALID_REQUEST");
      const result = await createSubscriptionV1(dependencies, principal, {
        plan_id: requiredText(value.plan_id, 128), term_start_utc_ns: start, term_end_utc_ns: end,
        seats: expectedVersion(value.seats), status: value.status,
        expected_version: expectedVersion(value.expected_version), reason: requireReason(value.reason),
        idempotency_key: idempotency(request), request_id: requestId(responseContext),
      }, now);
      return adminJsonV1({ ...adminSuccessV1(responseContext, { resource_id: result.resource_id, resource_version: result.resource_version }), audit_id: result.audit_id });
    }
    if (orgId !== null && parts[2] === "subscriptions" && parts.length === 4 && request.method === "PUT") {
      const { principal, now } = await principalAndAuth(request, dependencies, "subscriptions:update"); requireOrg(principal, orgId);
      const value = await body(request, ["plan_id", "term_start_utc_ns", "term_end_utc_ns", "seats", "status", "expected_version", "reason"]);
      if (!validStatus(value.status)) throw new AdminApiErrorV1(422, "UNSUPPORTED_STATUS");
      const start = requiredText(value.term_start_utc_ns, 64); const end = requiredText(value.term_end_utc_ns, 64);
      if (!validUint(start) || !validUint(end) || BigInt(end) <= BigInt(start)) throw new AdminApiErrorV1(400, "INVALID_REQUEST");
      const result = await changeSubscriptionV1(dependencies, principal, pathId(parts[3]!), "PATCH", {
        plan_id: requiredText(value.plan_id, 128), term_start_utc_ns: start, term_end_utc_ns: end,
        seats: expectedVersion(value.seats), status: value.status, expected_version: expectedVersion(value.expected_version),
        reason: requireReason(value.reason), idempotency_key: idempotency(request), request_id: requestId(responseContext),
      }, now);
      return adminJsonV1({ ...adminSuccessV1(responseContext, { resource_id: result.resource_id, resource_version: result.resource_version }), audit_id: result.audit_id });
    }
    if (orgId !== null && parts[2] === "subscriptions" && parts.length === 5 && request.method === "POST") {
      const op = parts[4];
      if (op !== "extend" && op !== "suspend" && op !== "resume") throw new AdminApiErrorV1(404, "NOT_FOUND");
      const { principal, now } = await principalAndAuth(request, dependencies, `subscriptions:${op}`); requireOrg(principal, orgId);
      let value: Record<string, unknown>;
      if (op === "extend") {
        value = await body(request, ["term_end_utc_ns", "expected_version", "reason"]);
        value.term_end_utc_ns = requiredText(value.term_end_utc_ns, 64);
      } else if (op === "suspend") {
        value = await body(request, ["expected_version", "reason"]);
      } else {
        value = await body(request, ["target_status", "expected_version", "reason"]);
        if (value.target_status !== "ACTIVE" && value.target_status !== "PAST_DUE") throw new AdminApiErrorV1(400, "INVALID_REQUEST");
      }
      const result = await changeSubscriptionV1(dependencies, principal, pathId(parts[3]!), op.toUpperCase() as "EXTEND" | "SUSPEND" | "RESUME", {
        ...Object.fromEntries(Object.entries(value).map(([key, field]) => [key, requiredText(field, key === "term_end_utc_ns" ? 64 : 256)])),
        expected_version: expectedVersion(value.expected_version), reason: requireReason(value.reason),
        idempotency_key: idempotency(request), request_id: requestId(responseContext),
      }, now);
      return adminJsonV1({ ...adminSuccessV1(responseContext, { resource_id: result.resource_id, resource_version: result.resource_version }), audit_id: result.audit_id });
    }
    if (orgId !== null && parts[2] === "devices" && parts.length === 3 && request.method === "GET") {
      const { principal } = await principalAndAuth(request, dependencies, "devices:read"); requireOrg(principal, orgId);
      const query = pageQuery(url);
      const data = await page(dependencies, orgId, "devices", query,
        (cursor) => dependencies.store.listDevices({ org_id: orgId, page_size: query.page_size, cursor }), isAllowedDeviceRow);
      return adminJsonV1(adminSuccessV1(responseContext, data));
    }
    if (orgId !== null && parts[2] === "devices" && parts.length === 5 && parts[4] === "revoke" && request.method === "POST") {
      const { principal, now } = await principalAndAuth(request, dependencies, "devices:revoke"); requireOrg(principal, orgId);
      const value = await body(request, ["expected_version", "reason"]);
      const result = await revokeDeviceV1(dependencies, principal, pathId(parts[3]!), {
        expected_version: expectedVersion(value.expected_version), reason: requireReason(value.reason),
        idempotency_key: idempotency(request), request_id: requestId(responseContext),
      }, now);
      return adminJsonV1({ ...adminSuccessV1(responseContext, { resource_id: result.resource_id, resource_version: result.resource_version }), audit_id: result.audit_id });
    }
    if (orgId !== null && parts[2] === "audit" && parts.length === 3 && request.method === "GET") {
      const { principal } = await principalAndAuth(request, dependencies, "audit:read"); requireOrg(principal, orgId);
      const query = pageQuery(url);
      const data = await page(dependencies, orgId, "audit", query,
        (cursor) => dependencies.store.listAudit({ org_id: orgId, page_size: query.page_size, cursor }), auditRow);
      return adminJsonV1(adminSuccessV1(responseContext, data));
    }
    throw new AdminApiErrorV1(404, "NOT_FOUND");
  } catch (error) {
    return adminErrorV1(error, responseContext);
  }
}
