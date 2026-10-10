import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rename, rm, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { call, heal } from "../vendor/api-anything/dist/execute.js";
import { addOperation } from "../vendor/api-anything/dist/heal.js";
import { waitForHumanChallenge } from "./challenge.js";
import { PersistentRateLimiter } from "./rate-limiter.js";
import { runLearnCanary } from "./learn-canary.js";
import { callWithChallengeSignal, isChallengeResponse } from "./challenge-signal.js";
import { replayRawTemplate, type ReplayFixture } from "./fixture-replay.js";
import { semanticCheck } from "./semantic.js";
import { stampFirstSeen as stampRowsFirstSeen } from "./first-seen.js";
import { sanitizedFixtureBody } from "./fixture-sanitize.js";
import { buildRequestPolicy, urlAllowed, type RequestPolicy } from "./robots.js";
import { ZodError } from "zod";
import { PIN_REGISTRY_SHA256 } from "./pin-hash.js";
import {
  HUMAN_ACTION_TIMEOUT_MS,
  MAX_LINE_BYTES,
  MAX_RESPONSE_BYTES,
  MAX_RECORDS,
  OPERATION_TIMEOUT_MS,
  operationContracts,
  pinRequirements,
  requestSchema,
  responseSchema,
  type OperationId,
} from "./contracts.js";

type Contract = (typeof operationContracts)[OperationId];
const sourceIdentifier = (operationId: OperationId) => `api_anything.${operationId}`;
type RegistryEntry = {
  version: string;
  sha256: string;
  template_path: string;
  allowed_hosts: string[];
  challenge_hosts: string[];
  tos_review_id: string;
  review_note: string;
  fixture_path: string;
  fixture_sha256: string;
  approved_at: string;
  mapping_recipe: Contract["mappingRecipe"];
  mapping_sha256: string;
  mapping_fixture_kind: "recorded-native-body" | "hand-built-native-body";
  fixture_origin: "recorded-live-response" | "hand-built-test-fixture";
};
type Registry = {
  schema_version: 1;
  operations: Partial<Record<OperationId, RegistryEntry>>;
  challenge_hosts_by_operation: Record<OperationId, string[]>;
  pin_requirements: Record<OperationId, "reviewed-fixture-allowed" | "recorded-native-body-required">;
  tos_reviews: Record<string, { reviewed_at: string; reviewer: string; verdict: string; redistribution: false; decision: string }>;
};
const collectorRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const templatesRoot = join(collectorRoot, "templates");
const registryFile = join(templatesRoot, "PINNED.json");

const activeDataDir: string = process.env.LEVIATHAN_COLLECTOR_DATA ?? (() => {
  throw new Error("LEVIATHAN_COLLECTOR_DATA_REQUIRED");
})();
process.env.LEVIATHAN_PUBLIC_USER_AGENT = "LeviathanPublicCollector/1.0";
process.env.API_ANYTHING_HOME = `${activeDataDir}/api-anything`;

const runTime = () => new Date().toISOString();
let requestPolicy: RequestPolicy | undefined;
let currentRetryAfterMs = 0;
let currentChallengeSignal = false;
let lastPublicResponse: { fetched_at: string; body: string; content_type: string } | undefined;
const getLastPublicResponse = () => lastPublicResponse;
const publicFetch: typeof fetch = async (input, init) => {
  currentChallengeSignal = false;
  const requestUrl = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
  if (!requestPolicy || !urlAllowed(requestUrl, requestPolicy)) throw new Error("ROBOTS_OR_HOST_BLOCKED");
  const headers = new Headers(init?.headers);
  headers.set("User-Agent", process.env.LEVIATHAN_PUBLIC_USER_AGENT!);
  const response = await fetch(input, { ...init, headers, redirect: "manual" });
  const responseBody = await response.clone().text().catch(() => "");
  lastPublicResponse = { fetched_at: runTime(), body: responseBody, content_type: response.headers.get("content-type") ?? "application/octet-stream" };
  const retryAfter = response.headers.get("retry-after");
  if (isChallengeResponse(response.status, responseBody)) {
    currentChallengeSignal = true;
    throw new Error("CHALLENGE_SIGNAL");
  }
  if (response.status === 429) {
    currentRetryAfterMs = retryAfter
      ? Number.isFinite(Number(retryAfter))
        ? Math.max(0, Number(retryAfter) * 1000)
        : Math.max(0, Date.parse(retryAfter) - Date.now())
      : 60_000;
    throw new Error("RATE_LIMITED");
  }
  if (response.status >= 300 && response.status < 400) {
    const location = response.headers.get("location");
    const nextUrl = location ? new URL(location, requestUrl).href : "";
    if (!nextUrl || !urlAllowed(nextUrl, requestPolicy)) throw new Error("HOST_OR_ROBOTS_REDIRECT_BLOCKED");
    return publicFetch(nextUrl, init);
  }
  return response;
};
const safeError = (error: unknown): string => {
  const message = error instanceof Error ? error.message : "unknown";
  if (/timeout/i.test(message)) return "TIMEOUT";
  if (/USER_ACTION_DECLINED/i.test(message)) return "USER_ACTION_DECLINED";
  if (/USER_ACTION_REQUIRED/i.test(message)) return "USER_ACTION_REQUIRED";
  if (/RATE_LIMITED/i.test(message)) return "RATE_LIMITED";
  if (/NOT_DUE/i.test(message)) return "NOT_DUE";
  if (/TEMPLATE_UNPINNED/i.test(message)) return "TEMPLATE_UNPINNED";
  if (/CHALLENGE_WINDOW_FAILED/i.test(message)) return "CHALLENGE_WINDOW_FAILED";
  if (/BROWSER_UNAVAILABLE/i.test(message)) return "BROWSER_UNAVAILABLE";
  if (/PIN_REGISTRY_INVALID/i.test(message)) return "PIN_REGISTRY_INVALID";
  if (/FIRST_SEEN_LEDGER_INVALID/i.test(message)) return "FIRST_SEEN_LEDGER_INVALID";
  if (error instanceof ZodError) return "SCHEMA_INVALID";
  return "OPERATION_DEGRADED";
};
const statusForError = (code: string): "DEGRADED" | "USER_ACTION_REQUIRED" | "USER_ACTION_DECLINED" | "TIMEOUT" =>
  code === "USER_ACTION_REQUIRED" || code === "USER_ACTION_DECLINED" || code === "TIMEOUT"
    ? code
    : "DEGRADED";

async function atomicWrite(path: string, bytes: string | Buffer): Promise<void> {
  const temporary = `${path}.${process.pid}.${Date.now()}.tmp`;
  await writeFile(temporary, bytes, { mode: 0o600 });
  await rename(temporary, path);
}

function fixtureArgs(operationId: OperationId): Record<string, unknown> {
  const today = new Date().toISOString().slice(0, 10);
  if (operationId === "calendar.fed") return { year: new Date().getUTCFullYear() };
  if (operationId === "earnings.forward") return { symbols: ["AAPL"] };
  if (operationId === "senate.efd.ptr") return { page: 1 };
  if (operationId === "cboe.daily.stats") return { date: today };
  return {};
}

async function replayFixture(operationId: OperationId, template: Buffer, fixtures: ReplayFixture[]): Promise<void> {
  const contract = operationContracts[operationId];
  for (const fixture of fixtures) {
    if (!Number.isFinite(Date.parse(fixture.fetched_at)) || containsCredentialMaterial(fixture.raw_body)) {
      throw new Error("FIXTURE_TEMPLATE_REPLAY_FAILED");
    }
    const data = await replayRawTemplate(activeDataDir, contract.site, contract.operation, fixtureArgs(operationId), template, fixture, contract.minIntervalMs);
    const output = Array.isArray(data) ? data : [data];
    const extracted = contract.records.parse(output) as Record<string, unknown>[];
    semanticCheck(operationId, extracted, Date.parse(fixture.fetched_at));
    if (stableJson(extracted) !== stableJson(fixture.rows)) throw new Error("FIXTURE_TEMPLATE_OUTPUT_MISMATCH");
  }
}

const rateStateFile = join(activeDataDir, "rate-state.json");
const rateLimiter = new PersistentRateLimiter(rateStateFile);

async function registry(): Promise<Registry> {
  let value: unknown;
  try {
    const bytes = await readFile(registryFile);
    if (createHash("sha256").update(bytes).digest("hex") !== PIN_REGISTRY_SHA256) throw new Error("PIN_REGISTRY_INVALID");
    value = JSON.parse(bytes.toString("utf8"));
  } catch {
    throw new Error("PIN_REGISTRY_INVALID");
  }
  if (typeof value !== "object" || value === null || (value as Registry).schema_version !== 1 || typeof (value as Registry).operations !== "object" || typeof (value as Registry).challenge_hosts_by_operation !== "object" || typeof (value as Registry).pin_requirements !== "object" || typeof (value as Registry).tos_reviews !== "object") {
    throw new Error("PIN_REGISTRY_INVALID");
  }
  for (const operationId of Object.keys(operationContracts) as OperationId[]) {
    const hosts = (value as Registry).challenge_hosts_by_operation[operationId];
    if (!Array.isArray(hosts) || hosts.some((host) => typeof host !== "string" || !/^[a-z0-9.-]+$/.test(host) || host !== host.toLowerCase())) throw new Error("PIN_REGISTRY_INVALID");
    const required = pinRequirements[operationId];
    if ((value as Registry).pin_requirements[operationId] !== required) throw new Error("PIN_REGISTRY_INVALID");
  }
  for (const [operationId, entry] of Object.entries((value as Registry).operations) as [OperationId, RegistryEntry][]) {
    const contract = operationContracts[operationId];
    if (!entry || stableJson(entry.mapping_recipe) !== stableJson(contract.mappingRecipe) ||
      entry.mapping_sha256 !== createHash("sha256").update(stableJson(contract.mappingRecipe)).digest("hex") ||
      (pinRequirements[operationId] === "recorded-native-body-required" && (entry.mapping_fixture_kind !== "recorded-native-body" || entry.fixture_origin !== "recorded-live-response"))) {
      throw new Error("PIN_REGISTRY_INVALID");
    }
  }
  return value as Registry;
}

const responseBase = (requestId: string) => ({
  schema_version: 1 as const,
  request_id: requestId,
  operation_id: null,
  template_version: null,
  source_id: null,
  source_tier: null,
  status: "DEGRADED" as const,
  template_sha256: null,
  approval_id: null,
  approval_deadline: null,
  freshness_deadline: null,
  fetched_at: runTime(),
  as_of: null,
  knowable_at: null,
  redistribution: false as const,
  records: [] as Record<string, unknown>[],
});

function emit(raw: string): void {
  const output = Buffer.byteLength(raw, "utf8") <= MAX_RESPONSE_BYTES
    ? raw
    : JSON.stringify({ ...responseBase("00000000-0000-4000-8000-000000000000"), error_code: "SCHEMA_INVALID" });
  process.stdout.write(`${output}\n`);
}

function publicTime(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? new Date(parsed).toISOString() : null;
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b));
    return `{${entries.map(([key, nested]) => `${JSON.stringify(key)}:${stableJson(nested)}`).join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

function templateMatchesMapping(templateValue: unknown, operationId: OperationId): boolean {
  if (!templateValue || typeof templateValue !== "object") return false;
  const operations = (templateValue as { operations?: unknown }).operations;
  if (!Array.isArray(operations)) return false;
  const operation = operations.find((entry) => entry && typeof entry === "object" && (entry as { name?: unknown }).name === operationContracts[operationId].operation) as { response?: unknown } | undefined;
  if (!operation?.response || typeof operation.response !== "object") return false;
  const actual = operation.response as Record<string, unknown>;
  const expected = operationContracts[operationId].mappingRecipe as Record<string, unknown>;
  return Object.entries(expected).every(([key, value]) => stableJson(actual[key]) === stableJson(value));
}

function containsCredentialMaterial(value: unknown): boolean {
  if (Array.isArray(value)) return value.some(containsCredentialMaterial);
  if (value && typeof value === "object") {
    return Object.entries(value as Record<string, unknown>).some(([key, item]) =>
      /^(cookie|set-cookie|authorization|proxy-authorization|x-[\w-]*(token|secret|key))$/i.test(key) || containsCredentialMaterial(item));
  }
  return typeof value === "string" && /(?:^|\s)Bearer\s+\S{8,}|(?:^|[?&])(?:access_token|session|auth_token|api_key)=/i.test(value);
}

function eventAndValues(operationId: OperationId, value: Record<string, unknown>, fetchedAt: string) {
  const eventKey = operationId.startsWith("calendar.") || operationId === "earnings.forward"
    ? "scheduled_at"
    : operationId === "senate.efd.ptr"
      ? "filed_at"
      : operationId === "cboe.daily.stats"
        ? "observed_at"
        : "observed_at";
  const eventAt = publicTime(value[eventKey]);
  const publishedAt = publicTime(value.published_at);
  const availableAt = publicTime(value.available_at);
  const firstSeen = publicTime(value.__collector_first_seen) ?? fetchedAt;
  const sourcePublished = publicTime(value.published_at);
  if (
    (sourcePublished && Date.parse(sourcePublished) > Date.parse(fetchedAt)) ||
    (availableAt && Date.parse(availableAt) > Date.parse(fetchedAt))
  ) throw new Error("SCHEMA_INVALID");
  const knowledgeStamps = [firstSeen, sourcePublished, availableAt]
    .filter((stamp): stamp is string => stamp !== null)
    .map((stamp) => Date.parse(stamp));
  const knowableAt = new Date(Math.max(...knowledgeStamps)).toISOString();
  const asOf = publicTime(value.as_of)
    ?? publishedAt
    ?? publicTime(value.observed_at)
    ?? publicTime(value.filed_at)
    ?? knowableAt
    ?? fetchedAt;
  const values = { ...value };
  delete values.record_id;
  delete values.knowable_at;
  delete values.as_of;
  delete values.available_at;
  delete values.__collector_first_seen;
  delete values.__collector_record_id;
  const quality = (sourcePublished || availableAt)
    && Date.parse(sourcePublished ?? availableAt!) <= Date.parse(fetchedAt)
    ? "source_timestamped"
    : "first_observed";
  return {
    record_id: typeof value.__collector_record_id === "string"
      ? value.__collector_record_id
      : typeof value.record_id === "string" && value.record_id.length > 0
        ? value.record_id
        : createHash("sha256").update(stableJson(values)).digest("hex"),
    as_of: asOf,
    event_at: eventAt,
    published_at: publishedAt,
    available_at: availableAt,
    knowable_at: knowableAt,
    first_seen_at: firstSeen,
    quality,
    values,
    redistribution: false,
  };
}

async function processRequest(raw: string, profileDir?: string): Promise<string> {
  const parsed = requestSchema.safeParse(JSON.parse(raw));
  if (!parsed.success) {
    return JSON.stringify({ ...responseBase("00000000-0000-4000-8000-000000000000"), error_code: "SCHEMA_INVALID" });
  }
  const request = parsed.data;
  const base = responseBase(request.request_id);
  if (request.method === "health") {
    return JSON.stringify(responseSchema.parse({ ...base, status: "OK" }));
  }
  if (process.env.LEVIATHAN_REPLAY_ONLY === "1" && ["learn", "repair"].includes(request.method)) {
    return JSON.stringify(responseSchema.parse({ ...base, operation_id: request.operation_id, source_tier: 3, error_code: "BROWSER_UNAVAILABLE" }));
  }
  const operationId = request.operation_id as OperationId;
  const contract: Contract = operationContracts[operationId];
  const pinnedRegistry = await registry();
  const tosReview = pinnedRegistry.tos_reviews[contract.tosReviewId];
  if (!tosReview || tosReview.redistribution !== false || !["ALLOWED", "INTERNAL_SINGLE_USER_ONLY"].includes(tosReview.verdict)) {
    return JSON.stringify(responseSchema.parse({ ...base, operation_id: operationId, source_id: sourceIdentifier(operationId), source_tier: 3, error_code: "OPERATION_DEGRADED" }));
  }
  const pinned = pinnedRegistry.operations[operationId];
  if (request.method !== "learn" && !pinned) {
    return JSON.stringify(responseSchema.parse({ ...base, operation_id: operationId, source_id: sourceIdentifier(operationId), source_tier: 3, error_code: "TEMPLATE_UNPINNED" }));
  }
  if (request.method !== "learn" && (
    !Array.isArray(pinned!.allowed_hosts) ||
    pinned!.allowed_hosts.length === 0 ||
    pinned!.allowed_hosts.some((host) => !(contract.allowedHosts as readonly string[]).includes(host)) ||
    !Array.isArray(pinned!.challenge_hosts) ||
    pinned!.challenge_hosts.some((host) => !pinnedRegistry.challenge_hosts_by_operation[operationId]?.includes(host))
  )) {
    return JSON.stringify(responseSchema.parse({ ...base, operation_id: operationId, source_id: sourceIdentifier(operationId), source_tier: 3, error_code: "TEMPLATE_UNAVAILABLE" }));
  }
  requestPolicy = await buildRequestPolicy(request.method === "learn" ? contract.allowedHosts : pinned!.allowed_hosts, activeDataDir);
  process.env.LEVIATHAN_REQUEST_POLICY = JSON.stringify(requestPolicy);
  if (!urlAllowed(contract.challengeUrl, requestPolicy)) {
    return JSON.stringify(responseSchema.parse({ ...base, operation_id: operationId, source_id: sourceIdentifier(operationId), source_tier: 3, error_code: "OPERATION_DEGRADED" }));
  }
  if (request.method === "learn") {
    await rateLimiter.gate(operationId, "learn", contract.cadenceSeconds * 1000, contract.minIntervalMs);
    const examples: [Record<string, unknown>, Record<string, unknown>] = [
      contract.input.parse(request.examples[0]) as unknown as Record<string, unknown>,
      contract.input.parse(request.examples[1]) as unknown as Record<string, unknown>,
    ];
    const learnHome = join(activeDataDir, "learning", operationId.replaceAll(".", "-"));
    await mkdir(learnHome, { recursive: true });
    const originalHome = process.env.API_ANYTHING_HOME;
    process.env.API_ANYTHING_HOME = learnHome;
    try {
      const learn = () => addOperation({
          site: contract.site,
          op: contract.operation,
          trigger: { url: contract.challengeUrl },
          examples,
          response: { ...contract.mappingRecipe, pick: [...contract.mappingRecipe.pick] },
          fetchImpl: publicFetch,
        });
      try {
        await learn();
      } catch (error) {
        if (!currentChallengeSignal && !(error && typeof error === "object" && "challenge" in error && (error as { challenge?: unknown }).challenge === true)) throw error;
        currentChallengeSignal = false;
        const notification = {
          type: "notification",
          request_id: request.request_id,
          status: "USER_ACTION_REQUIRED",
          source_id: sourceIdentifier(operationId),
          operation_id: operationId,
          message: `Leviathan needs you to complete a check on ${contract.site}.`,
        };
        let notified = false;
        const notify = () => {
          if (!notified) emit(JSON.stringify(notification));
          notified = true;
        };
        const outcome = await waitForHumanChallenge(join(learnHome, "profile"), contract.challengeUrl, notify, undefined, HUMAN_ACTION_TIMEOUT_MS, pinnedRegistry.challenge_hosts_by_operation[operationId], activeDataDir);
        if (outcome === "timeout") throw new Error("TIMEOUT");
        if (outcome === "declined") throw new Error("USER_ACTION_DECLINED");
        if (outcome === "window_failed") throw new Error("CHALLENGE_WINDOW_FAILED");
        if (outcome === "browser_unavailable") throw new Error("BROWSER_UNAVAILABLE");
        await learn();
      }
      const candidateFixtureRows: Record<string, unknown>[] = [];
      const candidateFixtures: ReplayFixture[] = [];
      const learnedAt = runTime();
      for (const example of examples) {
        lastPublicResponse = undefined;
        const canaryResult = await runLearnCanary(
          async (maxTier) => await callWithChallengeSignal(
            () => call(contract.site, contract.operation, example, {
            maxTier,
            timeoutMs: OPERATION_TIMEOUT_MS,
            minIntervalMs: contract.minIntervalMs,
            fetchImpl: publicFetch,
            }),
            { get current() { return currentChallengeSignal; }, set current(value: boolean) { currentChallengeSignal = value; } },
          ),
          async () => {
          const notification = {
            type: "notification", request_id: request.request_id, status: "USER_ACTION_REQUIRED",
            source_id: sourceIdentifier(operationId), operation_id: operationId,
            message: `Leviathan needs you to complete a check on ${contract.site}.`,
          };
          let notified = false;
          const notify = () => { if (!notified) emit(JSON.stringify(notification)); notified = true; };
          const outcome = await waitForHumanChallenge(join(learnHome, "profile"), contract.challengeUrl, notify, undefined, HUMAN_ACTION_TIMEOUT_MS, pinnedRegistry.challenge_hosts_by_operation[operationId], activeDataDir);
          if (outcome === "timeout") throw new Error("TIMEOUT");
          if (outcome === "declined") throw new Error("USER_ACTION_DECLINED");
          if (outcome === "window_failed") throw new Error("CHALLENGE_WINDOW_FAILED");
          if (outcome === "browser_unavailable") throw new Error("BROWSER_UNAVAILABLE");
          lastPublicResponse = undefined;
          currentChallengeSignal = false;
          },
        );
        if (!canaryResult.ok || canaryResult.class !== "ok") throw new Error("learn canary call failed");
        const rawRows = Array.isArray(canaryResult.data) ? canaryResult.data : [canaryResult.data];
        if (rawRows.length > MAX_RECORDS) throw new Error("learn canary record cap exceeded");
        const rows = contract.records.parse(rawRows) as Record<string, unknown>[];
        const observed = getLastPublicResponse();
        if (!observed) throw new Error("CANDIDATE_FIXTURE_UNAVAILABLE");
        const sanitizedBody = sanitizedFixtureBody(observed.body, observed.content_type, contract.mappingRecipe);
        semanticCheck(operationId, rows, Date.parse(observed.fetched_at));
        if (containsCredentialMaterial(rows)) throw new Error("CANDIDATE_CONTAINS_CREDENTIALS");
        candidateFixtureRows.push(...rows);
        candidateFixtures.push({ fetched_at: observed.fetched_at, raw_body: sanitizedBody, content_type: observed.content_type, rows });
      }
      const templateFile = join(learnHome, "sites", `${contract.site}.json`);
      const template = await readFile(templateFile);
      const parsedTemplate: unknown = JSON.parse(template.toString("utf8"));
      if (containsCredentialMaterial(parsedTemplate)) throw new Error("CANDIDATE_CONTAINS_CREDENTIALS");
      if (!templateMatchesMapping(parsedTemplate, operationId)) throw new Error("CANDIDATE_MAPPING_MISMATCH");
      await replayFixture(operationId, template, candidateFixtures);
      const digest = createHash("sha256").update(template).digest("hex");
      const version = `${Date.now()}-${digest.slice(0, 12)}`;
      const candidatePath = join(activeDataDir, "candidates", operationId, `${version}.json`);
      await mkdir(dirname(candidatePath), { recursive: true });
      await atomicWrite(candidatePath, template);
      const candidateFixture = Buffer.from(JSON.stringify(candidateFixtures));
      const fixtureDigest = createHash("sha256").update(candidateFixture).digest("hex");
      await atomicWrite(join(dirname(candidatePath), `${version}.fixture.json`), candidateFixture);
      await atomicWrite(join(dirname(candidatePath), `${version}.candidate.json`), JSON.stringify({
        operation_id: operationId,
        version,
        sha256: digest,
        fixture_sha256: fixtureDigest,
        allowed_hosts: contract.allowedHosts,
          challenge_hosts: pinnedRegistry.challenge_hosts_by_operation[operationId],
          tos_review_id: contract.tosReviewId,
          mapping_recipe: contract.mappingRecipe,
          mapping_sha256: createHash("sha256").update(stableJson(contract.mappingRecipe)).digest("hex"),
          mapping_fixture_kind: "recorded-native-body",
          fixture_origin: "recorded-live-response",
          pin_requires_recorded_body: pinRequirements[operationId] === "recorded-native-body-required",
          mapping_review_note: "The native body mapping is reviewed against the named strict contract and fixture before pinning.",
          review_note: "Candidate requires the normal acceptance and review flow before pinning.",
      }));
      const fetchedAt = runTime();
      const response = responseSchema.parse({
        ...base,
        operation_id: operationId,
        template_version: version,
        template_sha256: digest,
        source_id: sourceIdentifier(operationId),
        source_tier: 3,
        status: "OK",
        fetched_at: fetchedAt,
        as_of: null,
        knowable_at: null,
        candidate_only: true,
        records: [],
      });
      return JSON.stringify(response);
    } catch (error) {
      const errorCode = safeError(error);
      return JSON.stringify(responseSchema.parse({
        ...base,
        operation_id: operationId,
        source_id: sourceIdentifier(operationId),
        source_tier: 3,
        status: statusForError(errorCode),
        error_code: errorCode,
      }));
    } finally {
      process.env.API_ANYTHING_HOME = originalHome;
    }
  }
  const input = contract.input.safeParse(request.args);
  if (!input.success) {
    return JSON.stringify(responseSchema.parse({ ...base, operation_id: operationId, source_tier: 3, error_code: "SCHEMA_INVALID" }));
  }
  if (!pinned) {
    return JSON.stringify(responseSchema.parse({ ...base, operation_id: operationId, source_id: sourceIdentifier(operationId), source_tier: 3, error_code: "TEMPLATE_UNPINNED" }));
  }
  if (
    !/^[a-f0-9]{64}$/.test(pinned.sha256) ||
    !pinned.version ||
    pinned.tos_review_id !== contract.tosReviewId ||
    !Array.isArray(pinned.allowed_hosts) ||
    pinned.allowed_hosts.some((host) => !(contract.allowedHosts as readonly string[]).includes(host)) ||
    !Array.isArray(pinned.challenge_hosts) ||
    pinned.challenge_hosts.some((host) => !pinnedRegistry.challenge_hosts_by_operation[operationId]?.includes(host)) ||
    !pinned.fixture_path ||
    !/^[a-f0-9]{64}$/.test(pinned.fixture_sha256) ||
    !Number.isFinite(Date.parse(pinned.approved_at)) ||
    !pinned.review_note.trim()
  ) {
    return JSON.stringify(responseSchema.parse({ ...base, operation_id: operationId, source_id: sourceIdentifier(operationId), source_tier: 3, error_code: "TEMPLATE_UNAVAILABLE" }));
  }
  {
    const fixturePath = resolve(templatesRoot, pinned.fixture_path);
    const fixtureRelative = relative(resolve(templatesRoot), fixturePath);
    if (isAbsolute(fixtureRelative) || fixtureRelative === ".." || fixtureRelative.startsWith(`..${process.platform === "win32" ? "\\" : "/"}`)) {
      return JSON.stringify(responseSchema.parse({ ...base, operation_id: operationId, source_id: sourceIdentifier(operationId), source_tier: 3, error_code: "TEMPLATE_UNAVAILABLE" }));
    }
    try {
      const fixture = await readFile(fixturePath);
      if (createHash("sha256").update(fixture).digest("hex") !== pinned.fixture_sha256) throw new Error("fixture digest mismatch");
      const fixtureData: unknown = JSON.parse(fixture.toString("utf8"));
      if (!Array.isArray(fixtureData) || fixtureData.length === 0 || fixtureData.length > 2) throw new Error("invalid fixture bundle");
      const fixtures = fixtureData.map((entry) => {
        if (!entry || typeof entry !== "object" || typeof (entry as ReplayFixture).raw_body !== "string" || typeof (entry as ReplayFixture).content_type !== "string" || typeof (entry as ReplayFixture).fetched_at !== "string" || !Array.isArray((entry as ReplayFixture).rows)) throw new Error("invalid fixture record");
        return { ...(entry as ReplayFixture), rows: contract.records.parse((entry as ReplayFixture).rows) as Record<string, unknown>[] };
      });
      const templatePath = resolve(templatesRoot, pinned.template_path);
      const templateRelative = relative(resolve(templatesRoot), templatePath);
      if (isAbsolute(templateRelative) || templateRelative === ".." || templateRelative.startsWith(`..${process.platform === "win32" ? "\\" : "/"}`)) throw new Error("template outside registry");
      const template = await readFile(templatePath);
      if (createHash("sha256").update(template).digest("hex") !== pinned.sha256) throw new Error("template digest mismatch");
      const parsedTemplate: unknown = JSON.parse(template.toString("utf8"));
      if (containsCredentialMaterial(parsedTemplate)) throw new Error("template contains credentials");
      if (!templateMatchesMapping(parsedTemplate, operationId)) throw new Error("TEMPLATE_MAPPING_MISMATCH");
      await replayFixture(operationId, template, fixtures);
    } catch {
      return JSON.stringify(responseSchema.parse({ ...base, operation_id: operationId, source_id: sourceIdentifier(operationId), source_tier: 3, error_code: "TEMPLATE_UNAVAILABLE" }));
    }
  }
  const approvedAt = Date.parse(pinned.approved_at);
  const approvalDeadline = approvedAt + 90 * 86_400_000;
  if (!Number.isFinite(approvedAt) || Date.now() > approvalDeadline) {
    return JSON.stringify(responseSchema.parse({ ...base, operation_id: operationId, source_id: sourceIdentifier(operationId), source_tier: 3, template_version: pinned.version, template_sha256: pinned.sha256, approval_id: pinned.tos_review_id, error_code: "TEMPLATE_UNAVAILABLE" }));
  }
  const canaryStateFile = join(activeDataDir, "canary-state.json");
  let canaryAt = approvedAt;
  try {
    const state = JSON.parse(await readFile(canaryStateFile, "utf8")) as Record<string, string>;
    const parsedCanary = Date.parse(state[operationId] ?? "");
    if (Number.isFinite(parsedCanary)) canaryAt = Math.min(Date.now(), parsedCanary);
  } catch {
    // No successful semantic canary has been persisted yet; the next call is the canary.
  }
  let freshnessDeadline = canaryAt + 48 * 60 * 60 * 1000;
  requestPolicy = await buildRequestPolicy(pinned.allowed_hosts, activeDataDir);
  try {
    await rateLimiter.gate(operationId, request.method === "repair" ? "repair" : "call", contract.cadenceSeconds * 1000, contract.minIntervalMs);
    const apiArgs = input.data as Record<string, unknown>;
    lastPublicResponse = undefined;
    let apiResult = request.method === "repair"
      ? await heal(contract.site, contract.operation, input.data as Record<string, unknown>, {
          maxTier: 1,
          timeoutMs: OPERATION_TIMEOUT_MS,
          minIntervalMs: contract.minIntervalMs,
          fetchImpl: publicFetch,
        })
      : await call(contract.site, contract.operation, input.data as Record<string, unknown>, {
          maxTier: 1,
          timeoutMs: OPERATION_TIMEOUT_MS,
          minIntervalMs: contract.minIntervalMs,
          fetchImpl: publicFetch,
        });
    const challenge = apiResult.challenge === true || currentChallengeSignal;
    currentChallengeSignal = false;
    if (challenge) {
      if (process.env.LEVIATHAN_REPLAY_ONLY === "1") {
        return JSON.stringify(responseSchema.parse({ ...base, operation_id: operationId, source_id: sourceIdentifier(operationId), template_version: pinned.version, template_sha256: pinned.sha256, approval_id: pinned.tos_review_id, approval_deadline: new Date(approvalDeadline).toISOString(), freshness_deadline: new Date(freshnessDeadline).toISOString(), source_tier: 3, error_code: "BROWSER_UNAVAILABLE" }));
      }
      const notification = {
        type: "notification",
        request_id: request.request_id,
        status: "USER_ACTION_REQUIRED",
        source_id: sourceIdentifier(operationId),
        operation_id: operationId,
        message: `Leviathan needs you to complete a check on ${contract.site}.`,
      };
      if (!profileDir) return JSON.stringify(responseSchema.parse({ ...base, operation_id: operationId, source_id: sourceIdentifier(operationId), template_version: pinned.version, template_sha256: pinned.sha256, approval_id: pinned.tos_review_id, approval_deadline: new Date(approvalDeadline).toISOString(), freshness_deadline: new Date(freshnessDeadline).toISOString(), source_tier: 3, error_code: "USER_ACTION_REQUIRED" }));
      let notified = false;
      const notify = () => {
        if (!notified) emit(JSON.stringify(notification));
        notified = true;
      };
      const outcome = await waitForHumanChallenge(
        profileDir,
        contract.challengeUrl,
        notify,
        undefined,
        HUMAN_ACTION_TIMEOUT_MS,
        pinned.challenge_hosts,
        activeDataDir,
      );
      if (outcome === "timeout") {
        return JSON.stringify(responseSchema.parse({ ...base, operation_id: operationId, source_id: sourceIdentifier(operationId), template_version: pinned.version, source_tier: 3, status: "TIMEOUT", error_code: "TIMEOUT" }));
      }
      if (outcome === "declined") {
        return JSON.stringify(responseSchema.parse({ ...base, operation_id: operationId, source_id: sourceIdentifier(operationId), template_version: pinned.version, source_tier: 3, status: "USER_ACTION_DECLINED", error_code: "USER_ACTION_DECLINED" }));
      }
      if (outcome === "window_failed") return JSON.stringify(responseSchema.parse({ ...base, operation_id: operationId, source_id: sourceIdentifier(operationId), template_version: pinned.version, template_sha256: pinned.sha256, approval_id: pinned.tos_review_id, approval_deadline: new Date(approvalDeadline).toISOString(), freshness_deadline: new Date(freshnessDeadline).toISOString(), source_tier: 3, error_code: "CHALLENGE_WINDOW_FAILED" }));
      if (outcome === "browser_unavailable") return JSON.stringify(responseSchema.parse({ ...base, operation_id: operationId, source_id: sourceIdentifier(operationId), template_version: pinned.version, template_sha256: pinned.sha256, approval_id: pinned.tos_review_id, approval_deadline: new Date(approvalDeadline).toISOString(), freshness_deadline: new Date(freshnessDeadline).toISOString(), source_tier: 3, error_code: "BROWSER_UNAVAILABLE" }));
      apiResult = request.method === "repair"
        ? await heal(contract.site, contract.operation, apiArgs, {
            maxTier: 2,
            timeoutMs: OPERATION_TIMEOUT_MS,
            minIntervalMs: contract.minIntervalMs,
            fetchImpl: publicFetch,
          })
        : await call(contract.site, contract.operation, apiArgs, {
            maxTier: 2,
            timeoutMs: OPERATION_TIMEOUT_MS,
            minIntervalMs: contract.minIntervalMs,
            fetchImpl: publicFetch,
          });
    }
    if (currentRetryAfterMs > 0 || /RATE_LIMITED|retry after/i.test(apiResult.reason ?? "")) {
      await rateLimiter.backoff(operationId, currentRetryAfterMs || 60_000);
      currentRetryAfterMs = 0;
      return JSON.stringify(responseSchema.parse({ ...base, operation_id: operationId, source_id: sourceIdentifier(operationId), template_version: pinned.version, template_sha256: pinned.sha256, approval_id: pinned.tos_review_id, approval_deadline: new Date(approvalDeadline).toISOString(), freshness_deadline: new Date(freshnessDeadline).toISOString(), source_tier: 3, status: "DEGRADED", error_code: "RATE_LIMITED" }));
    }
    if (!apiResult.ok || apiResult.class !== "ok") {
      return JSON.stringify(responseSchema.parse({ ...base, operation_id: operationId, source_id: sourceIdentifier(operationId), template_version: pinned.version, source_tier: 3, error_code: "OPERATION_DEGRADED" }));
    }
    const rawRows = Array.isArray(apiResult.data) ? apiResult.data : [apiResult.data];
    if (rawRows.length > MAX_RECORDS) throw new Error("record cap exceeded");
    const rows = contract.records.parse(rawRows) as Record<string, unknown>[];
    const observedResponse = getLastPublicResponse();
    const fetchedAt = observedResponse?.fetched_at ?? runTime();
    semanticCheck(operationId, rows, Date.parse(fetchedAt));
    const stamped = await stampRowsFirstSeen(join(activeDataDir, "first-seen", `${operationId}.json`), rows, fetchedAt);
    const records = stamped.map((row) => eventAndValues(operationId, row, fetchedAt));
    const observations = records.map((record) => Date.parse(record.as_of as string));
    const asOf = observations.length ? new Date(Math.max(...observations)).toISOString() : fetchedAt;
    const knowledgeStamps = records.map((record) => record.knowable_at).filter((stamp): stamp is string => stamp !== null);
    const knowableAt = knowledgeStamps.length ? knowledgeStamps.sort().at(-1)! : null;
    if (request.method === "repair") {
      const candidateTemplate = join(process.env.API_ANYTHING_HOME!, "sites", `${contract.site}.json`);
      const candidate = await readFile(candidateTemplate);
      const parsedCandidate: unknown = JSON.parse(candidate.toString("utf8"));
      if (containsCredentialMaterial(parsedCandidate) || containsCredentialMaterial(rows)) throw new Error("CANDIDATE_CONTAINS_CREDENTIALS");
      if (!observedResponse) throw new Error("CANDIDATE_FIXTURE_UNAVAILABLE");
      const sanitizedBody = sanitizedFixtureBody(observedResponse.body, observedResponse.content_type, contract.mappingRecipe);
      const candidateFixtures: ReplayFixture[] = [{ fetched_at: fetchedAt, raw_body: sanitizedBody, content_type: observedResponse.content_type, rows }];
      await replayFixture(operationId, candidate, candidateFixtures);
      const digest = createHash("sha256").update(candidate).digest("hex");
      const version = `${Date.now()}-${digest.slice(0, 12)}`;
      const candidatePath = join(activeDataDir, "candidates", operationId, `${version}.json`);
      await mkdir(dirname(candidatePath), { recursive: true });
      await atomicWrite(candidatePath, candidate);
      const candidateFixture = Buffer.from(JSON.stringify(candidateFixtures));
      const fixtureDigest = createHash("sha256").update(candidateFixture).digest("hex");
      await atomicWrite(join(dirname(candidatePath), `${version}.fixture.json`), candidateFixture);
      await atomicWrite(join(dirname(candidatePath), `${version}.candidate.json`), JSON.stringify({
        operation_id: operationId,
        version,
        sha256: digest,
        fixture_sha256: fixtureDigest,
        allowed_hosts: pinned.allowed_hosts,
        challenge_hosts: pinned.challenge_hosts,
        tos_review_id: pinned.tos_review_id,
        mapping_recipe: contract.mappingRecipe,
        mapping_sha256: createHash("sha256").update(stableJson(contract.mappingRecipe)).digest("hex"),
        mapping_fixture_kind: "recorded-native-body",
        fixture_origin: "recorded-live-response",
        pin_requires_recorded_body: pinRequirements[operationId] === "recorded-native-body-required",
        mapping_review_note: "The native body mapping is reviewed against the named strict contract and fixture before pinning.",
        review_note: "Repair candidate requires re-review and re-pin before activation.",
      }));
      return JSON.stringify(responseSchema.parse({ ...base, operation_id: operationId, source_id: sourceIdentifier(operationId), source_tier: 3, template_version: version, template_sha256: digest, approval_id: pinned.tos_review_id, approval_deadline: new Date(approvalDeadline).toISOString(), freshness_deadline: new Date(freshnessDeadline).toISOString(), error_code: "TEMPLATE_UNPINNED" }));
    }
    await rateLimiter.success(operationId);
    freshnessDeadline = Date.parse(fetchedAt) + 48 * 60 * 60 * 1000;
    let canaryState: Record<string, string> = {};
    try { canaryState = JSON.parse(await readFile(canaryStateFile, "utf8")) as Record<string, string>; } catch { /* first passing canary */ }
    canaryState[operationId] = fetchedAt;
    await atomicWrite(canaryStateFile, JSON.stringify(canaryState));
    await mkdir(join(activeDataDir, "last-good"), { recursive: true });
    await atomicWrite(join(activeDataDir, "last-good", `${operationId}.json`), JSON.stringify({
      schema_version: 1,
      request_id: request.request_id,
      operation_id: operationId,
      template_version: pinned.version,
      template_sha256: pinned.sha256,
      approval_id: pinned.tos_review_id,
      approval_deadline: new Date(approvalDeadline).toISOString(),
      freshness_deadline: new Date(freshnessDeadline).toISOString(),
      source_id: sourceIdentifier(operationId),
      source_tier: 3,
      status: "OK",
      fetched_at: fetchedAt,
      as_of: asOf,
      knowable_at: knowableAt,
      redistribution: false,
    records,
    }));
    return JSON.stringify(responseSchema.parse({
      ...base,
      operation_id: operationId,
      template_version: pinned.version,
      template_sha256: pinned.sha256,
      approval_id: pinned.tos_review_id,
      approval_deadline: new Date(approvalDeadline).toISOString(),
      freshness_deadline: new Date(freshnessDeadline).toISOString(),
      source_id: sourceIdentifier(operationId),
      source_tier: 3,
      status: "OK",
      fetched_at: fetchedAt,
      as_of: asOf,
      knowable_at: knowableAt,
      records,
    }));
  } catch (error) {
    const errorCode = safeError(error);
    if (errorCode === "RATE_LIMITED") {
      await rateLimiter.backoff(operationId, currentRetryAfterMs || 60_000).catch(() => undefined);
      currentRetryAfterMs = 0;
    }
    return JSON.stringify(responseSchema.parse({ ...base, operation_id: operationId, source_id: sourceIdentifier(operationId), template_version: pinned.version, source_tier: 3, status: statusForError(errorCode), error_code: errorCode }));
  }
}

let requestQueue = Promise.resolve();
let queuedRequests = 0;
let inputBuffer = Buffer.alloc(0);

function failInput(): void {
  emit(JSON.stringify({ ...responseBase("00000000-0000-4000-8000-000000000000"), error_code: "SCHEMA_INVALID" }));
  process.stdin.pause();
  process.exitCode = 1;
}

function enqueueLine(lineBytes: Buffer): void {
  queuedRequests += 1;
  if (queuedRequests > 32) {
    failInput();
    return;
  }
  if (queuedRequests >= 24) process.stdin.pause();
  const line = lineBytes.toString("utf8");
  requestQueue = requestQueue.then(async () => {
    const request = requestSchema.parse(JSON.parse(line));
    if (request.method === "health") {
      emit(await processRequest(line));
      return;
    }
    const operationId = request.operation_id as OperationId;
    const contract = operationContracts[operationId];
    const pinned = (await registry()).operations[operationId];
    if (request.method === "learn" || !pinned) {
      emit(await processRequest(line));
      return;
    }
    const templateRoot = templatesRoot;
    const resolvedTemplate = resolve(templateRoot, pinned.template_path);
    const withinTemplates = relative(resolve(templateRoot), resolvedTemplate);
    if (isAbsolute(withinTemplates) || withinTemplates === ".." || withinTemplates.startsWith(`..${process.platform === "win32" ? "\\" : "/"}`)) {
      emit(JSON.stringify(responseSchema.parse({ ...responseBase(request.request_id), operation_id: operationId, source_id: sourceIdentifier(operationId), source_tier: 3, error_code: "TEMPLATE_UNAVAILABLE" })));
      return;
    }
    const siteFile = resolvedTemplate;
    let original: Buffer;
    try {
      original = await readFile(siteFile);
    } catch {
      emit(await processRequest(line));
      return;
    }
    const hashBefore = createHash("sha256").update(original).digest("hex");
    if (hashBefore !== pinned.sha256) {
      emit(JSON.stringify(responseSchema.parse({ ...responseBase(request.request_id), operation_id: operationId, source_id: sourceIdentifier(operationId), source_tier: 3, error_code: "TEMPLATE_UNAVAILABLE" })));
      return;
    }
    const isolatedHome = join(activeDataDir, "isolated", contract.site);
    const isolatedSiteFile = join(isolatedHome, "sites", `${contract.site}.json`);
    await mkdir(join(isolatedHome, "sites"), { recursive: true });
    try {
      const isolatedCurrent = await readFile(isolatedSiteFile);
      if (createHash("sha256").update(isolatedCurrent).digest("hex") !== pinned.sha256) {
        await writeFile(isolatedSiteFile, original, { mode: 0o600 });
      }
    } catch {
      await writeFile(isolatedSiteFile, original, { mode: 0o600 });
    }
    const activeHome = process.env.API_ANYTHING_HOME;
    process.env.API_ANYTHING_HOME = isolatedHome;
    let result: string;
    try {
      result = await processRequest(line, join(isolatedHome, "profile"));
    } finally {
      process.env.API_ANYTHING_HOME = activeHome;
    }
    emit(result);
  }).catch((error: unknown) => {
    let requestId = "00000000-0000-4000-8000-000000000000";
    let operationId: OperationId | undefined;
    try {
      const parsed = JSON.parse(line) as { request_id?: string; operation_id?: OperationId };
      if (parsed.request_id && /^[0-9a-f-]{36}$/i.test(parsed.request_id)) requestId = parsed.request_id;
      if (parsed.operation_id && parsed.operation_id in operationContracts) operationId = parsed.operation_id;
    } catch { /* malformed input uses the stable zero UUID */ }
    const errorCode = safeError(error);
    emit(JSON.stringify(responseSchema.parse({
      ...responseBase(requestId),
      operation_id: operationId ?? null,
      ...(operationId ? { source_id: sourceIdentifier(operationId), source_tier: 3 as const } : {}),
      status: statusForError(errorCode),
      error_code: errorCode,
    })));
  }).finally(() => {
    queuedRequests -= 1;
    if (queuedRequests < 12 && !process.stdin.destroyed) process.stdin.resume();
  });
}

process.stdin.on("data", (chunk: Buffer) => {
  inputBuffer = Buffer.concat([inputBuffer, chunk]);
  let newline = inputBuffer.indexOf(0x0a);
  while (newline >= 0) {
    if (newline > MAX_LINE_BYTES) {
      failInput();
      return;
    }
    enqueueLine(inputBuffer.subarray(0, newline));
    inputBuffer = inputBuffer.subarray(newline + 1);
    newline = inputBuffer.indexOf(0x0a);
  }
  if (inputBuffer.length > MAX_LINE_BYTES) failInput();
});
process.stdin.on("end", () => {
  if (inputBuffer.length > 0) failInput();
});
