// Node-side units for the cycle-2 production build in scratch (AA_DIST). Fakes only: no browser, no network.
import assert from "node:assert/strict";
import test from "node:test";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";
import { join } from "node:path";
import { mkdtempSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";

const DIST = process.env.AA_DIST;
assert.ok(DIST, "AA_DIST required");
const load = (name) => import(pathToFileURL(join(DIST, name)).href);
const challenge = await load("challenge.js");
const robots = await load("robots.js");
const limiter = await load("rate-limiter.js");
const contracts = await load("contracts.js");
const canary = await load("canary.js");
const requireFromDist = createRequire(join(DIST, "main.js"));
const browser = await import(pathToFileURL(join(DIST, "..", "vendor", "api-anything", "dist", "browser.js")).href);
const haveChrome = browser.chromeAvailable();
const dir = () => mkdtempSync(join(tmpdir(), "aa2-"));

// ---------------------------------------------------------------- fakes
function strictContext({ pageText = "A public page with plenty of ordinary public content", confirm = "click", challengeClosed = false, onRoute } = {}) {
  const log = [];
  const allowed = new Set(["isClosed", "goto", "locator", "setContent", "waitForFunction", "close"]);
  const mk = (name, extra) => new Proxy({
    isClosed: () => (log.push(`${name}.isClosed`), name === "challenge" ? challengeClosed : confirm === "closed"),
    goto: async (url) => { log.push(`${name}.goto:${url}`); },
    setContent: async () => { log.push(`${name}.setContent`); },
    waitForFunction: async () => {
      log.push(`${name}.waitForFunction`);
      if (confirm === "timeout" || confirm === "closed") throw new Error("Timeout");
    },
    locator: (sel) => ({ innerText: async () => { log.push(`${name}.locator:${sel}`); if (pageText === null) throw new Error("gone"); return pageText; } }),
    close: async () => { log.push(`${name}.close`); },
    ...extra,
  }, { get: (t, k) => { if (typeof k === "string" && !allowed.has(k) && k !== "then") throw new Error(`UNEXPECTED PAGE ACTION ${k}`); return t[k]; } });
  const pages = [mk("challenge"), mk("confirm")];
  const context = {
    routes: [],
    newPage: async () => pages.shift(),
    route: async (pattern, handler) => { context.routes.push({ pattern, handler }); onRoute?.(handler); },
    close: async () => { log.push("context.close"); },
  };
  return { context, log };
}
const opener = (context, rec = {}) => async (profileDir) => { rec.profileDir = profileDir; return context; };

// ---------------------------------------------------------------- challenge window
test("vendor channel: the default opener launches visible Google Chrome in the supplied isolated profile, no evasion options", async () => {
  const { chromium } = requireFromDist("playwright-core");
  const original = chromium.launchPersistentContext;
  const seen = [];
  chromium.launchPersistentContext = async (...args) => { seen.push(args); return { sentinel: true }; };
  try { assert.equal((await challenge.openVisibleChallenge("/iso/profile")).sentinel, true); } finally { chromium.launchPersistentContext = original; }
  const [profile, options] = seen[0];
  assert.equal(profile, "/iso/profile");
  assert.equal(options.headless, false);
  assert.equal(options.channel, "chrome");
  assert.deepEqual(Object.keys(options).sort(), ["args", "channel", "headless", "timeout"]);
  assert.deepEqual(options.args, ["--new-window"]);
  for (const k of ["userAgent", "executablePath", "ignoreDefaultArgs", "proxy", "storageState", "extraHTTPHeaders", "permissions"]) assert.ok(!(k in options), k);
});

test("no Chrome installed is its own outcome (and nothing is launched)", { skip: haveChrome }, async () => {
  const out = await challenge.waitForHumanChallenge(dir(), "https://public.example/", () => {}, async () => { throw new Error("must not open"); }, 1000);
  assert.equal(out, "browser_unavailable");
});

test("window flow: notify after the confirm page is ready and before the wait; completes only after Done + a cleared page", async () => {
  const { context, log } = strictContext();
  let notified = 0;
  const rec = {};
  const wrapped = { ...context, newPage: context.newPage, route: context.route, close: context.close };
  const out = await challenge.waitForHumanChallenge(dir(), "https://www.cnn.com/markets/fear-and-greed", () => { notified++; log.push("notify"); }, opener(wrapped, rec), 3000);
  assert.equal(out, "completed");
  assert.equal(notified, 1);
  assert.ok(log.indexOf("confirm.setContent") < log.indexOf("notify") && log.indexOf("notify") < log.indexOf("confirm.waitForFunction"), log.join(","));
  assert.ok(log.includes("challenge.goto:https://www.cnn.com/markets/fear-and-greed") && log.at(-1) === "context.close");
  assert.ok(existsSync(rec.profileDir));
});

for (const [name, cfg, expected] of [
  ["challenge text still on the page after Done", { pageText: "Please complete the CAPTCHA to continue with this page" }, "declined"],
  ["near-empty page after Done", { pageText: "ok" }, "declined"],
  ["site tab closed", { challengeClosed: true }, "declined"],
  ["site tab unreadable", { pageText: null }, "declined"],
  ["confirm tab closed (dismissed)", { confirm: "closed" }, "declined"],
  ["confirm never clicked (timeout)", { confirm: "timeout" }, "timeout"],
]) {
  test(`outcome ${expected}: ${name}`, async () => {
    const { context } = strictContext(cfg);
    assert.equal(await challenge.waitForHumanChallenge(dir(), "https://www.cnn.com/x", () => {}, opener(context), 2000), expected);
  });
}

test("window failure is not a decline: a failed open gives window_failed", async () => {
  assert.equal(await challenge.waitForHumanChallenge(dir(), "https://www.cnn.com/x", () => {}, async () => { throw new Error("launch failed"); }, 1000), "window_failed");
  const { context } = strictContext();
  context.newPage = async () => { throw new Error("no tab"); };
  assert.equal(await challenge.waitForHumanChallenge(dir(), "https://www.cnn.com/x", () => {}, opener(context), 1000), "window_failed");
});

test("the window never acts on the page: only navigation and reading (strict page proxy would throw)", async () => {
  const { context, log } = strictContext();
  await challenge.waitForHumanChallenge(dir(), "https://www.cnn.com/x", () => {}, opener(context), 2000);
  assert.ok(log.every((l) => /^(challenge|confirm)\.(isClosed|goto:|setContent|waitForFunction|locator:body|close)|^notify$|^context\.close$/.test(l)), log.join(","));
});

test("every browser request is routed through the host and robots policy", async () => {
  const policy = { allowedHosts: ["www.cnn.com"], robots: { "www.cnn.com": [{ path: "/private/", allow: false }] } };
  process.env.LEVIATHAN_REQUEST_POLICY = JSON.stringify(policy);
  let handler;
  const { context } = strictContext({ onRoute: (h) => { handler = h; } });
  await challenge.waitForHumanChallenge(dir(), "https://www.cnn.com/x", () => {}, opener(context), 1500);
  assert.ok(handler, "context.route must be installed");
  const decide = async (url) => { let r = null; await handler({ request: () => ({ url: () => url }), continue: async () => { r = "continue"; }, abort: async () => { r = "abort"; } }); return r; };
  assert.equal(await decide("https://www.cnn.com/markets/fear-and-greed"), "continue");
  assert.equal(await decide("https://www.cnn.com/private/x"), "abort");
  assert.equal(await decide("https://evil.example/x"), "abort");
  assert.equal(await decide("http://www.cnn.com/x"), "abort");
  assert.equal(await decide("file:///C:/Windows/win.ini"), "abort");
  assert.equal(await decide("not a url"), "abort");
  delete process.env.LEVIATHAN_REQUEST_POLICY;
});

// ---------------------------------------------------------------- robots
test("robots parsing: specific allow, wildcard, our group beats *, empty disallow, end anchor", () => {
  const rules = (text) => robots.robotsAllows(JSON.parse(JSON.stringify(text)), "/x");
  assert.equal(robots.robotsAllows([{ path: "/private/", allow: false }], "/private/a"), false);
  assert.equal(robots.robotsAllows([{ path: "/private/", allow: false }], "/public/a"), true);
  assert.equal(robots.robotsAllows([{ path: "/", allow: false }, { path: "/ok/", allow: true }], "/ok/a"), true, "longest match wins");
  assert.equal(robots.robotsAllows([{ path: "/*.json$", allow: false }], "/a/b.json"), false);
  assert.equal(robots.robotsAllows([{ path: "/*.json$", allow: false }], "/a/b.json?x=1"), true);
  assert.equal(robots.robotsAllows([], "/anything"), true);
  assert.equal(rules([]), true);
});

test("urlAllowed: https only, host must be in the policy, robots applied, no loopback exception in the shipped build", () => {
  const policy = { allowedHosts: ["www.cnn.com"], robots: { "www.cnn.com": [{ path: "/private/", allow: false }] } };
  assert.equal(robots.urlAllowed("https://www.cnn.com/a", policy), true);
  assert.equal(robots.urlAllowed("https://WWW.CNN.COM/a", policy), true);
  assert.equal(robots.urlAllowed("http://www.cnn.com/a", policy), false);
  assert.equal(robots.urlAllowed("https://www.cnn.com/private/a", policy), false);
  assert.equal(robots.urlAllowed("https://evil.example/a", policy), false);
  assert.equal(robots.urlAllowed("https://www.cnn.com.evil.example/a", policy), false);
  assert.equal(robots.urlAllowed("https://user:pw@evil.example/a", policy), false);
  const saved = process.env.AA_CONTROL;
  process.env.AA_CONTROL = "1";
  try { assert.equal(robots.urlAllowed("http://127.0.0.1:1/a", { allowedHosts: ["127.0.0.1"], robots: {} }), false, "AA_CONTROL must not open a loopback exception"); }
  finally { if (saved === undefined) delete process.env.AA_CONTROL; else process.env.AA_CONTROL = saved; }
});

// ---------------------------------------------------------------- rate limiter (file backed)
test("limiter: spacing, cadence, learn/repair spacing, backoff, persistence, invalid state", async () => {
  const file = join(dir(), "rate.json");
  const l = new limiter.PersistentRateLimiter(file);
  await l.gate("op", "call", 3_600_000, 5000);
  await assert.rejects(l.gate("op", "call", 3_600_000, 5000), /RATE_LIMITED/);
  const state = JSON.parse(readFileSync(file, "utf8"));
  const back = (iso, ms) => new Date(Date.parse(iso) - ms).toISOString();
  state.operations.op.last_send_at = back(state.operations.op.last_send_at, 10_000);
  writeFileSync(file, JSON.stringify(state));
  await l.success("op");
  await assert.rejects(new limiter.PersistentRateLimiter(file).gate("op", "call", 3_600_000, 5000), /NOT_DUE/, "a new instance reads the persisted state");
  await new limiter.PersistentRateLimiter(file).gate("other", "call", 3_600_000, 5000);
  await l.backoff("op2", 60_000);
  await assert.rejects(l.gate("op2", "call", 1000, 1), /RATE_LIMITED/);
  const t0 = Date.now();
  await assert.rejects(l.gate("op2", "learn", 3_600_000, 5000), /RATE_LIMITED/);
  assert.ok(Date.now() - t0 < 1000, "refusals are immediate");
  writeFileSync(file, "{broken");
  await assert.rejects(new limiter.PersistentRateLimiter(file).gate("op", "call", 1000, 1), /RATE_STATE_INVALID/);
});

// ---------------------------------------------------------------- constants / contracts
test("bounds: human wait 10 min, call timeout 15 s, records 500, line 1.1 MB, response 1 MiB", () => {
  assert.equal(contracts.HUMAN_ACTION_TIMEOUT_MS, 600_000);
  assert.equal(contracts.OPERATION_TIMEOUT_MS, 15_000);
  assert.equal(contracts.MAX_RECORDS, 500);
  assert.ok(contracts.MAX_LINE_BYTES >= contracts.MAX_RESPONSE_BYTES && contracts.MAX_RESPONSE_BYTES <= 1_048_576);
  const c = contracts.operationContracts;
  assert.deepEqual(Object.keys(c).sort(), ["calendar.fed", "cboe.daily.stats", "cnn.fear_greed", "earnings.forward", "senate.efd.ptr"]);
  for (const [id, v] of Object.entries(c)) {
    assert.ok(v.allowedHosts.length > 0 && v.allowedHosts.every((h) => /^[a-z0-9.-]+$/.test(h)), id);
    assert.ok(v.minIntervalMs >= 1000 && v.cadenceSeconds >= 3600, id);
    assert.equal(new URL(v.challengeUrl).protocol, "https:");
    assert.ok(v.allowedHosts.includes(new URL(v.challengeUrl).hostname), `${id} challenge url host is not in its allowlist`);
  }
});

test("response schema: new error codes and provenance fields are closed sets", () => {
  const base = { schema_version: 1, request_id: "95c8cf46-15bc-4509-9961-59d6dbe44144", operation_id: "cnn.fear_greed", template_version: "v", source_id: "api_anything.cnn.fear_greed", source_tier: 3, status: "OK", fetched_at: "2026-10-09T15:00:00Z", as_of: null, knowable_at: null, redistribution: false, records: [] };
  const R = contracts.responseSchema;
  assert.equal(R.safeParse(base).success, true);
  for (const code of ["RATE_LIMITED", "NOT_DUE", "CHALLENGE_WINDOW_FAILED", "BROWSER_UNAVAILABLE", "TEMPLATE_UNPINNED", "PIN_REGISTRY_INVALID", "FIRST_SEEN_LEDGER_INVALID"]) assert.equal(R.safeParse({ ...base, status: "DEGRADED", error_code: code }).success, true, code);
  assert.equal(R.safeParse({ ...base, error_code: "WHATEVER" }).success, false);
  assert.equal(R.safeParse({ ...base, redistribution: true }).success, false);
  assert.equal(R.safeParse({ ...base, source_tier: 2 }).success, false);
  assert.equal(R.safeParse({ ...base, template_sha256: "nothex" }).success, false);
});

test("canary shape check is unchanged (drift and explosion rejected)", () => {
  assert.equal(canary.canaryCompatible([{ values: { a: 1 } }], [{ values: { a: "1" } }]), false);
  assert.equal(canary.canaryCompatible([{ values: { a: 1 } }], [{ values: { a: 2 } }]), true);
});

test("challenge hosts: reviewed challenge origins are reachable in the window, data hosts keep their robots rules, everything else is blocked", async () => {
  const policy = { allowedHosts: ["www.cnn.com"], robots: { "www.cnn.com": [{ path: "/private/", allow: false }] } };
  process.env.LEVIATHAN_REQUEST_POLICY = JSON.stringify(policy);
  let handler;
  const { context } = strictContext({ onRoute: (h) => { handler = h; } });
  await challenge.waitForHumanChallenge(dir(), "https://www.cnn.com/x", () => {}, opener(context), 1500, ["verify.example"], dir());
  const decide = async (url) => { let r = null; await handler({ request: () => ({ url: () => url }), continue: async () => { r = "continue"; }, abort: async () => { r = "abort"; } }); return r; };
  assert.equal(await decide("https://verify.example/widget.js"), "continue");
  assert.equal(await decide("http://verify.example/widget.js"), "abort");
  assert.equal(await decide("https://www.cnn.com/private/x"), "abort", "data host robots still apply in the window");
  assert.equal(await decide("https://other.example/x"), "abort");
  delete process.env.LEVIATHAN_REQUEST_POLICY;
});
