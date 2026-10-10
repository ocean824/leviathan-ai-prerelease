// Node-side acceptance units for the freshly built dist (AA_DIST).  Fakes only; no browser, no network.
import assert from "node:assert/strict";
import test from "node:test";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";
import { join } from "node:path";
import { mkdtempSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";

const DIST = process.env.AA_DIST;
assert.ok(DIST, "AA_DIST required");
const load = (name) => import(pathToFileURL(join(DIST, name)).href);
const challenge = await load("challenge.js");
const canary = await load("canary.js");
const contracts = await load("contracts.js");
const requireFromDist = createRequire(join(DIST, "main.js"));

// ---------------------------------------------------------------- fakes
function strictPage({ texts, closeAfter }) {
  const calls = [];
  let reads = 0;
  let closed = false;
  const allowed = new Set(["isClosed", "goto", "locator", "close"]);
  const page = {
    isClosed: () => (calls.push("isClosed"), closed),
    goto: async () => { calls.push("goto"); },
    locator: (sel) => {
      calls.push(`locator:${sel}`);
      return { innerText: async () => {
        const t = texts(++reads);
        if (closeAfter && reads >= closeAfter) closed = true;
        return t;
      } };
    },
    close: async () => { calls.push("close"); },
  };
  return { calls, page: new Proxy(page, { get: (t, k) => {
    if (typeof k === "string" && !allowed.has(k) && k !== "then") throw new Error(`UNEXPECTED PAGE ACTION ${k}`);
    return t[k];
  } }) };
}
const fakeOpen = (page, record) => async (profileDir) => {
  record.profileDir = profileDir;
  return { newPage: async () => page, close: async () => { record.closed = true; } };
};
const dir = () => mkdtempSync(join(tmpdir(), "aa-ch-"));

// ---------------------------------------------------------------- challenge window
test("no challenge is ever auto-completed: a persistent challenge ends in timeout, window closed", async () => {
  const { page, calls } = strictPage({ texts: () => "Please complete the CAPTCHA to continue" });
  const rec = {}; let notified = 0;
  const t0 = Date.now();
  const out = await challenge.waitForHumanChallenge(dir(), "https://public.example/", () => { notified++; }, fakeOpen(page, rec), 1500);
  assert.equal(out, "timeout");
  assert.ok(Date.now() - t0 >= 1400, "must actually wait for the user until the deadline");
  assert.ok(Date.now() - t0 < 5000, "wait must be bounded by the supplied timeout");
  assert.equal(notified, 1);
  assert.equal(rec.closed, true);
  assert.ok(calls.every((c) => /^(goto|isClosed|locator:body)$/.test(c)), calls.join());
});

test("a page that never showed a challenge is not reported as solved", async () => {
  const { page } = strictPage({ texts: () => "ordinary public data page" });
  const out = await challenge.waitForHumanChallenge(dir(), "https://public.example/", () => {}, fakeOpen(page, {}), 1200);
  assert.notEqual(out, "completed");
});

test("completion needs the challenge to be seen and then cleared twice", async () => {
  const { page } = strictPage({ texts: (n) => (n === 1 ? "verify you are human" : "data") });
  const out = await challenge.waitForHumanChallenge(dir(), "https://public.example/", () => {}, fakeOpen(page, {}), 5000);
  assert.equal(out, "completed");
});

test("closing the window is a decline, and the context is released", async () => {
  const { page } = strictPage({ texts: () => "CAPTCHA", closeAfter: 2 });
  const rec = {};
  const out = await challenge.waitForHumanChallenge(dir(), "https://public.example/", () => {}, fakeOpen(page, rec), 5000);
  assert.equal(out, "declined");
  assert.equal(rec.closed, true);
});

test("failure to open a window is not completion", async () => {
  const out = await challenge.waitForHumanChallenge(dir(), "https://public.example/", () => {}, async () => { throw new Error("no chrome"); }, 1000);
  assert.notEqual(out, "completed");
});

test("the profile directory handed to the browser is exactly the one given and gets created", async () => {
  const base = dir();
  const wanted = join(base, "nested", "isolated-profile");
  const { page } = strictPage({ texts: () => "CAPTCHA", closeAfter: 1 });
  const rec = {};
  await challenge.waitForHumanChallenge(wanted, "https://public.example/", () => {}, fakeOpen(page, rec), 2000);
  assert.equal(rec.profileDir, wanted);
  assert.ok(existsSync(wanted));
});

test("default opener launches a VISIBLE persistent context in the supplied isolated profile with no evasion options", async () => {
  const { chromium } = requireFromDist("playwright-core");
  const original = chromium.launchPersistentContext;
  const seen = [];
  chromium.launchPersistentContext = async (...args) => { seen.push(args); return { sentinel: true }; };
  try {
    const ctx = await challenge.openVisibleChallenge("/some/isolated/profile");
    assert.equal(ctx.sentinel, true);
  } finally {
    chromium.launchPersistentContext = original;
  }
  assert.equal(seen.length, 1);
  const [profile, options] = seen[0];
  assert.equal(profile, "/some/isolated/profile");
  assert.equal(options.headless, false, "challenge window must be visible");
  assert.deepEqual(Object.keys(options).sort(), ["args", "headless", "timeout"]);
  assert.deepEqual(options.args, ["--new-window"]);
  for (const k of ["userAgent", "executablePath", "channel", "ignoreDefaultArgs", "proxy", "storageState", "extraHTTPHeaders"]) {
    assert.ok(!(k in options), k);
  }
});

test("human wait is bounded at 120 s and call timeout at 15 s", () => {
  assert.equal(contracts.HUMAN_ACTION_TIMEOUT_MS, 120_000);
  assert.equal(contracts.OPERATION_TIMEOUT_MS, 15_000);
  assert.ok(contracts.MAX_RECORDS <= 500 && contracts.MAX_RESPONSE_BYTES <= 1_048_576);
  assert.ok(contracts.MAX_LINE_BYTES >= contracts.MAX_RESPONSE_BYTES);
});

// ---------------------------------------------------------------- canary
const rows = (values) => values.map((v) => ({ values: v }));
test("canary: same shape passes", () => {
  assert.equal(canary.canaryCompatible(rows([{ a: 1, b: "x", c: null }]), rows([{ a: 2, b: "y", c: null }])), true);
});
test("canary: type change, missing key, extra key, null-vs-value all fail", () => {
  const base = rows([{ a: 1, b: "x", c: null }]);
  for (const cand of [
    rows([{ a: "1", b: "x", c: null }]),
    rows([{ a: 1, b: "x" }]),
    rows([{ a: 1, b: "x", c: null, d: 1 }]),
    rows([{ a: 1, b: "x", c: "s" }]),
    rows([{ a: [1], b: "x", c: null }]),
  ]) assert.equal(canary.canaryCompatible(base, cand), false, JSON.stringify(cand));
});
test("canary: empty candidate, empty baseline, malformed rows all fail closed", () => {
  const base = rows([{ a: 1 }]);
  assert.equal(canary.canaryCompatible(base, []), false);
  assert.equal(canary.canaryCompatible([], base), false);
  assert.equal(canary.canaryCompatible(base, [{ values: null }]), false);
  assert.equal(canary.canaryCompatible(base, [{ values: [1] }]), false);
  assert.equal(canary.canaryCompatible(base, [{}]), false);
});
test("canary: candidate record explosion fails (cap = max(2, 4x baseline) = 4 for one baseline row)", () => {
  const one = rows([{ a: 1 }]);
  assert.equal(canary.canaryCompatible(one, rows(Array.from({ length: 4 }, () => ({ a: 1 })))), true);
  assert.equal(canary.canaryCompatible(one, rows(Array.from({ length: 5 }, () => ({ a: 1 })))), false);
  const four = rows(Array.from({ length: 4 }, () => ({ a: 1 })));
  assert.equal(canary.canaryCompatible(four, rows(Array.from({ length: 16 }, () => ({ a: 1 })))), true);
  assert.equal(canary.canaryCompatible(four, rows(Array.from({ length: 17 }, () => ({ a: 1 })))), false);
});

// ---------------------------------------------------------------- contracts / allowlist
const id = "95c8cf46-15bc-4509-9961-59d6dbe44144";
const OPS = ["calendar.fed", "earnings.forward", "senate.efd.ptr", "cboe.daily.stats", "cnn.fear_greed"];
test("allowlist is exactly the five operation ids", () => {
  assert.deepEqual(Object.keys(contracts.operationContracts).sort(), [...OPS].sort());
});
test("requests: unknown ids/methods/extra keys/non-uuid ids are rejected", () => {
  const ok = { method: "call", request_id: id, operation_id: "cnn.fear_greed", args: {} };
  assert.equal(contracts.requestSchema.safeParse(ok).success, true);
  for (const bad of [
    { ...ok, operation_id: "x.y" }, { ...ok, method: "login" }, { ...ok, method: "import" },
    { ...ok, extra: 1 }, { ...ok, request_id: "nope" }, { method: "call", request_id: id, operation_id: "cnn.fear_greed" },
    { method: "health", request_id: id, extra: 1 }, { ...ok, url: "https://x.invalid" },
  ]) assert.equal(contracts.requestSchema.safeParse(bad).success, false, JSON.stringify(bad));
});
test("per-operation inputs are strict (no urls, no unknown fields, bounded values)", () => {
  const c = contracts.operationContracts;
  assert.equal(c["calendar.fed"].input.safeParse({ year: 2026 }).success, true);
  assert.equal(c["calendar.fed"].input.safeParse({ year: 2026, url: "x" }).success, false);
  assert.equal(c["calendar.fed"].input.safeParse({ year: 1999 }).success, false);
  assert.equal(c["earnings.forward"].input.safeParse({ symbols: ["aapl"] }).success, false);
  assert.equal(c["earnings.forward"].input.safeParse({ symbols: [] }).success, false);
  assert.equal(c["senate.efd.ptr"].input.safeParse({ page: 11 }).success, false);
  assert.equal(c["cboe.daily.stats"].input.safeParse({ date: "2026-02-30" }).success, false);
  assert.equal(c["cnn.fear_greed"].input.safeParse({ a: 1 }).success, false);
});
test("every operation's challenge/ToS url is https and on its reviewed host", () => {
  const hosts = {
    "calendar.fed": "www.federalreserve.gov", "earnings.forward": "finance.yahoo.com",
    "senate.efd.ptr": "efdsearch.senate.gov", "cboe.daily.stats": "www.cboe.com", "cnn.fear_greed": "www.cnn.com",
  };
  for (const [op, c] of Object.entries(contracts.operationContracts)) {
    assert.equal(new URL(c.challengeUrl).protocol, "https:");
    assert.equal(new URL(c.challengeUrl).hostname, hosts[op], op);
    assert.equal(new URL(c.tosUrl).protocol, "https:");
  }
});
test("responses must carry redistribution=false, source_tier 3 and bounded record count", () => {
  const base = {
    schema_version: 1, request_id: id, operation_id: "cnn.fear_greed", template_version: "v", source_id: "api_anything.cnn.fear_greed",
    source_tier: 3, status: "OK", fetched_at: "2026-10-09T15:00:00Z", as_of: null, knowable_at: null, redistribution: false, records: [],
  };
  const R = contracts.responseSchema;
  assert.equal(R.safeParse(base).success, true);
  assert.equal(R.safeParse({ ...base, redistribution: true }).success, false);
  assert.equal(R.safeParse({ ...base, source_tier: 2 }).success, false);
  assert.equal(R.safeParse({ ...base, status: "FINE" }).success, false);
  assert.equal(R.safeParse({ ...base, error_code: "WHATEVER" }).success, false);
  const row = { record_id: "r", as_of: "2026-10-09T14:00:00Z", event_at: null, published_at: null, available_at: null, knowable_at: null,
    quality: "availability_unknown", values: {}, redistribution: false };
  assert.equal(R.safeParse({ ...base, records: [row] }).success, true);
  assert.equal(R.safeParse({ ...base, records: [{ ...row, redistribution: true }] }).success, false);
  assert.equal(R.safeParse({ ...base, records: Array.from({ length: 501 }, () => row) }).success, false);
});
