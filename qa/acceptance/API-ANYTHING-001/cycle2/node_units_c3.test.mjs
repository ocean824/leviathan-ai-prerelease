// Cycle-3 Node units on the scratch production build (AA_DIST): learn-canary hand-off, semantic reference time,
// raw-body fixture replay (nested extract paths) and the pacer bypass.  Real vendored runtime, fake fetch only.
import assert from "node:assert/strict";
import test from "node:test";
import { pathToFileURL } from "node:url";
import { join } from "node:path";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";

const DIST = process.env.AA_DIST;
assert.ok(DIST, "AA_DIST required");
const load = (p) => import(pathToFileURL(join(DIST, p)).href);
const semantic = await load("semantic.js");
const canary = await load("learn-canary.js");
const replay = await load("fixture-replay.js");
const vendor = await load("../vendor/api-anything/dist/execute.js");
const DAY = 86_400_000;
const dir = () => mkdtempSync(join(tmpdir(), "aa3d-"));
const siteDoc = (extract, url = "https://www.cnn.com/feed.json") => ({
  name: "cnn-fear-greed", baseUrl: "https://www.cnn.com",
  operations: [{ name: "current-index", request: { method: "GET", url, headers: {} }, slots: [], volatile: [], trigger: { url: "https://www.cnn.com/" },
    match: { path: "/feed.json" }, response: { format: "json", extract }, params: [], readOnly: true, minTier: 1 }],
});
const home = (doc) => {
  const h = mkdtempSync(join(tmpdir(), "aa3-"));
  mkdirSync(join(h, "sites"), { recursive: true });
  writeFileSync(join(h, "sites", "cnn-fear-greed.json"), JSON.stringify(doc));
  return h;
};

// ------------------------------------------------------------- semantic reference time
test("semantic check judges rows at the supplied reference time, not the wall clock", () => {
  const long = Date.now() - 400 * DAY;
  const row = (t) => [{ value: 40, label: "Fear", observed_at: new Date(t - 3_600_000).toISOString() }];
  semantic.semanticCheck("cnn.fear_greed", row(long), long);
  assert.throws(() => semantic.semanticCheck("cnn.fear_greed", row(long)), /SEMANTIC_CANARY_FAILED/, "same rows fail against today's clock");
  assert.throws(() => semantic.semanticCheck("cnn.fear_greed", row(Date.now()), long), /SEMANTIC_CANARY_FAILED/, "rows from the future of the reference time fail");
  assert.throws(() => semantic.semanticCheck("cnn.fear_greed", [], long), /SEMANTIC_CANARY_FAILED/);
  const dup = [row(long)[0], row(long)[0]];
  assert.throws(() => semantic.semanticCheck("cnn.fear_greed", dup, long), /SEMANTIC_CANARY_FAILED/);
});

// ------------------------------------------------------------- runLearnCanary
test("learn canary: hands off only on a challenge, exactly once, and retries at tier 2 only after the hand-off", async () => {
  const calls = [];
  let handoffs = 0;
  const ok = await canary.runLearnCanary(async (tier) => { calls.push(tier); return { ok: true }; }, async () => { handoffs++; });
  assert.deepEqual(calls, [1]); assert.equal(handoffs, 0); assert.equal(ok.ok, true);
  calls.length = 0;
  const after = await canary.runLearnCanary(async (tier) => { calls.push(tier); return tier === 1 ? { challenge: true } : { ok: true }; }, async () => { handoffs++; });
  assert.deepEqual(calls, [1, 2]); assert.equal(handoffs, 1); assert.equal(after.ok, true);
  await assert.rejects(canary.runLearnCanary(async () => ({ challenge: true }), async () => { throw new Error("USER_ACTION_DECLINED"); }), /USER_ACTION_DECLINED/);
  calls.length = 0;
  const still = await canary.runLearnCanary(async (tier) => { calls.push(tier); return { challenge: true }; }, async () => {});
  assert.deepEqual(calls, [1, 2], "no endless loop when the wall persists");
  assert.equal(still.challenge, true);
});

// ------------------------------------------------------------- real vendor: 200 interstitial + raw nested replay + pacing
test("real vendor flags a 200 interstitial page as a challenge, never as data", async () => {
  const h = home(siteDoc("data"));
  const previous = process.env.API_ANYTHING_HOME; process.env.API_ANYTHING_HOME = h;
  try {
    const page = '<!doctype html><title>Just a moment...</title><div id="cf-chl-widget">Verify you are human</div><script>window._cf_chl_opt={}</script>';
    const r = await vendor.call("cnn-fear-greed", "current-index", {}, { maxTier: 1, minIntervalMs: 0, fetchImpl: async () => new Response(page, { status: 200, headers: { "content-type": "text/html" } }) });
    assert.equal(r.ok, false); assert.equal(r.challenge, true); assert.equal(r.data, undefined);
  } finally { process.env.API_ANYTHING_HOME = previous; }
});

for (const [extract, body] of [
  ["data", { data: [{ a: 1 }] }],
  ["payload.items", { payload: { items: [{ a: 1 }] } }],
  ["payload.series.items", { payload: { series: { items: [{ a: 1 }] } }, meta: { x: 1 } }],
]) {
  test(`raw-body replay extracts rows at "${extract}"`, async () => {
    const fixture = { fetched_at: new Date().toISOString(), raw_body: JSON.stringify(body), content_type: "application/json", rows: [{ a: 1 }] };
    const data = await replay.replayRawTemplate(dir(), "cnn-fear-greed", "current-index", {}, Buffer.from(JSON.stringify(siteDoc(extract))), fixture, 5000);
    assert.deepEqual(data, [{ a: 1 }]);
  });
}

test("raw-body replay fails closed on a wrong extract path, a non-ok body and a thrown fetch", async () => {
  const tpl = Buffer.from(JSON.stringify(siteDoc("payload.missing.items")));
  const fixture = { fetched_at: new Date().toISOString(), raw_body: JSON.stringify({ payload: { items: [] } }), content_type: "application/json", rows: [] };
  await assert.rejects(replay.replayRawTemplate(dir(), "cnn-fear-greed", "current-index", {}, tpl, fixture, 5000), /FIXTURE_TEMPLATE_REPLAY_FAILED/);
  await assert.rejects(replay.replayRawTemplate(dir(), "cnn-fear-greed", "current-index", {}, Buffer.from("not json"), fixture, 5000));
});

test("replay is network-free: it never calls the global fetch", async () => {
  const original = globalThis.fetch;
  let touched = 0;
  globalThis.fetch = async () => { touched++; throw new Error("network"); };
  try {
    const fixture = { fetched_at: new Date().toISOString(), raw_body: JSON.stringify({ data: [{ a: 1 }] }), content_type: "application/json", rows: [{ a: 1 }] };
    await replay.replayRawTemplate(dir(), "cnn-fear-greed", "current-index", {}, Buffer.from(JSON.stringify(siteDoc("data"))), fixture, 5000);
  } finally { globalThis.fetch = original; }
  assert.equal(touched, 0);
});

test("pacer bypass: replay never waits on the site's pace, but live calls still do", async () => {
  const h = home(siteDoc("data"));
  const previous = process.env.API_ANYTHING_HOME; process.env.API_ANYTHING_HOME = h;
  const body = JSON.stringify({ data: [{ a: 1 }] });
  const fetchImpl = async () => new Response(body, { headers: { "content-type": "application/json" } });
  try {
    await vendor.call("cnn-fear-greed", "current-index", {}, { maxTier: 1, minIntervalMs: 3000, fetchImpl });
    const fixture = { fetched_at: new Date().toISOString(), raw_body: body, content_type: "application/json", rows: [{ a: 1 }] };
    const tpl = Buffer.from(JSON.stringify(siteDoc("data")));
    for (let i = 0; i < 3; i++) {
      const t0 = performance.now();
      await replay.replayRawTemplate(dir(), "cnn-fear-greed", "current-index", {}, tpl, fixture, 5000);
      assert.ok(performance.now() - t0 < 1000, `replay ${i} waited ${(performance.now() - t0).toFixed(0)} ms`);
    }
    const t1 = performance.now();
    await vendor.call("cnn-fear-greed", "current-index", {}, { maxTier: 1, minIntervalMs: 3000, fetchImpl });
    assert.ok(performance.now() - t1 >= 2000, "a LIVE call must still honour the per-site pace (bypass is replay-only)");
  } finally { process.env.API_ANYTHING_HOME = previous; }
});

test("skipPacing is not reachable from the Python-facing request schema", async () => {
  const contracts = await load("contracts.js");
  const id = "95c8cf46-15bc-4509-9961-59d6dbe44144";
  for (const extra of [{ skipPacing: true }, { skip_pacing: true }, { minIntervalMs: 0 }]) {
    assert.equal(contracts.requestSchema.safeParse({ method: "call", request_id: id, operation_id: "cnn.fear_greed", args: {}, ...extra }).success, false);
    assert.equal(contracts.operationContracts["cnn.fear_greed"].input.safeParse(extra).success, false);
  }
});
