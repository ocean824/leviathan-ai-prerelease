import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { call } from "../vendor/api-anything/dist/execute.js";
import { addOperation, BotChallengeError, type CaptureFile } from "../vendor/api-anything/dist/heal.js";
import { runLearnCanary } from "./learn-canary.js";
import { waitForHumanChallenge, type ChallengeContext, type ChallengePage } from "./challenge.js";
import { replayRawTemplate, type ReplayFixture } from "./fixture-replay.js";
import { callWithChallengeSignal, isChallengeResponse } from "./challenge-signal.js";

const fixtureRoot = join(process.cwd(), "fixtures", "challenges");
const readFixture = async (name: string) => await (await import("node:fs/promises")).readFile(join(fixtureRoot, name), "utf8");

test("built vendor 403 CHALLENGE_SIGNAL reaches the learn canary hand-off in production mode", async () => {
  const home = await mkdtemp(join(tmpdir(), "collector-vendor-403-canary-"));
  const previous = process.env.API_ANYTHING_HOME;
  const site = {
    name: "cnn-fear-greed",
    baseUrl: "https://www.cnn.com",
    operations: [{
      name: "current-index",
      request: { method: "GET", url: "https://www.cnn.com/markets/fear-and-greed", headers: {} },
      slots: [], volatile: [], trigger: { url: "https://www.cnn.com/markets/fear-and-greed" },
      match: { path: "/markets/fear-and-greed" },
      response: { format: "json", extract: "fear_and_greed_historical.data", pick: ["value=value", "label=rating", "observed_at=timestamp"] },
      params: [], readOnly: true, minTier: 1,
    }],
  };
  await mkdir(join(home, "sites"), { recursive: true });
  await writeFile(join(home, "sites", "cnn-fear-greed.json"), JSON.stringify(site));
  const wall = await readFixture("cf-challenge-403.html");
  const data = await readFixture("fear-greed-historical.json");
  process.env.API_ANYTHING_HOME = home;
  let challengeSignal = false;
  let fetchCount = 0;
  let handoffCount = 0;
  try {
    const result = await runLearnCanary(
      () => callWithChallengeSignal(async () => {
        const result = await call("cnn-fear-greed", "current-index", {}, {
          maxTier: 1,
          minIntervalMs: 0,
          fetchImpl: async () => {
            challengeSignal = false;
            if (fetchCount++ === 0) {
              const blocked = new Response(wall, { status: 403, headers: { "content-type": "text/html" } });
              const body = await blocked.clone().text();
              if (isChallengeResponse(blocked.status, body)) {
                challengeSignal = true;
                throw new Error("CHALLENGE_SIGNAL");
              }
              return blocked;
            }
            return new Response(data, { status: 200, headers: { "content-type": "application/json" } });
          },
        });
        return result;
      }, { get current() { return challengeSignal; }, set current(value: boolean) { challengeSignal = value; } }),
      async () => { handoffCount += 1; challengeSignal = false; },
    );
    assert.equal(fetchCount, 2);
    assert.equal(handoffCount, 1);
    assert.equal(result.ok, true);
    assert.equal(result.class, "ok");
  } finally {
    process.env.API_ANYTHING_HOME = previous;
    await rm(home, { recursive: true, force: true });
  }
});

test("real addOperation turns a recorded addOperation warning into a typed challenge error", async () => {
  const home = await mkdtemp(join(tmpdir(), "collector-vendor-learn-wall-"));
  const previous = process.env.API_ANYTHING_HOME;
  process.env.API_ANYTHING_HOME = home;
  try {
    const body = await readFixture("add-operation-warning.json");
    const capture: CaptureFile = {
      id: "recorded-wall",
      at: new Date().toISOString(),
      url: "https://www.cnn.com/markets/fear-and-greed",
      finalUrl: "https://www.cnn.com/markets/fear-and-greed",
      cookies: [],
      exchanges: [{
        id: 1,
        resourceType: "fetch",
        request: { method: "GET", url: "https://www.cnn.com/data.json", headers: {} },
        response: { status: 403, headers: { "content-type": "application/json" }, body, contentType: "application/json" },
      }],
    };
    await assert.rejects(addOperation({
      site: "cnn-fear-greed",
      op: "current-index",
      trigger: { url: "https://www.cnn.com/markets/fear-and-greed" },
      examples: [{}, {}],
      match: { method: "GET", host: "www.cnn.com", path: "/data.json" },
      from: { capture },
      response: { format: "json", extract: "fear_and_greed_historical.data" },
    }), (error: unknown) => error instanceof BotChallengeError && error.challenge === true);
  } finally {
    process.env.API_ANYTHING_HOME = previous;
    await rm(home, { recursive: true, force: true });
  }
});

test("200 interstitial from the real vendor triggers visible challenge handoff and raw nested fixture replay", async () => {
  const home = await mkdtemp(join(tmpdir(), "collector-vendor-canary-wall-"));
  const profile = join(home, "profile");
  const site = {
    name: "cnn-fear-greed",
    baseUrl: "https://www.cnn.com",
    operations: [{
      name: "current-index",
      request: { method: "GET", url: "https://www.cnn.com/markets/fear-and-greed", headers: {} },
      slots: [], volatile: [], trigger: { url: "https://www.cnn.com/markets/fear-and-greed" },
      match: { path: "/markets/fear-and-greed" },
      response: { format: "json", extract: "fear_and_greed_historical.data" },
      params: [], readOnly: true, minTier: 1,
    }],
  };
  await mkdir(join(home, "sites"), { recursive: true });
  await writeFile(join(home, "sites", "cnn-fear-greed.json"), JSON.stringify(site));
  const previous = process.env.API_ANYTHING_HOME;
  process.env.API_ANYTHING_HOME = home;
  const interstitial = await readFixture("interstitial-200.html");
  const raw = await readFixture("fear-greed-historical.json");
  let fetchCount = 0;
  let openerCount = 0;
  let notificationCount = 0;
  try {
    const response = await runLearnCanary(
      async (maxTier) => await call("cnn-fear-greed", "current-index", {}, {
        maxTier,
        minIntervalMs: 0,
        fetchImpl: async () => new Response(fetchCount++ === 0 ? interstitial : raw, {
          status: 200,
          headers: { "content-type": fetchCount === 1 ? "text/html" : "application/json" },
        }),
      }),
      async () => {
        const page: ChallengePage = {
          isClosed: () => false,
          goto: async () => undefined,
          locator: () => ({ innerText: async () => "Public index is ready after the human check." }),
          setContent: async () => undefined,
          waitForFunction: async () => undefined,
          close: async () => undefined,
        };
        const context: ChallengeContext = {
          newPage: async () => page,
          close: async () => undefined,
        };
        const outcome = await waitForHumanChallenge(profile, "https://www.cnn.com/markets/fear-and-greed", () => { notificationCount += 1; }, async () => {
          openerCount += 1;
          return context;
        }, 1000);
        assert.equal(outcome, "completed");
      },
    );
    assert.equal(response.ok, true);
    assert.equal(response.challenge, undefined);
    assert.equal((response.data as Array<{ value: number }>)[0]?.value, 42);
    assert.equal(fetchCount, 2);
    assert.equal(openerCount, 1);
    assert.equal(notificationCount, 1);

    const replayFixture: ReplayFixture = {
      fetched_at: "2026-10-09T20:00:00Z",
      raw_body: raw,
      content_type: "application/json",
      rows: [{ value: 42, rating: "fear", timestamp: "2026-10-09T20:00:00Z" }],
    };
    const replayed = await replayRawTemplate(home, "cnn-fear-greed", "current-index", {}, Buffer.from(JSON.stringify(site)), replayFixture, 5000);
    assert.deepEqual(replayed, replayFixture.rows);
  } finally {
    process.env.API_ANYTHING_HOME = previous;
    await rm(home, { recursive: true, force: true });
  }
});

test("real vendor fixture replay skips a site's network pacing bucket", async () => {
  const home = await mkdtemp(join(tmpdir(), "collector-vendor-pacing-"));
  const previous = process.env.API_ANYTHING_HOME;
  process.env.API_ANYTHING_HOME = home;
  const site = {
    name: "cnn-fear-greed",
    baseUrl: "https://www.cnn.com",
    operations: [{
      name: "current-index",
      request: { method: "GET", url: "https://www.cnn.com/markets/fear-and-greed", headers: {} },
      slots: [], volatile: [], trigger: { url: "https://www.cnn.com/markets/fear-and-greed" },
      match: { path: "/markets/fear-and-greed" },
      response: { format: "json", extract: "fear_and_greed_historical.data" },
      params: [], readOnly: true, minTier: 1,
    }],
  };
  await mkdir(join(home, "sites"), { recursive: true });
  await writeFile(join(home, "sites", "cnn-fear-greed.json"), JSON.stringify(site));
  const raw = await readFixture("fear-greed-historical.json");
  try {
    await call("cnn-fear-greed", "current-index", {}, { maxTier: 1, minIntervalMs: 0, fetchImpl: async () => new Response(raw, { headers: { "content-type": "application/json" } }) });
    const fixture: ReplayFixture = { fetched_at: "2026-10-09T20:00:00Z", raw_body: raw, content_type: "application/json", rows: [] };
    const start = performance.now();
    await replayRawTemplate(home, "cnn-fear-greed", "current-index", {}, Buffer.from(JSON.stringify(site)), fixture, 5000);
    assert.ok(performance.now() - start < 1000, "local raw fixture replay must not wait for network pacing");
  } finally {
    process.env.API_ANYTHING_HOME = previous;
    await rm(home, { recursive: true, force: true });
  }
});
