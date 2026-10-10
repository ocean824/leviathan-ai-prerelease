import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { canaryCompatible } from "./canary.js";
import { waitForHumanChallenge, type ChallengeContext, type ChallengeOpener, type ChallengePage } from "./challenge.js";
import { operationContracts, requestSchema } from "./contracts.js";

test("only stable operation IDs and strict arguments are accepted", () => {
  assert.equal(requestSchema.safeParse({
    method: "call",
    request_id: "95c8cf46-15bc-4509-9961-59d6dbe44144",
    operation_id: "cnn.fear_greed",
    args: {},
  }).success, true);
  assert.equal(requestSchema.safeParse({
    method: "call",
    request_id: "95c8cf46-15bc-4509-9961-59d6dbe44144",
    operation_id: "unknown.site",
    args: { url: "https://not-allowed.invalid" },
  }).success, false);
  assert.equal(operationContracts["calendar.fed"].input.safeParse({ year: 2026, url: "https://bad.invalid" }).success, false);
  assert.equal(requestSchema.safeParse({
    method: "learn",
    request_id: "95c8cf46-15bc-4509-9961-59d6dbe44144",
    operation_id: "calendar.fed",
    examples: [{ year: 2026 }, { year: 2027 }],
  }).success, true);
  assert.equal(requestSchema.safeParse({
    method: "learn",
    request_id: "95c8cf46-15bc-4509-9961-59d6dbe44144",
    operation_id: "calendar.fed",
    examples: [{ year: 2026 }],
  }).success, false);
});

test("repair canary accepts matching record shape and rejects schema drift", () => {
  const previous = [{ values: { score: 42, label: "Fear", observed_at: "2026-10-09T14:59:00Z" } }];
  const sameShape = [{ values: { score: 45, label: "Fear", observed_at: "2026-10-09T15:00:00Z" } }];
  const changedShape = [{ values: { score: "45", label: "Fear", observed_at: "2026-10-09T15:00:00Z" } }];
  assert.equal(canaryCompatible(previous, sameShape), true);
  assert.equal(canaryCompatible(previous, changedShape), false);
  assert.equal(canaryCompatible(previous, []), false);
});

test("a user clears a visible fake challenge and the operation may resume", async () => {
  const dir = await mkdtemp(join(tmpdir(), "api-anything-challenge-test-"));
  let solved = false;
  let notified = false;
  let contextClosed = false;
  const page: ChallengePage = {
    isClosed: () => false,
    goto: async () => undefined,
    locator: () => ({ innerText: async () => solved ? "Public data page with expected public content" : "Complete CAPTCHA" }),
    setContent: async () => undefined,
    waitForFunction: async () => undefined,
    close: async () => undefined,
  };
  let pageNumber = 0;
  const context: ChallengeContext = {
    newPage: async () => (++pageNumber === 1 ? page : {
      ...page,
      waitForFunction: async () => { solved = true; },
    }),
    close: async () => { contextClosed = true; },
  };
  const open: ChallengeOpener = async () => context;
  try {
    const result = await waitForHumanChallenge(dir, "https://public.example/", () => { notified = true; }, open, 3000);
    assert.equal(result, "completed");
    assert.equal(notified, true);
    assert.equal(contextClosed, true);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("closing the visible challenge window returns declined", async () => {
  const dir = await mkdtemp(join(tmpdir(), "api-anything-challenge-test-"));
  let closed = false;
  const page: ChallengePage = {
    isClosed: () => closed,
    goto: async () => { closed = true; },
    locator: () => ({ innerText: async () => "CAPTCHA" }),
    setContent: async () => undefined,
    waitForFunction: async () => { throw new Error("window closed"); },
    close: async () => undefined,
  };
  let pageNumber = 0;
  const context: ChallengeContext = {
    newPage: async () => (++pageNumber === 1 ? page : {
      ...page,
      isClosed: () => true,
    }),
    close: async () => undefined,
  };
  const open: ChallengeOpener = async () => context;
  try {
    const result = await waitForHumanChallenge(dir, "https://public.example/", () => undefined, open, 3000);
    assert.equal(result, "declined");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
