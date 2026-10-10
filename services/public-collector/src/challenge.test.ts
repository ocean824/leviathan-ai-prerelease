import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { waitForHumanChallenge, type ChallengeContext, type ChallengePage } from "./challenge.js";

test("challenge hosts bypass robots while public data hosts keep their robots rules", async () => {
  const dataDir = await mkdtemp(join(tmpdir(), "collector-challenge-robots-"));
  const previousPolicy = process.env.LEVIATHAN_REQUEST_POLICY;
  process.env.LEVIATHAN_REQUEST_POLICY = JSON.stringify({
    allowedHosts: ["www.cnn.com"],
    robots: { "www.cnn.com": [{ path: "/deny", allow: false }] },
  });
  const routeResults: string[] = [];
  const page: ChallengePage = {
    isClosed: () => false,
    goto: async () => undefined,
    locator: () => ({ innerText: async () => "The public page is ready after the check." }),
    setContent: async () => undefined,
    waitForFunction: async () => undefined,
    close: async () => undefined,
  };
  const context: ChallengeContext = {
    newPage: async () => page,
    route: async (_pattern, handler) => {
      for (const url of ["https://captcha.vendor.example/widget.js", "https://www.cnn.com/deny"]) {
        let result = "";
        await handler({
          request: () => ({ url: () => url }),
          continue: async () => { result = "continue"; },
          abort: async () => { result = "abort"; },
        });
        routeResults.push(result);
      }
    },
    close: async () => undefined,
  };
  try {
    const outcome = await waitForHumanChallenge(
      join(dataDir, "profile"),
      "https://www.cnn.com/markets/fear-and-greed",
      () => undefined,
      async () => context,
      1000,
      ["captcha.vendor.example"],
      dataDir,
    );
    assert.equal(outcome, "completed");
    assert.deepEqual(routeResults, ["continue", "abort"]);
  } finally {
    if (previousPolicy === undefined) delete process.env.LEVIATHAN_REQUEST_POLICY;
    else process.env.LEVIATHAN_REQUEST_POLICY = previousPolicy;
    await rm(dataDir, { recursive: true, force: true });
  }
});
