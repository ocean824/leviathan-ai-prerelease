import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { once } from "node:events";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const fixtureRoot = join(root, "fixtures", "challenges");
const mainFile = join(root, "dist", "main.js");

function capture(id, url, status, body, contentType) {
  return {
    id,
    at: new Date().toISOString(),
    url,
    finalUrl: url,
    cookies: [],
    exchanges: [{
      id: 1,
      resourceType: "document",
      request: { method: "GET", url, headers: {} },
      response: { status, headers: { "content-type": contentType }, body, contentType },
    }],
  };
}

async function waitForLines(child, lines, count, stderr) {
  const deadline = Date.now() + 12_000;
  while (lines.length < count) {
    if (child.exitCode !== null) throw new Error(`sidecar exited ${child.exitCode}: ${stderr()}`);
    if (Date.now() > deadline) throw new Error(`sidecar output timed out: ${stderr()}`);
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

test("production stdio learn handles a recorded vendor challenge through the user handoff branch", async () => {
  const dataDir = await mkdtemp(join(tmpdir(), "leviathan-learn-wall-e2e-"));
  const captureFile = join(dataDir, "captures.json");
  const bodyFile = join(fixtureRoot, "fear-greed-historical.json");
  const url = "https://www.cnn.com/markets/fear-and-greed";
  const wall = await readFile(join(fixtureRoot, "cf-challenge-403.html"), "utf8");
  const successful = await readFile(bodyFile, "utf8");
  await writeFile(captureFile, JSON.stringify({
    wall: capture("recorded-wall", url, 403, wall, "text/html"),
    success: capture("recorded-success", url, 200, successful, "application/json"),
  }));
  const args = [
    "--experimental-loader", pathToFileURL(join(root, "e2e", "learn-wall-loader.mjs")).href,
    "--import", pathToFileURL(join(root, "e2e", "learn-wall-fetch.mjs")).href,
    mainFile,
  ];
  const child = spawn(process.execPath, args, {
    cwd: root,
    env: {
      PATH: process.env.PATH ?? "",
      ...(process.env.SystemRoot ? { SystemRoot: process.env.SystemRoot } : {}),
      ...(process.env.TEMP ? { TEMP: process.env.TEMP } : {}),
      LEVIATHAN_COLLECTOR_DATA: dataDir,
      LEVIATHAN_TEST_CAPTURE_FILE: captureFile,
      LEVIATHAN_TEST_CNN_BODY: bodyFile,
      LEVIATHAN_PUBLIC_USER_AGENT: "LeviathanPublicCollector/1.0",
    },
    stdio: ["pipe", "pipe", "pipe"],
  });
  try {
    const lines = [];
    let pending = "";
    let stderr = "";
    child.stderr.setEncoding("utf8").on("data", (chunk) => { stderr += chunk; });
    child.stdout.setEncoding("utf8").on("data", (chunk) => {
      pending += chunk;
      for (;;) {
        const index = pending.indexOf("\n");
        if (index < 0) break;
        lines.push(JSON.parse(pending.slice(0, index)));
        pending = pending.slice(index + 1);
      }
    });
    child.stdin.write(`${JSON.stringify({
      method: "learn",
      request_id: "8b77aa89-75fb-4d31-9ea8-d8df2adf1572",
      operation_id: "cnn.fear_greed",
      examples: [{}, {}],
    })}\n`);
    await waitForLines(child, lines, 2, () => stderr);
    assert.equal(lines[0].type, "notification");
    assert.equal(lines[0].status, "USER_ACTION_REQUIRED");
    assert.match(lines[0].message, /cnn-fear-greed/);
    assert.equal(lines[1].status, "OK", JSON.stringify({ response: lines[1], stderr }));
    assert.equal(lines[1].candidate_only, true);
    assert.equal(lines[1].operation_id, "cnn.fear_greed");
  } finally {
    child.stdin.end();
    if (child.exitCode === null) {
      child.kill();
      await Promise.race([once(child, "exit"), new Promise((resolve) => setTimeout(resolve, 1_000))]);
    }
    await rm(dataDir, { recursive: true, force: true });
  }
});
