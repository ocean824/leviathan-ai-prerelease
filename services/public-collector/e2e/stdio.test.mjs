import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { once } from "node:events";
import { fileURLToPath } from "node:url";
import test from "node:test";

test("production entrypoint speaks bounded NDJSON over stdio and stays fail closed", async () => {
  const dataDir = await mkdtemp(join(tmpdir(), "leviathan-collector-e2e-"));
  const env = {
    LEVIATHAN_COLLECTOR_DATA: dataDir,
    PATH: process.env.PATH ?? "",
    ...(process.env.SystemRoot ? { SystemRoot: process.env.SystemRoot } : {}),
    ...(process.env.TEMP ? { TEMP: process.env.TEMP } : {}),
  };
  const child = spawn(process.execPath, [fileURLToPath(new URL("../dist/main.js", import.meta.url))], {
    cwd: fileURLToPath(new URL("..", import.meta.url)),
    env,
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
    child.stdin.write(JSON.stringify({ method: "health", request_id: "b0bc1d2f-972a-4843-9ea9-d57bc54c8910" }) + "\n");
    await waitForLines(child, lines, 1, () => stderr);
    assert.equal(lines[0].status, "OK");
    child.stdin.write(JSON.stringify({ method: "call", request_id: "f2135f77-77e0-4472-b9de-b12c77571bb0", operation_id: "cnn.fear_greed", args: {} }) + "\n");
    await waitForLines(child, lines, 2, () => stderr);
    assert.equal(lines[1].error_code, "TEMPLATE_UNPINNED");
    assert.equal(lines[1].records.length, 0);
  } finally {
    child.stdin.end();
    await once(child, "exit");
    await rm(dataDir, { recursive: true, force: true });
  }
});

async function waitForLines(child, lines, count, getStderr) {
  const deadline = Date.now() + 10_000;
  while (lines.length < count) {
    if (child.exitCode !== null) throw new Error(`sidecar exited ${child.exitCode}: ${getStderr()}`);
    if (Date.now() > deadline) throw new Error(`sidecar output timed out: ${getStderr()}`);
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}
