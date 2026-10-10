import assert from "node:assert/strict";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const mainFile = join(dirname(fileURLToPath(import.meta.url)), "main.js");

async function startSidecar(replayOnly = false): Promise<{ child: ChildProcessWithoutNullStreams; dataDir: string; lines: AsyncIterator<string> }> {
  const dataDir = await mkdtemp(join(tmpdir(), "leviathan-sidecar-e2e-"));
  const child = spawn(process.execPath, [mainFile], {
    env: {
      PATH: process.env.PATH ?? "",
      SystemRoot: process.env.SystemRoot ?? "",
      TEMP: process.env.TEMP ?? tmpdir(),
      LEVIATHAN_COLLECTOR_DATA: dataDir,
      LEVIATHAN_PUBLIC_USER_AGENT: "LeviathanPublicCollector/1.0",
      ...(replayOnly ? { LEVIATHAN_REPLAY_ONLY: "1" } : {}),
    },
    stdio: ["pipe", "pipe", "pipe"],
  });
  const lines = (async function* () {
    let buffered = "";
    for await (const chunk of child.stdout) {
      buffered += chunk.toString("utf8");
      let newline = buffered.indexOf("\n");
      while (newline >= 0) {
        yield buffered.slice(0, newline);
        buffered = buffered.slice(newline + 1);
        newline = buffered.indexOf("\n");
      }
    }
  })();
  return { child, dataDir, lines };
}

function send(child: ChildProcessWithoutNullStreams, request: object): void {
  child.stdin.write(`${JSON.stringify(request)}\n`);
}

test("real stdio main loop returns health and fails unpinned calls closed without network", async () => {
  const { child, dataDir, lines } = await startSidecar();
  try {
    send(child, { method: "health", request_id: "95c8cf46-15bc-4509-9961-59d6dbe44144" });
    const health = JSON.parse((await lines.next()).value ?? "{}");
    assert.equal(health.status, "OK");
    assert.equal(health.request_id, "95c8cf46-15bc-4509-9961-59d6dbe44144");

    send(child, {
      method: "call",
      request_id: "1a338cb3-1c20-4626-a50d-48ca47b9a2e2",
      operation_id: "calendar.fed",
      args: { year: 2026 },
    });
    const call = JSON.parse((await lines.next()).value ?? "{}");
    assert.equal(call.error_code, "TEMPLATE_UNPINNED");
    assert.equal(call.records.length, 0);
  } finally {
    child.kill();
    await rm(dataDir, { recursive: true, force: true });
  }
});

test("real stdio main loop rejects an oversized frame", async () => {
  const { child, dataDir, lines } = await startSidecar();
  try {
    child.stdin.write(`${"x".repeat(1_100_001)}\n`);
    const response = JSON.parse((await lines.next()).value ?? "{}");
    assert.equal(response.error_code, "SCHEMA_INVALID");
  } finally {
    child.kill();
    await rm(dataDir, { recursive: true, force: true });
  }
});

test("real production stdio entrypoint routes learn through the replay-only fail-closed branch", async () => {
  const { child, dataDir, lines } = await startSidecar(true);
  try {
    send(child, {
      method: "learn",
      request_id: "c2e5c226-14d1-4e18-af93-e4fbf44151f4",
      operation_id: "calendar.fed",
      examples: [{ year: 2026 }, { year: 2027 }],
    });
    const response = JSON.parse((await lines.next()).value ?? "{}");
    assert.equal(response.request_id, "c2e5c226-14d1-4e18-af93-e4fbf44151f4");
    assert.equal(response.operation_id, "calendar.fed");
    assert.equal(response.error_code, "BROWSER_UNAVAILABLE");
    assert.equal(response.records.length, 0);
  } finally {
    child.kill();
    await rm(dataDir, { recursive: true, force: true });
  }
});
