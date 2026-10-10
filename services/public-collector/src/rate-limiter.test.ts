import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { PersistentRateLimiter } from "./rate-limiter.js";

test("persistent cadence and backoff checks return immediately across limiter instances", async () => {
  const dir = await mkdtemp(join(tmpdir(), "leviathan-rate-limiter-"));
  const path = join(dir, "rate-state.json");
  try {
    const first = new PersistentRateLimiter(path);
    await first.gate("calendar.fed", "call", 86_400_000, 5);
    await first.success("calendar.fed");
    await first.backoff("cnn.fear_greed", 60_000);

    const restarted = new PersistentRateLimiter(path);
    const started = performance.now();
    await assert.rejects(restarted.gate("calendar.fed", "call", 86_400_000, 5), /NOT_DUE/);
    await assert.rejects(restarted.gate("cnn.fear_greed", "call", 3_600_000, 5), /RATE_LIMITED/);
    assert.ok(performance.now() - started < 100, "rate gates must never sleep for cadence or backoff");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("learn and repair spacing is persisted and independent of the long call cadence", async () => {
  const dir = await mkdtemp(join(tmpdir(), "leviathan-rate-limiter-"));
  const path = join(dir, "rate-state.json");
  try {
    const limiter = new PersistentRateLimiter(path);
    await limiter.gate("calendar.fed", "learn", 86_400_000, 10_000);
    const restarted = new PersistentRateLimiter(path);
    const started = performance.now();
    await assert.rejects(restarted.gate("calendar.fed", "learn", 86_400_000, 10_000), /RATE_LIMITED/);
    assert.ok(performance.now() - started < 100);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
