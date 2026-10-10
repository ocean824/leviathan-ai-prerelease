import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { stampFirstSeen } from "./first-seen.js";

test("first-seen is write-once per source key and content across repeated fetches", async () => {
  const home = await mkdtemp(join(tmpdir(), "first-seen-write-once-"));
  const file = join(home, "first-seen.json");
  const row = { record_id: "native-7", value: 42 };
  try {
    const first = await stampFirstSeen(file, [row], "2026-10-10T10:00:00.000Z");
    const second = await stampFirstSeen(file, [row], "2026-10-10T10:05:00.000Z");
    const third = await stampFirstSeen(file, [row], "2026-10-10T09:55:00.000Z");
    const expected = first[0]!.__collector_first_seen;
    assert.equal(second[0]!.__collector_first_seen, expected);
    assert.equal(third[0]!.__collector_first_seen, expected);
    assert.equal(Object.keys(JSON.parse(await readFile(file, "utf8"))).length, 1);

    const changed = await stampFirstSeen(file, [{ ...row, value: 43 }], "2026-10-10T10:06:00.000Z");
    assert.notEqual(changed[0]!.__collector_first_seen, expected);
    assert.equal(Object.keys(JSON.parse(await readFile(file, "utf8"))).length, 2);
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});
