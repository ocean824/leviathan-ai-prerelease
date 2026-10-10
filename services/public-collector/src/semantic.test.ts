import assert from "node:assert/strict";
import test from "node:test";
import { semanticCheck } from "./semantic.js";

test("pinned fixture date windows use recorded fetched_at instead of wall clock", () => {
  const rows = [{
    record_id: "fomc-2024-12",
    event_name: "FOMC meeting",
    release_type: "meeting",
    scheduled_at: "2024-12-31T18:00:00Z",
  }];
  const recordedFetch = Date.parse("2025-10-01T18:00:00Z");

  assert.doesNotThrow(() => semanticCheck("calendar.fed", rows, recordedFetch));
  assert.throws(() => semanticCheck("calendar.fed", rows, Date.parse("2026-10-09T18:00:00Z")), /SEMANTIC_CANARY_FAILED/);
});
