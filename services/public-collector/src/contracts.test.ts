import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { operationContracts } from "./contracts.js";

const fixtures = {
  "calendar.fed": [{ event_name: "FOMC meeting", agency: "Federal Reserve", scheduled_at: "2026-10-29T18:00:00Z", release_type: "meeting" }],
  "earnings.forward": [{ ticker: "AAPL", fiscal_period: "2026 Q4", event_type: "earnings", scheduled_at: "2026-10-29T20:00:00Z", status: "scheduled" }],
  "senate.efd.ptr": [{ report_url: "https://efdsearch.senate.gov/search/report/1", filed_at: "2026-10-09T20:00:00Z", transactions: [{ ticker: "XYZ", trade_date: "2026-10-01T00:00:00Z", transaction_type: "purchase", amount_range: "$1,001-$15,000" }] }],
  "cboe.daily.stats": [{ observed_at: "2026-10-09T20:00:00Z", metric: "put_call_ratio", value: 0.91, unit: "ratio", maturity: null }],
  "cnn.fear_greed": [{ value: 42, label: "Fear", observed_at: "2026-10-09T20:00:00Z" }],
} as const;

test("recorded native page fields satisfy strict operation output contracts", () => {
  for (const [operationId, fixture] of Object.entries(fixtures) as [keyof typeof operationContracts, unknown][]) {
    assert.doesNotThrow(() => operationContracts[operationId].records.parse(fixture));
    const row = (fixture as Record<string, unknown>[])[0]!;
    assert.throws(() => operationContracts[operationId].records.parse([{ ...row, unexpected_native_field: true }]));
  }
});

test("Fed and Senate pins require recorded native response bodies", async () => {
  const registry = JSON.parse(await readFile(new URL("../templates/PINNED.json", import.meta.url), "utf8")) as {
    pin_requirements: Record<string, string>;
  };
  assert.equal(registry.pin_requirements["calendar.fed"], "recorded-native-body-required");
  assert.equal(registry.pin_requirements["senate.efd.ptr"], "recorded-native-body-required");
  assert.equal(registry.pin_requirements["earnings.forward"], "reviewed-fixture-allowed");
});
