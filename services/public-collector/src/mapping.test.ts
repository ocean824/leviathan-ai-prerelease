import assert from "node:assert/strict";
import test from "node:test";
import { extract } from "../vendor/api-anything/dist/extract.js";
import { operationContracts, type OperationId } from "./contracts.js";

const nativeBodies: Record<OperationId, string> = {
  "calendar.fed": JSON.stringify({ events: [{ id: "fed-2026-10-29", name: "FOMC meeting", agency: "Federal Reserve", date: "2026-10-29T18:00:00Z", type: "meeting" }] }),
  "earnings.forward": JSON.stringify({ calendar: [{ id: "earnings-AAPL-2026Q4", ticker: { symbol: "AAPL" }, quarter: "2026 Q4", type: "earnings", date: "2026-10-29T20:00:00Z", status: "scheduled" }] }),
  "senate.efd.ptr": JSON.stringify({ reports: [{ id: "ptr-2026-0042", url: "https://efdsearch.senate.gov/search/report/0042", filedAt: "2026-10-09T20:00:00Z", availableAt: "2026-10-09T20:00:00Z", transactions: [{ ticker: "XYZ", trade_date: "2026-10-01T00:00:00Z", transaction_type: "purchase", amount_range: "$1,001-$15,000" }] }] }),
  "cboe.daily.stats": JSON.stringify({ dailyStatistics: [{ id: "cboe-2026-10-09-pc", timestamp: "2026-10-09T20:00:00Z", name: "put_call_ratio", value: 0.91, unit: "ratio", expiry: null }] }),
  "cnn.fear_greed": JSON.stringify({ fear_and_greed_historical: { data: [{ id: "cnn-2026-10-09", value: 42, rating: "Fear", timestamp: "2026-10-09T20:00:00Z" }] } }),
};

test("each reviewed native mapping recipe yields a strict operation candidate", () => {
  for (const operationId of Object.keys(operationContracts) as OperationId[]) {
    const contract = operationContracts[operationId];
    assert.equal(contract.mappingRecipe.format, "json", `${operationId} sanitizer fixture kind must match its recipe`);
    const mapped = extract({ ...contract.mappingRecipe, pick: [...contract.mappingRecipe.pick] }, nativeBodies[operationId]);
    const rows = Array.isArray(mapped) ? mapped : [mapped];
    assert.doesNotThrow(() => contract.records.parse(rows), `${operationId} mapping did not satisfy its contract`);
    assert.equal(contract.mappingFixtureKind, operationId === "cnn.fear_greed" ? "recorded-native-body" : "hand-built-native-body");
  }
});
