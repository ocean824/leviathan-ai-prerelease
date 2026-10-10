import assert from "node:assert/strict";
import test from "node:test";
import { extract } from "../vendor/api-anything/dist/extract.js";
import { operationContracts } from "./contracts.js";
import { sanitizedFixtureBody } from "./fixture-sanitize.js";

test("HTML fixture sanitation drops executable, form, hidden, and patterned personal data", () => {
  const cases = [
    '<html><body><script>secret()</script><input value="hidden"><div hidden>hidden value</div><table><tr><td>Scheduled event</td><td>2026-10-29</td><td>Alex Doe</td><td>alex.doe@example.org</td><td>(202) 555-0100</td></tr></table></body></html>',
    '<html><body><script>window.__DATA__ = {name:"Jane Doe"}</script><input type="hidden" name="csrf" value="token"><tr><td>Public filing</td><td>2026-10-01</td><td>jane@example.org</td></tr></body></html>',
  ];
  for (const html of cases) {
    const sanitized = sanitizedFixtureBody(html, "text/html");
    assert.doesNotMatch(sanitized, /<script|<input|hidden|Alex Doe|Jane Doe|example\.org|555-0100/i);
    assert.match(sanitized, /Scheduled event|Public filing/);
  }
});

test("JSON redaction uses content patterns and leaves harmless names intact", () => {
  const sanitized = JSON.parse(sanitizedFixtureBody(JSON.stringify({ name: "release calendar", email: "jane@example.org", status: "scheduled" }), "application/json")) as Record<string, string>;
  assert.equal(sanitized.name, "release calendar");
  assert.equal(sanitized.email, "[REDACTED]");
  assert.equal(sanitized.status, "scheduled");
});

const nativeBodies: Record<keyof typeof operationContracts, unknown> = {
  "calendar.fed": { events: [{ name: "Federal Reserve meeting", agency: "Federal Reserve", date: "2026-10-29T18:00:00Z", type: "Federal Reserve announcement", id: "fed-1", publishedAt: "2026-10-01T12:00:00Z", filerName: "Senator Jane Doe", contact: "jane.doe@example.org" }] },
  "earnings.forward": { calendar: [{ ticker: { symbol: "AAPL" }, quarter: "Second Quarter 2027", type: "Earnings Call", date: "2026-10-29T20:00:00Z", status: "Federal Reserve watch", id: "earn-1", personalName: "Alex Morgan", email: "alex@example.org" }] },
  "senate.efd.ptr": { reports: [{ url: "https://efdsearch.senate.gov/search/report/1", filedAt: "2026-10-09T20:00:00Z", transactions: [{ ticker: "XYZ", trade_date: "2026-10-01T00:00:00Z", transaction_type: "Federal Reserve purchase", amount_range: "$1,001-$15,000" }], id: "ptr-1", availableAt: "2026-10-09T20:00:00Z", filerName: "Senator Jane Doe", email: "jane@example.org" }] },
  "cboe.daily.stats": { dailyStatistics: [{ timestamp: "2026-10-09T20:00:00Z", name: "Put Call Ratio", value: 0.91, unit: "ratio", expiry: "Federal Reserve week", id: "cboe-1", contact: "market@example.org" }] },
  "cnn.fear_greed": { fear_and_greed_historical: { data: [{ value: 18, rating: "Extreme Fear", timestamp: "2026-10-09T20:00:00Z", id: "fg-1", analyst: "Jane Doe", email: "jane@example.org" }] } },
};

test("every operation preserves recipe-selected native values byte-for-byte while redacting unused PII", () => {
  for (const [operationId, rawObject] of Object.entries(nativeBodies) as [keyof typeof operationContracts, unknown][]) {
    const raw = JSON.stringify(rawObject);
    const contractRecipe = operationContracts[operationId].mappingRecipe;
    const recipe = { ...contractRecipe, pick: [...contractRecipe.pick] } as Parameters<typeof extract>[0];
    const sanitized = sanitizedFixtureBody(raw, "application/json", recipe);
    assert.deepEqual(extract(recipe, sanitized), extract(recipe, raw), `${operationId} extracted mapping changed`);
    assert.match(sanitized, /\[REDACTED\]/, `${operationId} did not redact unused personal data`);
  }
});
