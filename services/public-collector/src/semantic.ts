import { MAX_RECORDS, type OperationId } from "./contracts.js";

export function semanticCheck(
  operationId: OperationId,
  rows: Record<string, unknown>[],
  referenceTimeMs = Date.now(),
): void {
  if (rows.length === 0 || rows.length > MAX_RECORDS) throw new Error("SEMANTIC_CANARY_FAILED");
  const seen = new Set<string>();
  const now = referenceTimeMs;
  const day = 86_400_000;
  for (const row of rows) {
    const id = typeof row.record_id === "string" ? row.record_id : JSON.stringify(row);
    if (seen.has(id)) throw new Error("SEMANTIC_CANARY_FAILED");
    seen.add(id);
    const timestamp = (key: string): number | null => {
      const value = row[key];
      return typeof value === "string" && Number.isFinite(Date.parse(value)) ? Date.parse(value) : null;
    };
    if (operationId === "calendar.fed") {
      const scheduled = timestamp("scheduled_at");
      if (typeof row.event_name !== "string" || !row.event_name.trim() || typeof row.release_type !== "string" || !row.release_type.trim() || scheduled === null || scheduled < now - 365 * day || scheduled > now + 5 * 365 * day) throw new Error("SEMANTIC_CANARY_FAILED");
    } else if (operationId === "earnings.forward") {
      const scheduled = timestamp("scheduled_at");
      if (typeof row.ticker !== "string" || !/^[A-Z0-9.-]{1,16}$/.test(row.ticker) || typeof row.status !== "string" || !row.status.trim() || scheduled === null || scheduled < now - 365 * day || scheduled > now + 365 * day) throw new Error("SEMANTIC_CANARY_FAILED");
    } else if (operationId === "senate.efd.ptr") {
      const report = typeof row.report_url === "string" ? new URL(row.report_url) : null;
      if (!report || report.hostname !== "efdsearch.senate.gov" || !Array.isArray(row.transactions) || !row.transactions.length) throw new Error("SEMANTIC_CANARY_FAILED");
      const filed = timestamp("filed_at");
      if (filed !== null && filed > now + 5 * 60_000) throw new Error("SEMANTIC_CANARY_FAILED");
    } else if (operationId === "cboe.daily.stats") {
      const observed = timestamp("observed_at");
      const value = row.value;
      if (observed === null || observed > now + 5 * 60_000 || observed < now - 14 * day || typeof value !== "number" || !Number.isFinite(value) || value < 0 || value > 200 || typeof row.unit !== "string" || !row.unit.trim()) throw new Error("SEMANTIC_CANARY_FAILED");
      if (row.metric === "vix_term_structure" && (typeof row.maturity !== "string" || !row.maturity.trim())) throw new Error("SEMANTIC_CANARY_FAILED");
    } else if (operationId === "cnn.fear_greed") {
      const observed = timestamp("observed_at");
      if (typeof row.value !== "number" || !Number.isInteger(row.value) || row.value < 0 || row.value > 100 || typeof row.label !== "string" || !row.label.trim() || observed === null || observed > now + 5 * 60_000 || observed < now - 7 * day) throw new Error("SEMANTIC_CANARY_FAILED");
    }
  }
}
