import { createHash } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b));
    return `{${entries.map(([key, nested]) => `${JSON.stringify(key)}:${stableJson(nested)}`).join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

export async function stampFirstSeen(
  file: string,
  rows: Record<string, unknown>[],
  fetchedAt: string,
): Promise<Record<string, unknown>[]> {
  const fetchedMs = Date.parse(fetchedAt);
  if (!Number.isFinite(fetchedMs)) throw new Error("FIRST_SEEN_LEDGER_INVALID");
  let ledger: Record<string, string> = {};
  try {
    ledger = JSON.parse(await readFile(file, "utf8")) as Record<string, string>;
    if (!ledger || typeof ledger !== "object" || Array.isArray(ledger)) throw new Error("FIRST_SEEN_LEDGER_INVALID");
    for (const [id, stamp] of Object.entries(ledger)) {
      if (!id || typeof stamp !== "string" || !Number.isFinite(Date.parse(stamp))) throw new Error("FIRST_SEEN_LEDGER_INVALID");
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw new Error("FIRST_SEEN_LEDGER_INVALID");
  }

  let monotonicFloor = Math.max(0, ...Object.values(ledger).map((stamp) => Date.parse(stamp)));
  const stamped = rows.map((row) => {
    const sourceKey = typeof row.record_id === "string" && row.record_id.length > 0
      ? row.record_id
      : createHash("sha256").update(stableJson(row)).digest("hex");
    const contentHash = createHash("sha256").update(stableJson(row)).digest("hex");
    const identity = createHash("sha256").update(`${sourceKey}\0${contentHash}`).digest("hex");
    let firstSeen = ledger[identity];
    if (!firstSeen) {
      firstSeen = new Date(Math.max(fetchedMs, monotonicFloor)).toISOString();
      ledger[identity] = firstSeen;
    }
    monotonicFloor = Math.max(monotonicFloor, Date.parse(firstSeen));
    return { ...row, __collector_record_id: sourceKey, __collector_first_seen: firstSeen };
  });

  await mkdir(dirname(file), { recursive: true });
  const temporary = `${file}.${process.pid}.${Date.now()}.tmp`;
  await writeFile(temporary, JSON.stringify(ledger), { mode: 0o600 });
  await rename(temporary, file);
  return stamped;
}
