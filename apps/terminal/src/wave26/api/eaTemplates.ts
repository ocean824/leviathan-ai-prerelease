/* EA-TEMPLATE-CATALOG-UI-001: GET-only reader for the EA template catalog metadata.
 *
 * The route returns identifiers only. This module reduces the response to closed sets
 * (platforms, block ids, the known catalog id) so a hostile or drifting payload can
 * never put free text on screen. Any extra field is dropped: a source body, and also
 * any `as_of` or `asOf`, because the route defines no source timestamp and a field it
 * does not define must never make the catalog look source-fresh.
 */
import type { ApiResult } from "../../api/client";

export const EA_TEMPLATES_PATH = "/v1/ea/templates";
export const UNRECOGNIZED = "UNRECOGNIZED";
export const OPERATOR_SESSION_UNAVAILABLE = "OPERATOR_SESSION_UNAVAILABLE";
export const PLATFORMS = ["MT4", "MT5"] as const;
export const KNOWN_BLOCK_IDS: ReadonlySet<string> = new Set([
  "bar_event", "sma_indicator", "compare.v1", "crossover.v1", "entry_signal.v1",
  "exit_signal.v1",
]);
export const KNOWN_CATALOG_IDS: ReadonlySet<string> = new Set(["leviathan_mql_source"]);
export const KNOWN_HTTP_REASONS: ReadonlySet<string> = new Set([
  "AUTH_REQUIRED", "INVALID_QUERY", "CATALOG_UNAVAILABLE", "TEMPLATE_NOT_FOUND",
]);
export const MAX_TEMPLATES = 64;
const MAX_VERSION = 1_000_000_000;
const DIGEST = /^[0-9a-f]{64}$/;

export type Platform = (typeof PLATFORMS)[number];

export interface EaTemplateEntry {
  /** Always `${platform}:${blockId}`; checked, never taken on trust. */
  templateId: string;
  blockId: string;
  platform: Platform;
}

export interface EaCatalogReport {
  catalogId: string;
  version: number;
  catalogDigest: string;
  templates: EaTemplateEntry[];
  /** Entries on a known platform whose block id is outside the closed set. Not shown. */
  unrecognizedCount: number;
}

type UnknownRecord = Record<string, unknown>;

function isRecord(value: unknown): value is UnknownRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isPlatform(value: unknown): value is Platform {
  return typeof value === "string" && (PLATFORMS as readonly string[]).includes(value);
}

export function parseEaCatalog(value: unknown): EaCatalogReport | null {
  if (!isRecord(value)) return null;
  const { catalog_id: catalogId, version, catalog_digest: digest, templates } = value;
  if (typeof catalogId !== "string" || typeof digest !== "string" || !DIGEST.test(digest)) {
    return null;
  }
  if (typeof version !== "number" || !Number.isSafeInteger(version)
    || version < 1 || version > MAX_VERSION) return null;
  // A hostile size fails closed before anything is scanned; a partial list is never shown.
  if (!Array.isArray(templates) || templates.length > MAX_TEMPLATES) return null;
  const entries: EaTemplateEntry[] = [];
  const seen = new Set<string>();
  let unrecognizedCount = 0;
  for (const item of templates) {
    if (!isRecord(item)) return null;
    const { template_id: templateId, block_id: blockId, platform } = item;
    if (typeof templateId !== "string" || typeof blockId !== "string" || !isPlatform(platform)) {
      return null;
    }
    if (templateId !== `${platform}:${blockId}`) return null;
    if (seen.has(templateId)) return null;
    seen.add(templateId);
    if (!KNOWN_BLOCK_IDS.has(blockId)) {
      unrecognizedCount += 1;
      continue;
    }
    entries.push({ templateId, blockId, platform });
  }
  return {
    catalogId: KNOWN_CATALOG_IDS.has(catalogId) ? catalogId : UNRECOGNIZED,
    version,
    catalogDigest: digest,
    templates: entries,
    unrecognizedCount,
  };
}

function httpCode(status: number, body: unknown): string {
  if (!Number.isInteger(status) || status < 100 || status > 599) return "HTTP_ERROR";
  if (status === 401) return OPERATOR_SESSION_UNAVAILABLE;
  const detail = isRecord(body) ? body.detail : undefined;
  return typeof detail === "string" && KNOWN_HTTP_REASONS.has(detail)
    ? `HTTP_${status}:${detail}`
    : `HTTP_${status}`;
}

export async function fetchEaTemplates(): Promise<ApiResult<EaCatalogReport>> {
  let response: Response;
  try {
    // No query string: the route rejects any. No body, and no method other than GET.
    response = await fetch(`/api${EA_TEMPLATES_PATH}`, {
      method: "GET",
      headers: { Accept: "application/json" },
    });
  } catch {
    return { ok: false, error: "NETWORK_ERROR" };
  }
  let body: unknown;
  try {
    body = await response.json();
  } catch {
    body = undefined;
  }
  if (!response.ok) return { ok: false, error: httpCode(response.status, body) };
  const report = parseEaCatalog(body);
  return report === null ? { ok: false, error: "MALFORMED_RESPONSE" } : { ok: true, data: report };
}
