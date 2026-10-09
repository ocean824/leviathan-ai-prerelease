import type { DataSourcesApiResult, DataSourcesResponse } from "./model";

async function listSources(): Promise<DataSourcesApiResult> {
  try {
    const response = await fetch("/api/data-sources", {
      headers: { Accept: "application/json" },
    });
    if (!response.ok) return { ok: false, error: "Data source status unavailable" };
    const data = (await response.json()) as DataSourcesResponse;
    if (data.schema_version !== "leviathan.data-sources/1" || !Array.isArray(data.sources)) {
      return { ok: false, error: "Data source status unavailable" };
    }
    return { ok: true, data };
  } catch {
    return { ok: false, error: "Data source status unavailable" };
  }
}

export const dataSourcesApi = { listSources };
