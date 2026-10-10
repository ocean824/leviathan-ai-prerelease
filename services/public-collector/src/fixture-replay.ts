import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { call } from "../vendor/api-anything/dist/execute.js";
import { OPERATION_TIMEOUT_MS } from "./contracts.js";

export type ReplayFixture = {
  fetched_at: string;
  raw_body: string;
  content_type: string;
  rows: Record<string, unknown>[];
};

export async function replayRawTemplate(
  appDataDir: string,
  site: string,
  operation: string,
  args: Record<string, unknown>,
  template: Buffer,
  fixture: ReplayFixture,
  minIntervalMs: number,
): Promise<unknown> {
  const replayRoot = join(appDataDir, "template-replay");
  await mkdir(replayRoot, { recursive: true });
  const replayHome = await mkdtemp(join(replayRoot, "run-"));
  const sitePath = join(replayHome, "sites", `${site}.json`);
  const previousHome = process.env.API_ANYTHING_HOME;
  try {
    await mkdir(dirname(sitePath), { recursive: true });
    await writeFile(sitePath, template, { mode: 0o600 });
    process.env.API_ANYTHING_HOME = replayHome;
    const result = await call(site, operation, args, {
      maxTier: 1,
      timeoutMs: OPERATION_TIMEOUT_MS,
      minIntervalMs,
      skipPacing: true,
      fetchImpl: async () => new Response(fixture.raw_body, {
        status: 200,
        headers: { "content-type": fixture.content_type },
      }),
    });
    if (!result.ok || result.class !== "ok") throw new Error("FIXTURE_TEMPLATE_REPLAY_FAILED");
    return result.data;
  } finally {
    process.env.API_ANYTHING_HOME = previousHome;
    await rm(replayHome, { recursive: true, force: true });
  }
}
