import { readdir, readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { Pool } from "@neondatabase/serverless";

const root = dirname(dirname(fileURLToPath(import.meta.url)));

/** Apply packaged SQL files in order; connection credentials are never logged. */
export async function applyMigrationsV1({ connectionString, pool } = {}) {
  if (!pool && (typeof connectionString !== "string" || connectionString.length === 0)) {
    throw new Error("DATABASE_URL_NOT_CONFIGURED");
  }
  const clientPool = pool ?? new Pool({ connectionString });
  const client = await clientPool.connect();
  try {
    await client.query("CREATE TABLE IF NOT EXISTS schema_migrations (name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())");
    const files = (await readdir(join(root, "migrations")))
      .filter((name) => /^\d{3}_.+\.sql$/.test(name)).sort();
    for (const name of files) {
      const found = await client.query("SELECT 1 FROM schema_migrations WHERE name=$1", [name]);
      if (found.rows.length) continue;
      const source = await readFile(join(root, "migrations", name), "utf8");
      const body = source.replace(/^\s*BEGIN\s*;\s*/i, "").replace(/\s*COMMIT\s*;\s*$/i, "");
      await client.query("BEGIN");
      try {
        await client.query(body);
        await client.query("INSERT INTO schema_migrations(name) VALUES ($1)", [name]);
        await client.query("COMMIT");
      } catch (error) {
        await client.query("ROLLBACK").catch(() => undefined);
        throw error;
      }
    }
  } finally {
    client.release();
    if (!pool) await clientPool.end();
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  try {
    await applyMigrationsV1({ connectionString: process.env.DATABASE_URL });
    process.stdout.write("Migrations applied.\n");
  } catch (error) {
    process.stderr.write("Migration failed.\n");
    process.exitCode = 1;
  }
}
