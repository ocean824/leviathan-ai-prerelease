// stdin: {"body": "...", "contentType": "...", "recipe": {format, extract, pick}|null}  ->  stdout JSON
import { pathToFileURL } from "node:url";
import { join } from "node:path";
import { readFileSync } from "node:fs";

const DIST = process.env.AA_DIST;
const { sanitizedFixtureBody } = await import(pathToFileURL(join(DIST, "fixture-sanitize.js")).href);
const { extract } = await import(pathToFileURL(join(DIST, "..", "vendor", "api-anything", "dist", "extract.js")).href);
const input = JSON.parse(readFileSync(0, "utf8"));
const out = {};
try {
  out.sanitized = sanitizedFixtureBody(input.body, input.contentType, input.recipe ?? undefined);
} catch (error) {
  out.error = String(error.message);
}
if (input.recipe && out.sanitized !== undefined) {
  const run = (text) => { try { const r = extract({ ...input.recipe, pick: [...input.recipe.pick] }, text); return Array.isArray(r) ? r : [r]; } catch (e) { return { error: String(e.message) }; } };
  out.raw_rows = run(input.body);
  out.sanitized_rows = run(out.sanitized);
}
process.stdout.write(JSON.stringify(out));
