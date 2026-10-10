import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "public");
const files = (await readdir(root)).filter((name) => name.endsWith(".html"));
const paths = new Set(["/", ...files.filter((name) => name !== "index.html").map((name) => `/${name.slice(0, -5)}`), "/site.css"]);
const errors = [];
for (const file of files) {
  const html = await readFile(path.join(root, file), "utf8");
  for (const [, href] of html.matchAll(/\bhref="([^"]+)"/g)) {
    if (/^(?:https?:|mailto:|#)/i.test(href)) continue;
    if (!paths.has(href)) errors.push(`${file}: unresolved link ${href}`);
  }
}
if (errors.length) { console.error(errors.join("\n")); process.exitCode = 1; }
else console.log(`Link check passed for ${files.length} generated pages.`);
