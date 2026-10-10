import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const pages = JSON.parse(await readFile(path.join(root, "pages.json"), "utf8")) as Array<{ key: string; path: string; title: string; description: string }>;
const outputName = (key: string) => key === "home" ? "index.html" : `${key}.html`;

describe("generated public pages", () => {
  it.each(pages.map((page) => [page.path, page] as const))("renders metadata, date and complete navigation on %s", async (_route, page) => {
    const html = await readFile(path.join(root, "public", outputName(page.key)), "utf8");
    expect(html).toContain(`<title>${page.title} | Leviathan AI</title>`);
    expect(html).toContain(`name="description" content="${page.description}"`);
    expect(html).toContain("Last updated: 2026-10-09");
    expect(html).toContain("aria-label=\"Main navigation\"");
    expect(html).toContain("aria-label=\"Footer navigation\"");
    for (const item of pages) expect(html).toContain(`href=\"${item.path}\"`);
    expect(html).not.toMatch(/<script\b/i);
  });

  it("uses local responsive styling with light and dark color schemes", async () => {
    const css = await readFile(path.join(root, "public", "site.css"), "utf8");
    expect(css).toContain("color-scheme: light dark");
    expect(css).toContain("prefers-color-scheme: dark");
    expect(css).toContain("100% - 32px");
  });
});
