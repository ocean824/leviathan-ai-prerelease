// SITE-LEGAL-001 mutation check. Usage: node qa/acceptance/SITE-LEGAL-001/mutants.mjs [--writer-only]
//
// Start from the writer tree, applying the minimal routing reference fix only when absent, then apply each mutant.
// A mutant is KILLED when at least one test that
// passed on the baseline now fails.
import { spawnSync } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { SITE_SRC, COMPLETE_COMPANY } from "./helpers.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const testFile = path.join(here, "acceptance.test.mjs");

export function patchedBaseline() {
  const dir = mkdtempSync(path.join(tmpdir(), "site-legal-001-base-"));
  cpSync(SITE_SRC, dir, { recursive: true, filter: (s) => !/[\\/](node_modules|public|\.wrangler)([\\/]|$)/.test(s.slice(SITE_SRC.length)) });
  const f = path.join(dir, "src", "index.ts");
  let t = readFileSync(f, "utf8");
  const a = 'const assetPath = path === "/" ? "/index.html" : `${path.slice(1)}.html`;';
  const b = 'if (!PAGES.has(path)) return';
  if (t.includes(a) && t.includes(b)) {
    t = t.replace(a, "const assetPath = path;").replace(b, 'if (path !== "/site.css" && !PAGES.has(path)) return');
    writeFileSync(f, t);
  } else if (!t.includes('asset.pathname = path;') || !t.includes('path !== "/site.css" && !PAGES.has(path)')) {
    throw new Error("routing patch is neither present nor applicable to the writer's index.ts");
  }
  // Facts are completed by the tests themselves (stageSite({company})); content tests need the writer's other fixes too, so
  // the baseline set is simply "whatever passes" — mutants are judged against that set.
  return dir;
}

function runSuite(siteRoot) {
  const r = spawnSync(process.execPath, ["--test", "--test-reporter=tap", testFile], {
    env: { ...process.env, SITE_ROOT: siteRoot }, encoding: "utf8", maxBuffer: 64 * 1024 * 1024,
  });
  const passed = new Set(); const failed = new Set();
  for (const line of r.stdout.split(/\r?\n/)) {
    const m = /^(not )?ok \d+ - (.*?)(?: # .*)?$/.exec(line);
    if (m) (m[1] ? failed : passed).add(m[2]);
  }
  return { passed, failed };
}

const edit = (file, from, to) => (dir) => {
  const p = path.join(dir, file); const t = readFileSync(p, "utf8");
  if (!t.includes(from)) throw new Error(`mutant anchor not found in ${file}: ${from}`);
  writeFileSync(p, t.replace(from, to));
};

export const MUTANTS = [
  ["M01 drop HSTS header", edit("src/index.ts", '  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",\n', "")],
  ["M02 CSP default-src 'self' -> *", edit("src/index.ts", "default-src 'self';", "default-src *;")],
  ["M03 drop X-Content-Type-Options nosniff", edit("src/index.ts", '  "X-Content-Type-Options": "nosniff",\n', "")],
  ["M04 drop Referrer-Policy", edit("src/index.ts", '  "Referrer-Policy": "strict-origin-when-cross-origin",\n', "")],
  ["M05 unknown routes answer 200", edit("src/index.ts", 'return withSecurity(new Response("Not found", { status: 404 }));', 'return withSecurity(new Response("<title>ok</title>", { status: 200 }));')],
  ["M06 third-party tracker script on homepage", edit("pages/home.html", '<p class="lede">', '<script async src="https://www.googletagmanager.com/gtag/js?id=G-X"></script><p class="lede">')],
  ["M07 broken internal link on homepage", edit("pages/home.html", 'href="/risk-disclosure"', 'href="/risk-disclosre"')],
  ["M08 facts gate: support_email no longer required", edit("src/facts.mjs", '  ["company.support_email", (config) => config.company?.support_email],\n', "")],
  ["M09 facts gate: ignores owner confirmation", edit("src/facts.mjs", "|| (confirmationRequired?.(config) ?? false)", "|| false")],
  ["M10 facts gate: [REQUIRED: marker no longer detected", edit("src/facts.mjs", '|| value.includes("[REQUIRED:")', "|| false")],
  ["M11 terms: 'not investment advice' sentence removed", edit("pages/terms.html", "not investment, trading, legal, accounting or tax advice", "a software tool")],
  ["M12 homepage gains a performance claim", edit("pages/home.html", '<p class="lede">', '<p class="lede">Our traders enjoy guaranteed profit and beat the market every month. ')],
  ["M13 viewport meta removed from every page", edit("scripts/build.mjs", '<meta name="viewport" content="width=device-width, initial-scale=1">', "")],
  ["M14 privacy loses its link to /contact", edit("pages/privacy.html", '<a href="/contact">Contact</a>. To delete', "Contact. To delete")],
  ["M15 site.css route blocked again (writer's original bug)", edit("src/index.ts", 'path !== "/site.css" && ', "")],
  ["M16 contact page loses the support mailto", edit("scripts/build.mjs", '`<a href="mailto:${escape(config.company.support_email)}">${escape(config.company.support_email)}</a>`', "escape(config.company.support_email)")],
];

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.includes("--writer-only")) {
    const w = runSuite(SITE_SRC);
    console.log(`WRITER AS-IS: pass=${w.passed.size} fail=${w.failed.size}`);
    for (const n of [...w.failed].sort()) console.log("  FAIL " + n);
    process.exit(0);
  }
  const baseDir = patchedBaseline();
  const base = runSuite(baseDir);
  console.log(`PATCHED BASELINE: pass=${base.passed.size} fail=${base.failed.size}`);
  for (const n of [...base.failed].sort()) console.log("  (baseline-fail, content/gate finding) " + n);
  let survived = 0;
  for (const [name, mutate] of MUTANTS) {
    const dir = patchedBaseline();
    mutate(dir);
    const res = runSuite(dir);
    const killers = [...base.passed].filter((t) => res.failed.has(t) || !res.passed.has(t));
    console.log(`${killers.length ? "KILLED  " : "SURVIVED"} ${name}${killers.length ? `  <- ${killers.length} test(s), e.g. "${killers[0]}"` : ""}`);
    if (!killers.length) survived++;
    rmSync(dir, { recursive: true, force: true });
  }
  rmSync(baseDir, { recursive: true, force: true });
  console.log(`MUTANTS: ${MUTANTS.length} run, ${MUTANTS.length - survived} killed, ${survived} survived`);
  process.exitCode = survived ? 1 : 0;
}
