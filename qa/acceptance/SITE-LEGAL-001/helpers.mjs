// SITE-LEGAL-001 independent acceptance helpers (reviewer-owned; the writer's files are never modified).
// Every test stages a COPY of the site into a temp dir, so nothing in the worktree is written.
import { spawn, spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
export const SITE_SRC = path.resolve(process.env.SITE_ROOT ?? path.join(here, "..", "..", "..", "workers", "site"));
export const REPO = process.env.CANONICAL_REPO
  ? path.resolve(process.env.CANONICAL_REPO)
  : path.resolve(here, "..", "..", "..", "..", "..", "repo");
export const DEPLOY_SCRIPT = process.env.DEPLOY_SCRIPT
  ?? path.resolve(here, "..", "..", "..", "infra", "release", "cloudflare", "Deploy-LeviathanWorkers.ps1");

const STAGED = [];
process.on("exit", () => { for (const d of STAGED) { try { rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ } } });

export const ROUTES = [
  ["/", "Trading and analysis platform | Leviathan AI"],
  ["/app", "Web app coming soon | Leviathan AI"],
  ["/privacy", "Privacy policy | Leviathan AI"],
  ["/terms", "Terms of service | Leviathan AI"],
  ["/contact", "Contact | Leviathan AI"],
  ["/risk-disclosure", "Trading risk disclosure | Leviathan AI"],
  ["/data-deletion", "Data deletion | Leviathan AI"],
  ["/security", "Security | Leviathan AI"],
  ["/cookies", "Cookies | Leviathan AI"],
  ["/subprocessors", "Subprocessors | Leviathan AI"],
];

// Obviously fake test values. They only ever exist inside a temp copy.
export const COMPLETE_COMPANY = {
  legal_name: { value: "Lossless Holdings, LLC", owner_confirmation_required: false },
  formation_state: "Delaware",
  mailing_address: "100 Example Test Road, Testville, DE 19999",
  support_email: "support@example.test",
  regulatory_status: "Lossless Holdings, LLC is not registered as a broker-dealer or investment adviser.",
  web_backend_host: "Cloudflare Containers",
  domain: "example.test",
  effective_date: "2026-10-09",
};
export const FACT_KEYS = Object.keys(COMPLETE_COMPANY);

export function stageSite({ company, mutate } = {}) {
  const dir = mkdtempSync(path.join(tmpdir(), "site-legal-001-"));
  STAGED.push(dir);
  cpSync(SITE_SRC, dir, {
    recursive: true,
    filter: (src) => !/[\\/](node_modules|public|\.wrangler)([\\/]|$)/.test(src.slice(SITE_SRC.length)),
  });
  if (company) {
    const cfgPath = path.join(dir, "site.config.json");
    const cfg = JSON.parse(readFileSync(cfgPath, "utf8"));
    cfg.company = typeof company === "function" ? company(structuredClone(COMPLETE_COMPANY)) : company;
    // Temporary test-only decisions satisfy the newly required fact gate; never copied to the product config.
    cfg.retention = { account_deletion_days: "30", legal_retention_years: "7" };
    cfg.refund_policy = "Refunds are available within 30 days where required by law.";
    writeFileSync(cfgPath, JSON.stringify(cfg, null, 2));
  }
  if (mutate) mutate(dir);
  return dir;
}

export function runBuild(dir, args = []) {
  const r = spawnSync(process.execPath, ["scripts/build.mjs", ...args], { cwd: dir, encoding: "utf8" });
  return { code: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
}

export function read(dir, ...parts) { return readFileSync(path.join(dir, ...parts), "utf8"); }
export function exists(dir, ...parts) { return existsSync(path.join(dir, ...parts)); }
export function write(dir, rel, text) { mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true }); writeFileSync(path.join(dir, rel), text); }

export function textOf(html) {
  return html
    .replace(/<(script|style)[\s\S]*?<\/\1>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"').replace(/&#39;/g, "'")
    .replace(/\s+/g, " ").trim();
}

function findWrangler() {
  const candidates = [
    process.env.SITE_ACCEPT_WRANGLER_JS,
    path.join(SITE_SRC, "node_modules", "wrangler", "bin", "wrangler.js"),
  ].filter(Boolean);
  return candidates.find((p) => existsSync(p));
}

function freePort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.listen(0, "127.0.0.1", () => { const { port } = s.address(); s.close(() => resolve(port)); });
    s.on("error", reject);
  });
}

/** Builds with complete facts, then runs the REAL Workers runtime (wrangler dev --local, workerd + Static Assets). */
export async function startRuntime(dir) {
  const wrangler = findWrangler();
  if (!wrangler) throw new Error("WRANGLER_REQUIRED: set SITE_ACCEPT_WRANGLER_JS to wrangler/bin/wrangler.js (fail closed, no mock fallback)");
  const built = runBuild(dir);
  if (built.code !== 0) throw new Error(`strict build failed with complete facts: ${built.stderr}`);
  const port = await freePort();
  const child = spawn(process.execPath, [wrangler, "dev", "--local", "--ip", "127.0.0.1", "--port", String(port)], {
    cwd: dir, env: { ...process.env, CI: "1", WRANGLER_SEND_METRICS: "false", NO_COLOR: "1" }, stdio: ["ignore", "pipe", "pipe"],
  });
  let log = "";
  child.stdout.on("data", (d) => { log += d; });
  child.stderr.on("data", (d) => { log += d; });
  const base = `http://127.0.0.1:${port}`;
  const deadline = Date.now() + 120_000;
  let ready = false;
  while (Date.now() < deadline && child.exitCode === null) {
    try { await fetch(base + "/", { redirect: "manual" }); ready = true; break; } catch { await new Promise((r) => setTimeout(r, 500)); }
  }
  const stop = () => {
    if (child.exitCode === null) {
      if (process.platform === "win32") spawnSync("taskkill", ["/pid", String(child.pid), "/T", "/F"]);
      else child.kill("SIGKILL");
    }
    rmSync(dir, { recursive: true, force: true });
  };
  if (!ready) { stop(); throw new Error(`runtime did not start: ${log.slice(-800)}`); }
  return { base, stop, log: () => log };
}

// Retry only transport errors (a keep-alive socket reset while spawnSync blocked the event loop); HTTP statuses are never retried.
export async function get(base, p, init = {}) {
  let last;
  for (let i = 0; i < 3; i++) {
    try { return await fetch(base + p, { redirect: "manual", headers: { connection: "close" }, ...init }); } catch (e) { last = e; await new Promise((r) => setTimeout(r, 300)); }
  }
  throw last;
}
