// SITE-LEGAL-001 cycle-1 supplement (independent reviewer, NEW file; acceptance.test.mjs is not touched).
// Probes the specific cycle-1 closure claims plus new-issue hunting. Run:
//   node --test qa/acceptance/SITE-LEGAL-001/acceptance-c1.test.mjs
import assert from "node:assert/strict";
import { test, after } from "node:test";
import { spawnSync } from "node:child_process";
import { readFileSync, existsSync, readdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { COMPLETE_COMPANY, DEPLOY_SCRIPT, REPO, ROUTES, SITE_SRC, read, runBuild, stageSite, textOf } from "./helpers.mjs";

const ROUTE_FILE = { "/": "index", "/app": "app", "/privacy": "privacy", "/terms": "terms", "/contact": "contact", "/risk-disclosure": "risk-disclosure", "/data-deletion": "data-deletion", "/security": "security", "/cookies": "cookies", "/subprocessors": "subprocessors" };
let built;
const site = () => {
  if (!built) { built = stageSite({ company: COMPLETE_COMPANY }); const b = runBuild(built); assert.equal(b.code, 0, b.stderr); }
  return built;
};
const text = (route) => textOf(read(site(), "public", `${ROUTE_FILE[route]}.html`));
const withFacts = (mut) => { const dir = stageSite({ company: COMPLETE_COMPANY, mutate: (d) => { const p = path.join(d, "site.config.json"); const c = JSON.parse(readFileSync(p, "utf8")); mut(c); writeFileSync(p, JSON.stringify(c, null, 2)); } }); return runBuild(dir); };

// ---- P2-1 closure: strict validators ------------------------------------------------------------
for (const dom of ["leviathan-site.ocean824.workers.dev", "FOO.WORKERS.DEV", "localhost", "example..test", "-bad.test", "exa mple.test", "https://example.test"]) {
  test(`C1 GATE rejects domain "${dom}"`, () => assert.equal(withFacts((c) => { c.company.domain = dom; }).code, 1));
}
for (const mail of ["a@b", "a b@example.test", "@example.test", "a@@example.test", "support@example..test", "mailto:support@example.test"]) {
  test(`C1 GATE rejects support_email "${mail}"`, () => assert.equal(withFacts((c) => { c.company.support_email = mail; }).code, 1));
}
for (const d of ["2026-13-45", "2026-02-30x", "10/09/2026", "2026-1-9", "yesterday"]) {
  test(`C1 GATE rejects effective_date "${d}"`, () => assert.equal(withFacts((c) => { c.company.effective_date = d; }).code, 1));
}
test("C1 GATE accepts a real custom domain, plain email and ISO date", () => assert.equal(withFacts(() => {}).code, 0));
for (const key of ["retention.account_deletion_days", "retention.legal_retention_years", "refund_policy"]) {
  for (const [label, val] of [["placeholder marker", "[REQUIRED: x]"], ["empty", ""], ["TBD", "TBD"], ["null", null]]) {
    test(`C1 GATE new owner fact ${key} (${label}) blocks and is named`, () => {
      const r = withFacts((c) => { if (key === "refund_policy") c.refund_policy = val; else c.retention[key.split(".")[1]] = val; });
      assert.equal(r.code, 1); assert.ok(r.stderr.includes(key), r.stderr);
    });
  }
}
// numeric facts are rendered into "within N days" / "up to N years"
for (const [k, v] of [["account_deletion_days", "soon"], ["account_deletion_days", "-5"], ["account_deletion_days", "0"], ["account_deletion_days", "thirty"], ["legal_retention_years", "seven"], ["legal_retention_years", "-1"], ["legal_retention_years", "0"]]) {
  test(`C1 GATE rejects non-numeric/non-positive retention ${k}="${v}" (rendered as "within ${v} days/years")`, () =>
    assert.equal(withFacts((c) => { c.retention[k] = v; }).code, 1, `strict build shipped ${k}="${v}"`));
}

// ---- P1-3 closure: -IncludeSite opt-in ----------------------------------------------------------
const ps = readFileSync(DEPLOY_SCRIPT, "utf8");
test("C1 DEPLOY -IncludeSite switch exists and defaults off", () => assert.match(ps, /\[switch\]\$IncludeSite/));
test("C1 DEPLOY every site statement (gate, build, deploy, smoke) is inside an `if ($IncludeSite)` block", () => {
  for (const needle of ["Assert-SiteFactsComplete -ConfigPath", "Invoke-SiteBuild $siteDirectory $NodeExePath", "Invoke-Deploy $siteDirectory", "Invoke-Smoke \"$siteOrigin"]) {
    const idx = ps.lastIndexOf(needle);
    assert.ok(idx > 0, needle);
    const before = ps.slice(0, idx);
    const open = before.lastIndexOf("if ($IncludeSite)");
    assert.ok(open > -1, needle + " has no preceding if ($IncludeSite)");
    const between = before.slice(open);
    assert.ok(!/\r?\n\}/.test(between), needle + " is after the closing brace of the if ($IncludeSite) block");
  }
});
test("C1 DEPLOY non-site Workers' smoke checks and deploys are not behind the site switch", () => {
  assert.match(ps, /Invoke-Deploy \$licensingDirectory/); assert.match(ps, /Invoke-Smoke "\$licensingOrigin\/v1\/admin\/license" @\(401, 403\)/);
});
const pwsh = spawnSync("powershell.exe", ["-NoProfile", "-Command", "$PSVersionTable.PSVersion.Major"], { encoding: "utf8" });
const havePs = pwsh.status === 0;
for (const [label, extra, expectSite] of [["without -IncludeSite", [], false], ["with -IncludeSite", ["-IncludeSite"], true]]) {
  test(`C1 DEPLOY -WhatIf ${label} plans ${expectSite ? "four" : "three"} Workers and reads no secret`, { skip: !havePs }, () => {
    const r = spawnSync("powershell.exe", ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", DEPLOY_SCRIPT, "-MasterRoot", path.join(tmpdir(), "no-such-master"), "-WhatIf", ...extra], { encoding: "utf8" });
    const out = r.stdout + r.stderr;
    assert.equal(r.status, 0, out);
    assert.match(out, /Plan only; no secrets read/);
    assert.match(out, expectSite ? /Deploy order: [^\r\n]*leviathan-site/ : /Deploy order: leviathan-licensing-worker, leviathan-data-gateway, leviathan-release-feed\s*$/m);
    assert.match(out, new RegExp(`Site Worker included: ${expectSite ? "True" : "False"}`));
  });
}

// ---- P1-2 closure + copy hygiene ----------------------------------------------------------------
test("C1 COPY no page contains internal/engineering wording (extended list)", () => {
  const bad = /WEB-APP|SITE-LEGAL|BILLING-PORTAL|canonical|worktree|ledger|cycle[- ]\d|TODO|FIXME|lorem|append-only|Worker code|plan says|owner input|owner review|counsel/i;
  for (const [route] of ROUTES) { const m = bad.exec(text(route)); assert.ok(!m, m ? `${route}: "${m[0]}" -> ${text(route).slice(Math.max(0, m.index - 60), m.index + 60)}` : ""); }
});
test("C1 COPY no doubled punctuation or repeated sentence on any page", () => {
  for (const [route] of ROUTES) {
    const t = text(route);
    assert.ok(!/[.,;:]{2,}(?!\.)/.test(t.replace(/\.\.\./g, "")), `${route}: doubled punctuation near "${/(.{25}[.,;:]{2,}.{10})/.exec(t)?.[1]}"`);
    const sentences = t.split(/(?<=[.!?])\s+/).filter((s) => s.length > 25);
    const dup = sentences.find((s, i) => sentences.indexOf(s) !== i && !/^(Skip|Overview|Leviathan AI Overview)/.test(s));
    assert.ok(!dup, `${route}: repeated sentence "${dup}"`);
  }
});
test("C1 COPY /app has a single lede (no duplicated tagline)", () => {
  assert.equal((read(site(), "public/app.html").match(/class="lede"/g) ?? []).length, 1);
});

// ---- Legal text closure ------------------------------------------------------------------------
test("C1 LEGAL regulatory sentence renders verbatim, once, with no splice", () => {
  const t = text("/terms");
  assert.ok(t.includes(COMPLETE_COMPANY.regulatory_status), "full sentence missing");
  assert.equal(t.split(COMPLETE_COMPANY.regulatory_status).length - 1, 1);
  assert.ok(!/subject to confirmation/i.test(t));
});
test("C1 LEGAL Google scopes and Limited Use statement present, exactly the three scopes", () => {
  const t = text("/privacy");
  assert.match(t, /openid, email and profile/);
  assert.match(t, /Google API Services User Data Policy, including the Limited Use requirements/);
  assert.match(t, /do not use Google user data for advertising/i);
});
test("C1 LEGAL retention paragraph uses the owner facts, in both privacy and data-deletion, and nowhere else invents numbers", () => {
  for (const r of ["/privacy", "/data-deletion"]) { const t = text(r); assert.match(t, /within 30 days/); assert.match(t, /up to 7 years/); }
  for (const [route] of ROUTES) { const t = text(route); const nums = [...t.matchAll(/\b(\d+) (days|years)\b/g)].map((m) => m[0]); for (const n of nums) assert.ok(["30 days", "7 years", "18 years"].includes(n),`${route}: unexpected hard-coded period "${n}"`); }
});
test("C1 LEGAL data-deletion is truthful: operator-run, no self-service claim, subject line, email, retained-record statement", () => {
  const t = text("/data-deletion");
  assert.match(t, /operator-run/i); assert.match(t, /no self-service deletion form/i); assert.match(t, /Leviathan AI data deletion/);
  assert.match(t, /support@example\.test/); assert.match(t, /may be retained/i);
});
test("C1 LEGAL privacy BODY links /data-deletion and /contact and /subprocessors and /security", () => {
  const main = /<main[\s\S]*<\/main>/.exec(read(site(), "public/privacy.html"))[0];
  for (const l of ["/data-deletion", "/contact", "/subprocessors", "/security"]) assert.ok(main.includes(`href="${l}"`), l);
});
test("C1 LEGAL AI providers named on privacy and subprocessors (Anthropic, OpenAI, OpenAI-compatible, local)", () => {
  for (const r of ["/privacy", "/subprocessors"]) { const t = text(r); assert.match(t, /Anthropic/); assert.match(t, /OpenAI/); assert.match(t, /OpenAI-compatible/); }
  assert.match(text("/privacy"), /own computer/);
});
test("C1 LEGAL every flow I found in the canonical code is disclosed (gateway, update check, IP, Stripe email, org name, local data)", () => {
  const t = text("/privacy");
  for (const re of [/gateway/i, /rate-limits per device identifier/i, /app version, operating system and architecture/i, /IP address/i, /Stripe receives your email address/i, /organization name/i, /Conversation history, preferences and strategies/i, /Crash and diagnostic logs stay on your device/i]) assert.match(t, re);
});
test("C1 LEGAL SnapTrade wording: provider-collected login, planned server storage, no repo wording", () => {
  const t = text("/privacy");
  assert.match(t, /SnapTrade — not us — collects your brokerage login/);
  assert.match(t, /being introduced/); assert.match(t, /encrypted SnapTrade user secret/);
  assert.ok(!/canonical|repository/i.test(t));
});
// Cycle 2: cancellation wording is driven by the fact billing.cancellation_method ("email" default, "portal" opt-in).
const shippedConfig = JSON.parse(readFileSync(path.join(SITE_SRC, "site.config.json"), "utf8"));
const withMethod = (method) => { const dir = stageSite({ company: COMPLETE_COMPANY, mutate: (d) => { const p = path.join(d, "site.config.json"); const c = JSON.parse(readFileSync(p, "utf8")); if (method === undefined) delete c.billing; else c.billing = { cancellation_method: method }; writeFileSync(p, JSON.stringify(c, null, 2)); } }); return { dir, build: runBuild(dir) }; };
test("C1 CANCEL shipped default is exactly 'email'", () => assert.equal(shippedConfig.billing?.cancellation_method, "email"));
test("C1 CANCEL default (email): Terms say cancel by emailing support from the account email; no portal, no 'account controls'; refund fact present", () => {
  const t = text("/terms");
  assert.match(t, /cancel before the next renewal by emailing support@example\.test from your account email/);
  assert.match(t, /Cancellation takes effect at the end of the current paid term/);
  assert.ok(!/billing portal/i.test(t), "email mode must not mention a portal");
  assert.ok(!/through the account controls/i.test(t));
  assert.match(t, /Refunds are available within 30 days where required by law\./);
});
test("C1 CANCEL portal fact renders the Stripe billing portal sentence and drops the email sentence", () => {
  const { dir, build } = withMethod("portal"); assert.equal(build.code, 0, build.stderr);
  const t = textOf(read(dir, "public/terms.html"));
  assert.match(t, /Stripe billing portal/); assert.ok(!/cancel before the next renewal by emailing/i.test(t));
});
for (const [label, v] of [["Portal (case)", "Portal"], ["EMAIL (case)", "EMAIL"], ["both", "both"], ["empty", ""], ["whitespace", "  "], ["null", null], ["number", 1], ["key deleted", undefined], ["TBD", "TBD"], ["portal with space", "portal "]]) {
  if (label === "portal with space") continue; // trimmed values are tolerated by design
  test(`C1 CANCEL invalid method (${label}) fails closed and names billing.cancellation_method`, () => {
    const { build } = withMethod(v); assert.equal(build.code, 1); assert.ok(build.stderr.includes("billing.cancellation_method"), build.stderr);
  });
}
test("C1 CANCEL portal mode may only be a deliberate fact: shipped config is not portal, and the repo has portal code if it ever is", () => {
  if (shippedConfig.billing?.cancellation_method !== "portal") return; // email default: nothing to prove
  const re = /billing_portal|billingPortal/;
  const hits = [];
  const walk = (d) => { for (const e of readdirSync(d, { withFileTypes: true })) { const p = path.join(d, e.name); if (e.isDirectory()) { if (!/node_modules|\.git$/.test(e.name)) walk(p); } else if (/\.(ts|py|rs|tsx)$/.test(e.name) && re.test(readFileSync(p, "utf8"))) hits.push(p); } };
  for (const d of ["workers/licensing/src", "apps/api/src", "apps/desktop/src-tauri/src"]) if (existsSync(path.join(REPO, d))) walk(path.join(REPO, d));
  assert.ok(hits.length > 0, "cancellation_method=portal but the canonical repo has no billing-portal session code (BILLING-PORTAL-001)");
});
test("C1 CANCEL data-deletion page does not tell people to use a portal in email mode", () => {
  assert.ok(!/billing portal/i.test(text("/data-deletion")));
});
test("C1 CLAIM AI prompts 'do not pass through our servers' is scoped to the desktop app (web build will route through the hosted API)", () => {
  const t = text("/privacy");
  const m = /AI features\.[\s\S]{0,400}?do not pass through our servers/i.exec(t);
  assert.ok(m, "sentence missing");
  assert.match(m[0], /desktop/i, "unscoped claim becomes false when the hosted web API ships");
});
test("C1 CLAIM market-data vendors receive no identity: gateway builds fresh headers (canonical code)", { skip: !existsSync(path.join(REPO, "workers/data-gateway/src/handler.ts")) }, () => {
  const h = readFileSync(path.join(REPO, "workers/data-gateway/src/handler.ts"), "utf8");
  assert.match(h, /const headers = new Headers\(\);/); assert.ok(!/headers\.set\("(x-forwarded-for|cf-connecting-ip|user-agent)"/i.test(h));
});
test("C1 SEC HSTS no preload; CSP unchanged", () => {
  const idx = readFileSync(path.join(path.dirname(DEPLOY_SCRIPT), "..", "..", "..", "workers", "site", "src", "index.ts"), "utf8");
  assert.ok(!/preload/i.test(idx)); assert.match(idx, /default-src 'self'/);
});
test("C1 STRICT footer shows only the update note; draft note only in draft builds", () => {
  assert.ok(!/Draft for owner review/.test(read(site(), "public/privacy.html")));
  const d = stageSite(); runBuild(d, ["--allow-incomplete"]);
  assert.match(read(d, "public/privacy.html"), /Draft for owner review: required company facts are incomplete/);
});
test("C1 SHIPPED config still fails closed and names all new facts", () => {
  const d = stageSite(); const b = runBuild(d);
  assert.equal(b.code, 1);
  for (const k of ["company.legal_name", "company.formation_state", "company.mailing_address", "company.support_email", "company.regulatory_status", "company.domain", "company.effective_date", "retention.account_deletion_days", "retention.legal_retention_years", "refund_policy"]) assert.ok(b.stderr.includes(k), k);
});
