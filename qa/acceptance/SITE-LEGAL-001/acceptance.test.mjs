// SITE-LEGAL-001 acceptance suite (independent reviewer). Run:  node --test qa/acceptance/SITE-LEGAL-001/acceptance.test.mjs
// Needs wrangler for the real-runtime tests: set SITE_ACCEPT_WRANGLER_JS=<...>/wrangler/bin/wrangler.js (no mock fallback).
// Test titles are prefixed with a group tag: ROUTE, HDR, 3P, LINK, GATE, MOBILE, LEGAL, ACC, CLAIM.
import assert from "node:assert/strict";
import { after, test } from "node:test";
import { readFileSync, existsSync, readdirSync } from "node:fs";
import path from "node:path";
import {
  COMPLETE_COMPANY, DEPLOY_SCRIPT, FACT_KEYS, REPO, ROUTES, get, read, exists, runBuild, stageSite, startRuntime, textOf, write,
} from "./helpers.mjs";

// ---- one shared real runtime for all HTTP tests ------------------------------------------------
let runtimePromise;
const runtime = () => (runtimePromise ??= startRuntime(stageSite({ company: COMPLETE_COMPANY })));
after(async () => { if (runtimePromise) { try { (await runtimePromise).stop(); } catch { /* start failed */ } } });

const pageCache = new Map();
async function page(route) {
  if (!pageCache.has(route)) {
    const { base } = await runtime();
    const r = await get(base, route);
    pageCache.set(route, { status: r.status, headers: r.headers, html: await r.text() });
  }
  return pageCache.get(route);
}
const allText = async () => (await Promise.all(ROUTES.map(([r]) => page(r)))).map((p) => textOf(p.html));
const textFor = async (route) => textOf((await page(route)).html);

// ============ ROUTE: every route 200 + exact title, unknown 404 =====================================
for (const [route, title] of ROUTES) {
  test(`ROUTE ${route} returns 200 (no redirect) with exact title`, async () => {
    const p = await page(route);
    assert.equal(p.status, 200, `expected 200 got ${p.status} (a 3xx here means a redirect loop through the ASSETS binding)`);
    assert.match(p.headers.get("content-type") ?? "", /^text\/html/);
    assert.ok(p.html.includes(`<title>${title}</title>`), `title mismatch for ${route}`);
    assert.match(p.html, /<html lang="en">/);
    assert.match(p.html, /<meta name="viewport" content="width=device-width, initial-scale=1">/);
  });
}
for (const bad of ["/nope", "/admin", "/.env", "/privacy.html", "/index.html", "/privacy/../secret", "/PRIVACY-POLICY", "/robots.txt-nonexistent"]) {
  test(`ROUTE unknown ${bad} returns 404`, async () => {
    const { base } = await runtime();
    const r = await get(base, bad);
    assert.equal(r.status, 404);
    assert.ok(!(await r.text()).includes("<title>Privacy"), "404 must not leak a real page");
  });
}
test("ROUTE trailing slash is tolerated or redirected, never 5xx or a loop", async () => {
  const { base } = await runtime();
  const r = await get(base, "/privacy/");
  assert.ok([200, 301, 308].includes(r.status), `status ${r.status}`);
});
test("ROUTE HEAD ok; POST/PUT/DELETE rejected 405 with Allow", async () => {
  const { base } = await runtime();
  assert.equal((await get(base, "/terms", { method: "HEAD" })).status, 200);
  for (const method of ["POST", "PUT", "DELETE", "PATCH"]) {
    const r = await get(base, "/terms", { method, body: method === "DELETE" ? undefined : "x" });
    assert.equal(r.status, 405, method);
    assert.match(r.headers.get("allow") ?? "", /GET/);
  }
});
test("ROUTE stylesheet /site.css is served 200 text/css (pages are unstyled without it)", async () => {
  const { base } = await runtime();
  const r = await get(base, "/site.css");
  assert.equal(r.status, 200, `got ${r.status}; every page links /site.css`);
  assert.match(r.headers.get("content-type") ?? "", /css/);
});
test("ROUTE no server error or cookie on any route", async () => {
  for (const [route] of ROUTES) assert.equal((await page(route)).headers.get("set-cookie"), null, route);
});

// ============ HDR: security headers on pages, assets, 404 and 405 ===================================
const HEADER_TARGETS = [...ROUTES.map(([r]) => r), "/site.css", "/definitely-missing"];
for (const route of HEADER_TARGETS) {
  test(`HDR ${route} carries CSP default-src 'self', HSTS, nosniff, Referrer-Policy, framing denial`, async () => {
    const { base } = await runtime();
    const r = await get(base, route);
    const csp = r.headers.get("content-security-policy") ?? "";
    assert.match(csp, /(^|;\s*)default-src 'self'(;|$)/, "CSP default-src 'self'");
    assert.ok(!/unsafe-inline|unsafe-eval|\*|http:|data:\s*;?\s*$/.test(csp.replace(/img-src[^;]*/, "")), `CSP too loose: ${csp}`);
    assert.match(csp, /frame-ancestors 'none'/);
    assert.match(csp, /object-src 'none'/);
    const hsts = r.headers.get("strict-transport-security") ?? "";
    const maxAge = Number(/max-age=(\d+)/.exec(hsts)?.[1] ?? 0);
    assert.ok(maxAge >= 15552000, `HSTS max-age ${maxAge}`);
    assert.equal(r.headers.get("x-content-type-options"), "nosniff");
    const rp = r.headers.get("referrer-policy") ?? "";
    assert.ok(["no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin", "origin", "origin-when-cross-origin"].includes(rp), `Referrer-Policy '${rp}'`);
    assert.equal(r.headers.get("x-frame-options"), "DENY");
  });
}
test("HDR 405 response also carries the security headers", async () => {
  const { base } = await runtime();
  const r = await get(base, "/", { method: "POST", body: "x" });
  assert.equal(r.status, 405);
  assert.match(r.headers.get("content-security-policy") ?? "", /default-src 'self'/);
  assert.match(r.headers.get("strict-transport-security") ?? "", /max-age=/);
});

// ============ 3P: no third-party scripts/trackers/embeds ============================================
const TRACKERS = /google-analytics|googletagmanager|gtag\(|doubleclick|facebook\.net|fbq\(|hotjar|segment\.(io|com)|mixpanel|amplitude|clarity\.ms|plausible\.io|posthog|sentry|cloudflareinsights|fullstory|intercom|hubspot|adsbygoogle|fonts\.googleapis|fonts\.gstatic|cdn\./i;
for (const [route] of ROUTES) {
  test(`3P ${route} has no script, inline handler, inline style, iframe, external asset or tracker`, async () => {
    const { html } = await page(route);
    assert.ok(!/<script\b/i.test(html), "script tag");
    assert.ok(!/\son[a-z]+\s*=/i.test(html), "inline event handler");
    assert.ok(!/\sstyle\s*=/i.test(html), "inline style attribute (blocked by CSP style-src 'self')");
    assert.ok(!/<(iframe|embed|object|form|img|video|audio|link rel="(?!stylesheet)[^"]*")\b/i.test(html), "embedded/third-party element");
    assert.ok(!TRACKERS.test(html), "tracker string");
    const external = [...html.matchAll(/\b(?:src|href|action)="(https?:)?\/\/[^"]+"/gi)].map((m) => m[0]);
    assert.deepEqual(external, [], "absolute external URL");
  });
}
test("3P stylesheet has no remote @import/url()", async () => {
  const { base } = await runtime();
  const css = await (await get(base, "/site.css")).text();
  assert.ok(css.length > 200, "css must actually be served");
  assert.ok(!/@import|url\(\s*['"]?(https?:)?\/\//i.test(css));
});
test("3P no response sets a cookie or links a Link header to a third party", async () => {
  for (const [route] of ROUTES) {
    const p = await page(route);
    assert.equal(p.headers.get("set-cookie"), null);
    assert.ok(!/https?:\/\//.test(p.headers.get("link") ?? ""));
  }
});

// ============ LINK: internal links resolve over real HTTP ===========================================
test("LINK every internal href/src on every page resolves to 200 over HTTP; every page links every other page", async () => {
  const { base } = await runtime();
  const seen = new Set();
  const failures = [];
  for (const [route] of ROUTES) {
    const { html } = await page(route);
    const hrefs = [...html.matchAll(/\b(?:href|src)="([^"]+)"/g)].map((m) => m[1]);
    for (const h of hrefs) {
      if (h.startsWith("mailto:")) continue;
      if (h.startsWith("#")) { assert.ok(new RegExp(`id="${h.slice(1)}"`).test(html), `${route}: missing anchor ${h}`); continue; }
      assert.ok(h.startsWith("/"), `${route}: non-root-relative link ${h}`);
      if (seen.has(h)) continue;
      seen.add(h);
      const r = await get(base, h);
      if (r.status !== 200) failures.push(`${route} -> ${h} = ${r.status}`);
    }
    for (const [other] of ROUTES) assert.ok(html.includes(`href="${other}"`), `${route} lacks nav link to ${other}`);
  }
  assert.deepEqual(failures, []);
});
test("LINK privacy, terms, contact and data-deletion are linked from the homepage footer/nav (Google homepage requirement)", async () => {
  const { html } = await page("/");
  for (const r of ["/privacy", "/terms", "/contact", "/data-deletion"]) assert.ok(html.includes(`href="${r}"`), r);
});
const mainOf = (html) => /<main[\s\S]*<\/main>/.exec(html)?.[0] ?? "";
test("LINK privacy policy BODY (not just the site nav) links the deletion route (/data-deletion)", async () => {
  assert.match(mainOf((await page("/privacy")).html), /href="\/data-deletion"/, "privacy must link the deletion route");
});
test("LINK privacy policy BODY links /contact; contact page exposes a mailto link and the address", async () => {
  assert.match(mainOf((await page("/privacy")).html), /href="\/contact"/);
  const c = (await page("/contact")).html;
  assert.match(c, /href="mailto:support@example\.test"/);
  assert.ok(c.includes(COMPLETE_COMPANY.mailing_address));
});

// ============ GATE: facts gate fails closed =========================================================
test("GATE shipped config fails strict build with SITE_FACTS_INCOMPLETE, exit 1, and removes stale public/", () => {
  const dir = stageSite();
  write(dir, "public/index.html", "stale");
  const b = runBuild(dir);
  assert.equal(b.code, 1);
  assert.match(b.stderr, /SITE_FACTS_INCOMPLETE/);
  for (const k of FACT_KEYS) {
    if (k === "web_backend_host") assert.ok(!b.stderr.includes(`company.${k}`), "owner supplied the container host");
    else assert.ok(b.stderr.includes(`company.${k}`), `gate must name company.${k}`);
  }
  for (const k of ["retention.account_deletion_days", "retention.legal_retention_years", "refund_policy"])
    assert.ok(b.stderr.includes(k), `gate must name ${k}`);
  assert.ok(!exists(dir, "public"), "stale public output must be removed");
});
for (const key of FACT_KEYS) {
  for (const [label, mutateFact] of [
    ["placeholder marker", (c) => { c[key] = key === "legal_name" ? { value: "[REQUIRED: x]", owner_confirmation_required: false } : "[REQUIRED: fill me]"; }],
    ["empty string", (c) => { c[key] = key === "legal_name" ? { value: "", owner_confirmation_required: false } : ""; }],
    ["whitespace only", (c) => { c[key] = key === "legal_name" ? { value: "   ", owner_confirmation_required: false } : "   "; }],
    ["key deleted", (c) => { delete c[key]; }],
    ["wrong type (null)", (c) => { c[key] = null; }],
  ]) {
    test(`GATE missing ${key} (${label}) blocks the strict build`, () => {
      const dir = stageSite({ company: (c) => { mutateFact(c); return c; } });
      const b = runBuild(dir);
      assert.equal(b.code, 1, b.stdout + b.stderr);
      assert.match(b.stderr, /SITE_FACTS_INCOMPLETE/);
      assert.ok(b.stderr.includes(`company.${key}`));
      assert.ok(!exists(dir, "public"), "no public output on gate failure");
    });
  }
}
test("GATE legal name still awaiting owner confirmation blocks the build", () => {
  const dir = stageSite({ company: (c) => { c.legal_name.owner_confirmation_required = true; return c; } });
  const b = runBuild(dir);
  assert.equal(b.code, 1);
  assert.match(b.stderr, /company\.legal_name/);
});
test("GATE legal_name given as a bare string (schema drift) fails closed", () => {
  const dir = stageSite({ company: (c) => { c.legal_name = "Lossless Holdings, LLC"; return c; } });
  assert.equal(runBuild(dir).code, 1);
});
test("GATE complete facts build exits 0, emits 10 pages, no placeholders, stale files cleared", () => {
  const dir = stageSite({ company: COMPLETE_COMPANY });
  write(dir, "public/stale.html", "old");
  const b = runBuild(dir);
  assert.equal(b.code, 0, b.stderr);
  assert.ok(!exists(dir, "public/stale.html"));
  for (const f of ["index", "app", "privacy", "terms", "contact", "risk-disclosure", "data-deletion", "security", "cookies", "subprocessors"]) {
    const html = read(dir, "public", `${f}.html`);
    assert.ok(!/\[REQUIRED|\{\{|fact-missing/.test(html), `${f}: placeholder leaked`);
  }
});
// Hole probes: the gate only recognises the literal "[REQUIRED:" marker. A value like TBD must not ship.
for (const [key, bad] of [
  ["support_email", "TBD"], ["support_email", "not-an-email"], ["support_email", "support@"],
  ["effective_date", "soon"], ["effective_date", "TBD"], ["domain", "TBD"], ["domain", "http://"],
  ["mailing_address", "N/A"], ["formation_state", "TODO"], ["regulatory_status", "tbd"], ["web_backend_host", "TBD"],
]) {
  test(`GATE rejects non-factual value ${key}="${bad}" (not only the [REQUIRED:] marker)`, () => {
    const dir = stageSite({ company: (c) => { c[key] = bad; return c; } });
    const b = runBuild(dir);
    assert.equal(b.code, 1, `strict build shipped ${key}="${bad}"`);
  });
}
test("GATE draft mode never produces output that looks production-ready (warns SITE_FACTS_INCOMPLETE)", () => {
  const dir = stageSite();
  const b = runBuild(dir, ["--allow-incomplete"]);
  assert.equal(b.code, 0);
  assert.match(b.stderr + b.stdout, /SITE_FACTS_INCOMPLETE/);
  assert.match(read(dir, "public/privacy.html"), /fact-missing/, "placeholders must be visibly marked in draft output");
});
test("GATE deploy script runs the facts gate before any secret read or Worker deploy, and smoke-checks every route title", () => {
  const ps = readFileSync(DEPLOY_SCRIPT, "utf8");
  const gate = ps.indexOf("Assert-SiteFactsComplete -ConfigPath");
  assert.ok(gate > 0, "gate call missing");
  assert.ok(ps.indexOf("= Read-LiveRuntimeKeysetValues") > gate, "gate must precede secret reads");
  assert.ok(ps.indexOf("Invoke-Deploy $siteDirectory") > gate, "gate must precede site deploy");
  assert.ok(ps.indexOf("Invoke-SiteBuild $siteDirectory") > gate);
  assert.match(ps, /\$siteWorker\s*=\s*'leviathan-site'/);
  for (const [route, title] of ROUTES) assert.ok(ps.includes("Path = '" + route + "'") && ps.includes(title), "smoke entry " + route);
});

// ============ MOBILE: phone width (static CSS proof; browser measurement is recorded in the verdict) ====
test("MOBILE every page has the viewport meta; CSS has no fixed width wider than a 320px phone", async () => {
  const { base } = await runtime();
  for (const [route] of ROUTES) assert.match((await page(route)).html, /name="viewport" content="width=device-width, initial-scale=1"/, route);
  const css = await (await get(base, "/site.css")).text();
  assert.match(css, /box-sizing:\s*border-box/);
  for (const m of css.matchAll(/(?<![-\w])(?:min-)?width:\s*(\d+)px/g)) assert.ok(Number(m[1]) <= 320, `fixed width ${m[0]}`);
  assert.match(css, /width:\s*min\(100% - 32px/, "16px side gutters via min()");
  assert.match(css, /flex-wrap:\s*wrap/, "nav wraps");
  assert.match(css, /minmax\(min\(100%,/, "cards grid cannot exceed the container");
});
test("MOBILE no pre/table/long unbreakable block that forces horizontal scroll", async () => {
  for (const [route] of ROUTES) assert.ok(!/<(pre|table|textarea)\b/i.test((await page(route)).html), route);
});

// ============ LEGAL: completeness for SnapTrade / Google reviewers ==================================
const has = (text, re, msg) => assert.match(text, re, msg);
test("LEGAL privacy policy: identity, data categories, rights, deletion route, contact, no-sale, minors, retention, transfers", async () => {
  const t = await textFor("/privacy");
  has(t, /Lossless Holdings, LLC/); has(t, /Delaware/); has(t, /100 Example Test Road/);
  has(t, /support@example\.test/);
  has(t, /access, correction, deletion, portability/i);
  has(t, /do not sell personal information/i);
  has(t, /18 or older/i);
  has(t, /Retention/);
  has(t, /International transfers/i);
  has(t, /Stripe/); has(t, /DPAPI/); has(t, /Keychain/); has(t, /SnapTrade/);
  const sub = await textFor("/subprocessors"); for (const p of ["Cloudflare", "Neon", "Stripe", "Google", "SnapTrade", "Databento", "Massive", "Unusual Whales"]) has(sub, new RegExp(p));
});
test("LEGAL privacy policy tells people where to delete: points to the Data deletion page by name", async () => {
  const body = textOf(mainOf((await page("/privacy")).html));
  has(body, /Data deletion|delete your (?:account|data)/i, "policy body must tell people how to delete");
});
test("LEGAL privacy policy contains the Google API Services User Data Policy / Limited Use statement (Google OAuth verification)", async () => {
  has(await textFor("/privacy"), /Google API Services User Data Policy[\s\S]{0,200}Limited Use/i);
});
test("LEGAL privacy policy names the right to complain to a supervisory authority and a contact for privacy requests", async () => {
  has(await textFor("/privacy"), /supervisory authority|data[- ]protection authority/i);
});
test("LEGAL privacy policy discloses the market-data gateway and update check (device id / version / IP metadata)", async () => {
  const t = await textFor("/privacy");
  has(t, /gateway/i, "data gateway Worker verifies device tokens and rate-limits per device id");
});
test("LEGAL privacy policy names the AI providers supported by the vault (Anthropic, OpenAI, OpenAI-compatible)", async () => {
  const t = await textFor("/privacy") + await textFor("/subprocessors");
  has(t, /Anthropic/); has(t, /OpenAI/);
});
test("LEGAL privacy policy states what Stripe receives (email, order metadata) not just that cards go to Stripe", async () => {
  has(await textFor("/privacy"), /Stripe[\s\S]{0,400}(email address|customer email)/i);
});
test("LEGAL terms cover: license, subscription auto-renewal, cancellation, refunds, not advice, not broker-dealer/adviser, automation, risk, third parties, outages, prohibited use, IP, disclaimer, liability cap, indemnity, termination, governing law, changes, contact", async () => {
  const t = await textFor("/terms");
  for (const re of [/non-transferable/i, /renew automatically/i, /cancel/i, /refund/i, /not investment, trading, legal, accounting or tax advice/i,
    /not a broker-dealer or investment adviser|not registered as a broker-dealer or investment adviser/i, /Full-auto/i, /Semi-automatic/i, /total loss/i,
    /Third-party services/i, /outages/i, /Prohibited use/i, /Intellectual property/i, /as is/i, /will not exceed/i, /indemnify/i,
    /terminate/i, /Governing law/i, /governed by the laws of Delaware/i, /Changes and contact/i]) has(t, re);
});
test("LEGAL terms: broker-dealer/adviser sentence is a clean standalone statement (not spliced with the fact string)", async () => {
  const t = await textFor("/terms");
  assert.ok(!/subject to confirmation of the company's regulatory status at/i.test(t), "garbled splice of REGULATORY_STATUS into prose");
});
test("LEGAL contact page: email, mailing address, company name, no-credentials warning", async () => {
  const t = await textFor("/contact");
  has(t, /support@example\.test/); has(t, /100 Example Test Road/); has(t, /Lossless Holdings, LLC/); has(t, /Do not send passwords/i);
});
test("LEGAL data-deletion page: steps, email route, timeline, retained-data statement, Google revoke, subject line", async () => {
  const t = await textFor("/data-deletion");
  has(t, /support@example\.test/); has(t, /30 days/); has(t, /Leviathan AI data deletion/); has(t, /revoke/i); has(t, /retained/i);
});
test("LEGAL risk disclosure: loss, leverage, crypto, prediction markets, automation, AI limits, not advice", async () => {
  const t = await textFor("/risk-disclosure");
  for (const re of [/loss of your entire investment/i, /Leverage/i, /Cryptoassets/i, /Prediction markets/i, /Automation/i, /AI responses/i, /not investment, legal or tax advice/i, /funds you can afford to lose/i]) has(t, re);
});
test("LEGAL homepage carries a visible no-returns-promise and risk link", async () => {
  const t = await textFor("/");
  has(t, /does not promise returns or trading performance/i);
  assert.match((await page("/")).html, /href="\/risk-disclosure"/);
});
test("LEGAL no performance claims, guarantees or hype anywhere", async () => {
  const banned = /\b(guarantee[sd]? (?:profit|return|income|result)s?|risk[- ]free|beat(?:s|ing)? the market|outperform\w*|passive income|get rich|double your|\d+\s?%\s+(?:return|gain|profit|win)|win[- ]?rate|proven (?:strategy|results)|consistent(?:ly)? profit\w*|maximi[sz]e (?:your )?(?:profit|return)s?|never lose|can'?t lose)\b/i;
  for (const [route] of ROUTES) {
    const sentences = (await textFor(route)).split(/(?<=[.!?])\s+/);
    for (const s of sentences) if (banned.test(s)) assert.fail(`${route}: performance claim: ${s}`);
  }
});
test("LEGAL sentences that mention returns/profit are negations or risk warnings only", async () => {
  const claim = /\b(profit(?:s|able|ability)?|returns?|earn(?:s|ings)?|gains?|alpha|edge)\b/i;
  const ok = /\b(not|no|never|cannot|can't|loss|lose|losses|risk|amplify|guarantee|past|promise|may|might|could|without|unless|omit|history|historical|nor|neither)\b/i;
  for (const [route] of ROUTES) for (const s of (await textFor(route)).split(/(?<=[.!?])\s+/)) if (claim.test(s) && !ok.test(s)) assert.fail(`${route}: unqualified claim: ${s}`);
});

// ============ ACC: public copy hygiene (what a reviewer would see) ==================================
test("ACC no internal ticket ids, repo jargon or engineering status on any public page", async () => {
  const jargon = /WEB-APP-\d+|SITE-LEGAL|canonical (?:repository|licensing|repo)|current canonical|Worker code|persistence (?:and|code)|in the current|not (?:yet )?implemented in/i;
  for (const [route] of ROUTES) { const t = await textFor(route); const m = jargon.exec(t); assert.ok(!m, `${route}: internal wording "${m?.[0]}"`); }
});
test("ACC production pages carry no draft/owner-action banner or counsel-review note when facts are complete", async () => {
  const draft = /Draft for owner review|have not been reviewed by counsel|owner input|must be completed before publication|must be published before this route|facts remain marked as required|not yet ready for public launch/i;
  for (const [route] of ROUTES) { const t = await textFor(route); const m = draft.exec(t); assert.ok(!m, `${route}: "${m?.[0]}"`); }
});
test("ACC no mojibake or replacement characters", async () => {
  for (const [route] of ROUTES) assert.ok(!/[ÂÃ�]/.test((await page(route)).html), route);
});
test("ACC every page shows a Last updated date and a copyright line with the legal name", async () => {
  for (const [route] of ROUTES) { const t = await textFor(route); has(t, /Last updated: 20\d\d-\d\d-\d\d/); has(t, /© 20\d\d Lossless Holdings, LLC/); }
});
test("ACC html is well-formed enough: one h1 and one main per page, landmark nav labels", async () => {
  for (const [route] of ROUTES) {
    const { html } = await page(route);
    assert.equal((html.match(/<h1\b/g) ?? []).length, 1, route);
    assert.equal((html.match(/<main\b/g) ?? []).length, 1, route);
    assert.match(html, /aria-label="Main navigation"/);
  }
});
test("ACC /app is honest: says coming soon, has no sign-in form or script", async () => {
  const { html } = await page("/app");
  assert.match(textOf(html), /coming soon/i);
  assert.ok(!/<form|<input|type="password"/i.test(html));
});

// ============ CLAIM: copy is tied to the canonical code (read-only) =================================
const repoFile = (...p) => path.join(REPO, ...p);
const canonical = existsSync(repoFile("workers", "licensing", "migrations", "003_signup_admin.sql"));
test("CLAIM canonical repo is readable for fact checks", () => assert.ok(canonical, `REPO=${REPO}`));
test("CLAIM licensing schema matches the policy's data list (and has no app-version column)", { skip: !canonical }, () => {
  const sql = ["001_subscription.sql", "002_no_trial.sql", "003_signup_admin.sql"].map((f) => readFileSync(repoFile("workers", "licensing", "migrations", f), "utf8")).join("\n");
  for (const col of ["password_hash_pbkdf2", "totp_secret_ciphertext", "failed_login_count", "token_digest", "stripe_customer_id", "stripe_session_id", "device_id", "last_seen_at_utc_ns", "owner_email", "display_name"]) assert.ok(sql.includes(col), col);
  assert.ok(!/app_version/i.test(sql), "policy says there is no app-version field");
  assert.ok(!/card|pan\b|cvc/i.test(sql.replace(/discard|scard/gi, "")), "no card data columns");
});
test("CLAIM credentials vault uses DPAPI on Windows and Keychain on macOS", { skip: !canonical }, () => {
  const py = readFileSync(repoFile("packages", "leviathan-vault", "src", "leviathan_vault", "app_credentials.py"), "utf8");
  assert.match(py, /CryptProtect|DPAPI/i); assert.match(py, /MacOSKeychainCredentialStore/);
});
// Revised after the canonical repo gained workers/licensing/src/google_auth (AUTH-GOOGLE-001, 2026-10-09): the old premise
// ("no Google OAuth code exists") is no longer true. The claim to verify is now: if Google OIDC code exists, the scopes and
// stored fields it uses must match what the privacy policy says (openid, email, profile; no profile picture persisted).
test("CLAIM Google OIDC code (if present) requests exactly the scopes the policy states and persists no picture", { skip: !canonical }, async () => {
  const dir = repoFile("workers", "licensing", "src", "google_auth");
  if (!existsSync(dir)) return; // no code: the policy must (and does, see next test) label Google sign-in as planned
  const src = readdirSync(dir).map((f) => readFileSync(path.join(dir, f), "utf8")).join("\n");
  assert.match(src, /searchParams\.set\("scope", "openid email profile"\)/, "scopes in code differ from the privacy policy");
  const mig = existsSync(repoFile("workers", "licensing", "migrations", "004_google_oidc.sql")) ? readFileSync(repoFile("workers", "licensing", "migrations", "004_google_oidc.sql"), "utf8") : "";
  assert.ok(!/picture|avatar|given_name|family_name/i.test(mig), "profile picture / name parts persisted but not disclosed");
  const t = await textFor("/privacy");
  has(t, /openid, email and profile/);
});
test("CLAIM privacy labels Google sign-in and SnapTrade server storage as planned/conditional, not live", async () => {
  const t = await textFor("/privacy");
  has(t, /Google sign-in is a planned flow|planned|if enabled/i);
  assert.ok(!/we store (?:your )?SnapTrade|SnapTrade (?:user )?secret is stored/i.test(t) || /if (?:that )?feature is enabled|planned/i.test(t));
});
test("CLAIM no overclaiming security superlatives", async () => {
  for (const t of await allText()) assert.ok(!/bank[- ]grade|military[- ]grade|unhackable|SOC ?2|ISO ?27001|end-to-end encrypt|we never store|zero[- ]knowledge/i.test(t));
});
