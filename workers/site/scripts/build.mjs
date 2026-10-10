import { cp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { assertSiteFacts, missingFacts } from "../src/facts.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const config = JSON.parse(await readFile(path.join(root, "site.config.json"), "utf8"));
const allowIncomplete = process.argv.includes("--allow-incomplete");
const missing = missingFacts(config);
const output = path.join(root, "public");
if (missing.length && !allowIncomplete) {
  await rm(output, { recursive: true, force: true });
  console.error(`SITE_FACTS_INCOMPLETE: ${missing.join(", ")}`);
  process.exitCode = 1;
} else {
  if (!missing.length) assertSiteFacts(config);
  await rm(output, { recursive: true, force: true });
  await mkdir(output, { recursive: true });
  await cp(path.join(root, "src", "site.css"), path.join(output, "site.css"));
  const pages = JSON.parse(await readFile(path.join(root, "pages.json"), "utf8"));
  const escape = (value) => String(value).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#39;");
  const fact = (value) => value.includes("[REQUIRED:") ? `<span class="fact-missing">${escape(value)}</span>` : escape(value);
  const nav = pages.map((page) => `<li><a href="${page.path}">${page.nav}</a></li>`).join("");
  const legalName = config.company.legal_name.value;
  const commonStart = (page) => `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${escape(page.title)} | ${escape(config.product_name)}</title><meta name="description" content="${escape(page.description)}"><link rel="stylesheet" href="/site.css"></head><body><a class="skip" href="#main">Skip to content</a><header><a class="brand" href="/">${escape(config.product_name)}</a><nav aria-label="Main navigation"><ul>${nav}</ul></nav></header><main id="main"><p><small>Last updated: ${escape(config.last_updated)}</small></p><h1>${escape(page.heading)}</h1>`;
  const commonEnd = `</main><footer><p>© ${new Date(config.last_updated).getFullYear()} ${fact(legalName)} · ${fact(config.company.mailing_address)}</p><nav aria-label="Footer navigation"><ul>${nav}</ul></nav><p><small>We may update these documents. The current version and its date appear on each page.</small></p>${missing.length ? '<p><small>Draft for owner review: required company facts are incomplete.</small></p>' : ''}</footer></body></html>`;
  const supportContact = config.company.support_email.includes("[REQUIRED:")
    ? fact(config.company.support_email)
    : `<a href="mailto:${escape(config.company.support_email)}">${escape(config.company.support_email)}</a>`;
  const cancellationAction = config.billing?.cancellation_method === "portal"
    ? "cancel before the next renewal through the Stripe billing portal linked from your account"
    : `cancel before the next renewal by emailing ${fact(config.company.support_email)} from your account email`;
  for (const page of pages) {
    const body = await readFile(path.join(root, "pages", `${page.key}.html`), "utf8");
    const rendered = body
      .replaceAll("{{LEGAL_NAME}}", fact(legalName))
      .replaceAll("{{ADDRESS}}", fact(config.company.mailing_address))
      .replaceAll("{{SUPPORT_EMAIL}}", fact(config.company.support_email))
      .replaceAll("{{SUPPORT_CONTACT}}", supportContact)
      .replaceAll("{{FORMATION_STATE}}", fact(config.company.formation_state))
      .replaceAll("{{REGULATORY_STATUS}}", fact(config.company.regulatory_status))
      .replaceAll("{{WEB_BACKEND_HOST}}", fact(config.company.web_backend_host))
      .replaceAll("{{DOMAIN}}", fact(config.company.domain))
      .replaceAll("{{EFFECTIVE_DATE}}", fact(config.company.effective_date))
      .replaceAll("{{RETENTION_DELETION_DAYS}}", fact(config.retention.account_deletion_days))
      .replaceAll("{{RETENTION_LEGAL_YEARS}}", fact(config.retention.legal_retention_years))
      .replaceAll("{{REFUND_POLICY}}", fact(config.refund_policy))
      .replaceAll("{{CANCELLATION_ACTION}}", cancellationAction);
    const filename = page.key === "home" ? "index.html" : `${page.key}.html`;
    await writeFile(path.join(output, filename), commonStart(page) + rendered + commonEnd, "utf8");
  }
  if (missing.length) console.warn(`Draft generated with required placeholders. Build gate: SITE_FACTS_INCOMPLETE (${missing.join(", ")})`);
}
